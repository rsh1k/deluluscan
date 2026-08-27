#!/usr/bin/env bash
# up-compose.sh — Stand up the target via docker-compose, wait for readiness,
# provision multi-role test users, and fetch the authenticated OpenAPI spec.
#
# Usage:  ./up-compose.sh [docker-compose.yml]
# Tear down: docker compose down
set -euo pipefail

COMPOSE_FILE="${1:-}"
CONFIG="config.dev.yaml"
OPENAPI_OUT="openapi.json"

# Compose only auto-loads docker-compose.override.yml when NO -f is passed.
# Passing -f docker-compose.yml unconditionally silently discarded the override,
# so a run that had pinned a specific release under test came up on whatever
# :latest happened to resolve to locally — and the scan then reported findings
# against a build nobody chose. Default to letting Compose resolve the files
# itself; only pass -f when the caller explicitly named one.
COMPOSE_ARGS=()
if [[ -n "$COMPOSE_FILE" ]]; then
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        echo "[!] compose file not found: $COMPOSE_FILE" >&2
        exit 1
    fi
    COMPOSE_ARGS=(-f "$COMPOSE_FILE")
    echo "[*] using explicitly named compose file: $COMPOSE_FILE"
    echo "    (note: this DISABLES docker-compose.override.yml)"
fi

echo "[*] starting the target stack (db + search + target)..."
docker compose "${COMPOSE_ARGS[@]}" up -d

# State the image actually under test. The whole report is scoped to this build,
# so it must be observed from the running container, never assumed from a tag.
RUNNING_IMAGE="$(docker compose "${COMPOSE_ARGS[@]}" config 2>/dev/null \
                 | awk '/^ *image:/{print $2; exit}')"
echo "[*] the target image under test: ${RUNNING_IMAGE:-unknown}"

echo "[*] waiting for the target to become ready (first run can take 3–5 min)..."
READY=0
for i in $(seq 1 120); do
    if curl -sf  "http://127.0.0.1:8080/" >/dev/null 2>&1 \
    || curl -ksf "https://127.0.0.1:8443/" >/dev/null 2>&1; then
        READY=1
        break
    fi
    printf "\r    still starting... (%ds elapsed)" "$((i * 10))"
    sleep 10
done
echo ""

if [[ "$READY" -eq 0 ]]; then
    echo "[!] timed out waiting for the target; check: docker compose logs target" >&2
    exit 1
fi
echo "[*] the target is up."

# Cross-check the tag we THINK we launched against the version the server
# reports. These disagreeing is exactly how an audit ends up describing the
# wrong release, and the header is the only source that reflects reality.
SERVED_VERSION="$(curl -sI "http://127.0.0.1:8080/" \
                  | awk -F': *' 'tolower($1)=="x-app-version"{print $2}' | tr -d '\r')"
echo "[*] server reports x-app-version: ${SERVED_VERSION:-unknown}"
if [[ -n "$SERVED_VERSION" && -n "${RUNNING_IMAGE:-}" ]]; then
    IMAGE_TAG="${RUNNING_IMAGE##*:}"
    if [[ "$IMAGE_TAG" != "latest" && "$IMAGE_TAG" != "$SERVED_VERSION"* ]]; then
        echo "[!] WARNING: image tag '$IMAGE_TAG' does not match served version" \
             "'$SERVED_VERSION' — findings would be attributed to the wrong build." >&2
    fi
fi

echo "[*] provisioning test users..."
python3 scripts/provision_users.py --config "$CONFIG" --openapi-out "$OPENAPI_OUT"

echo ""
echo "[*] the target audit stack ready."
echo "    Admin UI: http://127.0.0.1:8080/admin   (admin@example.com / admin)"
echo ""
echo "[*] Run full scan:"
echo "    python3 -m deluluscan.cli --config $CONFIG --openapi-file $OPENAPI_OUT --allow-state-changing --fuzz"
