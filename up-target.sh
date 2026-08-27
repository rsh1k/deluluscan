#!/usr/bin/env bash
# up-target.sh — stand up an ephemeral single-container target for an authorized
# local audit.
#
# Deluluscan ships no target of its own. Set TARGET_IMAGE to a container you are
# authorized to assess; it is bound to LOOPBACK only, so the scan target is a
# throwaway instance on THIS host and is inherently in authorization scope.
#
# Usage:  TARGET_IMAGE=your-app:tag ./up-target.sh
# Tear down:  docker rm -f deluluscan-target
set -euo pipefail

IMAGE="${TARGET_IMAGE:-}"
NAME="deluluscan-target"
DATA_DIR="$(pwd)/.target-data"
READY_PATH="${TARGET_READY_PATH:-/}"

if [[ -z "$IMAGE" ]]; then
  echo "[!] set TARGET_IMAGE to the container you are authorized to test, e.g." >&2
  echo "    TARGET_IMAGE=your-app:latest ./up-target.sh" >&2
  exit 2
fi

echo "[*] starting ${IMAGE} (loopback only)"
docker rm -f "$NAME" >/dev/null 2>&1 || true
mkdir -p "$DATA_DIR"

# Bind common HTTP(S) ports to 127.0.0.1 ONLY. --rm so it disappears on stop.
docker run -d --rm --name "$NAME" \
  -p 127.0.0.1:8443:8443 \
  -p 127.0.0.1:8080:8080 \
  -v "$DATA_DIR:/data" \
  "$IMAGE" >/dev/null

echo "[*] waiting for the target to become ready (first run can take several minutes)"
for i in $(seq 1 80); do
  if curl -ksf "https://127.0.0.1:8443${READY_PATH}" >/dev/null 2>&1 \
     || curl -sf "http://127.0.0.1:8080${READY_PATH}" >/dev/null 2>&1; then
    echo "[*] the target is up."
    echo "    HTTPS: https://127.0.0.1:8443   HTTP: http://127.0.0.1:8080"
    exit 0
  fi
  sleep 15
done
echo "[!] the target did not become ready in time; check: docker logs $NAME" >&2
exit 1
