#!/usr/bin/env bash
# Stand up a local Quilzo target in Docker and provision the identity matrix
# Deluluscan needs to test it, then emit a ready-to-use config.
#
# Idempotent: safe to re-run. Requires: docker, git, go (to build the image),
# and this repo checked out. Loopback-only — the authorization boundary stays intact.
#
#   ./setup_quilzo.sh [SRC_DIR]
#
# SRC_DIR is a Quilzo source checkout (default: ./.quilzo-src, cloned if absent).
# Writes: config.quilzo.yaml (+ tokens.txt) next to this script.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:-$HERE/.quilzo-src}"
IMAGE="quilzo:pentest"
ADMIN_PORT="${ADMIN_PORT:-9080}"
SITE_PORT="${SITE_PORT:-9081}"
VOL_STORE="quilzo_store"
VOL_TPL="quilzo_tpl"

echo "[*] Quilzo source -> $SRC"
[ -d "$SRC/.git" ] || git clone --depth 1 https://github.com/Quilzo/Quilzo.git "$SRC"

echo "[*] building $IMAGE (distroless, static)"
docker build -q -t "$IMAGE" --build-arg VERSION=pentest "$SRC" >/dev/null

echo "[*] (re)provisioning store volume with demo content + identities"
# Stop any running containers first, so the volume is free to be recreated fresh.
docker rm -f quilzo_admin quilzo_site >/dev/null 2>&1 || true
docker volume rm "$VOL_STORE" "$VOL_TPL" >/dev/null 2>&1 || true
docker volume create "$VOL_STORE" >/dev/null
docker volume create "$VOL_TPL"   >/dev/null
R="docker run --rm -v $VOL_STORE:/srv/store $IMAGE --root /srv/store"

$R init  >/dev/null 2>&1 || true
$R demo  >/dev/null 2>&1 || true
# First grant bootstraps access control; capture the admin token it lets us mint.
$R auth grant alice admin >/dev/null 2>&1 || true
ALICE="$($R token issue alice-key --principal alice 2>/dev/null | grep -oE '^qz_[a-z0-9]+' | head -1)"
[ -n "$ALICE" ] || { echo "!! could not mint the admin token"; exit 1; }

RA="docker run --rm -e QUILZO_TOKEN=$ALICE -v $VOL_STORE:/srv/store $IMAGE --root /srv/store"
for pair in "bob publisher" "carol author" "dave reader"; do
  set -- $pair; $RA auth grant "$1" "$2" >/dev/null 2>&1 || true
done
$RA auth grant erin author --on /blog >/dev/null 2>&1 || true

mint() { # name principal role [extra flags...]
  local name="$1" pr="$2" role="$3"; shift 3
  $RA token issue "$name" --principal "$pr" --role "$role" "$@" 2>/dev/null \
    | grep -oE '^qz_[a-z0-9]+' | head -1
}
BOB="$(mint bob-key bob publisher)"
CAROL="$(mint carol-key carol author)"
DAVE="$(mint dave-key dave reader)"
ERIN="$(mint erin-key erin author --on /blog)"
RO="$(mint ro-key bob publisher --read-only)"
SCOPED="$(mint scoped-key bob publisher --on /blog)"

# a template layout so `site` can render, and the public site can be scanned too
$RA template use sections --dir /srv/store/templates >/dev/null 2>&1 || true
docker run --rm -e QUILZO_TOKEN="$ALICE" -v "$VOL_STORE":/srv/store -v "$VOL_TPL":/srv/templates \
  "$IMAGE" --root /srv/store template use sections --dir /srv/templates >/dev/null 2>&1 || true

echo "[*] (re)starting servers  admin:127.0.0.1:$ADMIN_PORT  site:127.0.0.1:$SITE_PORT"
docker rm -f quilzo_admin quilzo_site >/dev/null 2>&1 || true
docker run -d --name quilzo_admin -e QUILZO_TOKEN="$ALICE" -v "$VOL_STORE":/srv/store \
  -p "127.0.0.1:$ADMIN_PORT:8080" "$IMAGE" --root /srv/store serve --addr 0.0.0.0:8080 >/dev/null
docker run -d --name quilzo_site  -e QUILZO_TOKEN="$ALICE" -v "$VOL_STORE":/srv/store -v "$VOL_TPL":/srv/templates \
  -p "127.0.0.1:$SITE_PORT:8081" "$IMAGE" --root /srv/store site --addr 0.0.0.0:8081 --api --templates /srv/templates >/dev/null

{ echo "alice  admin        / : $ALICE"
  echo "bob    publisher    / : $BOB"
  echo "carol  author       / : $CAROL"
  echo "dave   reader       / : $DAVE"
  echo "erin   author   /blog : $ERIN"
  echo "bob    publisher(ro)/ : $RO"
  echo "bob    publisher /blog: $SCOPED"; } > "$HERE/tokens.txt"

sed -e "s|__ADMIN__|$ALICE|" -e "s|__PUBLISHER__|$BOB|" \
    -e "s|__EDITOR__|$CAROL|" -e "s|__READER__|$DAVE|" \
    -e "s|__ADMIN_PORT__|$ADMIN_PORT|" \
    "$HERE/config.quilzo.template.yaml" > "$HERE/config.quilzo.yaml"

cat <<EOF

[+] Ready.
    admin: http://127.0.0.1:$ADMIN_PORT   site: http://127.0.0.1:$SITE_PORT
    tokens: $HERE/tokens.txt
    config: $HERE/config.quilzo.yaml

  Fingerprint it:
    python3 -m deluluscan.platforms --url http://127.0.0.1:$ADMIN_PORT

  Deep multi-identity scan (seeded with Quilzo's routes):
    python3 -m deluluscan.cli --config $HERE/config.quilzo.yaml \\
        --openapi-file $HERE/quilzo_openapi.json \\
        --observe --observe-container quilzo_admin

  Tear down:
    docker rm -f quilzo_admin quilzo_site
    docker volume rm $VOL_STORE $VOL_TPL
EOF
