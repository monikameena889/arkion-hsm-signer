#!/usr/bin/env bash
# Creates an isolated SoftHSM2 token under ./.softhsm for local development.
# Usage: source <(scripts/dev-token.sh)   -> exports SOFTHSM2_CONF and HSM_PIN_FILE
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/.softhsm"
LABEL="${HSM_TOKEN_LABEL:-arkion}"
mkdir -p "$DIR/tokens" "$DIR/secrets"
chmod 700 "$DIR/secrets"

cat > "$DIR/softhsm2.conf" <<CONF
directories.tokendir = $DIR/tokens
objectstore.backend = file
log.level = ERROR
CONF
export SOFTHSM2_CONF="$DIR/softhsm2.conf"

# Random PINs, generated once and kept in files with 0600 permissions (never on the command line
# of the service, never in the repo).
for f in user_pin so_pin; do
  [[ -s "$DIR/secrets/$f" ]] || (umask 077; openssl rand -hex 16 > "$DIR/secrets/$f")
done

if ! softhsm2-util --show-slots 2>/dev/null | grep -q "Label:.*\b$LABEL\b"; then
  softhsm2-util --init-token --free --label "$LABEL" \
    --so-pin "$(cat "$DIR/secrets/so_pin")" --pin "$(cat "$DIR/secrets/user_pin")" >&2
fi

echo "export SOFTHSM2_CONF=$DIR/softhsm2.conf"
echo "export HSM_PIN_FILE=$DIR/secrets/user_pin"
echo "export HSM_TOKEN_LABEL=$LABEL"
