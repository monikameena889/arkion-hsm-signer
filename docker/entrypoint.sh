#!/bin/sh
# Initialises the SoftHSM2 token on first start (test environment only), then execs the service.
# PINs come from files (Docker/K8s secrets) or env vars; they are never printed.
set -eu

LABEL="${HSM_TOKEN_LABEL:-arkion}"

read_secret() { # $1 = *_FILE var value, $2 = plain env var value
  if [ -n "$1" ] && [ -r "$1" ]; then tr -d '\r\n' < "$1"; else printf '%s' "$2"; fi
}

if ! softhsm2-util --show-slots 2>/dev/null | grep -Eq "Label:[[:space:]]+${LABEL}[[:space:]]*$"; then
  USER_PIN="$(read_secret "${HSM_PIN_FILE:-}" "${HSM_PIN:-}")"
  if [ -z "$USER_PIN" ]; then
    echo "entrypoint: token '$LABEL' not initialised and no HSM_PIN_FILE/HSM_PIN provided" >&2
    exit 64
  fi
  SO_PIN="$(read_secret "${HSM_SO_PIN_FILE:-}" "${HSM_SO_PIN:-}")"
  if [ -z "$SO_PIN" ]; then
    # Nobody needs the SO PIN for this test token; generate and discard it.
    SO_PIN="$(openssl rand -hex 16)"
  fi
  softhsm2-util --init-token --free --label "$LABEL" --so-pin "$SO_PIN" --pin "$USER_PIN" >/dev/null
  unset SO_PIN USER_PIN
  echo "entrypoint: initialised SoftHSM2 token '$LABEL'" >&2
fi

exec "$@"
