#!/usr/bin/env bash
# Run the PKCS#11 test suite against a fresh, disposable SoftHSMv2 token.
#
# Requires softhsm2 (Debian/Ubuntu: apt-get install softhsm2). The token store is a
# temporary directory removed on exit; nothing touches the system token store.
# All PINs here are PUBLIC TEST DATA.
set -euo pipefail

MODULE="${SOFTHSM2_MODULE:-}"
if [ -z "$MODULE" ]; then
  for candidate in /usr/lib/softhsm/libsofthsm2.so \
                   /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
                   /usr/local/lib/softhsm/libsofthsm2.so \
                   /opt/homebrew/lib/softhsm/libsofthsm2.so; do
    if [ -f "$candidate" ]; then MODULE="$candidate"; break; fi
  done
fi
[ -n "$MODULE" ] || { echo "libsofthsm2.so not found; set SOFTHSM2_MODULE" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/tokens"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$WORK" > "$WORK/softhsm2.conf"
export SOFTHSM2_CONF="$WORK/softhsm2.conf"

LABEL="ipg-live"
PIN="123456"
softhsm2-util --init-token --free --label "$LABEL" --pin "$PIN" --so-pin 12345678 >/dev/null
SERIAL="$(softhsm2-util --show-slots | awk -v label="$LABEL" '/Serial number:/ {s=$3} /Label:/ {if ($2 == label) {print s; exit}}')"
[ -n "$SERIAL" ] || { echo "could not read the SoftHSM token serial" >&2; exit 1; }

export IPG_TEST_PKCS11_MODULE="$MODULE"
export IPG_TEST_PKCS11_SERIAL="$SERIAL"
export IPG_TEST_PKCS11_PIN="$PIN"
export IPG_TEST_PKCS11_REQUIRED=1
echo "SoftHSM module $MODULE, token serial $SERIAL"
cargo test --locked --features pkcs11 "$@"
