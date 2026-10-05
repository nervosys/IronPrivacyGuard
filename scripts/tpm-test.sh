#!/usr/bin/env bash
# Run the TPM test suite against a fresh swtpm software TPM 2.0. The TPM state lives
# in a temporary directory removed on exit.
#
# Requires (Debian/Ubuntu): swtpm swtpm-tools.
# Tests run on one thread: they share one TPM.
# All PINs in the tests are PUBLIC TEST DATA.
set -euo pipefail

WORK="$(mktemp -d)"
cleanup() {
  [ -n "${SWTPM_PID:-}" ] && kill "$SWTPM_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# Manufacture the TPM with an RSA-2048 EK and its certificate from a throwaway
# local CA (root and intermediate), so attestation tests verify a real chain.
mkdir -p "$WORK/state" "$WORK/ca"
printf 'statedir = %s\nsigningkey = %s\nissuercert = %s\ncertserial = %s\n' \
  "$WORK/ca" "$WORK/ca/signkey.pem" "$WORK/ca/issuercert.pem" "$WORK/ca/certserial" > "$WORK/ca.conf"
printf 'create_certs_tool = %s\ncreate_certs_tool_config = %s\ncreate_certs_tool_options = /dev/null\n' \
  "$(command -v swtpm_localca)" "$WORK/ca.conf" > "$WORK/setup.conf"
swtpm_setup --tpm2 --tpmstate "$WORK/state" --create-ek-cert --config "$WORK/setup.conf" >/dev/null

PORT="${SWTPM_PORT:-2321}"
swtpm socket --tpm2 --tpmstate "dir=$WORK/state" --flags startup-clear \
  --server "type=tcp,port=$PORT" --ctrl "type=tcp,port=$((PORT + 1))" \
  --daemon --pid "file=$WORK/swtpm.pid"
SWTPM_PID="$(cat "$WORK/swtpm.pid")"

export IPG_TEST_TPM_TCTI="swtpm:port=$PORT"
export IPG_TEST_TPM_REQUIRED=1
export IPG_TEST_TPM_ATTEST=1
export IPG_TEST_EK_ANCHORS="$WORK/ca/swtpm-localca-rootca-cert.pem"
export IPG_TEST_EK_INTERMEDIATES="$WORK/ca/issuercert.pem"
echo "swtpm on port $PORT"
export RUST_TEST_THREADS=1
cargo test --locked --features tpm "$@"
