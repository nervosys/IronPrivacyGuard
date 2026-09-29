#!/usr/bin/env bash
# Run the TPM test suite against a fresh swtpm software TPM 2.0. The TPM state lives
# in a temporary directory removed on exit.
#
# Requires (Debian/Ubuntu): swtpm swtpm-tools libtss2-dev pkg-config.
# All PINs in the tests are PUBLIC TEST DATA.
set -euo pipefail

WORK="$(mktemp -d)"
cleanup() {
  [ -n "${SWTPM_PID:-}" ] && kill "$SWTPM_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

PORT="${SWTPM_PORT:-2321}"
swtpm socket --tpm2 --tpmstate "dir=$WORK" --flags startup-clear \
  --server "type=tcp,port=$PORT" --ctrl "type=tcp,port=$((PORT + 1))" \
  --daemon --pid "file=$WORK/swtpm.pid"
SWTPM_PID="$(cat "$WORK/swtpm.pid")"

export APG_TEST_TPM_TCTI="swtpm:port=$PORT"
export APG_TEST_TPM_REQUIRED=1
echo "swtpm on port $PORT"
cargo test --locked --features tpm "$@"
