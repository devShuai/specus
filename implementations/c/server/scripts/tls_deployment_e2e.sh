#!/usr/bin/env bash
set -euo pipefail

# The production TLS rule of the control listener, on the real binary: a production server
# (SPECUS_ENV=prod, an unknown or unset SPECUS_ENV, or SPECUS_TLS_REQUIRE_ENCRYPTION) refuses to
# start with a public plaintext control listener, and says why; it starts with PEM file TLS, or with
# TLS terminated upstream in front of a loopback/private bind. The PEM listener is then checked with
# openssl s_client against the test CA and the certificate's host name.
#
# Usage: tls_deployment_e2e.sh [path-to-specus-server-c]

C_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="${1:-$C_DIR/build/specus-server-c}"
CONTROL_PORT="${CONTROL_PORT:-17480}"
TLS_HOST="specus-c.test"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-tls-deploy.XXXXXX")"
REJECTION="TLS configuration rejected: production control channel requires TLS, or trusted upstream TLS with a private/loopback bind address"

cleanup() {
  local status=$?
  set +e
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
  rm -rf "$TMP_DIR"
  return "$status"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

# shellcheck source=tls_test_pki.sh
source "$C_DIR/scripts/tls_test_pki.sh"
make_test_pki "$TMP_DIR" "$TLS_HOST"

fail() {
  echo "TLS deployment E2E failed: $*" >&2
  [[ -f "$TMP_DIR/server.log" ]] && sed -n '1,80p' "$TMP_DIR/server.log" >&2
  exit 1
}

# run_server NAME ENV... starts the server in the background with only the given environment on top
# of what every case needs (the environment-token client, the control port, no admin listener).
run_server() {
  local name="$1"
  shift
  : >"$TMP_DIR/server.log"
  env -i PATH="$PATH" HOME="${HOME:-/tmp}" \
    SPECUS_CLIENT_ACCESS_TOKEN=tls-deployment-token \
    SPECUS_NETTY_PORT="$CONTROL_PORT" \
    SPECUS_ADMIN_PORT=0 \
    "$@" \
    stdbuf -oL -eL "$SERVER" >"$TMP_DIR/server.log" 2>&1 &
  SERVER_PID=$!
  CASE="$name"
}

# expect_refused NAME MESSAGE ENV...: the process exits non-zero, prints MESSAGE and never listens.
expect_refused() {
  local name="$1" message="$2"
  shift 2
  run_server "$name" "$@"
  local status=0
  for _ in $(seq 1 100); do
    kill -0 "$SERVER_PID" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    fail "$name: the server is still running after 10 s"
  fi
  wait "$SERVER_PID" || status=$?
  SERVER_PID=""
  [[ "$status" -ne 0 ]] || fail "$name: the server exited with status 0"
  grep -qF "$message" "$TMP_DIR/server.log" || fail "$name: no '$message' in the output"
  ! grep -q "listening on" "$TMP_DIR/server.log" || fail "$name: the control listener was opened"
  echo "ok   $name refused to start (exit $status): $(grep -F "$message" "$TMP_DIR/server.log" | head -n 1)"
}

# expect_started NAME TLS_MODE ENV...: the control listener comes up with the given TLS mode.
expect_started() {
  local name="$1" mode="$2"
  shift 2
  run_server "$name" "$@"
  for _ in $(seq 1 100); do
    if grep -q "listening on .*:$CONTROL_PORT tls=$mode " "$TMP_DIR/server.log"; then
      echo "ok   $name started: $(grep -m 1 "listening on" "$TMP_DIR/server.log")"
      return 0
    fi
    kill -0 "$SERVER_PID" 2>/dev/null || fail "$name: the server exited during startup"
    sleep 0.1
  done
  fail "$name: the control listener did not come up with tls=$mode"
}

stop_server() {
  kill "$SERVER_PID"
  wait "$SERVER_PID" || true
  SERVER_PID=""
}

expect_refused "prod, plaintext on 0.0.0.0" "$REJECTION" SPECUS_ENV=prod
expect_refused "unset SPECUS_ENV (fails safe to prod), plaintext" "$REJECTION"
expect_refused "unknown SPECUS_ENV=staging, plaintext" "$REJECTION" SPECUS_ENV=staging
expect_refused "dev with SPECUS_TLS_REQUIRE_ENCRYPTION, plaintext" "$REJECTION" \
  SPECUS_ENV=dev SPECUS_TLS_REQUIRE_ENCRYPTION=true
expect_refused "prod, upstream TLS claimed but public bind" "$REJECTION" \
  SPECUS_ENV=prod SPECUS_TLS_TERMINATED_UPSTREAM=true SPECUS_NETTY_BIND_ADDRESS=0.0.0.0
expect_refused "prod, self-signed certificate" "production control channel cannot use a self-signed certificate" \
  SPECUS_ENV=prod SPECUS_TLS_MODE=self-signed
expect_refused "prod, PEM certificate without its key" "file TLS mode requires" \
  SPECUS_ENV=prod SPECUS_TLS_MODE=file SPECUS_TLS_CERTIFICATE="$TMP_DIR/server.pem"

expect_started "dev, plaintext" disabled SPECUS_ENV=dev
stop_server
expect_started "prod, upstream TLS in front of a loopback bind" disabled \
  SPECUS_ENV=prod SPECUS_TLS_TERMINATED_UPSTREAM=true SPECUS_NETTY_BIND_ADDRESS=127.0.0.1
stop_server
expect_started "prod, PEM certificate and key" file \
  SPECUS_ENV=prod SPECUS_TLS_MODE=file \
  SPECUS_TLS_CERTIFICATE="$TMP_DIR/server.pem" SPECUS_TLS_PRIVATE_KEY="$TMP_DIR/server.key"

# The PEM listener presents the CA-signed chain for the test host name.
s_client() {
  openssl s_client -connect "127.0.0.1:$CONTROL_PORT" -servername "$TLS_HOST" \
    -verify_return_error -CAfile "$1" -verify_hostname "$2" </dev/null >"$TMP_DIR/s_client.log" 2>&1
}
s_client "$TMP_DIR/ca.pem" "$TLS_HOST" || fail "s_client with the test CA and $TLS_HOST: $(tail -n 5 "$TMP_DIR/s_client.log")"
grep -q "Verify return code: 0 (ok)" "$TMP_DIR/s_client.log" || fail "s_client did not verify the chain"
echo "ok   s_client verified the PEM chain for $TLS_HOST"
if s_client "$TMP_DIR/other-ca.pem" "$TLS_HOST"; then fail "s_client trusted the chain with another CA"; fi
echo "ok   s_client rejected it with another CA: $(grep -m 1 -o 'verify error:.*' "$TMP_DIR/s_client.log")"
if s_client "$TMP_DIR/ca.pem" "wrong.$TLS_HOST"; then fail "s_client accepted the name wrong.$TLS_HOST"; fi
echo "ok   s_client rejected it for wrong.$TLS_HOST: $(grep -m 1 -o 'verify error:.*' "$TMP_DIR/s_client.log")"
grep -q "\[tls\] handshake complete" "$TMP_DIR/server.log" || fail "the server logged no completed handshake"
stop_server
echo "TLS deployment E2E passed"
