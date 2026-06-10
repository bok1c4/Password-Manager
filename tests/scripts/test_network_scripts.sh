#!/usr/bin/env bash
# Sandboxed tests for the network-tooling scripts (gen-db-certs,
# onion-auth-keygen, setup-onion, rotate-db-password). Needs only
# bash/coreutils/openssl/python3; psql/pg_dump/systemctl are PATH stubs that
# log argv+stdin into the sandbox. Nothing touches the real system: every test
# runs under its own tmpdir with HOME redirected.
#
#   make test-scripts     (or: tests/scripts/test_network_scripts.sh)
set -u

HERE="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPTS="$HERE/scripts"
PASS=0
FAIL=0

# Sandboxes are collected and removed by ONE harness-level EXIT trap (a
# per-function RETURN trap would delete the dir before the test body ran).
SANDBOXES=()
cleanup_all() {
  for sb in ${SANDBOXES[@]+"${SANDBOXES[@]}"}; do rm -rf "$sb"; done
}
trap cleanup_all EXIT

sandbox() {
  SB="$(mktemp -d /tmp/pwmgr_script_test_XXXXXX)"
  SANDBOXES+=("$SB")
  mkdir -p "$SB/bin" "$SB/home" "$SB/tmp"
  # Stubs log their argv and stdin; psql/pg_dump succeed by default.
  for tool in psql pg_dump systemctl; do
    cat > "$SB/bin/$tool" <<EOF
#!/usr/bin/env bash
echo "\$0 \$*" >> "$SB/calls.log"
cat >> "$SB/stdin.log" 2>/dev/null || true
exit "\${PWMGR_STUB_RC:-0}"
EOF
    chmod +x "$SB/bin/$tool"
  done
}

# t <name> <fn>: run fn in a subshell with the sandbox env. The subshell is
# NOT run inside the `if` condition (bash disables set -e there, which made
# an earlier draft of this harness false-green): capture rc separately.
t() {
  local name="$1" fn="$2"
  sandbox
  local out rc
  out="$(
    set -e
    export PATH="$SB/bin:$PATH" HOME="$SB/home" TMPDIR="$SB/tmp"
    export PWMGR_BACKUP_DIR="$SB/backups"
    unset PGPASSWORD 2>/dev/null || true
    "$fn" 2>&1
  )"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "[ OK ] $name"
    PASS=$((PASS + 1))
  else
    echo "[FAIL] $name (rc=$rc)"
    echo "$out" | sed 's/^/       /'
    FAIL=$((FAIL + 1))
  fi
}

assert_perm() { # <file> <perm>
  local got
  got="$(stat -c %a "$1")"
  [ "$got" = "$2" ] || { echo "perm of $1: got $got want $2"; return 1; }
}

# ---------------- gen-db-certs.sh ----------------

certs_full_set() {
  export PWMGR_CERT_DIR="$SB/certs"
  "$SCRIPTS/gen-db-certs.sh" 192.168.1.50 >/dev/null
  for f in ca.key ca.crt server.key server.crt; do
    [ -f "$SB/certs/$f" ] || { echo "missing $f"; return 1; }
  done
  assert_perm "$SB/certs/ca.key" 600
  assert_perm "$SB/certs/server.key" 600
  openssl verify -CAfile "$SB/certs/ca.crt" "$SB/certs/server.crt" >/dev/null
}

certs_san_typed() {
  export PWMGR_CERT_DIR="$SB/certs"
  "$SCRIPTS/gen-db-certs.sh" 192.168.1.50 myhost.lan >/dev/null
  local txt
  txt="$(openssl x509 -in "$SB/certs/server.crt" -noout -text)"
  echo "$txt" | grep -q "IP Address:192.168.1.50" || { echo "no IP SAN"; return 1; }
  echo "$txt" | grep -q "DNS:myhost.lan" || { echo "no DNS SAN"; return 1; }
}

certs_noop_on_complete() {
  export PWMGR_CERT_DIR="$SB/certs"
  "$SCRIPTS/gen-db-certs.sh" 192.168.1.50 >/dev/null
  local before after
  before="$(sha256sum "$SB/certs/server.crt")"
  "$SCRIPTS/gen-db-certs.sh" 192.168.1.50 >/dev/null   # second run: no-op
  after="$(sha256sum "$SB/certs/server.crt")"
  [ "$before" = "$after" ] || { echo "no-op run changed the cert"; return 1; }
}

certs_partial_refused() {
  export PWMGR_CERT_DIR="$SB/certs"
  "$SCRIPTS/gen-db-certs.sh" 192.168.1.50 >/dev/null
  rm "$SB/certs/server.crt"   # now a partial set
  if "$SCRIPTS/gen-db-certs.sh" 192.168.1.50 >/dev/null 2>&1; then
    echo "partial set was not refused"
    return 1
  fi
  return 0
}

t "gen-db-certs: full set, perms, verify" certs_full_set
t "gen-db-certs: SAN auto-typing IP/DNS" certs_san_typed
t "gen-db-certs: complete set -> no-op" certs_noop_on_complete
t "gen-db-certs: partial set -> refused" certs_partial_refused

echo
echo "==== $PASS passed, $FAIL failed ===="
[ "$FAIL" -eq 0 ]
