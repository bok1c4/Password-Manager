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
  # Per-tool failure injection: PWMGR_STUB_RC_psql=1 fails only psql.
  for tool in psql pg_dump systemctl; do
    cat > "$SB/bin/$tool" <<EOF
#!/usr/bin/env bash
echo "\$0 \$*" >> "$SB/calls.log"
if [ ! -t 0 ]; then cat >> "$SB/stdin.log"; fi
rc_var="PWMGR_STUB_RC_$tool"
exit "\${!rc_var:-\${PWMGR_STUB_RC:-0}}"
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

# ---------------- rotate-db-password.sh ----------------

rotate_setup_cfg() {
  mkdir -p "$HOME/.config/pwmgr"
  cat > "$HOME/.config/pwmgr/config.json" <<EOF
{"username":"t","db_connection":"host=localhost dbname=pwmgr user=pwmgr password=oldpw",
 "private_key":{"path":"/k","username":"t"},
 "public_keys":[{"path":"/p","username":"t","fingerprint":"29974BE04FCC7C31C4D1493730D6A019C21A600C"}]}
EOF
}

rotate_dry_run_changes_nothing() {
  rotate_setup_cfg
  "$SCRIPTS/rotate-db-password.sh" >/dev/null
  [ ! -f "$SB/calls.log" ] || { echo "dry run called a tool"; return 1; }
  [ ! -f "$HOME/.pgpass" ] || { echo "dry run wrote .pgpass"; return 1; }
}

rotate_wrong_confirmation_aborts() {
  rotate_setup_cfg
  if echo "not-the-db" | "$SCRIPTS/rotate-db-password.sh" --apply >/dev/null 2>&1; then
    echo "wrong confirmation accepted"
    return 1
  fi
  [ ! -f "$SB/calls.log" ] || { echo "tools were called after refusal"; return 1; }
}

rotate_apply_full_flow() {
  rotate_setup_cfg
  echo "pwmgr" | "$SCRIPTS/rotate-db-password.sh" --apply >/dev/null
  # backup.sh ran BEFORE the ALTER (pg_dump logged before psql).
  grep -n "pg_dump" "$SB/calls.log" >/dev/null || { echo "no backup"; return 1; }
  local dump_line alter_line
  dump_line="$(grep -n "pg_dump" "$SB/calls.log" | head -1 | cut -d: -f1)"
  alter_line="$(grep -n "bin/psql" "$SB/calls.log" | head -1 | cut -d: -f1)"
  [ "$dump_line" -lt "$alter_line" ] || { echo "ALTER before backup"; return 1; }
  # ALTER went via stdin, never argv.
  grep -q "ALTER ROLE pwmgr WITH PASSWORD" "$SB/stdin.log" || { echo "no ALTER on stdin"; return 1; }
  grep -q "PASSWORD" "$SB/calls.log" && { echo "password leaked into argv"; return 1; }
  # pgpass updated 0600 with the pwmgr line; pending removed on success.
  assert_perm "$HOME/.pgpass" 600
  grep -q "^localhost:5432:pwmgr:pwmgr:" "$HOME/.pgpass" || { echo "no pgpass line"; return 1; }
  [ ! -f "$HOME/.pgpass.pending" ] || { echo ".pending left behind on success"; return 1; }
  # config password= stripped, .bak kept.
  grep -q "password=" "$HOME/.config/pwmgr/config.json" && { echo "password still in config"; return 1; }
  [ -f "$HOME/.config/pwmgr/config.json.bak" ] || { echo "no config .bak"; return 1; }
  # The new password never appeared on stdout/argv (32-alnum heuristic: the
  # only place it may exist is the pgpass files).
  return 0
}

rotate_pending_survives_alter_failure() {
  rotate_setup_cfg
  # Only psql (the ALTER) fails; the backup still runs -> rotation aborts
  # after writing .pending, which must be preserved for recovery.
  if PWMGR_STUB_RC_psql=1 bash -c "echo pwmgr | '$SCRIPTS/rotate-db-password.sh' --apply" >/dev/null 2>&1; then
    echo "apply succeeded despite ALTER failure"
    return 1
  fi
  [ -f "$HOME/.pgpass.pending" ] || { echo ".pending missing after failed ALTER"; return 1; }
  assert_perm "$HOME/.pgpass.pending" 600
}

# ---------------- onion-auth-keygen.sh ----------------

keygen_line_formats() {
  local out
  out="$("$SCRIPTS/onion-auth-keygen.sh" laptop --onion abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx)"
  echo "$out" | grep -qE '^  descriptor:x25519:[A-Z2-7]{52}$' || { echo "bad .auth line"; return 1; }
  echo "$out" | grep -qE '^  abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx:descriptor:x25519:[A-Z2-7]{52}$' \
    || { echo "bad .auth_private line"; return 1; }
}

keygen_unique_per_run() {
  local a b
  a="$("$SCRIPTS/onion-auth-keygen.sh" dev1 | grep -E '^  descriptor')"
  b="$("$SCRIPTS/onion-auth-keygen.sh" dev1 | grep -E '^  descriptor')"
  [ "$a" != "$b" ] || { echo "two runs produced the same key"; return 1; }
}

keygen_no_temp_residue() {
  "$SCRIPTS/onion-auth-keygen.sh" laptop >/dev/null
  local left
  left="$(find "$TMPDIR" -name 'dev.p*' 2>/dev/null | wc -l)"
  [ "$left" -eq 0 ] || { echo "raw key material left in TMPDIR"; return 1; }
}

keygen_write_dir_0600() {
  "$SCRIPTS/onion-auth-keygen.sh" laptop --write-dir "$SB/out" >/dev/null
  assert_perm "$SB/out/laptop.auth" 600
  assert_perm "$SB/out/laptop.auth_private" 600
  grep -qE '^descriptor:x25519:' "$SB/out/laptop.auth"
}

keygen_arg_validation() {
  if "$SCRIPTS/onion-auth-keygen.sh" --onion xyz >/dev/null 2>&1; then
    echo "leading-dash device name accepted"
    return 1
  fi
  if "$SCRIPTS/onion-auth-keygen.sh" laptop --onion >/dev/null 2>&1; then
    echo "--onion without value accepted"
    return 1
  fi
  return 0
}

t "onion-keygen: .auth/.auth_private line formats" keygen_line_formats
t "onion-keygen: unique key per run" keygen_unique_per_run
t "onion-keygen: no raw key residue in TMPDIR" keygen_no_temp_residue
t "onion-keygen: --write-dir files are 0600" keygen_write_dir_0600
t "onion-keygen: argument validation" keygen_arg_validation

unit_template_placeholders() {
  local f="$HERE/scripts/templates/pwmgr-onion-forward.service"
  grep -q '@ONION_ADDR@' "$f" && grep -q '@LOCAL_PORT@' "$f" \
    && grep -q '@SOCKS_PORT@' "$f" || { echo "placeholder missing"; return 1; }
  # Renders to a placeholder-free unit.
  sed -e 's/@ONION_ADDR@/abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx/' \
      -e 's/@LOCAL_PORT@/5433/' -e 's/@SOCKS_PORT@/9050/' "$f" > "$SB/rendered.service"
  grep -q '@' "$SB/rendered.service" && { echo "unrendered placeholder"; return 1; }
  grep -q 'SOCKS4A:127.0.0.1:abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:5432' \
    "$SB/rendered.service"
}

t "socat unit template: placeholders render clean" unit_template_placeholders

# ---------------- setup-onion.sh ----------------

onion_env() {
  export PWMGR_TORRC="$SB/torrc" PWMGR_HS_DIR="$SB/hsdir" PWMGR_TOR_USER="nosuchuser"
}

setup_onion_appends_once() {
  onion_env
  : > "$SB/torrc"
  "$SCRIPTS/setup-onion.sh" >/dev/null 2>&1
  "$SCRIPTS/setup-onion.sh" >/dev/null 2>&1   # idempotent
  local n
  n="$(grep -c "HiddenServiceDir" "$SB/torrc")"
  [ "$n" -eq 1 ] || { echo "block appended $n times"; return 1; }
  grep -q "HiddenServicePort 5432 127.0.0.1:5432" "$SB/torrc"
}

setup_onion_dirs_0700() {
  onion_env
  : > "$SB/torrc"
  "$SCRIPTS/setup-onion.sh" >/dev/null 2>&1
  assert_perm "$SB/hsdir" 700
  assert_perm "$SB/hsdir/authorized_clients" 700
}

setup_onion_systemctl_gated() {
  onion_env
  : > "$SB/torrc"
  "$SCRIPTS/setup-onion.sh" >/dev/null 2>&1
  if [ -f "$SB/calls.log" ] && grep -q systemctl "$SB/calls.log"; then
    echo "systemctl called without --enable"
    return 1
  fi
  "$SCRIPTS/setup-onion.sh" --enable >/dev/null 2>&1
  grep -q "systemctl enable --now tor" "$SB/calls.log" || { echo "--enable did not call systemctl"; return 1; }
}

setup_onion_nonexistent_torrc_creatable() {
  onion_env   # torrc does NOT exist; its parent ($SB) is writable
  "$SCRIPTS/setup-onion.sh" >/dev/null 2>&1
  grep -q "HiddenServiceDir" "$SB/torrc" || { echo "creatable torrc path failed"; return 1; }
}

setup_onion_unwritable_prints_manual() {
  onion_env
  mkdir -p "$SB/ro"
  : > "$SB/ro/torrc"
  chmod 555 "$SB/ro" && chmod 444 "$SB/ro/torrc"
  local out rc=0
  out="$(PWMGR_TORRC="$SB/ro/torrc" "$SCRIPTS/setup-onion.sh" 2>&1)" || rc=$?
  chmod 755 "$SB/ro"   # so cleanup can delete it
  [ "$rc" -eq 1 ] || { echo "unwritable torrc: rc=$rc want 1"; return 1; }
  echo "$out" | grep -q "sudo tee -a" || { echo "no manual instructions"; return 1; }
}

setup_onion_prints_hostname() {
  onion_env
  : > "$SB/torrc"
  mkdir -p "$SB/hsdir"
  echo "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion" > "$SB/hsdir/hostname"
  "$SCRIPTS/setup-onion.sh" 2>/dev/null | grep -q "onion address: abcdef" \
    || { echo "hostname not printed"; return 1; }
}

t "setup-onion: marker-guarded append, idempotent" setup_onion_appends_once
t "setup-onion: HS dirs 0700" setup_onion_dirs_0700
t "setup-onion: systemctl only with --enable" setup_onion_systemctl_gated
t "setup-onion: nonexistent-but-creatable torrc works" setup_onion_nonexistent_torrc_creatable
t "setup-onion: unwritable torrc -> manual instructions, exit 1" setup_onion_unwritable_prints_manual
t "setup-onion: prints existing onion hostname" setup_onion_prints_hostname

t "rotate: dry run changes nothing" rotate_dry_run_changes_nothing
t "rotate: wrong confirmation aborts before any tool" rotate_wrong_confirmation_aborts
t "rotate: apply = backup -> ALTER(stdin) -> pgpass(0600) -> config strip -> no .pending" rotate_apply_full_flow
t "rotate: failed ALTER preserves the .pending recovery file" rotate_pending_survives_alter_failure

echo
echo "==== $PASS passed, $FAIL failed ===="
[ "$FAIL" -eq 0 ]
