#!/usr/bin/env bash
# Staging rehearsal on a COPY of real data (MULTI_DEVICE_PLAN.md §5 item 4):
# restore the latest prod dump into pwmgr_test, run `pwmgr migrate` there, and
# prove the passwords table is BIT-IDENTICAL before/after (plus backfill shape
# and idempotency). Production is never touched.
#
#   make test-staging
#   PWMGR_STAGING_DECRYPT=1 make test-staging   # additionally decrypts every
#                                               # entry (GPG passphrase needed)
#
# Needs: a dump in $PWMGR_BACKUP_DIR (~/pwmgr-backups), the built binary
# (make), and CREATEDB for the pwmgr role OR a pre-created empty pwmgr_test
# (sudo -u postgres createdb pwmgr_test --owner pwmgr).
#
# Exit codes: 30 infra · 32 passwords drift · 33 backfill shape ·
# 34 idempotency · 35 decrypt failure.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
BACKUP_DIR="${PWMGR_BACKUP_DIR:-$HOME/pwmgr-backups}"
SDB="pwmgr_test"
PGHOST="${PGHOST:-localhost}"
PGUSER="${PGUSER:-pwmgr}"
BIN="$HERE/build/make/pwmgr"
FOUNDING_FPR="29974BE04FCC7C31C4D1493730D6A019C21A600C"

fail() { echo "[FAIL] $2" >&2; exit "$1"; }

[ -x "$BIN" ] || fail 30 "build the binary first: make"

# Source config resolved exactly like the binary does.
CFG="${PWMGR_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/pwmgr/config.json}"
[ -f "$CFG" ] || fail 30 "no config at $CFG"
grep -q "$FOUNDING_FPR" "$CFG" || fail 30 "config does not carry the founding fingerprint"

DUMP="$(ls -t "$BACKUP_DIR"/pwmgr_*.dump 2>/dev/null | head -1 || true)"
[ -n "$DUMP" ] || fail 30 "no dump in $BACKUP_DIR — run scripts/backup.sh first"
echo "[*] using dump: $DUMP"

# Auth for psql/pg_dump: PGPASSWORD, ~/.pgpass, or the config's token.
if [ -z "${PGPASSWORD:-}" ]; then
  PW="$(grep -oP '"db_connection"\s*:\s*"[^"]*password=\K[^ "]+' "$CFG" || true)"
  [ -n "$PW" ] && export PGPASSWORD="$PW"
fi

q() { psql -h "$PGHOST" -U "$PGUSER" -d "$SDB" -tAc "$1"; }

echo "[*] restoring into $SDB (throwaway)"
PWMGR_RESTORE_DB="$SDB" PGHOST="$PGHOST" PGUSER="$PGUSER" \
  "$HERE/scripts/restore.sh" "$DUMP" || fail 30 "restore failed"

WORK="$(mktemp -d /tmp/pwmgr_staging.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# Work config = real config with ONLY the dbname swapped (word-boundary; a
# substring replace could mangle e.g. dbname=pwmgr2).
python3 - "$CFG" "$WORK/config.json" <<'PY'
import json, re, sys
src, dst = sys.argv[1], sys.argv[2]
with open(src) as f:
    j = json.load(f)
conn = j["db_connection"]
if not re.search(r"\bdbname=pwmgr\b", conn):
    sys.exit("db_connection does not target dbname=pwmgr — refusing to guess")
j["db_connection"] = re.sub(r"\bdbname=pwmgr\b", "dbname=pwmgr_test", conn)
with open(dst, "w") as f:
    json.dump(j, f, indent=4)
PY
chmod 600 "$WORK/config.json"

snapshot() { # <outfile>
  psql -h "$PGHOST" -U "$PGUSER" -d "$SDB" --csv -c \
    "SELECT id, password, encode(aes_key,'base64'), note, created_at, enc_version
     FROM passwords ORDER BY id" > "$1.csv"
  # pg_dump 18 emits a RANDOM \restrict token per dump — strip it or two
  # dumps of identical data never byte-compare equal.
  pg_dump -h "$PGHOST" -U "$PGUSER" --data-only --table=passwords "$SDB" \
    | grep -vE '^\\(un)?restrict ' > "$1.dump"
}

echo "[*] snapshot BEFORE migrate"
snapshot "$WORK/before"
N_ENTRIES="$(q "SELECT count(*) FROM passwords")"
echo "    $N_ENTRIES entries"

echo "[*] running pwmgr migrate against $SDB"
PWMGR_CONFIG="$WORK/config.json" "$BIN" migrate || fail 30 "pwmgr migrate failed"

echo "[*] snapshot AFTER migrate — asserting bit-identity"
snapshot "$WORK/after"
cmp -s "$WORK/before.csv" "$WORK/after.csv" || fail 32 "passwords CSV drifted"
cmp -s "$WORK/before.dump" "$WORK/after.dump" || fail 32 "passwords pg_dump drifted"
echo "    passwords table bit-identical"

echo "[*] backfill shape"
[ "$(q "SELECT count(*) FROM devices")" = "1" ] || fail 33 "expected exactly 1 device"
[ "$(q "SELECT count(*) FROM devices WHERE fingerprint='$FOUNDING_FPR' AND status='active'")" = "1" ] \
  || fail 33 "founding device fingerprint/status wrong"
[ "$(q "SELECT count(*) FROM password_keys")" = "$N_ENTRIES" ] \
  || fail 33 "expected one password_keys row per entry"
[ "$(q "SELECT count(*) FROM password_keys pk JOIN passwords p ON p.id=pk.password_id
        WHERE pk.wrapped_key <> p.aes_key")" = "0" ] \
  || fail 33 "a backfilled wrap differs from its aes_key"
echo "    1 device, $N_ENTRIES wraps, all byte-equal to aes_key"

echo "[*] idempotency: second migrate changes nothing"
PWMGR_CONFIG="$WORK/config.json" "$BIN" migrate >/dev/null || fail 34 "second migrate failed"
snapshot "$WORK/again"
cmp -s "$WORK/after.csv" "$WORK/again.csv" || fail 34 "second migrate drifted passwords"
[ "$(q "SELECT count(*) FROM devices")" = "1" ] || fail 34 "second migrate added a device"
[ "$(q "SELECT count(*) FROM password_keys")" = "$N_ENTRIES" ] || fail 34 "second migrate added wraps"

if [ "${PWMGR_STAGING_DECRYPT:-0}" = "1" ]; then
  echo "[*] gated: decrypting EVERY entry on the restored copy (pinentry will prompt)"
  for id in $(q "SELECT id FROM passwords ORDER BY id"); do
    out="$(PWMGR_CONFIG="$WORK/config.json" "$BIN" entry show "$id")" \
      || fail 35 "entry $id failed to decrypt on the restored copy"
    [ -n "$out" ] || fail 35 "entry $id decrypted to empty"
    echo "    entry $id: ok"
  done
else
  echo "[*] decrypt pass skipped (set PWMGR_STAGING_DECRYPT=1 to run it)"
fi

echo
echo "[OK] staging rehearsal passed on $SDB ($N_ENTRIES entries; prod untouched)"
