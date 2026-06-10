#!/usr/bin/env bash
# Rotate the pwmgr database password safely (docs/REMOTE.md §2 step 1,
# docs/ROTATION.md). Recommended before exposing Postgres to any network tier
# and after revoking a device (every enrolled device knows the shared
# password under the shared-role decision D3).
#
#   scripts/rotate-db-password.sh           # dry run: prints the plan only
#   scripts/rotate-db-password.sh --apply   # asks you to type the DB name
#
# What --apply does, in order:
#   1. fresh backup via scripts/backup.sh (ABORTS the rotation if it fails)
#   2. generate a 32-char alnum password (never printed, never in argv)
#   3. write the complete new ~/.pgpass line to ~/.pgpass.pending (0600)
#      BEFORE the ALTER — a crash between ALTER and the pgpass update is
#      recoverable from that file without the postgres superuser
#   4. ALTER ROLE ... PASSWORD via psql stdin (ON_ERROR_STOP)
#   5. update ~/.pgpass (dedupe + append, 0600, .bak kept) and strip any
#      password=... from db_connection in the pwmgr config (atomic, .bak)
#   6. verify SELECT 1 using only ~/.pgpass, then remove the .pending file
#
# PREREQUISITE: steps 1 and 4 authenticate with the CURRENT password — have
# PGPASSWORD set, an existing ~/.pgpass entry, or a TTY for the prompt. If
# PGPASSWORD is unset and the config's db_connection still embeds
# password=..., it is used for those two steps only.
#
# Overrides: PGHOST, PGPORT, PGUSER, PGDATABASE, PWMGR_CONFIG.
set -euo pipefail

MODE="${1:-dry-run}"
PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-pwmgr}"
PGDATABASE="${PGDATABASE:-pwmgr}"
CFG="${PWMGR_CONFIG:-$HOME/.config/pwmgr/config.json}"
PGPASS="$HOME/.pgpass"
PENDING="$PGPASS.pending"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ "$MODE" != "--apply" ]; then
  cat <<EOF
[*] DRY RUN — nothing changes. With --apply this will:
    1. back up '$PGDATABASE' via scripts/backup.sh (abort on failure)
    2. generate a new 32-char password (never shown)
    3. persist it to $PENDING (0600) before any change
    4. ALTER ROLE $PGUSER on $PGHOST:$PGPORT
    5. update $PGPASS + strip password= from $CFG
    6. verify via ~/.pgpass, then remove the .pending file
[*] Auth prerequisite: the backup and ALTER use the CURRENT password
    (PGPASSWORD, ~/.pgpass, or the config's password= token).
[*] Hygiene note: the repo-root config.json embeds a historical password=
    token for an unrelated host; this rotation does not touch it — clean it
    up separately if it bothers you.
EOF
  exit 0
fi

read -r -p "Type the database name ('$PGDATABASE') to confirm rotation: " CONFIRM
if [ "$CONFIRM" != "$PGDATABASE" ]; then
  echo "[!!] confirmation mismatch — aborted, nothing changed" >&2
  exit 1
fi

# Convenience: feed the current password from the config to backup+ALTER only.
if [ -z "${PGPASSWORD:-}" ] && [ -f "$CFG" ]; then
  OLD_PW="$(grep -oP '"db_connection"\s*:\s*"[^"]*password=\K[^ "]+' "$CFG" || true)"
  if [ -n "$OLD_PW" ]; then
    export PGPASSWORD="$OLD_PW"
  fi
fi

echo "[*] 1/6 fresh backup (abort on failure)"
PGHOST="$PGHOST" PGUSER="$PGUSER" PGDATABASE="$PGDATABASE" "$HERE/backup.sh"

echo "[*] 2/6 generating new password"
# Finite reads only: an unbounded tr</dev/urandom | head pipeline dies of
# SIGPIPE under pipefail.
NEW_PW="$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"
[ "${#NEW_PW}" -eq 32 ] || { echo "[!!] password generation failed" >&2; exit 1; }

on_abort() {
  if [ -f "$PENDING" ]; then
    echo "[!!] rotation interrupted — the NEW password line is preserved in" >&2
    echo "     $PENDING (move it into ~/.pgpass to recover)" >&2
  fi
}
trap on_abort ERR

echo "[*] 3/6 persisting recovery file $PENDING"
umask 077
printf '%s:%s:%s:%s:%s\n' "$PGHOST" "$PGPORT" "$PGDATABASE" "$PGUSER" "$NEW_PW" > "$PENDING"
chmod 600 "$PENDING"

echo "[*] 4/6 ALTER ROLE $PGUSER"
psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
     -v ON_ERROR_STOP=1 -q <<SQL
ALTER ROLE $PGUSER WITH PASSWORD '$NEW_PW';
SQL

echo "[*] 5/6 updating $PGPASS and $CFG"
touch "$PGPASS"
cp "$PGPASS" "$PGPASS.bak" && chmod 600 "$PGPASS.bak"
# Dedupe the matching host:port:db:user line, then append the new one.
grep -v "^$PGHOST:$PGPORT:$PGDATABASE:$PGUSER:" "$PGPASS.bak" > "$PGPASS.tmp" || true
cat "$PENDING" >> "$PGPASS.tmp"
chmod 600 "$PGPASS.tmp"
mv "$PGPASS.tmp" "$PGPASS"

if [ -f "$CFG" ]; then
  python3 - "$CFG" <<'PY'
import json, os, shutil, sys, re
cfg = sys.argv[1]
with open(cfg) as f:
    j = json.load(f)
conn = j.get("db_connection", "")
stripped = re.sub(r'\s*password=\S+', '', conn)
if stripped != conn:
    shutil.copy2(cfg, cfg + ".bak")
    os.chmod(cfg + ".bak", 0o600)
    j["db_connection"] = stripped
    tmp = cfg + ".tmp"
    with open(tmp, "w") as f:
        json.dump(j, f, indent=4)
    os.chmod(tmp, 0o600)
    os.replace(tmp, cfg)
    print("    password= stripped from db_connection (libpq now reads ~/.pgpass)")
else:
    print("    config carries no password= token (already clean)")
PY
else
  echo "    (no config at $CFG — skipped)"
fi

echo "[*] 6/6 verifying with ~/.pgpass only"
if env -u PGPASSWORD PGPASSFILE="$PGPASS" \
     psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
          -v ON_ERROR_STOP=1 -q -c "SELECT 1" >/dev/null; then
  rm -f "$PENDING"
  echo "[OK] password rotated; ~/.pgpass updated; recovery file removed"
  echo "[!!] other enrolled devices need the new ~/.pgpass line — hand it over"
  echo "     out-of-band (it is in $PGPASS)"
else
  echo "[!!] verification FAILED — the new password line is in $PENDING and" >&2
  echo "     $PGPASS; the .bak files preserve the previous state" >&2
  exit 1
fi
