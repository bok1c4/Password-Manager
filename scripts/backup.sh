#!/usr/bin/env bash
# Backs up the pwmgr database (custom + plain SQL) and the active config to a
# directory OUTSIDE the repo. Run before any migration and on a schedule.
#
# Auth: set PGPASSWORD or use ~/.pgpass. Never hard-code the password here.
set -euo pipefail

BACKUP_DIR="${PWMGR_BACKUP_DIR:-$HOME/pwmgr-backups}"
PGHOST="${PGHOST:-localhost}"
PGUSER="${PGUSER:-pwmgr}"
PGDATABASE="${PGDATABASE:-pwmgr}"

mkdir -p "$BACKUP_DIR/config"
STAMP="$(date +%Y%m%d_%H%M%S)"

pg_dump -h "$PGHOST" -U "$PGUSER" -Fc "$PGDATABASE" \
        -f "$BACKUP_DIR/pwmgr_${STAMP}.dump"
pg_dump -h "$PGHOST" -U "$PGUSER" --no-owner "$PGDATABASE" \
        -f "$BACKUP_DIR/pwmgr_${STAMP}.sql"

CFG="${PWMGR_CONFIG:-$HOME/.config/pwmgr/config.json}"
[ -f "$CFG" ] && cp "$CFG" "$BACKUP_DIR/config/config_${STAMP}.json"

echo "[OK] DB + config backed up to $BACKUP_DIR (pwmgr_${STAMP}.dump/.sql)"
echo "[!!] The GPG SECRET key is the only decryptor and is NOT backed up here."
echo "     Export it offline once and store on encrypted media:"
echo "       gpg --export-secret-keys --armor <FINGERPRINT> > /secure/pwmgr-key.asc"
