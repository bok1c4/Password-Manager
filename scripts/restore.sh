#!/usr/bin/env bash
# Safe restore. By default restores into a THROWAWAY database so you can verify
# before touching production. Only restores over the real DB when the second
# arg is the literal word PRODUCTION (and you confirm the db name).
#
#   scripts/restore.sh <dump-file>              # -> pwmgr_restore_test
#   scripts/restore.sh <dump-file> PRODUCTION   # -> real DB (destructive)
set -euo pipefail

DUMP="${1:?usage: restore.sh <dump-file> [PRODUCTION]}"
MODE="${2:-throwaway}"
PGHOST="${PGHOST:-localhost}"
PGUSER="${PGUSER:-pwmgr}"
PGDATABASE="${PGDATABASE:-pwmgr}"

if [ "$MODE" != "PRODUCTION" ]; then
  TDB="pwmgr_restore_test"
  echo "[*] Restoring into throwaway DB '$TDB' (needs CREATEDB privilege)."
  dropdb -h "$PGHOST" -U "$PGUSER" --if-exists "$TDB"
  createdb -h "$PGHOST" -U "$PGUSER" "$TDB"
  pg_restore -h "$PGHOST" -U "$PGUSER" -d "$TDB" "$DUMP"
  echo "[OK] Restored to '$TDB'. Verify (and run the compat decrypt test) before"
  echo "     re-running with PRODUCTION."
else
  read -r -p "Type the production DB name ('$PGDATABASE') to confirm: " CONFIRM
  [ "$CONFIRM" = "$PGDATABASE" ] || { echo "Aborted."; exit 1; }
  pg_restore -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" --clean --if-exists "$DUMP"
  echo "[OK] Restored over production '$PGDATABASE'."
fi
