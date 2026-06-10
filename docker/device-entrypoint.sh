#!/usr/bin/env bash
# Boot script for a simulated pwmgr device container (compose.test.yml):
# generates an EPHEMERAL no-passphrase GPG key (idempotent across restarts),
# publishes its public key + fingerprint on /shared, writes the container's
# config.json, puts `pwmgr` on PATH, drops a ready sentinel and idles.
set -euo pipefail

: "${DEVICE_NAME:?DEVICE_NAME must be set}"
export GNUPGHOME="${GNUPGHOME:-/root/.gnupg}"
mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"

# Idempotent keygen: reuse the key if a restart already made one.
FPR="$(gpg --list-keys --with-colons "$DEVICE_NAME" 2>/dev/null |
       awk -F: '/^fpr/{print $10; exit}' || true)"
if [ -z "$FPR" ]; then
  gpg --batch --generate-key <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: $DEVICE_NAME
Expire-Date: 0
%commit
EOF
  FPR="$(gpg --list-keys --with-colons "$DEVICE_NAME" |
         awk -F: '/^fpr/{print $10; exit}')"
fi
echo "[entrypoint] $DEVICE_NAME fingerprint: $FPR"

gpg --export --armor "$FPR" > "/shared/$DEVICE_NAME.pub.asc"
printf '%s\n' "$FPR" > "/shared/$DEVICE_NAME.fpr"

mkdir -p /config
cat > /config/config.json <<EOF
{
    "username": "$DEVICE_NAME",
    "device_name": "$DEVICE_NAME",
    "db_connection": "host=db port=5432 dbname=pwmgr_test user=pwmgr password=test-only",
    "private_key": {"path": "/shared/$DEVICE_NAME.pub.asc", "username": "$DEVICE_NAME"},
    "public_keys": [
        {"path": "/shared/$DEVICE_NAME.pub.asc", "username": "$DEVICE_NAME",
         "fingerprint": "$FPR"}
    ]
}
EOF
chmod 600 /config/config.json

# The harness calls a bare `pwmgr` over docker exec.
ln -sf /app/build/make/pwmgr /usr/local/bin/pwmgr

touch "/shared/$DEVICE_NAME.ready"
echo "[entrypoint] $DEVICE_NAME ready"
exec sleep infinity
