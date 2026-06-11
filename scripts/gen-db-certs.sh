#!/usr/bin/env bash
# Mini-CA + PostgreSQL server certificate for the LAN tier (docs/DEPLOYMENT.md §A2).
#
#   scripts/gen-db-certs.sh <lan-ip-or-hostname> [extra-san ...]
#
# Writes into $PWMGR_CERT_DIR (default ~/.config/pwmgr/db-certs):
#   ca.key (0600)  ca.crt (0644)  server.key (0600)  server.crt (0644)
#
# This script only GENERATES files — installing them into PGDATA, editing
# postgresql.conf/pg_hba.conf and the firewall need root and are printed as
# instructions at the end, never executed. Re-running with a complete set
# already present is a no-op (exit 0); a PARTIAL set is refused (exit 1) so a
# half-generated state can never be silently mixed with a fresh one.
#
# Overrides: PWMGR_CERT_DIR, PWMGR_CA_DAYS (default 3650), PWMGR_SRV_DAYS
# (default 825).
set -euo pipefail

HOST="${1:?usage: gen-db-certs.sh <lan-ip-or-hostname> [extra-san ...]}"
shift
EXTRA_SANS=("$@")

CERT_DIR="${PWMGR_CERT_DIR:-$HOME/.config/pwmgr/db-certs}"
CA_DAYS="${PWMGR_CA_DAYS:-3650}"
SRV_DAYS="${PWMGR_SRV_DAYS:-825}"

FILES=(ca.key ca.crt server.key server.crt)
present=0
for f in "${FILES[@]}"; do
  [ -e "$CERT_DIR/$f" ] && present=$((present + 1))
done
if [ "$present" -eq "${#FILES[@]}" ]; then
  echo "[OK] complete cert set already present in $CERT_DIR — nothing to do"
  exit 0
fi
if [ "$present" -gt 0 ]; then
  echo "[!!] PARTIAL cert set in $CERT_DIR ($present/${#FILES[@]} files)." >&2
  echo "     Refusing to mix old and new material. Move the directory away" >&2
  echo "     and re-run." >&2
  exit 1
fi

# IP: vs DNS: SAN typing.
san_for() {
  if [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "IP:$1"
  else
    echo "DNS:$1"
  fi
}
SAN="$(san_for "$HOST")"
for s in ${EXTRA_SANS[@]+"${EXTRA_SANS[@]}"}; do
  SAN="$SAN,$(san_for "$s")"
done

umask 077
mkdir -p "$CERT_DIR"

echo "[*] generating mini-CA (RSA-3072, $CA_DAYS days)"
openssl req -x509 -newkey rsa:3072 -nodes -days "$CA_DAYS" \
  -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
  -subj "/CN=pwmgr-db-ca" >/dev/null 2>&1

echo "[*] generating server key + CSR (CN=$HOST, SAN=$SAN)"
openssl req -newkey rsa:3072 -nodes \
  -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
  -subj "/CN=$HOST" >/dev/null 2>&1

EXT="$(mktemp)"
trap 'rm -f "$EXT" "$CERT_DIR/server.csr"' EXIT
printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' "$SAN" > "$EXT"

echo "[*] signing server cert ($SRV_DAYS days)"
openssl x509 -req -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -days "$SRV_DAYS" -extfile "$EXT" -out "$CERT_DIR/server.crt" >/dev/null 2>&1
rm -f "$CERT_DIR/ca.srl"

chmod 600 "$CERT_DIR/ca.key" "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt"

echo "[*] self-check: openssl verify"
openssl verify -CAfile "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt" >/dev/null
echo "[OK] certs written to $CERT_DIR"

cat <<EOF

[!!] ca.key signs new server certs — move it OFFLINE (same media as the GPG
     secret key) once you are done issuing.

Next steps (root needed — run them yourself; this script never does):
  0. Rotate the DB password first (recommended): scripts/rotate-db-password.sh
  1. install server.crt/server.key into PGDATA, owned by postgres, key 0600:
       sudo install -o postgres -g postgres -m 644 $CERT_DIR/server.crt \$PGDATA/server.crt
       sudo install -o postgres -g postgres -m 600 $CERT_DIR/server.key \$PGDATA/server.key
  2. postgresql.conf:  listen_addresses = 'localhost, $HOST'
                       ssl = on
  3. pg_hba.conf:      hostssl pwmgr pwmgr <your-subnet>/24 scram-sha-256
                       (no 'trust' lines; reload after editing)
  4. reload:           sudo systemctl reload postgresql
  5. firewall:         allow tcp/5432 from the subnet only
  6. distribute ca.crt to each device:
       client config: sslmode=verify-full sslrootcert=~/.config/pwmgr/ca.crt
EOF
