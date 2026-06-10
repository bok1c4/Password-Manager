#!/usr/bin/env bash
# Tier-1 LAN TLS acceptance tests (REMOTE.md §2) on a throwaway docker rig:
#   41 plaintext connection refused
#   42 wrong CA refused under verify-full
#   43 wrong password refused (TLS fine, scram fails)
#   44 verify-full + correct password connects (psql positive control)
#   45 the pwmgr client path itself connects with verify-full (skipped with a
#      notice if the pwmgr-test:local image is absent — build it via
#      `make test-devices`)
# Ends with the MANUAL-ONLY onion checklist (tor is never enabled by tests).
#
#   make test-net      (infra failures exit 20; PWMGR_KEEP=1 keeps the rig up)
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
export PWMGR_NET_DIR="${PWMGR_NET_DIR:-$(mktemp -d /tmp/pwmgr_net_test.XXXXXX)}"
COMPOSE=(docker compose -f "$HERE/docker/compose.net.yml")

cleanup() {
  if [ "${PWMGR_KEEP:-0}" != "1" ]; then
    "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
    rm -rf "$PWMGR_NET_DIR"
  else
    echo "[*] PWMGR_KEEP=1 — rig left up; certs in $PWMGR_NET_DIR"
  fi
}
trap cleanup EXIT

fail() { echo "[FAIL] $2" >&2; exit "$1"; }

echo "[*] generating server certs (SAN db-tls) + a WRONG CA into $PWMGR_NET_DIR"
PWMGR_CERT_DIR="$PWMGR_NET_DIR/server" "$HERE/scripts/gen-db-certs.sh" db-tls >/dev/null
mkdir -p "$PWMGR_NET_DIR/client"
cp "$PWMGR_NET_DIR/server/ca.crt" "$PWMGR_NET_DIR/client/ca.crt"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout /dev/null -out "$PWMGR_NET_DIR/client/wrong-ca.crt" \
  -subj "/CN=not-our-ca" >/dev/null 2>&1

# hostssl-only over TCP (the assertion); local trust for the image's init.
cat > "$PWMGR_NET_DIR/server/pg_hba.conf" <<'EOF'
local   all all                trust
hostssl all all 0.0.0.0/0      scram-sha-256
hostssl all all ::0/0          scram-sha-256
EOF

# The postgres process (uid 999 in the image) must own the 0600 server.key.
docker run --rm -v "$PWMGR_NET_DIR/server":/c alpine \
  sh -c 'chown 999:999 /c/server.key /c/pg_hba.conf && chmod 600 /c/server.key && chmod 644 /c/pg_hba.conf' \
  || fail 20 "cert ownership one-shot failed"
chmod 755 "$PWMGR_NET_DIR" "$PWMGR_NET_DIR/server" "$PWMGR_NET_DIR/client"
chmod 644 "$PWMGR_NET_DIR/client"/*.crt "$PWMGR_NET_DIR/server"/ca.crt "$PWMGR_NET_DIR/server"/server.crt

echo "[*] bringing up the TLS rig"
"${COMPOSE[@]}" up -d --wait db-tls client 2>/dev/null \
  || "${COMPOSE[@]}" up -d db-tls client || fail 20 "compose up failed"
for _ in $(seq 1 30); do
  "${COMPOSE[@]}" exec -T db-tls pg_isready -h 127.0.0.1 -U pwmgr -d pwmgr_net_test >/dev/null 2>&1 && break
  sleep 2
done

cpsql() { # <extra-conninfo> <password>
  "${COMPOSE[@]}" exec -T -e PGPASSWORD="$2" client \
    psql "host=db-tls port=5432 dbname=pwmgr_net_test user=pwmgr $1" \
    -tAc "SELECT 1" 2>/dev/null
}

echo "[*] 41: plaintext refused"
if cpsql "sslmode=disable" "net-test-pw" >/dev/null; then
  fail 41 "PLAINTEXT connection was accepted"
fi
echo "    refused — ok"

echo "[*] 42: wrong CA refused under verify-full"
if cpsql "sslmode=verify-full sslrootcert=/certs/wrong-ca.crt" "net-test-pw" >/dev/null; then
  fail 42 "verify-full accepted a cert signed by the WRONG CA"
fi
echo "    refused — ok"

echo "[*] 43: wrong password refused"
if cpsql "sslmode=verify-full sslrootcert=/certs/ca.crt" "wrong-password" >/dev/null; then
  fail 43 "scram accepted a wrong password"
fi
echo "    refused — ok"

echo "[*] 44: verify-full + correct password connects (psql)"
out="$(cpsql "sslmode=verify-full sslrootcert=/certs/ca.crt" "net-test-pw")" \
  || fail 44 "positive control failed"
[ "$out" = "1" ] || fail 44 "positive control returned '$out'"
echo "    connected — ok"

echo "[*] 45: pwmgr client path with verify-full"
if docker image inspect pwmgr-test:local >/dev/null 2>&1; then
  CFG_DIR="$PWMGR_NET_DIR/pwmgr-cfg"
  mkdir -p "$CFG_DIR"
  cat > "$CFG_DIR/config.json" <<EOF
{"username":"net-test","device_name":"net-test",
 "db_connection":"host=db-tls port=5432 dbname=pwmgr_net_test user=pwmgr password=net-test-pw sslmode=verify-full sslrootcert=/certs/ca.crt",
 "private_key":{"path":"/config/config.json","username":"net-test"},
 "public_keys":[{"path":"/config/config.json","username":"net-test",
  "fingerprint":"29974BE04FCC7C31C4D1493730D6A019C21A600C"}]}
EOF
  NET="$(docker inspect "$("${COMPOSE[@]}" ps -q db-tls)" \
         --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}')"
  docker run --rm --network "$NET" \
    -v "$CFG_DIR":/config -v "$PWMGR_NET_DIR/client":/certs:ro \
    -e PWMGR_CONFIG=/config/config.json \
    pwmgr-test:local migrate >/dev/null \
    || fail 45 "pwmgr migrate over verify-full TLS failed"
  echo "    pwmgr migrate over TLS — ok (throwaway pwmgr_net_test)"
else
  echo "    SKIPPED: pwmgr-test:local image absent (build via make test-devices)"
fi

cat <<'EOF'

[OK] Tier-1 TLS assertions passed (41-45).

Manual-only checks (tests never enable tor; do these at Phase-4 go-live):
  - onion positive: a device with only tor + its .auth_private connects
  - onion negative: without the .auth_private the descriptor is unreachable
  - revocation: delete a device's .auth + `systemctl reload tor` -> next
    connection fails
  - physical-LAN end-to-end from a second machine with verify-full
EOF
