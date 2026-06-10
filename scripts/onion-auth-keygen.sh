#!/usr/bin/env bash
# Generate one x25519 Tor v3 client-authorization keypair per device
# (docs/REMOTE.md §3.2). Needs only openssl + python3. Prints two lines:
#
#   server side -> /var/lib/tor/pwmgr/authorized_clients/<device>.auth
#   client side -> /var/lib/tor/onion_auth/pwmgr.auth_private  (the device
#                  keeps the private half; the server NEVER sees it)
#
#   scripts/onion-auth-keygen.sh <device-name> [--onion <56-char-addr>]
#                                [--write-dir <dir>]
#
# --onion fills the address into the client line (else a placeholder).
# --write-dir additionally writes <device>.auth / <device>.auth_private
# (0600) into <dir> for hand-over; move them, then shred your copies.
# This script never touches /var/lib/tor or systemctl — installing the files
# is printed as instructions.
set -euo pipefail

usage() {
  echo "usage: onion-auth-keygen.sh <device-name> [--onion <addr>] [--write-dir <dir>]" >&2
  exit 2
}

[ $# -ge 1 ] || usage
DEVICE="$1"
shift
# Reject a leading dash so an omitted name cannot silently consume a flag.
[[ "$DEVICE" =~ ^[A-Za-z0-9._][A-Za-z0-9._-]*$ ]] || {
  echo "[!!] invalid device name '$DEVICE'" >&2
  usage
}

ONION="<56-char-onion-addr-without-.onion>"
WRITE_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --onion) ONION="${2:?--onion needs a value}"; shift 2 ;;
    --write-dir) WRITE_DIR="${2:?--write-dir needs a value}"; shift 2 ;;
    *) usage ;;
  esac
done

umask 077
TMP="$(mktemp -d "${TMPDIR:-/tmp}/onion-keygen.XXXXXX")"
cleanup() {
  # Shred the raw key material; best-effort on filesystems without shred.
  for f in "$TMP"/dev.pem "$TMP"/dev.priv "$TMP"/dev.pub; do
    [ -f "$f" ] && shred -u "$f" 2>/dev/null || rm -f "$f"
  done
  rmdir "$TMP" 2>/dev/null || rm -rf "$TMP"
}
trap cleanup EXIT

openssl genpkey -algorithm x25519 -out "$TMP/dev.pem" 2>/dev/null
# Raw keys are the last 32 bytes of the DER encodings.
openssl pkey -in "$TMP/dev.pem" -outform DER 2>/dev/null | tail -c 32 > "$TMP/dev.priv"
openssl pkey -in "$TMP/dev.pem" -pubout -outform DER 2>/dev/null | tail -c 32 > "$TMP/dev.pub"

b32() {  # unpadded uppercase base32 of a 32-byte file
  python3 -c 'import base64,sys; print(base64.b32encode(open(sys.argv[1],"rb").read()).decode().rstrip("="))' "$1"
}
PUB_B32="$(b32 "$TMP/dev.pub")"
PRIV_B32="$(b32 "$TMP/dev.priv")"

AUTH_LINE="descriptor:x25519:$PUB_B32"
PRIV_LINE="$ONION:descriptor:x25519:$PRIV_B32"

echo "[OK] x25519 client-auth pair for '$DEVICE'"
echo
echo "SERVER -> /var/lib/tor/pwmgr/authorized_clients/$DEVICE.auth :"
echo "  $AUTH_LINE"
echo
echo "CLIENT -> /var/lib/tor/onion_auth/pwmgr.auth_private (dir 0700, tor-owned):"
echo "  $PRIV_LINE"

if [ -n "$WRITE_DIR" ]; then
  mkdir -p "$WRITE_DIR"
  printf '%s\n' "$AUTH_LINE" > "$WRITE_DIR/$DEVICE.auth"
  printf '%s\n' "$PRIV_LINE" > "$WRITE_DIR/$DEVICE.auth_private"
  chmod 600 "$WRITE_DIR/$DEVICE.auth" "$WRITE_DIR/$DEVICE.auth_private"
  echo
  echo "[OK] written to $WRITE_DIR/ (0600) — MOVE them to their destinations,"
  echo "     then shred your copies: shred -u $WRITE_DIR/$DEVICE.auth_private"
fi

cat <<EOF

Install steps (root; this script never does them):
  server: sudo install -m 600 $DEVICE.auth /var/lib/tor/pwmgr/authorized_clients/
          sudo systemctl reload tor
  client: /etc/tor/torrc gets:  ClientOnionAuthDir /var/lib/tor/onion_auth
          install the .auth_private there (dir 0700, tor-owned), reload tor,
          render the socat unit from scripts/templates/pwmgr-onion-forward.service
EOF
