#!/usr/bin/env bash
# Idempotent server-side Tor onion-service setup for pwmgr (docs/REMOTE.md
# §3.1). Appends the marker-guarded HiddenService block to torrc and prepares
# the HiddenServiceDir — and that is ALL it does by itself:
#
#   - tor is NEVER enabled/started unless you pass an explicit --enable
#   - if torrc / the HS dir are not writable (normal case: they are
#     root/tor-owned), it prints the exact manual commands and exits 1
#
#   scripts/setup-onion.sh [--enable]
#
# Overrides (mainly for tests): PWMGR_TORRC (default /etc/tor/torrc),
# PWMGR_HS_DIR (default /var/lib/tor/pwmgr), PWMGR_TOR_USER (default tor).
set -euo pipefail

ENABLE=0
[ "${1:-}" = "--enable" ] && ENABLE=1

TORRC="${PWMGR_TORRC:-/etc/tor/torrc}"
HS_DIR="${PWMGR_HS_DIR:-/var/lib/tor/pwmgr}"
TOR_USER="${PWMGR_TOR_USER:-tor}"
MARKER="# pwmgr onion service (managed by scripts/setup-onion.sh)"

manual_instructions() {
  cat >&2 <<EOF
[!!] $TORRC / $HS_DIR not writable by this user — run these yourself:

  sudo tee -a $TORRC >/dev/null <<'BLOCK'
$MARKER
HiddenServiceDir $HS_DIR/
HiddenServiceVersion 3
HiddenServicePort 5432 127.0.0.1:5432
BLOCK
  sudo install -d -m 700 -o $TOR_USER -g $TOR_USER $HS_DIR $HS_DIR/authorized_clients
  # per-device .auth files go into $HS_DIR/authorized_clients/ (onion-auth-keygen.sh)
  sudo systemctl enable --now tor      # ONLY when you decide to go live
  sudo cat $HS_DIR/hostname            # the .onion address (~30 min to propagate)
EOF
}

# Writability gate with explicit grouping; a nonexistent torrc counts as
# writable when its parent directory is (creatable).
torrc_writable() {
  if [ -e "$TORRC" ]; then
    [ -w "$TORRC" ]
  else
    [ -w "$(dirname "$TORRC")" ]
  fi
}
hsdir_writable() {
  if [ -e "$HS_DIR" ]; then
    [ -w "$HS_DIR" ]
  else
    [ -w "$(dirname "$HS_DIR")" ]
  fi
}
if ! torrc_writable || ! hsdir_writable; then
  manual_instructions
  exit 1
fi

[ -e "$TORRC" ] || : > "$TORRC"

if grep -qF "$MARKER" "$TORRC"; then
  echo "[OK] torrc block already present (marker found) — not appending again"
else
  cat >> "$TORRC" <<EOF
$MARKER
HiddenServiceDir $HS_DIR/
HiddenServiceVersion 3
HiddenServicePort 5432 127.0.0.1:5432
EOF
  echo "[OK] HiddenService block appended to $TORRC"
fi

mkdir -p "$HS_DIR/authorized_clients"
chmod 700 "$HS_DIR" "$HS_DIR/authorized_clients"
if [ "$(id -u)" -eq 0 ] && id -u "$TOR_USER" >/dev/null 2>&1; then
  chown -R "$TOR_USER:$TOR_USER" "$HS_DIR"
else
  echo "[!!] make sure $HS_DIR is owned by the '$TOR_USER' user (mode 0700)" >&2
  echo "     or tor will refuse to start:  sudo chown -R $TOR_USER:$TOR_USER $HS_DIR" >&2
fi

if [ "$ENABLE" -eq 1 ]; then
  echo "[*] --enable given: enabling tor"
  systemctl enable --now tor
else
  echo "[*] tor NOT touched (pass --enable when you decide to go live):"
  echo "      sudo systemctl enable --now tor"
fi

if [ -f "$HS_DIR/hostname" ]; then
  echo "[OK] onion address: $(cat "$HS_DIR/hostname")"
else
  echo "[*] tor creates $HS_DIR/hostname (the .onion address) on first start;"
  echo "    a fresh address can take ~30 min to become reachable."
fi

cat <<EOF
[!!] BACK UP $HS_DIR/hs_ed25519_secret_key OFFLINE once it exists — it IS the
    onion address (no recovery; same encrypted media as the GPG secret key).
EOF
