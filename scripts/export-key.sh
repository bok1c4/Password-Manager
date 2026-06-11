#!/usr/bin/env bash
# =============================================================================
#  pwmgr — GPG SECRET-KEY OFFLINE BACKUP  (the single irreplaceable asset)
# =============================================================================
#  Every password in the vault is encrypted to GPG key
#  29974BE04FCC7C31C4D1493730D6A019C21A600C. The matching SECRET key is the ONLY
#  thing that can decrypt your data. If it is ever lost, the DB rows (and your
#  backups of them) become permanently unrecoverable. Back it up OFF this disk.
#
#  USAGE
#    scripts/export-key.sh --help              # print this guide, do nothing
#    scripts/export-key.sh <destination-file>  # export the secret key there
#
#    Example (straight onto a mounted USB, never touching the local disk):
#      scripts/export-key.sh /run/media/$USER/MYUSB/pwmgr-secret.asc
#
#  STEP-BY-STEP GUIDE
#    1. Choose a destination that is OFF this machine (mounted USB, etc.). One
#       copy on the same disk as the vault is NOT a backup.
#    2. Run this script with that destination. You WILL be prompted for your key
#       passphrase by pinentry — only you can enter it (that is why you run this,
#       not the agent). Run it in a real terminal, or in Claude with the `!`
#       prefix so the prompt reaches you.
#    3. The output .asc is ALREADY encrypted with your key passphrase — it is not
#       a plaintext key — but still treat it as the crown jewels.
#    4. Make a SECOND, independent copy (different medium/place): a printed
#       paperkey, a second USB, or an encrypted cloud note. Aim for 2 copies in
#       2 places.
#    5. Verify the backup actually restores, WITHOUT touching your real keyring:
#         GNUPGHOME=$(mktemp -d) gpg --import <destination-file> && echo RESTORABLE
#    6. If you exported to a temporary local file, remove it once it is safely
#       copied off-machine:  shred -u <destination-file>
#
#  DISASTER RECOVERY (how you'd actually use this backup later)
#    On a fresh machine: gpg --import <your-backup.asc>  (enter the passphrase
#    when first decrypting), then restore the DB from pwmgr-backups and run the
#    app. Without this key the restored rows are ciphertext you cannot open.
#
#  SECOND IRREPLACEABLE SECRET (once the Tor onion service is set up)
#    /var/lib/tor/pwmgr/hs_ed25519_secret_key IS the onion address — there is
#    no seed phrase and no recovery; losing it means a new address rolled out
#    to every device. Back up the whole HiddenServiceDir to the SAME offline
#    encrypted media as this GPG key (docs/DEPLOYMENT.md §B3):
#      sudo tar czf /run/media/$USER/MYUSB/pwmgr-onion-dir.tgz /var/lib/tor/pwmgr
#
#  PAPER BACKUP (optional, survives dead drives)
#    gpg --export-secret-keys 29974BE04FCC7C31C4D1493730D6A019C21A600C \
#      | paperkey | lpr            # prints; store the paper physically & safely
# =============================================================================
set -euo pipefail

FPR="${PWMGR_FPR:-29974BE04FCC7C31C4D1493730D6A019C21A600C}"

guide() {
  # Print the header guide block (the commented lines between the banner lines).
  sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'
}

case "${1:-}" in
  -h|--help|help|guide|"")
    guide
    [ -z "${1:-}" ] && {
      echo
      echo ">> No destination given. Re-run with a path, ideally on removable media:"
      echo "   scripts/export-key.sh /run/media/\$USER/MYUSB/pwmgr-secret.asc"
    }
    exit 0
    ;;
esac

DEST="$1"
umask 077  # 0600 on the output

echo "[*] Exporting secret key $FPR"
echo "[*] You will be asked for your key passphrase (pinentry)..."
gpg --export-secret-keys --armor "$FPR" > "$DEST"

echo
echo "[OK] Secret key written to: $DEST"
echo "[!!] Next steps (see 'scripts/export-key.sh --help' for the full guide):"
echo "     1. Get a copy OFF this machine (USB / paperkey / encrypted cloud)."
echo "     2. Verify it restores:"
echo "          GNUPGHOME=\$(mktemp -d) gpg --import \"$DEST\" && echo RESTORABLE"
echo "     3. If this was a temp/local file, shred it after copying off:"
echo "          shred -u \"$DEST\""
