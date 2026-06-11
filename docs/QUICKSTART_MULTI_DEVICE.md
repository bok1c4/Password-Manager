# Quick Guide — Using the Vault Across Devices (LAN + Tor Onion)

This is the condensed, copy-paste version. Full background:
[MULTI_DEVICE_PLAN.md](MULTI_DEVICE_PLAN.md) (design),
[REMOTE.md](REMOTE.md) (network details), [USAGE.md](USAGE.md) (daily use).

**The model:** one machine (the **server**) runs PostgreSQL and holds the
vault — ciphertext only. Every **device** (laptop, second PC, …) runs the
`pwmgr` CLI with its **own GPG key** and connects to that one database:
over the **LAN** when at home, over a **Tor onion service** from anywhere.
The database never sees a plaintext password; stealing it yields nothing
without a device's GPG secret key.

```
 device A ── wifi ────▶ <server-LAN-IP>:5432 (TLS + password)  ┐
                                                               ├▶ PostgreSQL
 device B ── tor  ────▶ xyz….onion:5432 ─▶ 127.0.0.1:5432      ┘  (ciphertext)
```

---

## 0. Prerequisites

| Where | What |
|---|---|
| Server | this repo set up per the README (Postgres running, `pwmgr` built, vault migrated: `pwmgr migrate` — take `./scripts/backup.sh` first) |
| Each device | build deps per README (`gcc make pkgconf libpqxx openssl gpgme gnupg pinentry`), this repo cloned + `make` |
| Each device (onion only) | `tor` and `socat` installed |

---

## 1. Enroll a new device (once per device — needed for BOTH transports)

**On the new device** — generate its own key (the secret key never leaves it):

```bash
gpg --full-generate-key      # ECC/ed25519 is fine; SET A PASSPHRASE
gpg --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}'   # its 40-char fingerprint
gpg --export --armor <FINGERPRINT> > mydevice.pub.asc
```

Copy `mydevice.pub.asc` to the server (USB stick or `scp`).

> **Verify the 40-character fingerprint out-of-band** — read it aloud /
> compare both screens. This is the trust root of the whole scheme; a wrong
> key here means encrypting the vault to a stranger.

**On the server:**

```bash
./build/make/pwmgr device add mydevice mydevice.pub.asc --fpr <FINGERPRINT>
```

This registers the device and re-wraps every entry's key to it (seconds; a
fingerprint mismatch enrolls nothing and exits 3). Check with
`pwmgr device list`. From now on, every save from any device is readable by
all active devices.

---

## 2. LAN connection (devices on the same wifi/ethernet)

### Server, one time

```bash
./scripts/rotate-db-password.sh --apply      # recommended: password moves into ~/.pgpass
./scripts/gen-db-certs.sh <SERVER-LAN-IP>    # mini-CA + server certificate
```

The cert script prints the root steps it never runs itself — do them:

1. install `server.crt` / `server.key` into PGDATA (postgres-owned, key 0600)
2. `postgresql.conf`: `listen_addresses = 'localhost, <SERVER-LAN-IP>'` and `ssl = on`
3. `pg_hba.conf`: `hostssl pwmgr pwmgr 192.168.1.0/24 scram-sha-256` (your subnet; no `trust` lines)
4. `sudo systemctl reload postgresql`
5. firewall: allow tcp/5432 **from the subnet only**

Copy `ca.crt` to each device.

### Each device

`~/.config/pwmgr/config.json` (start from `config.example.json`):

```json
{
    "username": "you",
    "device_name": "mydevice",
    "db_connection": "host=<SERVER-LAN-IP> port=5432 dbname=pwmgr user=pwmgr sslmode=verify-full sslrootcert=/home/you/.config/pwmgr/ca.crt",
    "public_keys": [{ "path": "...", "username": "you", "fingerprint": "<THIS-DEVICE'S-FPR>" }],
    "private_key": { "path": "...", "username": "you" }
}
```

DB password goes in `~/.pgpass` (mode 0600):
`<SERVER-LAN-IP>:5432:pwmgr:pwmgr:<password>` — get it from the server admin
out-of-band. `sslmode=verify-full` makes the device cryptographically verify
it is talking to *your* server, not an impostor on the wifi.

Test: `./build/make/pwmgr entry show 1` → prompts your GPG passphrase →
prints the password. Done.

---

## 3. Onion connection (from anywhere; free, no port-forwarding)

### Server, one time

```bash
sudo ./scripts/setup-onion.sh            # torrc block + dirs; does NOT start tor
sudo ./scripts/setup-onion.sh --enable   # when ready to go live
sudo cat /var/lib/tor/pwmgr/hostname     # your .onion address (~30 min until reachable)
```

Postgres needs **no changes** — it stays on localhost; tor delivers
connections locally.

> **Back up `/var/lib/tor/pwmgr/` offline immediately** (same media as the
> GPG secret key). `hs_ed25519_secret_key` IS the address — no recovery.

### Per device: issue its access key (on the server)

```bash
./scripts/onion-auth-keygen.sh mydevice --onion <ONION-ADDR-WITHOUT-.onion>
```

- the printed **server line** → `/var/lib/tor/pwmgr/authorized_clients/mydevice.auth`,
  then `sudo systemctl reload tor`
- the printed **client line** → goes to the device (next step), never stored
  on the server

Without this key the service is *invisible* — others cannot even discover it
exists.

### Each device

```bash
sudo pacman -S tor socat                                  # or your distro's equivalent
echo 'ClientOnionAuthDir /var/lib/tor/onion_auth' | sudo tee -a /etc/tor/torrc
sudo install -d -m 700 -o tor -g tor /var/lib/tor/onion_auth
# put the client line into /var/lib/tor/onion_auth/pwmgr.auth_private (0600, tor-owned)
sudo systemctl enable --now tor
```

Bridge libpq → tor with the socat user unit (libpq can't speak SOCKS):

```bash
sed -e 's/@ONION_ADDR@/<ONION-ADDR>/' -e 's/@LOCAL_PORT@/5433/' -e 's/@SOCKS_PORT@/9050/' \
    scripts/templates/pwmgr-onion-forward.service \
    > ~/.config/systemd/user/pwmgr-onion-forward.service
systemctl --user daemon-reload && systemctl --user enable --now pwmgr-onion-forward
```

Onion config is then simply:

```
host=localhost port=5433 dbname=pwmgr user=pwmgr
```

(`~/.pgpass` line: `localhost:5433:pwmgr:pwmgr:<password>`.) No TLS needed —
tor's circuit is end-to-end encrypted and the address authenticates the
server. Tip: keep `config.lan.json` and `config.onion.json` side by side and
switch with `PWMGR_CONFIG=~/.config/pwmgr/config.onion.json pwmgr`.

---

## 4. Daily use & revocation

- Any device: `pwmgr` (menu) or `pwmgr entry show <id>` / `entry add --note …`.
  Saves are automatically encrypted to **all** active devices.
- Device lost/stolen — from any other device:

  ```bash
  pwmgr device revoke mydevice        # prompts rotation: type ROTATE (do it)
  ```

  then finish the printed checklist: delete its `.auth` file on the server +
  `sudo systemctl reload tor`, and rotate the DB password
  (`./scripts/rotate-db-password.sh --apply`) — every enrolled device knows it.
- A revoked name cannot be re-enrolled; a returning device gets a fresh key
  and a new name.

## 5. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `connection refused` on LAN | `listen_addresses` / firewall / wrong IP |
| `no pg_hba.conf entry` | subnet line missing, or connecting without TLS |
| certificate verify failed | wrong/missing `ca.crt`, or `host=` ≠ the SAN in the cert |
| onion never connects | wait ~30 min after first start; check `.auth_private` perms (tor-owned, dir 0700); `systemctl --user status pwmgr-onion-forward` |
| decrypt fails on a device | that device isn't enrolled (`pwmgr device list`), or wrong GPG key/passphrase |
| `device tables not migrated` | run `pwmgr migrate` on the server (after `./scripts/backup.sh`) |
