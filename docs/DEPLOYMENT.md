# Deployment Guide — Exposing the Vault over LAN and Tor Onion

The full, in-depth walkthrough of both transports, end to end. The condensed
copy-paste version is [QUICKSTART_MULTI_DEVICE.md](QUICKSTART_MULTI_DEVICE.md);
the network spec behind it is [REMOTE.md](REMOTE.md).

**The mental model first:** nothing gets "deployed" anywhere and there is no
website, hosting account, domain, or port-forwarding involved. PostgreSQL stays
on your server and never moves. A Tor **onion service** is something your own
server's `tor` daemon hosts locally — Tor just gives the database an address
(`xxxx….onion`) reachable from anywhere. (Whonix is *not* needed; it's an OS
for anonymous browsing. If a client device happens to run Whonix there's a
sidebar at the end.) Every piece of software below comes from your distro's
package manager; the only download is cloning this repo onto the new device.

Prerequisite state on the **server**: repo built per the README, Postgres
running with the vault, and the vault migrated to the multi-device schema
(`./scripts/backup.sh`, then `pwmgr migrate`).

---

## Part 0 — Enroll the new device (required for BOTH variants)

Do this first, regardless of transport. The transport only moves ciphertext;
without enrollment the device can connect but decrypt nothing.

**On the new device:**

```bash
# 1. Install build deps (Arch shown; Fedora equivalents are in the README)
sudo pacman -S --needed gcc make pkgconf libpqxx postgresql-libs openssl gpgme gnupg pinentry

# 2. Get the code and build
git clone <your-repo-url> Password-Manager && cd Password-Manager
make          # -> build/make/pwmgr

# 3. Generate this device's OWN GPG key (its secret key never leaves this machine)
gpg --full-generate-key        # ECC/ed25519, SET A PASSPHRASE
gpg --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}'  # 40-char fingerprint
gpg --export --armor <FINGERPRINT> > laptop.pub.asc
```

**Move `laptop.pub.asc` to the server** (USB stick or `scp`). Then — this is
the trust root of the whole scheme — **verify the 40-character fingerprint
out-of-band**: read it aloud over a call, or compare both screens in person.
If you enroll the wrong key, you're encrypting your vault to a stranger.

**On the server:**

```bash
./build/make/pwmgr device add laptop laptop.pub.asc --fpr <FINGERPRINT>
./build/make/pwmgr device list      # both devices listed, both active
```

A fingerprint mismatch exits 3 and imports nothing. On success every existing
entry's key is re-wrapped to the new device in seconds, and every future save
from any device is automatically readable by all active devices.

---

## Part A — LAN deployment (devices on your home network)

Out of the box Postgres only listens on `127.0.0.1`. The LAN variant opens it
to your subnet, but only over TLS with certificate verification, so a laptop
on your wifi can't be tricked by an impostor database and nobody can sniff the
password.

### A1. Server: rotate the DB password (recommended)

Every enrolled device will know this password, and it may be sitting in your
config. Move it to a fresh one in `~/.pgpass`:

```bash
./scripts/rotate-db-password.sh --apply
```

This generates a strong random password, writes it to `~/.pgpass` (0600)
*before* applying the `ALTER ROLE`, then verifies login with it. After it
succeeds, remove any `password=` token from `~/.config/pwmgr/config.json`.

### A2. Server: generate the TLS certificates

Find your LAN IP first (`ip -4 addr show | grep 'inet '` — say it's
`192.168.1.50`):

```bash
./scripts/gen-db-certs.sh 192.168.1.50
```

This creates a mini-CA and a server certificate in `~/.config/pwmgr/db-certs/`
(`ca.key`, `ca.crt`, `server.key`, `server.crt`) and self-verifies them. It
deliberately does **not** touch Postgres — that's the next step, run by you as
root.

> If your server's IP can change, either give it a DHCP reservation in your
> router (recommended) or pass extra SANs:
> `./scripts/gen-db-certs.sh 192.168.1.50 myserver.lan`.

### A3. Server: install certs + open Postgres to the subnet (root, 5 steps)

On Arch, `PGDATA` is `/var/lib/postgres/data`.

```bash
# 1. install the cert pair into PGDATA, postgres-owned, key locked down
sudo install -o postgres -g postgres -m 644 ~/.config/pwmgr/db-certs/server.crt /var/lib/postgres/data/server.crt
sudo install -o postgres -g postgres -m 600 ~/.config/pwmgr/db-certs/server.key /var/lib/postgres/data/server.key

# 2. /var/lib/postgres/data/postgresql.conf — set:
#      listen_addresses = 'localhost, 192.168.1.50'
#      ssl = on

# 3. /var/lib/postgres/data/pg_hba.conf — ADD (and make sure no 'trust' lines exist):
#      hostssl  pwmgr  pwmgr  192.168.1.0/24  scram-sha-256

# 4. apply
sudo systemctl restart postgresql      # restart, not reload — listen_addresses needs it

# 5. firewall: allow 5432 from the subnet ONLY (examples)
sudo ufw allow from 192.168.1.0/24 to any port 5432 proto tcp        # ufw
# or: sudo firewall-cmd --add-rich-rule='rule family=ipv4 source address=192.168.1.0/24 port port=5432 protocol=tcp accept' --permanent && sudo firewall-cmd --reload
```

The `pg_hba.conf` line is the real gate: only the `pwmgr` user, only your
subnet, only over TLS, only with the password. Anything else is rejected
before authentication even starts.

Finally, copy `ca.crt` (just that file — it's public) to each device, and move
`ca.key` **offline** (same encrypted media as your GPG backup); it can mint
trusted server certs.

### A4. Each device: point the client at the server

```bash
mkdir -p ~/.config/pwmgr
cp /path/from/usb/ca.crt ~/.config/pwmgr/ca.crt
```

`~/.config/pwmgr/config.json` (start from `config.example.json`):

```json
{
    "username": "you",
    "device_name": "laptop",
    "db_connection": "host=192.168.1.50 port=5432 dbname=pwmgr user=pwmgr sslmode=verify-full sslrootcert=/home/you/.config/pwmgr/ca.crt",
    "public_keys": [{ "path": "/home/you/.config/pwmgr/public.asc", "username": "you", "fingerprint": "<THIS-DEVICE'S-40-CHAR-FPR>" }],
    "private_key": { "path": "", "username": "you" }
}
```

`chmod 600` it. The fingerprint must be **this device's** fingerprint, not the
server's. The DB password goes in `~/.pgpass` (mode 0600), one line:

```
192.168.1.50:5432:pwmgr:pwmgr:<password-from-A1>
```

`sslmode=verify-full` is what makes this safe on shared wifi: the device
checks the server's certificate chains to *your* CA **and** that the IP
matches the certificate's SAN.

### A5. Test the LAN path

```bash
# transport first (no GPG involved):
psql "host=192.168.1.50 port=5432 dbname=pwmgr user=pwmgr sslmode=verify-full sslrootcert=$HOME/.config/pwmgr/ca.crt" -c "select count(*) from passwords"
# then end-to-end (prompts this device's GPG passphrase):
./build/make/pwmgr entry show 1
```

If `psql` works but `pwmgr entry show` fails to decrypt, the device isn't
enrolled (Part 0) or the wrong fingerprint is in its config.

---

## Part B — Onion deployment (access from anywhere, free)

Architecture: tor on the server publishes a v3 onion service that forwards to
`127.0.0.1:5432`. **Postgres itself needs zero changes** — it keeps listening
on localhost; tor delivers remote connections as local ones. Client-side, tor
plus a tiny `socat` bridge make the onion look like `localhost:5433` to libpq.
Two locks protect it: client authorization (without your device's x25519 key
the service is *undiscoverable* — not just closed, invisible) and the scram
password on Postgres itself. The tor circuit is end-to-end encrypted, so no
TLS certs are needed on this path.

### B1. Server: create the onion service

```bash
sudo ./scripts/setup-onion.sh
```

This appends a marker-guarded block to `/etc/tor/torrc`
(`HiddenServiceDir /var/lib/tor/pwmgr/`,
`HiddenServicePort 5432 127.0.0.1:5432`) and creates
`/var/lib/tor/pwmgr/authorized_clients/` (0700, tor-owned). It does **not**
start tor.

### B2. Server: issue each device's access key — BEFORE going live

```bash
./scripts/onion-auth-keygen.sh laptop
```

It prints two lines:

- the **server line** (`descriptor:x25519:…`) — install it:

  ```bash
  echo 'descriptor:x25519:<PRINTED-PUBLIC-PART>' | sudo tee /var/lib/tor/pwmgr/authorized_clients/laptop.auth
  sudo chmod 600 /var/lib/tor/pwmgr/authorized_clients/laptop.auth
  sudo chown tor:tor /var/lib/tor/pwmgr/authorized_clients/laptop.auth
  ```

- the **client line** (`<onion>:descriptor:x25519:…`) — goes to the device in
  B4 and is **never stored on the server**. (You don't know the onion address
  yet — that's fine, the placeholder gets filled in after B3; or re-run the
  script later with `--onion <addr>` to print a ready-to-paste line. One
  keypair per device; repeat for each.)

Doing this before first start matters: once at least one `.auth` file exists,
the service descriptor is encrypted from the moment it's first published —
there is no window where the service is publicly discoverable.

### B3. Server: go live and get your address

```bash
sudo ./scripts/setup-onion.sh --enable     # runs: systemctl enable --now tor
sudo cat /var/lib/tor/pwmgr/hostname       # -> something like  vw3kj…xqd.onion
```

Two things immediately after:

1. **Back up `/var/lib/tor/pwmgr/` offline now** — `hs_ed25519_secret_key`
   *is* the address. Lose it and the address is gone forever (you'd have to
   redo B2–B4 on every device with a new one). Same encrypted media as your
   GPG secret key:

   ```bash
   sudo tar czf - -C /var/lib/tor pwmgr | gpg --encrypt -r <YOUR-FPR> > onion-identity.tar.gz.gpg
   # then move it to the offline media
   ```

2. **Wait ~30 minutes.** A fresh onion address takes that long to propagate
   through the Tor directory before clients can reach it. Don't debug
   "connection refused" before then.

### B4. Each device: tor + the bridge

```bash
sudo pacman -S tor socat        # Debian/Ubuntu: sudo apt install tor socat

# tell tor where client-auth keys live:
echo 'ClientOnionAuthDir /var/lib/tor/onion_auth' | sudo tee -a /etc/tor/torrc
sudo install -d -m 700 -o tor -g tor /var/lib/tor/onion_auth

# install the CLIENT line from B2 (with the real onion address from B3 filled in):
echo '<ONION-ADDR-WITHOUT-.onion>:descriptor:x25519:<PRIVATE-PART>' | sudo tee /var/lib/tor/onion_auth/pwmgr.auth_private
sudo chmod 600 /var/lib/tor/onion_auth/pwmgr.auth_private
sudo chown tor:tor /var/lib/tor/onion_auth/pwmgr.auth_private

sudo systemctl enable --now tor
```

(On Debian the tor user is `debian-tor` — adjust the `chown`s.)

Now the socat bridge, because libpq can't speak SOCKS. Render the committed
template as a systemd **user** unit:

```bash
mkdir -p ~/.config/systemd/user
sed -e 's/@ONION_ADDR@/<ONION-ADDR-WITHOUT-.onion>/' \
    -e 's/@LOCAL_PORT@/5433/' -e 's/@SOCKS_PORT@/9050/' \
    scripts/templates/pwmgr-onion-forward.service \
    > ~/.config/systemd/user/pwmgr-onion-forward.service
systemctl --user daemon-reload
systemctl --user enable --now pwmgr-onion-forward
```

From this device's point of view the vault is now simply `localhost:5433`.

### B5. Each device: config + test

`~/.config/pwmgr/config.json` — identical to the LAN one except the connection
string, which needs no TLS options:

```json
"db_connection": "host=localhost port=5433 dbname=pwmgr user=pwmgr"
```

`~/.pgpass` line: `localhost:5433:pwmgr:pwmgr:<password>`.

```bash
psql "host=localhost port=5433 dbname=pwmgr user=pwmgr" -c "select count(*) from passwords"
./build/make/pwmgr entry show 1
```

The first connection takes a few seconds (tor builds a circuit); after that
it's snappy enough for a CLI.

**Use both?** Keep two configs side by side and switch per invocation — LAN
at home (faster), onion when away:

```bash
PWMGR_CONFIG=~/.config/pwmgr/config.onion.json ./build/make/pwmgr
```

---

## If a client device runs Whonix

Only here does Whonix enter the picture, and only as a *client*. Whonix splits
tor onto the Gateway VM, so two things move:

- the `pwmgr.auth_private` file is installed on the **Whonix-Gateway** (it
  runs tor), not the Workstation — follow the "Onion Services Client
  Authentication" page on whonix.org for the exact directory/wizard;
- the socat bridge on the Workstation points at the Gateway's SOCKS port
  instead of localhost:
  `SOCKS4A:10.152.152.10:<onion>.onion:5432,socksport=9050`.

Everything else (config.json, `.pgpass`, enrollment) is unchanged. For
ordinary Linux laptops, plain `tor` from the distro is simpler and exactly as
secure for this purpose.

---

## The irreplaceable secrets after deployment

| Secret | Where | If lost | If stolen |
|---|---|---|---|
| Each device's GPG secret key | that device only | revoke + rotate, others still read vault | `pwmgr device revoke <name>` → type `ROTATE` |
| Onion identity (`hs_ed25519_secret_key`) | server + offline backup | address gone; redo B2–B4 everywhere | attacker can impersonate the *address* but still hits client-auth + scram + GPG |
| `ca.key` (LAN CA) | offline media | regenerate certs, redistribute `ca.crt` | attacker can impersonate the DB on LAN — keep it offline |
| DB password | `~/.pgpass` on each device | `rotate-db-password.sh --apply` | same — rotate it |

The full revocation checklist (revoke + ROTATE + delete the device's `.auth` +
`systemctl reload tor` + DB password rotation) is printed by
`pwmgr device revoke` itself and written up in
[QUICKSTART_MULTI_DEVICE.md](QUICKSTART_MULTI_DEVICE.md) §4.

One ordering note: **Part 0 → A → B** is the comfortable sequence (LAN first
lets you debug enrollment with a fast connection before adding tor's latency),
but A and B are fully independent — you can deploy onion-only and never open
Postgres to the LAN at all.
