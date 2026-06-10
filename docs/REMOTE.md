# Network Access Spec — LAN + Tor Onion Service

Status: **SPEC ONLY — nothing below has been applied.** No packages have been
installed, no configs changed, tor remains disabled. This documents exactly
what will be done in Phases 3 (LAN) and 4 (onion) of
[MULTI_DEVICE_PLAN.md](MULTI_DEVICE_PLAN.md), so it can be reviewed first.

Clearnet (WireGuard/SSH/VPS) was **dropped by decision 2026-06-10**: LAN and
onion are both completely free to run — no public IP, no port forwarding, no
rented infrastructure.

Reference: the v3 onion + client-auth model follows the Tor manual /
[Whonix Onion Services guide](https://www.whonix.org/wiki/Onion_Services).
Whonix's Gateway/Workstation VM split is Whonix-specific; on plain Arch the
same `torrc` directives apply with tor running on the host itself (§6).

---

## 0. Inventory — everything we need

### Server (this machine, Arch, hosts Postgres)
| Item | Status |
|---|---|
| `tor` ≥ 0.4.x | **already installed** (0.4.9.9), service `disabled`/`inactive` — stays off until Phase 4 execution |
| `openssl`, `python` | installed (needed by the auth-key generator) |
| PostgreSQL 18 | running, currently localhost-only (correct for the onion path) |
| TLS server cert + mini-CA (LAN tier) | to generate — `scripts/gen-db-certs.sh` (Phase 3) |
| Rotated DB password | **recommended before any network tier** — the `temp123` in git history was only ever a dummy; the real password was never committed. It does live in plaintext in the local config, so rotating it into `~/.pgpass` is good hygiene before it's shared with more devices |
| Offline backup slot for the onion identity key | same encrypted media as the GPG secret key |

### Each client device (Arch assumed; others analogous)
| Item | Status |
|---|---|
| pwmgr build deps | per README |
| Its **own** GPG keypair | generated on the device at enrollment (Phase 2) |
| `tor` | install at Phase 4 |
| `socat` (recommended) *or* `torsocks` | install at Phase 4 — libpq cannot speak SOCKS by itself |
| Its x25519 **onion client-auth keypair** | issued at enrollment (`scripts/onion-auth-keygen.sh`) |
| `ca.crt` + LAN config (Tier 1) | distributed at enrollment |

Nothing on this list is installed/changed until its phase is executed.

---

## 1. Topology

```
                        ┌──────────── server (this machine) ────────────┐
  LAN device ── wifi ──▶ <LAN-IP>:5432  (TLS + scram, subnet-scoped)    │
                        │        └──────────► PostgreSQL                │
  remote device ─ tor ─▶ xyz…onion:5432 ─ tor daemon ─► 127.0.0.1:5432  │
                        └───────────────────────────────────────────────┘
```
Both paths end at the same database. The vault payload is GPG+AES ciphertext
end-to-end regardless of transport — the network tiers only protect
credentials, metadata and availability.

---

## 2. Tier 1 — LAN (same wifi/ethernet)

Order matters; **step 1 before anything listens on a network.**

1. **Rotate the DB password** (recommended — the real password was never
   committed; only the dummy `temp123` is in git history. Rotating moves it
   out of the plaintext config and into `~/.pgpass`, sensible before it's
   shared with more devices): `ALTER ROLE pwmgr PASSWORD '<new>';` → update
   `~/.config/pwmgr/config.json` and `~/.pgpass` (0600).
2. **Mini-CA + server cert** (`scripts/gen-db-certs.sh`, Phase 3
   deliverable): CA key/cert → server cert with SAN = LAN IP/hostname →
   `server.crt`, `server.key` (0600, postgres-owned) into PGDATA;
   distribute `ca.crt` to devices.
3. `postgresql.conf`:
   ```
   listen_addresses = 'localhost, <LAN-IP>'
   ssl = on
   ```
4. `pg_hba.conf` — TLS + scram only, scoped to the subnet; no `trust`:
   ```
   hostssl  pwmgr  pwmgr  192.168.1.0/24  scram-sha-256
   ```
5. Firewall: allow tcp/5432 from the subnet only.
6. Per-device client config:
   ```
   host=<server-LAN-IP> port=5432 dbname=pwmgr user=pwmgr
   sslmode=verify-full sslrootcert=~/.config/pwmgr/ca.crt
   ```

Acceptance (Phase 5): `verify-full` connects; **plaintext refused, wrong CA
refused, wrong password refused.** Rollback: restore the two `.conf` files.

---

## 3. Tier 2 — Tor onion service

### 3.1 Server: torrc
`scripts/setup-onion.sh` (committed) appends this block idempotently and
prepares the directories — tor is only enabled with an explicit `--enable`.
The block it manages in `/etc/tor/torrc`:
```
HiddenServiceDir /var/lib/tor/pwmgr/
HiddenServiceVersion 3
HiddenServicePort 5432 127.0.0.1:5432
```
- Postgres needs **no change** for this path — it stays on 127.0.0.1; the tor
  daemon delivers connections locally.
- `HiddenServiceDir` must be owned by the `tor` user, mode **0700** (tor
  refuses to start otherwise).
- Then `systemctl enable --now tor`. Tor creates the dir, the keypair and
  `hostname` (the 56-char `.onion` address) on first start.
- A fresh address can take **up to ~30 minutes** to become reachable
  (descriptor propagation) — don't debug before that.

### 3.2 Per-device client-auth keys (the gate)
Without a valid client key a device cannot even *fetch the service
descriptor* — the service is invisible and unconnectable to everyone else.

`scripts/onion-auth-keygen.sh <device> [--onion <addr>] [--write-dir <dir>]`
(committed) generates one x25519 pair per device using only openssl + python
(both already present) and prints both lines. The recipe it implements:
```bash
openssl genpkey -algorithm x25519 -out /tmp/dev.pem
# raw private key = last 32 bytes of the DER:
openssl pkey  -in /tmp/dev.pem -outform DER          | tail -c 32 > /tmp/dev.priv
# raw public key  = last 32 bytes of the public DER:
openssl pkey  -in /tmp/dev.pem -pubout -outform DER  | tail -c 32 > /tmp/dev.pub
# base32-encode (uppercase, no padding):
python3 -c 'import base64,sys; print(base64.b32encode(open(sys.argv[1],"rb").read()).decode().rstrip("="))' /tmp/dev.pub
```
It prints two lines and securely deletes the temporaries:
- **Server side** → `/var/lib/tor/pwmgr/authorized_clients/<device>.auth`:
  ```
  descriptor:x25519:<PUBKEY_BASE32>
  ```
- **Client side** → the device keeps the private half (§3.4); the server
  never sees it.

Reload tor after adding/removing `.auth` files. **Revoking a device's onion
access = delete its `.auth` file + reload** — this slots into
`pwmgr device revoke` alongside the GPG re-wrap/rotation.

### 3.3 Back up the onion identity key — second irreplaceable secret
`/var/lib/tor/pwmgr/hs_ed25519_secret_key` **is** the address (the `.onion`
name is derived from this key; there is no seed phrase, no recovery). Losing
it means generating a new address and re-distributing it to every device.
Back up the whole `HiddenServiceDir` to the same offline/encrypted media as
the GPG secret key (extend `scripts/export-key.sh` guidance, Phase 4).

### 3.4 Client device setup
1. Install `tor` and `socat`.
2. `/etc/tor/torrc`:
   ```
   ClientOnionAuthDir /var/lib/tor/onion_auth
   ```
3. `/var/lib/tor/onion_auth/pwmgr.auth_private` (tor-owned, dir 0700):
   ```
   <56-char-addr-without-.onion>:descriptor:x25519:<PRIVKEY_BASE32>
   ```
4. `systemctl enable --now tor`.
5. **Bridge libpq → SOCKS** (libpq can't use a proxy natively):
   - **Option A — socat (recommended):** a small systemd user unit —
     template: `scripts/templates/pwmgr-onion-forward.service` (render
     instructions in its header). The forward it runs:
     ```
     socat TCP-LISTEN:5433,bind=127.0.0.1,reuseaddr,fork \
           SOCKS4A:127.0.0.1:<addr>.onion:5432,socksport=9050
     ```
     Client config: `host=localhost port=5433 dbname=pwmgr user=pwmgr`.
   - **Option B — torsocks:** `torsocks ./build/make/pwmgr` with
     `host=<addr>.onion port=5432` in the config. No extra process, but
     wraps the whole binary.

### 3.5 Postgres-side notes for the onion path
- Onion connections arrive **from 127.0.0.1** (tor hands them over locally),
  so the existing local scram rule in `pg_hba.conf` already covers them —
  and conversely, the local rule cannot distinguish tor from local. The
  gates on this path are: tor client-auth (connection), scram password (DB),
  GPG key (payload). Since scram is the only DB-level gate here, make sure
  the password is strong and unique before tor is enabled — the rotation in
  §2 step 1 is the natural moment for that.
- Postgres TLS over the onion path is **optional**: the tor rendezvous
  circuit is already end-to-end encrypted, and the onion address itself
  authenticates the server (the address *is* its public key). `sslmode`
  may be `disable` on the onion config without losing the security model.

### 3.6 Optional hardening (from the Whonix guide; not required)
- `HiddenServiceEnableIntroDoSDefense 1` — intro-point DoS rate-limiting.
- `vanguards` (AUR) — guard-discovery protection; aimed at high-value
  services, overkill for a personal vault but harmless.

---

## 4. Security model — who authenticates whom

| Layer | LAN tier | Onion tier |
|---|---|---|
| Can connect at all | subnet + firewall | tor **client-auth key** (service invisible without it) |
| Transport encryption | Postgres TLS | tor rendezvous (E2E) |
| Server authenticity | `verify-full` vs our CA | onion address **is** the server's pubkey |
| DB authentication | scram-sha-256 | scram-sha-256 |
| Vault payload | GPG+AES ciphertext | GPG+AES ciphertext |

A compromised network, a curious neighbour on the wifi, or a seized server
disk each still yield only ciphertext without a device's GPG secret key.

---

## 5. Enrollment additions (ties into Phase 2)

`pwmgr device add` (GPG re-wrap) is accompanied per device by:
1. issue x25519 onion-auth pair → `.auth` to the server dir, `.auth_private`
   stays with the device;
2. hand over: onion address, `ca.crt` (LAN), socat unit file.

`pwmgr device revoke` is accompanied by: delete the `.auth` file + reload
tor, rotate the DB password if the device knew it, and the GPG rotation the
CLI already prompts for.

---

## 6. Whonix notes — what applies to us
- The torrc directives, client-auth format, key-backup advice and the
  ~30-min propagation delay apply 1:1 to plain Arch.
- The Gateway/Workstation split (tor in one VM, the service in another, so a
  compromised service can't steal the onion key) is Whonix/Qubes-specific.
  On our single host, a Postgres-level compromise is a host-level compromise
  anyway — the split buys little for this setup and is not planned.
- Whonix's web-server hardening sections (nginx banners, OnionBalance)
  target public web onions; not applicable to a private, client-auth'd
  Postgres forward.

---

## 7. Test hooks (Phase 5 of the main plan)
- Onion positive: container with **no LAN route**, tor only + its
  `.auth_private` → connects, decrypts a test entry.
- Onion negative: same container **without** the client-auth key → cannot
  even reach the service descriptor.
- LAN negatives: plaintext, wrong-CA and wrong-password connections refused.
- Revocation: delete a device's `.auth` + reload → its next connection fails.
