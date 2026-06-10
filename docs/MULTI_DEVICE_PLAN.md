# Multi-Device Password Sharing — Design & Rollout Plan

Status: **PLANNED, not implemented.** Nothing below has been applied to the
production vault. A fresh backup was taken before planning
(`~/pwmgr-backups/pwmgr_20260610_140555.dump`).

---

## 1. Why the current design makes this easy

Every entry is already encrypted with its **own random AES-256 key**, and that
AES key is GPG-wrapped to a recipient fingerprint (`passwords.aes_key`). The
password ciphertext itself never changes when you add a reader — you only add
**another wrap of the same AES key** for another public key.

So "group encryption" here = **per-device key wrapping**:

```
                       password ciphertext  (v1 CBC / v2 GCM — UNCHANGED)
                              ▲
                              │ AES-256 key K (random, per entry)
            ┌─────────────────┼──────────────────┐
   GPG(K → laptop fpr)  GPG(K → desktop fpr)  GPG(K → phone fpr)
        row in              row in               row in
     password_keys       password_keys        password_keys
```

The server/DB only ever stores ciphertext. A device that holds one of the GPG
secret keys can unwrap K and decrypt. **DB compromise alone reveals nothing**
— this E2E property holds on localhost, LAN and onion alike, which
is what makes the transport tiers below low-risk.

### Considered and rejected: OpenPGP multi-recipient blobs
GPG can encrypt one blob to N recipients (multiple PKESK packets). Fewer rows,
but: no visible access matrix in the DB, adding/removing a device rewrites the
blob for *every* row anyway, and revocation is invisible. Per-device rows give
an auditable access matrix and (for free) future *selective* sharing — a given
entry shared with only some devices.

---

## 2. Schema (additive only — the standing invariant)

The 13 existing v1 rows must stay decryptable at every step. Therefore:
`passwords` is **never altered or rewritten**; `passwords.aes_key` is kept
untouched as the legacy fallback wrap for the founding device.

```sql
-- Registered devices ("device usernames" + their public keys)
CREATE TABLE IF NOT EXISTS devices (
    id           bigserial PRIMARY KEY,
    name         text   UNIQUE NOT NULL,          -- e.g. "arch-laptop"
    fingerprint  char(40) UNIQUE NOT NULL,        -- full GPG fingerprint
    public_key   text   NOT NULL,                 -- armored public key
    status       text   NOT NULL DEFAULT 'active',-- 'active' | 'revoked'
    enrolled_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz
);

-- Access matrix: one wrapped AES key per (entry, device)
CREATE TABLE IF NOT EXISTS password_keys (
    password_id  bigint NOT NULL REFERENCES passwords(id) ON DELETE CASCADE,
    device_id    bigint NOT NULL REFERENCES devices(id),
    wrapped_key  bytea  NOT NULL,                 -- GPG(K → that device)
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (password_id, device_id)
);
```

**Backfill (idempotent, copies — never moves):**
1. Insert founding device from the active config
   (fingerprint `29974BE04FCC7C31C4D1493730D6A019C21A600C`, name from config).
2. `INSERT INTO password_keys (password_id, device_id, wrapped_key)
   SELECT id, <founding_id>, aes_key FROM passwords ON CONFLICT DO NOTHING;`

**Read path:** try `password_keys` for *my* fingerprint → fall back to
`passwords.aes_key` (same decoupled-probe pattern as `has_enc_version_`, so
the binary works against an unmigrated DB).

**Write path:** new entries wrap K once per *active* device. Keep also writing
`passwords.aes_key` (founding-device wrap) so the old binary/rollback path
still reads new rows.

**Rollback:** `DROP TABLE password_keys, devices;` — production data identical
to today. Plus the dumps.

Note: the existing `user_public_keys` table is a proto-`devices` table; it gets
superseded (left in place, ignored).

---

## 3. Device lifecycle

### Enroll a new device
1. **On the new device:** generate its own GPG keypair — the secret key never
   leaves the device. Export the *public* key + fingerprint to a file.
2. **Transfer** the public key to an existing device (USB / scp over LAN).
3. **Verify the 40-char fingerprint out-of-band** (read it aloud / compare on
   both screens). This is the trust root of the whole scheme — a wrong key
   here means encrypting your vault to a stranger.
4. **On an existing (admin) device:** `pwmgr device add <name> <pubkey.asc>`
   → imports the key, inserts the `devices` row, then **re-wraps**: for each
   entry, GPG-decrypt K (one passphrase, gpg-agent caches the session),
   GPG-encrypt K to the new fingerprint, insert the `password_keys` row.
   Plaintext passwords are never touched — only 32-byte keys, in memory,
   cleansed after use. 13 entries ≈ seconds.

### Revoke a device
`pwmgr device revoke <name>` → status='revoked', delete its `password_keys`
rows. **That alone is not enough** — the device may have cached unwrapped
keys — so revoke prompts for `pwmgr rotate`: per entry, generate a new K,
re-encrypt the secret as v2 GCM, re-wrap to all remaining active devices.
(Rotation is also how the v1 CBC rows eventually migrate to v2, for free.)

### New CLI
`device add | device list | device revoke | rewrap | rotate` — plus a
"Devices" screen in the menu.

---

## 4. Transport tiers

### Tier 0 — localhost (today)
Unchanged.

### Tier 1 — LAN (other devices on the same wifi/ethernet)
Devices connect **directly to the existing Postgres**; it's the sync point and
only ever holds ciphertext. Hardening before opening it up:

- `postgresql.conf`: `listen_addresses = 'localhost, <LAN-IP>'`, `ssl = on`
  with a self-signed cert (or tiny local CA so clients can `verify-full`).
- `pg_hba.conf`: `hostssl pwmgr pwmgr 192.168.x.0/24 scram-sha-256` — TLS
  required, scram only, no `trust`, scoped to the subnet.
- **Rotate the DB password first (recommended)** — the real password was
  never committed (only the dummy `temp123` is in git history), but it sits
  in plaintext in the local config and is about to be shared with more
  devices; rotating into `~/.pgpass` is the right hygiene step.
- Optional nicety: one DB role per device for audit trails.
- Each device's config: `host=<server-LAN-IP> ... sslmode=verify-full
  sslrootcert=~/.config/pwmgr/server-ca.crt`.

### Tier 2 — remote (Tor onion service ONLY — clearnet dropped)
**Decision 2026-06-10:** clearnet access (WireGuard/SSH/VPS) is dropped.
Both remaining tiers are completely free to run: LAN costs nothing, and an
onion service needs no public IP, no port-forwarding, no rented relay.

**Never expose Postgres raw to the internet.** The onion service is the only
remote path: `torrc` on the server —
`HiddenServiceDir /var/lib/tor/pwmgr/`,
`HiddenServicePort 5432 127.0.0.1:5432` (Postgres stays bound to localhost!),
and **client authorization** (per-device x25519 keys in `authorized_clients/`)
so only enrolled devices can even *connect to* the service. Clients run tor
and reach `xyz…onion:5432` via a local socat forward (or torsocks). NAT
traversal for free; the service is invisible without a client key; tor's
rendezvous crypto is end-to-end and the onion address itself authenticates
the server. Latency is higher — fine for a password manager.

The onion identity key (`hs_ed25519_secret_key`) becomes a **second
irreplaceable secret** next to the GPG key: it IS the address. Back it up
offline; losing it means a new address rolled out to every device.

Full setup spec (server + per-device client, exact files and commands):
**`docs/REMOTE.md`**.

A thin REST sync API was considered and **deferred**: tor + raw Postgres is
far less new code, and the threat model already tolerates a curious server.

---

## 5. Safe testing — never touch the real vault until step 6

1. **Unit tests** (extend `make test`; no DB, no secrets): wrap/unwrap
   round-trips with throwaway GPG keys, device-record validation, fingerprint
   parsing, read-path version dispatch.
2. **Gated repository tests** against a throwaway DB (existing guard: dbname
   must contain `test`): devices CRUD; backfill idempotency; the three read
   shapes — legacy-only row, `password_keys`-only row, both.
3. **Two-device simulation in Docker** — the key rehearsal
   (→ `make test-devices`). Compose file: `db` + two device containers, each
   generating its *own ephemeral* GPG key on first run, seeded with dummy
   entries. Scripted assertions: A creates entries → enroll B →
   **B decrypts them**; revoke B + rotate → **B can no longer decrypt
   anything**. Whole lifecycle proven with zero real secrets.
4. **Staging rehearsal on real data** (→ `make test-staging`;
   `PWMGR_STAGING_DECRYPT=1` for the gated decrypt pass): restore the latest
   prod dump into `pwmgr_test`, run `pwmgr migrate` there, decrypt every
   restored row (covers the known compat row id 1). Asserts the `passwords`
   table bytes are bit-identical pre/post migration.
5. **Network tier rehearsal:** Tier 1 (→ `make test-net`) — plaintext,
   wrong-CA and wrong-password connections refused; `verify-full` connects
   (psql and the pwmgr client itself). Tier 2 — **manual only** (tests never
   enable tor): onion service up, connect from a device with *no* LAN route,
   only tor; negative: connection without the client-auth key must fail.
6. **Production, in order:** fresh backup → apply additive migration → verify
   reads on device 1 → enroll the real second device → verify on device 2.

---

## 6. Phases

| Phase | Deliverable | Risk to existing data |
|---|---|---|
| 0 | Fresh backup (**done** 2026-06-10) | none |
| 1 | Schema + repository: `devices`, `password_keys`, backfill, fallback read; tests 1–2 | none (additive, tested on throwaway) |
| 2 | CLI: device add/list/revoke, re-wrap engine, rotate | none until run |
| 3 | LAN: Postgres TLS + scram + pg_hba; DB password rotation; per-device config | config-only |
| 4 | Remote: Tor onion service w/ client auth (spec: `docs/REMOTE.md`) | none |
| 5 | Docker two-device harness + staging rehearsal (tests 3–5) | none (copies) |
| 6 | Prod migration + enroll real second device (test 6) | guarded by 0+5 |

### Standing invariants (carried over from the rewrite)
- The 13 v1 rows stay decryptable at every commit.
- All schema changes additive; `passwords` never rewritten in place.
- Backup before any step that writes to prod.
- Secret keys never leave their device; fingerprints verified out-of-band.
- Revocation without rotation is treated as incomplete.

---

## 7. Phase detail

Dependency order: **1 → 2 → 5**, with **3 and 4 independent** (pure network
plumbing — can run in parallel with 1/2 or after). **6 strictly last.**

### Phase 1 — Data layer (schema, repository, migration)
*Goal: the DB and C++ repository understand devices and per-device wraps,
while a pre-migration DB keeps working.*

Build:
- `scripts/schema.sql`: add `devices` + `password_keys` (fresh installs).
- `src/core/db/repository.{h,cpp}`:
  - migration **v2** inside `apply_migrations()`: `CREATE TABLE IF NOT
    EXISTS` both tables; insert founding device from the active config
    fingerprint; idempotent backfill
    (`INSERT … SELECT id, <founding>, aes_key FROM passwords
    ON CONFLICT DO NOTHING`). One transaction.
  - `has_device_tables_` probe (same decoupling pattern as
    `has_enc_version_`) so the binary runs against an unmigrated DB.
  - New API: `list_devices()`, `add_device(Device)`,
    `revoke_device(name)`, `wrapped_key_for(password_id, fingerprint)`
    → falls back to `passwords.aes_key`, `insert_wrapped_key(...)`.
- `src/core/db/device.h`: `struct Device { id, name, fingerprint,
  public_key, status, enrolled_at }` + fingerprint validation (40 hex).

Verify: `make test` (validation, dispatch); gated `test_repository` on
`pwmgr_test` covering the three read shapes (legacy-only / new-only / both)
and backfill idempotency (run migration twice).
Risk: none to prod — nothing here touches the real DB.

### Phase 2 — Crypto engine + CLI (enroll / revoke / rotate)
*Goal: full device lifecycle usable from the terminal.*

Build:
- `src/core/crypto/gpg.{h,cpp}`: `gpg_import_public_key(armored)` →
  returns fingerprint of what was actually imported (compared against the
  expected one — defends against swapped key files).
- `src/core/sharing/rewrap.{h,cpp}`:
  - **re-wrap** (enroll): per entry — unwrap K with my key (gpg-agent
    caches the passphrase after the first), `gpg_encrypt_to_fingerprint`
    K → new device, insert `password_keys` row, `OPENSSL_cleanse` K.
    Resumable: skips (password_id, device_id) pairs that already exist.
  - **rotate** (revoke / v1→v2 upgrade): per entry, one transaction —
    decrypt fully, new random K, re-encrypt as v2 GCM, wrap K to every
    *active* device, update `passwords` + replace `password_keys` rows.
- CLI: a **Devices screen** (list / add / revoke) in the menu, *and*
  argv subcommands (`pwmgr device add <name> <pubkey.asc>`,
  `device list`, `device revoke <name>`, `rotate`) — the subcommands are
  what the Phase 5 Docker harness scripts against.
- Write path change: new entries wrap K to all active devices **and**
  still write the founding wrap to `passwords.aes_key` (rollback safety;
  D5 below).

Verify: unit tests run the whole enroll flow against an **ephemeral
`GNUPGHOME`** (two throwaway no-passphrase keys generated in a temp dir) —
no real keyring involved. Revoke-without-rotate prints a loud warning.
Risk: none to prod until the binary is pointed at it.

### Phase 3 — LAN tier (server hardening)
*Goal: a second machine on your wifi/LAN can reach Postgres safely.*

Runbook (server = this machine; config changes only, no code):
1. **Rotate the DB password** (recommended; the real one was never
   committed — only the dummy `temp123` is in git history): `ALTER ROLE
   pwmgr PASSWORD '<new>'` → update `~/.config/pwmgr/config.json` +
   `~/.pgpass`. Best done *before* the password ever crosses a network.
2. Mini-CA + server cert (`scripts/gen-db-certs.sh`, new): CA key →
   server cert for the LAN hostname/IP → `server.{crt,key}` into PGDATA,
   `ca.crt` distributed to devices.
3. `postgresql.conf`: `listen_addresses = 'localhost, <LAN-IP>'`,
   `ssl = on`.
4. `pg_hba.conf`: `hostssl pwmgr pwmgr <subnet>/24 scram-sha-256`;
   confirm no `trust` lines; reload.
5. Firewall: allow 5432 from the subnet only.
6. Client config (each device): `host=<server-ip> … sslmode=verify-full
   sslrootcert=~/.config/pwmgr/ca.crt`.

Verify: from another machine/container — `verify-full` connects;
**negative tests**: plaintext refused, wrong CA refused, wrong password
refused. Risk: config-only; revert = restore the two .conf files.

### Phase 4 — Remote tier (Tor onion service)
*Goal: the same devices work from outside the LAN; Postgres is never
exposed raw — it stays bound to 127.0.0.1 for this path; tor delivers
connections to it locally.*

Full spec: **`docs/REMOTE.md`** (server torrc, per-device x25519 client-auth
key generation, client `ClientOnionAuthDir` + socat forward, onion-key
backup, pg_hba implications). Implementation deliverables:
- `scripts/onion-auth-keygen.sh` — generate a device's x25519 pair, print
  the server `.auth` line and the client `.auth_private` line.
- `scripts/setup-onion.sh` — idempotent server-side torrc + dirs setup.
- systemd unit template for the client-side socat forward.
- Device enrollment (Phase 2) additionally issues the device's onion auth
  key alongside the GPG re-wrap.

Verify in Phase 5. Risk: none to data; worst case the tunnel doesn't come up.

### Phase 5 — Rehearsals (the gate before prod)
*Goal: prove the entire lifecycle and every transport path with zero real
secrets, then once against a **copy** of real data.*

- `docker/compose.test.yml`: `db` + `deviceA` + `deviceB`; each device
  container generates an ephemeral GPG key on boot (batch,
  `%no-protection`). Scripted scenario (`scripts/test-two-devices.sh`):
  1. A creates entry → A reads it back.
  2. A enrolls B (pubkey via shared volume, fingerprint asserted).
  3. **B decrypts the entry** — the core feature, proven.
  4. Revoke B + rotate.
  5. **B can no longer decrypt; A still can.** All five steps must pass.
- **Staging rehearsal on real data** (gated — needs your passphrase):
  `scripts/restore.sh` the latest dump into `pwmgr_test`; run the new
  binary against it → migration v2 applies; assert `passwords` table is
  **bit-identical** pre/post (dump-and-diff), `password_keys` has one row
  per entry, and the known compat row (`~/pwmgr-backups/compat_id1_*`)
  decrypts.
- Network rehearsals: Tier-1 negative tests (Phase 3); onion: a container
  with **no LAN route**, tor only, connects — and fails without its
  client-auth key.

### Phase 6 — Production rollout (runbook, ~1 hour + second-device setup)
1. `./scripts/backup.sh` (fresh dump).
2. Run the new binary here → migration v2 → list + decrypt one entry.
3. Second device: install deps, build, **generate its own GPG key**,
   export pubkey, transfer, **verify fingerprint out-of-band**.
4. `pwmgr device add <name> <pubkey.asc>` here (re-wrap runs, ~seconds).
5. Second device connects via **LAN tier first**, decrypts a test entry.
6. Only after LAN works: hand it WireGuard/onion credentials.
- Rollback at any step: `DROP TABLE password_keys, devices;` and/or
  restore the dump. `passwords` is never modified by enrollment.

## 8. Open decisions (defaults applied unless overridden)
- **D1** Device mgmt UX: menu screen **and** argv subcommands → *both*
  (subcommands are required for the test harness anyway).
- **D2** Clearnet transport: **RESOLVED 2026-06-10 — dropped entirely.**
  LAN + Tor onion only; both are free to run (no public IP, no paid infra).
- **D3** DB roles: **shared `pwmgr` role** for all devices first;
  per-device roles later if audit matters.
- **D4** Revoke behavior: **rotation prompted by default**, explicit
  `--no-rotate` to skip (logged as incomplete).
- **D5** Legacy `passwords.aes_key` writes: **keep writing it** until all
  devices run the new binary; remove in a later release.
