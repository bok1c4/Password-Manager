# 🔐 Password Manager

A terminal password manager that stores secrets in **PostgreSQL**, encrypted with a
**hybrid GPG + AES-256 scheme** so the same vault can be decrypted on any machine
that holds the right GPG key.

- Each password is encrypted with a fresh random **AES-256** key.
- That AES key is **GPG-encrypted** (OpenPGP) to your key's fingerprint and stored
  alongside the ciphertext.
- To read a password you GPG-decrypt the AES key (your passphrase, via your normal
  `gpg-agent`/pinentry), then AES-decrypt the secret.

New entries use authenticated **AES-256-GCM** (`v2:` envelope); legacy AES-256-CBC
rows (`v1`) are still read transparently.

---

## Prerequisites

- A C++20 compiler (GCC 13+ / Clang 16+)
- **libpqxx 8.x** + libpq, **gpgme**, **OpenSSL** (libcrypto)
- `make` (or CMake ≥ 3.20), `pkg-config`
- **PostgreSQL** (server, or use the Docker one below)
- **GnuPG** with a keypair (and a working pinentry for the passphrase prompt)

> libpqxx 8 needs C++20. On distros that still ship libpqxx 6/7 (e.g. Debian
> stable), either use the Docker build below or build libpqxx 8 from source.

---

## Setup on your own machine

### 1. Install dependencies

**Arch Linux**
```bash
sudo pacman -S --needed gcc make pkgconf libpqxx postgresql-libs openssl gpgme gnupg pinentry
# optional, for the CMake build: sudo pacman -S cmake
```

**Fedora**
```bash
sudo dnf install gcc-c++ make pkgconf-pkg-config libpqxx-devel libpq-devel \
                 gpgme-devel openssl-devel gnupg2 pinentry
```

### 2. Create the database + schema
```bash
sudo -u postgres createuser pwmgr --pwprompt        # set a password
sudo -u postgres createdb   pwmgr --owner pwmgr
psql "host=localhost dbname=pwmgr user=pwmgr" -f scripts/schema.sql
```

### 3. Have a GPG keypair
```bash
gpg --full-generate-key        # pick ECC/ed25519 or RSA; SET A PASSPHRASE
gpg --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}'   # your 40-char fingerprint
# export the public key (referenced by the config):
gpg --export --armor <FINGERPRINT> > ~/.config/pwmgr/public.asc
```
**Back up the secret key offline — it is the only thing that can decrypt your vault:**
`./scripts/export-key.sh --help`

### 4. Configure
The app loads ONE config from an absolute path:
`PWMGR_CONFIG` → `$XDG_CONFIG_HOME/pwmgr/config.json` → `~/.config/pwmgr/config.json`.
It **fails loud** if that file is missing (it never silently writes a default).

```bash
mkdir -p ~/.config/pwmgr
cp config.example.json ~/.config/pwmgr/config.json
chmod 600 ~/.config/pwmgr/config.json
$EDITOR ~/.config/pwmgr/config.json
```
Fill in:
- `db_connection` — e.g. `host=localhost port=5432 dbname=pwmgr user=pwmgr` (keep the
  password in `~/.pgpass` or `PWMGR_DB_PASSWORD`; see `docs/ROTATION.md`).
- `public_keys[0].fingerprint` — your **full 40-char** GPG fingerprint (the recipient).
- `public_keys[0].path` / `private_key.path` — exported key files (informational;
  decryption uses your `~/.gnupg` keyring).

### 5. Build & run
```bash
make                       # -> build/make/pwmgr (and the test runner)
# or: cmake --preset debug && cmake --build build/debug   # -> build/debug/pwmgr

./build/make/pwmgr
```
First launch applies one additive migration (`enc_version`). Decryption prompts for
your GPG passphrase via pinentry.

---

## Setup with Docker

### Option A — Postgres in Docker, CLI native (recommended)
Your GPG key and pinentry stay on the host, so decryption "just works".
```bash
docker compose up -d db                 # Postgres + schema on localhost:5432
# point ~/.config/pwmgr/config.json at host=localhost port=5432
make && ./build/make/pwmgr
```

### Option B — everything in Docker
The CLI is interactive and needs your GPG key, so we mount `~/.gnupg` and run with a TTY.
```bash
cp docker/config.example.json docker/config.json     # uses host=db; edit fingerprint/password
docker compose run --rm app
```
Notes:
- The base tables are created automatically from `scripts/schema.sql` on first DB boot.
- Decryption inside a container needs your secret key reachable in the mounted
  `~/.gnupg` and a pinentry that can prompt on the TTY. If the agent handoff is awkward,
  prefer Option A.

---

## Testing
```bash
make test                                   # unit tests (no secrets, no DB)
```
Gated tests (opt-in, need real secrets / a throwaway DB):
```bash
# backward-compat: decrypt a real captured v1 row (needs your passphrase)
PWMGR_COMPAT_PASSWORD=... PWMGR_COMPAT_AESKEY=... build/make/pwmgr_tests --gated
# repository CRUD against a THROWAWAY db (name must contain "test")
PWMGR_TEST_DB="host=localhost dbname=pwmgr_test user=... password=..." build/make/pwmgr_tests --gated
```

---

## Backups & security
- **DB backup/restore:** `scripts/backup.sh`, `scripts/restore.sh` (restores into a
  throwaway DB first).
- **GPG key (the irreplaceable asset):** `scripts/export-key.sh` — export offline.
- **Rotation & secret hygiene:** `docs/ROTATION.md`. Day-to-day usage: `docs/USAGE.md`.

Config files and DB dumps are gitignored; never commit `config.json`.

---

## Project layout
```
src/core/crypto/   versioned envelope (base64, AES CBC/GCM, GPG, encryptor)
src/core/db/       libpqxx 8 repository + migrations
src/core/config/   absolute-path, fail-loud config manager
src/cli/           line-based terminal UI
tests/             self-contained test suite
scripts/           backup / restore / export-key / schema.sql
docs/              USAGE.md, ROTATION.md
```

## Troubleshooting
- `error while loading shared libraries: libpqxx-7.10.so` — an old binary linked
  against libpqxx 7; rebuild (`make`) against the installed libpqxx 8.
- `[FATAL] Config file not found` — set `PWMGR_CONFIG` or create
  `~/.config/pwmgr/config.json` (the app won't invent one).
- Decryption returns nothing / hangs — your GPG key is passphrase-protected and needs
  a working pinentry/`gpg-agent` on the same TTY.

## License
MIT
