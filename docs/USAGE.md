# Password Manager — usage (rewrite)

## Build
Primary (CMake):
```sh
cmake --preset debug      # or: cmake -S . -B build/debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build/debug
```
Fallback without CMake:
```sh
make            # builds build/make/pwmgr and build/make/pwmgr_tests
```

## Configure
The app loads ONE config from an absolute path (it never invents a default):
`PWMGR_CONFIG` > `$XDG_CONFIG_HOME/pwmgr/config.json` > `~/.config/pwmgr/config.json`.

Copy `config.example.json` to `~/.config/pwmgr/config.json`, fill in your DB
connection and the full 40-char fingerprint of your GPG key, and `chmod 600` it.
Keep the DB password in `~/.pgpass` (or `PWMGR_DB_PASSWORD`) rather than in the
file. See `docs/ROTATION.md`.

## Run
```sh
./build/make/pwmgr        # or ./build/debug/pwmgr
```
On first launch it applies one additive migration (`enc_version` column) — this
is non-destructive and idempotent. Decryption uses your GPG key and will prompt
for the passphrase via your normal pinentry/gpg-agent.

Menu: generate & store, view/search, manage DB connection, key info. In an
entry: `[c]` copy to clipboard (auto-clears in 20s), `[s]` show transiently,
`[e]` edit, `[n]` rename, `[d]` delete (typed confirmation).

## Test
```sh
make test                         # unit tests (no secrets, no DB)
build/make/pwmgr_tests --gated \
  PWMGR_COMPAT_PASSWORD=... PWMGR_COMPAT_AESKEY=...   # backward-compat decrypt
PWMGR_TEST_DB="...test..." build/make/pwmgr_tests --gated   # repository CRUD
```

## Crypto envelope
- **v1 (existing rows):** `base64(IV‖AES-256-CBC)`, AES key GPG-wrapped. Read-only,
  decrypt path preserved byte-for-byte.
- **v2 (new writes):** `v2:‖base64(nonce‖AES-256-GCM‖tag)` — authenticated, AES key
  GPG-wrapped to the same recipient. Reads auto-detect the version.

## Rollback
The previous binary still works via `./run.sh` (uses the bundled libpqxx 7.10).
Keep it until you've confirmed the new binary decrypts a real entry.
