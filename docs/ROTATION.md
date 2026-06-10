# Secret rotation & recovery

## The one irreplaceable asset: the GPG secret key
Every entry's AES key is GPG-encrypted to the recipient fingerprint in your
config. The matching **secret key is the only thing that can decrypt your vault.**
Back it up once, offline, on encrypted media:

```sh
gpg --export-secret-keys --armor <FINGERPRINT> > /secure/offline/pwmgr-key.asc
```

Without it, restored database rows are ciphertext you can never open.

## Rotate the database password (deferred, do when ready)
Only the old dummy password `temp123` is in git history — the working password
was never committed, but it lives in plaintext in the local config. To rotate:

```sql
ALTER ROLE pwmgr WITH PASSWORD '<new-strong-password>';
```

Then put the new password in `~/.pgpass` (mode 0600) **instead of** the config
file, and drop `password=...` from `db_connection`:

```
# ~/.pgpass : hostname:port:database:username:password
localhost:5432:pwmgr:pwmgr:<new-strong-password>
```

The app appends `PWMGR_DB_PASSWORD` if the connection string omits a password,
or libpq reads `~/.pgpass` automatically.

## Purge the leaked password from git history (irreversible — back up first)
```sh
git clone --mirror . ../pwmgr-history-backup.git   # safety copy
git rm --cached config.json                         # already untracked here
# then, with python-pip 'git-filter-repo' or BFG:
git filter-repo --path config.json --invert-paths
```
History rewrite changes every commit hash and cannot be undone — make the mirror
backup first and coordinate with anyone who has a clone.

## Rotate the encryption (recipient) key WITHOUT losing existing rows
This is non-destructive and per-row. For each row, inside a transaction and
after a fresh backup:
1. GPG-decrypt `aes_key` with the OLD secret key -> 32-byte AES key.
2. Re-wrap the SAME 32-byte AES key to the NEW recipient fingerprint.
3. `UPDATE passwords SET aes_key = <new armored> WHERE id = ...`.

The `password` column (the AES-encrypted secret) is untouched; only the wrapping
of the AES key changes. Verify the new key decrypts a test row before rotating
the rest, and keep the old secret key until every row is re-wrapped.
