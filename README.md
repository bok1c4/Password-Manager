# 🔐 Password Manager

A lightweight CLI password manager with AES-256 encryption and PostgreSQL backend. Built for personal use across multiple machines.

## Features

- **AES-256 encryption** with multi-key support
- **PostgreSQL backend** for syncing across devices
- **Cross-platform** (Linux/Windows)
- **Machine-specific** private keys per device

## Quick Start

```bash
# First run creates config at ~/.pwmanager/config.json
./pwmanager

# Configure your database and key paths
{
  "db_connection": "postgres://user:pass@localhost:5432/passwords",
  "private_key_path": "/path/to/private.key",
  "public_keys": ["/path/to/public1.key", "/path/to/public2.key"]
}
```

## How It Works

Each password is encrypted with a unique AES key. That key is then encrypted for each registered public key, allowing multiple machines to decrypt the same password using their own private keys.

## Architecture

- **Core**: C++ library (can be integrated into any infrastructure)
- **CLI**: Terminal interface
- **UI**: Desktop interface (planned)
- **Storage**: PostgreSQL only

## Why This?

Terminal-first, full control over encryption and keys, scriptable, and works exactly how I need it to.

## License

MIT

---

**Note**: This is a personal tool I use daily. Fork it, break it, improve it.
