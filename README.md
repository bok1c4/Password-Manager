<!--toc:start-->

- [🔐 Password Manager CLI Tool](#🔐-password-manager-cli-tool)
  - [⚙️ Features](#️-features)
  - [📦 Menu Example](#📦-menu-example)
  - [🧱 Architecture Overview](#🧱-architecture-overview)
    - [🔐 Encryption Strategy](#🔐-encryption-strategy)
  - [📁 Configuration](#📁-configuration)
  - [🛠️ Tech Stack](#🛠️-tech-stack)
  - [📡 Usage Scenario (How I Use It)](#📡-usage-scenario-how-i-use-it)
  - [❓ Why Not Use Bitwarden / KeePassXC / Browser Managers?](#why-not-use-bitwarden-keepassxc-browser-managers)
  - [🧪 Future Plans](#🧪-future-plans)
  - [🤝 Contributing](#🤝-contributing)
  - [📝 License](#📝-license)
  - [👨‍💻 Developer Note](#👨‍💻-developer-note)
  <!--toc:end-->

# 🔐 Password Manager CLI Tool

A modular, pragmatic, and secure cross-platform **CLI-based Password Manager**, built for my own daily use across **Linux** and **Windows** machines.  
It’s designed to manage encrypted passwords with full control over **database connectivity**, **key-based encryption**, and **machine-specific private key settings**.

> 🛠️ If you find this project useful or want to adapt it for yourself — go ahead. This tool is built with personal use in mind, but it’s open to contributions and ideas.

---

## ⚙️ Features

- ✅ AES-256 hybrid encryption per password (PGP-style)
- ✅ Multi-machine & multi-key support
- ✅ PostgreSQL integration for syncing encrypted data
- ✅ Cross-platform (Linux / Windows tested)
- ✅ Configurable key and DB settings
- ✅ Minimal UI: pure keyboard CLI with ASCII feedback

---

## 📦 Menu Example

```
+============================================+
|         PASSWORD MANAGER CLI TOOL          |
+--------------------------------------------+
|  [1] Generate New Password                 |
|  [2] View Stored Passwords                 |
|  [3] Manage Database                       |
|  [4] Key Sharing & Encryption Setup        |
|  [q] Quit                                  |
+============================================+
```

---

## 🧱 Architecture Overview

```
           ┌─────────────────────────────┐
           │    User CLI Interaction     │
           └────────────┬────────────────┘
                        │
                 Reads Config
                        ▼
            ┌─────────────────────┐
            │ ~/.pwmanager/config │◄────┐
            └─────────┬───────────┘     │
                      │                 │
         ┌────────────▼────────────┐    │
         │   PostgreSQL Database   │    │
         │ (Encrypted Passwords)   │    │
         └────────────┬────────────┘    │
                      │                 │
               Loads Public Key(s)      │
                      ▼                 │
        ┌───────────────────────────┐   │
        │ AES-256 Encryption Engine │   │
        └───────────────────────────┘   │
                      │                 │
                      ▼                 │
        ┌────────────────────────────┐  │
        │ Machine Private Key (Path)│───┘
        └────────────────────────────┘
```

### 🔐 Encryption Strategy

Each password is encrypted using a unique AES key, and that key is encrypted for **every public key** registered in your setup.

That means:

- Multiple machines (with different private keys) can decrypt the same password.
- The decryption key is never stored in plaintext — it is only unlocked at runtime.

---

## 📁 Configuration

The app auto-generates a config file on first run:

```
~/.pwmanager/config.json
```

Example:

```json
{
  "db_connection": "postgres://user:pass@localhost:5432/passwords",
  "private_key_path": "/home/you/.keys/private.asc",
  "public_keys": ["/home/you/.keys/public.asc", "/mnt/shared/public_vm.asc"]
}
```

> ⚠️ This file is **not encrypted** (yet), but it's expected to live in a secure, user-owned directory. You can use `chmod 600` or store it in a mounted encrypted volume.

You can also add support for GPG-encrypted config in the future if needed.

---

## 🛠️ Tech Stack

- Language: **C++** (cross-platform build)
- Database: **PostgreSQL**
- Encryption: **Hybrid AES-256-GCM + RSA/ECC** (OpenPGP-style)
- Storage: **Database only**, no local file-based vault

---

## 📡 Usage Scenario (How I Use It)

- Use my Ubuntu server to host the encrypted PostgreSQL database
- Connect from:
  - ParrotOS VM (Pentesting lab)
  - Arch Linux main desktop
  - Windows laptop
- Share encrypted passwords between these using only public key additions
- Each machine has its own private key path (set in config)
- When decrypting, I provide only the private key and get instant access (which is dynamic ofc)

---

## ❓ Why Not Use Bitwarden / KeePassXC / Browser Managers?

Because:

- I wanted a CLI-only, scriptable, composable solution
- I trust my terminal more than GUIs
- I wanted control over the encryption model, key paths, and DB setup
- I wanted to learn how to architect my own encryption workflows

---

## 🧪 Future Plans

- [ ] Add QR-export for OTPs / TOTP secrets
- [ ] Add clipboard auto-clear timer
- [ ] GPG-agent or SSH-agent integration
- [ ] Optional GPG-encrypted config file
- [ ] Rust rewrite (maybe 😉)

---

## 🤝 Contributing

This project was built to **scratch my own itch**, but if it solves a problem for you too:

- File issues / feature requests
- Contribute patches via PR
- Or fork it and go wild

---

## 📝 License

MIT — do whatever you want, just don’t blame me if it eats your passwords 😉.

---

## 👨‍💻 Developer Note

This is a tool I genuinely use daily across multiple OSes. If you’re interested in cryptographic design, key sharing, or cross-platform CLI tooling — check out the source.

Cheers,  
**Boris**
