# Password Manager

Encrypted password manager CLI using **AES-256-GCM** + **Argon2id**.

## Features

- 🔐 AES-256-GCM encryption with a unique nonce per save
- 🧂 Key derivation via Argon2id (64 MB RAM, 3 iterations)
- 🔍 Fuzzy search for website names
- 🎲 Random password generator (20 chars: letters + digits + symbols)
- 👁️ Password masking on display
- 🔑 Master password change

## Installation

### Linux / macOS

```bash
git clone git@github.com:saliou198/password-manager.git
cd password-manager
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Windows

```powershell
git clone git@github.com:saliou198/password-manager.git
cd password-manager
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

### CLI mode (Typer)

```bash
python cli.py --help

python cli.py view              # Show stored passwords (masked)
python cli.py add               # Add a new account
python cli.py modify            # Modify an existing account
python cli.py generate          # Generate a random password
python cli.py change-master     # Change the master password
```

On first run, the vault file `vault.enc` is created automatically.

### Interactive mode (fallback)

```bash
python password_crypto.py
```

Classic text menu with the same operations.

## Project structure

```
password-manager/
├── cli.py              # Typer interface
├── password_crypto.py  # Business logic + encryption
├── requirements.txt    # Dependencies
└── vault.enc           # Encrypted vault file (created on 1st run)
```

## Security

| Component | Detail |
|-----------|--------|
| Encryption | AES-256-GCM (authenticated) |
| Key derivation | Argon2id — 64 MB RAM, parallelism 4 |
| Nonce | 96-bit random, regenerated on every save |
| Storage | Base64-encoded JSON file |

## ⚠️ Known bugs

- **`delete` unavailable** — `python cli.py delete` raises an `AttributeError` because `delete_password()` hasn't been implemented yet in `password_crypto.py`.
- **One account per site** — The `{site: {username, password}}` structure only supports one entry per site. The "Add account in same website" option overwrites the previous entry.
- **Fuzzy match on `None`** — When `website_searcher` finds nothing, `modify_password` displays `"Did you mean: None (y/n)"`.
- **Interactive mode** — `change_master_password` returns `None` in `main()` when passwords don't match, making the key invalid for subsequent operations.

## License

MIT — do whatever you want with it.
