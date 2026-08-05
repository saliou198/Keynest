# KEYNEST

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
git clone https://github.com/saliou198/keynest.git
cd keynest
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Windows

```powershell
git clone https://github.com/saliou198/keynest.git
cd keynest
python3 -m venv .venv
.venv\Scripts\activate
pip install -e .
```

## Usage

```bash
pm --help               # Show available commands
pm view                 # List stored passwords (masked)
pm add                  # Add a new account
pm modify               # Modify an existing account
pm delete               # Delete an account
pm generate             # Generate a random password
pm change-master        # Change the master password
```

On first run, the vault file `vault.enc` is created automatically.

## Project structure

```
password-manager/
├── pyproject.toml
├── README.md
├── src/
│   └── pm/
│       ├── __init__.py
│       ├── cli.py              # Typer CLI interface
│       └── password_crypto.py  # Encryption + business logic
└── vault.enc                   # Encrypted vault file (created on 1st run)
```

## Security

| Component | Detail |
|-----------|--------|
| Encryption | AES-256-GCM (authenticated) |
| Key derivation | Argon2id — 64 MB RAM, parallelism 4 |
| Nonce | 96-bit random, regenerated on every save |
| Storage | Base64-encoded JSON file |


## License

MIT — do whatever you want with it.
