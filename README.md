# PwVault

Encrypted password manager CLI using **AES-256-GCM** + **Argon2id**, with pluggable storage backends (local files, GitHub).

## Features

-  AES-256-GCM encryption with a unique nonce per save
-  Key derivation via Argon2id (64 MB RAM, 3 iterations)
-  Fuzzy search for website names
-  Random password generator (20 chars: letters + digits + symbols)
-  Password masking on display
-  Master password change
- ☁️ Sync vault to/from GitHub (StorageBackend abstraction — add your own backends)

## Installation

### Need python on your os/works on every os

```bash
pipx install pwvault
```



## Usage

### Vault commands (local file)

```bash
pm view              # List stored passwords (masked)
pm add               # Add a new account
pm modify            # Modify an existing account
pm delete            # Delete an account
pm generate          # Generate a random password
pm change-master      # Change the master password
pm key add            #add new api Key
pm key list          #list api keys
pm key modify       #modify api key if exists
pm key delete       #
```

On first run, the vault file `vault.enc` is created automatically in the current directory.

### GitHub sync

PwVault can push/pull your encrypted vault to a GitHub repository via the Content API.
Authentication is done through a **Personal Access Token** (recommended) or through the GitHub device flow.

```bash
# Step 1 — set your GitHub token
# Generate a Personal Access Token (classic) at:
#   https://github.com/settings/tokens/new
# Select scope: repo
pm config set-token ghp_xxxxxxxxxxxxxxxxxxxx

# Step 2 — choose which repository to sync to
pm storage add github <your-username>/<your-repo>

# Step 3 — sync
pm sync push          # Upload local vault to GitHub
pm sync pull          # Download vault from GitHub to local

# See what's configured
pm storage list
```

### GitHub login (device flow)

An alternative to the PAT is `pm login`, which uses the **GitHub device flow**.
However, for `pm sync` to work, the OAuth App must have the **Contents** permission
enabled in its GitHub App settings. If you see this error:

> Resource not accessible by integration

It means the OAuth App is missing the `Contents → Read & write` permission.
Either enable that permission in your GitHub App settings (Settings → Developer
settings → GitHub Apps → your app → Permissions → Contents) and re-run `pm login`,
or use a PAT with `pm config set-token`.

```bash
pm login             # GitHub device-flow authentication
pm config set-token  # Set a Personal Access Token manually
```

## Project structure

```
pwvault/
├── pyproject.toml
├── README.md
├── LICENSE
├── src/
│   └── pm/
│       ├── __init__.py
│       ├── cli.py              # Typer CLI interface
│       ├── config.py           # Token & repo persistence (~/.pwvault/)
│       ├── password_crypto.py  # Encryption + vault lifecycle
│       ├── github_auth.py      # GitHub device-flow OAuth
│       └── storage/
│           ├── __init__.py
│           ├── base.py         # StorageBackend ABC (upload/download/exists)
│           ├── local.py        # LocalStorage — plain file on disk
│           └── github.py       # GitHubStorage — GitHub Contents API
└── vault.enc                   # Encrypted vault file (created on 1st run)
```

### Architecture

```
                         pm CLI
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
          view/add    login/sync    config
              │            │            │
              ▼            ▼            ▼
       password_crypto  github_auth   config.py
              │
              ▼
         StorageBackend  ◄── ABC (upload / download / exists)
              │
      ┌───────┼───────┐
      ▼       ▼       ▼
   Local   GitHub   (future)
```

The password manager never knows where the vault lives. It asks a `StorageBackend`
to read/write opaque `bytes`. The encryption layer stays untouched regardless of
how many backends are added.

## Security

| Component | Detail |
|-----------|--------|
| Encryption | AES-256-GCM (authenticated) |
| Key derivation | Argon2id — 64 MB RAM, parallelism 4 |
| Nonce | 96-bit random, regenerated on every save |
| Storage format | JSON with Base64-encoded binary fields |
| Token storage | `~/.pwvault/config.json` (user-only) |

## License

Apache License 2.0 — see [LICENSE](LICENSE).
