import typer
from getpass import getpass
from cryptography.exceptions import InvalidTag

from . import password_crypto as pwm
from . import config
from .storage import LocalStorage, StorageBackend
from .storage.github import GitHubStorage
from .github_auth import login as github_login

app = typer.Typer()
_state = {"passwords": None, "key": None, "storage": None}


def _get_storage() -> StorageBackend:
    """Lazily create the default LocalStorage instance."""
    if _state["storage"] is None:
        _state["storage"] = LocalStorage()
    return _state["storage"]


def _unlock():
    storage = _get_storage()
    if not storage.exists():
        typer.echo("No vault found, creating a new one.")
        master = getpass("Choose a master password: ")
        confirm = getpass("Confirm master password: ")
        if master != confirm:
            typer.echo("Passwords do not match.")
            raise typer.Exit(1)
        return pwm.create_new_vault(master, storage)

    master = getpass("Enter your master password: ")
    try:
        return pwm.unlock_vault(master, storage)
    except InvalidTag:
        typer.echo("Invalid password.")
        raise typer.Exit(1)


def _get_github_storage() -> GitHubStorage:
    """Build a GitHubStorage from saved config, or exit with a message."""
    token = config.get_github_token()
    if token is None:
        typer.echo("Not logged in. Run 'pm login' or 'pm config set-token <token>'.")
        raise typer.Exit(1)

    repo = config.get_github_repo()
    if repo is None:
        typer.echo("No GitHub repository configured. Run 'pm storage add github <owner/repo>'.")
        raise typer.Exit(1)

    owner, repo_name = repo
    return GitHubStorage(access_token=token, owner=owner, repo=repo_name)


# ── main callback ────────────────────────────────────────────────────


@app.callback()
def main():
    """Password manager CLI — encrypted with AES-256-GCM."""


# ── vault commands (local storage) ───────────────────────────────────


@app.command()
def view():
    """List all stored passwords."""
    _state["passwords"], _state["key"] = _unlock()
    pwm.view_passwords(_state["passwords"])


@app.command()
def add():
    """Add a new password."""
    _state["passwords"], _state["key"] = _unlock()
    pwm.add_password(_state["passwords"], _state["key"], _get_storage())


@app.command()
def modify():
    """Modify an existing password."""
    _state["passwords"], _state["key"] = _unlock()
    pwm.modify_password(_state["passwords"], _state["key"], _get_storage())


@app.command()
def delete():
    """Delete a password."""
    _state["passwords"], _state["key"] = _unlock()
    pwm.delete_password(_state["passwords"], _state["key"], _get_storage())


@app.command()
def generate():
    """Generate a random password."""
    typer.echo(pwm.generate_password())


@app.command()
def change_master():
    """Change the vault master password."""
    _state["passwords"], _state["key"] = _unlock()
    try:
        new_key = pwm.change_master_password(_state["passwords"], _get_storage())
        _state["key"] = new_key
        typer.echo("Master password changed successfully.")
    except ValueError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)


# ── GitHub auth ──────────────────────────────────────────────────────


@app.command()
def login():
    """Login with GitHub via device flow (stores token locally)."""
    try:
        access_token, user = github_login()
        config.save_github_token(access_token)
        typer.echo(f"\n✓ Logged in as @{user['login']}")
    except Exception as e:
        typer.echo(f"\n✗ Login failed: {e}")
        raise typer.Exit(1)


# ── config ───────────────────────────────────────────────────────────


config_app = typer.Typer()
app.add_typer(config_app, name="config", help="View and edit configuration.")


@config_app.command()
def set_token(token: str = typer.Argument(help="GitHub Personal Access Token with 'repo' scope")):
    """Set the GitHub token directly (use a PAT instead of OAuth)."""
    config.save_github_token(token)
    typer.echo("✓ GitHub token saved.")


# ── storage management ───────────────────────────────────────────────


storage_app = typer.Typer()
app.add_typer(storage_app, name="storage", help="Manage storage backends.")


@storage_app.command()
def add(backend: str = typer.Argument(help="Backend type, e.g. 'github'"),
        target: str = typer.Argument(help="Target, e.g. 'owner/repo'")):
    """Configure a storage backend."""
    if backend == "github":
        if "/" not in target:
            typer.echo("Error: target must be 'owner/repo'.")
            raise typer.Exit(1)
        owner, repo = target.split("/", 1)
        config.save_github_repo(owner, repo)
        typer.echo(f"✓ GitHub storage configured: {owner}/{repo}")
    else:
        typer.echo(f"Unknown backend: {backend}. Supported: github")
        raise typer.Exit(1)


@storage_app.command("list")
def storage_list():
    """List configured storage backends."""
    typer.echo("Storage backends:\n")
    typer.echo("  local")
    typer.echo("    vault.enc")

    repo = config.get_github_repo()
    token = config.get_github_token()
    if repo:
        owner, repo_name = repo
        status = "(authenticated)" if token else "(not logged in)"
        typer.echo(f"\n  github {status}")
        typer.echo(f"    {owner}/{repo_name}")


# ── sync ─────────────────────────────────────────────────────────────


@app.command()
def sync(direction: str = typer.Argument("push", help="'push' (local→remote) or 'pull' (remote→local)")):
    """Sync the vault with a remote backend."""
    local = _get_storage()
    remote = _get_github_storage()

    if direction == "push":
        if not local.exists():
            typer.echo("No local vault to push. Create one with 'pm add'.")
            raise typer.Exit(1)
        typer.echo("Pushing local vault to GitHub...")
        remote.upload(local.download())
        typer.echo("✓ Vault pushed to GitHub.")

    elif direction == "pull":
        if not remote.exists():
            typer.echo("No remote vault found on GitHub.")
            raise typer.Exit(1)
        typer.echo("Pulling vault from GitHub...")
        local.upload(remote.download())
        typer.echo("✓ Vault pulled from GitHub (local vault.enc updated).")

    else:
        typer.echo(f"Unknown direction: {direction}. Use 'push' or 'pull'.")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
