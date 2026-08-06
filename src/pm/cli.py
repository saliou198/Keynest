import typer
from getpass import getpass
from cryptography.exceptions import InvalidTag

from . import password_crypto as pwm
from .storage import LocalStorage
from .github_auth import login as github_login

app = typer.Typer()
_state = {"passwords": None, "key": None, "storage": None}


def _get_storage():
    """Lazily create the LocalStorage instance."""
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


@app.callback()
def main():
    """Password manager CLI — encrypted with AES-256-GCM."""


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

@app.command()
def login():
    """Login with GitHub via device flow."""
    try:
        access_token, user = github_login()
        typer.echo(f"\n✓ Logged in as @{user['login']}")
    except Exception as e:
        typer.echo(f"\n✗ Login failed: {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
