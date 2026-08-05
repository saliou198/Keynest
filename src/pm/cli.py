import os
import typer
from getpass import getpass
from cryptography.exceptions import InvalidTag

from . import password_crypto as pwm

app = typer.Typer()
_state = {"passwords": None, "key": None}


def _unlock():
    if not os.path.exists(pwm.VAULT_FILE):
        typer.echo("No vault found, creating a new one.")
        master = getpass("Choose a master password: ")
        return pwm.create_new_vault(master)

    master = getpass("Enter your master password: ")
    try:
        return pwm.unlock_vault(master)
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
    pwm.add_password(_state["passwords"], _state["key"])


@app.command()
def modify():
    """Modify an existing password."""
    _state["passwords"], _state["key"] = _unlock()
    pwm.modify_password(_state["passwords"], _state["key"])

@app.command()
def delete():
    """Delete a password."""
    _state["passwords"], _state["key"] = _unlock()
    pwm.delete_password(_state["passwords"], _state["key"])


@app.command()
def generate():
    """Generate a random password."""

    typer.echo(pwm.generate_password())


@app.command()
def change_master():
    """Change the vault master password."""
    _state["passwords"], _state["key"] = _unlock()
    new_key = pwm.change_master_password(_state["passwords"])
    if new_key is not None:
        _state["key"] = new_key
        typer.echo("Master password changed successfully.")
        raise typer.Exit(0)
    else:
        typer.echo("Failed to change master password.")
        raise typer.Exit(1)

if __name__ == "__main__":
    app()
