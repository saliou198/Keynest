import json
import os
import base64
import difflib
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from getpass import getpass
import secrets
import pyperclip

from .storage import StorageBackend

# ---------- helpers ----------

def _safe_input(prompt: str = "") -> str:
    """Wrapper around input() that strips whitespace and handles paste/EOF."""
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise

def _safe_getpass(prompt: str = "") -> str:
    """Wrapper around getpass() that strips whitespace and handles paste/EOF."""
    try:
        return getpass(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise

def _ensure_v1(data: dict) -> dict:
    """Migrate a v0 vault (flat site→creds dict) to v1 if needed."""
    if "version" in data:
        return data
    return {
        "version": 1,
        "entries": {
            "passwords": data,
            "api_keys": {},
        },
    }

# ---------- Argon2id: master password -> AES-256 key ----------

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derives a 32-byte key (AES-256) from the master password."""
    return hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=3,        # number of iterations
        memory_cost=65536,  # 64 MB of RAM used (slows down brute-force)
        parallelism=4,
        hash_len=32,        # 32 bytes = 256 bits for AES-256
        type=Type.ID,       # Argon2id
    )


# ---------- AES-256-GCM: encrypt / decrypt the vault ----------


def encrypt_vault(data: dict, key: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # unique nonce for each encryption, never reused
    plaintext = json.dumps(data).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext


def decrypt_vault(nonce: bytes, ciphertext: bytes, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return json.loads(plaintext.decode())

# ---------- Vault serialization (vault bytes ↔ dict) ----------


def dump_vault(salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Serialize vault fields to bytes (JSON with Base64-encoded binary)."""
    return json.dumps({
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }, indent=4).encode()


def parse_vault(data: bytes) -> dict:
    """Deserialize vault bytes back to {salt, nonce, ciphertext}."""
    raw = json.loads(data.decode())
    return {
        "salt": base64.b64decode(raw["salt"]),
        "nonce": base64.b64decode(raw["nonce"]),
        "ciphertext": base64.b64decode(raw["ciphertext"]),
    }


# ----------- Quality of life ----------

def website_searcher(website: str, passwords: dict):
    word_list = list(passwords.keys())
    matches = difflib.get_close_matches(website.lower(), [w.lower() for w in word_list], n=5, cutoff=0.6)

    if matches:
        for site in word_list:
            if site.lower() == matches[0]:
                return site
    return None


def hide_password(password: str) -> str:
    """Masks the password by displaying asterisks."""
    return "*" * len(password)


# ---------- Vault lifecycle ----------

def create_new_vault(master_password: str, storage: StorageBackend) -> tuple[dict, bytes]:
    """Create a new v1 vault (empty) and persist it."""
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    empty_vault = {"version": 1, "entries": {"passwords": {}, "api_keys": {}}}
    nonce, ciphertext = encrypt_vault(empty_vault, key)
    storage.upload(dump_vault(salt, nonce, ciphertext))
    return empty_vault, key


def unlock_vault(master_password: str, storage: StorageBackend) -> tuple[dict, bytes]:
    """Returns (decrypted v1 vault dict, key). Raises InvalidTag on wrong password."""
    stored = parse_vault(storage.download())
    key = derive_key(master_password, stored["salt"])
    data = decrypt_vault(stored["nonce"], stored["ciphertext"], key)
    return _ensure_v1(data), key


def persist_vault(vault: dict, key: bytes, storage: StorageBackend):
    """Re-encrypts and saves after each modification."""
    stored = parse_vault(storage.download())  # keep the same salt
    nonce, ciphertext = encrypt_vault(vault, key)
    storage.upload(dump_vault(stored["salt"], nonce, ciphertext))


def randomChar_generator() -> str:
    # 1. All letters (lowercase + uppercase)
    LETERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    # 2. All digits
    NUMBERS = "0123456789"
    # 3. All ASCII punctuation symbols
    SYMBOLES = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""

    ALL_CHARS = LETERS + NUMBERS + SYMBOLES
    return secrets.choice(ALL_CHARS)


# ---------- Password entries (v1) ----------

def add_password(vault: dict, key: bytes, storage: StorageBackend):
    try:
        site = _safe_input("Site (ex: github.com): ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return

    pws = vault["entries"]["passwords"]

    if site in pws:
        print(f"Site '{site}' already exists.")
        print("1. Update existing password")
        print("2. Delete existing password")
        print("3. Add an account in the same website")
        try:
            choice = _safe_input("Enter your choice: ")
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return

        if choice == "1":
            username = _safe_input("Username: ")
        elif choice == "2":
            del pws[site]
            persist_vault(vault, key, storage)
            print(f"Password for '{site}' deleted.")
            return
        elif choice == "3":
            purpose = _safe_input("What is the purpose of this account? ex(Professional): ")
            username = _safe_input("Username: ")
            username = username + "(" + purpose + ")"
        else:
            print("Invalid choice.")
            return
    else:
        username = _safe_input("Username: ")

    try:
        choice = _safe_input("Generate a random password? (y/n): ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return

    if choice.lower() == "y":
        password = generate_password()
        print(f"Generated password (copied to clipboard): {password}")
        pyperclip.copy(password)
    else:
        password = _safe_getpass("Password: ")

    pws[site] = {"username": username, "password": password}
    persist_vault(vault, key, storage)
    print(f"Password for '{site}' saved (encrypted).")


def delete_password(vault: dict, key: bytes, storage: StorageBackend):
    try:
        site = _safe_input("Site whose password to delete: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return

    pws = vault["entries"]["passwords"]

    if site not in pws:
        match = website_searcher(site, pws)
        if match is None:
            print(f"Site '{site}' not found.")
            return
        try:
            choice = _safe_input(f"Did you mean: {match}? (y/n): ")
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return
        if choice.lower() == "y":
            site = match
        else:
            print(f"Site '{site}' not found.")
            return

    try:
        achoice = _safe_input(f"Are you sure you want to delete the password for '{site}'? (y/n): ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return

    if achoice.lower() == "y":
        del pws[site]
        persist_vault(vault, key, storage)
        print(f"Password for '{site}' deleted.")


def modify_password(vault: dict, key: bytes, storage: StorageBackend):
    try:
        site = _safe_input("Site whose password to modify: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return

    pws = vault["entries"]["passwords"]

    if site not in pws:
        match = website_searcher(site, pws)
        if match is None:
            print(f"Site '{site}' not found.")
            return
        try:
            choice = _safe_input(f"Did you mean: {match}? (y/n): ")
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return
        if choice.lower() == "y":
            site = match
        else:
            print(f"Site '{site}' not found.")
            return

    username = _safe_input("Username: ")
    password = _safe_getpass("Password: ")
    pws[site] = {"username": username, "password": password}
    persist_vault(vault, key, storage)
    print(f"Password for '{site}' modified (encrypted).")


def view_passwords(vault: dict):
    pws = vault["entries"]["passwords"]
    if not pws:
        print("No passwords stored.")
        return
    print("\n--- Passwords ---")
    for site, creds in pws.items():
        print(f"Site: {site}")
        print(f"  Username: {creds['username']}")
        print(f"  Password: {hide_password(creds['password'])}")
    try:
        choice = _safe_input("\nDo you want to see the passwords? (y/n): ")
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if choice.lower() in ("oui", "o", "y"):
        for site, creds in pws.items():
            print(f"Site: {site}")
            print(f"  Username: {creds['username']}")
            print(f"  Password: {creds['password']}")


# ---------- API key ----------

def _key_searcher(name: str, api_keys: dict):
    """Fuzzy search for an API key name."""
    word_list = list(api_keys.keys())
    matches = difflib.get_close_matches(name.lower(), [w.lower() for w in word_list], n=5, cutoff=0.6)
    if matches:
        for key_name in word_list:
            if key_name.lower() == matches[0]:
                return key_name
    return None


def add_api_key(vault: dict, key: bytes, storage: StorageBackend):
    try:
        name = _safe_input("API key name (ex: openai, github, stripe): ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return

    api_keys = vault["entries"]["api_keys"]

    if name in api_keys:
        print(f"API key '{name}' already exists.")
        try:
            choice = _safe_input("Overwrite it? (y/n): ")
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return
        if choice.lower() != "y":
            return

    api_key_value = _safe_input("API key value (or leave empty to generate): ")
    if not api_key_value:
        api_key_value = generate_password()
        print(f"Generated key (copied to clipboard): {api_key_value}")
        pyperclip.copy(api_key_value)

    note = _safe_input("Note (optional): ")

    api_keys[name] = {
        "key": api_key_value,
        "note": note,
    }
    persist_vault(vault, key, storage)
    print(f"API key '{name}' saved (encrypted).")


def modify_api_key(vault: dict, key: bytes, storage: StorageBackend):
    try:
        name = _safe_input("API key name to modify: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return

    api_keys = vault["entries"]["api_keys"]

    if name not in api_keys:
        match = _key_searcher(name, api_keys)
        if match is None:
            print(f"API key '{name}' not found.")
            return
        try:
            choice = _safe_input(f"Did you mean: {match}? (y/n): ")
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return
        if choice.lower() == "y":
            name = match
        else:
            print(f"API key '{name}' not found.")
            return

    api_key_value = _safe_input("New API key value (leave empty to keep current): ")
    note = _safe_input(f"New note [{api_keys[name].get('note', '')}] (leave empty to keep current): ")

    if api_key_value:
        api_keys[name]["key"] = api_key_value
    if note:
        api_keys[name]["note"] = note

    persist_vault(vault, key, storage)
    print(f"API key '{name}' modified (encrypted).")


def delete_api_key(vault: dict, key: bytes, storage: StorageBackend):
    try:
        name = _safe_input("API key name to delete: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return

    api_keys = vault["entries"]["api_keys"]

    if name not in api_keys:
        match = _key_searcher(name, api_keys)
        if match is None:
            print(f"API key '{name}' not found.")
            return
        try:
            choice = _safe_input(f"Did you mean: {match}? (y/n): ")
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return
        if choice.lower() == "y":
            name = match
        else:
            print(f"API key '{name}' not found.")
            return

    try:
        achoice = _safe_input(f"Are you sure you want to delete the API key '{name}'? (y/n): ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return

    if achoice.lower() == "y":
        del api_keys[name]
        persist_vault(vault, key, storage)
        print(f"API key '{name}' deleted.")


def view_api_keys(vault: dict):
    api_keys = vault["entries"]["api_keys"]
    if not api_keys:
        print("No API keys stored.")
        return
    print("\n--- API Keys ---")
    for name, entry in api_keys.items():
        print(f"Name: {name}")
        print(f"  Key:  {hide_password(entry['key'])}")
        if entry.get("note"):
            print(f"  Note: {entry['note']}")
    try:
        choice = _safe_input("\nDo you want to see the keys? (y/n): ")
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if choice.lower() in ("oui", "o", "y"):
        for name, entry in api_keys.items():
            print(f"Name: {name}")
            print(f"  Key:  {entry['key']}")
            if entry.get("note"):
                print(f"  Note: {entry['note']}")


# ---------- Change master password ----------

def change_master_password(vault: dict, storage: StorageBackend):
    new_master_password = _safe_getpass("New master password: ")
    confirm_new_password = _safe_getpass("Confirm new master password: ")
    if new_master_password != confirm_new_password:
        raise ValueError("Passwords do not match.")
    new_salt = os.urandom(16)
    new_key = derive_key(new_master_password, new_salt)
    nonce, ciphertext = encrypt_vault(vault, new_key)
    storage.upload(dump_vault(new_salt, nonce, ciphertext))
    return new_key


def generate_password():
    password = ""
    for _ in range(20):
        password += randomChar_generator()
    return password




def main():
    from .storage import LocalStorage
    storage = LocalStorage()

    if not storage.exists():
        print("No vault found, creating a new vault.")
        master_password = _safe_getpass("Choose a master password: ")
        confirm = _safe_getpass("Confirm master password: ")
        if master_password != confirm:
            print("Passwords do not match.")
            return
        vault, key = create_new_vault(master_password, storage)
    else:
        master_password = _safe_getpass("Enter your master password: ")
        try:
            vault, key = unlock_vault(master_password, storage)
        except InvalidTag:
            print("Incorrect password.")
            return

    while True:
        print("\n--- Password Manager ---")
        print("1. Add a password")
        print("2. View all passwords")
        print("3. Modify a password")
        print("4. Change master password")
        print("5. Generate a password")
        print("6. Add an API key")
        print("7. View API keys")
        print("8. Modify an API key")
        print("9. Delete an API key")
        print("10. Exit")

        try:
            choice = _safe_input("Choice: ")
        except (EOFError, KeyboardInterrupt):
            print("\nLogged out. Key wiped from memory.")
            break

        if choice == "1":
            add_password(vault, key, storage)
        elif choice == "2":
            view_passwords(vault)
        elif choice == "3":
            modify_password(vault, key, storage)
        elif choice == "4":
            try:
                new_key = change_master_password(vault, storage)
                key = new_key
                print("Master password changed successfully.")
            except ValueError as e:
                print(f"Error: {e}")
        elif choice == "5":
            generated_password = generate_password()
            print(f"Generated password (copied to clipboard): {generated_password}")
            pyperclip.copy(generated_password)
        elif choice == "6":


            add_api_key(vault, key, storage)
        elif choice == "7":
            view_api_keys(vault)
        elif choice == "8":
            modify_api_key(vault, key, storage)
        elif choice == "9":
            delete_api_key(vault, key, storage)
        elif choice == "10":
            print("Logged out. Key wiped from memory.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
