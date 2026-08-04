import json
import os
import base64
import difflib
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from getpass import getpass
import secrets

VAULT_FILE = "vault.enc"

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

# ---------- Disk persistence ----------

def save_vault_file(salt: bytes, nonce: bytes, ciphertext: bytes):
    with open(VAULT_FILE, "w") as f:
        json.dump({
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }, f, indent=4)


def load_vault_file() -> dict:
    with open(VAULT_FILE, "r") as f:
        raw = json.load(f)
    return {
        "salt": base64.b64decode(raw["salt"]),
        "nonce": base64.b64decode(raw["nonce"]),
        "ciphertext": base64.b64decode(raw["ciphertext"]),
    }



# ----------- Quality of life :peace and love ----------
def website_searcher(website: str, passwords: dict):

    word_list = list(passwords.keys())
    matches = difflib.get_close_matches(website.lower(), [w.lower() for w in word_list], n=5, cutoff=0.6)

    if matches:

        for site in word_list:
            if site.lower() == matches[0]:
                return site
    return None

def hide_password(password: str, passwords: dict) -> str:
    """Masks the password by displaying asterisks."""
    return "*" * len(password)


# ---------- Logic ----------
def create_new_vault(master_password: str) -> tuple[dict, bytes]:
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    nonce, ciphertext = encrypt_vault({}, key)
    save_vault_file(salt, nonce, ciphertext)
    return {}, key

def randomChar_generator() -> str:
      # 1. All letters (lowercase + uppercase)
      LETERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

      # 2. All digits
      NUMBERS = "0123456789"

      # 3. All ASCII punctuation symbols
      SYMBOLES = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""


      ALL_CHARS = LETERS + NUMBERS + SYMBOLES
      return secrets.choice(ALL_CHARS)

def unlock_vault(master_password: str) -> tuple[dict, bytes]:
    """Returns (decrypted data, key). Raises an exception if password is wrong."""
    stored = load_vault_file()
    key = derive_key(master_password, stored["salt"])
    # If the password is wrong, InvalidTag is raised here -> no access to data.
    data = decrypt_vault(stored["nonce"], stored["ciphertext"], key)
    return data, key


def persist_vault(passwords: dict, key: bytes):
    """Re-encrypts and saves after each modification."""
    stored = load_vault_file()  # keep the same salt
    nonce, ciphertext = encrypt_vault(passwords, key)
    save_vault_file(stored["salt"], nonce, ciphertext)


def add_password(passwords: dict, key: bytes):
    site = input("Site (ex: github.com): ")
    if site in passwords:
        print(f"Site '{site}' already exists.")
        print("1. Update existing password: ")
        print("2. Delete existing password: ")
        print("3.Add an account in the same website: ")
        choice = input("Enter your choice: ")
        if choice == "1":
              username = input("Username: ")
        elif choice == "2":
            del passwords[site]
            persist_vault(passwords, key)
            return
        elif choice == "3":
            purpose = input("What is the purpose of this account? ex(Professional): ")
            username = input("Username: ")
            username = username + "(" + purpose + ")"
    else:
        username = input("Username: ")


    choice = input("Generate a random password? (y/n): ")
    if choice.lower() == "y":
        password = generate_password()
        print(f"Generated password: {password}")
    else:
        password = getpass("Password: ")
    passwords[site] = {"username": username, "password": password}
    persist_vault(passwords, key)
    print(f"Password for '{site}' saved (encrypted).")

def delete_password(passwords: dict, key: bytes):
    site = input("Site whose password to delete: ")
    if site not in passwords:
        match = website_searcher(site, passwords)
        if match == None:
            print(f"Site '{site}' not found.")
            return
        choice = input(f"Did you mean: {match} (y/n): ")
        if choice.lower() == "y":
            site = match
        else:
            print(f"Site '{site}' not found.")
            return
    achoice = input(f"Are you sure you want to delete the password for '{site}'? (y/n): ")
    if achoice.lower() == "y":
        del passwords[site]
        persist_vault(passwords, key)
        print(f"Password for '{site}' deleted.")


def modify_password(passwords: dict, key: bytes):
    site = input("Site whose password to modify: ")
    if site not in passwords:
        match = website_searcher(site, passwords)
        choice = input(f"Did you mean: {match} (y/n): ")
        if choice.lower() == "y":
            site = match
        else:
            print(f"Site '{site}' not found.")
            return

    username = input("Username: ")
    password = getpass("Password: ")
    passwords[site] = {"username": username, "password": password}
    persist_vault(passwords, key)
    print(f"Password for '{site}' modified (encrypted).")


def view_passwords(passwords: dict):
    if not passwords:
        print("No passwords stored.")
        return
    print("\n--- Passwords ---")
    for site, creds in passwords.items():
        print(f"Site: {site}")
        print(f"  Username: {creds['username']}")
        print(f"  Password: {hide_password(creds['password'], passwords)}")
    choice = input("Do you want to see the passwords? (y/n): ")
    if choice.lower() == "oui" or choice.lower() == "o" or choice.lower() == "y":
        for site, creds in passwords.items():
                print(f"Site: {site}")
                print(f"  Username: {creds['username']}")
                print(f"  Password: {(creds['password'])}")

def change_master_password(passwords: dict):
    new_master_password = getpass("New master password: ")
    confirm_new_password = getpass("Confirm new master password: ")
    if new_master_password != confirm_new_password:
        print("Passwords do not match.")
        return
    new_salt = os.urandom(16)
    new_key = derive_key(new_master_password, new_salt)
    nonce, ciphertext = encrypt_vault(passwords, new_key)
    save_vault_file(new_salt, nonce, ciphertext)
    print("Master password changed successfully.")
    return new_key

def generate_password():
    password = ""
    for _ in range(20):
        password += randomChar_generator()
    return password


def main():
    if not os.path.exists(VAULT_FILE):
        print("No vault found, creating a new vault.")
        master_password = getpass("Choose a master password: ")
        passwords, key = create_new_vault(master_password)
    else:
        master_password = getpass("Enter your master password: ")
        try:
            passwords, key = unlock_vault(master_password)
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
        print("6. Exit")

        choice = input("Choice: ")

        if choice == "1":
            add_password(passwords, key)
        elif choice == "2":
            view_passwords(passwords)
        elif choice == "3":
            modify_password(passwords, key)
        elif choice == "4":
            key = change_master_password(passwords)

        elif choice == "5":
            generated_password = generate_password()
            print(f"Generated password: {generated_password}")
        elif choice == "6":
            print("Logged out. Key wiped from memory.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
