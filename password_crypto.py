import json
import os
import base64
import difflib
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from getpass import getpass
import sqlite3
import random

VAULT_FILE = "vault.enc"

# ---------- Argon2id : mot de passe maître -> clé AES-256 ----------

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Dérive une clé de 32 octets (AES-256) à partir du mot de passe maître."""
    return hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=3,        # nombre d'itérations
        memory_cost=65536,  # 64 Mo de RAM utilisés (ralentit le brute-force)““
        parallelism=4,
        hash_len=32,        # 32 octets = 256 bits pour AES-256
        type=Type.ID,       # Argon2id
    )


# ---------- AES-256-GCM : chiffrer / déchiffrer le vault ----------


def encrypt_vault(data: dict, key: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # nonce unique à chaque chiffrement, jamais réutilisé
    plaintext = json.dumps(data).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext



def decrypt_vault(nonce: bytes, ciphertext: bytes, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return json.loads(plaintext.decode())


# ---------- Persistance sur disque ----------

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



# -----------Quality of life :peace and love
def website_searcher(website: str, passwords: dict):
    """Cherche le site le plus proche parmi les sites déjà enregistrés."""
    word_list = list(passwords.keys())
    matches = difflib.get_close_matches(website.lower(), [w.lower() for w in word_list], n=4, cutoff=0.6)
    match_list = []
    if matches:
        for site in word_list:
            if site.lower() == matches[0]:
                return site
            for match in matches[1:]:
                if site.lower() == match:
                    match_list.append(match)
        return match_list
    print("Aucune correspondance trouvée.")
    return None

def hide_password(password: str, passwords: dict) -> str:
    """Masque le mot de passe en affichant des étoiles."""
    return "*" * len(password)


# ---------- Logique
def create_new_vault(master_password: str) -> tuple[dict, bytes]:
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    nonce, ciphertext = encrypt_vault({}, key)
    save_vault_file(salt, nonce, ciphertext)
    return {}, key

def randomChar_generator() -> str:
      # 1. Toutes les lettres (Minuscules + Majuscules)
      LETERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

      # 2. Tous les chiffres
      NUMBERS = "0123456789"

      # 3. Tous les symboles ASCII de ponctuation
      SYMBOLES = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""

      ALL_CHARS = LETERS + NUMBERS + SYMBOLES
      return random.choice(ALL_CHARS)

def unlock_vault(master_password: str) -> tuple[dict, bytes]:
    """Retourne (données déchiffrées, clé). Lève une exception si mot de passe faux."""
    stored = load_vault_file()
    key = derive_key(master_password, stored["salt"])
    # Si le mot de passe est faux, InvalidTag est levée ici -> pas d'accès aux données.
    data = decrypt_vault(stored["nonce"], stored["ciphertext"], key)
    return data, key


def persist_vault(passwords: dict, key: bytes):
    """Re-chiffre et sauvegarde après chaque modification."""
    stored = load_vault_file()  # on garde le même salt
    nonce, ciphertext = encrypt_vault(passwords, key)
    save_vault_file(stored["salt"], nonce, ciphertext)


def add_password(passwords: dict, key: bytes):
    site = input("Site (ex: github.com): ")
    username = input("Utilisateur: ")
    choice = input("Générer un mot de passe aléatoire? (y/n): ")
    if choice.lower() == "y":
        password = generate_password()
        print(f"Mot de passe généré: {password}")
    else:
        password = getpass("Mot de passe: ")
    passwords[site] = {"username": username, "password": password}
    persist_vault(passwords, key)
    print(f"Mot de passe pour '{site}' sauvegardé (chiffré).")


def modify_password(passwords: dict, key: bytes):
    site = input("Site whose password to modify: ")

    match = website_searcher(site, passwords)
    if type(match) is list:
        if len(match) > 1:
            for i in range(len(match)):
                print(f"{i + 1}. {match[i]}")
            choice = int(input("Choisissez un site: "))
            site = match[choice - 1]
        else:
            site = match[0]
    elif match is None:
        print(f"Site '{site}' non trouvé.")
        return

    site = match
    username = input("Utilisateur: ")
    password = getpass("Mot de passe: ")
    passwords[site] = {"username": username, "password": password}
    persist_vault(passwords, key)
    print(f"Mot de passe pour '{site}' modifié (chiffré).")


def view_passwords(passwords: dict):
    if not passwords:
        print("Aucun mot de passe stocké.")
        return
    print("\n--- Mots de passe ---")
    for site, creds in passwords.items():
        print(f"Site: {site}")
        print(f"  Utilisateur: {creds['username']}")
        print(f"  Mot de passe: {hide_password(creds['password'], passwords)}")
    choice = input("vous voulez voire les mots de passe o/n: ")
    if choice.lower() == "oui" or choice.lower() == "o" or choice.lower() == "y":
        for site, creds in passwords.items():
                print(f"Site: {site}")
                print(f"  Utilisateur: {creds['username']}")
                print(f"  Mot de passe: {(creds['password'], passwords)}")

def change_master_password(passwords: dict, old_key: bytes):
    old_salt = load_vault_file()["salt"]
    new_master_password = getpass("Nouveau mot de passe maître: ")
    new_salt = os.urandom(16)
    new_key = derive_key(new_master_password, new_salt)
    nonce, ciphertext = encrypt_vault(passwords, new_key)
    save_vault_file(new_salt, nonce, ciphertext)
    print("Mot de passe maître changé avec succès.")
    return new_key

def generate_password():
    password = ""
    for _ in range(16):
        password += randomChar_generator()
    return password


def main():
    if not os.path.exists(VAULT_FILE):
        print("Aucun vault trouvé, création d'un nouveau vault.")
        master_password = getpass("Choisis un mot de passe maître: ")
        passwords, key = create_new_vault(master_password)
    else:
        master_password = getpass("Entre ton mot de passe maître: ")
        try:
            passwords, key = unlock_vault(master_password)
        except InvalidTag:
            print("Mot de passe incorrect.")
            return

    while True:
        print("\n--- Password Manager ---")
        print("1. Ajouter un mot de passe")
        print("2. Voir tous les mots de passe")
        print("3. Modifier un mot de passe")
        print("4. Modifier le mot de passe maître")
        print("5. Generate a password")
        print("6. Quitter")

        choice = input("Choix: ")

        if choice == "1":
            add_password(passwords, key)
        elif choice == "2":
            view_passwords(passwords)
        elif choice == "3":
            modify_password(passwords, key)
        elif choice == "4":
            key = change_master_password(passwords, key)

        elif choice == "5":
            generated_password = generate_password()
            print(f"Mot de passe généré: {generated_password}")
        elif choice == "6":
            print("Déconnecté. Clé effacée de la mémoire.")
            break
        else:
            print("Choix invalide.")


if __name__ == "__main__":
    main()
