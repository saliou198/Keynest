# Password Manager

CLI de gestion de mots de passe chiffré avec **AES-256-GCM** + **Argon2id**.

## Fonctionnalités

- 🔐 Chiffrement AES-256-GCM avec nonce unique par sauvegarde
- 🧂 Dérivation de clé via Argon2id (64 MB RAM, 3 itérations)
- 🔍 Recherche approximative (fuzzy matching) des sites
- 🎲 Générateur de mots de passe aléatoires (20 caractères, lettres + chiffres + symboles)
- 👁️ Masquage des mots de passe à l'affichage
- 🔑 Changement de mot de passe maître

## Installation

```bash
git clone <url-du-repo>
cd password-manager
python -m venv venv
source venv/bin/activate        # Linux/macOS
pip install -r requirements.txt
```

## Utilisation

### Mode CLI (Typer)

```bash
python cli.py --help

# Créer/lister/ajouter
python cli.py view              # Affiche les mots de passe (masqués)
python cli.py add               # Ajouter un compte
python cli.py modify            # Modifier un compte
python cli.py generate          # Générer un mot de passe aléatoire
python cli.py change-master     # Changer le mot de passe maître
```

Au premier lancement, le vault `vault.enc` est créé automatiquement.

### Mode interactif (fallback)

```bash
python password_crypto.py
```

Menu texte classique avec les mêmes opérations.

## Structure

```
password-manager/
├── cli.py              # Interface Typer
├── password_crypto.py  # Logique métier + chiffrement
├── requirements.txt    # Dépendances
└── vault.enc           # Fichier de stockage chiffré (généré au 1er lancement)
```

## Sécurité

| Élément | Détail |
|--------|--------|
| Chiffrement | AES-256-GCM (authentifié) |
| Dérivation de clé | Argon2id — 64 MB RAM, parallélisme 4 |
| Nonce | 96 bits aléatoires, régénérés à chaque sauvegarde |
| Stockage | Fichier JSON encodé en base64 |

## ⚠️ Bugs connus

- **`delete` indisponible** — La commande `python cli.py delete` lève une `AttributeError` car `delete_password()` n'a pas encore été implémentée dans `password_crypto.py`.
- **Un seul compte par site** — La structure `{site: {username, password}}` ne supporte qu'une entrée par site. L'option "Add account in same website" écrase l'entrée précédente.
- **Fuzzy match sur `None`** — Si `website_searcher` ne trouve rien, `modify_password` affiche `"Did you mean: None (y/n)"`.
- **Mode interactif** — `change_master_password` retourne `None` dans `main()` si les mots de passe ne correspondent pas, rendant la clé invalide pour les opérations suivantes.

## Licence

MIT — faites-en ce que vous voulez.
