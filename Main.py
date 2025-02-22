import os
import base64
import string
import random
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import re

# Mapnamen
CONF_DIR = "Conf"
ENC_DIR = "Enc"
os.makedirs(ENC_DIR, exist_ok=True)

# Bestandsnamen
HASH_FILE = os.path.join(CONF_DIR, "Secret_Hash.conf")
SALT_FILE = os.path.join(CONF_DIR, "Secret_Salt.conf")
KEY_FILE = os.path.join(CONF_DIR, "Secret_Key.key")  # Nu als .key-bestand

# Controleer of de configuratiebestanden bestaan
if not all(os.path.exists(f) for f in [HASH_FILE, SALT_FILE, KEY_FILE]):
    print("❌ Error: Configuratiebestanden ontbreken. Voer eerst MasterHasher.py uit.")
    exit(1)

# Vraag om het masterwachtwoord
master_password = input("🔑 Voer je master wachtwoord in: ")

# Lees de opgeslagen bestanden
with open(SALT_FILE, "rb") as f:
    salt = f.read()

with open(KEY_FILE, "rb") as f:  # Binair lezen
    key = f.read()

with open(HASH_FILE, "rb") as f:
    encrypted_hash = f.read()

# Ontsleutel de hash
from cryptography.fernet import Fernet
cipher = Fernet(key)
decrypted_hash = cipher.decrypt(encrypted_hash).decode()

# Controleer het wachtwoord
ph = PasswordHasher()
try:
    ph.verify(decrypted_hash, master_password + salt.hex())
    print("\n✅ Toegang verleend: Wachtwoord correct!\n")

except:
    print("❌ Toegang geweigerd: Wachtwoord incorrect!")
    exit(1)

# Genereer AES-256 sleutel uit masterwachtwoord
aes_key = hashlib.pbkdf2_hmac("sha256", master_password.encode(), salt, 100000, dklen=32)

# ======================== AES-256 Encryptie Functies ========================
def encrypt_file(file_path):
    """Versleutelt een bestand met AES-256 en slaat het op in de 'Enc' map."""
    if not os.path.exists(file_path):
        print("❌ Fout: Bestand bestaat niet!")
        return
    
    print("\n⚠️ WAARSCHUWING: Dit bestand wordt versleuteld! Toegang vereist het masterwachtwoord!\n")

    iv = os.urandom(16)  # Initialisatievector (IV)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, "rb") as f:
        data = f.read()

    # Padding toevoegen (AES vereist blokgrootte van 16 bytes)
    padding_length = 16 - (len(data) % 16)
    data += bytes([padding_length]) * padding_length

    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # Sla het versleutelde bestand op in de "Enc" map
    file_name = os.path.basename(file_path)
    encrypted_file_path = os.path.join(ENC_DIR, file_name + ".enc")

    with open(encrypted_file_path, "wb") as f:
        f.write(iv + encrypted_data)

    print(f"✅ Bestand versleuteld: {encrypted_file_path}")

    # Verwijder het originele bestand
    os.remove(file_path)
    print(f"🗑️ Origineel bestand verwijderd: {file_path}")


def decrypt_file(file_name):
    """Ontsleutelt een AES-256 versleuteld bestand uit de 'Enc' map."""
    encrypted_file_path = os.path.join(ENC_DIR, file_name + ".enc")

    if not os.path.exists(encrypted_file_path):
        print("❌ Fout: Versleuteld bestand bestaat niet!")
        return

    with open(encrypted_file_path, "rb") as f:
        iv = f.read(16)  # De eerste 16 bytes zijn de IV
        encrypted_data = f.read()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]

    original_file_path = os.path.join(os.getcwd(), file_name)
    with open(original_file_path, "wb") as f:
        f.write(decrypted_data)

    print(f"✅ Bestand ontsleuteld: {original_file_path}")

    os.remove(encrypted_file_path)
    print(f"🗑️ Versleuteld bestand verwijderd: {encrypted_file_path}")

# ======================== Wachtwoordgenerator ========================
def generate_password(length, use_uppercase, use_numbers, use_special_chars):
    """Genereert een wachtwoord met opgegeven opties."""
    all_chars = string.ascii_lowercase
    if use_uppercase:
        all_chars += string.ascii_uppercase
    if use_numbers:
        all_chars += string.digits
    if use_special_chars:
        all_chars += string.punctuation

    password = ''.join(random.choice(all_chars) for _ in range(length))
    return password

# ======================== Wachtwoordsterkte meten en tips ========================
def check_password_strength(password):
    """Controleert de sterkte van een wachtwoord."""
    length_check = len(password) >= 8
    upper_check = any(c.isupper() for c in password)
    number_check = any(c.isdigit() for c in password)
    special_check = any(c in string.punctuation for c in password)
    
    strength = 0
    if length_check:
        strength += 1
    if upper_check:
        strength += 1
    if number_check:
        strength += 1
    if special_check:
        strength += 1
    
    # Geef sterkte score terug
    if strength == 4:
        return "✅ Zeer sterk", "n.v.t."  # Geen tips voor zeer sterke wachtwoorden
    elif strength == 3:
        return "⚡ Sterk", get_password_tips(strength)
    elif strength == 2:
        return "⚠️ Gemiddeld", get_password_tips(strength)
    else:
        return "❌ Zwak", get_password_tips(strength)

def get_password_tips(strength):
    """Geeft tips om het wachtwoord te verbeteren op basis van de sterkte."""
    tips = []
    if strength < 4:
        tips.append("- Voeg een speciale teken toe (zoals @, #, $, %).")
    if strength < 3:
        tips.append("- Voeg een cijfer toe.")
    if strength < 2:
        tips.append("- Voeg een hoofdletter toe.")
    if strength < 1:
        tips.append("- Maak het wachtwoord langer dan 8 tekens.")
    return tips

# ======================== Gebruikersmenu ========================
def menu():
    while True:
        print("\n🔐 MENU:")
        print("1️⃣  Versleutel een bestand")
        print("2️⃣  Ontsleutel een bestand")
        print("3️⃣  Genereer een wachtwoord")
        print("4️⃣  Controleer wachtwoordsterkte")
        print("5️⃣  Afsluiten")

        keuze = input("\nKies een optie (1/2/3/4/5): ")

        if keuze == "1":
            bestand = input("Voer het pad in van het bestand dat je wilt versleutelen: ")
            encrypt_file(bestand)

        elif keuze == "2":
            bestand = input("Voer de naam in van het versleutelde bestand (zonder '.enc'): ")
            decrypt_file(bestand)

        elif keuze == "3":
            lengte = int(input("Geef de lengte van het wachtwoord: "))
            use_uppercase = input("Gebruik hoofdletters? (y/n): ").strip().lower() == 'y'
            use_numbers = input("Gebruik cijfers? (y/n): ").strip().lower() == 'y'
            use_special_chars = input("Gebruik speciale tekens? (y/n): ").strip().lower() == 'y'
            
            wachtwoord = generate_password(lengte, use_uppercase, use_numbers, use_special_chars)
            print(f"✅ Genereerd wachtwoord: {wachtwoord}")

        elif keuze == "4":
            wachtwoord = input("Voer het wachtwoord in om de sterkte te meten: ")
            sterkte, tips = check_password_strength(wachtwoord)
            print(f"🔐 Wachtwoordsterkte: {sterkte}")
            if tips != "n.v.t.":
                print("💡 Tips om je wachtwoord te verbeteren:")
                for tip in tips:
                    print(f"  - {tip}")

        elif keuze == "5":
            print("👋 Afsluiten...")
            exit(0)

        else:
            print("❌ Ongeldige keuze, probeer opnieuw!")

menu()
