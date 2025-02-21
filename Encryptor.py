import os
from argon2 import PasswordHasher
from pathlib import Path
import base64

# XOR encryptie en decryptie functie
def xor_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

# Functie om de sleutel uit key.conf te lezen
def read_key_from_file():
    conf_folder = Path("Conf")
    key_file_path = conf_folder / "key.conf"
    
    with open(key_file_path, 'r') as file:
        key = file.read().strip().encode()
    
    return key

# Functie om de hash en salt uit versleutelde bestanden te lezen
def read_encrypted_hash_and_salt():
    conf_folder = Path("Conf")
    
    # Pad naar de versleutelde bestanden
    hash_file_path = conf_folder / "Secret_Hash.conf"
    salt_file_path = conf_folder / "Salt.conf"
    
    # Lees de sleutel uit key.conf
    key = read_key_from_file()
    
    # Lees de versleutelde hash en salt uit de bestanden
    with open(hash_file_path, 'rb') as file:
        encrypted_hash = file.read()
    
    with open(salt_file_path, 'rb') as file:
        encrypted_salt = file.read()
    
    # Ontsleutel de bestanden met de sleutel
    decrypted_hash = xor_encrypt_decrypt(encrypted_hash, key).decode('utf-8')
    decrypted_salt = xor_encrypt_decrypt(encrypted_salt, key)
    
    return decrypted_hash, decrypted_salt

# Functie om het wachtwoord te verifiëren
def verify_password(entered_password: str, stored_hash: str, salt: bytes):
    # Maak een PasswordHasher object
    ph = PasswordHasher()
    
    # Maak een aangepaste hash met dezelfde salt, gebruikmakend van de base64-encoded salt
    # Gebruik alleen het opgeslagen salt in combinatie met het ingevoerde wachtwoord
    combined_password = entered_password + base64.b64encode(salt).decode('utf-8')
    
    try:
        # Probeer het ingevoerde wachtwoord te verifiëren met de hash
        ph.verify(stored_hash, combined_password)
        return True
    except Exception as e:
        return False

def main():
    # Vraag de gebruiker om het master wachtwoord in te voeren
    entered_password = input("Voer je master wachtwoord in: ")
    
    # Lees de opgeslagen hash en salt uit de versleutelde bestanden
    hashed_password, salt = read_encrypted_hash_and_salt()
    
    # Verifieer of het ingevoerde wachtwoord correct is
    if verify_password(entered_password, hashed_password, salt):
        print("Het wachtwoord is correct!")
    else:
        print("Het wachtwoord is onjuist.")

if __name__ == "__main__":
    main()
