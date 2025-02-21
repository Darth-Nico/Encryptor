import os
import secrets
import string
from argon2 import PasswordHasher
from pathlib import Path
import base64

# XOR encryptie en decryptie functie
def xor_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

# Functie om een willekeurige sleutel te genereren
def generate_random_key(length: int = 16) -> bytes:
    # Willekeurige sleutel bestaande uit letters en cijfers
    alphabet = string.ascii_letters + string.digits
    key = ''.join(secrets.choice(alphabet) for _ in range(length))
    return key.encode()

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

# Functie om de sleutel uit key.conf te lezen
def read_key_from_file():
    conf_folder = Path("Conf")
    key_file_path = conf_folder / "key.conf"
    
    with open(key_file_path, 'r') as file:
        key = file.read().strip().encode()
    
    return key

# Functie om de hash en salt te versleutelen en op te slaan
def encrypt_and_save_hash_and_salt(hashed_password: str, salt: bytes, key: bytes):
    conf_folder = Path("Conf")
    conf_folder.mkdir(exist_ok=True)
    
    # Versleutel de hash en salt
    encrypted_hash = xor_encrypt_decrypt(hashed_password.encode('utf-8'), key)
    encrypted_salt = xor_encrypt_decrypt(salt, key)
    
    # Pad naar de versleutelde bestanden
    hash_file_path = conf_folder / "Secret_Hash.conf"
    salt_file_path = conf_folder / "Salt.conf"
    
    # Sla de versleutelde hash en salt op
    with open(hash_file_path, 'wb') as file:
        file.write(encrypted_hash)
    
    with open(salt_file_path, 'wb') as file:
        file.write(encrypted_salt)
    
    # Sla de sleutel op in key.conf (plaintext)
    key_file_path = conf_folder / "key.conf"
    with open(key_file_path, 'w') as file:
        file.write(key.decode())

def main():
    # Vraag de gebruiker om een master wachtwoord
    password = input("Voer je master wachtwoord in: ")
    
    # Genereer een willekeurige 64-byte salt
    salt = os.urandom(64)
    
    # Maak een PasswordHasher object
    ph = PasswordHasher()
    
    # Hash het wachtwoord
    hashed_password = ph.hash(password + base64.b64encode(salt).decode('utf-8'))
    
    # Genereer een willekeurige encryptiesleutel van 16 tekens
    encryption_key = generate_random_key(16)
    
    # Versleutel en sla de hash en salt op
    encrypt_and_save_hash_and_salt(hashed_password, salt, encryption_key)
    
    print("De hash en salt zijn versleuteld en opgeslagen.")

if __name__ == "__main__":
    main()
