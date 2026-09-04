from cryptography.fernet import Fernet
import os
import hashlib

# -------------------------------
# Folder Paths
# -------------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

KEY_FOLDER = os.path.join(BASE_DIR, "keys")
ENCRYPTED_FOLDER = os.path.join(BASE_DIR, "encrypted")
DECRYPTED_FOLDER = os.path.join(BASE_DIR, "decrypted")

os.makedirs(KEY_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)


# -------------------------------
# Encrypt File
# -------------------------------

def encrypt_file(file_path):

    key = Fernet.generate_key()

    cipher = Fernet(key)

    with open(file_path, "rb") as file:

        data = file.read()

    encrypted_data = cipher.encrypt(data)

    filename = os.path.basename(file_path)

    encrypted_file = os.path.join(
        ENCRYPTED_FOLDER,
        filename + ".enc"
    )

    with open(encrypted_file, "wb") as file:

        file.write(encrypted_data)

    return encrypted_file, key


# -------------------------------
# Decrypt File
# -------------------------------

def decrypt_file(encrypted_file_path, aes_key):

    cipher = Fernet(aes_key)

    with open(encrypted_file_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = cipher.decrypt(encrypted_data)

    filename = os.path.basename(encrypted_file_path)

    if filename.endswith(".enc"):
        filename = filename[:-4]

    decrypted_file = os.path.join(
        DECRYPTED_FOLDER,
        filename
    )

    with open(decrypted_file, "wb") as file:
        file.write(decrypted_data)

    return decrypted_file

def calculate_file_hash(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(4096)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()