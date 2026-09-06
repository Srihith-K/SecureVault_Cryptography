from cryptography.fernet import Fernet
import os

# Base directory of the crypto folder
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Master key file
KEY_FILE = os.path.join(BASE_DIR, "master.key")


def load_master_key():
    """
    Loads the master key if it exists.
    Otherwise, generates a new one and saves it.
    """

    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as file:
            file.write(key)

    with open(KEY_FILE, "rb") as file:
        return file.read()


# Create Fernet object
fernet = Fernet(load_master_key())


def encrypt_private_key(private_key: str) -> str:
    """
    Encrypt an RSA private key before storing it in the database.
    """
    encrypted = fernet.encrypt(private_key.encode("utf-8"))
    return encrypted.decode("utf-8")


def decrypt_private_key(encrypted_private_key: str) -> str:
    """
    Decrypt an RSA private key before using it.
    """
    decrypted = fernet.decrypt(encrypted_private_key.encode("utf-8"))
    return decrypted.decode("utf-8")