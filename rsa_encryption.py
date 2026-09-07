import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
# Base directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "keys")


# -------------------------------
# Encrypt AES Key
# -------------------------------

def encrypt_aes_key(aes_key):

    private_key_b64 = os.getenv("SIGNING_PRIVATE_KEY_B64")

    if private_key_b64:
        import base64

        private_key_data = base64.b64decode(private_key_b64)

        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=None
        )

        public_key = private_key.public_key()

    else:
        public_key_path = os.path.join(KEYS_DIR, "public_key.pem")

        with open(public_key_path, "rb") as file:
            public_key = serialization.load_pem_public_key(
                file.read()
            )

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key


# -------------------------------
# Decrypt AES Key
# -------------------------------

def decrypt_aes_key(encrypted_key):

    private_key_b64 = os.getenv("SIGNING_PRIVATE_KEY_B64")

    if private_key_b64:
        import base64

        private_key_data = base64.b64decode(private_key_b64)

        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=None
        )

    else:
        private_key_path = os.path.join(KEYS_DIR, "private_key.pem")

        with open(private_key_path, "rb") as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=None
            )

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return aes_key

def generate_user_keypair():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    return public_pem, private_pem


def encrypt_aes_key_with_public_key(aes_key, public_key_pem):

    public_key = serialization.load_pem_public_key(
        public_key_pem.encode()
    )

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key


def decrypt_aes_key_with_private_key(
        encrypted_key,
        private_key_pem):

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return aes_key