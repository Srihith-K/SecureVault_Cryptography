import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


PRIVATE_KEY_PATH = "keys/private_key.pem"
PUBLIC_KEY_PATH = "keys/public_key.pem"


# ----------------------------------------------------
# Load Private Key
# ----------------------------------------------------
def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )


# ----------------------------------------------------
# Load Public Key
# ----------------------------------------------------
def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read()
        )


# ----------------------------------------------------
# Sign Data
# ----------------------------------------------------
def sign_data(data: bytes) -> str:
    """
    Returns Base64 encoded digital signature
    """

    private_key = load_private_key()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return base64.b64encode(signature).decode("utf-8")


# ----------------------------------------------------
# Verify Signature
# ----------------------------------------------------
def verify_signature(data: bytes, signature: str) -> bool:

    public_key = load_public_key()

    try:

        public_key.verify(
            base64.b64decode(signature),
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return True

    except InvalidSignature:

        return False