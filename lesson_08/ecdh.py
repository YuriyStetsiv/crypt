from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_sign_keys():
    private_sign_key = ec.generate_private_key(ec.SECP256K1())
    public_sign_key = private_sign_key.public_key()

    return private_sign_key, public_sign_key

def generate_keys():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key

def restore_public_key(public_key: str):
    public_key_bytes = bytes.fromhex(public_key)
    return X25519PublicKey.from_public_bytes(public_key_bytes)

def convert_key_to_hex_format(key):
    key_bytes = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return key_bytes.hex()

# Припустимо що алгоритм генрації уже узгоджено 
# і він відповідає цьому
def generate_derived_key(shared_value):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_value)