from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives import serialization

def generate_x25519_keys():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key

def restore_x25519_public_key(public_key: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(public_key)

def get_x25519_public_key_bytes(public_key: X25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def get_x25519_private_key_bytes(private_key: X25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )