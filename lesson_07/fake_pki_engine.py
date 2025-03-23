from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_sign(rsa_private_key, public_key):
    signature = rsa_private_key.sign(
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    return signature

def rsa_verify(user_id, rsa_public_key, signature, public_key):
    rsa_public_key.verify(
        signature,
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    print(f"{user_id} signature is valid.")