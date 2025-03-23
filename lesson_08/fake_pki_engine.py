from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def verify_key(public_sign_key, payload, signature_flag):
    public_sign_key.verify(
        bytes.fromhex(payload.signature),
        bytes.fromhex(payload.public_key),
        ec.ECDSA(hashes.SHA256())
    )

    print(f"{signature_flag}: signature is valid!")

def sign_key(public_key, private_sign_key, signature_flag):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    signature_eccdh = private_sign_key.sign(
        public_key_bytes,
        ec.ECDSA(hashes.SHA256())
    )

    print(f"{signature_flag}: signature created")
    return signature_eccdh.hex()