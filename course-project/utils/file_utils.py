import os
from cryptography.hazmat.primitives import serialization

def save_keys(
          private_path: str, 
          public_path: str,
          private_key):
    with open(private_path, "wb") as f:
                f.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )

    with open(public_path, "wb") as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def load_keys(private_path: str, public_path: str):
    if os.path.exists(private_path) and os.path.exists(public_path):
        with open(private_path, "rb") as f:
             private_key = serialization.load_pem_private_key(f.read(), password=None)

        with open(public_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())


        return private_key, public_key