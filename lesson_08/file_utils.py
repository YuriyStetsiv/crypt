import json
import os
from cryptography.hazmat.primitives import serialization

from models.payload import PAYLOAD

def load_payload(path):
    if os.path.exists(path):
        with open(path, 'r') as f:
            try:
                file_payload = json.load(f)
                return PAYLOAD.from_dict(file_payload)
                 
            except json.JSONDecodeError:
                return PAYLOAD()
    return PAYLOAD()



def save_key(path: str, pub_sign_key):
    pem_public_key = pub_sign_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(path, "wb") as f:
        f.write(pem_public_key)

def load_key(path: str):
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    
    return public_key