from cryptography.hazmat.primitives.serialization import load_pem_public_key

def load_file(path):
    with open(path, "r") as text_file:
        file = bytes.fromhex(text_file.read())

    return file

def load_key(path):
    with open(path, "rb") as key_file:
        public_key = load_pem_public_key(key_file.read())

    return public_key