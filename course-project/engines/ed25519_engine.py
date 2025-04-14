from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def generate_ed25519_keys():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key

def ed25519_sign(ed25519_private_key: Ed25519PrivateKey, public_key):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signature = ed25519_private_key.sign(public_key_bytes)

    return signature

def ed25519_verify(user_id, ed25519_public_key, signature, public_key):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    ed25519_public_key.verify(signature, public_key_bytes)

def restore_public_key(public_key: str):
    public_key_bytes = bytes.fromhex(public_key)
    return Ed25519PublicKey.from_public_bytes(public_key_bytes)

# Приклад використання
# if __name__ == "__main__":
#     # Генеруємо identity key (довготерміновий ключ)
#     id_private_key, id_public_key = generate_ed25519_keys()
    
#     # Генеруємо, наприклад, ефемерний ключ, який потрібно підписати identity key
#     ephemeral_private, ephemeral_public = generate_ed25519_keys()
    
#     # Підписуємо публічний ефемерний ключ за допомогою identity приватного ключа
#     signature = ed25519_sign(id_private_key, ephemeral_public)
    
#     # Перевіряємо підпис за допомогою identity публічного ключа
#     try:
#         ed25519_verify("User", id_public_key, signature, ephemeral_public)
#     except Exception as e:
#         print("Verification failed:", str(e))
