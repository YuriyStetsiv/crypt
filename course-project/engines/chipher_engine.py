import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class CipherEngine:
    def __init__(self, key: bytes = None):
        self.key = key or ChaCha20Poly1305.generate_key()

    def encrypt(self, plaintext: bytes, aad: bytes = b'') -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(self.key)
        ciphertext = chacha.encrypt(nonce, plaintext, aad)

        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes = b'') -> bytes:
        chacha = ChaCha20Poly1305(self.key)

        return chacha.decrypt(nonce, ciphertext, aad)