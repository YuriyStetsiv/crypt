from dataclasses import dataclass
import base64
import json

@dataclass
class SecureMessage:
    user_id: str
    dh_public: bytes  # Епемеральний публічний ключ відправника (для ECDH)
    nonce: bytes                   # 12 байт (nonce для ChaCha20-Poly1305)
    ciphertext: bytes              # Зашифрований текст з вбудованим тегом (MAC)
    #signature: bytes               # Цифровий підпис даних (ephemeral_public_bytes + nonce + ciphertext)

    def serialize(self) -> bytes:
        data = {
            "user_id": base64.b64encode(self.user_id.encode()).decode(),
            "dh_public": base64.b64encode(self.dh_public).decode(),  # Замість self.dh_public.encode()
            "nonce": base64.b64encode(self.nonce).decode(),
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
            # "signature": base64.b64encode(self.signature).decode() if self.signature is not None else None,
        }
        return json.dumps(data).encode()

    @staticmethod
    def deserialize(data: bytes) -> 'SecureMessage':
        obj = json.loads(data.decode())
        return SecureMessage(
            user_id=base64.b64decode(obj["user_id"]).decode(),
            dh_public=base64.b64decode(obj["dh_public"]),
            nonce=base64.b64decode(obj["nonce"]),
            ciphertext=base64.b64decode(obj["ciphertext"]),
            # signature=base64.b64decode(obj["signature"]) if obj.get("signature") else None,
        )