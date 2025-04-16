from dataclasses import dataclass
import base64
import json

@dataclass
class SecureMessage:
    dh_public: bytes               # Епемеральний публічний ключ відправника (для ECDH)
    nonce: bytes                   # 12 байт (nonce для ChaCha20-Poly1305)
    ciphertext: bytes              # Зашифрований текст з вбудованим тегом (MAC)
    msg_num: int
    signature: bytes  = b''             # Цифровий підпис даних (ephemeral_public_bytes + nonce + ciphertext)
    identity_id: str = ''

    def serialize(self) -> bytes:
        data = {
            "identity_id": base64.b64encode(self.identity_id.encode()).decode(),
            "dh_public": base64.b64encode(self.dh_public).decode(),  # Замість self.dh_public.encode()
            "nonce": base64.b64encode(self.nonce).decode(),
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
            "signature": base64.b64encode(self.signature).decode() if self.signature is not None else None,
            "msg_num": self.msg_num      
        }
        return json.dumps(data).encode()

    @staticmethod
    def deserialize(data: bytes) -> 'SecureMessage':
        obj = json.loads(data.decode())
        return SecureMessage(
            identity_id=base64.b64decode(obj["identity_id"]).decode(),
            dh_public=base64.b64decode(obj["dh_public"]),
            nonce=base64.b64decode(obj["nonce"]),
            ciphertext=base64.b64decode(obj["ciphertext"]),
            signature=base64.b64decode(obj["signature"]) if obj.get("signature") else None,
            msg_num=obj["msg_num"]  
        )