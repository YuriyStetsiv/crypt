from dataclasses import dataclass
import base64, os, json, hashlib

@dataclass
class SecureMessage:
    dh_public: bytes = None                 # Епемеральний публічний ключ відправника (для ECDH)
    nonce: bytes = None                     # 12 байт (nonce для ChaCha20-Poly1305)
    ciphertext: bytes = None             # Зашифрований текст з вбудованим тегом (MAC)
    msg_num: int = 0
    prev_msg_num: int = 0

    signature: bytes  = b''             # Цифровий підпис даних
    identity_id: str = ''


    # AAD-поля (не входять до signed_data)
    # практичного значення для коду немають
    # єдина ціль використння в MAC як приклад
    conversation_id: bytes = hashlib.sha256(b"alice:bob:" + os.urandom(32)).digest() # заглушка
    message_type: str = 'text'     # Напр. "text", "file", "system"
    protocol_version: int = 1      # Напр. 1 або 2

    def get_signed_data(self) -> bytes:
        return (
            self.identity_id.encode("utf-8") +
            self.dh_public +
            self.nonce +
            self.ciphertext +
            self.msg_num.to_bytes(4, "big") +
            self.prev_msg_num.to_bytes(4, "big")
        )
    
    def get_aad(self) -> bytes:
        return (
            self.conversation_id +
            self.message_type.encode("utf-8") +
            self.protocol_version.to_bytes(1, "big")
        )
    
    def serialize(self) -> bytes:
        data = {
            "identity_id": base64.b64encode(self.identity_id.encode()).decode(),
            "dh_public": base64.b64encode(self.dh_public).decode(),  # Замість self.dh_public.encode()
            "nonce": base64.b64encode(self.nonce).decode(),
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
            "signature": base64.b64encode(self.signature).decode() if self.signature is not None else None,
            "msg_num": self.msg_num,
            "prev_msg_num": self.prev_msg_num,
            "conversation_id": base64.b64encode(self.conversation_id).decode(),
            "message_type": self.message_type,
            "protocol_version": self.protocol_version  
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
            msg_num=obj["msg_num"],
            prev_msg_num=obj["prev_msg_num"],
            conversation_id=base64.b64decode(obj.get("conversation_id", "")) if obj.get("conversation_id") else b'',
            message_type=obj.get("message_type", "text"),
            protocol_version=obj.get("protocol_version", 1)  
        )