from dataclasses import dataclass
import base64
import json

@dataclass
class HandshakeMessage:
    identity_id: str
    handshake_public: bytes  # для генерації root_key
    dh_public: bytes         # перший DH X25519
    signature: bytes         # підпис

    def serialize(self) -> bytes:
        data = {
            "identity_id": base64.b64encode(self.identity_id.encode()).decode(),
            "handshake_public": base64.b64encode(self.handshake_public).decode(),
            "dh_public": base64.b64encode(self.dh_public).decode(),
            "signature": base64.b64encode(self.signature).decode()
        }
        return json.dumps(data).encode()

    @staticmethod
    def deserialize(data: bytes) -> 'HandshakeMessage':
        obj = json.loads(data.decode())
        return HandshakeMessage(
            identity_id=base64.b64decode(obj["identity_id"]).decode(),
            handshake_public=base64.b64decode(obj["handshake_public"]),
            dh_public=base64.b64decode(obj["dh_public"]),
            signature=base64.b64decode(obj["signature"])
        )
