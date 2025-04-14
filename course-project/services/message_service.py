from models.secure_message import SecureMessage
from services.identity_service import IdentityService
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

class MessageService:
    def generate_message(user_id: str, message: str, private_identity_key: Ed25519PrivateKey) -> bytes:
        chiphertext=message.strip().encode()

        secure_msg = SecureMessage(user_id=user_id, ciphertext=chiphertext)

        return secure_msg.serialize()
    
    def parse_message(data: bytes):
        secure_msg = SecureMessage.deserialize(data)

        identityKey = IdentityService.get_public_key(secure_msg.user_id, False)
        
        return secure_msg.ciphertext.decode()