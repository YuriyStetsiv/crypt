from models.secure_message import SecureMessage
from services.identity_service import IdentityService
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from double_ratchet import DoubleRatchet
from utils.logger_utils import show_message_logs
from engines.x25519_engine import get_x25519_public_key_bytes

class MessageService:
    def __init__(self, dr_instance: DoubleRatchet, identity_id: str, debug_mode: bool):
        self.dr_instance = dr_instance
        self.identity_id = identity_id
        self.debug_mode = debug_mode

    def generate_message(self, message: str, private_identity_key: Ed25519PrivateKey) -> bytes:
        secure_msg = SecureMessage(identity_id=self.identity_id)
                
        nonce, ciphertext = self.dr_instance.encrypt(message.encode(),secure_msg.get_aad())

        secure_msg.dh_public=get_x25519_public_key_bytes(self.dr_instance.dh_public)
        secure_msg.nonce=nonce
        secure_msg.ciphertext=ciphertext
        secure_msg.msg_num=self.dr_instance.send_msg_number     
        secure_msg.prev_msg_num=self.dr_instance.prev_msg_number
        secure_msg.signature = private_identity_key.sign(secure_msg.get_signed_data())

        if self.debug_mode:
            show_message_logs(secure_msg, 'send')

        return secure_msg.serialize()

    def parse_message(self, data: bytes):
        secure_msg = SecureMessage.deserialize(data)

        if self.debug_mode:
            show_message_logs(secure_msg, 'reciev')

        is_verify = IdentityService.verify(secure_msg.identity_id, 
                                           secure_msg.signature, 
                                           secure_msg.get_signed_data(),
                                           self.debug_mode)
        if is_verify:
            return self.dr_instance.decrypt(secure_msg).decode()
        else:
            return '[Error] Signature not valid'
