from models.secure_message import SecureMessage
from services.identity_service import IdentityService
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from double_ratchet import DoubleRatchet
from utils.logger_utils import show_message_logs

class MessageService:
    def __init__(self, dr_instance: DoubleRatchet, user_id: str, debug_mode: bool):
        self.dr_instance = dr_instance
        self.user_id = user_id
        self.debug_mode = debug_mode

    def generate_message(self, message: str, private_identity_key: Ed25519PrivateKey) -> bytes:
        packet = self.dr_instance.encrypt(message.encode())
        header = packet["header"]
        ciphertext_hex = packet["ciphertext"]

        # Витягуємо дані з header: якщо є, то ефемерний DH публічний ключ та nonce
        dh_public = bytes.fromhex(header["dh"]) if "dh" in header else None
        nonce = bytes.fromhex(header["nonce"]) if "nonce" in header else None
        signature = private_identity_key.sign(dh_public)

        # Формуємо об'єкт SecureMessage, який пакує ці дані
        secure_msg = SecureMessage(
            user_id=self.user_id,
            dh_public=dh_public,
            nonce=nonce,
            ciphertext=bytes.fromhex(ciphertext_hex),
            signature=signature 
        )

        if self.debug_mode:
            show_message_logs(secure_msg)

        return secure_msg.serialize()

    def parse_message(self, data: bytes):
        secure_msg = SecureMessage.deserialize(data)

        if self.debug_mode:
            show_message_logs(secure_msg)

        is_verify = IdentityService.verify(secure_msg.user_id, 
                                           secure_msg.signature, 
                                           secure_msg.dh_public,
                                           self.debug_mode)
        if is_verify:
            header = {}
            if secure_msg.dh_public is not None:
                header["dh"] = secure_msg.dh_public.hex()
            if secure_msg.nonce is not None:
                header["nonce"] = secure_msg.nonce.hex()

            # Отримуємо ciphertext у hex-форматі
            ciphertext_hex = secure_msg.ciphertext.hex()
            plaintext = self.dr_instance.decrypt(header, ciphertext_hex)

            return plaintext.decode()
        else:
            return '[Error] Signature not valid'
