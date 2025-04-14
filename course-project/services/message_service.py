from models.secure_message import SecureMessage
from services.identity_service import IdentityService
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from double_ratchet import DoubleRatchet

class MessageService:
    def __init__(self, dr_instance: DoubleRatchet, user_id: str):
        """
        Конструктор, який встановлює Double Ratchet instance.
        Параметр dr_instance – це об'єкт DoubleRatchet, який використовується для
        шифрування/дешифрування повідомлень.
        """
        self.dr_instance = dr_instance
        self.user_id = user_id

    def generate_message(self, message: str, private_identity_key: Ed25519PrivateKey) -> bytes:
        packet = self.dr_instance.encrypt(message.encode())
        header = packet["header"]
        ciphertext_hex = packet["ciphertext"]

        print(packet)
        print(header)
        print(ciphertext_hex)

        # Витягуємо дані з header: якщо є, то ефемерний DH публічний ключ та nonce
        dh_public = bytes.fromhex(header["dh"]) if "dh" in header else None
        nonce = bytes.fromhex(header["nonce"]) if "nonce" in header else None

        # Формуємо об'єкт SecureMessage, який пакує ці дані
        secure_msg = SecureMessage(
            user_id=self.user_id,
            dh_public=dh_public,
            nonce=nonce,
            ciphertext=bytes.fromhex(ciphertext_hex),
            #signature=None  # Підпис можна додати окремо, якщо потрібен
        )
        return secure_msg.serialize()

    def parse_message(self, data: bytes):
        secure_msg = SecureMessage.deserialize(data)

        header = {}
        if secure_msg.dh_public is not None:
            header["dh"] = secure_msg.dh_public.hex()
        if secure_msg.nonce is not None:
            header["nonce"] = secure_msg.nonce.hex()

        # Отримуємо ciphertext у hex-форматі
        ciphertext_hex = secure_msg.ciphertext.hex()
        print(ciphertext_hex)
        print(header)
        plaintext = self.dr_instance.decrypt(header, ciphertext_hex)

        return plaintext.decode()
