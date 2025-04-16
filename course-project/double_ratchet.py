from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from binascii import hexlify
from models.secure_message import SecureMessage
from engines.chipher_engine import CipherEngine
from engines.x25519_engine import get_x25519_public_key_bytes
from utils.logger_utils import show_ratchet_logs
from services.key_service import kdf_chain, derive_double_ratchet_keys

MAX_SKIP = 20

class DoubleRatchet:
    def __init__(self, root_key: bytes, dh_private: X25519PrivateKey,
                 dh_public: X25519PublicKey, remote_dh_public: X25519PublicKey,
                 debug_mode: bool):
        self.root_key = root_key
        self.dh_private = dh_private
        self.dh_public = dh_public
        self.remote_dh_public = remote_dh_public
        self.send_chain = None
        self.recv_chain = None
        self.send_msg_number = 0
        self.recv_msg_number = 0
        self.skipped_keys = {}  # {(dh_public_bytes, msg_num): message_key}
        self.debug_mode = debug_mode
    
    def _dh_ratchet(self, new_remote_dh_public: X25519PublicKey, is_initiator: bool):
        shared_secret = self.dh_private.exchange(new_remote_dh_public)
        new_root, chain_key_1, chain_key_2 = derive_double_ratchet_keys(self.root_key, shared_secret)
        self.root_key = new_root

        if is_initiator:
            self.send_chain = chain_key_1
            self.recv_chain = chain_key_2
        else:
            self.recv_chain = chain_key_1
            self.send_chain = chain_key_2

        self.dh_private = X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key()
        self.remote_dh_public = new_remote_dh_public
        self.send_msg_number = 0
        self.recv_msg_number = 0

        if self.debug_mode:
            show_debug_logs(self, shared_secret = shared_secret,  operation='update')
    
    #  Поки що encrypt\decrypt
    #  Відбувається на основі спільного секрету
    #  оскільки не виходить синхронізувати ретчет після першого повідомлення
    def encrypt(self, plaintext: bytes) -> SecureMessage:
        engine = CipherEngine(key=self.root_key)
        nonce, ciphertext = engine.encrypt(plaintext)

        if self.debug_mode:
            show_debug_logs(self, message_key=self.root_key, operation='encrypt')

        return SecureMessage(         
            dh_public=get_x25519_public_key_bytes(self.dh_public),         
            nonce=nonce,
            ciphertext=ciphertext,
            msg_num=0
        )
    
    def decrypt(self, secure_message: SecureMessage) -> bytes:
        return self._decrypt_with(self.root_key, secure_message)  

    def _decrypt_with(self, message_key: bytes, secure_message: SecureMessage) -> bytes:
        engine = CipherEngine(key=message_key)      
        plaintext = engine.decrypt(secure_message.nonce, secure_message.ciphertext)

        if self.debug_mode:
            show_debug_logs(self, message_key=message_key, operation='decrypt')

        return plaintext

    def _advance_send_chain(self) -> bytes:
        self.send_chain, message_key = kdf_chain(self.send_chain)
        self.send_msg_number += 1
        return message_key

    def _advance_recv_chain(self) -> bytes:
        self.recv_chain, message_key = kdf_chain(self.recv_chain)
        self.recv_msg_number += 1
        return message_key
    
@staticmethod
def show_debug_logs(self, 
                    shared_secret: bytes | None = None,
                    message_key: bytes | None = None, 
                    operation: str | None = None):
        if self.debug_mode:
            show_ratchet_logs(self.root_key, 
                            self.dh_private, 
                            self.dh_public,
                            self.remote_dh_public,
                            self.send_chain,
                            self.recv_chain,
                            self.send_msg_number,
                            self.recv_msg_number,
                            shared_secret,
                            message_key,
                            operation)