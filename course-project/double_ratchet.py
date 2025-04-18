from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from models.secure_message import SecureMessage
from engines.chipher_engine import CipherEngine
from engines.x25519_engine import get_x25519_public_key_bytes
from utils.logger_utils import show_ratchet_logs, show_skipped_key_log
from services.key_service import KDF_Root_Key, KDF_Chain_Key
from engines.x25519_engine import generate_x25519_keys

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
        self.prev_msg_number = 0
        self.skipped_keys = {}  # {(dh_public_bytes, msg_num): message_key}
        self.debug_mode = debug_mode
    
    def _dh_ratchet(self, new_remote_dh_public: X25519PublicKey):
        shared_secret = self.dh_private.exchange(new_remote_dh_public)
        self.root_key, self.recv_chain = KDF_Root_Key(self.root_key, shared_secret)
        
        self.dh_private, self.dh_public = generate_x25519_keys()
        shared_secret = self.dh_private.exchange(new_remote_dh_public)
        self.root_key, self.send_chain = KDF_Root_Key(self.root_key, shared_secret)

        self.remote_dh_public = new_remote_dh_public
        self.prev_msg_number = self.send_msg_number
        self.send_msg_number = 0
        self.recv_msg_number = 0

        if self.debug_mode:
            show_debug_logs(self, shared_secret = shared_secret,  operation='update')

    def _dh_ratchet_initial(self):
        shared_secret = self.dh_private.exchange(self.remote_dh_public)
        self.root_key , self.send_chain = KDF_Root_Key(self.root_key, shared_secret)
  
        if self.debug_mode:
            show_debug_logs(self, shared_secret = shared_secret,  operation='update')
    
    def encrypt(self, plaintext: bytes, aad: bytes) -> tuple:
        if self.send_chain is None:
            self._dh_ratchet_initial()

        message_key = self._advance_send_chain()
        engine = CipherEngine(key=message_key)
        nonce, ciphertext = engine.encrypt(plaintext, aad)

        if self.debug_mode:
            show_debug_logs(self, message_key=message_key, operation='encrypt')

        return nonce, ciphertext
    
    def decrypt(self, secure_message: SecureMessage) -> bytes:
        plaintext = self._decrypt_by_skipped_key(secure_message)
        if plaintext is not None:
            return plaintext

        is_new_dh = (
            self.remote_dh_public is None or
            get_x25519_public_key_bytes(self.remote_dh_public) != secure_message.dh_public
        )

        if is_new_dh:
            new_remote_dh_public = X25519PublicKey.from_public_bytes(secure_message.dh_public)
            self._generate_skipped_keys(secure_message.prev_msg_num)
            self._dh_ratchet(new_remote_dh_public)

        self._generate_skipped_keys(secure_message.msg_num)
        message_key = self._advance_recv_chain()

        try:
            return self._decrypt_with(message_key, secure_message)
        except Exception as e:
            return b'[ERROR] Failed to decrypt message]'

    
    def _decrypt_with(self, message_key: bytes, secure_message: SecureMessage) -> bytes:
        engine = CipherEngine(key=message_key)      
        plaintext = engine.decrypt(secure_message.nonce, 
                                   secure_message.ciphertext,
                                   secure_message.get_aad())

        if self.debug_mode:
            show_debug_logs(self, message_key=message_key, operation='decrypt')

        return plaintext

    def _generate_skipped_keys(self, msg_num) -> None:
        if self.recv_msg_number + MAX_SKIP < msg_num:
            raise Exception(f'[ERROR] Too much keys skipped.')
        
        if self.recv_chain != None:
            dh_bytes = get_x25519_public_key_bytes(self.remote_dh_public)
            while self.recv_msg_number + 1 < msg_num:
                self.recv_chain, message_key = KDF_Chain_Key(self.recv_chain)
                self.skipped_keys[dh_bytes, self.recv_msg_number] = message_key

                if self.debug_mode:
                    show_skipped_key_log(dh_bytes, self.send_msg_number, message_key)

                self.recv_msg_number +=1

    def _decrypt_by_skipped_key(self, secure_message: SecureMessage)->bytes | None:
        key_id = (secure_message.dh_public, secure_message.msg_num)

        if key_id in self.skipped_keys:
            message_key = self.skipped_keys.pop(key_id)

            return self._decrypt_with(message_key, secure_message)

        return None

    def _advance_send_chain(self) -> bytes:
        self.send_chain, message_key = KDF_Chain_Key(self.send_chain)
        self.send_msg_number += 1

        return message_key

    def _advance_recv_chain(self) -> bytes:
        self.recv_chain, message_key = KDF_Chain_Key(self.recv_chain)
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
                            self.prev_msg_number,
                            shared_secret,
                            message_key,
                            operation)