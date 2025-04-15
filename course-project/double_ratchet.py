from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from binascii import hexlify

from services.key_service import kdf_chain, derive_double_ratchet_keys
from engines.chipher_engine import CipherEngine
from utils.logger_utils import show_ratchet_logs


class DoubleRatchet:
    def __init__(self, root_key: bytes, dh_private: X25519PrivateKey,
                 dh_public: X25519PublicKey, remote_dh_public: X25519PublicKey,
                 debug_mode: bool):
        self.root_key = root_key
        self.dh_private = dh_private
        self.dh_public = dh_public
        self.remote_dh_public = remote_dh_public
        self.send_chain = None  # Встановиться після першого DH ratchet
        self.recv_chain = None
        self.send_msg_number = 0
        self.recv_msg_number = 0
        self.debug_mode = debug_mode

    def dh_ratchet(self, new_remote_dh_public: X25519PublicKey):
        shared_secret = self.dh_private.exchange(new_remote_dh_public)
        new_root, new_send_chain, new_recv_chain = derive_double_ratchet_keys(self.root_key, shared_secret)

        self.root_key = new_root
        self.send_chain = new_send_chain
        self.recv_chain = new_recv_chain

        # Генеруємо нову DH пару для наступних ratchet-оновлень
        self.dh_private = X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key()
        self.remote_dh_public = new_remote_dh_public
        self.send_msg_number = 0
        self.recv_msg_number = 0

        if self.debug_mode:
            show_ratchet_logs(self.root_key, 
                              self.dh_private, 
                              self.dh_public,
                              self.remote_dh_public,
                              self.send_chain,
                              self.recv_chain,
                              self.send_msg_number,
                              self.recv_msg_number)

    def advance_send_chain(self) -> bytes:
        self.send_chain, message_key = kdf_chain(self.send_chain)
        self.send_msg_number += 1

        return message_key

    def advance_recv_chain(self) -> bytes:
        self.recv_chain, message_key = kdf_chain(self.recv_chain)
        self.recv_msg_number += 1

        return message_key

    def encrypt(self, plaintext: bytes) -> dict:
        header = {}

        if self.send_msg_number == 0:
            header['dh'] = self.dh_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex()
        else: 
            header['dh'] = self.dh_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex()

        message_key = self.advance_send_chain()

        print(f'message_key: {hexlify(message_key)}')

        engine = CipherEngine(key=message_key)
        nonce, ciphertext = engine.encrypt(plaintext)

        header['nonce'] = nonce.hex()
        header['msg_num'] = self.send_msg_number

        return {'header': header, 'ciphertext': ciphertext.hex()}

    def decrypt(self, header: dict, ciphertext_hex: str) -> bytes:
        if 'dh' in header:
            remote_dh_bytes = bytes.fromhex(header['dh'])
            new_remote_dh_public = X25519PublicKey.from_public_bytes(remote_dh_bytes)
            
            # Якщо отримано новий DH ключ – виконуємо ratchet update           
            if (self.remote_dh_public is None or 
                self.remote_dh_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw) != remote_dh_bytes):
                self.dh_ratchet(new_remote_dh_public)

        message_key = self.advance_recv_chain()
        print(f'message_key: {hexlify(message_key)}')

        nonce = bytes.fromhex(header['nonce'])
        ciphertext = bytes.fromhex(ciphertext_hex)

        engine = CipherEngine(key=message_key)

        return engine.decrypt(nonce, ciphertext)