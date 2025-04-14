from binascii import hexlify
import logging
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey

def show_init_connection_logs(user_id, 
                              dh_private:X25519PrivateKey , 
                              dh_public: X25519PublicKey, 
                              handshake_private:X25519PrivateKey , 
                              handshake_public: X25519PublicKey, 
                              reciev_handshake_public: X25519PublicKey,
                              shared_secret: bytes,
                              initial_root: bytes,):
    
    dh_private_bytes = dh_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    dh_public_bytes = dh_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    handshake_private_bytes = handshake_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    handshake_public_bytes = handshake_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    reciev_handshake_public_bytes = reciev_handshake_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    logging.info(f'[Client] {user_id} init_connection:')
    logging.info(f'[Client] {user_id} dh_private: {hexlify(dh_private_bytes)}')
    logging.info(f'[Client] {user_id} dh_public: {hexlify(dh_public_bytes)}') 
    logging.info(f'[Client] {user_id} handshake_private_key: {hexlify(handshake_private_bytes)}')
    logging.info(f'[Client] {user_id} handshake_public_key: {hexlify(handshake_public_bytes)}')
    logging.info(f'[Client] reciev_handshake_public_bytes: {hexlify(reciev_handshake_public_bytes)}') 
    logging.info(f'[Client] shared_secret: {hexlify(shared_secret)}')
    logging.info(f'[Client] double_ratchet_initial_root: {hexlify(initial_root)}')      