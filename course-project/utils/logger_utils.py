from binascii import hexlify
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey

from models.secure_message import SecureMessage

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

    print('\n')

def show_ratchet_logs(root_key: bytes,
                      dh_private: X25519PrivateKey,
                      dh_public: X25519PublicKey,
                      remote_dh_public: X25519PublicKey,
                      send_chain: bytes | None,
                      recv_chain: bytes | None,
                      send_msg_number,
                      recv_msg_number, 
                      message_key: bytes | None = None,
                      operation: str | None = None):
    
    dh_private_bytes = dh_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    dh_public_bytes = dh_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw       
    )

    remote_dh_public_bytes = remote_dh_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw        
    )


    if send_chain is None:
        send_chain_info = 'None'
    else:
        send_chain_info = hexlify(send_chain).decode()

    if recv_chain is None:
        recv_chain_info = 'None'
    else:
        recv_chain_info = hexlify(recv_chain).decode()
    
    if operation is None:
        logging.info(f'[Ratchet] configurations:')
    else:
        logging.info(f'[Ratchet] {operation} configurations:')

    logging.info(f'[Ratchet] root_key: {hexlify(root_key)}')
    logging.info(f'[Ratchet] dh_private: {hexlify(dh_private_bytes)}')
    logging.info(f'[Ratchet] dh_public: {hexlify(dh_public_bytes)}')
    logging.info(f'[Ratchet] remote_dh_public: {hexlify(remote_dh_public_bytes)}')
    logging.info(f'[Ratchet] send_chain: {send_chain_info}')
    logging.info(f'[Ratchet] recv_chain: {recv_chain_info}')
    logging.info(f'[Ratchet] send_msg_number: {send_msg_number}')
    logging.info(f'[Ratchet] recv_msg_number: {recv_msg_number}')

    if message_key is not None:
        logging.info(f'[Ratchet] key_message: {hexlify(message_key)}')

    print('\n')

def show_identity_logs(user_id: str, private_key,  public_key):
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    logging.info(f'[Identity] {user_id} ed25519 init_keys:')
    logging.info(f'[Identity] {user_id} ed25519 private_key: {hexlify(private_bytes)}')
    logging.info(f'[Identity] {user_id} ed25519 public_key: {hexlify(public_bytes)}')

def show_message_logs(secure_message: SecureMessage):
    logging.info(f'[Message] info:')
    logging.info(f'[Message] message.user_id: {secure_message.user_id}')
    logging.info(f'[Message] message.dh_public: {hexlify(secure_message.dh_public)}')
    logging.info(f'[Message] message.nonce: {hexlify(secure_message.nonce)}')
    logging.info(f'[Message] message.ciphertext: {hexlify(secure_message.ciphertext)}')
    logging.info(f'[Message] message.signature: {hexlify(secure_message.signature)}')
