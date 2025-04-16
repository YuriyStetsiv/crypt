from binascii import hexlify
import logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from models.secure_message import SecureMessage
from models.handshake_message import HandshakeMessage
from engines.x25519_engine import get_x25519_public_key_bytes, get_x25519_private_key_bytes
from engines.ed25519_engine import get_ed25519_public_key_bytes, get_ed25519_private_key_bytes

def show_init_connection_logs(identity_id, 
                              dh_private:X25519PrivateKey , 
                              dh_public: X25519PublicKey, 
                              handshake_private:X25519PrivateKey , 
                              handshake_public: X25519PublicKey, 
                              reciev_dh_public: bytes,
                              shared_secret: bytes,
                              initial_root: bytes,):
    
    dh_private_bytes = get_x25519_private_key_bytes(dh_private)
    dh_public_bytes = get_x25519_public_key_bytes(dh_public)
    handshake_private_bytes = get_x25519_private_key_bytes(handshake_private)
    handshake_public_bytes = get_x25519_public_key_bytes(handshake_public)

    logging.info(f'[Client] {identity_id} configuration:')
    logging.info(f'[Client] {identity_id} dh_private: {hexlify(dh_private_bytes)}')
    logging.info(f'[Client] {identity_id} dh_public: {hexlify(dh_public_bytes)}') 
    logging.info(f'[Client] {identity_id} handshake_private_key: {hexlify(handshake_private_bytes)}')
    logging.info(f'[Client] {identity_id} handshake_public_key: {hexlify(handshake_public_bytes)}')
    logging.info(f'[Client] reciev_dh_public: {hexlify(reciev_dh_public)}') 
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
    
    dh_private_bytes = get_x25519_private_key_bytes(dh_private)
    dh_public_bytes = get_x25519_public_key_bytes(dh_public)
    remote_dh_public_bytes = get_x25519_public_key_bytes(remote_dh_public)

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

    print('')

def show_identity_logs(identity_id: str, private_key:Ed25519PrivateKey,  public_key: Ed25519PublicKey):
    private_bytes = get_ed25519_private_key_bytes(private_key)
    public_bytes = get_ed25519_public_key_bytes(public_key)

    logging.info(f'[Identity] {identity_id} ed25519 init_keys:')
    logging.info(f'[Identity] {identity_id} ed25519 private_key: {hexlify(private_bytes)}')
    logging.info(f'[Identity] {identity_id} ed25519 public_key: {hexlify(public_bytes)}')

    print('')

def show_message_logs(secure_message: SecureMessage, action: str):
    logging.info(f'[Message] {action} info:')
    logging.info(f'[Message] identity_id: {secure_message.identity_id}')
    logging.info(f'[Message] dh_public: {hexlify(secure_message.dh_public)}')
    logging.info(f'[Message] nonce: {hexlify(secure_message.nonce)}')
    logging.info(f'[Message] ciphertext: {hexlify(secure_message.ciphertext)}')
    logging.info(f'[Message] msg_num: {secure_message.msg_num}')
    logging.info(f'[Message] signature: {hexlify(secure_message.signature)}')

    print('')

def show_handshake_log(hanshake_message: HandshakeMessage, action: str):
    logging.info(f'[Handshake] {action} info:')
    logging.info(f'[Handshake] identity_id: {hanshake_message.identity_id}')
    logging.info(f'[Handshake] handshake_public: {hexlify(hanshake_message.handshake_public)}')
    logging.info(f'[Handshake] dh_public: {hexlify(hanshake_message.dh_public)}')
    logging.info(f'[Handshake] signature: {hexlify(hanshake_message.signature)}')

    print('')