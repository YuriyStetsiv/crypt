from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.identity_service import IdentityService
from models.handshake_message import HandshakeMessage
from engines.x25519_engine import get_x25519_public_key_bytes
from utils.logger_utils import show_handshake_log

#
# DEPRECATED - більше не використовується
#
async def _send_handshake_message(writer,
                         identity_id: str, 
                         handshake_pulic_key: X25519PublicKey,
                         dh_public_key: X25519PublicKey,
                         identity_private_key: Ed25519PrivateKey,
                         debug_mode: bool) -> None:
    
    handshake_pulic_key_bytes = get_x25519_public_key_bytes(handshake_pulic_key)
    dh_public_key_bytes = get_x25519_public_key_bytes(dh_public_key)
    siganture_data = handshake_pulic_key_bytes + dh_public_key_bytes + identity_id.encode('utf-8')
    signature = identity_private_key.sign(siganture_data)

    handshake_msg = HandshakeMessage(identity_id, 
                                     handshake_pulic_key_bytes, 
                                     dh_public_key_bytes, 
                                     signature)

    if debug_mode:
        show_handshake_log(handshake_msg, 'send')

    writer.write(handshake_msg.serialize() + b"\n")

    await writer.drain()

async def _receive_handshake_message(reader, debug_mode: bool) -> HandshakeMessage:
    line = await reader.readline()
    msg = HandshakeMessage.deserialize(line)

    if debug_mode:
        show_handshake_log(msg, 'receive')

    siganture_data = msg.handshake_public + msg.dh_public + msg.identity_id.encode('utf-8')
    is_verify = IdentityService.verify(msg.identity_id, msg.signature, siganture_data, debug_mode)

    if is_verify:
        return msg
    else:
        raise ValueError(f"Invalid handshake signature from {msg.identity_id}")

async def do_handshake(reader, writer, 
                       identity_id: str,
                       handshake_pulic_key: X25519PublicKey,
                       dh_public_key: X25519PublicKey, 
                       private_identity_key: Ed25519PrivateKey,
                       debug_mode: bool) -> HandshakeMessage:

    await _send_handshake_message(writer,
                                 identity_id, 
                                 handshake_pulic_key,
                                 dh_public_key, 
                                 private_identity_key,
                                 debug_mode)
    
    return await _receive_handshake_message(reader, debug_mode)
