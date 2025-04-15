import json
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from services.identity_service import IdentityService
import json

# Функція для відправлення handshake з підписом
async def send_handshake(writer, handshake_pulic_key: X25519PublicKey, identity_private_key: Ed25519PrivateKey) -> None:
    handshake_pulic_key_bytes = handshake_pulic_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Підписуємо ефемерний ключ
    signature = identity_private_key.sign(handshake_pulic_key_bytes)

    handshake_msg = {
        "type": "handshake",
        "handshake_pulic": handshake_pulic_key_bytes.hex(),
        "signature": signature.hex()
    }
    writer.write((json.dumps(handshake_msg) + "\n").encode())

    await writer.drain()

async def receive_handshake(reader, identity_public_key: Ed25519PublicKey) -> X25519PublicKey:
    line = await reader.readline()
    handshake_msg = json.loads(line.decode())
    if handshake_msg.get("type") != "handshake":
        raise ValueError("Очікувалось handshake-повідомлення")
    
    handshake_pulic_hex = handshake_msg["handshake_pulic"]
    signature_hex = handshake_msg.get("signature")
    if not signature_hex:
        raise ValueError("Підпис ефемерного ключа відсутній")
    
    received_handshake_pulic_bytes = bytes.fromhex(handshake_pulic_hex)
    signature = bytes.fromhex(signature_hex)

    try:
        identity_public_key.verify(signature, received_handshake_pulic_bytes)
    except Exception as e:
        raise ValueError("Перевірка підпису ефемерного ключа не пройшла") from e
    
    return X25519PublicKey.from_public_bytes(received_handshake_pulic_bytes)

async def do_handshake(reader, writer, 
                       handshake_pulic, 
                       private_identity_key: Ed25519PrivateKey,  
                       user_id:str) -> X25519PublicKey:

    await send_handshake(writer, handshake_pulic, private_identity_key)
    
    identityKey = IdentityService.get_public_key(user_id, False)
    remote_dh_public = await receive_handshake(reader, identityKey)

    return remote_dh_public
