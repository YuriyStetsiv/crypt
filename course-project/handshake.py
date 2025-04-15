import json
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from services.identity_service import IdentityService
import json

# Функція для відправлення handshake з підписом
async def send_handshake(writer, local_dh_public: X25519PublicKey, identity_private_key: Ed25519PrivateKey) -> None:
    # Отримуємо байтове представлення ефемерного публічного ключа
    local_dh_bytes = local_dh_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Підписуємо ефемерний ключ
    signature = identity_private_key.sign(local_dh_bytes)

    handshake_msg = {
        "type": "handshake",
        "dh_public": local_dh_bytes.hex(),
        "signature": signature.hex()
    }
    writer.write((json.dumps(handshake_msg) + "\n").encode())

    await writer.drain()

async def receive_handshake(reader, identity_public_key: Ed25519PublicKey) -> X25519PublicKey:
    """
    Приймає handshake-повідомлення, перевіряє підпис і повертає отриманий публічний ключ.
    """
    line = await reader.readline()
    handshake_msg = json.loads(line.decode())
    if handshake_msg.get("type") != "handshake":
        raise ValueError("Очікувалось handshake-повідомлення")
    
    dh_public_hex = handshake_msg["dh_public"]
    signature_hex = handshake_msg.get("signature")
    if not signature_hex:
        raise ValueError("Підпис ефемерного ключа відсутній")
    
    received_dh_public_bytes = bytes.fromhex(dh_public_hex)
    signature = bytes.fromhex(signature_hex)

    try:
        identity_public_key.verify(signature, received_dh_public_bytes)
    except Exception as e:
        raise ValueError("Перевірка підпису ефемерного ключа не пройшла") from e
    
    return X25519PublicKey.from_public_bytes(received_dh_public_bytes)

async def do_handshake(reader, writer, 
                       local_dh_public, 
                       private_identity_key: Ed25519PrivateKey,  
                       user_id:str) -> X25519PublicKey:
    """
    Виконує повноцінний handshake: відправляє свій публічний ключ і чекає на публічний ключ співрозмовника.
    """
    await send_handshake(writer, local_dh_public, private_identity_key)
    
    identityKey = IdentityService.get_public_key(user_id, False)
    remote_dh_public = await receive_handshake(reader, identityKey)

    return remote_dh_public
