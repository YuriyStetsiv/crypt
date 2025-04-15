import asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
import sys 

from models.constants import Constants

from services.identity_service import IdentityService
from services.key_service import derive_initial_root
from services.message_service import MessageService
from engines.x25519_engine import generate_x25519_keys
from handshake import do_handshake
from double_ratchet import DoubleRatchet

from utils.server_utils import bob_client, show, prompt, read_message_from_stdin
from utils.logger_utils import show_init_connection_logs

debug_mode = False
private_identity_key: Ed25519PrivateKey
public_idenity_key: Ed25519PublicKey

message_service: MessageService

async def receive(reader):
    """Receive data from other party"""
    while True:
        # Receive data from Alice (can be multiple messages)
        data = await reader.read(1024)
        if not data:
            break

        try:
            message = message_service.parse_message(data)
            show(message)
        except Exception as e:
            show(f"[ERROR] Failed to decrypt message: {e}")

        prompt()

async def send(writer):
    """Send data to other party"""
    while True:
        message = await read_message_from_stdin()

        if message.strip().lower() == "q":
            print("Exit")
            writer.close()
            await writer.wait_closed()
            sys.exit(0)      
            
        # {ENCRYPT HERE}
        data = message_service.generate_message(message, private_identity_key)

        # Send message
        writer.write(data)

        prompt()
        await writer.drain()

async def init_connection():
    reader, writer = await bob_client()
    print("Connected to Alice!")
    prompt()

    # INITIAL EXCHANGE HERE
    global private_identity_key, public_idenity_key
    private_identity_key, public_idenity_key = IdentityService.init_keys(Constants.BOB, debug_mode)

    # Генеруємо DH пару для Double Ratchet
    bob_dh_private, bob_dh_public = generate_x25519_keys()
    bob_handshake_private, bob_handshake_public = generate_x25519_keys()

    # Виконуємо handshake: відправляємо свій публічний ключ і отримуємо публічний ключ Alice
    alice_handshake_public = await do_handshake(reader, writer, bob_handshake_public, private_identity_key, Constants.ALICE)
    shared_secret = bob_handshake_private.exchange(alice_handshake_public)
    initial_root = derive_initial_root(shared_secret)


    if debug_mode:
        show_init_connection_logs(Constants.BOB, 
                                  bob_dh_private,
                                  bob_dh_public,
                                  bob_handshake_private, 
                                  bob_handshake_public, 
                                  alice_handshake_public,
                                  shared_secret,
                                  initial_root) 


    dr = DoubleRatchet(initial_root, bob_handshake_private, bob_handshake_public, alice_handshake_public, debug_mode)
    dr.dh_ratchet(alice_handshake_public, False)
   
    global message_service
    message_service = MessageService(dr, Constants.BOB, debug_mode)
    
    await asyncio.gather(receive(reader), send(writer))

async def init_connection_wrapper(debug=False):
    global debug_mode
    debug_mode = debug

    if debug_mode:
        print("Bob is running in debug mode")

    await init_connection()

if __name__ == "__main__":
    print("Starting Bob's chat...")
    asyncio.run(init_connection())
