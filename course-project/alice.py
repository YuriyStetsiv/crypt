import asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from binascii import hexlify

from models.constants import Constants

from models.secure_message import SecureMessage
from services.identity_service import IdentityService
from services.message_service import MessageService
from engines.ed25519_engine import generate_ed25519_keys
from engines.x25519_engine import generate_x25519_keys
from handshake import do_handshake,derive_initial_root
from double_ratchet import DoubleRatchet

from utils.server_utils import alice_server, prompt, show, read_message_from_stdin
from utils.logger_utils import show_init_connection_logs

debug_mode = False
private_identity_key: Ed25519PrivateKey
public_idenity_key: Ed25519PublicKey


async def receive(reader):
    """Receive data from other party"""
    while True:
        # Receive data from Bob (can be multiple messages)
        data = await reader.read(1024)
        if not data:
            break

        try:    
            message = MessageService.parse_message(data)
            show(message)
        except Exception as e:
            show(f"[ERROR] Failed to decrypt message: {e}")

        prompt()


async def send(writer):
    """Send data to other party"""
    while True:
        message = await read_message_from_stdin()

        # {ENCRYPT HERE}
        data = MessageService.generate_message(Constants.ALICE, message, private_identity_key)

        # Send message
        writer.write(data)

        prompt()
        await writer.drain()


async def init_connection(reader, writer):
    print("Connected with Bob!")
    prompt()

    # INITIAL EXCHANGE HERE

    await asyncio.gather(receive(reader), send(writer))

async def init_connection_wrapper(debug=False):
    global debug_mode
    debug_mode = debug

    if debug_mode:
        ("Alice is running in debug mode")

    IdentityService.init_storage()

    global private_identity_key, public_idenity_key
    private_identity_key, public_idenity_key = IdentityService.init_keys(Constants.ALICE, debug_mode)

    # Генеруємо DH пару для Double Ratchet (або можна використати handshake DH пару)
    alice_dh_private, alice_dh_public = generate_x25519_keys()
    alice_handshake_private, alice_handshake_public = generate_x25519_keys()

    async def wrapped_init(reader, writer):
        # Виконуємо handshake: відправляємо свій ключ і отримуємо ключ Bob
        bob_handshake_public = await do_handshake(reader, writer, alice_handshake_public, private_identity_key, Constants.BOB)
        shared_secret = alice_handshake_private.exchange(bob_handshake_public)      
        initial_root = derive_initial_root(shared_secret)

        # Припустимо, що публічний ключ Bob для Double Ratchet узгоджується через handshake – в цій демонстрації використовуємо bob_handshake_public.
        dr = DoubleRatchet(initial_root, alice_dh_private, alice_dh_public, bob_handshake_public)
        # # Виконуємо початковий ratchet update
        dr.dh_ratchet(bob_handshake_public)
        #set_double_ratchet_instance(dr)

        if debug_mode:
            show_init_connection_logs(Constants.ALICE, 
                                    alice_dh_private,
                                    alice_dh_public,
                                    alice_handshake_private, 
                                    alice_handshake_public, 
                                    bob_handshake_public,
                                    shared_secret,
                                    initial_root)        
        
        await init_connection(reader, writer)
    
    await alice_server(wrapped_init)    


def init_fake_identity():
    IdentityService.init_storage()

    global private_identity_key, public_idenity_key
    private_identity_key, public_idenity_key = IdentityService.init_keys(Constants.ALICE, debug_mode)


if __name__ == "__main__":
    print("Starting Alice's chat... Waiting for Bob...")
    asyncio.run(alice_server(init_connection))
