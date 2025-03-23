
from ecdh import generate_sign_keys, generate_keys, restore_public_key, convert_key_to_hex_format, generate_derived_key
from fake_pki_engine import  verify_key, sign_key
from file_utils import load_payload, save_key, load_key
from models.payload import PAYLOAD

PATH_ALLICE_KEY = "keys/allice_pub_sign_key.pem"
PATH_BOB_KEY = "keys/bob_pub_sign_key.pem"

PATH_ALLICE_PAYLOAD = "files/allice_payload.json"

def main():
    bob_private_sign_key, bob_public_sign_key = generate_sign_keys()
    bob_private_key, bob_public_key = generate_keys()

    save_key(PATH_BOB_KEY, bob_public_sign_key)

    alice_public_sign_key = load_key(PATH_ALLICE_KEY)
    allice_payload = load_payload(PATH_ALLICE_PAYLOAD)

    print(f"allice_payload.public_key: {allice_payload.public_key}")
    print(f"allice_payload.signature:\n  {allice_payload.signature}")

    try:
        verify_key(alice_public_sign_key, allice_payload, "allice_signature")

        bob_signature = sign_key(bob_public_key, bob_private_sign_key, "bob_signature")
        bob_public_key_hex = convert_key_to_hex_format(bob_public_key)
        bob_payload = PAYLOAD(bob_public_key_hex, bob_signature)

        print(f"\nSENDING TO ALLICE...") # Формально кінець завдання
        print(f"bob_payload.public_key: {bob_payload.public_key} ")
        print(f"bob_payload.signature:\n {bob_payload.signature} ")

        allice_public_key = restore_public_key(allice_payload.public_key)
        bob_shared_value = bob_private_key.exchange(allice_public_key)
        bob_derived_key = generate_derived_key(bob_shared_value)

        print(f"\nderived_key: {bob_derived_key.hex()}")
        

    except Exception as e:
        print("Signature is invalid:", e)

if __name__ == "__main__":
    main()