from binascii import hexlify

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_parameters():
    print("Generating parameters...")
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    print("\nModule:\n", parameters.parameter_numbers().p)
    print(f"\nGen: {parameters.parameter_numbers().g}\n")

    return parameters

def generate_user_keys(parameters):
    private_key = parameters.generate_private_key()  # a
    public_key = private_key.public_key()

    return private_key, public_key

def generate_derived_key(shared_value):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,  # Важливо не додавати рандомізацію для отримання однакового ключа з обох сторін.
        info=b"handshake data",
    ).derive(shared_value)

def simulate():
    # Загальні параметри DH спільні для всіх учасників і узгоджуються на рівні протоколу.
    print("Generating parameters...")
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    print("\nModule:\n", parameters.parameter_numbers().p)
    print("\nGen:", parameters.parameter_numbers().g)

    # Alice
    alice_private_key = parameters.generate_private_key()  # a
    alice_public_key = alice_private_key.public_key()  # g^a

    # Bob

    bob_private_key = parameters.generate_private_key()  # b
    bob_public_key = bob_private_key.public_key()  # g^b

    # Alice --> Bob:    alice_public_key
    # Bob --> Alice:    bob_public_key

    # Alice
    alice_shared_value = alice_private_key.exchange(bob_public_key)
    print("\nShared secret value:\n", hexlify(alice_shared_value))
    alice_derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,  # Важливо не додавати рандомізацію для отримання однакового ключа з обох сторін.
        info=b"handshake data",
    ).derive(alice_shared_value)
    print("\nDerived secret key:\n", hexlify(alice_derived_key))

    # Bob
    bob_shared_value = bob_private_key.exchange(alice_public_key)
    print("\nShared secret value:\n", hexlify(bob_shared_value))
    bob_derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,  # Важливо не додавати рандомізацію для отримання однакового ключа з обох сторін.
        info=b"handshake data",
    ).derive(bob_shared_value)

    print("\nDerived secret key:\n", hexlify(bob_derived_key))
    print("\nShared values equal?\t", alice_shared_value == bob_shared_value)
    print("Shared keys equal?\t", alice_derived_key == bob_derived_key)
