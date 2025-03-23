from binascii import hexlify
from cryptography.exceptions import InvalidSignature

from fake_pki_engine import generate_rsa_keys, rsa_sign, rsa_verify
from dh import simulate, generate_parameters, generate_user_keys, generate_derived_key

def main():
    # Генерація ключів для підпису, 
    # імітація сертифікатів
    # умовно паралельне виконання
    # не потребує завязки на іншому користувачі
    alice_rsa_private_key, alice_rsa_public_key = generate_rsa_keys()
    bob_rsa_private_key, bob_rsa_public_key = generate_rsa_keys()

    # Генерація Діфі-Хелмана
    # умовно паралельне виконання після генерації і обміну спільними параметрами 
    # не потребує завязки на іншому користувачі
    dh_parameters = generate_parameters()
    alice_private_key, alice_public_key = generate_user_keys(dh_parameters)
    bob_private_key, bob_public_key = generate_user_keys(dh_parameters)

    # Підпис публічних ключів перед відправкою іншій стороні
    # імітація PKI
    # теж умовно паралельне виконання
    alice_signature = rsa_sign(alice_rsa_private_key, alice_public_key)
    bob_signature = rsa_sign(bob_rsa_private_key, bob_public_key)

    #ALLICE FLOW
    try:
        # Аліса перевіряє публічний ключ Боба
        # Якщо перевірка успішна то продовжує генерацію спільного секрета і ключа
        # на основі публічного ключа Боба,
        rsa_verify("bob_signature", bob_rsa_public_key, bob_signature, bob_public_key)
        alice_shared_value = alice_private_key.exchange(bob_public_key)
        alice_derived_key = generate_derived_key(alice_shared_value)
    except InvalidSignature:
        print("ERROR: bob_signature signature verification failed!")
        exit(1)      

    #BOB FLOW
    try:
        # Боб перевіряє публічний ключ Аліси
        # Після чого виконує ті самі дії що і Аліса вище
        rsa_verify("alice_signature", alice_rsa_public_key, alice_signature, alice_public_key)
        bob_shared_value = bob_private_key.exchange(alice_public_key)
        bob_derived_key = generate_derived_key(bob_shared_value)
    except InvalidSignature:
        print("ERROR: alice_signature signature verification failed!")
        exit(1)

    print("\nChannel is ready for communication")
    print("\nalice_shared_value:\n", hexlify(alice_shared_value))
    print("\nbob_shared_value:\n", hexlify(bob_shared_value))
    print("\nShared values equal?\t", alice_shared_value == bob_shared_value)
    print("\nbob_derived_key:\t", hexlify(bob_derived_key))
    print("allice_derived_key:\t", hexlify(alice_derived_key))
    print("Shared keys equal?\t", alice_derived_key == bob_derived_key)

#    simulate()

if __name__ == "__main__":
    main()