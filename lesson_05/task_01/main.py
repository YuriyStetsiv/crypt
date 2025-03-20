from argon2 import PasswordHasher
from file_utils import save_file

PASSWORDS = [
    "qwertyuiop",
    "sofPed-westag-jejzo1",
    "f3Fg#Puu$EA1mfMx2",
    "TIMCfJDkKBRm9/zwcFbHhE6zaMcSxR7nke1mJKcVqXpvCzg69d7Mf2quanMoAfmPJXyqT4gyGpLoL1lTHoqmwVmaUwrpOPRecB8GAU17eUJJHiksv3qrqcVxhgpMkX/UlKaLdFSwFIr7cVoJmBqQ/buWzxJNCIo7qbtIi3fSi62NwMHh"
]

FILE_PATH = "files/password-hashes.txt"

def main():
    hasher = PasswordHasher(
            time_cost=4,
            memory_cost= 131072, #128
            hash_len=32,
            salt_len=16,
            parallelism= 8
        )
    
    password_hashes = []
    for password in PASSWORDS:
        password_hash = hasher.hash(password)
        password_hashes.append(password_hash)

        print(f"passwod: {password}")
        print(f"hash: {password_hash}")

    save_file(FILE_PATH, password_hashes)
    
if __name__ == "__main__":
    main()