import binascii

from engine import generate_kdf, restore_kdf
from file_utils import load_db, save_db

from models.user import USER

DB_PATH = "files/fake_db.json"

def register(username: str, password: str):
    users = load_db(DB_PATH)
    user = next((u for u in users if u["username"] == username), None)
    
    if user:
        print("❌ Username has already use.")
        return False
    
    kdf = generate_kdf()
    key = kdf.derive(password.encode())

    user_data = USER(username, kdf._salt.hex(), kdf._iterations, key.hex())
    users.append(user_data.to_dict())
    save_db(DB_PATH, users)

    return True

def login(username: str, password: str):
    users = load_db(DB_PATH)
    user_data = next((u for u in users if u["username"] == username), None)

    if not user_data:
        #print("❌ User not found.")
        return False
    
    user = USER.from_dict(user_data)

    stored_salt_bytes = binascii.unhexlify(user.salt)
    stored_key_bytes = binascii.unhexlify(user.key)

    kdf = restore_kdf(stored_salt_bytes, user.iterations)

    try:
        kdf.verify(password.encode(), stored_key_bytes)
        #print("❌ Correct password")
        return True
    except Exception as e:
        #print("❌ Invalid password")
        return False 
    


def main():
    while True:
        print("\n=== Main Menu ===")
        print("1️⃣  Register")
        print("2️⃣  Login")
        print("0️⃣  Exit")

        choice = input("Choose an action: ").strip()

        if choice == "1":
            username = input("👤 Enter username: ")
            password = input("🔑 Enter password: ")
            if register(username, password):
                print(f"✅ Registration successful!")

        elif choice == "2":
            username = input("👤 Enter username: ")
            password = input("🔑 Enter password: ")
            if login(username, password):
                print("✅ Login successful!")
            else:
                print("❌ Invalid username or password.")

        elif choice == "0":
            break

        else:
            print("⚠️ Invalid choice. Please try again.")

if __name__ == "__main__":
    main()