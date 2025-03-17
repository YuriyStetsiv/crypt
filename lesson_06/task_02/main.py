from file_utils import load_key, load_file, save_file

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

MESSAGE_PATH = "files/message.txt"
KEY_PATH = "files/task_pub.pem"
SAVE_MESSAGE_PATH = "files/task-2-message.txt"

def main():
    public_key = load_key(KEY_PATH)
    message = load_file(MESSAGE_PATH)

    message_hex = message.encode().hex()
    message_bytes = bytes.fromhex(message_hex)
    
    ciphertext = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    save_file(SAVE_MESSAGE_PATH, ciphertext)

if __name__ == "__main__":
    main()