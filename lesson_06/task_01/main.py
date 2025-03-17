from file_utils import load_file, load_key

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

MESSAGE_PATH = "files/task_message.txt"
SIGNATURE_PATH = "files/task_signature.txt"
KEY_PATH = "files/task_pub.pem"

def main():
    message = load_file(MESSAGE_PATH)
    signature = load_file(SIGNATURE_PATH)
    public_key = load_key(KEY_PATH)

    print(f"public_key: {public_key}")
    print(f"signature: {signature}")
    print(f"message: {message}")

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("Signature: VALID")
    except Exception as e:
        print("Signature: INVALID")

if __name__ == "__main__":
    main()