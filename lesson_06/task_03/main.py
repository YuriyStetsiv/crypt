from file_utils import load_file, save_file
from Crypto.Util.number import long_to_bytes

FILE_PATH = "files/output.txt"
RESULT_PATH = "files/result.txt"

def main():
    data = load_file(FILE_PATH)

    ct = data["ct"]
    decrypted = long_to_bytes(ct)

    print(decrypted.decode())
    save_file(RESULT_PATH, decrypted.decode())

if __name__ == "__main__":
    main()   