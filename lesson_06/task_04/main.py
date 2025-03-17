from file_utils import load_file, save_file
from engine import decrypt

from Crypto.Util.number import long_to_bytes

FILE_PATH = "files/output.txt"
RESULT_PATH = "files/result.txt"

def main():
    data = load_file(FILE_PATH)

    ct = data["ct"]
    e = data["e"]

    pt = decrypt(ct, e)

    print(f"pt: {pt}")

    if pt != -1:
        print(long_to_bytes(pt).decode())
        save_file(RESULT_PATH, long_to_bytes(pt).decode())


if __name__ == "__main__":
    main()   