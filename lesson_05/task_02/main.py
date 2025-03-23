import binascii
import os
import hashlib
import hmac
import datetime

from file_utils import save_file

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

PATH = "files/result.txt"

KEY = "63e353ae93ecbfe00271de53b6f02a46"
IV = "75b777fc8f70045c6006b39da1b3d622"
CHIPHERTEXT = "76c3ada7f1f7563ff30d7290e58fb4476eb12997d02a6488201c075da52ff3890260e2c89f631e7f919af96e4e47980a"

def main():
    key_bytes = binascii.unhexlify(KEY)
    ciphertext_bytes = binascii.unhexlify(CHIPHERTEXT)
    iv_bytes = binascii.unhexlify(IV)

    salt = os.urandom(16)
    
    session_counter = os.urandom(16) #fake mock for logic of getting real session_counter
    date_time_flag = datetime.datetime.now()

    info = f"MAC_KEY-session-{session_counter.hex()}-{date_time_flag.isoformat()}"

    key_mac = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info.encode(),
        backend=default_backend()
    )

    derived_key = key_mac.derive(key_bytes)

    mac = hmac.new(derived_key, iv_bytes + ciphertext_bytes, hashlib.sha256).digest()

    save_file(PATH, mac)

    print(f"Info: {info}")
    print(f"Salt: {binascii.hexlify(salt).decode()}")
    print(f"MAC:  {binascii.hexlify(mac).decode()}")

if __name__ == "__main__":
    main()