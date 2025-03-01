import requests
import json

from binascii import hexlify


def encrypt(pt):
    """Obtain ciphertext (encryption) for plaintext"""
    hex = hexlify(pt.encode()).decode()
    url = "http://aes.cryptohack.org/ecb_oracle/encrypt/" + hex
    r = requests.get(url)
    ct = (json.loads(r.text))["ciphertext"]
    return ct


def print_ciphertext(ct):
    """Print ciphertext by block"""
    parts = [ct[i : i + 32] for i in range(0, len(ct), 32)]
    for p in parts:
        print(p)

def get_chiper_blocks(ct):
    parts = [ct[i : i + 64] for i in range(0, len(ct), 64)]
    return [parts[0], parts[1]]