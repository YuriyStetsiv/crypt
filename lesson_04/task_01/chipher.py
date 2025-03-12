import requests
import json

from binascii import hexlify, unhexlify


def encrypt(message):
    """Obtain ciphertext (encryption) for plaintext"""
    hex = hexlify(message.encode()).decode()
    url = "http://aes.cryptohack.org/lazy_cbc/encrypt/" + hex
    response = requests.get(url)

    ct = (json.loads(response.text))["ciphertext"]
    return ct

def dencrypt(message):
    """Obtain ciphertext (encryption) for plaintext"""
    url = "http://aes.cryptohack.org/lazy_cbc/receive/" + message
    response = requests.get(url)

    ct = (json.loads(response.text))
 
    return ct['error'].split('Invalid plaintext: ')[1]

def get_flag(key): 
    url = "http://aes.cryptohack.org/lazy_cbc/get_flag/" + key
    response = requests.get(url)

    ct = (json.loads(response.text))["plaintext"]
    
    return unhexlify(ct).decode()
