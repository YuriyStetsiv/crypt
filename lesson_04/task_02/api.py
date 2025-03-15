import requests
import json

def get_cookie():
    url = "http://aes.cryptohack.org/flipping_cookie/get_cookie/"
    response = requests.get(url)
    cookie = (json.loads(response.text))["cookie"]
    return cookie

def check_admin(cookie, iv):
    url = f"http://aes.cryptohack.org/flipping_cookie/check_admin/{cookie}/{iv}/"
    response = requests.get(url)
    flag = (json.loads(response.text))["flag"]
    return flag
