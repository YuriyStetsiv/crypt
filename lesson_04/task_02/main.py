from api import get_cookie, check_admin
from utils import get_blocks, print_result
from engine import xor_hex


BLOCK_SIZE = 16
ORIGINAL_MESSAGE = "admin=False;expi".encode().hex()
FAKE_MESSAGE = "admin=True; expi".encode().hex()

def main():
    response = get_cookie()
    blocks = get_blocks(response, BLOCK_SIZE)

    iv = blocks[0]
    cookie = blocks[1]+blocks[2]

    iv_fake = xor_hex(ORIGINAL_MESSAGE, iv)
    iv_fake = xor_hex(iv_fake, FAKE_MESSAGE)

    flag = check_admin(cookie, iv_fake)

    print_result(response,blocks, cookie, iv, iv_fake, flag)


if __name__ == "__main__":
    main()