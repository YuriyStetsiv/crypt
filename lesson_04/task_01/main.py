from chipher import encrypt, dencrypt, get_flag
from utils import get_chiper_blocks, print_result
from binascii import hexlify

block_size = 16
message_template = '-'*block_size

message_original = message_template*2
encrypted_message_original = encrypt(message_original)

encrypted_message_modified = encrypted_message_original[2*block_size:]
decrypted_message_modified = dencrypt(encrypted_message_modified)

blocks = get_chiper_blocks(encrypted_message_original, block_size)

bytes_block1 = bytes.fromhex(blocks[0])
bytes_block2 = bytes.fromhex(decrypted_message_modified)
bytes_origin = bytes.fromhex(hexlify(message_template.encode()).decode())

xor_result = bytes(с0 ^ с1 ^ c for с0, с1, c in zip(bytes_block1, bytes_block2, bytes_origin))

key_hex = xor_result.hex()
flag = get_flag(key_hex)

print_result(encrypted_message_original,encrypted_message_modified, decrypted_message_modified,key_hex,flag)