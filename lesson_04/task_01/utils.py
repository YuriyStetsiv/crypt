def get_chiper_blocks(ct, block_size):
    parts = [ct[i : i + 2*block_size] for i in range(0, len(ct), 2*block_size)]
    return parts

def print_result(encrypted_message_original,encrypted_message_modified, decnrypted_message_modified, key_hex, flag):
    print(f'encrypted_message_original: {encrypted_message_original}')
    print(f'encrypted_message_modified: {encrypted_message_modified}')
    print(f'decrypted_message_modified: {decnrypted_message_modified}')
    print(f"key_hex: {key_hex}")
    print(f'flag_ascii: {flag}')