# def flip(origin_symbol, target_symbol):
#     origin_symbol_byte = ord(origin_symbol)
#     target_symbol_byte = ord(target_symbol)

#     flip_value = origin_symbol_byte ^ target_symbol_byte

#     return flip_value

def xor_hex(first_value, second_value):
    first_value_bytes = bytes.fromhex(first_value)
    second_value_bytes = bytes.fromhex(second_value)

    original_block = bytes(a ^ b for a, b in zip(first_value_bytes, second_value_bytes))

    return original_block.hex()
