

def generate_message(flag, symbol, message_template):
    blocks = [message_template[i : i + 32] for i in range(0, len(message_template), 32)]

    trim_len = 1 + len(flag)
    block1 = blocks[0][:-trim_len] + flag + symbol
    block2 = blocks[1][:-trim_len]

    return block1 + block2

