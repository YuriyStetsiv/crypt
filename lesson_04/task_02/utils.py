def get_blocks(ct, block_size):
    parts = [ct[i : i + 2*block_size] for i in range(0, len(ct), 2*block_size)]
    return parts

def print_result(response, blocks, cookie, iv, iv_fake, flag):
    print(f"response: {response}")
    print(f"bloks: {blocks}")
    print(f"cookie: {cookie}")
    print(f"IV: {iv}")
    print(f"IV_fake: {iv_fake}")

    print(f"flag: {flag}")