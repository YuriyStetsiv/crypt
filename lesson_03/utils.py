def print_result(flag,blocks):
    print(f"Result:")
    print(f"Flag: {flag}")
    print_blocks_result(blocks)

def print_process_details(try_count, message, blocks):
    print(f"Count: {try_count}")
    print(f"Message {message}")
    print_blocks_result(blocks)
    print(f"\n")

def print_blocks_result(blocks):
    print(f"Blocks:")
    for block in blocks:
        print(block)

