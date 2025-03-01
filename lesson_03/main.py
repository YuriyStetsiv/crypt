from chipher import encrypt, get_chiper_blocks
from utils import print_result, print_process_details
from ascii_engine import generate_message

try_count = 0
is_continue = True
current_pointer = 32

flag = ""
blocks_result = []

message_template = ("--------------------------------"
                    "--------------------------------")

print("Process Info:")
while is_continue or current_pointer == 1:
    for i in range(32, 128):
        try_count += 1

        message = generate_message(flag, chr(i), message_template)
        ct = encrypt(message)
        blocks = get_chiper_blocks(ct)


        print_process_details(try_count, message, blocks)

        if blocks[0] == blocks[1]:
            blocks_result = blocks
            flag.append(chr(i))
            current_pointer -= 1
            break

        if(blocks[0] != blocks[1]) and (i == 127):
            is_continue = False
            break
            

print_result(flag, blocks_result)