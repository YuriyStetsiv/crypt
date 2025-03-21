def save_file(path, ct):
    with open(path, 'w') as output_file:
        output_file.write(ct.hex())