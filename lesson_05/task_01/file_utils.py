def load_file(path):
    with open(path, "r") as f:
        lines = f.readlines()

    
    data = {}
    for line in lines:
        key, value = line.strip().split(" = ")
        data[key] = int(value) 

    return data

def save_file(path, text):
    with open(path, 'w') as output_file:
        output_file.writelines("\n".join(text) + "\n")