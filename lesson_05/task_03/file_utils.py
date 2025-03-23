import json
import os

def save_db(path, users):
    with open(path, 'w') as f:
        json.dump(users, f, indent=4)

# Завантаження з файлу
def load_db(path):
    if os.path.exists(path):
        with open(path, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []