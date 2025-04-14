import json
import os
from typing import List

from models.identity_key import IdentityKey

def save_db(path: str, identity_keys: List[IdentityKey]):
    with open(path, 'w') as f:
        json.dump([key.to_dict() for key in identity_keys], f, indent=4)

def load_db(path: str) -> List[IdentityKey]:
    if os.path.exists(path):
        with open(path, 'r') as f:
            try:
                data = json.load(f)
                return [IdentityKey.from_dict(item) for item in data]
            except json.JSONDecodeError:
                return []
    return []