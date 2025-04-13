import hashlib
from typing import Optional

class Block:
    def __init__(self, data, prev_hash: str = "") -> None:
        self.data = data
        self.prev_hash = prev_hash
        self.nonce: Optional[int] = None
        self.hash: Optional[str] = None

    def compute_hash(self, nonce: int) -> str:
        text = f"{self.data}{self.prev_hash}{nonce}"
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    def __str__(self) -> str:
        return (f"Block(data={self.data}, prev_hash={self.prev_hash}, "
                f"nonce={self.nonce}, hash={self.hash})")