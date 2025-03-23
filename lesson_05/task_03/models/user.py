class USER:
    def __init__(self, username: str, salt: str = None, iterations: int = None, key: str = None):
        self.username = username
        self.salt = salt
        self.iterations = iterations
        self.key = key

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "salt": self.salt,
            "iterations": self.iterations,
            "key": self.key
        }
    
    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            username=data["username"],
            salt=data["salt"],
            iterations=data["iterations"],
            key=data["key"]
        )