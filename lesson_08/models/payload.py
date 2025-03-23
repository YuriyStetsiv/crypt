class PAYLOAD:
    def __init__(self, public_key: str = None, signature: str = None):
        self.public_key = public_key
        self.signature = signature

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            public_key=data["public_key"],
            signature=data["signature"]
        )