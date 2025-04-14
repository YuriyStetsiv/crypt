class IdentityKey:
    def __init__(self, user_id: str, pubic_key: str):
        self.user_id = user_id
        self.public_key = pubic_key

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "public_key": self.public_key,
        }
    
    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            user_id=data["user_id"],
            pubic_key=data["public_key"],
        )