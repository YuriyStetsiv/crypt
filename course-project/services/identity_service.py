import logging
import os
from binascii import hexlify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from utils.file_utils import save_keys, load_keys
from models.constants import Constants

class IdentityService:
    def init_keys(user_id: str, debug_mode: bool):
        private_path, public_path = _get_paths(user_id)
        private_key, public_key = load_keys(private_path, public_path)

        # Інакше – генеруємо нові ключі
        if private_key is None or public_key is None:
            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            save_keys(private_path, public_path, private_key)
  
        if debug_mode:
            _show_init_keys_debug_info(user_id, private_key, public_key)

        return private_key, public_key

    def get_public_key(user_id: str, debug_mode: bool) -> Ed25519PublicKey:
        assert user_id in (Constants.ALICE, Constants.BOB), "Unknown user_id"

        if user_id == Constants.ALICE:
            public_path = Constants.ALICE_PUBLIC_SIGN_KEY
        else:
            public_path = Constants.BOB_PUBLIC_SIGN_KEY

        if  os.path.exists(public_path):
            with open(public_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())

            return public_key

    
    def get_private_key(path: str, debug_mode: bool):
        print('work')


@staticmethod
def _get_paths(user_id: str):
    assert user_id in (Constants.ALICE, Constants.BOB), "Unknown user_id"

    if user_id == Constants.ALICE:
        private_path = Constants.ALICE_PRIVATE_SIGN_KEY
        public_path = Constants.ALICE_PUBLIC_SIGN_KEY
    else:
        private_path = Constants.BOB_PRIVATE_SIGN_KEY
        public_path = Constants.BOB_PUBLIC_SIGN_KEY 

    return  private_path ,public_path 

@staticmethod
def _show_init_keys_debug_info(user_id: str, private_key,  public_key):
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    logging.info(f'[Identity] {user_id} ed25519 init_keys:')
    logging.info(f'[Identity] {user_id} ed25519 private_key: {hexlify(private_bytes)}')
    logging.info(f'[Identity] {user_id} ed25519 public_key: {hexlify(public_bytes)}')