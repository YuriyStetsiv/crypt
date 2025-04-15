import os
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from utils.file_utils import save_keys, load_keys
from utils.logger_utils import show_identity_logs
from models.constants import Constants

class IdentityService:
    def init_keys(user_id: str, debug_mode: bool):
        private_path, public_path = _get_paths(user_id)
        private_key, public_key = load_keys(private_path, public_path)

        # if private_key is None or public_key is None:
        #     private_key = Ed25519PrivateKey.generate()
        #     public_key = private_key.public_key()
        #     save_keys(private_path, public_path, private_key)
  
        if debug_mode:
            show_identity_logs(user_id, private_key, public_key)

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
        else:
             raise ValueError(f"public_sign_key {user_id} for not found")
        
    @staticmethod
    def verify(
            user_id: str, 
            signature, 
            data,
            debug_mode: bool) -> bool:
        public_key = IdentityService.get_public_key(user_id, debug_mode)

        try:
            public_key.verify(signature, data)
            logging.info(f'[Identity] message from {user_id} valid')

            return True
        except Exception:
            logging.info(f'[Identity] message from {user_id}  not valid')

            return False



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
