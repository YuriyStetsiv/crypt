import logging
import os
from binascii import hexlify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from engines.ed25519_engine import generate_ed25519_keys
from utils.file_utils import save_db, load_db
from models.constants import Constants
from models.identity_key import IdentityKey

class IdentityService:
    def init_storage():
        save_db(Constants.IDENTITY_KEY_STORAGE_PATH, [])

    def init_keys(user_id: str, debug_mode: bool):
        assert user_id in (Constants.ALICE, Constants.BOB), "Unknown user_id"

        if user_id == Constants.ALICE:
            private_path = Constants.ALICE_PRIVATE_SIGN_KEY
            public_path = Constants.ALICE_PUBLIC_SIGN_KEY
        else:
            private_path = Constants.BOB_PRIVATE_SIGN_KEY
            public_path = Constants.BOB_PUBLIC_SIGN_KEY

        # Якщо ключі існують – завантажуємо
        if os.path.exists(private_path) and os.path.exists(public_path):
            with open(private_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            with open(public_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())

            if debug_mode:
                _show_init_keys_debug_info(user_id, private_key, public_key)

            return private_key, public_key

        # Інакше – генеруємо нові ключі
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Зберігаємо приватний ключ у PKCS#8
        with open(private_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Зберігаємо публічний ключ у SubjectPublicKeyInfo
        with open(public_path, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        _add_key_to_storage(user_id, public_key)

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
def _add_key_to_storage(user_id: str, public_key:  Ed25519PublicKey):
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    newIdentityKey = IdentityKey(user_id, public_bytes.hex())
    identityKeys = load_db(Constants.IDENTITY_KEY_STORAGE_PATH)
    identityKeys.append(newIdentityKey)

    save_db(Constants.IDENTITY_KEY_STORAGE_PATH, identityKeys)

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