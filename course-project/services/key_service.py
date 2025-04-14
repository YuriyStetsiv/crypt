from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_initial_root(shared_secret: bytes) -> bytes:
    """
    Використовує HKDF для виведення початкового root key із спільного DH секрету.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"InitialRootKey",
        backend=default_backend()
    )
    
    return hkdf.derive(shared_secret)

def derive_double_ratchet_keys(current_root_key: bytes, dh_shared_secret: bytes) -> tuple:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=96,
        salt=current_root_key,
        info=b"DoubleRatchetKeys",
        backend=default_backend()
    )
    key_material = hkdf.derive(dh_shared_secret)

    return key_material[0:32], key_material[32:64], key_material[64:96]

def kdf_chain(chain_key: bytes) -> tuple:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"DoubleRatchetChain",
        backend=default_backend()
    )
    key_material = hkdf.derive(chain_key)
    
    return key_material[:32], key_material[32:]