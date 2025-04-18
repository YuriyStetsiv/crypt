from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac, hashes
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


def KDF_Root_Key(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """
    Оновлює root key (rk) та повертає нові (rk, ck) після DH обміну.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk,
        info=b"DoubleRatchetKDF_RK", 
        backend=default_backend()
    )
    key_material = hkdf.derive(dh_out)
    new_rk = key_material[:32]
    ck = key_material[32:]

    return new_rk, ck

def KDF_Chain_Key(ck: bytes) -> tuple[bytes, bytes]:
    """
    Генерує (message_key, next_chain_key) з поточного chain key.
    """
    h = hmac.HMAC(ck, hashes.SHA256())
    h.update(b'\x01')
    mk = h.finalize()

    h = hmac.HMAC(ck, hashes.SHA256())
    h.update(b'\x02')
    next_ck = h.finalize()

    return next_ck, mk