import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

ALGORITHMS = {
    "rsa2048": "RSA 2048",
    "rsa3072": "RSA 3072",
    "rsa4096": "RSA 4096",
    "ec256": "EC P-256",
    "ec384": "EC P-384",
    "ed25519": "Ed25519",
}


def generate(algo):
    if algo in ("rsa2048", "rsa3072", "rsa4096"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(algo[3:]))
    if algo == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    if algo == "ec384":
        return ec.generate_private_key(ec.SECP384R1())
    if algo == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(f"Unsupported key algorithm: {algo}")


def _public(key):
    if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey,
                        ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return key.public_key()
    return key


def describe(key):
    pub = _public(key)
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA {pub.key_size}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return {"secp256r1": "EC P-256", "secp384r1": "EC P-384", "secp521r1": "EC P-521"}.get(
            pub.curve.name, f"EC {pub.curve.name}")
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448"
    return type(pub).__name__


def check_supported(key):
    if not isinstance(_public(key), (rsa.RSAPublicKey, ec.EllipticCurvePublicKey,
                                     ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        raise ValueError(f"Unsupported key type: {describe(key)}")


def signing_hash(private_key):
    if isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return None
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        if private_key.curve.key_size >= 521:
            return hashes.SHA512()
        if private_key.curve.key_size >= 384:
            return hashes.SHA384()
    return hashes.SHA256()


def fingerprint(key):
    der = _public(key).public_bytes(serialization.Encoding.DER,
                                    serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def public_pem(key):
    return _public(key).public_bytes(serialization.Encoding.PEM,
                                     serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def to_pem(private_key, password=None):
    enc = (serialization.BestAvailableEncryption(password.encode()) if password
           else serialization.NoEncryption())
    return private_key.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.PKCS8, enc)


def load_private(data, password=None):
    """Load a PEM or DER private key. Raises ValueError with a readable message."""
    pw = password.encode() if isinstance(password, str) and password else password or None
    loader = (serialization.load_pem_private_key if b"-----BEGIN" in data
              else serialization.load_der_private_key)
    try:
        key = loader(data, pw)
    except TypeError:
        if pw is None:
            raise ValueError("The private key is encrypted; enter its password.")
        # A password was given but the key is not encrypted.
        key = loader(data, None)
    except ValueError:
        raise ValueError("Could not read the private key (wrong password or unsupported format).")
    check_supported(key)
    return key
