"""Import parsing (PEM bundles, DER, PKCS#12) and PKCS#12 export."""
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from . import keys

_PEM_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n.*?-----END \1-----", re.S)


SQLITE_HEADER = b"SQLite format 3\x00"


def parse(data, password=None):
    """Return (private_keys, certificates, csrs) found in data."""
    if data.startswith(SQLITE_HEADER):
        # A certhaven backup holds certificates as PEM text, which the scan below would pick out on
        # their own, without names or the (encrypted) private keys.
        raise ValueError("This is a certhaven database backup, not a certificate file. "
                         "To bring everything back, use Settings → Restore backup.")
    found_keys, found_certs, found_csrs = [], [], []
    blocks = list(_PEM_RE.finditer(data))
    if blocks:
        for m in blocks:
            label, block = m.group(1).decode(), m.group(0)
            if label in ("CERTIFICATE", "X509 CERTIFICATE"):
                found_certs.append(x509.load_pem_x509_certificate(block))
            elif label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
                found_csrs.append(x509.load_pem_x509_csr(block))
            elif label.endswith("PRIVATE KEY"):
                found_keys.append(keys.load_private(block, password))
        return found_keys, found_certs, found_csrs

    for loader, bucket in ((x509.load_der_x509_certificate, found_certs),
                           (x509.load_der_x509_csr, found_csrs)):
        try:
            bucket.append(loader(data))
            return found_keys, found_certs, found_csrs
        except ValueError:
            pass

    p12 = _load_pkcs12(data, password)
    if p12 is not None:
        if p12.key is not None:
            keys.check_supported(p12.key)
            found_keys.append(p12.key)
        if p12.cert is not None:
            found_certs.append(p12.cert.certificate)
        found_certs.extend(c.certificate for c in p12.additional_certs)
        return found_keys, found_certs, found_csrs

    try:
        found_keys.append(keys.load_private(data, password))
    except ValueError:
        raise ValueError("Unrecognised data. Supported: PEM, DER, PKCS#12 (.p12/.pfx). "
                         "If it is a password-protected PKCS#12 file, check the password.")
    return found_keys, found_certs, found_csrs


def _load_pkcs12(data, password):
    candidates = [password.encode()] if password else [None, b""]
    for pw in candidates:
        try:
            return pkcs12.load_pkcs12(data, pw)
        except (ValueError, TypeError):
            continue
    return None


def pkcs12_bytes(name, private_key, cert, chain, password):
    if password:
        enc = (serialization.PrivateFormat.PKCS12.encryption_builder()
               .kdf_rounds(50000)
               .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC)
               .hmac_hash(hashes.SHA256())
               .build(password.encode()))
    else:
        enc = serialization.NoEncryption()
    return pkcs12.serialize_key_and_certificates(name.encode(), private_key, cert, chain or None, enc)
