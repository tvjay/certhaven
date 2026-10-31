from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import keys


def load(data):
    data = data.strip()
    try:
        if b"-----BEGIN" in data:
            return x509.load_pem_x509_csr(data)
        return x509.load_der_x509_csr(data)
    except ValueError:
        raise ValueError("Could not read the certificate signing request.")


def build(subject, private_key, sans):
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(private_key, keys.signing_hash(private_key))


def to_pem(csr):
    return csr.public_bytes(serialization.Encoding.PEM).decode()
