from datetime import timedelta

from cryptography import x509

from . import keys
from .certs import _aki_for

REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "keyCompromise": x509.ReasonFlags.key_compromise,
    "cACompromise": x509.ReasonFlags.ca_compromise,
    "affiliationChanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
    "privilegeWithdrawn": x509.ReasonFlags.privilege_withdrawn,
}
REASON_LABELS = {
    "unspecified": "Unspecified",
    "keyCompromise": "Key compromise",
    "cACompromise": "CA compromise",
    "affiliationChanged": "Affiliation changed",
    "superseded": "Superseded",
    "cessationOfOperation": "Cessation of operation",
    "privilegeWithdrawn": "Privilege withdrawn",
}


def build(ca_cert, ca_key, revoked, number, now, days):
    """revoked: iterable of (serial int, revocation datetime, reason name)."""
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=days))
        .add_extension(x509.CRLNumber(number), critical=False)
        .add_extension(_aki_for(ca_cert), critical=False)
    )
    for serial, when, reason in revoked:
        entry = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when)
        # RFC 5280: omit the reason code rather than using "unspecified".
        if reason and reason != "unspecified" and reason in REASONS:
            entry = entry.add_extension(x509.CRLReason(REASONS[reason]), critical=False)
        builder = builder.add_revoked_certificate(entry.build())
    return builder.sign(ca_key, keys.signing_hash(ca_key))
