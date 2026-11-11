import hashlib
import ipaddress
import re
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from . import keys

SUBJECT_FIELDS = [
    ("C", NameOID.COUNTRY_NAME, "Country"),
    ("ST", NameOID.STATE_OR_PROVINCE_NAME, "State / province"),
    ("L", NameOID.LOCALITY_NAME, "Locality"),
    ("O", NameOID.ORGANIZATION_NAME, "Organization"),
    ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME, "Organizational unit"),
    ("CN", NameOID.COMMON_NAME, "Common name"),
    ("E", NameOID.EMAIL_ADDRESS, "Email"),
]
SUBJECT_KEYS = [f[0] for f in SUBJECT_FIELDS]

KEY_USAGES = [
    ("digitalSignature", "digital_signature", "Digital signature"),
    ("nonRepudiation", "content_commitment", "Non-repudiation"),
    ("keyEncipherment", "key_encipherment", "Key encipherment"),
    ("dataEncipherment", "data_encipherment", "Data encipherment"),
    ("keyAgreement", "key_agreement", "Key agreement"),
    ("keyCertSign", "key_cert_sign", "Certificate signing"),
    ("cRLSign", "crl_sign", "CRL signing"),
]
EXT_KEY_USAGES = [
    ("serverAuth", ExtendedKeyUsageOID.SERVER_AUTH, "TLS server"),
    ("clientAuth", ExtendedKeyUsageOID.CLIENT_AUTH, "TLS client"),
    ("codeSigning", ExtendedKeyUsageOID.CODE_SIGNING, "Code signing"),
    ("emailProtection", ExtendedKeyUsageOID.EMAIL_PROTECTION, "Email protection"),
    ("timeStamping", ExtendedKeyUsageOID.TIME_STAMPING, "Time stamping"),
    ("OCSPSigning", ExtendedKeyUsageOID.OCSP_SIGNING, "OCSP signing"),
]
_KU_ATTR = {name: attr for name, attr, _ in KEY_USAGES}
_KU_LABEL = {attr: label for _, attr, label in KEY_USAGES}
_EKU_OID = {name: oid for name, oid, _ in EXT_KEY_USAGES}
_EKU_NAME = {oid: name for name, oid, _ in EXT_KEY_USAGES}
_EKU_LABEL = {oid: label for _, oid, label in EXT_KEY_USAGES}

_DNS_RE = re.compile(r"^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?$")


@dataclass
class Profile:
    is_ca: bool = False
    path_length: int | None = None
    key_usage: list = field(default_factory=list)
    ext_key_usage: list = field(default_factory=list)


def build_name(values):
    attrs = []
    for key, oid, label in SUBJECT_FIELDS:
        value = (values.get(key) or "").strip()
        if not value:
            continue
        if key == "C":
            if len(value) != 2 or not value.isalpha():
                raise ValueError("Country must be a 2-letter code.")
            value = value.upper()
        elif len(value) > 64 and key != "E":
            raise ValueError(f"{label} must be 64 characters or fewer.")
        attrs.append(x509.NameAttribute(oid, value))
    return x509.Name(attrs)


def name_text(name):
    """RFC 4514 text, with the email attribute shown as E= instead of its raw OID."""
    return name.rfc4514_string({NameOID.EMAIL_ADDRESS: "E"})


def common_name(name):
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def _dns_name(value):
    value = value.strip().rstrip(".").lower()
    try:
        prefix = "*." if value.startswith("*.") else ""
        rest = value[len(prefix):]
        ascii_value = prefix + rest.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"Invalid DNS name: {value}")
    if not _DNS_RE.match(ascii_value) or len(ascii_value) > 253:
        raise ValueError(f"Invalid DNS name: {value}")
    return ascii_value


def parse_sans(text):
    """Parse one SAN per line (or comma separated). Accepts DNS:, IP:, email:, URI:
    prefixes; bare values are detected as IP, URI, email or DNS."""
    names = []
    for raw in re.split(r"[\n,]+", text or ""):
        item = raw.strip()
        if not item:
            continue
        kind, sep, value = item.partition(":")
        kind = kind.strip().lower()
        if sep and kind in ("dns", "ip", "email", "uri"):
            value = value.strip()
        else:
            kind, value = None, item
            if "://" in value:
                kind = "uri"
            else:
                try:
                    ipaddress.ip_address(value)
                    kind = "ip"
                except ValueError:
                    kind = "email" if "@" in value else "dns"
        if kind == "dns":
            names.append(x509.DNSName(_dns_name(value)))
        elif kind == "ip":
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(value)))
            except ValueError:
                raise ValueError(f"Invalid IP address: {value}")
        elif kind == "email":
            names.append(x509.RFC822Name(value))
        else:
            names.append(x509.UniformResourceIdentifier(value))
    return list(dict.fromkeys(names))


def general_name_text(name):
    if isinstance(name, x509.DNSName):
        return f"DNS:{name.value}"
    if isinstance(name, x509.IPAddress):
        return f"IP:{name.value}"
    if isinstance(name, x509.RFC822Name):
        return f"email:{name.value}"
    if isinstance(name, x509.UniformResourceIdentifier):
        return f"URI:{name.value}"
    if isinstance(name, x509.DirectoryName):
        return f"DirName:{name_text(name.value)}"
    return f"{type(name).__name__}:{name.value}"


def sans_to_text(names):
    return "\n".join(general_name_text(n) for n in names)


def _key_usage(names, public_key):
    flags = {attr: False for _, attr, _ in KEY_USAGES}
    for name in names:
        if name in _KU_ATTR:
            flags[_KU_ATTR[name]] = True
    if not isinstance(public_key, rsa.RSAPublicKey):
        # Encipherment usages only make sense for RSA keys.
        flags["key_encipherment"] = flags["data_encipherment"] = False
    if not any(flags.values()):
        return None
    return x509.KeyUsage(**flags, encipher_only=False, decipher_only=False)


def key_identifier(public_key):
    """Subject key identifier: the first 160 bits of the SHA-256 hash of the public key info, which RFC 7093
    allows in place of RFC 5280's SHA-1 method. It only labels the key; nothing relies on it for security."""
    spki = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return x509.SubjectKeyIdentifier(hashlib.sha256(spki).digest()[:20])


def _aki_for(issuer_cert):
    try:
        ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key())


def issue(*, subject, public_key, signer_key, issuer_cert, profile, sans, not_before, not_after,
          serial=None, crl_url=None, aia_url=None):
    """Build and sign a certificate. issuer_cert=None means self-signed with signer_key."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(public_key)
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=profile.is_ca,
                                             path_length=profile.path_length if profile.is_ca else None),
                       critical=True)
    )
    ku = _key_usage(profile.key_usage, public_key)
    if ku:
        builder = builder.add_extension(ku, critical=True)
    ekus = [_EKU_OID[n] for n in profile.ext_key_usage if n in _EKU_OID]
    if ekus:
        builder = builder.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=len(subject) == 0)
    ski = key_identifier(public_key)
    builder = builder.add_extension(ski, critical=False)
    if issuer_cert:
        builder = builder.add_extension(_aki_for(issuer_cert), critical=False)
        if crl_url:
            builder = builder.add_extension(x509.CRLDistributionPoints([
                x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(crl_url)],
                                       relative_name=None, reasons=None, crl_issuer=None)
            ]), critical=False)
        if aia_url:
            builder = builder.add_extension(x509.AuthorityInformationAccess([
                x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                                       x509.UniformResourceIdentifier(aia_url))
            ]), critical=False)
    else:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
    return builder.sign(signer_key, keys.signing_hash(signer_key))


def basic_constraints(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return None


def get_sans(obj):
    try:
        return list(obj.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        return []


def profile_from_cert(cert):
    profile = Profile()
    bc = basic_constraints(cert)
    if bc:
        profile.is_ca, profile.path_length = bc.ca, bc.path_length
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        profile.key_usage = [name for name, attr, _ in KEY_USAGES if getattr(ku, attr)]
    except x509.ExtensionNotFound:
        pass
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        profile.ext_key_usage = [_EKU_NAME[oid] for oid in eku if oid in _EKU_NAME]
    except x509.ExtensionNotFound:
        pass
    return profile, get_sans(cert)


def colon_hex(data):
    return ":".join(f"{b:02X}" for b in data)


def _oid_name(oid):
    return getattr(oid, "_name", None) or oid.dotted_string


def extension_text(ext):
    v = ext.value
    if isinstance(v, x509.BasicConstraints):
        text = "CA: " + ("yes" if v.ca else "no")
        if v.ca:
            text += ", path length: " + ("unlimited" if v.path_length is None else str(v.path_length))
        return text
    if isinstance(v, x509.KeyUsage):
        return ", ".join(label for attr, label in _KU_LABEL.items() if getattr(v, attr))
    if isinstance(v, x509.ExtendedKeyUsage):
        return ", ".join(_EKU_LABEL.get(oid, _oid_name(oid)) for oid in v)
    if isinstance(v, x509.SubjectAlternativeName):
        return ", ".join(general_name_text(n) for n in v)
    if isinstance(v, x509.SubjectKeyIdentifier):
        return colon_hex(v.digest)
    if isinstance(v, x509.AuthorityKeyIdentifier):
        return colon_hex(v.key_identifier) if v.key_identifier else "(issuer name and serial)"
    if isinstance(v, x509.CRLDistributionPoints):
        return ", ".join(n.value for dp in v for n in (dp.full_name or []))
    if isinstance(v, x509.AuthorityInformationAccess):
        return ", ".join(f"{_oid_name(d.access_method)}: {d.access_location.value}" for d in v)
    return str(v)[:500]


def details(cert):
    return {
        "subject": name_text(cert.subject),
        "issuer": name_text(cert.issuer),
        "serial": colon_hex(cert.serial_number.to_bytes((cert.serial_number.bit_length() + 7) // 8 or 1, "big")),
        "not_before": cert.not_valid_before_utc.replace(tzinfo=None),
        "not_after": cert.not_valid_after_utc.replace(tzinfo=None),
        "signature_algorithm": _oid_name(cert.signature_algorithm_oid),
        "public_key": keys.describe(cert.public_key()),
        "sha256": colon_hex(cert.fingerprint(hashes.SHA256())),
        "extensions": [(_oid_name(e.oid), e.critical, extension_text(e)) for e in cert.extensions],
    }
