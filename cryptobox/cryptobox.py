
import base64
import os
import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import padding
from cryptography import x509

# encode bytes to base64
def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

# decode base64 to bytes
def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode('utf-8'))

# generate nonce
def generate_nonce(length: int) -> bytes:
    return os.urandom(length)

# generate symmetric key
def generate_symmetric_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)

# authenticated encryption
def encrypt(key: bytes, plaintext: bytes):
    nonce = generate_nonce(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

# authenticated decryption
def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    nonce = ciphertext[:12]
    ciphertext = ciphertext[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext

# hash
def hash(message: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    return digest.finalize()

# generate MAC
def mac(message: bytes, key: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()

# verify MAC
def verify_mac(message: bytes, key: bytes, mac_tag: bytes) -> bool:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(mac_tag)
        return True
    except InvalidSignature:
        return False

# derive share key (ECDHE)
def key_exchange(private_key: bytes, peer_public_key: bytes) -> bytes:
    private_key = serialization.load_der_private_key(private_key, password=None)
    peer_public_key = serialization.load_der_public_key(peer_public_key)
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
    ).derive(shared_key)
    return derived_key

# generate assymteric key (EC)
def generate_assymetric_key():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ),
        public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
# generate public key identifier
def get_public_key_id(public_key: bytes) -> bytes:
    public_key = serialization.load_der_public_key(public_key)
    return x509.SubjectKeyIdentifier.from_public_key(public_key).digest

# sign (ECDSA)
def sign(private_key: bytes, message: bytes) -> bytes:
    private_key = serialization.load_der_private_key(private_key, password=None)
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    padder = padding.PKCS7(128).padder()
    padded_signature = padder.update(signature)
    padded_signature += padder.finalize()
    return padded_signature

# verify signature (ECDSA)
def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    unpadder = padding.PKCS7(128).unpadder()
    signature = unpadder.update(signature)
    signature += unpadder.finalize()
    public_key = serialization.load_der_public_key(public_key)
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    
# create a Certificate Authority
def create_certificate_authority(org: str, ca_private_key: bytes):
    ca_private_key = serialization.load_der_private_key(ca_private_key, password=None)
    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, org)])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca_private_key.public_key()
        ),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)

# generate certificate signed by CA
def generate_certificate(org: str, user_public_key: bytes, ca_cert: bytes, ca_private_key: bytes):
    ca_cert = x509.load_der_x509_certificate(ca_cert)
    ca_private_key = serialization.load_der_private_key(ca_private_key, password=None)
    user_public_key = serialization.load_der_public_key(user_public_key)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, org)])
    issuer = ca_cert.subject
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        user_public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(org)]),
        critical=False,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        ),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)

# verify certificate against trusted CA certs
def verify_certificate(org: bytes, cert: bytes, trusted_ca_certs: list[bytes]) -> bool:
    cert = x509.load_der_x509_certificate(cert)
    store = x509.verification.Store(list(map(lambda c: x509.load_der_x509_certificate(c), trusted_ca_certs)))
    builder = x509.verification.PolicyBuilder().store(store)
    verifier = builder.build_server_verifier(x509.DNSName(org))
    chain = verifier.verify(cert, [])
    return len(chain) == 2

# show certificate info
def certificate_info(cert: bytes):
    cert = x509.load_der_x509_certificate(cert)
    org = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
    issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
    org_public_key = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    issuer_public_key_identifier = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier
    return {
        "org": org,
        "org_public_key": org_public_key,
        "issuer": issuer,
        "issuer_key_id": issuer_public_key_identifier,
    }
