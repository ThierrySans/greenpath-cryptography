# CryptoBox

**CryptoBox** is a simple cryptographic library built on top of `cryptography`. It supports symmetric encryption, hashing, Message Authentication Code (MAC), key exchange, digital signature, and certificate generation and verification.

- [Symmetric Encryption](#symmetric-encryption)
- [Hashing](#hashing)
- [Message Authentication Code (MAC)](#mac)
- [Key Exchange](#key-exchange)
- [Digital Signature](#digital-signature)
- [Certificate](#certificate)

## Symmetric Encryption

```python
from cryptobox import generate_symmetric_key, encrypt, decrypt

key = generate_symmetric_key()
message = b"Hello World!"
ciphertext = encrypt(key, message)
plaintext = decrypt(key, ciphertext)

assert plaintext == message
```

## Hashing

```python
from cryptobox import hash
msg = b"Hello World!"
digest = hash(msg)
```

## MAC

```python
from cryptobox import mac, generate_symmetric_key

msg = b"Hello World!"
key = generate_symmetric_key()
tag = mac(msg, key)
```

## Key Exchange

```python
from cryptobox import generate_assymetric_key, key_exchange

priv1, pub1 = generate_assymetric_key()
priv2, pub2 = generate_assymetric_key()

shared1 = key_exchange(priv1, pub2)
shared2 = key_exchange(priv2, pub1)

assert shared1 == shared2
```

## Digital Signature

```python
from cryptobox import generate_assymetric_key, sign, verify

priv, pub = generate_assymetric_key()
msg = b"Hello World!"
signature = sign(priv, msg)

assert verify(msg, signature, pub)
```

## Certificate

```python
from cryptobox import generate_assymetric_key, create_certificate_authority, certificate_signing_request, generate_certificate, verify_certificate

ca_priv, ca_pub = generate_assymetric_key()
ca_cert = create_certificate_authority(ca_priv)

priv, pub = generate_assymetric_key()
csr = certificate_signing_request(priv, "example.com")

cert = generate_certificate(ca_cert, ca_priv, csr)

print(certificate_info(cert))
assert verify_certificate("example.com", cert, [ca_cert])
```

## License

MIT