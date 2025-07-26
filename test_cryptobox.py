
import unittest
from cryptobox import *

sample_message = b"Hello World!"

class CryptoLibTest(unittest.TestCase):
    
    def test_encrypt(self):
        key = generate_symmetric_key()
        ciphertext = encrypt(key, sample_message)
        decrypted = decrypt(key, ciphertext)
        self.assertEqual(decrypted, sample_message)

    def test_key_exchange(self):
        priv1, pub1 = generate_assymetric_key()
        priv2, pub2 = generate_assymetric_key()
        shared1 = key_exchange(priv1, pub2)
        shared2 = key_exchange(priv2, pub1)
        self.assertEqual(shared1, shared2)

    def test_signature(self):
        priv, pub = generate_assymetric_key()
        signature = sign(priv, sample_message)
        is_valid = verify(sample_message, signature, pub)
        self.assertTrue(is_valid)

    def test_certificate(self):
        ca_org = "My Trusted CA"
        ca_priv, ca_pub = generate_assymetric_key()
        ca_key_id = get_public_key_id(ca_pub)
        ca_cert = create_certificate_authority(ca_org, ca_priv)
        ca_cert_info = certificate_info(ca_cert)
        self.assertEqual(ca_cert_info["org"], ca_org)
        self.assertEqual(ca_cert_info["org_public_key"], ca_pub)
        self.assertEqual(ca_cert_info["issuer"], ca_org)
        self.assertEqual(ca_cert_info["issuer_key_id"], ca_key_id)
        user_org = "example.com"
        _, user_pub = generate_assymetric_key()
        user_cert = generate_certificate(user_org, user_pub, ca_cert, ca_priv)
        user_cert_info = certificate_info(user_cert)
        self.assertEqual(user_cert_info["org"], user_org)
        self.assertEqual(user_cert_info["org_public_key"], user_pub)
        self.assertEqual(user_cert_info["issuer"], ca_org)
        self.assertEqual(user_cert_info["issuer_key_id"], ca_key_id)
        self.assertTrue(verify_certificate(user_org, user_cert, [ca_cert]))

if __name__ == "__main__":
    unittest.TextTestRunner().run(unittest.TestLoader().loadTestsFromTestCase(CryptoLibTest))