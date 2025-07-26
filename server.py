from cryptobox.cryptobox import *

class Server():
    def __init__(self, priv:str , cert: str, data: str): 
        self.priv = priv
        self.cert = cert
        self.data = data

    def send_server_hello(self, client_hello: bytes) -> bytes:
        try:
            peer_pub = client_hello
            priv, pub = generate_assymetric_key()
            self.shared_key = key_exchange(priv, peer_pub)
            message = peer_pub + pub + self.cert
            signature = sign(self.priv, message)
            ciphertext = encrypt(self.shared_key, signature + self.cert)
            return pub + ciphertext
        except:
            return None

    def send_data(self, client_ready: bytes) -> bytes:
        try:
            plaintext = decrypt(self.shared_key, client_ready) 
            if (plaintext != b'READY'):
                return None
            return encrypt(self.shared_key, self.data)
        except:
            return None