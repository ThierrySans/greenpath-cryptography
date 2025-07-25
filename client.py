from cryptobox import *

PUBLIC_KEY_SIZE = 120 # bytes
SIGNATURE_SIZE = 112 # bytes

class Client():
    def __init__(self, url: bytes, trusted_certs: list[bytes]): 
        self.url = url
        self.trusted_certs = trusted_certs
    
    def send_client_hello(self) -> bytes:
        return None

    def send_client_ready(self, server_hello: bytes) -> bytes:
        return None
        
    def receive_data(self, data: bytes) -> bytes:
        return None
