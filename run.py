import os
import sys

from cryptobox import b64decode, b64encode
from server import Server
from client import Client

def run(url, trusted_cert_dir, server_dir):
    with open(os.path.join(server_dir, "priv.key"), 'r') as f:
        priv = b64decode(f.read())
    with open(os.path.join(server_dir, "server.cert"), 'r') as f:
        cert = b64decode(f.read())
    with open(os.path.join(server_dir, "data.txt"), 'r') as f:
        data = b64decode(f.read()) 
    trusted_certs = []
    for filename in os.listdir(trusted_cert_dir):
        with open(os.path.join(trusted_cert_dir, filename), 'r') as f:
            trusted_certs.append(b64decode(f.read()))

    server = Server(priv, cert, data)
    client = Client(url, trusted_certs)
    client_hello = client.send_client_hello()
    if client_hello is None:
        print("client_hello: None")
        return
    else: 
        print("client_hello: " + b64encode(client_hello))
    server_hello = server.send_server_hello(client_hello)
    if server_hello is None:
        print("server_hello: None")
        return
    else: 
        print("server_hello: " + b64encode(server_hello))
    client_ready = client.send_client_ready(server_hello)
    if client_ready is None:
        print("client_ready: None")
        return
    else: 
        print("client_ready: " + b64encode(client_ready))
    server_data = server.send_data(client_ready)
    if server_data is None:
        print("server_data: None")
        return
    else: 
        print("server_data: " + b64encode(server_data))
    client_data = client.receive_data(server_data)
    if server_data is None:
        print("client_data: None")
        return
    else: 
        print("client_data: " + str(client_data))

if __name__ == "__main__":
    import os, sys, getopt
    def usage():
        print ('Usage:    ' + os.path.basename(__file__) + ' options url server ')
        print ('Options:')
        print ('\t -c config, --config=config')
        sys.exit(2)
    try:
      opts, args = getopt.getopt(sys.argv[1:],"hc:",["help","config="])
    except getopt.GetoptError as err:
      print(err)
      usage()
    # extract parameters
    config = None
    url = args[0] if len(args) > 0 else None
    server = args[1] if len(args) > 0 else None
    # check arguments
    if (config is None):
       config = os.path.join("config")
    if (url is None):
        print('url is missing\n')
        usage()
    if (server is None):
       print('server is missing\n')
       usage()
    # check config
    if not os.path.exists(config):
        print(config + ' does not exists\n')
        usage()
    # check trusted_cert
    trusted_cert_dir = os.path.join(config, "trusted_certs")
    if not os.path.exists(trusted_cert_dir):
        print(trusted_cert_dir + ' does not exists\n')
        usage()
    # check server_dir
    server_dir = os.path.join(config, "servers", server)
    if not os.path.exists(server_dir):
        print(server_dir + ' does not exists\n')
        usage()
    # run
    run(url, trusted_cert_dir, server_dir)