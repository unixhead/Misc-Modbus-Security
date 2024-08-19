# Simple test warpper for the Modbus TCP Proxy PoC
# Just sends one modbus query

import socket, ssl, pprint
dest_host = "127.0.0.1"
dest_port = 8443
CA_cert="CA_cert.pem"
key_file="hostkey.pem"
cert_file="hostcert.pem"

#binary file containing a modbus query for test pusrposes
test_query_file = "MB_query.dat"


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

ssl_context = ssl.SSLContext();
ssl_context.load_verify_locations(CA_cert)
ssl_context.load_cert_chain(cert_file, key_file=key_file)

with open(test_query_file, "rb") as f:
    test_query_data = f.read(20)


with ssl_context.wrap_socket(s, server_hostname=dest_host) as ssl_sock:

    ssl_sock.connect((dest_host, dest_port))
    pprint.pprint(ssl_sock.getpeercert())

    ssl_sock.sendall(test_query_data)

    response = ssl_sock.recv(4096)
    print(str(response))

    ssl_sock.close()
