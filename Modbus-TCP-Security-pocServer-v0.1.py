# Modbus TCP Security Proxy Proof of Concept
#
#   https://modbus.org/docs/MB-TCP-Security-v21_2018-07-24.pdf
#
# Accepts inbound Modbus TCP-Security connections and forward to a backend modbus service
#
# There is no filtering of what is forwarded
# The Modbus TCP Security roles are not implemented in this version
# Uses local CA certs

import socket, ssl
import OpenSSL.crypto as crypto

#peers allowed to connect to the backend modbus system - must have the certificate common name set to one of these values
allowedPeers="test3", "test1", "test2"

#Client certificates must be signed by the CA whose public key is here:
caCert="cacert.pem"

#key and cert used for the servers own identification
keyFile="serverkey.pem"
certFile="servercert.pem"

#where this server will listen for Modbus/TCP Security connections
server_ip = '127.0.0.1'
server_port = 8443

#the backend plain text modbus system that connections will be forwarded to
backend_ip = "127.0.0.1"
backend_port = 10502


#open server socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((server_ip,server_port))
s.listen(5)

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);
ssl_context.load_verify_locations(caCert)
ssl_context.load_cert_chain(certFile, keyfile=keyFile)
ssl_context.verify_mode = ssl.CERT_REQUIRED
# MB-TCP-Security spec R32 must be TLSv1.2 or better
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

#open connection to backend plain text modbus service
backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    backend_sock.connect((backend_ip, backend_port)) 
except:
    print("Backend Modbus Service on " + backend_ip + "/" + str(backend_port) + " is not responding, exiting.")
    exit(0)

print("Connected to backend Modbus-TCP service on " + backend_ip)


#open the TLS service to receive inbound connection
with ssl_context.wrap_socket(s, server_side=True) as ssl_sock:
    while True:
        (conn, addr) = ssl_sock.accept()
        print("New Connection from " + str(conn.getpeername())) 

        #obtain certificate provided by peer
        peer_cert_der = conn.getpeercert(True) 
        if not peer_cert_der: # Shouldn't happen due to setting ssl.CERT_REQUIRED
            print("no cert supplied")
            break

        #extract common name and validate against the allowed list
        peer_cert_obj = crypto.load_certificate(crypto.FILETYPE_ASN1,peer_cert_der)
        peer_CN = peer_cert_obj.get_subject().CN
        print("Peer commonNameN=" + peer_CN)
        if (peer_CN not in allowedPeers):
            print("Peer "+peer_CN +" not in allowedPeers list, closing connection")
            break
        else:   
            print("Peer " + peer_CN + " allowed")


        # Final version needs to check it has the 1.3.6.1.4.1.50316.802.1 PEM OID which contains the role
        role_oid = "1.3.6.1.4.1.50316.802.1"
        # not straightforward to do this with openssl library so not including this for now and just using NULL as the role definition to align with RFC
        
        # Peer passed mTLS tests, continue with connection
        while True:
            #read data from the connection - this should be a modbus application PDU
            data = conn.recv(4096)
            if not data:
                print("Client closed connection")
                conn.close()
                break

            #print(f"Received data: {data.decode('utf-8')}")
            print("Forwarding modbus traffic")

            #transmit it to the backend plain modbus service
            backend_sock.sendall(data)

            #wait for a response - blocking
            backend_response = backend_sock.recv(4096)

            #forward the response back to the client
            conn.sendall(backend_response)
    
