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
from cryptography import x509
from cryptography.x509.oid import NameOID


#peers allowed to connect to the backend modbus system - must have the certificate common name set to one of these values
allowedPeers="test3", "test1", "test2"

#Client certificates must be signed by the CA whose public key is here:
caCert="cacert.pem"

#key and cert used for the servers own identification
keyFile="hostkey.pem"
certFile="hostcert.pem"

#where this server will listen for Modbus/TCP Security connections
server_ip = '127.0.0.1'
server_port = 8443

#the backend plain text modbus system that connections will be forwarded to
backend_ip = "127.0.0.1"
backend_port = 10502

# This supports 2 roles, 
# Operator = Read-only
# Admin = read-write


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
        peer_cert_obj = x509.load_der_x509_certificate(peer_cert_der)
        peer_CN = peer_cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        
        
        print("Peer commonNameN=" + peer_CN)
        if (peer_CN not in allowedPeers):
            print("Peer "+peer_CN +" not in allowedPeers list, closing connection")
            break
        else:   
            print("Peer " + peer_CN + " allowed")

        
        

        # Final version needs to check it has the 1.3.6.1.4.1.50316.802.1 PEM OID which contains the role
        role_oid = "1.3.6.1.4.1.50316.802.1"
        # have to faff about as the crypto library doesn't like unknown OIDs
        #Looks like this:
        #<Extension    (oid=
        #               <ObjectIdentifier (oid=1.3.6.1.4.1.50316.802.1, name=Unknown OID)>, 
        #               critical=False, 
        #               value=<UnrecognizedExtension(oid=<ObjectIdentifier(oid=1.3.6.1.4.1.50316.802.1, name=Unknown OID)>, 
        #               value=b'\x0c\x08Operator')>
        #       )>


        for ext in peer_cert_obj.extensions:
            if role_oid in str(ext):    # extract the value of the role OID from the extension object - strip out the UTF8 header
                role_val = str(ext).split("value=b")[1].split('\'')[1].replace('\\x0c\\x08','')
                print("Role: " + role_val)



        # Peer passed mTLS tests, continue with connection
        while True:
            #read data from the connection - this should be a modbus application PDU
            data = conn.recv(4096)
            if not data:
                print("Client closed connection")
                conn.close()
                break

            # Extract the modbus function code
            # packet header is 7 bytes, then function code is 1 byte
            function_code = data[7:8]
            if (role_val.casefold() == "operator"):
                #readonly
                print("operator")
                allowed_functions = "01", "02", "03", "04", "14", "18", "2B", "0E" # all the read functions
                #print(function_code.hex())
                if not function_code.hex() in allowed_functions:
                    print("operator not permitted write function")
                    continue
                else:
                    print("operator allowed function")
            elif (role_val.casefold() == "admin"):
                #rw
                print("admin")
            else:
                print("Certificate presented no Modbus role in OID " + role_oid + ", NULL role assigned which has no permissions, closing Connection")
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
    
