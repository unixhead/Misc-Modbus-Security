#!/bin/sh

#creates a CA with NO PASSWORD for test purposes

#CA will be created in folder CA-xxxx with 4 random characters

randstr=`tr -dc A-Za-z0-9 </dev/urandom | head -c 4`
folder="CA-${randstr}"

mkdir -p $folder/certs $folder/private $folder/crl $folder/newcerts $folder/private $folder/csr
echo 00 > $folder/serial 
touch $folder/index.txt $folder/crlnumber

cat << EOF > $folder/ca.cnf
HOME			= .

[ ca ]
default_ca	= CA_default		# The default ca section

[ CA_default ]

dir		= ./		# Where everything is kept
certs		= \$dir/certs		# Where the issued certs are kept
crl_dir		= \$dir/crl		# Where the issued crl are kept
database	= \$dir/index.txt	# database index file.
#unique_subject	= no			# Set to 'no' to allow creation of
					# several ctificates with same subject.
new_certs_dir	= \$dir/newcerts		# default place for new certs.

certificate	= \$certs/cacert.pem 	# The CA certificate
serial		= \$dir/serial 		# The current serial number
crlnumber	= \$dir/crlnumber	# the current crl number
					# must be commented out to leave a V1 CRL
crl		= \$dir/crl.pem 		# The current CRL
private_key	= \$dir/private/cakey.pem # The private key
RANDFILE	= \$dir/private/.rand	# private random number file

x509_extensions	= usr_cert		# The extentions to add to the cert

default_days	= 3650			# how long to certify for - 10 years
default_crl_days= 30			# how long before next CRL
default_md	= default		# use public key default MD
preserve	= no			# keep passed DN ordering

policy		= policy_match
    
[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

[ policy_match ]
countryName		= match
stateOrProvinceName	= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional



[ req ]
default_bits		= 4096
default_md          = sha256
default_keyfile 	= privkey.pem
distinguished_name	= req_distinguished_name
attributes		= req_attributes
x509_extensions	= v3_ca	



[ req_distinguished_name ]
countryName			= County Name
countryName_default		= UK
countryName_min			= 2
countryName_max			= 2

stateOrProvinceName		= Province Name
stateOrProvinceName_default	= County

localityName			= Locality Name
localityName_default            = Town
0.organizationName		= Oganization Name
0.organizationName_default	= Test Organisation

organizationalUnitName		= Organization Unit Name
organizationalUnitName_default	= Test Lab

commonName			= Common Name (e.g. server FQDN or YOUR name)
commonName_max			= 64

emailAddress			= Email Address
emailAddress_max		= 64

[ req_attributes ]
challengePassword		= A challenge password
challengePassword_min		= 4
challengePassword_max		= 20
unstructuredName		= An optional company name


[ usr_cert ]
basicConstraints=CA:FALSE
nsComment			= "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer


[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment



[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical,CA:true



[req_mbaps]
1.3.6.1.4.1.50316.802.1=ASN1:UTF8String:Admin

EOF

#create the CA cert
# remove the "-nodes" option to require CA password
openssl req -new -x509 -days 3650 -nodes -extensions v3_ca -keyout $folder/private/cakey.pem -out $folder/certs/cacert.pem -config $folder/ca.cnf   -subj "/C=UK/ST=County/L=Town/O=Test Organisation/CN=test-CA" 

#create 3 client private keys and certificates named test1, test2 and test3
echo "creating client test1 key and cert"
cd $folder

for NAME in "test1" "test2" "test3"
do
    mkdir $NAME
    openssl req -new -nodes -out csr/${NAME}req.pem -keyout ${NAME}/${NAME}key.pem -config ca.cnf -extensions req_mbaps -subj "/C=UK/ST=County/L=Town/O=Test Organisation/CN=${NAME}" 
    #sign it
    openssl ca -batch -config ca.cnf -extensions req_mbaps -out ${NAME}/${NAME}cert.pem -infiles csr/${NAME}req.pem
done




