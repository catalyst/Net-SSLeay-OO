#!/bin/sh

cd $(dirname $0)
set -e

# create a CA request
if [ ! -s my-ca.req ]
then
  openssl req -batch -new -config ca-openssl.cnf \
    -keyout ca-key.pem -passout pass:secr1t \
    -out my-ca.req 
fi

# sign it using itself
if [ ! -s my-ca.pem ]
then
  openssl ca -create_serial  \
    -out my-ca.pem -days 365 -batch \
    -keyfile ca-key.pem -passin pass:secr1t -selfsign \
    -extensions v3_ca \
    -config ca-openssl.cnf \
    -infiles my-ca.req
fi

for which in server client;
do
  # create a $which Cert request
  if [ ! -s $which-cert.req ]
  then
    openssl req -batch -new -config $which-openssl.cnf \
      -keyout $which-key.pem -passout pass:secr1t \
      -out $which-cert.req 
  fi
  
  # sign it using CA cert
  if [ ! -s $which-cert.pem ]
  then
    openssl ca -create_serial  \
      -out $which-cert.pem -days 365 -batch \
      -keyfile ca-key.pem -passin pass:secr1t \
      -extensions ${which}_cert \
      -config ca-openssl.cnf \
      -infiles ${which}-cert.req
  fi
done

c_rehash .

echo "All certificates made."

