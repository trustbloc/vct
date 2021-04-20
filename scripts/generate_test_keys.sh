#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Generating test certs ..."

cd /opt/workspace/vct

CERTS_OUTPUT_DIR=test/bdd/fixtures/vct/keys/tls

mkdir -p ${CERTS_OUTPUT_DIR}

trustblocSSLConf=$(mktemp)
echo "subjectKeyIdentifier=hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage = serverAuth
keyUsage = Digital Signature, Key Encipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = *.vct.local" >> "$trustblocSSLConf"

CERT_CA="${CERTS_OUTPUT_DIR}/trustbloc-dev-ca.crt"
if [ ! -f "$CERT_CA" ]; then
    echo "... Generating CA cert ..."
    openssl ecparam -name prime256v1 -genkey -noout \
      -out ${CERTS_OUTPUT_DIR}/trustbloc-dev-ca.key
    openssl req -new -x509 -key ${CERTS_OUTPUT_DIR}/trustbloc-dev-ca.key \
      -subj "/C=CA/ST=ON/O=TrustBloc/OU=TrustBloc Dev CA" \
      -out ${CERTS_OUTPUT_DIR}/trustbloc-dev-ca.crt -days 1095
else
    echo "Skipping CA generation - already exists"
fi

echo "... Generating TrustBloc domain cert:  vct.local ..."

openssl ecparam -name prime256v1 -genkey -noout \
  -out ${CERTS_OUTPUT_DIR}/vct.local.key

openssl req -new -key ${CERTS_OUTPUT_DIR}/vct.local.key \
  -subj "/C=CA/ST=ON/O=TrustBloc/OU=trustbloc/CN=vct.local" \
  -out ${CERTS_OUTPUT_DIR}/vct.local.csr

openssl x509 -req -in ${CERTS_OUTPUT_DIR}/vct.local.csr \
  -CA ${CERTS_OUTPUT_DIR}/trustbloc-dev-ca.crt \
  -CAkey ${CERTS_OUTPUT_DIR}/trustbloc-dev-ca.key \
  -CAcreateserial -CAserial ${CERTS_OUTPUT_DIR}/vct.local.srl -extfile "$trustblocSSLConf" \
  -out ${CERTS_OUTPUT_DIR}/vct.local.crt -days 365

# RFC 4346 Append CA to CERT
cat ${CERTS_OUTPUT_DIR}/trustbloc-dev-ca.crt >> ${CERTS_OUTPUT_DIR}/vct.local.crt

echo "... Done generating test certs"