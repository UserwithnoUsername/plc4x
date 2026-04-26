#!/usr/bin/env bash
# Regenerate all ADS Secure test certificates.
# Run this from within the certs/ directory when the 365-day certs expire.
# The rootCA.pem is valid for 10 years and does not need regenerating unless lost.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "=== Root CA ==="
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 \
  -subj "/C=DE/O=ADS-Secure-Test/CN=RootCA" \
  -days 3650 -out rootCA.pem
openssl x509 -noout -subject -dates -in rootCA.pem

echo ""
echo "=== Client cert (CN=192.168.1.220) ==="
openssl genrsa -out client.key 2048
openssl req -new -key client.key \
  -subj "/C=DE/O=ADS-Secure-Test/CN=192.168.1.220" -out client.csr
openssl x509 -req -in client.csr \
  -CA rootCA.pem -CAkey rootCA.key -CAcreateserial \
  -sha256 -days 365 -out client.crt \
  -extfile <(printf "subjectAltName=IP:192.168.1.220\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth")
rm client.csr
openssl x509 -noout -subject -dates -in client.crt

echo ""
echo "=== Server cert (CN=192.168.1.162, for TwinCAT PLC) ==="
openssl genrsa -out server.key 2048
openssl req -new -key server.key \
  -subj "/C=DE/O=ADS-Secure-Test/CN=192.168.1.162" -out server.csr
openssl x509 -req -in server.csr \
  -CA rootCA.pem -CAkey rootCA.key -CAcreateserial \
  -sha256 -days 365 -out server.crt \
  -extfile <(printf "subjectAltName=IP:192.168.1.162\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")
rm server.csr rootCA.srl
openssl x509 -noout -subject -dates -in server.crt

echo ""
echo "Done. Copy server.crt, server.key, rootCA.pem to the PLC."