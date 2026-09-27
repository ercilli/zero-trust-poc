#!/usr/bin/env bash
set -euo pipefail

CERTS_DIR="./certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "==> 1. Generando Autoridad Certificadora (CA) Raíz..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt \
    -subj "/C=AR/ST=BA/L=Ituzaingo/O=ZeroTrustLab/CN=PoC-Internal-CA"

echo "==> 2. Generando Certificado del Servidor (NGINX Proxy)..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/C=AR/ST=BA/O=ZeroTrustLab/CN=proxy-servicio-b"

# SAN necesario: los clientes validan el certificado tanto desde dentro de
# Docker (hostname proxy-servicio-b) como desde el host (localhost/127.0.0.1)
cat > server_ext.cnf <<EOF
subjectAltName = DNS:localhost,DNS:proxy-servicio-b,IP:127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -sha256 -extfile server_ext.cnf

echo "==> 3. Generando Certificado de Cliente Legítimo (Servicio A)..."
openssl genrsa -out client-valid.key 2048
openssl req -new -key client-valid.key -out client-valid.csr \
    -subj "/C=AR/ST=BA/O=ZeroTrustLab/CN=client-facturacion"
openssl x509 -req -in client-valid.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client-valid.crt -days 365 -sha256

echo "==> 4. Generando Certificado Rogue (CA No Confiable)..."
openssl genrsa -out fake_ca.key 2048
openssl req -x509 -new -nodes -key fake_ca.key -days 365 -out fake_ca.crt \
    -subj "/CN=Rogue-Untrusted-CA"
openssl genrsa -out client-rogue.key 2048
openssl req -new -key client-rogue.key -out client-rogue.csr \
    -subj "/CN=attacker-client"
openssl x509 -req -in client-rogue.csr -CA fake_ca.crt -CAkey fake_ca.key -CAcreateserial \
    -out client-rogue.crt -days 365 -sha256

echo "==> Certificados creados exitosamente en ./certs"