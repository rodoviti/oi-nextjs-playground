#!/bin/sh
set -eu

: "${CAROOT:?CAROOT must point to the persistent CA directory}"
: "${CERT_DIR:?CERT_DIR must point to the shared certificate directory}"

umask 077
mkdir -p "$CAROOT" "$CERT_DIR"
chmod 700 "$CAROOT"

mkcert -cert-file "$CERT_DIR/localhost.pem" \
  -key-file "$CERT_DIR/localhost-key.pem" \
  localhost 127.0.0.1 ::1

cp "$CAROOT/rootCA.pem" "$CERT_DIR/rootCA.pem"
chmod 644 "$CERT_DIR/rootCA.pem" "$CERT_DIR/localhost.pem"
chmod 600 "$CERT_DIR/localhost-key.pem"
openssl verify -CAfile "$CERT_DIR/rootCA.pem" "$CERT_DIR/localhost.pem"

printf '%s\n' "HTTPS certificates ready. Trust certs/rootCA.pem on the host once; never export the CA private key."
