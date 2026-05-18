#!/bin/sh
# Generate a self-signed TLS certificate for nginx's first-boot start-up.
#
# This cert is only used until Jackdaw bootstraps a real Let's Encrypt cert
# for RELAY_DOMAIN and writes fullchain.pem / privkey.pem to the same path.
# nginx is sent SIGHUP by Jackdaw after the real cert is in place.

set -eu

CERT_DIR="/data/ssl"
CERT_FILE="${CERT_DIR}/fullchain.pem"
KEY_FILE="${CERT_DIR}/privkey.pem"

if [ -f "${CERT_FILE}" ] && [ -f "${KEY_FILE}" ]; then
    echo "TLS certificate already present at ${CERT_DIR} — skipping generation."
    exit 0
fi

mkdir -p "${CERT_DIR}"

echo "Generating self-signed certificate in ${CERT_DIR} …"
openssl req -x509 \
    -newkey ec \
    -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "${KEY_FILE}" \
    -out    "${CERT_FILE}" \
    -days   1 \
    -nodes \
    -subj   "/CN=jackdaw-bootstrap"

chmod 600 "${KEY_FILE}"
echo "Self-signed certificate written."
