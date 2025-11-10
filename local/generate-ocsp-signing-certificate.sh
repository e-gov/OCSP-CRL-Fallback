#!/bin/bash
set -eu
cd "$(dirname "$0")"

KEY_PATH=../src/main/resources/ocsp-certificate/ocsp.key.pem
CERT_PATH=../src/main/resources/ocsp-certificate/ocsp.cer.pem

# Generate ECDSA key
openssl ecparam \
  -name prime256v1 \
  -genkey \
  -param_enc named_curve \
  -out "$KEY_PATH"

# Generate self-signed certificate
# MSYS_NO_PATHCONV=1 needed for Git Bash on Windows users - unable to handle "/"-s in -subj parameter.
MSYS_NO_PATHCONV=1 \
  openssl req \
  -new \
  -x509 \
  -sha512 \
  -text \
  -key "$KEY_PATH" \
  -subj "/CN=local-ocsp" \
  -days 3650 \
  -out "$CERT_PATH"
