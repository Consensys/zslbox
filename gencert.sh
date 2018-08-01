#!/bin/bash

## Note this script is meant for dev purposes only. Certificate management and authenticity 
## verification in the gRPC client is necessarly for a secure deployment.
openssl req \
  -subj "/C=US/ST=Texas/L=Texas/O=ConsenSys/OU=ZSLBox/CN=example.com" \
  -newkey rsa:2048 -nodes \
  -keyout server.key \
  -out server.csr
openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt