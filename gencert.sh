#!/bin/bash
openssl req \
  -subj "/C=US/ST=Texas/L=Texas/O=ConsenSys/OU=PegaSys/CN=pegasys.tech" \
  -newkey rsa:2048 -nodes \
  -keyout server.key \
  -out server.csr
openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt