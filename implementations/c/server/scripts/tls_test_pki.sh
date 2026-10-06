# Sourced by the TLS E2E scripts. make_test_pki DIR HOST writes, with the openssl CLI, a throwaway
# P-256 PKI valid for two days:
#   DIR/ca.pem, DIR/ca.key            a test CA
#   DIR/server.pem, DIR/server.key    a server certificate for HOST (SAN DNS:HOST only) the CA signed
#   DIR/other-ca.pem                  an unrelated CA, for clients that must not trust the server
# HOST never has to resolve: clients reach 127.0.0.1 and check the certificate against HOST through
# controlTls.serverName, so neither /etc/hosts nor DNS is touched.
make_test_pki() {
  local dir="$1" host="$2"
  cat >"$dir/pki.cnf" <<CNF
[req]
distinguished_name = dn
prompt = no

[dn]
CN = Specus C TLS E2E CA

[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash

[server_ext]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:$host
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF
  openssl req -x509 -new -config "$dir/pki.cnf" -extensions ca_ext \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$dir/ca.key" -out "$dir/ca.pem" -days 2 2>/dev/null
  openssl req -x509 -new -config "$dir/pki.cnf" -extensions ca_ext -subj "/CN=Specus C TLS E2E other CA" \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$dir/other-ca.key" -out "$dir/other-ca.pem" -days 2 2>/dev/null
  openssl req -new -config "$dir/pki.cnf" -subj "/CN=$host" \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$dir/server.key" -out "$dir/server.csr" 2>/dev/null
  openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca.key" \
    -set_serial "0x$(openssl rand -hex 8)" -days 2 \
    -extfile "$dir/pki.cnf" -extensions server_ext -out "$dir/server.pem" 2>/dev/null
  openssl verify -CAfile "$dir/ca.pem" "$dir/server.pem" >/dev/null
}
