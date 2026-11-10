# Server certificates for PostgreSQL, OpenBao and Keycloak. Sourced.
#
# One local CA signs the three server certificates. Its certificate is published
# in the ConfigMap `platform-ca` (namespace platform), which every client
# mounts to verify the server it connects to. The CA key never leaves .tmp/.
# Certificates are valid for ten years: this setup does not rotate them.
# The CA declares its key usage and the server certificates carry an Authority
# Key Identifier: Python 3.13 and later refuse certificates without them.

ensure_platform_ca() {
  local dir="$WORK/ca"
  mkdir -p "$dir"; chmod 700 "$dir"
  if [[ ! -s "$dir/ca.crt" ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
      -subj "/CN=mcp-tenants platform CA" -keyout "$dir/ca.key" -out "$dir/ca.crt" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -addext "subjectKeyIdentifier=hash" 2>/dev/null
    chmod 600 "$dir/ca.key"
  fi
  kubectl -n platform create configmap platform-ca --from-file=ca.crt="$dir/ca.crt" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
}

# issue_server_cert NAME DNS_NAME... -> Secret NAME-tls (tls.crt, tls.key) in platform
issue_server_cert() {
  local name="$1"; shift
  local dir="$WORK/ca" san="" d
  ensure_platform_ca
  for d in "$@"; do san+="${san:+,}DNS:$d"; done
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" \
    -keyout "$dir/$name.key" -out "$dir/$name.csr" 2>/dev/null
  openssl x509 -req -in "$dir/$name.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
    -days 3650 -sha256 -out "$dir/$name.crt" \
    -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nsubjectAltName=%s,IP:127.0.0.1\n' "$san") 2>/dev/null
  kubectl -n platform create secret tls "$name-tls" --cert="$dir/$name.crt" --key="$dir/$name.key" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  rm -f "$dir/$name.key" "$dir/$name.csr"
}
