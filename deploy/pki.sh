#!/usr/bin/env bash
# Client PKI of the control plane: one CA, one certificate per tenant,
# whose CN is the tenant id its private gateway announces on :7000.
#
#   pki.sh init                CA key and certificate, once
#   pki.sh issue <tenant>      key and certificate for one private gateway
#   pki.sh show <tenant>       who it is for, until when, still signed by us
#
# Runs on the admin machine, not on the VPS: only ca.crt is deployed there
# (CONTROL_CLIENT_CA), never ca.key. Taking the VPS must not give the power to
# mint gateways.
#
# Revocation stays in tenants.json: dropping a tenant and reloading (SIGHUP)
# closes its tunnel at once. A CRL would have to be distributed to exactly one
# machine, which is what tenants.json already is.
set -euo pipefail
umask 077

: "${PKI_DIR:=$HOME/citadelle-pki}"
: "${CA_DAYS:=3650}"
: "${CERT_DAYS:=825}"

fail() {
	echo "pki: $*" >&2
	exit 1
}

init() {
	mkdir -p "$PKI_DIR"
	chmod 700 "$PKI_DIR"
	! [ -e "$PKI_DIR/ca.key" ] ||
		fail "$PKI_DIR/ca.key exists — a second CA would lock out every gateway signed by the first"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-days "$CA_DAYS" -subj "/CN=Citadelle control plane CA" \
		-addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
		-addext "keyUsage=critical,keyCertSign,cRLSign" \
		-keyout "$PKI_DIR/ca.key" -out "$PKI_DIR/ca.crt" 2> /dev/null
	chmod 600 "$PKI_DIR/ca.key"
	echo "CA: $PKI_DIR/ca.crt"
	echo "deploy that file as CONTROL_CLIENT_CA; ca.key never leaves this machine"
}

issue() {
	tenant=$1
	[ -r "$PKI_DIR/ca.key" ] || fail "no CA in $PKI_DIR — run '$0 init' first"
	# the CN is the identity the gateway is judged on, so keep it to the shape
	# tenant ids actually have
	case $tenant in
	"" | -* | *[!a-z0-9-]*) fail "tenant $tenant: lowercase letters, digits and dashes only" ;;
	esac
	! [ -e "$PKI_DIR/$tenant.crt" ] ||
		fail "$PKI_DIR/$tenant.crt exists — remove it first, its gateway is using it"

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	cat > "$tmp/ext" << 'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-subj "/CN=$tenant" -keyout "$PKI_DIR/$tenant.key" -out "$tmp/csr" 2> /dev/null
	openssl x509 -req -in "$tmp/csr" -CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" \
		-CAcreateserial -days "$CERT_DAYS" -extfile "$tmp/ext" \
		-out "$PKI_DIR/$tenant.crt" 2> /dev/null
	chmod 600 "$PKI_DIR/$tenant.key"
	echo "$PKI_DIR/$tenant.crt"
	echo "$PKI_DIR/$tenant.key"
	echo "on the client server: GATEWAY_CLIENT_CERT and GATEWAY_CLIENT_KEY"
}

show() {
	crt=$PKI_DIR/$1.crt
	[ -r "$crt" ] || crt=$1
	openssl x509 -in "$crt" -noout -subject -issuer -dates
	openssl verify -CAfile "$PKI_DIR/ca.crt" -purpose sslclient "$crt"
}

case "${1:-}" in
init) init ;;
issue)
	[ $# -eq 2 ] || fail "usage: $0 issue <tenant>"
	issue "$2"
	;;
show)
	[ $# -eq 2 ] || fail "usage: $0 show <tenant>"
	show "$2"
	;;
*)
	echo "usage: $0 {init|issue <tenant>|show <tenant>}" >&2
	exit 2
	;;
esac
