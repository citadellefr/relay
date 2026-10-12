#!/usr/bin/env bash
# Client PKI of the control plane: one CA, one certificate per tenant,
# whose CN is the tenant id its private gateway is known by on :7000.
#
#   pki.sh init                CA key and certificate, once
#   pki.sh issue <tenant>      draws the tenant's key, signs its certificate,
#                              prints the customer sheet
#   pki.sh show <tenant>       who it is for, which key, until when
#
# Runs on the admin machine, not on the VPS: only ca.crt is deployed there
# (CONTROL_CLIENT_CA), never ca.key. Taking the VPS must not give the power to
# mint gateways.
#
# The tenant's key is a 32-byte seed its server turns into an Ed25519 pair.
# The certificate is signed here, in advance, for that pair; the seed itself is
# printed once on the customer sheet and written nowhere, not even here.
#
# Revocation stays in tenants.json, which binds each tenant to the id of its
# key: dropping the tenant, or binding it to another key, closes its tunnel at
# the next reload. A CRL would have to be distributed to exactly one machine,
# which is what tenants.json already is.
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

# key_id reads a PEM public key: hex(SHA-256) of the 32 raw bytes an Ed25519
# key ends with — what tenants.json holds, and what a server asks its
# certificate by.
key_id() {
	openssl pkey -pubin -outform DER | tail -c 32 | sha256sum | cut -d ' ' -f 1
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
	# the seed lives in this variable and in pipes only: 32 bytes as 52
	# base32 characters, what the customer types
	seed=$(openssl rand 32 | base32 | tr -d '=')
	[ ${#seed} -eq 52 ] || fail "could not draw a seed"
	# an Ed25519 private key in DER is this fixed header followed by the seed
	{
		printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'
		printf '%s====' "$seed" | base32 -d
	} | openssl pkey -inform DER -pubout -out "$tmp/pub" ||
		fail "could not derive the key pair"
	# signed from the public key alone: no request, so no private key at rest
	openssl x509 -new -subj "/CN=$tenant" -force_pubkey "$tmp/pub" \
		-CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" -CAcreateserial \
		-days "$CERT_DAYS" -extfile "$tmp/ext" -out "$tmp/crt" ||
		fail "could not sign the certificate of $tenant"
	id=$(key_id < "$tmp/pub")
	mv "$tmp/crt" "$PKI_DIR/$tenant.crt"

	cat << EOF
Fiche client — $tenant

  Clé de raccordement, à recopier dans l'application pour raccorder le serveur :

    $(fold -w 4 <<< "$seed" | paste -sd ' ')

  Cette clé n'est affichée qu'une fois et n'est enregistrée nulle part.
  Qui la détient peut raccorder un serveur sous ce nom : à remettre au
  client seul, par un canal sûr.

Pour Citadelle
  Certificat             : $PKI_DIR/$tenant.crt
  Identifiant de retrait : $id
  Valable jusqu'au       : $(openssl x509 -in "$PKI_DIR/$tenant.crt" -noout -enddate | cut -d = -f 2)
EOF
}

show() {
	crt=$PKI_DIR/$1.crt
	[ -r "$crt" ] || crt=$1
	openssl x509 -in "$crt" -noout -subject -issuer -dates
	echo "id=$(openssl x509 -in "$crt" -noout -pubkey | key_id)"
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
