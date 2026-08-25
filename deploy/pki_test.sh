#!/usr/bin/env bash
# Checks the control-plane PKI end to end: a CA, a certificate a gateway could
# use, and the refusals that keep the CN trustworthy — because that CN is the
# only thing the gateway checks (control.go).
#
#   ./pki_test.sh
set -uo pipefail
cd "$(dirname "$0")" || exit 1

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export PKI_DIR=$work/pki

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

./pki.sh init > /dev/null || fail "init"
[ -r "$PKI_DIR/ca.crt" ] || fail "no CA certificate"
[ "$(stat -c %a "$PKI_DIR/ca.key")" = "600" ] || fail "the CA key is world readable"
[ "$(stat -c %a "$PKI_DIR")" = "700" ] || fail "the PKI directory is world readable"

# a second CA would sign certificates the deployed gateway rejects
./pki.sh init > /dev/null 2>&1 && fail "a second init overwrote the CA"

./pki.sh issue tenant1 > /dev/null || fail "issue"
[ "$(stat -c %a "$PKI_DIR/tenant1.key")" = "600" ] || fail "the client key is world readable"

# the CN is what control.go compares the announced tenant to
subject=$(openssl x509 -in "$PKI_DIR/tenant1.crt" -noout -subject -nameopt RFC2253)
[[ $subject == *"CN=tenant1" ]] || fail "wrong CN: $subject"

# what the control plane's TLS layer will do with it
openssl verify -CAfile "$PKI_DIR/ca.crt" -purpose sslclient "$PKI_DIR/tenant1.crt" > /dev/null ||
	fail "the certificate is not a valid client certificate for our CA"

# and what it must not accept: another CA's
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
	-subj "/CN=tenant1" -keyout "$work/other.key" -out "$work/other.crt" 2> /dev/null
openssl verify -CAfile "$PKI_DIR/ca.crt" "$work/other.crt" > /dev/null 2>&1 &&
	fail "a foreign certificate verified against our CA"

# the CN is an identity, not free text
for bad in "Tenant1" "a/b" "../evil" "" "-x"; do
	./pki.sh issue "$bad" > /dev/null 2>&1 && fail "issued a certificate for %s" "$bad"
done

# a live gateway is using the current one: overwriting it would cut its tunnel
./pki.sh issue tenant1 > /dev/null 2>&1 && fail "re-issued over an existing certificate"

./pki.sh show tenant1 > /dev/null || fail "show"

echo "ok — CA, issuance, client purpose, CN shape and no silent overwrite"
