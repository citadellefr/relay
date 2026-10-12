#!/usr/bin/env bash
# Checks the control-plane PKI end to end: a CA, a certificate a gateway could
# use for the key of its customer sheet, and the refusals that keep the CN
# trustworthy — the CN and the key id are what the gateway checks (control.go).
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

sheet=$(./pki.sh issue tenant1) || fail "issue"

# the sheet is the only place the key exists: 13 groups of 4 base32 characters
key=$(grep -xE ' +([A-Z2-7]{4} ){12}[A-Z2-7]{4}' <<< "$sheet" | tr -d ' ')
[ ${#key} -eq 52 ] || fail "no key on the customer sheet"
[ "$(ls "$PKI_DIR" | tr '\n' ' ')" = "ca.crt ca.key ca.srl tenant1.crt " ] ||
	fail "more than a certificate was written: $(ls "$PKI_DIR")"
grep -rqF "$key" "$PKI_DIR" && fail "the key was written to disk"

# the key and the certificate are one pair: rebuild the private key the way
# the server does and compare what it gives with what was signed
pub=$({
	printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'
	printf '%s====' "$key" | base32 -d
} | openssl pkey -inform DER -pubout)
[ "$pub" = "$(openssl x509 -in "$PKI_DIR/tenant1.crt" -noout -pubkey)" ] ||
	fail "the certificate was not signed for the key of the sheet"

# the id of the sheet is the one tenants.json holds, and show finds it again
id=$(openssl pkey -pubin -outform DER <<< "$pub" | tail -c 32 | sha256sum | cut -d ' ' -f 1)
grep -qF "$id" <<< "$sheet" || fail "the sheet does not print the key id"
./pki.sh show tenant1 | grep -qxF "id=$id" || fail "show prints another key id"

# two tenants never share a key
./pki.sh issue tenant2 | grep -qF "$id" && fail "two tenants got the same key"

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
	./pki.sh issue "$bad" > /dev/null 2>&1 && fail "issued a certificate for $bad"
done

# a live gateway is using the current one: overwriting it would cut its tunnel
./pki.sh issue tenant1 > /dev/null 2>&1 && fail "re-issued over an existing certificate"

./pki.sh show tenant1 > /dev/null || fail "show"

echo "ok — CA, key drawn and never stored, pair and id, client purpose, CN shape and no silent overwrite"
