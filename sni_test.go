package main

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

func TestPeekClientHello(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		tls.Client(client, &tls.Config{ServerName: "tenant1.gw.test", InsecureSkipVerify: true}).Handshake()
	}()

	sni, peeked, err := peekClientHello(server, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if sni != "tenant1.gw.test" {
		t.Fatalf("sni = %q", sni)
	}
	// 0x16: TLS handshake record — the replayed bytes must start the stream
	if len(peeked) == 0 || peeked[0] != 0x16 {
		t.Fatalf("peeked bytes do not start with a TLS record (%d bytes)", len(peeked))
	}
}

func TestPeekClientHelloNotTLS(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))

	if _, _, err := peekClientHello(server, 2*time.Second); err == nil {
		t.Fatal("expected an error on plain HTTP input")
	}
}

func TestTenantFromSNI(t *testing.T) {
	cases := []struct {
		sni, tenant string
		ok          bool
	}{
		{"tenant1.gw.test", "tenant1", true},
		{"Tenant1.GW.Test", "tenant1", true},
		{"gw.test", "", false},
		{"a.b.gw.test", "", false},
		{".gw.test", "", false},
		{"tenant1.other.test", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		tenant, ok := tenantFromSNI(c.sni, "gw.test")
		if tenant != c.tenant || ok != c.ok {
			t.Errorf("tenantFromSNI(%q) = %q, %v — want %q, %v", c.sni, tenant, ok, c.tenant, c.ok)
		}
	}
}

// An installation answers on two names: its own, and the one its public share
// links are handed out on. Both reach the same tunnel — the separation they buy
// is the browser origin, not the route.
func TestResolveTenantSharePrefix(t *testing.T) {
	reg := newRegistry(limits{})
	reg.register("tenant1", &yamux.Session{}, testKey)
	reg.register("partage-legitime", &yamux.Session{}, testKey)

	cases := []struct {
		sni, tenant string
		routed      bool
	}{
		{"tenant1.gw.test", "tenant1", true},
		{"partage-tenant1.gw.test", "tenant1", true},
		// a tenant whose own name starts with the prefix keeps it: the label is
		// tried as it comes before anything is stripped
		{"partage-legitime.gw.test", "partage-legitime", true},
		{"partage-inconnu.gw.test", "", false},
		{"partage-.gw.test", "", false},
		{"autre.gw.test", "", false},
		{"a.b.gw.test", "", false},
	}
	for _, c := range cases {
		tenant, sess := resolveTenant(c.sni, "gw.test", reg)
		if (sess != nil) != c.routed {
			t.Errorf("resolveTenant(%q): routed = %v, want %v", c.sni, sess != nil, c.routed)
			continue
		}
		if c.routed && tenant != c.tenant {
			t.Errorf("resolveTenant(%q) = %q, want %q", c.sni, tenant, c.tenant)
		}
	}
}
