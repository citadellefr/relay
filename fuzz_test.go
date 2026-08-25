package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

// The two things this VPS parses from bytes nobody has authenticated: the
// ClientHello of anyone who connects to :443, and the name it carries. The
// PROXY v2 header is written rather than read here, but a malformed one
// desynchronises the tenant stream just as badly, so it is checked against a
// decoder too.
//
//	go test -run=Fuzz -fuzz=FuzzPeekClientHello -fuzztime=2m
//
// The seed corpus of FuzzPeekClientHello is versioned in testdata/fuzz: real
// ClientHellos (TLS 1.2 and 1.3, ALPN acme-tls/1, no SNI, 63-character label).
// A crasher found later lands there too and becomes a regression test.

// fuzzConn serves a fixed slice and counts what is written back. Deadlines are
// no-ops: a fuzz target must not depend on the clock.
type fuzzConn struct {
	in            []byte
	read, written int
	local, remote net.Addr
}

func (c *fuzzConn) Read(p []byte) (int, error) {
	if c.read >= len(c.in) {
		return 0, io.EOF
	}
	n := copy(p, c.in[c.read:])
	c.read += n
	return n, nil
}

func (c *fuzzConn) Write(p []byte) (int, error)        { c.written += len(p); return len(p), nil }
func (c *fuzzConn) Close() error                       { return nil }
func (c *fuzzConn) LocalAddr() net.Addr                { return c.local }
func (c *fuzzConn) RemoteAddr() net.Addr               { return c.remote }
func (c *fuzzConn) SetDeadline(time.Time) error        { return nil }
func (c *fuzzConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fuzzConn) SetWriteDeadline(t time.Time) error { return nil }

func FuzzPeekClientHello(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	f.Add([]byte{0x16, 0x03, 0x01, 0xff, 0xff}) // record header announcing 64 KB
	f.Fuzz(func(t *testing.T, in []byte) {
		conn := &fuzzConn{in: in}
		sni, peeked, err := peekClientHello(conn, time.Second)

		// the aborted handshake emits a TLS alert; letting it out would answer
		// a scan and break the handshake of a legitimate client
		if conn.written != 0 {
			t.Fatalf("%d bytes reached the client", conn.written)
		}
		if err != nil {
			if sni != "" || peeked != nil {
				t.Fatalf("error %v with sni %q and %d peeked bytes", err, sni, len(peeked))
			}
			return
		}
		if sni == "" {
			t.Fatal("no error but no SNI")
		}
		// what is replayed into the tunnel must be exactly what was read: the
		// private gateway redoes the whole handshake on these bytes
		if !bytes.Equal(peeked, in[:conn.read]) {
			t.Fatalf("peeked %d bytes, %d were read from the client", len(peeked), conn.read)
		}
	})
}

// resolveTenant reads a name an attacker chooses. It decides which tunnel gets
// the connection, so it must never route outside the base domain, never
// resolve a tenant we do not serve, and never return a name with a dot in it
// (that would be the routing loop).
func FuzzResolveTenant(f *testing.F) {
	const domain = "gw.test"
	tenants := testTenantStore(f, map[string]string{"tenant1": "a", "partage-legitime": "b"})
	reg := newRegistry(limits{})
	for id := range tenants.ids() {
		reg.register(id, &yamux.Session{}, "token")
	}

	for _, seed := range []string{
		"tenant1.gw.test", "partage-tenant1.gw.test", "TENANT1.GW.TEST",
		"partage-legitime.gw.test", "partage-.gw.test", "gw.test", ".gw.test",
		"a.b.gw.test", "tenant1.gw.test.evil.test", "tenant1.gw.testx", "",
		"tenant1..gw.test", "\x00.gw.test", "partage-partage-tenant1.gw.test",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, sni string) {
		tenant, sess := resolveTenant(sni, domain, reg)
		if strings.Contains(tenant, ".") {
			t.Fatalf("resolveTenant(%q) = %q: a label cannot contain a dot", sni, tenant)
		}
		if tenant != strings.ToLower(tenant) {
			t.Fatalf("resolveTenant(%q) = %q: not lowered", sni, tenant)
		}
		if !strings.HasSuffix(strings.ToLower(sni), "."+domain) && (tenant != "" || sess != nil) {
			t.Fatalf("resolveTenant(%q) = %q, routed=%v outside the base domain", sni, tenant, sess != nil)
		}
		if sess == nil {
			return
		}
		if !tenants.has(tenant) {
			t.Fatalf("resolveTenant(%q) routed to %q, which is not one of our tenants", sni, tenant)
		}
		// the only two names an installation answers on
		low := strings.ToLower(sni)
		if low != tenant+"."+domain && low != sharePrefix+tenant+"."+domain {
			t.Fatalf("resolveTenant(%q) routed to %q, which is neither of its names", sni, tenant)
		}
	})
}

// proxyHeader is what tells the private gateway who the client is: the login
// brute-force protection and the audit trail over there read it. A header
// whose announced length does not match its content desynchronises the stream,
// and the ClientHello behind it would be read as address bytes.
func FuzzProxyHeader(f *testing.F) {
	f.Add([]byte{192, 0, 2, 1}, []byte{198, 51, 100, 1}, uint16(51000), uint16(443))
	f.Add([]byte(net.ParseIP("2001:db8::1")), []byte(net.ParseIP("2001:db8::2")), uint16(51000), uint16(443))
	// mixed families and lengths a socket never produces, but a header
	// announcing 12 bytes and carrying 24 would be worse than no header
	f.Add([]byte{192, 0, 2, 1}, []byte(net.ParseIP("2001:db8::2")), uint16(1), uint16(2))
	f.Add([]byte{1, 2, 3}, []byte{4, 5, 6}, uint16(0), uint16(0))
	f.Add([]byte{}, []byte{}, uint16(0), uint16(0))
	f.Fuzz(func(t *testing.T, srcIP, dstIP []byte, sport, dport uint16) {
		conn := &fuzzConn{
			remote: &net.TCPAddr{IP: srcIP, Port: int(sport)},
			local:  &net.TCPAddr{IP: dstIP, Port: int(dport)},
		}
		hdr := proxyHeader(conn)

		if len(hdr) < 16 || !bytes.Equal(hdr[:12], proxyV2Sig) {
			t.Fatalf("header % x does not start with the v2 signature", hdr)
		}
		if n := int(binary.BigEndian.Uint16(hdr[14:16])); len(hdr) != 16+n {
			t.Fatalf("header announces %d address bytes and carries %d", n, len(hdr)-16)
		}
		if hdr[12] == 0x20 { // LOCAL: no address, the tenant keeps the tunnel one
			if len(hdr) != 16 {
				t.Fatalf("LOCAL header with %d address bytes", len(hdr)-16)
			}
			return
		}
		if hdr[12] != 0x21 {
			t.Fatalf("version/command byte %#x", hdr[12])
		}
		got, err := readProxyV2Header(bytes.NewReader(hdr))
		if err != nil {
			t.Fatalf("header % x: %v", hdr, err)
		}
		kind := "TCP4"
		if hdr[13] == 0x21 {
			kind = "TCP6"
		}
		want := fmt.Sprintf("%s %s %s %d %d", kind,
			net.IP(srcIP).String(), net.IP(dstIP).String(), sport, dport)
		if got != want {
			t.Fatalf("decoded %q, want %q", got, want)
		}
	})
}
