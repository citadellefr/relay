package main

import (
	"bytes"
	"crypto/tls"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLogAddr(t *testing.T) {
	cases := []struct {
		addr net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.ParseIP("203.0.113.42"), Port: 44321}, "203.0.113.0/24"},
		{&net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.42"), Port: 44321}, "203.0.113.0/24"},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::1"), Port: 44321}, "2001:db8:1::/48"},
		{&net.UnixAddr{Name: "/tmp/s", Net: "unix"}, "?"},
		{nil, "?"},
	}
	for _, c := range cases {
		if got := logAddr(c.addr); got != c.want {
			t.Errorf("logAddr(%v) = %q, want %q", c.addr, got, c.want)
		}
	}
}

// LOG_CLIENT_IP=full is the documented opt-out, for a debugging session only.
func TestLogAddrFull(t *testing.T) {
	logFullAddr = true
	t.Cleanup(func() { logFullAddr = false })
	addr := &net.TCPAddr{IP: net.ParseIP("203.0.113.42"), Port: 44321}
	if got := logAddr(addr); got != "203.0.113.42:44321" {
		t.Errorf("logAddr = %q, want the full address", got)
	}
}

func TestKnownTenant(t *testing.T) {
	tenants := testTenantStore(t, map[string]string{"tenant1": testKey, "partage-legitime": testKey})
	cases := []struct {
		label string
		want  bool
	}{
		{"tenant1", true},
		{"partage-tenant1", true}, // the share name of a tenant we serve
		{"partage-legitime", true},
		{"partage-inconnu", false},
		{"inconnu", false},
		{"", false},
	}
	for _, c := range cases {
		if got := knownTenant(c.label, tenants); got != c.want {
			t.Errorf("knownTenant(%q) = %v, want %v", c.label, got, c.want)
		}
	}
}

// The data path must never write a client address in the journal, and a name
// we do not serve must write nothing at all — otherwise anyone scanning the
// internet chooses what our journal contains.
func TestProxyJournalHasNoClientAddress(t *testing.T) {
	const domain = "gw.test"
	tenants := testTenantStore(t, map[string]string{"tenant1": testKey})

	var buf syncBuffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go runProxy(ln, domain, newRegistry(limits{}), tenants, turnRelay{})

	// no tunnel is registered: both handshakes fail, only the second one is
	// about a tenant we know, and the client sees the drop after the log
	// decision was taken
	hello := func(sni string) {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		tc.SetDeadline(time.Now().Add(3 * time.Second))
		tc.Handshake()
	}
	hello("scan.gw.test")
	hello("tenant1.gw.test")

	got := proxyLines(buf.String())
	if !strings.Contains(got, `no tunnel for "tenant1"`) {
		t.Fatalf("a tenant of ours with no tunnel must be reported, got %q", got)
	}
	if strings.Contains(got, "scan") {
		t.Errorf("an unknown name reached the journal: %q", got)
	}
	if !strings.Contains(got, "127.0.0.0/24") || strings.Contains(got, "127.0.0.1") {
		t.Errorf("client address not reduced to its network: %q", got)
	}
}

// proxyLines keeps the data-path lines only: a control-plane goroutine of
// another test may still be writing to the same logger, and the control plane
// follows the opposite policy on purpose.
func proxyLines(s string) string {
	var kept []string
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "proxy:") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// syncBuffer collects log output written from the proxy goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestLogNoTunnelRateLimit(t *testing.T) {
	var buf syncBuffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	noTunnelMu.Lock()
	delete(noTunnelLast, "t-rate")
	noTunnelMu.Unlock()

	addr := &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 12345}
	logNoTunnel("t-rate", addr)
	logNoTunnel("t-rate", addr)
	logNoTunnel("t-rate", addr)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 log line due to rate-limiting, got %d: %v", len(lines), lines)
	}
}
