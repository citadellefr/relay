package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

func testTenantStore(t testing.TB, tenants map[string]string) *tenantStore {
	t.Helper()
	raw, err := json.Marshal(tenants)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tenants.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newTenantStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testAuthLimiter() *failLimiter { return newFailLimiter(10, time.Minute) }

// testKey stands for a key id where no tunnel is ever opened.
var testKey = strings.Repeat("0", 64)

// startControl runs the control plane with these certificates as its CA and
// each tenant they name bound to its key, the last one given when two name
// the same tenant.
func startControl(t *testing.T, reg *registry, lim *failLimiter, clients ...tls.Certificate) (net.Listener, *tenantStore) {
	t.Helper()
	pool := x509.NewCertPool()
	keys := map[string]string{}
	for _, c := range clients {
		pool.AddCert(c.Leaf)
		keys[c.Leaf.Subject.CommonName] = keyID(c.Leaf)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{testCert(t, "control.gw.test")},
		MinVersion:   tls.VersionTLS12,
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	store := testTenantStore(t, keys)
	go runControl(ln, store, reg, lim)
	return ln, store
}

// controlAuth opens a control connection, sends one auth line and returns the
// reply. The connection stays open for the test to look at the tunnel.
func controlAuth(t *testing.T, ln net.Listener, line string, certs ...tls.Certificate) (string, error) {
	t.Helper()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, Certificates: certs})
	if err != nil {
		return "", err
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintln(conn, line)
	return bufio.NewReader(conn).ReadString('\n')
}

// Full path: https client → SNI proxy → tunnel → fake private gateway that
// terminates TLS and answers HTTP.
func TestEndToEnd(t *testing.T) {
	const domain = "gw.test"
	reg := newRegistry(limits{})
	clientCert := testClientCert(t, "tenant1")
	controlLn, tenants := startControl(t, reg, testAuthLimiter(), clientCert)

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()
	go runProxy(proxyLn, domain, reg, tenants, turnRelay{})

	tenantCert := testCert(t, "tenant1.gw.test")
	proxyHdr := make(chan string, 1)
	startFakePrivateGateway(t, controlLn.Addr().String(), clientCert, tenantCert, proxyHdr)

	waitForTunnel(t, reg, "tenant1")

	pool := x509.NewCertPool()
	pool.AddCert(tenantCert.Leaf)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := net.Dial("tcp", proxyLn.Addr().String())
				if err != nil {
					return nil, err
				}
				tc := tls.Client(c, &tls.Config{ServerName: "tenant1.gw.test", RootCAs: pool})
				if err := tc.HandshakeContext(ctx); err != nil {
					c.Close()
					return nil, err
				}
				return tc, nil
			},
		},
	}
	resp, err := client.Get("https://tenant1.gw.test/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hello from tenant1" {
		t.Fatalf("status %d, body %q", resp.StatusCode, body)
	}

	select {
	case hdr := <-proxyHdr:
		if !strings.HasPrefix(hdr, "TCP4 127.0.0.1 127.0.0.1 ") {
			t.Fatalf("proxy header = %q", hdr)
		}
	default:
		t.Fatal("no PROXY header received by the private gateway")
	}

	// the health endpoint must reflect the live tunnel and the stream count
	stats := reg.snapshot()["tenant1"]
	if !stats.Connected || stats.TotalStreams == 0 {
		t.Fatalf("unexpected tenant stats: %+v", stats)
	}

	// unknown tenant: the connection must be dropped, no TLS answer
	c, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc := tls.Client(c, &tls.Config{ServerName: "nope.gw.test", InsecureSkipVerify: true})
	tc.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tc.Handshake(); err == nil {
		t.Fatal("expected handshake failure for an unknown tenant")
	}
}

// A certificate our CA signed is not enough: tenants.json binds the tenant to
// one key, so the certificate of a seed that was replaced opens nothing.
func TestControlAuthFailure(t *testing.T) {
	reg := newRegistry(limits{})
	replaced, current := testClientCert(t, "tenant1"), testClientCert(t, "tenant1")
	controlLn, _ := startControl(t, reg, testAuthLimiter(), replaced, current)

	line, err := controlAuth(t, controlLn, `{"v":1}`, replaced)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(line, `"ok":true`) {
		t.Fatalf("auth accepted with the key tenants.json no longer names: %q", line)
	}
	if reg.lookup("tenant1") != nil {
		t.Fatal("session registered despite failed auth")
	}
	if line, err := controlAuth(t, controlLn, `{"v":1}`, current); err != nil || !strings.Contains(line, `"ok":true`) {
		t.Fatalf("auth refused with the bound key: %q, %v", line, err)
	}
}

// No token path is left: a peer without a certificate never gets a reply.
func TestControlRequiresCertificate(t *testing.T) {
	reg := newRegistry(limits{})
	controlLn, _ := startControl(t, reg, testAuthLimiter(), testClientCert(t, "tenant1"))

	if line, err := controlAuth(t, controlLn, `{"tenant":"tenant1","token":"sekrit"}`); err == nil {
		t.Fatalf("a peer without a certificate was answered: %q", line)
	}
	stranger := testClientCert(t, "tenant1")
	if line, err := controlAuth(t, controlLn, `{"v":1}`, stranger); err == nil {
		t.Fatalf("a certificate from another CA was answered: %q", line)
	}
	if reg.lookup("tenant1") != nil {
		t.Fatal("session registered without a valid certificate")
	}
}

// After the failure budget is spent, control connections from the same IP
// are dropped before the auth reply.
func TestControlAuthRateLimit(t *testing.T) {
	reg := newRegistry(limits{})
	replaced := testClientCert(t, "tenant1")
	controlLn, _ := startControl(t, reg, newFailLimiter(3, time.Minute), replaced, testClientCert(t, "tenant1"))

	for range 3 {
		if _, err := controlAuth(t, controlLn, `{"v":1}`, replaced); err != nil {
			t.Fatalf("expected an auth reply while under the limit: %v", err)
		}
	}
	if line, err := controlAuth(t, controlLn, `{"v":1}`, replaced); err == nil {
		t.Fatalf("expected a dropped connection over the limit, got %q", line)
	}
}

// The certificate CN is the identity: whatever tenant the auth line claims,
// the tunnel is the one of the tenant the certificate names.
func TestControlTenantFromCertificate(t *testing.T) {
	reg := newRegistry(limits{})
	cert1 := testClientCert(t, "tenant1")
	controlLn, _ := startControl(t, reg, testAuthLimiter(), cert1, testClientCert(t, "tenant2"))

	line, err := controlAuth(t, controlLn, `{"v":1,"tenant":"tenant2"}`, cert1)
	if err != nil || !strings.Contains(line, `"ok":true`) {
		t.Fatalf("auth refused for the tenant of the certificate: %q, %v", line, err)
	}
	waitForTunnel(t, reg, "tenant1")
	if reg.lookup("tenant2") != nil {
		t.Fatal("the certificate of tenant1 opened the tunnel of tenant2")
	}
}

// Only an Ed25519 key has an id, and a key without one must match nothing —
// not even a tenant that tenants.json does not know.
func TestKeyID(t *testing.T) {
	if id := keyID(testClientCert(t, "tenant1").Leaf); !validKeyID(id) {
		t.Fatalf("key id of an Ed25519 certificate = %q", id)
	}
	if id := keyID(testCert(t, "tenant1").Leaf); id != "" {
		t.Fatalf("key id of a P-256 certificate = %q, want none", id)
	}
}

// What deploy/pki.sh hands out has to be what control.go accepts, by the road
// a server takes: the key typed from the customer sheet gives the private key,
// the certificate was signed for it in advance, and the id printed next to it
// is what tenants.json holds.
func TestPKICertificateAccepted(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	pki := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("./deploy/pki.sh", args...)
		cmd.Env = append(os.Environ(), "PKI_DIR="+dir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("pki.sh %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	pki("init")
	sheet := pki("issue", "tenant1")

	typed := regexp.MustCompile(`(?m)^\s+((?:[A-Z2-7]{4} ){12}[A-Z2-7]{4})$`).FindStringSubmatch(sheet)
	if typed == nil {
		t.Fatalf("no key in the customer sheet:\n%s", sheet)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(typed[1], " ", ""))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("the key of the sheet is not a 32-byte seed: %v", err)
	}
	key := ed25519.NewKeyFromSeed(seed)

	pemBytes, err := os.ReadFile(filepath.Join(dir, "tenant1.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !key.Public().(ed25519.PublicKey).Equal(leaf.PublicKey) {
		t.Fatal("the certificate was not signed for the key of the sheet")
	}
	if !strings.Contains(sheet, keyID(leaf)) {
		t.Fatalf("the sheet does not print the key id %s:\n%s", keyID(leaf), sheet)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 4 {
		t.Fatalf("want ca.crt, ca.key, ca.srl and tenant1.crt only, got %v", entries)
	}

	pool, err := loadCertPool(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	reg := newRegistry(limits{})
	controlLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{testCert(t, "control.gw.test")},
		MinVersion:   tls.VersionTLS12,
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlLn.Close()
	store := testTenantStore(t, map[string]string{"tenant1": keyID(leaf)})
	go runControl(controlLn, store, reg, testAuthLimiter())

	clientCert := tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key}
	line, err := controlAuth(t, controlLn, `{"v":1}`, clientCert)
	if err != nil {
		t.Fatalf("the control plane refused a certificate issued by pki.sh: %v", err)
	}
	if !strings.Contains(line, `"ok":true`) {
		t.Fatalf("auth refused: %q", line)
	}
}

func TestCheckControlMTLS(t *testing.T) {
	for v, bad := range map[string]bool{"": false, "require": false, "off": true, "transition": true, "yes": true} {
		if err := checkControlMTLS(v); (err != nil) != bad {
			t.Errorf("checkControlMTLS(%q) = %v, want refused = %v", v, err, bad)
		}
	}
}

// Reloading the store closes the tunnels it no longer allows — tenant removed,
// or bound to another key — and those only.
func TestTenantReloadRevokes(t *testing.T) {
	keyA, keyB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	store := testTenantStore(t, map[string]string{"keep": keyA, "gone": keyA, "rekeyed": keyA})
	reg := newRegistry(limits{})

	mk := func() *yamux.Session {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		go yamux.Client(b, yamuxConfig())
		sess, err := yamux.Server(a, yamuxConfig())
		if err != nil {
			t.Fatal(err)
		}
		return sess
	}
	keep, gone, rekeyed := mk(), mk(), mk()
	reg.register("keep", keep, keyA)
	reg.register("gone", gone, keyA)
	reg.register("rekeyed", rekeyed, keyA)

	raw, _ := json.Marshal(map[string]string{"keep": keyA, "rekeyed": keyB})
	if err := os.WriteFile(store.path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store.apply(reg, t.Logf)
	if reg.lookup("keep") != keep {
		t.Fatal("kept tenant lost its tunnel")
	}
	for name, sess := range map[string]*yamux.Session{"gone": gone, "rekeyed": rekeyed} {
		if reg.lookup(name) != nil {
			t.Fatalf("%s: revoked tenant still routed", name)
		}
		select {
		case <-sess.CloseChan():
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: revoked session not closed", name)
		}
	}

	// neither a file still holding tokens nor one emptied by accident is
	// taken: the running set stays
	for _, broken := range []string{"", "null", `{"keep":`} {
		if err := os.WriteFile(store.path, []byte(broken), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := store.reload(); err == nil {
			t.Fatalf("tenants file %q was accepted", broken)
		}
	}
	if err := os.WriteFile(store.path, []byte(`{"keep":"un-ancien-jeton"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.reload(); err == nil {
		t.Fatal("a tenants file without key ids was accepted")
	}
	if store.key("rekeyed") != keyB {
		t.Fatal("a refused file changed the running set")
	}

	// {} is how the last tenant is revoked
	if err := os.WriteFile(store.path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	store.apply(reg, t.Logf)
	if reg.lookup("keep") != nil || store.has("keep") {
		t.Fatal("the last tenant survived an empty tenants file")
	}
}

func TestStreamCap(t *testing.T) {
	reg := newRegistry(limits{MaxStreams: 2})
	if !reg.acquireStream("t") || !reg.acquireStream("t") {
		t.Fatal("streams under the cap refused")
	}
	if reg.acquireStream("t") {
		t.Fatal("stream over the cap accepted")
	}
	if n := reg.snapshot()["t"].Refused; n != 1 {
		t.Fatalf("refused = %d, want 1", n)
	}
	reg.releaseStream("t")
	if !reg.acquireStream("t") {
		t.Fatal("released slot not reusable")
	}
}

func TestHealthEndpoint(t *testing.T) {
	reg := newRegistry(limits{})
	reg.acquireStream("t1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(struct {
			Status  string                 `json:"status"`
			Tenants map[string]tenantStats `json:"tenants"`
		}{"ok", reg.snapshot()})
	}))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Status  string                 `json:"status"`
		Tenants map[string]tenantStats `json:"tenants"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "ok" || out.Tenants["t1"].ActiveStreams != 1 {
		t.Fatalf("healthz = %+v", out)
	}
}

// startFakePrivateGateway mimics a private gateway: auth, yamux, PROXY
// v2 header, TLS termination, then a canned HTTP response.
func startFakePrivateGateway(t *testing.T, controlAddr string, client, cert tls.Certificate, hdr chan<- string) {
	t.Helper()
	conn, err := tls.Dial("tcp", controlAddr, &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{client}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(`{"v":1}` + "\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, `"ok":true`) {
		t.Fatalf("auth reply %q: %v", line, err)
	}
	// the server may already be sending yamux frames: keep the bufio bytes
	sess, err := yamux.Client(&bufferedConn{Conn: conn, r: br}, yamuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })

	go func() {
		for {
			stream, err := sess.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sbr := bufio.NewReader(c)
				line, err := readProxyV2Header(sbr)
				if err != nil {
					return
				}
				select {
				case hdr <- line:
				default:
				}
				tc := tls.Server(&bufferedConn{Conn: c, r: sbr}, &tls.Config{Certificates: []tls.Certificate{cert}})
				if err := tc.Handshake(); err != nil {
					return
				}
				if _, err := http.ReadRequest(bufio.NewReader(tc)); err != nil {
					return
				}
				body := "hello from tenant1"
				fmt.Fprintf(tc, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(stream)
		}
	}()
}

// readProxyV2Header consumes a PROXY v2 header and formats the address block
// as "TCP4 src dst sport dport" for assertions.
func readProxyV2Header(r io.Reader) (string, error) {
	fixed := make([]byte, 16)
	if _, err := io.ReadFull(r, fixed); err != nil {
		return "", err
	}
	if string(fixed[:12]) != string(proxyV2Sig) || fixed[12] != 0x21 {
		return "", fmt.Errorf("bad v2 header % x", fixed)
	}
	addr := make([]byte, binary.BigEndian.Uint16(fixed[14:16]))
	if _, err := io.ReadFull(r, addr); err != nil {
		return "", err
	}
	switch fixed[13] {
	case 0x11:
		return fmt.Sprintf("TCP4 %s %s %d %d", net.IP(addr[0:4]), net.IP(addr[4:8]),
			binary.BigEndian.Uint16(addr[8:10]), binary.BigEndian.Uint16(addr[10:12])), nil
	case 0x21:
		return fmt.Sprintf("TCP6 %s %s %d %d", net.IP(addr[0:16]), net.IP(addr[16:32]),
			binary.BigEndian.Uint16(addr[32:34]), binary.BigEndian.Uint16(addr[34:36])), nil
	}
	return "", fmt.Errorf("unknown family %#x", fixed[13])
}

func waitForTunnel(t *testing.T, reg *registry, tenant string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for reg.lookup(tenant) == nil {
		if time.Now().After(deadline) {
			t.Fatal("tunnel never registered")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestFailLimiterIPv6Prefix(t *testing.T) {
	lim := newFailLimiter(2, time.Minute)
	addr1 := &net.TCPAddr{IP: net.ParseIP("2001:db8:abcd:1234::1"), Port: 1111}
	addr2 := &net.TCPAddr{IP: net.ParseIP("2001:db8:abcd:1234::2"), Port: 2222}
	if lim.blocked(addr1) {
		t.Fatal("initially blocked")
	}
	lim.fail(addr1)
	if lim.blocked(addr2) {
		t.Fatal("blocked after 1 failure")
	}
	lim.fail(addr2)
	if !lim.blocked(addr1) || !lim.blocked(addr2) {
		t.Fatal("same /64 IPv6 prefix not blocked after 2 failures")
	}
}

func TestFailLimiterSweep(t *testing.T) {
	lim := newFailLimiter(5, 50*time.Millisecond)
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234}
	lim.fail(addr)
	time.Sleep(100 * time.Millisecond)
	lim.sweep(time.Now())
	lim.mu.Lock()
	count := len(lim.fails)
	lim.mu.Unlock()
	if count != 0 {
		t.Fatalf("expected sweep to purge expired entries, got %d", count)
	}
}

func TestTenantValidation(t *testing.T) {
	valid := []string{"tenant1", "tenant-alpha", "t1", "valid-123-name"}
	invalid := []string{"", "Tenant1", "tenant.with.dot", "-starts-with-dash", "ends-with-dash-", "with space", "with_underscore"}
	for _, id := range valid {
		if !validTenantID(id) {
			t.Errorf("expected valid for %q", id)
		}
	}
	for _, id := range invalid {
		if validTenantID(id) {
			t.Errorf("expected invalid for %q", id)
		}
	}
}

func TestRedirectHardening(t *testing.T) {
	srv := httptest.NewServer(redirectHandler("citadelle-tls.fr"))
	defer srv.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	tests := []struct {
		host, uri, wantLoc string
	}{
		{"tenant1.citadelle-tls.fr", "/test?a=b", "https://tenant1.citadelle-tls.fr/test?a=b"},
		{"tenant1.citadelle-tls.fr.", "/foo", "https://tenant1.citadelle-tls.fr/foo"},
		{"citadelle-tls.fr", "/path", "https://citadelle-tls.fr/path"},
		{"evil.com", "/path", "https://citadelle-tls.fr/"},
		{"a.b.citadelle-tls.fr", "/path", "https://citadelle-tls.fr/"},
		{".citadelle-tls.fr", "/path", "https://citadelle-tls.fr/"},
	}

	for _, tt := range tests {
		req, _ := http.NewRequest("GET", srv.URL+tt.uri, nil)
		req.Host = tt.host
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request for host %q failed: %v", tt.host, err)
		}
		resp.Body.Close()
		loc := resp.Header.Get("Location")
		if loc != tt.wantLoc {
			t.Errorf("host %q location = %q, want %q", tt.host, loc, tt.wantLoc)
		}
	}
}

// An upload sends for minutes while the server answers nothing, a download
// the reverse: one silent direction is not an idle connection.
func TestPipeOneWayTransferOutlivesIdleTimeout(t *testing.T) {
	defer func(d time.Duration) { pipeIdleTimeout = d }(pipeIdleTimeout)
	pipeIdleTimeout = 300 * time.Millisecond

	client, proxyIn := net.Pipe()
	proxyOut, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		pipe(proxyIn, proxyOut, nil)
		close(done)
	}()
	go io.Copy(io.Discard, server)

	for start := time.Now(); time.Since(start) < 3*pipeIdleTimeout; time.Sleep(50 * time.Millisecond) {
		client.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := client.Write([]byte("chunk")); err != nil {
			t.Fatalf("transfer cut after %v: %v", time.Since(start).Round(10*time.Millisecond), err)
		}
	}

	// once both directions are silent the connection is still reaped
	select {
	case <-done:
	case <-time.After(3 * pipeIdleTimeout):
		t.Fatal("idle connection never closed")
	}
}

// A refusal reaches the client as a TLS alert, not as a closed socket: no
// server behind one of our names, or no stream left in its tunnel. A name
// that is not ours gets no answer at all.
func TestRefusalIsATLSAlert(t *testing.T) {
	const domain = "gw.test"
	reg := newRegistry(limits{MaxStreams: 1})
	clientCert := testClientCert(t, "tenant1")
	controlLn, tenants := startControl(t, reg, testAuthLimiter(), clientCert)
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()
	go runProxy(proxyLn, domain, reg, tenants, turnRelay{})
	// the journal throttles that line per tenant, across tests
	t.Cleanup(func() {
		noTunnelMu.Lock()
		delete(noTunnelLast, "tenant1")
		noTunnelMu.Unlock()
	})

	handshake := func(name string) error {
		c, err := net.Dial("tcp", proxyLn.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		tc := tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true})
		tc.SetDeadline(time.Now().Add(3 * time.Second))
		return tc.Handshake()
	}
	// crypto/tls does not export the alert it received, only its text
	alertOf := func(err error) int {
		switch {
		case err == nil:
			return -1
		case strings.Contains(err.Error(), "tls: unrecognized name"):
			return alertNoTunnel
		case strings.Contains(err.Error(), "tls: internal error"):
			return alertTunnelBusy
		}
		return 0
	}

	// declared or not, a name of ours without a tunnel answers the same
	for _, name := range []string{"tenant1.gw.test", "nope.gw.test", "partage-tenant1.gw.test"} {
		if got := alertOf(handshake(name)); got != alertNoTunnel {
			t.Fatalf("%s: alert %d, want %d", name, got, alertNoTunnel)
		}
	}
	if err := handshake("tenant1.elsewhere.test"); alertOf(err) != 0 {
		t.Fatalf("a name that is not ours got an answer: %v", err)
	}

	startFakePrivateGateway(t, controlLn.Addr().String(), clientCert, testCert(t, "tenant1.gw.test"), make(chan string, 1))
	waitForTunnel(t, reg, "tenant1")
	reg.acquireStream("tenant1")
	if got := alertOf(handshake("tenant1.gw.test")); got != alertTunnelBusy {
		t.Fatalf("tunnel at its cap: alert %d, want %d", got, alertTunnelBusy)
	}
}

// The handshake settles a protocol version and tells the tenant its stream
// cap; a private gateway that announces no version is served as before.
func TestControlReplyVersionAndLimits(t *testing.T) {
	reg := newRegistry(limits{MaxStreams: 128})
	clientCert := testClientCert(t, "tenant1")
	controlLn, _ := startControl(t, reg, testAuthLimiter(), clientCert)

	for announced, retained := range map[string]int{`{}`: 0, `{"v":1}`: 1, `{"v":7}`: protocolVersion} {
		line, err := controlAuth(t, controlLn, announced, clientCert)
		if err != nil {
			t.Fatal(err)
		}
		var reply authReply
		if err := json.Unmarshal([]byte(line), &reply); err != nil {
			t.Fatal(err)
		}
		if !reply.OK || reply.V != retained || reply.MaxStreams != 128 {
			t.Fatalf("announced %q: reply %+v, want v=%d maxStreams=128", announced, reply, retained)
		}
	}
}

func TestPipeWriteDeadline(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	done := make(chan struct{})
	go func() {
		pipe(c1, c2, nil)
		close(done)
	}()

	time.Sleep(20 * time.Millisecond)
	c1.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipe did not terminate cleanly on close")
	}
}

// The visio relay's name is routed to the relay, bytes verbatim: the relay
// terminates its own TLS, and a tenant of the same label never sees it.
func TestTurnRelayRoutedBySNI(t *testing.T) {
	const domain = "gw.test"
	relayLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{testCert(t, "turn.gw.test")},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer relayLn.Close()
	go func() {
		for {
			conn, err := relayLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()
	turn := turnRelay{host: "turn.gw.test", addr: relayLn.Addr().String()}
	go runProxy(proxyLn, domain, newRegistry(limits{}), testTenantStore(t, map[string]string{"turn": testKey}), turn)

	conn, err := tls.Dial("tcp", proxyLn.Addr().String(),
		&tls.Config{ServerName: "TURN.gw.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("handshake with the relay through the proxy: %v", err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().PeerCertificates[0].Subject.CommonName; got != "turn.gw.test" {
		t.Fatalf("TLS terminated by %q, want the relay itself", got)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("allocate")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 8)
	if _, err := io.ReadFull(conn, echo); err != nil || string(echo) != "allocate" {
		t.Fatalf("relay answered %q, %v", echo, err)
	}
}
