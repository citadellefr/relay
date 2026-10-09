package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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

// Full path: https client → SNI proxy → tunnel → fake private gateway that
// terminates TLS and answers HTTP.
func TestEndToEnd(t *testing.T) {
	const domain = "gw.test"
	tenants := testTenantStore(t, map[string]string{"tenant1": "sekrit"})
	reg := newRegistry(limits{})

	controlLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{testCert(t, "control.gw.test")},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlLn.Close()
	go runControl(controlLn, tenants, reg, testAuthLimiter(), authToken)

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()
	go runProxy(proxyLn, domain, reg, tenants, turnRelay{})

	tenantCert := testCert(t, "tenant1.gw.test")
	proxyHdr := make(chan string, 1)
	startFakePrivateGateway(t, controlLn.Addr().String(), tenantCert, proxyHdr)

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

func TestControlAuthFailure(t *testing.T) {
	reg := newRegistry(limits{})
	controlLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{testCert(t, "control.gw.test")},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlLn.Close()
	go runControl(controlLn, testTenantStore(t, map[string]string{"tenant1": "sekrit"}), reg, testAuthLimiter(), authToken)

	conn, err := tls.Dial("tcp", controlLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, `{"tenant":"tenant1","token":"wrong"}`+"\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(line, `"ok":true`) {
		t.Fatalf("auth accepted with a wrong token: %q", line)
	}
	if reg.lookup("tenant1") != nil {
		t.Fatal("session registered despite failed auth")
	}
}

// After the failure budget is spent, control connections from the same IP
// are dropped before the auth reply.
func TestControlAuthRateLimit(t *testing.T) {
	reg := newRegistry(limits{})
	controlLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{testCert(t, "control.gw.test")},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlLn.Close()
	go runControl(controlLn, testTenantStore(t, map[string]string{"tenant1": "sekrit"}), reg, newFailLimiter(3, time.Minute), authToken)

	attempt := func() (string, error) {
		conn, err := tls.Dial("tcp", controlLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return "", err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(conn, `{"tenant":"tenant1","token":"wrong"}`+"\n")
		return bufio.NewReader(conn).ReadString('\n')
	}
	for range 3 {
		if _, err := attempt(); err != nil {
			t.Fatalf("expected an auth reply while under the limit: %v", err)
		}
	}
	if line, err := attempt(); err == nil {
		t.Fatalf("expected a dropped connection over the limit, got %q", line)
	}
}

// With mTLS the client certificate CN is the identity: the token is ignored
// and claiming another tenant than the CN is refused.
func TestControlMTLS(t *testing.T) {
	clientCert := testClientCert(t, "tenant1")
	pool := x509.NewCertPool()
	pool.AddCert(clientCert.Leaf)

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
	store := testTenantStore(t, map[string]string{"tenant1": "unused", "tenant2": "unused"})
	go runControl(controlLn, store, reg, testAuthLimiter(), authMTLS)

	attempt := func(tenant string) string {
		conn, err := tls.Dial("tcp", controlLn.Addr().String(), &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{clientCert},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(conn, `{"tenant":"%s","token":"ignored"}`+"\n", tenant)
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return line
	}
	if line := attempt("tenant1"); !strings.Contains(line, `"ok":true`) {
		t.Fatalf("mTLS auth refused for the CN tenant: %q", line)
	}
	if line := attempt("tenant2"); strings.Contains(line, `"ok":true`) {
		t.Fatalf("mTLS auth accepted for a tenant not matching the CN: %q", line)
	}
}

// The migration state: the fleet is converted one gateway at a time, so a
// certificate is used when there is one and the token still works when there
// is none. What must not happen is a certificate opening a door it does not
// name.
func TestControlMTLSTransition(t *testing.T) {
	clientCert := testClientCert(t, "tenant1")
	pool := x509.NewCertPool()
	pool.AddCert(clientCert.Leaf)

	reg := newRegistry(limits{})
	controlLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{testCert(t, "control.gw.test")},
		MinVersion:   tls.VersionTLS12,
		ClientCAs:    pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlLn.Close()
	store := testTenantStore(t, map[string]string{"tenant1": "token1", "tenant2": "token2"})
	go runControl(controlLn, store, reg, testAuthLimiter(), authTransition)

	attempt := func(certs []tls.Certificate, tenant, token string) string {
		conn, err := tls.Dial("tcp", controlLn.Addr().String(), &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       certs,
		})
		if err != nil {
			t.Fatal(err)
		}
		// kept open: the tunnel has to still be there to be looked at
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(conn, `{"tenant":%q,"token":%q}`+"\n", tenant, token)
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return line
	}
	migrated := []tls.Certificate{clientCert}

	// already migrated: the certificate decides and the token is not looked at
	if line := attempt(migrated, "tenant1", "wrong"); !strings.Contains(line, `"ok":true`) {
		t.Fatalf("certificate refused in transition: %q", line)
	}
	waitForTunnel(t, reg, "tenant1")
	if got := reg.snapshot()["tenant1"].Auth; got != "mtls" {
		t.Fatalf("tenant1 authenticated by %q, want mtls", got)
	}

	// not migrated yet: no certificate, the token still gets it in
	if line := attempt(nil, "tenant2", "token2"); !strings.Contains(line, `"ok":true`) {
		t.Fatalf("token refused in transition: %q", line)
	}
	waitForTunnel(t, reg, "tenant2")
	if got := reg.snapshot()["tenant2"].Auth; got != "token" {
		t.Fatalf("tenant2 authenticated by %q, want token", got)
	}

	// a certificate claiming another tenant stays refused even with that
	// tenant's token: presenting one is a commitment, not an option
	if line := attempt(migrated, "tenant2", "token2"); strings.Contains(line, `"ok":true`) {
		t.Fatalf("certificate of tenant1 accepted as tenant2: %q", line)
	}
}

// What deploy/pki.sh issues has to be what control.go accepts: a key usage or
// a CA shape the TLS layer refuses would only show up on the VPS, the day the
// fleet is switched over.
func TestPKICertificateAccepted(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	pki := func(args ...string) {
		t.Helper()
		cmd := exec.Command("./deploy/pki.sh", args...)
		cmd.Env = append(os.Environ(), "PKI_DIR="+dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("pki.sh %v: %v\n%s", args, err, out)
		}
	}
	pki("init")
	pki("issue", "tenant1")

	clientCert, err := tls.LoadX509KeyPair(filepath.Join(dir, "tenant1.crt"), filepath.Join(dir, "tenant1.key"))
	if err != nil {
		t.Fatal(err)
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
	store := testTenantStore(t, map[string]string{"tenant1": "unused"})
	go runControl(controlLn, store, reg, testAuthLimiter(), authMTLS)

	conn, err := tls.Dial("tcp", controlLn.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{clientCert},
	})
	if err != nil {
		t.Fatalf("the control plane refused a certificate issued by pki.sh: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, `{"tenant":"tenant1","token":""}`+"\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, `"ok":true`) {
		t.Fatalf("auth refused: %q", line)
	}
}

func TestControlAuthMode(t *testing.T) {
	cases := []struct {
		env, ca string
		want    authMode
		bad     bool
	}{
		{"", "", authToken, false},
		{"", "ca.pem", authMTLS, false}, // unchanged from before CONTROL_MTLS existed
		{"off", "", authToken, false},
		{"transition", "ca.pem", authTransition, false},
		{"require", "ca.pem", authMTLS, false},
		{"require", "", 0, true}, // nothing to verify certificates against
		{"off", "ca.pem", 0, true},
		{"yes", "ca.pem", 0, true},
	}
	for _, c := range cases {
		mode, err := controlAuthMode(c.env, c.ca)
		if (err != nil) != c.bad {
			t.Errorf("controlAuthMode(%q, %q) error = %v, want bad = %v", c.env, c.ca, err, c.bad)
			continue
		}
		if err == nil && mode != c.want {
			t.Errorf("controlAuthMode(%q, %q) = %v, want %v", c.env, c.ca, mode, c.want)
		}
	}
}

// Reloading the store closes the tunnels of removed tenants only.
func TestTenantReloadRevokes(t *testing.T) {
	store := testTenantStore(t, map[string]string{"keep": "a", "gone": "b"})
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
	keep, gone := mk(), mk()
	reg.register("keep", keep, "token")
	reg.register("gone", gone, "token")

	if err := os.WriteFile(store.path, []byte(`{"keep":"a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.reload(); err != nil {
		t.Fatal(err)
	}
	if n := reg.closeRemoved(store.ids()); n != 1 {
		t.Fatalf("closeRemoved = %d, want 1", n)
	}
	if reg.lookup("keep") != keep {
		t.Fatal("kept tenant lost its tunnel")
	}
	if reg.lookup("gone") != nil {
		t.Fatal("removed tenant still routed")
	}
	select {
	case <-gone.CloseChan():
	case <-time.After(2 * time.Second):
		t.Fatal("removed tenant session not closed")
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
func startFakePrivateGateway(t *testing.T, controlAddr string, cert tls.Certificate, hdr chan<- string) {
	t.Helper()
	conn, err := tls.Dial("tcp", controlAddr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(`{"tenant":"tenant1","token":"sekrit"}` + "\n")); err != nil {
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

func TestControlMTLS_DNSNames(t *testing.T) {
	cert := testClientCertSAN(t, "tenant-san")
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)

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
	store := testTenantStore(t, map[string]string{"tenant-san": ""})
	go runControl(controlLn, store, reg, testAuthLimiter(), authMTLS)

	conn, err := tls.Dial("tcp", controlLn.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, `{"tenant":"tenant-san","token":""}`+"\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, `"ok":true`) {
		t.Fatalf("mTLS with SAN DNS name failed: %q", line)
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
	go runProxy(proxyLn, domain, newRegistry(limits{}), testTenantStore(t, map[string]string{"turn": "sekrit"}), turn)

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
