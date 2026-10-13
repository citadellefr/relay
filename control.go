package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// protocolVersion is the newest tunnel protocol spoken here. A private gateway
// announces its own and gets back the one retained, the lower of the two; one
// that announces none predates versions and is served as before.
const protocolVersion = 1

// authRequest names no tenant: the client certificate does.
type authRequest struct {
	V int `json:"v"`
}

// authReply carries no reason beyond the refusal itself: saying whether the
// tenant exists would hand an unauthenticated peer the list of tenants.
type authReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	V     int    `json:"v,omitempty"`
	// concurrent connections this tenant may hold, 0 = unlimited
	MaxStreams int `json:"maxStreams,omitempty"`
}

// runControl accepts the persistent connections opened by private gateways:
// one JSON auth line, then the connection becomes a yamux session used to
// reach the tenant. The listener is TLS and requires a client certificate,
// already verified against the tunnel CA when the line is read: it carries the
// tenant identity.
func runControl(ln net.Listener, tenants *tenantStore, reg *registry, authLim *failLimiter) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleControl(conn, tenants, reg, authLim)
	}
}

func handleControl(conn net.Conn, tenants *tenantStore, reg *registry, authLim *failLimiter) {
	if authLim.blocked(conn.RemoteAddr()) {
		conn.Close()
		return
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(conn, 4096)
	// ReadSlice caps the line at the buffer size — ReadBytes would buffer
	// whatever a client streams without a newline (a real auth line is tiny)
	line, err := br.ReadSlice('\n')
	if err != nil {
		authLim.fail(conn.RemoteAddr())
		conn.Close()
		return
	}
	var req authRequest
	if err := json.Unmarshal(line, &req); err != nil {
		authLim.fail(conn.RemoteAddr())
		conn.Close()
		return
	}
	tenant, key := authenticate(conn, tenants)
	if key == "" {
		writeReply(conn, authReply{Error: "auth failed"})
		// full address on purpose: this is the security journal of the control
		// plane, and host-level banning reads these lines
		log.Printf("control: auth failed for %q from %s", tenant, conn.RemoteAddr())
		authLim.fail(conn.RemoteAddr())
		conn.Close()
		return
	}
	reply := authReply{OK: true, V: min(max(req.V, 0), protocolVersion), MaxStreams: reg.lim.MaxStreams}
	if err := writeReply(conn, reply); err != nil {
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{})
	if tc, ok := conn.(*tls.Conn); ok {
		boundSendQueue(tc)
		watchPeer(tc)
	}

	// the private gateway only starts yamux after reading the reply, but be
	// safe with anything the bufio reader may already hold
	bc := &bufferedConn{Conn: conn, r: br}
	sess, err := yamux.Server(bc, yamuxConfig())
	if err != nil {
		conn.Close()
		return
	}
	reg.register(tenant, sess, key)
	// a revocation that landed between the check and the registration would
	// otherwise leave this tunnel standing until the next reload
	if tenants.key(tenant) != key {
		sess.Close()
	}
	log.Printf("control: tenant %q connected from %s", tenant, conn.RemoteAddr())
	go measureRTT(sess, func(rtt time.Duration) { reg.setRTT(tenant, sess, rtt) })
	<-sess.CloseChan()
	cause := dropCause(bc.err())
	reg.unregister(tenant, sess, cause)
	log.Printf("control: tenant %q disconnected (%s)", tenant, cause)
}

// How often a live session is pinged, for /healthz only: a slow answer is a
// busy link, not a dead one, and closes nothing. A variable for the tests.
var rttInterval = time.Minute

// How long a frame may wait to be sent, and a ping to be answered.
const writeTimeout = 15 * time.Second

func measureRTT(sess *yamux.Session, record func(time.Duration)) {
	t := time.NewTicker(rttInterval)
	defer t.Stop()
	for {
		select {
		case <-sess.CloseChan():
			return
		case <-t.C:
		}
		rtt, err := sess.Ping()
		if errors.Is(err, yamux.ErrTimeout) {
			// no answer in writeTimeout: say at least that much
			rtt = writeTimeout
		} else if err != nil {
			continue
		}
		record(rtt)
	}
}

// dropCause names why a tunnel ended without the peer's address, which the
// connect line already gave: a closed connection is ours (replaced, revoked),
// EOF the peer's, a timeout the kernel's verdict on a silent peer.
func dropCause(err error) string {
	var op *net.OpError
	switch {
	case err == nil:
		return "closed"
	case errors.Is(err, net.ErrClosed):
		return "closed here"
	case errors.As(err, &op):
		return op.Err.Error()
	}
	return err.Error()
}

// authenticate returns the tenant the certificate names and the id of its
// key, the latter empty unless tenants.json binds that tenant to that key.
// The CA says who the peer is, the file says whether it is still welcome.
func authenticate(conn net.Conn, tenants *tenantStore) (tenant, key string) {
	certs := peerCertificates(conn)
	if len(certs) == 0 {
		return "", ""
	}
	tenant = certs[0].Subject.CommonName
	key = keyID(certs[0])
	if key == "" || tenants.key(tenant) != key {
		return tenant, ""
	}
	return tenant, key
}

// keyID is hex(SHA-256(public key)) of an Ed25519 certificate, "" for any
// other kind: the same id a server computes from its seed to fetch its
// certificate.
func keyID(cert *x509.Certificate) string {
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return ""
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func peerCertificates(conn net.Conn) []*x509.Certificate {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}
	return tc.ConnectionState().PeerCertificates
}

func writeReply(conn net.Conn, r authReply) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = conn.Write(append(raw, '\n'))
	return err
}

// The tunnel's liveness is the kernel's (watchPeer), not yamux's: its ping and
// its stream-open timer both wait behind the frames already queued, and closed
// sessions that were only busy.
func yamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = false
	cfg.StreamOpenTimeout = 0
	cfg.ConnectionWriteTimeout = writeTimeout
	// the receiver's window bounds the sender: 256 KiB held downloads to about
	// 5 MB/s at 50 ms. Worst case in memory is streams × window per tenant,
	// which TENANT_MAX_STREAMS bounds.
	cfg.MaxStreamWindowSize = 2 * 1024 * 1024
	return cfg
}

// bufferedConn replays bytes already sitting in the bufio reader, and keeps
// the first read error: the session ends on it.
type bufferedConn struct {
	net.Conn
	r       *bufio.Reader
	mu      sync.Mutex
	readErr error
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err != nil {
		c.mu.Lock()
		if c.readErr == nil {
			c.readErr = err
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *bufferedConn) err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readErr
}
