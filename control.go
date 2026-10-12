package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
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
	}

	// the private gateway only starts yamux after reading the reply, but be
	// safe with anything the bufio reader may already hold
	sess, err := yamux.Server(&bufferedConn{Conn: conn, r: br}, yamuxConfig())
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
	<-sess.CloseChan()
	reg.unregister(tenant, sess)
	log.Printf("control: tenant %q disconnected", tenant)
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

// yamux keepalive doubles as the tunnel heartbeat: a dead session closes
// itself and the registry entry is cleaned up.
func yamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.ConnectionWriteTimeout = 15 * time.Second
	// don't let Open block on a frozen tunnel the keepalive hasn't caught yet
	cfg.StreamOpenTimeout = 15 * time.Second
	// the receiver's window bounds the sender: 256 KiB held downloads to about
	// 5 MB/s at 50 ms. Worst case in memory is streams × window per tenant,
	// which TENANT_MAX_STREAMS bounds.
	cfg.MaxStreamWindowSize = 2 * 1024 * 1024
	return cfg
}

// bufferedConn replays bytes already sitting in the bufio reader.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
