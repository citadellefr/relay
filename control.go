package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
)

type authRequest struct {
	Tenant string `json:"tenant"`
	Token  string `json:"token"`
}

type authReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// authMode is what the control plane accepts as proof of identity. The
// migration to mTLS cannot be a flag day — the private gateways are updated
// one at a time — hence the middle state, where a gateway that has no
// certificate yet still gets in with its token.
type authMode int

const (
	authToken      authMode = iota // tenants.json token, the historical default
	authTransition                 // client certificate if offered, token otherwise
	authMTLS                       // client certificate only
)

func (m authMode) String() string {
	switch m {
	case authTransition:
		return "transition"
	case authMTLS:
		return "mtls"
	}
	return "token"
}

// runControl accepts the persistent connections opened by private gateways:
// one JSON auth line, then the connection becomes a yamux session used to
// reach the tenant. The listener is expected to be TLS. Under mtls the client
// certificate (already verified by the TLS layer) carries the tenant identity
// and replaces the shared token.
func runControl(ln net.Listener, tenants *tenantStore, reg *registry, authLim *failLimiter, mode authMode) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleControl(conn, tenants, reg, authLim, mode)
	}
}

func handleControl(conn net.Conn, tenants *tenantStore, reg *registry, authLim *failLimiter, mode authMode) {
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
	method := authenticate(conn, tenants, req, mode)
	if method == "" {
		writeReply(conn, authReply{Error: "auth failed"})
		// full address on purpose: this is the security journal of the control
		// plane, and host-level banning reads these lines
		log.Printf("control: auth failed for %q from %s", req.Tenant, conn.RemoteAddr())
		authLim.fail(conn.RemoteAddr())
		conn.Close()
		return
	}
	if err := writeReply(conn, authReply{OK: true}); err != nil {
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{})

	// the private gateway only starts yamux after reading the reply, but be
	// safe with anything the bufio reader may already hold
	sess, err := yamux.Server(&bufferedConn{Conn: conn, r: br}, yamuxConfig())
	if err != nil {
		conn.Close()
		return
	}
	reg.register(req.Tenant, sess, method)
	// the method is logged so the journal answers the only question that
	// decides when the fleet can move to CONTROL_MTLS=require
	log.Printf("control: tenant %q connected from %s (auth %s)", req.Tenant, conn.RemoteAddr(), method)
	<-sess.CloseChan()
	reg.unregister(req.Tenant, sess)
	log.Printf("control: tenant %q disconnected", req.Tenant)
}

// authenticate returns how the peer proved who it is ("mtls" or "token"), or
// "" when it did not.
func authenticate(conn net.Conn, tenants *tenantStore, req authRequest, mode authMode) string {
	if mode != authToken {
		if certs := peerCertificates(conn); len(certs) > 0 {
			if certMatchesTenant(certs[0], req.Tenant) && tenants.has(req.Tenant) {
				return "mtls"
			}
			return ""
		}
		if mode == authMTLS {
			return ""
		}
	}
	want := tenants.token(req.Tenant)
	wantSum := sha256.Sum256([]byte(want))
	gotSum := sha256.Sum256([]byte(req.Token))
	match := subtle.ConstantTimeCompare(wantSum[:], gotSum[:]) == 1
	if match && want != "" {
		return "token"
	}
	return ""
}

func certMatchesTenant(cert *x509.Certificate, tenant string) bool {
	norm := strings.ToLower(tenant)
	if strings.ToLower(cert.Subject.CommonName) == norm {
		return true
	}
	for _, name := range cert.DNSNames {
		if strings.ToLower(name) == norm {
			return true
		}
	}
	return false
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
	return cfg
}

// bufferedConn replays bytes already sitting in the bufio reader.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
