package main

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/time/rate"
)

// runProxy accepts raw TLS connections from clients, routes each one to the
// tenant tunnel matching its SNI and copies bytes both ways. The tenant store
// is only read to decide what deserves a log line;
// routing itself is the registry's business.
func runProxy(ln net.Listener, baseDomain string, reg *registry, tenants *tenantStore, turn turnRelay) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleClient(conn, baseDomain, reg, tenants, turn)
	}
}

// turnRelay is the one name that is not a tenant's: the visio relay, reached
// over TLS on this port by the clients whose network lets nothing else out —
// a company firewall, a hotel's wifi. Routed like a tenant, bytes verbatim:
// the relay terminates its own TLS at addr. An empty host routes nothing.
type turnRelay struct {
	host string
	addr string
}

func (t turnRelay) serve(conn net.Conn, peeked []byte) {
	relay, err := net.DialTimeout("tcp", t.addr, 10*time.Second)
	if err != nil {
		log.Printf("proxy: visio relay unreachable at %s: %v", t.addr, err)
		return
	}
	defer relay.Close()
	if _, err := relay.Write(peeked); err != nil {
		return
	}
	pipe(conn, relay, nil)
}

var (
	noTunnelMu   sync.Mutex
	noTunnelLast = make(map[string]time.Time)
)

func logNoTunnel(tenant string, addr net.Addr) {
	noTunnelMu.Lock()
	if time.Since(noTunnelLast[tenant]) >= 5*time.Minute {
		noTunnelLast[tenant] = time.Now()
		noTunnelMu.Unlock()
		log.Printf("proxy: no tunnel for %q (%s)", tenant, logAddr(addr))
		return
	}
	noTunnelMu.Unlock()
}

// pendingHellos bounds the connections that have not sent their ClientHello
// yet: each one holds a goroutine and a descriptor for up to ten seconds, and
// nothing else limits how many a single source opens.
var pendingHellos = make(chan struct{}, 4096)

// A refusal is told to the client as a TLS alert, the one thing this machine
// can say without a certificate: a closed socket reads as "no network", and
// the client could not tell a server that is off from a link that is down.
// Alerts sent before the handshake are in the clear by design — nothing is
// terminated here.
const (
	alertTunnelBusy = 80  // internal_error: the tunnel is there, not a free stream
	alertNoTunnel   = 112 // unrecognized_name: no server behind this name now
)

func refuseTLS(conn net.Conn, alert byte) {
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, alert})
}

func handleClient(conn net.Conn, baseDomain string, reg *registry, tenants *tenantStore, turn turnRelay) {
	defer conn.Close()
	select {
	case pendingHellos <- struct{}{}:
	default:
		return
	}
	sni, peeked, err := peekClientHello(conn, 10*time.Second)
	<-pendingHellos
	if err != nil {
		return
	}
	if turn.host != "" && strings.EqualFold(sni, turn.host) {
		turn.serve(conn, peeked)
		return
	}
	tenant, sess := resolveTenant(sni, baseDomain, reg)
	if sess == nil {
		// any name of ours gets the same answer, declared tenant or not: the
		// alert must not tell which names exist. Other names get nothing.
		if knownTenant(tenant, tenants) {
			logNoTunnel(tenant, conn.RemoteAddr())
		}
		if tenant != "" {
			refuseTLS(conn, alertNoTunnel)
		}
		return
	}
	if !reg.acquireStream(tenant) {
		refuseTLS(conn, alertTunnelBusy)
		log.Printf("proxy: stream cap reached for %q, dropping %s", tenant, logAddr(conn.RemoteAddr()))
		return
	}
	defer reg.releaseStream(tenant)
	stream, err := sess.Open()
	if err != nil {
		refuseTLS(conn, alertTunnelBusy)
		return
	}
	defer stream.Close()
	// one write, one yamux frame: the private side reads both together
	if _, err := stream.Write(append(proxyHeader(conn), peeked...)); err != nil {
		return
	}
	pipe(conn, framedStream{stream}, reg.bandwidth(tenant))
}

// tenantFromSNI accepts exactly one label before the base domain.
func tenantFromSNI(sni, baseDomain string) (string, bool) {
	tenant, found := strings.CutSuffix(strings.ToLower(sni), "."+strings.ToLower(baseDomain))
	if !found || tenant == "" || strings.Contains(tenant, ".") {
		return "", false
	}
	return tenant, true
}

const sharePrefix = "partage-"

// resolveTenant maps an SNI to a live tunnel.
func resolveTenant(sni, baseDomain string, reg *registry) (string, *yamux.Session) {
	label, ok := tenantFromSNI(sni, baseDomain)
	if !ok {
		return "", nil
	}
	if sess := reg.lookup(label); sess != nil {
		return label, sess
	}
	if tenant, found := strings.CutPrefix(label, sharePrefix); found && tenant != "" {
		if sess := reg.lookup(tenant); sess != nil {
			return tenant, sess
		}
	}
	return label, nil
}

func knownTenant(label string, tenants *tenantStore) bool {
	if label == "" || tenants == nil {
		return false
	}
	if tenants.has(label) {
		return true
	}
	base, found := strings.CutPrefix(label, sharePrefix)
	return found && tenants.has(base)
}

var proxyV2Sig = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

func proxyHeader(c net.Conn) []byte {
	src, sok := c.RemoteAddr().(*net.TCPAddr)
	dst, dok := c.LocalAddr().(*net.TCPAddr)
	hdr := make([]byte, 0, 52)
	hdr = append(hdr, proxyV2Sig...)
	if !sok || !dok {
		return append(hdr, 0x20, 0x00, 0x00, 0x00)
	}
	srcIP, dstIP := src.IP.To4(), dst.IP.To4()
	fam := byte(0x11)
	if srcIP == nil || dstIP == nil {
		srcIP, dstIP = src.IP.To16(), dst.IP.To16()
		fam = 0x21
	}
	if srcIP == nil || dstIP == nil {
		return append(hdr, 0x20, 0x00, 0x00, 0x00)
	}
	hdr = append(hdr, 0x21, fam)
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(2*len(srcIP)+4))
	hdr = append(hdr, srcIP...)
	hdr = append(hdr, dstIP...)
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(src.Port))
	return binary.BigEndian.AppendUint16(hdr, uint16(dst.Port))
}

// A variable only so that tests do not wait five minutes.
var pipeIdleTimeout = 5 * time.Minute

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

func pipe(a, b net.Conn, lim *rate.Limiter) {
	done := make(chan struct{}, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// idleness is judged on both directions at once: an upload sends for
	// minutes while the other side says nothing, and a download the reverse
	var lastByte atomic.Int64
	lastByte.Store(time.Now().UnixNano())
	cp := func(dst, src net.Conn) {
		bufPtr := copyBufPool.Get().(*[]byte)
		buf := *bufPtr
		defer copyBufPool.Put(bufPtr)
		for {
			quietSince := time.Unix(0, lastByte.Load())
			src.SetReadDeadline(quietSince.Add(pipeIdleTimeout))
			n, err := src.Read(buf)
			if n > 0 {
				lastByte.Store(time.Now().UnixNano())
				if lim != nil {
					if werr := lim.WaitN(ctx, n); werr != nil {
						break
					}
				}
				dst.SetWriteDeadline(time.Now().Add(pipeIdleTimeout))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() && lastByte.Load() != quietSince.UnixNano() {
				continue
			}
			if err != nil {
				break
			}
		}
		cancel()
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	a.Close()
	b.Close()
	<-done
}
