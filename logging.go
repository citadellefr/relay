package main

import (
	"io"
	"log"
	"net"
	"os"
)

// Logging policy.
//
// Nominal client traffic on :443 leaves no trace at all: no SNI, no address,
// no per-connection volumetry. Only two anomalies are logged, and the client
// address is cut down to its network — enough to tell a scan from a badly
// configured site, not enough to follow one person. The control plane keeps
// full addresses: its peers are the tenants' own gateways and those lines are
// the security journal (auth failures feed the host-level banning).
var logFullAddr = os.Getenv("LOG_CLIENT_IP") == "full"

// discardLog silences the internal reports of the two http servers (:80 and
// /healthz): they carry the peer address and neither serves anything whose
// protocol errors are worth keeping.
var discardLog = log.New(io.Discard, "", 0)

func addrPolicy() string {
	if logFullAddr {
		return "full"
	}
	return "masked"
}

// logAddr renders a peer address for the journal, keeping only its /24 (or
// /48 in v6) and never the port, which identifies a connection on its own.
func logAddr(a net.Addr) string {
	if a == nil {
		return "?"
	}
	if logFullAddr {
		return a.String()
	}
	ip := net.ParseIP(ipOf(a))
	switch {
	case ip == nil:
		return "?"
	case ip.To4() != nil:
		return ip.To4().Mask(net.CIDRMask(24, 32)).String() + "/24"
	default:
		return ip.Mask(net.CIDRMask(48, 128)).String() + "/48"
	}
}
