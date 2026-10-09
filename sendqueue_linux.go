package main

import (
	"crypto/tls"
	"net"
	"syscall"
)

// TCP_NOTSENT_LOWAT, which package syscall does not name.
const tcpNotSentLowat = 25

// How much the kernel may hold of the tunnel that it has not sent yet.
const tunnelUnsent = 32 * 1024

// boundSendQueue keeps the tunnel's socket from queueing megabytes ahead of
// the link. Every stream shares this one connection: with the kernel's default
// a transfer filling a slow uplink put seconds of its own data in front of
// everything else — a call's signalling answered late, and yamux's keepalive
// not at all, which closed the tunnel under everyone.
func boundSendQueue(conn *tls.Conn) {
	tcp, ok := conn.NetConn().(*net.TCPConn)
	if !ok {
		return
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpNotSentLowat, tunnelUnsent)
	})
}
