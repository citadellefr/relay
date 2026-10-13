package main

import (
	"crypto/tls"
	"net"
	"syscall"
)

// TCP_NOTSENT_LOWAT, which package syscall does not name.
const tcpNotSentLowat = 25

// How much the kernel may hold of a socket that it has not sent yet.
const tunnelUnsent = 32 * 1024

// boundSendQueue keeps a socket from queueing megabytes ahead of the link. The
// tunnel's carries every stream: with the kernel's default a transfer filling a
// slow uplink put seconds of its own data in front of everything else, a
// call's signalling among it. A TURN socket carries media, where what waits
// unsent is late audio.
func boundSendQueue(conn net.Conn) {
	if tc, ok := conn.(*tls.Conn); ok {
		conn = tc.NetConn()
	}
	tcp, ok := conn.(*net.TCPConn)
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
