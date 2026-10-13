package main

import (
	"crypto/tls"
	"net"
	"syscall"
	"time"
)

// TCP_USER_TIMEOUT, which package syscall does not name.
const tcpUserTimeout = 18

// How long the tunnel may go without the peer acknowledging what was sent to
// it, or answering on an idle link, before the kernel drops it.
const tunnelDeadAfter = 30 * time.Second

// watchPeer hands the tunnel's liveness to the kernel. yamux judged it by a
// ping that waited behind every frame queued before it: a transfer filling a
// slow uplink held the answer past 15 seconds and the session was closed under
// everyone while its data still flowed. Acknowledgements keep coming as long as
// the link carries anything.
func watchPeer(conn *tls.Conn) {
	tcp, ok := conn.NetConn().(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     10 * time.Second,
		Interval: 5 * time.Second,
		Count:    3,
	})
	raw, err := tcp.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout, int(tunnelDeadAfter.Milliseconds()))
	})
}
