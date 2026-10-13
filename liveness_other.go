//go:build !linux

package main

import (
	"crypto/tls"
	"net"
	"time"
)

// The gateway runs on Linux; elsewhere only TCP keepalive watches the peer.
func watchPeer(conn *tls.Conn) {
	if tcp, ok := conn.NetConn().(*net.TCPConn); ok {
		_ = tcp.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 10 * time.Second, Interval: 5 * time.Second, Count: 3})
	}
}
