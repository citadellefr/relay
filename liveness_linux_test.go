package main

import (
	"crypto/tls"
	"net"
	"syscall"
	"testing"
)

func TestWatchPeerHandsLivenessToTheKernel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	watchPeer(tls.Client(raw, &tls.Config{}))

	sc, err := raw.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	opt := func(level, name int) int {
		var v int
		var gerr error
		sc.Control(func(fd uintptr) { v, gerr = syscall.GetsockoptInt(int(fd), level, name) })
		if gerr != nil {
			t.Fatal(gerr)
		}
		return v
	}
	for _, c := range []struct {
		name       string
		level, opt int
		want       int
	}{
		{"TCP_USER_TIMEOUT", syscall.IPPROTO_TCP, tcpUserTimeout, 30000},
		{"SO_KEEPALIVE", syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1},
		{"TCP_KEEPIDLE", syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, 10},
		{"TCP_KEEPINTVL", syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 5},
		{"TCP_KEEPCNT", syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3},
	} {
		if got := opt(c.level, c.opt); got != c.want {
			t.Errorf("%s = %d, want %d", c.name, got, c.want)
		}
	}
}

// A ping or a stream open waits behind every queued frame: on a slow, busy
// uplink yamux took that for a dead peer and closed the whole session.
func TestYamuxDoesNotJudgeLiveness(t *testing.T) {
	cfg := yamuxConfig()
	if cfg.EnableKeepAlive || cfg.StreamOpenTimeout != 0 {
		t.Fatalf("keepalive %v, stream open timeout %v: liveness belongs to watchPeer", cfg.EnableKeepAlive, cfg.StreamOpenTimeout)
	}
}
