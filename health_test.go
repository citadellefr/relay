package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

func TestMeasureRTT(t *testing.T) {
	defer func(d time.Duration) { rttInterval = d }(rttInterval)
	rttInterval = 10 * time.Millisecond
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go yamux.Client(b, yamuxConfig())
	sess, err := yamux.Server(a, yamuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan time.Duration, 1)
	go measureRTT(sess, func(d time.Duration) {
		select {
		case got <- d:
		default:
		}
	})
	select {
	case d := <-got:
		if d <= 0 || d >= writeTimeout {
			t.Fatalf("rtt %v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no ping measured")
	}
}

func TestDropCause(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{nil, "closed here"},
		{io.EOF, "EOF"},
		{fmt.Errorf("read: %w", net.ErrClosed), "closed here"},
		{&net.OpError{Op: "read", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 4242},
			Err: os.NewSyscallError("read", syscall.ETIMEDOUT)}, "read: connection timed out"},
	} {
		if got := dropCause(c.err); got != c.want {
			t.Errorf("dropCause(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// The journal line and /healthz say why the last tunnel of a tenant ended.
func TestControlRecordsWhyATunnelEnded(t *testing.T) {
	reg := newRegistry(limits{})
	cert := testClientCert(t, "t1")
	ln, _ := startControl(t, reg, testAuthLimiter(), cert)
	line, err := controlAuth(t, ln, `{"v":1}`, cert)
	if err != nil || !strings.Contains(line, `"ok":true`) {
		t.Fatalf("auth: %q, %v", line, err)
	}
	waitForTunnel(t, reg, "t1")
	reg.lookup("t1").Close()
	deadline := time.Now().Add(2 * time.Second)
	for reg.snapshot()["t1"].LastDrop == "" {
		if time.Now().After(deadline) {
			t.Fatal("no cause recorded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := reg.snapshot()["t1"].LastDrop; got != "closed here" {
		t.Fatalf("lastDrop = %q", got)
	}
}
