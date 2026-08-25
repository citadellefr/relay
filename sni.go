package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"time"
)

var errHelloDone = errors.New("clienthello captured")

// peekClientHello extracts the SNI from the TLS ClientHello without
// consuming the connection: the bytes read are returned so they can be
// replayed to the tenant stream. The trick: run a real TLS handshake whose
// GetConfigForClient aborts right after the ClientHello is parsed.
func peekClientHello(conn net.Conn, timeout time.Duration) (sni string, peeked []byte, err error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", nil, err
	}
	defer conn.SetReadDeadline(time.Time{})

	rec := &recordingConn{Conn: conn}
	tls.Server(rec, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = h.ServerName
			return nil, errHelloDone
		},
	}).Handshake()
	if sni == "" {
		return "", nil, errors.New("no SNI in ClientHello")
	}
	return sni, rec.buf.Bytes(), nil
}

// recordingConn keeps everything read and swallows writes (the aborted
// handshake emits a TLS alert that must not reach the client).
type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.buf.Write(p[:n])
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) { return len(p), nil }
