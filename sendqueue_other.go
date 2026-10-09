//go:build !linux

package main

import "crypto/tls"

// The gateway runs on Linux; elsewhere the kernel's default stands.
func boundSendQueue(*tls.Conn) {}
