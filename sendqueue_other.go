//go:build !linux

package main

import "net"

// The gateway runs on Linux; elsewhere the kernel's default stands.
func boundSendQueue(net.Conn) {}
