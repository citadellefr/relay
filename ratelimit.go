package main

import (
	"net"
	"sync"
	"time"
)

// failLimiter throttles control-plane auth by IP: an IP that accumulates
// maxFails failures within the window is dropped before any processing.
// Successful tunnels are never counted, so legitimate reconnects stay free.
type failLimiter struct {
	mu        sync.Mutex
	fails     map[string][]time.Time
	maxFails  int
	window    time.Duration
	lastSweep time.Time
}

func newFailLimiter(maxFails int, window time.Duration) *failLimiter {
	return &failLimiter{
		fails:     make(map[string][]time.Time),
		maxFails:  maxFails,
		window:    window,
		lastSweep: time.Now(),
	}
}

func (l *failLimiter) blocked(addr net.Addr) bool {
	key := ipKeyOf(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(key)) >= l.maxFails
}

func (l *failLimiter) fail(addr net.Addr) {
	key := ipKeyOf(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.lastSweep) >= l.window || len(l.fails) >= 10000 {
		l.sweep(now)
	}
	l.fails[key] = append(l.prune(key), now)
}

func (l *failLimiter) sweep(now time.Time) {
	l.lastSweep = now
	cutoff := now.Add(-l.window)
	for k, times := range l.fails {
		var kept []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(l.fails, k)
		} else {
			l.fails[k] = kept
		}
	}
	if len(l.fails) > 10000 {
		for k := range l.fails {
			delete(l.fails, k)
			if len(l.fails) <= 5000 {
				break
			}
		}
	}
}

func (l *failLimiter) prune(key string) []time.Time {
	cutoff := time.Now().Add(-l.window)
	kept := l.fails[key][:0]
	for _, t := range l.fails[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.fails, key)
		return nil
	}
	l.fails[key] = kept
	return kept
}

func ipKeyOf(addr net.Addr) string {
	raw := ipOf(addr)
	ip := net.ParseIP(raw)
	if ip == nil {
		return raw
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

func ipOf(addr net.Addr) string {
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}
