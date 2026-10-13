package main

import (
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/time/rate"
)

// limits are global defaults applied to every tenant. Zero means unlimited.
type limits struct {
	MaxStreams  int // concurrent proxied connections per tenant
	MaxBytesSec int // shared bandwidth budget per tenant, bytes/second
}

// tenantState survives disconnections so counters tell the whole story.
type tenantState struct {
	sess          *yamux.Session
	connectedAt   time.Time
	connects      uint64
	activeStreams int
	totalStreams  uint64
	key           string        // key id the live session authenticated with
	bandwidth     *rate.Limiter // nil when unlimited
	refused       uint64        // connections turned away at the stream cap
	rtt           time.Duration // last ping of the live session, 0 = not yet
	lastDrop      string        // why the previous session ended
}

// registry maps a tenant id to its live tunnel session and usage counters.
type registry struct {
	mu      sync.Mutex
	tenants map[string]*tenantState
	lim     limits
}

func newRegistry(lim limits) *registry {
	return &registry{tenants: make(map[string]*tenantState), lim: lim}
}

func (r *registry) state(tenant string) *tenantState {
	st := r.tenants[tenant]
	if st == nil {
		st = &tenantState{}
		if r.lim.MaxBytesSec > 0 {
			// burst of one second of traffic, but never below the copy buffer
			burst := max(r.lim.MaxBytesSec, 64*1024)
			st.bandwidth = rate.NewLimiter(rate.Limit(r.lim.MaxBytesSec), burst)
		}
		r.tenants[tenant] = st
	}
	return st
}

// register replaces any previous session for the tenant: a fast reconnect
// can arrive before the dead session is detected by keepalive.
func (r *registry) register(tenant string, s *yamux.Session, key string) {
	r.mu.Lock()
	st := r.state(tenant)
	old := st.sess
	st.sess = s
	st.connectedAt = time.Now()
	st.connects++
	st.key = key
	r.mu.Unlock()
	if old != nil && old != s {
		old.Close()
	}
}

// unregister removes the session only if it is still the current one, and
// keeps why it ended.
func (r *registry) unregister(tenant string, s *yamux.Session, cause string) {
	r.mu.Lock()
	if st := r.tenants[tenant]; st != nil {
		st.lastDrop = cause
		if st.sess == s {
			st.sess = nil
			st.rtt = 0
		}
	}
	r.mu.Unlock()
}

// setRTT records a ping of the tenant's live session.
func (r *registry) setRTT(tenant string, s *yamux.Session, rtt time.Duration) {
	r.mu.Lock()
	if st := r.tenants[tenant]; st != nil && st.sess == s {
		st.rtt = rtt
	}
	r.mu.Unlock()
}

func (r *registry) lookup(tenant string) *yamux.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st := r.tenants[tenant]; st != nil {
		return st.sess
	}
	return nil
}

// acquireStream reserves a stream slot; false when the tenant is at its cap.
func (r *registry) acquireStream(tenant string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.state(tenant)
	if r.lim.MaxStreams > 0 && st.activeStreams >= r.lim.MaxStreams {
		st.refused++
		return false
	}
	st.activeStreams++
	st.totalStreams++
	return true
}

func (r *registry) releaseStream(tenant string) {
	r.mu.Lock()
	if st := r.tenants[tenant]; st != nil && st.activeStreams > 0 {
		st.activeStreams--
	}
	r.mu.Unlock()
}

// bandwidth returns the tenant's shared rate limiter (nil = unlimited).
func (r *registry) bandwidth(tenant string) *rate.Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state(tenant).bandwidth
}

// closeRevoked closes the tunnels keys no longer allows — tenant absent, or
// bound to another key than the one its session came in with — and drops the
// state of absent tenants. Returns how many tunnels were closed.
func (r *registry) closeRevoked(keys map[string]string) int {
	r.mu.Lock()
	var doomed []*yamux.Session
	for id, st := range r.tenants {
		key, known := keys[id]
		if st.sess != nil && (!known || st.key != key) {
			doomed = append(doomed, st.sess)
			st.sess = nil
		}
		if !known {
			delete(r.tenants, id)
		}
	}
	r.mu.Unlock()
	for _, s := range doomed {
		s.Close()
	}
	return len(doomed)
}

// tenantStats is the JSON shape served by the health endpoint.
type tenantStats struct {
	Connected     bool      `json:"connected"`
	ConnectedAt   time.Time `json:"connectedAt,omitzero"`
	Connects      uint64    `json:"connects"`
	ActiveStreams int       `json:"activeStreams"`
	TotalStreams  uint64    `json:"totalStreams"`
	Refused       uint64    `json:"refused"`
	RTTMs         int64     `json:"rttMs,omitempty"`
	LastDrop      string    `json:"lastDrop,omitempty"`
}

func (r *registry) snapshot() map[string]tenantStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]tenantStats, len(r.tenants))
	for id, st := range r.tenants {
		s := tenantStats{
			Connected:     st.sess != nil,
			Connects:      st.connects,
			ActiveStreams: st.activeStreams,
			TotalStreams:  st.totalStreams,
			Refused:       st.refused,
			LastDrop:      st.lastDrop,
		}
		if st.sess != nil {
			s.ConnectedAt = st.connectedAt
		}
		if st.rtt > 0 {
			// under a millisecond still reads as measured
			s.RTTMs = max(st.rtt.Milliseconds(), 1)
		}
		out[id] = s
	}
	return out
}
