package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// tenantStore holds the tenant→key id map and supports hot reload: SIGHUP
// re-reads the file without dropping the tunnels of unchanged tenants. The key
// id pins a tenant to one key pair, so a certificate signed for a seed that
// was since replaced opens nothing, however long it stays valid.

type tenantStore struct {
	mu   sync.RWMutex
	path string
	keys map[string]string
}

func newTenantStore(path string) (*tenantStore, error) {
	s := &tenantStore{path: path}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *tenantStore) reload() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var t map[string]string
	if err := json.Unmarshal(raw, &t); err != nil {
		return fmt.Errorf("%s: %w", s.path, err)
	}
	// an explicit {} is a decision — the last tenant was revoked — where an
	// empty or truncated file is an accident, and does not parse
	if t == nil {
		return fmt.Errorf("%s: want an object, {} for no tenant", s.path)
	}
	for id, key := range t {
		if !validTenantID(id) {
			return fmt.Errorf("%s: invalid tenant id %q", s.path, id)
		}
		if !validKeyID(key) {
			return fmt.Errorf("%s: tenant %q: want the 64 hex digits of its key id", s.path, id)
		}
	}
	s.mu.Lock()
	s.keys = t
	s.mu.Unlock()
	return nil
}

func validTenantID(id string) bool {
	if len(id) == 0 || len(id) > 63 {
		return false
	}
	if id[0] == '-' || id[len(id)-1] == '-' {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

func validKeyID(key string) bool {
	if len(key) != 64 {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// key returns the key id a tenant is bound to, "" for an unknown tenant.
func (s *tenantStore) key(tenant string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keys[tenant]
}

func (s *tenantStore) has(tenant string) bool {
	return s.key(tenant) != ""
}

func (s *tenantStore) all() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return maps.Clone(s.keys)
}

// reloadOnSIGHUP re-reads the tenants file and closes the tunnels it no longer
// allows, so revocation takes effect without a restart.
func (s *tenantStore) reloadOnSIGHUP(reg *registry, logf func(string, ...any)) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for range ch {
			s.apply(reg, logf)
		}
	}()
}

// apply re-reads the file and closes the tunnels of tenants that are gone or
// bound to another key, so revocation takes effect without a restart. A file
// that does not parse leaves
// the running set alone: an empty tenants.json would otherwise drop the whole
// fleet.
func (s *tenantStore) apply(reg *registry, logf func(string, ...any)) {
	if err := s.reload(); err != nil {
		logf("tenants reload failed, keeping previous set: %v", err)
		return
	}
	keys := s.all()
	closed := reg.closeRevoked(keys)
	logf("tenants reloaded from %s (%d tenants, %d tunnels revoked)", s.path, len(keys), closed)
}
