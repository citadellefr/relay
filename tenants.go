package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// tenantStore holds the tenant→token map and supports hot reload: SIGHUP
// re-reads the file without dropping the tunnels of unchanged tenants.
type tenantStore struct {
	mu     sync.RWMutex
	path   string
	tokens map[string]string
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
	if len(t) == 0 {
		return fmt.Errorf("%s: no tenants defined", s.path)
	}
	for id := range t {
		if !validTenantID(id) {
			return fmt.Errorf("%s: invalid tenant id %q", s.path, id)
		}
	}
	s.mu.Lock()
	s.tokens = t
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

func (s *tenantStore) token(tenant string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tokens[tenant]
}

func (s *tenantStore) has(tenant string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.tokens[tenant]
	return ok
}

func (s *tenantStore) ids() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make(map[string]bool, len(s.tokens))
	for id := range s.tokens {
		ids[id] = true
	}
	return ids
}

// reloadOnSIGHUP re-reads the tenants file and closes the tunnels of tenants
// that were removed, so revocation takes effect without a restart.
func (s *tenantStore) reloadOnSIGHUP(reg *registry, logf func(string, ...any)) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for range ch {
			if err := s.reload(); err != nil {
				logf("tenants reload failed, keeping previous set: %v", err)
				continue
			}
			closed := reg.closeRemoved(s.ids())
			logf("tenants reloaded from %s (%d tenants, %d tunnels revoked)", s.path, len(s.ids()), closed)
		}
	}()
}
