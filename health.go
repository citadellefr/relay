package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// runHealth serves a local supervision endpoint (bind it to 127.0.0.1): the
// VPS monitoring can see tunnel state and per-tenant counters without logs.
func runHealth(addr string, reg *registry) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(struct {
			Status  string                 `json:"status"`
			Tenants map[string]tenantStats `json:"tenants"`
		}{"ok", reg.snapshot()})
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    4096,
		ErrorLog:          discardLog,
	}
	return srv.ListenAndServe()
}
