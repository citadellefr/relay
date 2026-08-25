package main

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// runRedirect answers plain HTTP with a redirect to https. Nothing is served
// here; it only helps browsers that were given a bare domain. Hosts outside
// *.baseDomain fall back to the base domain (no open redirect).
func redirectHandler(baseDomain string) http.Handler {
	base := strings.TrimSuffix(strings.ToLower(baseDomain), ".")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		prefix, hasSuffix := strings.CutSuffix(host, "."+base)
		if host != base && (!hasSuffix || prefix == "" || strings.Contains(prefix, ".")) {
			http.Redirect(w, r, "https://"+base+"/", http.StatusMovedPermanently)
			return
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}

func runRedirect(addr, baseDomain string) error {
	srv := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8192,
		ErrorLog:          discardLog,
		Handler:           redirectHandler(baseDomain),
	}
	return srv.ListenAndServe()
}
