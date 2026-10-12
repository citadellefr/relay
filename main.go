// Citadelle public gateway: a deliberately dumb byte router on a VPS.
//
// Private gateways dial CONTROL_ADDR, authenticate with the client certificate
// of their tenant (signed by CONTROL_CLIENT_CA) and keep a yamux tunnel open. Clients hit PROXY_ADDR (:443) with plain HTTPS; the
// ClientHello SNI selects the tenant tunnel and bytes are copied verbatim —
// TLS is terminated by the private gateway, never here.
//
// SIGHUP reloads TENANTS_FILE: new tenants can connect, tenants removed or
// bound to another key get their tunnel closed, live tunnels of unchanged
// tenants are untouched.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

// version is the release this binary was built from, stamped by the Dockerfile.
var version = "dev"

func main() {
	log.Printf("gateway %s", version)
	domain := mustEnv("DOMAIN")
	certFile := mustEnv("TLS_CERT")
	keyFile := mustEnv("TLS_KEY")
	tenantsFile := mustEnv("TENANTS_FILE")
	controlAddr := envStr("CONTROL_ADDR", ":7000")
	proxyAddr := envStr("PROXY_ADDR", ":443")
	httpAddr := envStr("HTTP_ADDR", ":80")
	healthAddr := envStr("HEALTH_ADDR", "127.0.0.1:7001")
	clientCA := mustEnv("CONTROL_CLIENT_CA")
	if err := checkControlMTLS(os.Getenv("CONTROL_MTLS")); err != nil {
		log.Fatalf("control auth: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("control TLS certificate: %v", err)
	}
	tenants, err := newTenantStore(tenantsFile)
	if err != nil {
		log.Fatalf("tenants: %v", err)
	}

	reg := newRegistry(limits{
		MaxStreams:  envInt("TENANT_MAX_STREAMS", 128),
		MaxBytesSec: envInt("TENANT_MAX_MBPS", 0) * 1_000_000 / 8,
	})
	tenants.reloadOnSIGHUP(reg, log.Printf)
	// 10 auth failures per minute per IP before drops kick in
	authLim := newFailLimiter(10, time.Minute)

	clientCAs, err := loadCertPool(clientCA)
	if err != nil {
		log.Fatalf("control client CA: %v", err)
	}
	controlTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	controlLn, err := tls.Listen("tcp", controlAddr, controlTLS)
	if err != nil {
		log.Fatalf("control listen %s: %v", controlAddr, err)
	}
	proxyLn, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		log.Fatalf("proxy listen %s: %v", proxyAddr, err)
	}

	if httpAddr != "" {
		go func() { log.Fatalf("http redirect: %v", runRedirect(httpAddr, domain)) }()
	}
	if healthAddr != "" {
		go func() { log.Fatalf("health: %v", runHealth(healthAddr, reg)) }()
	}
	go func() { log.Fatalf("control: %v", runControl(controlLn, tenants, reg, authLim)) }()
	// the address policy is logged so a journal proves under which one it was
	// written
	log.Printf("gateway up — domain *.%s, control %s (mTLS), proxy %s, client addresses %s",
		domain, controlAddr, proxyAddr, addrPolicy())
	turn := turnRelay{host: os.Getenv("TURN_HOST"), addr: os.Getenv("TURN_TLS_ADDR")}
	if (turn.host == "") != (turn.addr == "") {
		log.Fatalf("TURN_HOST and TURN_TLS_ADDR go together: set both or neither")
	}
	if turn.host != "" {
		log.Printf("visio relay over TLS — %s on %s, relayed to %s", turn.host, proxyAddr, turn.addr)
	}
	log.Fatalf("proxy: %v", runProxy(proxyLn, domain, reg, tenants, turn))
}

// checkControlMTLS refuses the modes that let a token in. They are gone, and
// a deployment still asking for one must not start as if it had been heard.
func checkControlMTLS(v string) error {
	if v != "" && v != "require" {
		return fmt.Errorf("CONTROL_MTLS=%s: client certificates are the only way in, unset it or set require", v)
	}
	return nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificate in %s", path)
	}
	return pool, nil
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		log.Fatalf("%s: invalid integer %q", key, v)
	}
	return n
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing required env var %s", key)
	}
	return v
}
