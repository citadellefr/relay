# Citadelle Relay (Gateway)

A lightweight, zero-TLS-termination byte router and gateway for Citadelle instances.

Private tenant servers dial in to the control plane, authenticate, and maintain persistent multiplexed tunnels over [yamux](https://github.com/hashicorp/yamux). Public client HTTPS traffic is inspected for Server Name Indication (SNI) and routed directly through the appropriate tunnel.

TLS is terminated exclusively on the tenant's private gateway—never on the public relay.

---

## Architecture & How It Works

```
                        +---------------------------------------------+
                        |               Citadelle Relay               |
                        |                                             |
[ HTTPS Client ] ------>| :443 (SNI Proxy)                            |
                        |   - Peeks SNI from TLS ClientHello          |
                        |   - Prepends PROXY v2 header                |
                        |   - Copies raw TLS stream to tenant session |
                        |                                             |
[ Private Tenant ] ---->| :7000 (Control Plane)                       |
                        |   - Authenticates via Token or mTLS         |
                        |   - Keeps yamux multiplexed tunnel open     |
                        |                                             |
[ Supervisor ] -------->| 127.0.0.1:7001 (/healthz endpoint)          |
                        +---------------------------------------------+
```

1. **Control Plane (`:7000`)**: Tenant instances connect over TLS and authenticate either via a shared token (`tenants.json`) or via mTLS (X.509 client certificate). The handshake is one JSON line each way — `{"v":1,"tenant":"…","token":"…"}` answered by `{"ok":true,"v":1,"maxStreams":128}`: the protocol version retained (the lower of the two) and the tenant's stream cap. A refusal never says why. Once authenticated, the connection is upgraded to a yamux multiplexed session.
2. **SNI Data Proxy (`:443`)**: Accepts raw TLS connections, extracts the hostname from the `ClientHello` (`<tenant>.<domain>` or `partage-<tenant>.<domain>`), injects a PROXY protocol v2 header (to pass along client IP information), and pipes the stream directly into the tenant's tunnel. A refusal is told as a plaintext TLS alert, never as a response: `unrecognized_name` when no tunnel serves the name, `internal_error` when the tunnel has no stream left.
3. **HTTP Redirect (`:80`)**: Automatically redirects plain HTTP requests to HTTPS.
4. **Health & Supervision (`:7001/healthz`)**: Local JSON endpoint exposing active tunnel states, stream counters, and authentication methods.

---

## Configuration

Configuration is provided through environment variables:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DOMAIN` | Base domain (e.g. `example.com`). **(Required)** | — |
| `TLS_CERT` | Path to TLS certificate for the control plane. **(Required)** | — |
| `TLS_KEY` | Path to TLS private key for the control plane. **(Required)** | — |
| `TENANTS_FILE` | Path to `tenants.json` file. **(Required)** | — |
| `CONTROL_ADDR` | Listen address for private gateway tunnels. | `:7000` |
| `PROXY_ADDR` | Listen address for public HTTPS traffic. | `:443` |
| `HTTP_ADDR` | Listen address for HTTP to HTTPS redirect (`""` to disable). | `:80` |
| `HEALTH_ADDR` | Listen address for local health metrics (`""` to disable). | `127.0.0.1:7001` |
| `CONTROL_CLIENT_CA`| Path to CA certificate pool for mTLS client verification. | `""` |
| `CONTROL_MTLS` | mTLS enforcement mode: `off`, `transition`, or `require`. | `""` |
| `TENANT_MAX_STREAMS`| Max concurrent proxied streams per tenant (`0` for unlimited). Worst-case memory is streams × the 2 MiB yamux window. | `128` |
| `TENANT_MAX_MBPS` | Shared bandwidth limit per tenant in Mbps (`0` for unlimited). | `0` |
| `TURN_HOST` | The one name on the proxy port that is not a tenant's: a TURN relay reached over TLS, routed verbatim to `TURN_TLS_ADDR`. Empty routes nothing. | — |
| `TURN_TLS_ADDR` | `host:port` where that relay terminates its own TLS. Set together with `TURN_HOST`. | — |
| `LOG_CLIENT_IP` | Client IP logging policy: `masked` (/24 or /48) or `full`. | `masked` |

### `tenants.json`

Maps tenant identifiers to authentication tokens:

```json
{
  "tenant1": "random-secret-token-here",
  "tenant2": "another-secret-token-here"
}
```

> **Hot Reload:** Sending `SIGHUP` to the process reloads `tenants.json` on the fly. New tenants can connect immediately, removed tenants have their active tunnels severed, and untouched tenant tunnels remain connected without interruption.

---

## Control Plane PKI (mTLS)

A companion script [deploy/pki.sh](file:///home/me/Code/Citadelle/relay/deploy/pki.sh) is provided to generate and manage control-plane certificates:

```bash
# Initialize CA on the admin machine
./deploy/pki.sh init

# Issue a certificate for a tenant (CN=tenant1)
./deploy/pki.sh issue tenant1

# Inspect an issued certificate
./deploy/pki.sh show tenant1
```

---

## Build & Run

### Using Go

```bash
# Build the binary
go build -o relay .

# Run
export DOMAIN="example.com"
export TLS_CERT="/path/to/control.crt"
export TLS_KEY="/path/to/control.key"
export TENANTS_FILE="/path/to/tenants.json"

./relay
```

### Using Docker

```bash
docker build -t citadelle-relay .

docker run -d \
  --net=host \
  -e DOMAIN="example.com" \
  -e TLS_CERT="/certs/control.crt" \
  -e TLS_KEY="/certs/control.key" \
  -e TENANTS_FILE="/etc/citadelle/tenants.json" \
  -v /etc/citadelle/certs:/certs:ro \
  -v /etc/citadelle/tenants.json:/etc/citadelle/tenants.json:ro \
  citadelle-relay
```

---

## Testing

Run unit and integration tests:

```bash
go test -v ./...
bash deploy/pki_test.sh
```
