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
                        |   - Authenticates via mTLS (client cert)    |
                        |   - Keeps yamux multiplexed tunnel open     |
                        |                                             |
[ Supervisor ] -------->| 127.0.0.1:7001 (/healthz endpoint)          |
                        +---------------------------------------------+
```

1. **Control Plane (`:7000`)**: Tenant instances connect over TLS and authenticate with an X.509 client certificate (mTLS, mandatory): the tenant is the certificate's CommonName, and `tenants.json` must bind that tenant to the certificate's key. The handshake is one JSON line each way — `{"v":1}` answered by `{"ok":true,"v":1,"maxStreams":1024}`: the protocol version retained (the lower of the two) and the tenant's stream cap. A refusal never says why. Once authenticated, the connection is upgraded to a yamux multiplexed session.
2. **SNI Data Proxy (`:443`)**: Accepts raw TLS connections, extracts the hostname from the `ClientHello` (`<tenant>.<domain>` or `partage-<tenant>.<domain>`), injects a PROXY protocol v2 header (to pass along client IP information), and pipes the stream directly into the tenant's tunnel. A refusal is told as a plaintext TLS alert, never as a response: `unrecognized_name` when no tunnel serves the name, `internal_error` when the tunnel has no stream left.
3. **HTTP Redirect (`:80`)**: Automatically redirects plain HTTP requests to HTTPS.
4. **Health & Supervision (`:7001/healthz`)**: Local JSON endpoint exposing active tunnel states, stream counters, connections refused at the stream cap, the round trip of the last tunnel ping (measured every minute, it closes nothing) and why the last tunnel ended.

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
| `CONTROL_CLIENT_CA`| Path to the CA that signs the tenants' client certificates. **(Required)** | — |
| `CONTROL_MTLS` | Legacy: empty or `require`. Any other value asked for token access, which no longer exists, and prevents startup. | `""` |
| `TENANT_MAX_STREAMS`| Max concurrent proxied streams per tenant (`0` for unlimited). Worst-case memory is about streams × 1.4 MiB (1 MiB yamux window, measured). | `1024` |
| `MAX_STREAMS_PER_ADDRESS`| Max concurrent proxied streams per client address (IPv4, or IPv6 /64), all tenants together (`0` for unlimited): one address cannot take a tenant's whole cap, and what it can pin in memory stays bounded (about 180 MiB). | `128` |
| `TENANT_MAX_MBPS` | Shared bandwidth limit per tenant in Mbps (`0` for unlimited). | `0` |
| `TURN_HOST` | The one name on the proxy port that is not a tenant's: a TURN relay reached over TLS, routed verbatim to `TURN_TLS_ADDR`. Empty routes nothing. | — |
| `TURN_TLS_ADDR` | `host:port` where that relay terminates its own TLS. Set together with `TURN_HOST`. | — |
| `LOG_CLIENT_IP` | Client IP logging policy: `masked` (/24 or /48) or `full`. | `masked` |

### `tenants.json`

Binds each tenant identifier to the id of its key, `hex(SHA-256(Ed25519 public key))`, as printed by `deploy/pki.sh`. It holds no secret:

```json
{
  "tenant1": "73e7213af81718b8f00f7eea1e0458c0120d2171f00e9ff0bc83e1e2b66a3f95"
}
```

A certificate signed by the CA is not enough to get in: its key must be the one this file names. `{}` declares no tenant.

> **Hot Reload:** Sending `SIGHUP` to the process reloads `tenants.json` on the fly. New tenants can connect immediately, tenants removed or bound to another key have their active tunnels severed — this is how a tenant, or a single key, is revoked without a restart — and untouched tenant tunnels remain connected without interruption. A file that does not parse leaves the running set in place.

---

## Control Plane PKI (mTLS)

A companion script [deploy/pki.sh](file:///home/me/Code/Citadelle/relay/deploy/pki.sh) is provided to generate and manage control-plane certificates:

```bash
# Initialize CA on the admin machine
./deploy/pki.sh init

# Draw a tenant's key (a 32-byte seed, printed once and stored nowhere),
# sign the certificate of the Ed25519 pair it gives (CN=tenant1), and print
# the key id that goes into tenants.json
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
