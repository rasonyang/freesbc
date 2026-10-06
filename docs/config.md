# FreeSBC configuration reference

One YAML file configures the whole process (`freesbc run -c freesbc.yaml`). The annotated starting point is `freesbc.example.yaml`; `freesbc check -c <file>` validates a file without binding a socket or opening a certificate. The code is the source of truth: the schema is `internal/config/schema.go`, the rules are `internal/config/validate.go`, and the reload classes are `internal/config/restart.go`.

Principles of the schema:

- Every fact is written once. Addresses live in `public` and `private`; the edge refers to them.
- Presence enables. There are no `enabled:` flags.
- A key with exactly one valid value does not exist.
- No wildcard binds. Each side binds one specific local address.
- Business routing belongs to the switch (FreeSWITCH or Asterisk). FreeSBC forwards, rewrites addresses, anchors media and enforces allowlists.
- Timers are code constants (see [Constants](#constants)).

## Loading rules

`config.Parse` runs these steps in order:

1. Strict YAML decode. An unknown key is an error with a line number, so any key not in this document is rejected. A decoder panic on malformed input becomes a parse error.
2. `${VAR}` expansion in string values. Only the exact form `${NAME}` (`[A-Za-z_][A-Za-z0-9_]*`) is expanded; `${VAR:-default}` and other malformed references are errors, as is an undefined variable. Expansion runs after the decode, so parse errors never echo a secret, a `${VAR}` in a comment is inert, and expanded values are never re-scanned or written back. Only string fields expand: `rtp`, `shield.ban` and the port numbers are decoded before expansion, so `rtp: ${R}` is a parse error.
3. Defaults.
4. Validation. All problems are collected and reported together. Messages never echo an expanded environment value.

`check` stops after step 4. It does not test whether an address is assigned to this host, does not open `tls` files and binds nothing; `run` does those.

## Top-level keys

| Key | Required | Reload |
|---|---|---|
| `public` | yes | restart |
| `private` | yes | restart |
| `rtp` | no (default `20000-29999`) | restart |
| `tls` | when `edge.listen.wss` is set or `admin.allow_remote` is true | restart |
| `edge` | yes | restart (every key) |
| `shield` | no | hot |
| `admin` | no | restart |

### `public`

The side facing phones, browsers and carriers.

| Key | Default | Rules |
|---|---|---|
| `ip` | required | A literal IP, not `0.0.0.0` / `::`. Advertised in Contact, Via, Record-Route and SDP. |
| `bind` | `ip` | A literal IP, not `0.0.0.0` / `::`. The local address every public socket binds. Set it only behind 1:1 NAT, where `ip` is not a local address. |

### `private`

The side facing the switch.

| Key | Default | Rules |
|---|---|---|
| `ip` | required | A literal IP, not `0.0.0.0` / `::`, and different from the effective `public.bind`. Both the bind and the advertised address. |

The private SIP socket is fixed at `private.ip:5060` (`config.PrivateSIPPort`) and cannot be configured.

At startup `run` fails if `public.bind` or `private.ip` is not assigned to a local interface (`checkLocalAddr`, `internal/edge/edge.go:299`). `check` does not test this.

### `rtp`

`"<min>-<max>"`, a quoted or bare string such as `20000-29999` (default `20000-29999`).

- The YAML decoder requires `0 < min < max`, both at most 65535.
- `min` must be at least 1024.
- The range must hold at least one RTP/RTCP pair: RTP on an even port, RTCP on RTP+1.

There is one range and two independent allocators over it, one bound to `public.bind` and one to `private.ip`, so a port number can be in use on both sides at once.

### `tls`

| Key | Rules |
|---|---|
| `cert` | PEM certificate file path. |
| `key` | PEM private key file path. |

Both must be set when `tls` is present. The section is required when `edge.listen.wss` is set (browsers refuse an untrusted WSS certificate) or `admin.allow_remote` is true (the admin API must not carry Basic credentials in the clear). The files are opened by `run`, not by `check`.

The DTLS identity for WebRTC media is a per-process self-signed certificate generated at startup. It is independent of `tls`.

### `edge`

| Key | Default | Rules |
|---|---|---|
| `switch` | required | List of literal `IP:port` (UDP), at least one. |
| `switch_carrier_port` | `0` (the node's own `switch` port) | `0` or 1-65535. |
| `listen` | required | At least one of `udp`, `ws`, `wss`. |
| `carriers` | none | Map of name to `host[:port]`. |
| `carrier_sources` | none | List of IPs or CIDRs. |

#### `edge.switch`

The switch nodes, as literal `IP:port` over UDP (no DNS: a host name is a validation error). Rules: each entry is a valid IP with port 1-65535, not unspecified, not repeated, and not FreeSBC's own private socket `private.ip:5060`.

One entry is a single upstream. More than one is a pool: a request is hashed to a node by FNV-1a 64 over the lower-cased user part, and a node that answered nothing is skipped for 30 s (passive cooldown). The nodes must share a registration store. A node is named by its `IP:port` in logs and metrics.

A carrier registration, and the calls delivered to it, stay on the node that registered.

#### `edge.switch_carrier_port`

The port on each `edge.switch` node that receives carrier traffic (carrier to switch). Default: that node's own `edge.switch` port. FreeSBC sends only requests admitted from a carrier source there, and never client traffic, so the switch can run an unauthenticated carrier profile on it (FreeSWITCH: the `external` profile, 5080, `auth-calls=false`) while clients reach the authenticated port in `edge.switch` (FreeSWITCH: the `internal` profile, 5060, `auth-calls=true`).

#### `edge.listen`

Ports on `public.bind`; `0` or absent means not enabled; each present value is 1-65535.

| Key | Transport |
|---|---|
| `udp` | SIP over UDP. Required by `carriers`. |
| `ws` | Plaintext WebSocket, development only. |
| `wss` | WebSocket over TLS; needs `tls`. |

`ws` and `wss` must differ. Setting either enables WebRTC (ICE-Lite, DTLS-SRTP, rtcp-mux) for WebSocket clients. The public UDP and TCP ports are separate namespaces.

#### `edge.carriers`

An allowlist of the destinations the switch may send carrier traffic to. Each key is a name; each value is `host[:port]`:

- The name matches `[A-Za-z0-9._-]+`. It appears in logs and metrics and is stamped on inbound requests as `X-FreeSBC-Carrier`.
- `host` is a literal IP or a DNS name (labels of letters, digits and interior hyphens; at most 253 characters). A trailing dot is ignored and the host is lower-cased. An unspecified address is rejected.
- The port defaults to 5060 (UDP). An IPv6 literal with a port needs brackets: `[2001:db8::1]:5060`.
- A DNS name without a port is resolved through SRV (`_sip._udp`), then A/AAAA. A DNS name with a port is resolved through A/AAAA only (RFC 3263 §4.2). Resolution happens on the public side only and is cached for 300 s.
- No two entries may share the same `host:port` (default port applied).
- A literal-IP entry must not be FreeSBC's own public UDP socket (`public.bind` or `public.ip` with `edge.listen.udp`), nor an `edge.switch` node.
- A non-empty `carriers` requires `edge.listen.udp`.

An entry must equal the `host[:port]` the switch puts in the Request-URI (FreeSWITCH gateway `proxy`, Asterisk aor `contact`). That equality is what makes a request a carrier request.

#### `edge.carrier_sources`

Extra inbound carrier IPs or CIDRs, on top of the resolved addresses of `carriers`, which are sources implicitly. A bare IP is a single-host prefix. Rules:

- Valid CIDR or IP.
- No wider than /8 (IPv4) or /32 (IPv6).
- An IPv4-mapped IPv6 entry (`::ffff:a.b.c.d/n`, n at least 96) is normalised to the IPv4 prefix; one that mixes mapped and native IPv6 space is rejected.
- Entries are stored in masked form.

A request from a `carrier_sources` address that matches no `carriers` entry gets `X-FreeSBC-Carrier: unknown`.

### `shield`

| Key | Default | Rules |
|---|---|---|
| `rate_limit` | `20/s per_ip` | Applies to every public source that is not a carrier. |
| `carrier_rate_limit` | `200/s per_ip` | Applies to carrier sources (resolved `carriers` addresses and `carrier_sources`). |
| `ban` | `1h` | Duration, greater than 0. How long a source fingerprinted as a scanner stays banned (in memory only). Carrier sources are never banned as scanners. |

Rate limit syntax: `<n>/<s|m|h>` with an optional ` per_ip`; `n` is a positive integer. With `per_ip` each source (an IPv6 source by its /64) has its own token bucket; without it all sources share one bucket. Burst equals `n`.

A UDP scanner verdict bans only the exact source socket for at most one minute, because a datagram source address can be forged; stream transports get the IP ban for `ban`.

### `admin`

Optional. The section being present enables the HTTP API, `/metrics` and the WebUI.

| Key | Default | Rules |
|---|---|---|
| `listen` | required | Literal `IP:port`. Loopback unless `allow_remote`. |
| `password_hash` | required | bcrypt hash, cost at least 10. The user name is always `admin`. |
| `allow_remote` | `false` | Permits a non-loopback `listen`; requires top-level `tls` (served over HTTPS). |
| `allowed_hosts` | none | Extra host names or IP literals, no port, scheme or wildcard, no duplicates, that the `Host` header may carry (with the `listen` port). |

Web security (restart-only like the rest of `admin`):

- Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` (except `/healthz`). The WebUI also carries a `Content-Security-Policy`.
- Host check: every route except `/healthz` answers `421` unless `Host` is the `listen` IP with the listen port, on a loopback `listen` also `localhost`, `127.0.0.1` or `[::1]` with that port, or an `allowed_hosts` entry with that port (case-insensitive, trailing dot ignored). A bare host with no port is accepted only when the listen port is the scheme default (443 with TLS, 80 without). With a wildcard `listen` (`0.0.0.0`, `[::]`) any IP-literal `Host` with the listen port is accepted, since an IP literal cannot be DNS-rebound. Behind a reverse proxy or a DNS name, add the name to `allowed_hosts`. The check runs before authentication.
- Origin check: `PUT /api/config` (any method but GET, HEAD, OPTIONS) needs an `Origin` equal to `<scheme>://<Host>`, or no `Origin` and `Sec-Fetch-Site: same-origin`; otherwise `403`. The WebUI satisfies this by itself. A script must send the header:

  ```sh
  curl -u admin:PASSWORD -X PUT -H 'Origin: http://127.0.0.1:8080' \
       -H 'If-Match: "<etag>"' --data-binary @freesbc.yaml http://127.0.0.1:8080/api/config
  ```

- Auth model: HTTP Basic Auth stays. There is no logout and no idle timeout. The session ends when the browser forgets the credentials, and the server remembers credentials it has verified for 1 hour after their last use (`verifiedCredsTTL`). `/metrics` is scraped with Basic Auth as before.

`admin.listen` must not collide with `edge.listen.ws` / `edge.listen.wss` on `public.bind` (the same TCP address and port). Generate a hash with `htpasswd -bnBC 10 "" 'pw' | tr -d ':\n'`.

`GET /api/config/raw` returns the file unredacted on purpose; `GET /api/config` masks `admin.password_hash`.

The WebUI's Config tab has a **Download config** button that fetches `/api/config/raw` fresh (never the editor text, so unsaved edits are not included) and saves the exact bytes as `freesbc-<host>-<UTC timestamp>.yaml`, for example `freesbc-127.0.0.1-8080-20261006T120000Z.yaml`. The file is not redacted: it contains `admin.password_hash` and any secret written as a literal, so store it like a credential. `${VAR}` references are saved as references, not values. Keep secrets as `${VAR}` references so a downloaded copy does not leak them.

## Reload classes

`config.Watch` watches the file's parent directory (200 ms debounce, symlink-aware) and publishes each valid file as an immutable snapshot. An invalid file is logged and the previous snapshot stays. `PUT /api/config` only writes the file atomically; the watcher does the reload.

| Setting | Class |
|---|---|
| `shield.rate_limit`, `shield.carrier_rate_limit`, `shield.ban` | hot |
| `public`, `private`, `rtp`, `tls` | restart-only |
| `edge.switch`, `edge.switch_carrier_port`, `edge.listen`, `edge.carriers`, `edge.carrier_sources` | restart-only |
| `admin` (every key, including `allowed_hosts`, and whether the section exists) | restart-only |

A reload that edits a restart-only setting is still published, so its hot settings apply, and logs a warning listing the changed keys (`config.RestartOnlyChanges`). The running process keeps its startup values for the restart-only settings until it restarts. The table in `restartOnly` (`internal/config/restart.go`) and `docs/design.md` §4.4 are the same list.

## Constants

Not configurable. They live in code until there is a concrete need to tune one.

| Value | Constant | Where |
|---|---|---|
| Private SIP port | 5060 | `config.PrivateSIPPort` |
| Default carrier port | 5060 | `config.DefaultCarrierPort` |
| RTP silence teardown | 5 min | `rtpSilenceTimeout`, `internal/edge/edge.go` |
| Switch node cooldown | 30 s | `switchCooldown`, `internal/edge/edge.go` |
| Carrier DNS cache | 300 s (10 s for a failed or empty lookup) | `carrierDNSTTL`, `carrierDNSNegTTL`, `internal/edge/carrierdns.go` |
| Carrier DNS lookup timeout | 3 s | `carrierLookupTimeout`, `internal/edge/carrierdns.go` |
| Admin user name | `admin` | `config.AdminUser` |

`docs/design.md` §15.2 lists every other timeout.
