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
| `tls` | when `edge.listen.tls` or `edge.listen.wss` is set, or `admin.allow_remote` is true | restart |
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

Capacity: each call anchors one RTP/RTCP pair on each plane, and the planes bind different IPs, so the range holds `(max - min + 1) / 2` calls (with `min` rounded up to even). `shield.max_sessions` defaults to that number and may not exceed it.

There is one range and two independent allocators over it, one bound to `public.bind` and one to `private.ip`, so a port number can be in use on both sides at once.

### `tls`

| Key | Rules |
|---|---|
| `cert` | PEM certificate file path. |
| `key` | PEM private key file path. |

Both must be set when `tls` is present. The section is required when `edge.listen.tls` is set, when `edge.listen.wss` is set (browsers refuse an untrusted WSS certificate) or `admin.allow_remote` is true (the admin API must not carry Basic credentials in the clear). The files are opened by `run`, not by `check`.

The leaf of the loaded pair (`Certificate[0]`, so a chain file works) is shown read-only: the WebUI's TLS certificate card on the Overview (with a banner when it expires in under 30 days or has expired; the card is absent when no listener loaded the pair), `GET /api/tls` and the gauge `freesbc_tls_cert_expiry_timestamp_seconds{path}` (not-after as Unix seconds, `path` the `cert` file; absent when nothing is loaded). `GET /api/tls` returns `{"loaded": false}` when nothing is loaded, otherwise `subject`, `sans`, `issuer`, `not_before`, `not_after`, `key_type`, `key_size`, `key_curve`, `fingerprint_sha256`, `cert_file`, `key_file`, `loaded_at`, `listeners` (`tls`, `wss`, `admin`), `days_to_expiry`, `expired`, `expiring_soon` and `disk_differs`. The file is re-read only when the endpoint is asked: `disk_differs: true` means the file on disk now holds a different leaf than the one being served (or `disk_error` says it cannot be read). The key and the PEM are never exposed. `tls` is restart-only and there is no hot rotation: a renewed certificate is served only after a restart (drain first, see `docs/edge.md`). A malformed pair still fails startup. Alert with `freesbc_tls_cert_expiry_timestamp_seconds - time() < 14 * 86400`.

The DTLS identity for WebRTC media is a per-process self-signed certificate generated at startup. It is independent of `tls`.

### `edge`

| Key | Default | Rules |
|---|---|---|
| `switch` | required | List of literal `IP:port` (UDP), at least one. |
| `switch_carrier_port` | `0` (the node's own `switch` port) | `0` or 1-65535. |
| `listen` | required | At least one of `udp`, `tcp`, `tls`, `ws`, `wss`. |
| `carriers` | none | Map of name to `host[:port]`, or to a mapping `{host, transport, ca_file, client_cert, client_key, srtp}`. |
| `srtp` | `off` | SDES-SRTP policy for registered clients: `off`, `optional` or `required`. |
| `allow_insecure_sdes` | `false` | Allow SDES on a leg whose signaling is not TLS or WSS. |
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
| `udp` | SIP over UDP. Required by a `udp` carrier. |
| `tcp` | SIP over TCP, for registered clients and `tcp` carriers. |
| `tls` | SIP over TLS, for registered clients and `tls` carriers; needs `tls`. Min TLS 1.2. |
| `ws` | Plaintext WebSocket, development only. |
| `wss` | WebSocket over TLS; needs `tls`. |

`tcp`, `tls`, `ws` and `wss` are all TCP sockets on `public.bind`, so no two may share a port. `udp` is a separate port space and may share a number with `tcp` (the usual `5060` for both). Setting `ws` or `wss` enables WebRTC (ICE-Lite, DTLS-SRTP, rtcp-mux) for WebSocket clients; `tcp` and `tls` clients get plain RTP like UDP phones.

A client on a stream transport is reachable only through the connection it opened: FreeSBC never dials a client (RFC 5626 flow semantics), and the binding goes when the connection does. FreeSBC answers the RFC 5626 double-CRLF keep-alive ping with a single CRLF. A carrier on `tcp` or `tls` is the one exception: FreeSBC opens (and reopens) the connection to it, because its address is configured.

Every stream transport (`tcp`, `tls`, `ws`, `wss`) is bounded by constants, not keys (design.md §15.2): at most 256 open connections per source IP (an IPv6 source by its /64) and 10000 in all (connections to and from carriers have their own 1024 pool), a 10 s TLS handshake and WebSocket upgrade, a 15 s bound on one message once its first byte has arrived, a 60 s idle timeout (CRLF keep-alives and WebSocket ping/pong frames do not defer it), and 24 KiB per SIP message. The idle timeout does not apply to a connection with a live registration binding, a dialog or a carrier source. Each new connection costs the source one `shield.rate_limit` token. Open connections and refusals are in `freesbc_edge_stream_connections{transport}`, `freesbc_edge_stream_refused_total{reason}` and `freesbc_edge_stream_closed_total{reason}`. Each connection takes a file descriptor, so raise the process limit (`LimitNOFILE`) above the 10000 cap plus the media ports.

#### `edge.carriers`

An allowlist of the destinations the switch may send carrier traffic to. Each key is a name; each value is `host[:port]` (a UDP carrier) or a mapping:

```yaml
carriers:
  plain: sip.carrier-a.com:5060          # string form: UDP
  secure:
    host: sip.carrier-b.com              # same grammar as the string form
    transport: tls                       # udp (default) | tcp | tls
    ca_file: /etc/freesbc/carrier-b-ca.pem   # tls only, optional
    client_cert: /etc/freesbc/client.pem     # tls only; both or neither
    client_key: /etc/freesbc/client.key
    srtp: required                       # off (default) | optional | required; needs tls
```

An unknown key in the mapping is an error. `host` is required. Rules for the mapping and the keys it adds:

- The name matches `[A-Za-z0-9._-]+`. It appears in logs and metrics and is stamped on inbound requests as `X-FreeSBC-Carrier`.
- `host` is a literal IP or a DNS name (labels of letters, digits and interior hyphens; at most 253 characters). A trailing dot is ignored and the host is lower-cased. An unspecified address is rejected.
- The port written in `host` is the port the switch's Request-URI must carry and the port FreeSBC dials. Without one, the Request-URI port is taken as 5060 and the dial port is 5060 (5061 for `tls`) unless SRV says otherwise. An IPv6 literal with a port needs brackets: `[2001:db8::1]:5060`.
- A DNS name without a port is resolved through SRV (`_sip._udp`, `_sip._tcp` or `_sips._tcp` for `transport` udp, tcp, tls), then A/AAAA. A DNS name with a port is resolved through A/AAAA only (RFC 3263 §4.2). Resolution happens on the public side only and is cached for 300 s.
- No two entries may share the same `host:port` (default port applied).
- A literal-IP entry must not be FreeSBC's own public socket of the same transport (`public.bind` or `public.ip` with that `edge.listen` port), nor an `edge.switch` node.
- `transport` is `udp` (default), `tcp` or `tls`. A `udp` carrier requires `edge.listen.udp`. A `tcp` or `tls` carrier needs no listener to be called, because FreeSBC opens the connection; its own requests to FreeSBC (inbound calls, in-dialog requests) need the matching `edge.listen.tcp` or `edge.listen.tls`, or they can only use the connection FreeSBC opened. A `tls` carrier does not need the top-level `tls`, which is FreeSBC's server identity.
- `srtp` is `off` (default), `optional` or `required`, the SDES-SRTP policy toward that carrier. The string form means `off`. A non-`off` value needs `transport: tls`, unless `edge.allow_insecure_sdes` is `true`; `check` fails otherwise. Unlike a client, a carrier's transport is fixed, so the rule is checked at load. Restart-only, with the rest of `edge.carriers`.
- `ca_file`, `client_cert` and `client_key` are valid only with `transport: tls`, and `client_cert` and `client_key` come together. `ca_file` replaces the system roots for that carrier (it does not add to them). The server certificate is verified against `host` and fails closed; there is no option to skip verification. `check` does not open these files; startup (`run`) loads them and stops with a message naming the carrier if one is missing or malformed. All of `edge.carriers` is restart-only.

An entry must equal the `host[:port]` the switch puts in the Request-URI (FreeSWITCH gateway `proxy`, Asterisk aor `contact`). That equality is what makes a request a carrier request.

#### `edge.srtp`

The SDES-SRTP policy (RFC 4568) for the public leg of a call with a registered client: `off` (default), `optional` or `required`. `off` ignores `a=crypto` and keeps the leg plain RTP. The switch leg is always plain RTP. SDES is used on a client leg only when the client's signaling is TLS or WSS, decided per call by the transport the client registered over, unless `edge.allow_insecure_sdes` is set. A WebRTC leg (a client registered over `ws` or `wss`) is always DTLS-SRTP and ignores this key. Any other value is a validation error. Restart-only. Semantics: [SDES-SRTP on public legs](edge.md#sdes-srtp-on-public-legs).

#### `edge.allow_insecure_sdes`

Default `false`. SDES keys travel in the SDP, so with this off a leg whose signaling is not encrypted never uses SDES: `srtp: optional` then behaves as `off`, and `srtp: required` refuses every offer and answer with 488. Set it `true` only on a network where the signaling path is already protected (a VPN, a private link). It also lets a carrier with `transport: udp` or `tcp` have a non-`off` `srtp`. Restart-only.

#### `edge.carrier_sources`

Extra inbound carrier IPs or CIDRs, on top of the resolved addresses of `carriers`, which are sources implicitly. A `carriers` address is a source only on its carrier's transport (a `tls` carrier over UDP is not); a `carrier_sources` address matches on any public transport. A bare IP is a single-host prefix. Rules:

- Valid CIDR or IP.
- No wider than /8 (IPv4) or /32 (IPv6).
- An IPv4-mapped IPv6 entry (`::ffff:a.b.c.d/n`, n at least 96) is normalised to the IPv4 prefix; one that mixes mapped and native IPv6 space is rejected.
- Entries are stored in masked form.

A request from a `carrier_sources` address that matches no `carriers` entry gets `X-FreeSBC-Carrier: unknown`.

### `shield`

| Key | Default | Rules |
|---|---|---|
| `rate_limit` | `20/s per_ip` | Applies to every public source that is not a carrier. One token per UDP datagram, WS/WSS frame, TCP/TLS message started, and new stream connection, charged before parsing: malformed datagrams, responses and keepalives count too. |
| `carrier_rate_limit` | `200/s per_ip` | Applies to carrier sources (resolved `carriers` addresses and `carrier_sources`), charged the same way. |
| `ban` | `1h` | Duration, greater than 0. How long a source fingerprinted as a scanner stays banned (in memory only). Carrier sources are never banned as scanners. |
| `max_sessions` | the calls `rtp` can anchor | Integer, 0 or more. Global cap on calls holding a session slot: from the first out-of-dialog INVITE (ringing calls hold one) until the call is torn down by any path. 0 means the default, the `rtp` capacity (see `rtp`); an explicit value above that capacity is an error (`exceeds the N calls rtp a-b can anchor`). Counted across all four directions (client, carrier, switch to client, switch to carrier). Hot: applies to the next INVITE, running calls are never torn down, and lowering it below the running count refuses new calls until it drains. |
| `invite_rate_limit` | off | `<n>/<s|m|h>`, no `per_ip`: one global token bucket (burst `n`) charged once per new out-of-dialog INVITE that passed the session cap. Re-INVITEs and retransmissions are not charged. Empty is off. Hot. |

Rate limit syntax: `<n>/<s|m|h>` with an optional ` per_ip`; `n` is a positive integer. With `per_ip` each source (an IPv6 source by its /64) has its own token bucket; without it all sources share one bucket. Burst equals `n`.

An admitted peer (a registered client, a carrier or the switch) whose new INVITE is over `max_sessions` or `invite_rate_limit` gets `503 Service Unavailable` with `Retry-After` and costs no media port: `5` seconds for the session cap, `max(1, ceil(interval / n))` for the rate limit. They are counted in `freesbc_edge_invite_rejects_total{reason="session_cap"|"invite_rate"}`, and `freesbc_edge_sessions` is the current count. The reject is logged at WARN at most once per 10 s per reason. An unknown public source keeps the silent drop of INVITE admission. Per-carrier, per-user and per-source concurrency or rate, and a maximum call duration, stay on the switch (FreeSWITCH `limit` and `sched_hangup`, Asterisk `GROUP_COUNT()` and `TIMEOUT(absolute)`).

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
- Origin check: `POST /api/config/validate`, `POST /api/drain` and `DELETE /api/drain` (any method but GET, HEAD, OPTIONS) needs an `Origin` equal to `<scheme>://<Host>`, or no `Origin` and `Sec-Fetch-Site: same-origin`; otherwise `403`. The WebUI satisfies this by itself. A script must send the header:

  ```sh
  curl -u admin:PASSWORD -X POST -H 'Origin: http://127.0.0.1:8080' \
       --data-binary @freesbc.yaml http://127.0.0.1:8080/api/config/validate
  ```

- Auth model: HTTP Basic Auth stays. There is no logout and no idle timeout. The session ends when the browser forgets the credentials, and the server remembers credentials it has verified for 1 hour after their last use (`verifiedCredsTTL`). `/metrics` is scraped with Basic Auth as before.

`admin.listen` must not collide with `edge.listen.tcp` / `tls` / `ws` / `wss` on `public.bind` (the same TCP address and port). Generate a hash with `htpasswd -bnBC 10 "" 'pw' | tr -d ':\n'`.

`GET /api/drain` reports `{"draining", "since", "active_calls"}`; `POST` enters and `DELETE` leaves drain mode (idempotent, runtime state only, not a config key). While draining, new INVITEs get `503` with `Retry-After: 30` and are counted in `freesbc_edge_invite_rejects_total{reason="draining"}`; see `docs/edge.md`.

- Audit log: admin events (drain changes `drain_on` and `drain_off`, one per actual change, and sign-ins: `login_ok` on the first verification of a credential, `login_failed`, and `login_limited`, recorded once per lockout window per source rather than once per 429) go to the log as `admin audit` lines and into a 256-entry in-memory ring served by `GET /api/audit` and the WebUI's Audit tab; failures also count in `freesbc_admin_auth_failures_total{reason}`, where `rate_limited` counts every 429. A request with no `Authorization` header is not an event. Only the source IP is recorded (never the user, password, header or hash), and it is the connecting address: behind a reverse proxy that is the proxy's address, since `X-Forwarded-For` is not trusted.

`GET /api/config/raw` returns the file unredacted on purpose; `GET /api/config` masks `admin.password_hash`.

The config API is read-only. There is no write endpoint: edit the file, run `freesbc check -c freesbc.yaml`, and the watcher reloads it (see Reload classes). Any method other than GET on `/api/config` or `/api/config/raw` is `405` with an `Allow` header.

`POST /api/config/validate` checks a candidate without writing anything. The body is the candidate YAML file (at most 1 MiB, else `413`); it runs the same `config.Parse` as `freesbc check`, so an expanded `${VAR}` value never appears in an error. The response is always `200` JSON:

```json
{"valid": true, "errors": [], "restart_required": ["edge.listen"]}
```

`errors` lists the problems (`[]` when valid). `restart_required` lists the restart-only keys the candidate changes compared with the config the process started with (`[]` for none, and for an invalid candidate); see Reload classes. Any method other than POST is `405` with `Allow: POST`.

The WebUI's Config tab has a **Download config** button that fetches `/api/config/raw` fresh (never the candidate text) and saves the exact bytes as `freesbc-<host>-<UTC timestamp>.yaml`, for example `freesbc-127.0.0.1-8080-20261006T120000Z.yaml`. The file is not redacted: it contains `admin.password_hash` and any secret written as a literal, so store it like a credential. `${VAR}` references are saved as references, not values. Keep secrets as `${VAR}` references so a downloaded copy does not leak them.

## Reload classes

`config.Watch` watches the file's parent directory (200 ms debounce, symlink-aware) and publishes each valid file as an immutable snapshot. An invalid file is logged and the previous snapshot stays. FreeSBC never writes the file: the operator edits it (run `freesbc check` first) and the watcher does the reload.

| Setting | Class |
|---|---|
| `shield.rate_limit`, `shield.carrier_rate_limit`, `shield.ban`, `shield.max_sessions`, `shield.invite_rate_limit` | hot |
| `public`, `private`, `rtp`, `tls` | restart-only |
| `edge.switch`, `edge.switch_carrier_port`, `edge.listen`, `edge.carriers` (including each carrier's `srtp`), `edge.carrier_sources`, `edge.srtp`, `edge.allow_insecure_sdes` | restart-only |
| `admin` (every key, including `allowed_hosts`, and whether the section exists) | restart-only |

A reload that edits a restart-only setting is still published, so its hot settings apply, and logs a warning listing the changed keys (`config.RestartOnlyChanges`). The running process keeps its startup values for the restart-only settings until it restarts. The table in `restartOnly` (`internal/config/restart.go`) and `docs/design.md` §4.4 are the same list.

## Constants

Not configurable. They live in code until there is a concrete need to tune one.

| Value | Constant | Where |
|---|---|---|
| Private SIP port | 5060 | `config.PrivateSIPPort` |
| Default carrier port | 5060 (5061 for a `tls` carrier) | `config.DefaultCarrierPort`, `config.DefaultCarrierTLSPort` |
| Retry-After of a session-cap 503 | 5 s | `sessionCapRetryAfter`, `internal/edge/invite.go` |
| Session-cap and invite-rate WARN spacing | 10 s per reason | `capWarnEvery`, `internal/edge/invite.go` |
| RTP silence teardown | 5 min | `rtpSilenceTimeout`, `internal/edge/edge.go` |
| Switch node cooldown | 30 s | `switchCooldown`, `internal/edge/edge.go` |
| Carrier DNS cache | 300 s (10 s for a failed or empty lookup) | `carrierDNSTTL`, `carrierDNSNegTTL`, `internal/edge/carrierdns.go` |
| Carrier DNS lookup timeout | 3 s | `carrierLookupTimeout`, `internal/edge/carrierdns.go` |
| Admin user name | `admin` | `config.AdminUser` |

`docs/design.md` §15.2 lists every other timeout.
