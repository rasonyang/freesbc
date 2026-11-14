# Installing FreeSBC

FreeSBC is one static binary. It installs in one of three ways: the [install script](#install-script), a [release download](#release-download) checked by hand, or a [build from source](#build-from-source). After that, [`freesbc init`](#freesbc-init) writes a first config, and on Linux the [systemd unit](#run-as-a-systemd-service) runs it as a service. Every config key is in [config.md](config.md); the switch-side setup is in [edge.md](edge.md#switch-side-requirements).

> **Read before exposing FreeSBC to the public internet:** [design.md](design.md) (networking and deployment topology, security model) and [edge.md](edge.md) (switch-side requirements).

## Install script

```sh
curl -fsSL https://github.com/rasonyang/freesbc/releases/latest/download/install.sh | sh
```

`install.sh` is a release asset, so it always matches the release it comes from. It is published from the first release after v0.5.0; for v0.5.0 use the [release download](#release-download).

### What it does

1. Detects the OS (`linux` or `darwin`) and the CPU (`x86_64`/`amd64` as `amd64`, `aarch64`/`arm64` as `arm64`). Anything else exits with an error. It needs `curl` or `wget`, `tar`, `awk`, `mktemp`, and `sha256sum` or `shasum`; [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/) (v2.4.2 or later, v3 recommended) is optional and checks the signature.
2. Resolves the latest tag from the `releases/latest` redirect (no GitHub API call, so no rate limit), unless `FREESBC_VERSION` pins one.
3. Downloads `SHA256SUMS` into a temporary directory and, when `cosign` is installed, its signature `SHA256SUMS.sigstore.json`, and checks that `SHA256SUMS` was signed by this repository's release workflow (see [Integrity](#integrity); `FREESBC_VERIFY` controls it). Then it downloads `freesbc_<tag>_<os>_<arch>.tar.gz` and verifies the tarball's hash against `SHA256SUMS`. A bad signature or a mismatch exits non-zero and installs nothing.
4. Installs `freesbc` to `$FREESBC_PREFIX/bin` (default `/usr/local/bin`), using `sudo` only when that directory is not writable, and prints `freesbc version`. The new binary replaces the old one by a rename, so a running process is not disturbed; restart it to switch.
5. On Linux with systemd, run as root, unless `--no-service`: creates the `freesbc` system user and `/etc/freesbc` (mode 0750, `root:freesbc`), installs `/etc/systemd/system/freesbc.service` (with `ExecStart` pointing at `$FREESBC_PREFIX/bin`) and runs `systemctl daemon-reload`. It does **not** enable or start the service: the config needs addresses first. The layout is the one described in [Run as a systemd service](#run-as-a-systemd-service). Not root or no systemd, it skips this step and says why.
6. In that service step it never overwrites an existing `/etc/freesbc/freesbc.yaml`. When there is none and `FREESBC_SWITCH`, `FREESBC_PRIVATE_IP` and `FREESBC_PUBLIC_IP` are all set, it writes one with `freesbc init -c /etc/freesbc/freesbc.yaml`, sets it to `root:freesbc` mode 0640 and runs `freesbc check` on it. Piped from `curl`, stdin is not a terminal, so `init` cannot prompt; these variables are the only way to answer it.
7. Prints the next steps: with no config yet, `init`, `chown`/`chmod`, `check --deploy --local-addresses` and `systemctl enable --now freesbc`; with a config, `check --deploy --local-addresses` and `systemctl enable --now freesbc`; on a host whose `net.core.rmem_max` is below 8 MiB or `wmem_max` below 1 MiB (or unreadable), a sysctl drop-in line for each such cap and `sysctl -p` (see [UDP socket buffers](#udp-socket-buffers)) go before `systemctl enable --now freesbc`; without the service step, `init`, `check` and `run` on a local `freesbc.yaml`.

The whole body is in a `main()` function called on the last line, so a truncated download runs nothing. Running the script again is safe: it replaces the binary and the unit file and keeps the user, `/etc/freesbc` and the config. Put local unit changes in a drop-in (`systemctl edit freesbc`), which a re-run leaves alone.

### Options

| Flag | Effect |
|---|---|
| `--no-service` | Install the binary only; skip the user, `/etc/freesbc`, the unit and `init` |
| `--dry-run` | Download and verify as usual, then print every change (install, user, directory, unit, `systemctl`, `init`, `chown`, `chmod`) instead of making it |
| `-h`, `--help` | Print usage |

Through the pipe, pass flags after `sh -s --`:

```sh
curl -fsSL https://github.com/rasonyang/freesbc/releases/latest/download/install.sh | sh -s -- --no-service
```

| Environment | Default | Effect |
|---|---|---|
| `FREESBC_VERSION` | latest release | Install this tag, for example `v0.5.0` |
| `FREESBC_PREFIX` | `/usr/local` | Install the binary in `$FREESBC_PREFIX/bin` |
| `FREESBC_BASE_URL` | `https://github.com/rasonyang/freesbc/releases` | Download from a mirror, or a local file server for testing (files under `<base>/download/<tag>/`, the tag from `<base>/latest`) |
| `FREESBC_VERIFY` | `auto` | The signature check of `SHA256SUMS` (see [Integrity](#integrity)): `auto` checks it when `cosign` is installed and the release has a bundle, and says so when it does not; `require` fails when `cosign` or the bundle is missing; `off` skips it, for a mirror that does not carry the bundle. Any other value exits 2 |
| `FREESBC_SWITCH`, `FREESBC_PRIVATE_IP`, `FREESBC_PUBLIC_IP` | unset | All three set: write `/etc/freesbc/freesbc.yaml` with `freesbc init` in the service step (see step 6) |
| `FREESBC_PUBLIC_BIND`, `FREESBC_UDP_PORT` | unset | Read by that `init` as well (see [`freesbc init`](#freesbc-init)) |

A non-interactive install, as root, that leaves a checked config:

```sh
curl -fsSL https://github.com/rasonyang/freesbc/releases/latest/download/install.sh |
  FREESBC_SWITCH=10.77.0.10:5060 FREESBC_PRIVATE_IP=10.77.0.2 FREESBC_PUBLIC_IP=203.0.113.7 sh
```

### Integrity

`SHA256SUMS` lists the hash of every tarball and of `install.sh`, so one signature over it covers them all. The hash check alone catches a corrupted or truncated download, not a compromised release: whoever can replace a tarball can replace `SHA256SUMS` too. The signature closes that gap.

Every release after v0.6.1 signs `SHA256SUMS` with [Sigstore](https://www.sigstore.dev/) keyless signing: `release.yml` runs `cosign sign-blob` with the workflow's GitHub OIDC token, so no signing key exists to leak. Fulcio issues a short-lived certificate that names the workflow and the ref it ran from, the signature is logged in the public Rekor transparency log, and everything needed to verify it is in the release asset `SHA256SUMS.sigstore.json`. Releases up to v0.6.1 are unsigned.

A valid signature has:

- issuer `https://token.actions.githubusercontent.com`;
- identity `https://github.com/rasonyang/freesbc/.github/workflows/release.yml@refs/tags/<tag>` for a release made by pushing its tag, or `...release.yml@refs/heads/main` for a release built or rebuilt by hand (`release.yml` run from `main` with a `tag` input, to backfill one). Both are accepted by this regular expression, which `install.sh` and the commands below use:

  ```
  ^https://github\.com/rasonyang/freesbc/\.github/workflows/release\.yml@refs/(tags/v[^/]+|heads/main)$
  ```

  A run from any other branch is rejected, and so is any other repository or workflow file. `release.yml` verifies its own signature with the same expression before it uploads anything.

`install.sh` checks the signature before the tarball's hash, as `FREESBC_VERIFY` says. Under the default `auto`, it skips the check with a note when `cosign` is not installed or the release has no bundle. Use `FREESBC_VERIFY=require` to make either an error:

```sh
curl -fsSL https://github.com/rasonyang/freesbc/releases/latest/download/install.sh | FREESBC_VERIFY=require sh
```

`cosign` reads the bundle from v2.4.2 on (the first version that detects the protobuf bundle format without `--new-bundle-format`; v2.4.1 and older fail on it, so the check fails closed). Use v3 or later when you can: it is what `release.yml` signs with and what CI verifies with.

To check a release by hand:

```sh
v=v0.7.0 os=linux arch=amd64   # a release after v0.6.1; os: linux|darwin, arch: amd64|arm64
base=https://github.com/rasonyang/freesbc/releases/download/$v
curl -fsSLO $base/SHA256SUMS -O $base/SHA256SUMS.sigstore.json -O $base/freesbc_${v}_${os}_${arch}.tar.gz
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/rasonyang/freesbc/\.github/workflows/release\.yml@refs/(tags/v[^/]+|heads/main)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS   # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
```

`cosign` prints `Verified OK`, and the hash check prints `OK` for the tarball. Only then trust the tarball. The same works for a mirror: verify the files you got from it.

### Read it before running it

```sh
curl -fsSLo install.sh https://github.com/rasonyang/freesbc/releases/latest/download/install.sh
less install.sh
sh install.sh
```

`curl | sh` cannot check the script it is running, and neither can the script downloaded above. To run only a signed `install.sh`, take it from a release, check it against that release's signed `SHA256SUMS`, then run it pinned to the same release:

```sh
v=v0.7.0   # a release after v0.6.1
base=https://github.com/rasonyang/freesbc/releases/download/$v
curl -fsSLO $base/install.sh -O $base/SHA256SUMS -O $base/SHA256SUMS.sigstore.json
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/rasonyang/freesbc/\.github/workflows/release\.yml@refs/(tags/v[^/]+|heads/main)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS   # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
less install.sh
FREESBC_VERSION=$v FREESBC_VERIFY=require sh install.sh
```

## Release download

Each [release](https://github.com/rasonyang/freesbc/releases) carries `freesbc_<version>_<os>_<arch>.tar.gz` for linux and darwin on amd64 and arm64, plus `install.sh`, `SHA256SUMS` and (after v0.6.1) its signature `SHA256SUMS.sigstore.json`. Each archive holds the binary, the README, the license and `freesbc.example.yaml`; linux archives add `freesbc.service` (see [Run as a systemd service](#run-as-a-systemd-service)).

```sh
v=v0.5.0 os=linux arch=amd64   # os: linux|darwin, arch: amd64|arm64
curl -LO https://github.com/rasonyang/freesbc/releases/download/$v/freesbc_${v}_${os}_${arch}.tar.gz
curl -LO https://github.com/rasonyang/freesbc/releases/download/$v/SHA256SUMS
shasum -a 256 -c --ignore-missing SHA256SUMS   # Linux: sha256sum -c --ignore-missing SHA256SUMS
tar -xzf freesbc_${v}_${os}_${arch}.tar.gz && cd freesbc_${v}_${os}_${arch}
./freesbc check -c freesbc.example.yaml
```

The hash check alone only proves an intact download; to check the signature of `SHA256SUMS` first, see [Integrity](#integrity).

## Build from source

Requires Go >= 1.27.4:

```sh
go build -o freesbc ./cmd/freesbc
```

## `freesbc init`

`freesbc init -c <file>` writes a minimal config (mode 0600) and refuses to overwrite an existing file; it checks before asking anything. The generated file is validated with the same rules as `freesbc check` before it is written, so nothing invalid lands on disk.

```sh
freesbc init  -c freesbc.yaml        # asks for the switch, detects the addresses
freesbc check -c freesbc.yaml        # validate; errors name the line and key
freesbc run   -c freesbc.yaml
freesbc version                      # print the build version
```

### Prompts

On a terminal it prompts for each value not given by a flag or environment variable, showing a detected default that Enter accepts, in this order:

1. `edge.switch`: the switch, `IP[:port]` (port 5060 when omitted). No default; hostnames are not resolved.
2. `private.ip`: default, the local address that routes to the switch.
3. `public.bind`: default, the local address toward the default route.
4. `public.ip`: it first asks whether to look up the public address through `https://api.ipify.org` (Enter means yes). The lookup falls back to the EC2-compatible cloud instance metadata service, and with no answer the default is `public.bind` (a host with a direct public IP). `--no-public-lookup` or `--public-ip` skips the lookup.
5. `edge.listen.udp`: the public SIP UDP port, default 5060.
6. An optional admin password, read twice without echo and stored as a bcrypt hash (with `admin.listen: 127.0.0.1:8080`). Enter leaves out the `admin` section. A password is never taken from a flag or the environment.

`public.bind` is omitted from the file when it equals `public.ip`. When they differ (1:1 NAT), `init`, `check` and `run` print the ports your router must forward to `public.bind`: every `edge.listen` port and the `rtp` range, with the same numbers (see the [1:1 NAT checklist](config.md#11-nat-checklist)).

`init` fails if `private.ip` equals `public.bind` and `public.ip` equals them too: with no NAT the topology needs two addresses, one facing the switch and one facing the internet, so add a second IP or NIC (or a VLAN or loopback alias for the private side). Behind a 1:1 NAT (`public.ip` differs from `public.bind`) one address can serve both sides: `init` writes that layout when the detected `private.ip` and `public.bind` are the same private address, as it is on a single-NIC cloud host, with `edge.listen.udp` 5060 and a private switch address, and prints the single-IP note. The switch is then identified by its source IP; see [Single-IP host behind a 1:1 NAT](edge.md#single-ip-host-behind-a-11-nat). A second address remains the stronger layout.

### Without a terminal

When stdin is not a terminal, `init` never prompts: give flags or environment variables. Each value comes from the flag, then the environment variable, then the detected default; `edge.switch` has no default and is required.

```sh
freesbc init -c freesbc.yaml --switch 10.77.0.10:5060 \
    --private-ip 10.77.0.2 --public-ip 203.0.113.7 --public-bind 172.31.5.10
```

| Flag | Environment | Key | Default |
|---|---|---|---|
| `--switch IP[:port]` | `FREESBC_SWITCH` | `edge.switch` | required |
| `--private-ip` | `FREESBC_PRIVATE_IP` | `private.ip` | local address that routes to the switch |
| `--public-ip` | `FREESBC_PUBLIC_IP` | `public.ip` | looked up (ipify, then cloud metadata), else `public.bind` |
| `--public-bind` | `FREESBC_PUBLIC_BIND` | `public.bind` | local address toward the default route |
| `--udp-port N` | `FREESBC_UDP_PORT` | `edge.listen.udp` | 5060 |
| `--no-public-lookup` | | | look up `public.ip` |

Without a terminal the public address is looked up without asking, unless `--no-public-lookup` or a public IP is given.

Instead of `init`, you can copy the annotated `freesbc.example.yaml` and edit it by hand.

## Minimal config

Every key is documented in [config.md](config.md):

```yaml
public:
  ip: 203.0.113.7            # advertised to phones, browsers, carriers
private:
  ip: 10.77.0.2              # faces the switch
edge:
  switch: [10.77.0.10:5060]  # the switch, literal IP:port
  listen:
    udp: 5060                # ports on public.bind
```

`freesbc.yaml` is gitignored in this repository, since it may hold real addresses and a password hash. `-c` defaults to `freesbc.yaml`; a positional argument is a usage error (exit 2), so always pass `-c`.

## Run as a systemd service

The linux archives hold `freesbc.service` ([`packaging/freesbc.service`](../packaging/freesbc.service)), a systemd unit that runs FreeSBC as the unprivileged `freesbc` user, with `CAP_NET_BIND_SERVICE` for listen ports below 1024 (such as `wss: 443`) and a read-only filesystem. FreeSBC writes no files: logs go to stderr, so journald needs nothing.

The [install script](#install-script) does the first four steps below (the user, the binary, the unit and `/etc/freesbc`). By hand, as root, from the unpacked archive:

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin freesbc
install -m 0755 freesbc /usr/local/bin/freesbc
install -m 0644 freesbc.service /etc/systemd/system/freesbc.service
install -d -m 0750 -o root -g freesbc /etc/freesbc
/usr/local/bin/freesbc init -c /etc/freesbc/freesbc.yaml   # prompts on a terminal; in a script pass --switch etc.
chown root:freesbc /etc/freesbc/freesbc.yaml && chmod 0640 /etc/freesbc/freesbc.yaml
/usr/local/bin/freesbc check --deploy --local-addresses -c /etc/freesbc/freesbc.yaml   # TLS files and addresses
# raise only a cap below the request (UDP socket buffers); never lower a larger one
printf 'net.core.rmem_max = 8388608\nnet.core.wmem_max = 8388608\n' > /etc/sysctl.d/90-freesbc.conf
sysctl -p /etc/sysctl.d/90-freesbc.conf
systemctl enable --now freesbc
journalctl -u freesbc -f
```

`check --deploy --local-addresses` opens the TLS certificates and keys, carrier CA files and HEP TLS files the way `run` will, prints each certificate's subject, SANs, issuer and expiry (an expired one is an error, one under 30 days a warning), and checks `public.bind` and `private.ip` are assigned to this host. It binds no configured port and contacts no peer (an unaliased 127/8 address is probed with a bind on an ephemeral port, as `run` does), so it is safe next to a running instance; run it on the target host, as the `freesbc` user to prove the service can read the files (`sudo -u freesbc`). On Linux it also notes, without failing, a `net.core.rmem_max` or `wmem_max` below what the UDP SIP sockets request (see [UDP socket buffers](#udp-socket-buffers)). Plain `check` opens none of this, and a bad path would otherwise turn into a restart loop under `Restart=on-failure`. The config and any TLS cert and key it names must be readable by the `freesbc` group (`root:freesbc`, mode 0640), so the service can read but not change its own config. `init` writes mode 0600 owned by root, hence the `chown` and `chmod`. To start from the annotated `freesbc.example.yaml` instead of `init`, install it in place with `install -m 0640 -o root -g freesbc freesbc.example.yaml /etc/freesbc/freesbc.yaml` and edit the addresses.

### Environment file

For `${VAR}` values such as `admin.password_hash`, put `KEY=value` lines in `/etc/freesbc/freesbc.env` (same owner and mode, `root:freesbc` 0640); the unit reads it if present (`EnvironmentFile=-`). `freesbc check` does not read that file, so check such a config with (add `--deploy --local-addresses` as above):

```sh
env $(grep -v '^#' /etc/freesbc/freesbc.env) /usr/local/bin/freesbc check -c /etc/freesbc/freesbc.yaml
```

Do not `. freesbc.env` instead: the shell would expand the `$` in a bcrypt hash.

### UDP socket buffers

Many stock Linux hosts cap socket buffers at 212992 bytes (`net.core.rmem_max`, `wmem_max`), far below the 8 MiB receive and 1 MiB send buffer every UDP SIP socket requests, and the kernel then drops datagrams silently under bursts. The sysctl drop-in in the steps above (`/etc/sysctl.d/90-freesbc.conf`) raises them. Leave out a key that is already larger: never lower a cap. The install script prints a line only for each cap below the request, and `check --deploy` notes the shortfall on Linux without failing (exit code 0). A running socket keeps the size it got, so the drop-in takes effect only after the service is started or restarted. Details: [UDP socket buffers](edge.md#udp-socket-buffers).

### Tuning and reload

Buffer caps: see [UDP socket buffers](#udp-socket-buffers) above.

There is no `ExecReload` (FreeSBC has no SIGHUP handler): a `shield.*` edit reloads by itself when the file is saved, and any other key needs `systemctl restart freesbc`. A bad config or a bind error exits 1 and systemd retries every 5 s, so run `freesbc check` before a restart. The unit's comments cover `LimitNOFILE`, an optional `MemoryMax` with `GOMEMLIMIT`, and dropping the capability when no port is below 1024.

## Reload and signals

The config file is watched. A `shield` edit is validated and applied atomically; a bad edit never takes down the process, because the previous config stays active and the error is logged. Everything else (addresses, `rtp`, `tls`, `edge`, `admin`) is read once at startup: a reload that edits it is logged as a warning listing the keys, and the running process keeps its startup values until restarted. The reload classes are in [config.md](config.md#reload-classes).

On SIGINT or SIGTERM FreeSBC drops its calls with their media released; no BYE is sent. A second SIGINT or SIGTERM exits at once. To let calls finish before a restart, drain the node first (`POST /api/drain`, see [Restart and upgrade on one node](#restart-and-upgrade-on-one-node)).

## Restart and upgrade on one node

Use this for an upgrade, a rollback, a restart-only config change (everything except `shield.*`) or a renewed TLS certificate when there is one FreeSBC. With two nodes the other one takes the new calls during the drain: see "Rolling restart" in [two-node.md](two-node.md#rolling-restart).

What the drain does on one node ([edge.md](edge.md#admission-and-abuse-controls), Drain mode):

- **New carrier calls are refused** until the restart ends: carrier to switch and switch to carrier both get `503` + `Retry-After: 30`. The switch's gateway goes down or its dialplan falls through, and the carrier sees `503` too. An `OPTIONS` from a carrier source, from the switch to FreeSBC and from the switch to a carrier host also gets `503`, so a carrier that disables a trunk on failed pings may do so; check its policy first. This is a short outage by design. The drain's point is not to cut the calls that are already up. Pick a quiet time, and pause an outbound campaign (such as AI calling) before you start.
- **Client calls are not refused.** Registered-client calls, in both directions, are admitted while draining, and `active_calls` counts every confirmed call, clients included. A client on a long call keeps `active_calls` above 0, so decide the deadline with that in mind.
- **A stop drops what is still up.** SIGTERM drops every call and releases its media; no BYE is sent (see [Reload and signals](#reload-and-signals)). The far ends find out from their session timers or from RTP silence.

What a restart loses (all of it is in memory): client bindings (a client that holds a stream connection reconnects and registers again on its own, if its software does; a UDP client's calls are not admitted until it registers, up to its registration interval), the carrier registrations (the switch sends REGISTER again on its own timer; the `fsbc=` token is deterministic, so the same Contact is accepted again, but until then a carrier INVITE naming it is logged at WARN and falls back to the hash pool with the Request-URI unchanged), bans, subscriptions and the drain state (a restart starts not draining). A carrier `OPTIONS` is answered `200` again at once.

1. Note the running version (`curl` the admin API's `/api/status`, field `version`: `freesbc version` prints the binary on disk, not the process) and keep the current binary: `cp -p /usr/local/bin/freesbc /usr/local/bin/freesbc.prev`.
2. Install the new binary: `curl -fsSL https://github.com/rasonyang/freesbc/releases/latest/download/install.sh | sh`, or `... | FREESBC_VERSION=vX.Y.Z sh` for a tag. The running process is not disturbed. As root on systemd the script also rewrites the unit file and runs `systemctl daemon-reload`; it does not restart anything.
3. Check the config with the new binary, as the service user, so a problem fails now and not during the outage: `sudo -u freesbc /usr/local/bin/freesbc check --deploy --local-addresses -c /etc/freesbc/freesbc.yaml` (with an environment file, run it as in [Environment file](#environment-file)). `--deploy` opens the TLS, CA and HEP files the way `run` does, which plain `check` does not; it binds no configured port, so it is safe next to the running process. Stop here on a failure: nothing has been refused yet.
4. Run the script below. It drains, waits for `active_calls` to reach 0 until its deadline, restarts, and prints the running version and the drain state. At the deadline it stops without restarting and leaves the drain on, and you choose: restart anyway (every call still up is dropped, as above), or `DELETE /api/drain` to go back to normal.
5. Make one test call, through each path you use (carrier and client).
6. To roll back, install the previous release (`... | FREESBC_VERSION=<previous tag> sh`; a release up to v0.6.1 has no signature bundle; the default `FREESBC_VERIFY=auto` says so and goes on) or copy `freesbc.prev` back over `/usr/local/bin/freesbc`, then repeat steps 3 to 5. A downgrade needs no config change unless a key was added in between: strict YAML makes the old binary's `check` reject it (an unknown key), and the check says which.

```sh
#!/bin/sh
# Drain, wait for the calls to end, restart, verify. Run as root.
set -eu

ADMIN=http://127.0.0.1:8080          # admin.listen; scheme and host:port as in the Host header
PASSWORD=${FREESBC_ADMIN_PASSWORD:?set FREESBC_ADMIN_PASSWORD}
DEADLINE=300                         # seconds to wait for active_calls to reach 0
HEALTH_WAIT=60                       # seconds to wait for the admin API after the restart

# The password goes to curl on stdin, not on its command line.
api() {
  printf 'user = "admin:%s"\n' "$PASSWORD" | curl -fsS -K - -H "Origin: $ADMIN" "$@"
}
field() { sed -n "s/.*\"$1\": *\"\{0,1\}\([^\",}]*\).*/\1/p" | head -n 1; }

echo "running version: $(api "$ADMIN/api/status" | field version)"
api -X POST "$ADMIN/api/drain" >/dev/null
echo "draining: new carrier calls get 503 until the restart ends"

waited=0
while :; do
  calls=$(api "$ADMIN/api/drain" | field active_calls)
  [ "$calls" = 0 ] && break
  if [ "$waited" -ge "$DEADLINE" ]; then
    echo "deadline: $calls call(s) still up; not restarting, still draining" >&2
    echo "restart anyway: systemctl restart freesbc  (drops those calls, no BYE)" >&2
    echo "back out:       curl -X DELETE -H 'Origin: $ADMIN' -u admin $ADMIN/api/drain" >&2
    exit 1
  fi
  sleep 5
  waited=$((waited + 5))
done

systemctl restart freesbc

waited=0
until api "$ADMIN/api/health" >/dev/null 2>&1; do
  [ "$waited" -ge "$HEALTH_WAIT" ] && { echo "admin API not back after ${HEALTH_WAIT}s" >&2; exit 1; }
  sleep 2
  waited=$((waited + 2))
done
echo "running version: $(api "$ADMIN/api/status" | field version)"
echo "draining: $(api "$ADMIN/api/drain" | field draining)   (must be false)"
```

The unit has `Restart=on-failure`, so a restart that fails to start is retried every 5 s and the health wait times out: read `journalctl -u freesbc`.
