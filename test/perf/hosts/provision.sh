#!/usr/bin/env bash
# Provision one host of the 3-host rehearsal rig (Ubuntu 24.04 x86_64). Run it
# with sudo from the repository checkout at /opt/freesbc, as ecs-user:
#   ssh ecs-B 'sudo /opt/freesbc/test/perf/hosts/provision.sh sbc'
#
#   provision.sh loadgen         load generator: SIPp 3.6.1, webrtcload, secondary IPs
#   provision.sh sbc             FreeSBC host: Go, freesbc, second ENI (eth1, private vSwitch), service
#   provision.sh switch          switch host: SIPp, FreeSWITCH (docker.io from apt), Asterisk
#   provision.sh pi              optional: Node 22 + the pi agent (pi is already installed on the rig, not needed)
#   provision.sh authkey         fallback only: read ssh public keys from stdin into the ops user's authorized_keys (normal ssh uses ~/.ssh/aicc-dev-ecs.pem)
#   provision.sh fetch-sipp      download the SIPp tarball to /var/tmp (sha256 checked), for hosts without github access
#   provision.sh check           the self-check alone (PASS/FAIL per item)
#   provision.sh egress-gw [undo]      on A: NAT gateway for C's internet egress (OS route path)
#   provision.sh egress-client [undo]  on C: default route via A, tested, rolled back on failure
#   provision.sh proxy-gw [undo]       on A: HTTP(S) proxy (tinyproxy) for C
#   provision.sh proxy-client [undo]   on C: apt, docker, curl/git/go, npm and pi use that proxy
#
# Every address comes from plan.env (next to this script, or $PLAN_ENV). Roles
# refuse to run while plan.env still holds a __ASSIGN_IN_CONSOLE__ placeholder.
# Idempotent: re-run it after a spot instance is recreated, or after editing
# plan.env (the templates are rendered again into /etc/perf-kit). It ends with
# the self-check and exits 1 when any item is FAIL.
#
# Environment (all optional):
#   GOPROXY         default https://goproxy.cn,direct (proxy.golang.org is unreachable in mainland China)
#   GO_DL           default https://golang.google.cn/dl
#   FS_IMAGE        the FreeSWITCH image, default safarov/freeswitch:latest. It is pulled
#                   through the registry mirror of plan.env (DOCKER_REGISTRY_MIRROR).
#   FS_IMAGE_PULL   optional: pull this reference instead and retag it to FS_IMAGE
#   FS_IMAGE_TAR    a `docker save` tarball of FS_IMAGE (default /var/tmp/freeswitch-image.tar.gz,
#                   used first when present): the fallback when no registry works
#   DOCKER_REGISTRY_MIRROR (plan.env) registry-mirrors URL for
#                   /etc/docker/daemon.json, the account accelerator from the Alibaba console
#                   (容器镜像服务 -> 镜像加速器). Empty: daemon.json is not touched.
#   NPM_REGISTRY    npm registry for the pi install (default: npm's own)
#   ASTERISK_USERS  users per prefix (u, w) in Asterisk's pjsip, default 200, max 500
#   FREESBC_VERSION value for -X main.version, default perf-<COMMIT> (the COMMIT file the rsync writes), else perf-unknown
#   OPS_USER        the user that runs run.sh and owns ssh between hosts, default ecs-user
#                   (the login user, which already has passwordless sudo). Any other name is
#                   created with a sudoers file; PERFOPS_PASSWORDLESS_SUDO=0 skips that file.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
PERF=$REPO/test/perf
ROLE=${1:-}
ARG2=${2:-}
PLAN_ENV=${PLAN_ENV:-$HERE/plan.env}
KIT=/etc/perf-kit

SIPP_VERSION=3.6.1
SIPP_SHA256=6a560e83aff982f331ddbcadfb3bd530c5896cd5b757dd6eb682133cc860ecb1
SIPP_URL=https://github.com/SIPp/sipp/releases/download/v$SIPP_VERSION/sipp-$SIPP_VERSION.tar.gz
SIPP_LOCAL=/var/tmp/sipp-$SIPP_VERSION.tar.gz
GO_DL=${GO_DL:-https://golang.google.cn/dl}
GOPROXY=${GOPROXY:-https://goproxy.cn,direct}
FS_IMAGE=${FS_IMAGE:-safarov/freeswitch:latest}
FS_IMAGE_PULL=${FS_IMAGE_PULL:-}
FS_IMAGE_TAR=${FS_IMAGE_TAR:-/var/tmp/freeswitch-image.tar.gz}
FS_CONF=/opt/freeswitch/conf
FS_SPS=${FS_SPS:-5000}                  # sessions-per-second (formal run: 1000+ CPS)
FS_MAX_SESSIONS=${FS_MAX_SESSIONS:-30000}
FS_RTP_START=${FS_RTP_START:-20000}     # does not overlap Asterisk (10000-10999) or SIPp (6000-6999)
FS_RTP_END=${FS_RTP_END:-59999}
FS_NAME=freeswitch-perf
ASTERISK_USERS=${ASTERISK_USERS:-200}
FREESBC_VERSION=${FREESBC_VERSION:-perf-$(cat "$REPO/COMMIT" 2>/dev/null || echo unknown)}
OPS_USER=${OPS_USER:-ecs-user}
PROXY_PORT=3128

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
warn() { log "WARNING: $*"; }
die() { log "ERROR: $*"; exit 1; }
usage() { sed -n '2,/^set -eu/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

case $ROLE in
loadgen | sbc | switch | pi | authkey | fetch-sipp | check | egress-gw | egress-client | proxy-gw | proxy-client) ;;
-h | --help | help | "") usage; exit 0 ;;
*) usage >&2; exit 2 ;;
esac

[ "$(id -u)" -eq 0 ] || die "run with sudo (sudo $0 $ROLE)"
# shellcheck disable=SC1091
. /etc/os-release
[ "${VERSION_ID:-}" = "24.04" ] || log "WARNING: written for Ubuntu 24.04, this is ${PRETTY_NAME:-unknown}"
[ "$(uname -m)" = x86_64 ] || die "x86_64 only (SIPp pcap build, Go tarball, FreeSWITCH image)"

# ---- the address plan -----------------------------------------------------
[ -f "$PLAN_ENV" ] || die "no plan file $PLAN_ENV"
# shellcheck disable=SC1090
. "$PLAN_ENV"
B_PRIV_ADDR_MODE=${B_PRIV_ADDR_MODE:-static}
B_GOMEMLIMIT=${B_GOMEMLIMIT:-6GiB}
B_MEMORY_MAX=${B_MEMORY_MAX:-}
DOCKER_REGISTRY_MIRROR=${DOCKER_REGISTRY_MIRROR:-${DOCKER_MIRROR:-}}
placeholder() { case ${1:-} in "" | __ASSIGN_IN_CONSOLE__) return 0 ;; esac; return 1; }
require_plan() { # VAR...
	for v in "$@"; do
		placeholder "${!v:-}" && die "$v in $PLAN_ENV is empty or still __ASSIGN_IN_CONSOLE__: create it in the console and write the value there (STEPS.md R01)"
	done
	return 0
}
case $ROLE in
authkey | fetch-sipp) ;;
egress-gw | egress-client | proxy-gw | proxy-client) require_plan A_IP C_IP SUBNET_CIDR NET_IF ;;
*) require_plan SUBNET_CIDR PREFIX_LEN PRIV_SUBNET_CIDR PRIV_PREFIX_LEN A_IP A_CARRIERGEN_IP A_CARRIER_UAS_IP B_PUB_IP B_PRIV_IP C_IP NET_IF A_EXTRA_IF B_PRIV_IF ;;
esac
case $ROLE in
loadgen | sbc | switch | pi | check)
	if [ "$REPO" != /opt/freesbc ]; then
		die "the checkout must be /opt/freesbc (REMOTE_PERF=/opt/freesbc/test/perf); this one is $REPO"
	fi ;;
esac
# Refuse to run a role on the wrong host (a swapped ssh alias would misconfigure it).
case $ROLE in
loadgen) want=$A_IP ;;
sbc) want=$B_PUB_IP ;;
switch) want=$C_IP ;;
*) want= ;;
esac
if [ -n "$want" ] && ! ip -o -4 addr show | grep -q " $want/"; then
	die "role $ROLE expects this host to own $want (from $PLAN_ENV), but it is not assigned here: wrong host or a swapped ssh alias (STEPS.md R00). Nothing was changed."
fi
# plan sanity: addresses inside their vSwitches
in_cidr() { python3 -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2], strict=False) else 1)' "$1" "$2"; }
case $ROLE in
loadgen | sbc | switch | check)
	command -v python3 >/dev/null 2>&1 || { apt-get update -y >/dev/null 2>&1; apt-get install -y python3 >/dev/null 2>&1; }
	in_cidr "$A_IP" "$SUBNET_CIDR" || die "A_IP $A_IP is not inside SUBNET_CIDR $SUBNET_CIDR ($PLAN_ENV)"
	in_cidr "$B_PUB_IP" "$SUBNET_CIDR" || die "B_PUB_IP $B_PUB_IP is not inside SUBNET_CIDR $SUBNET_CIDR ($PLAN_ENV)"
	in_cidr "$B_PRIV_IP" "$PRIV_SUBNET_CIDR" || die "B_PRIV_IP $B_PRIV_IP is not inside PRIV_SUBNET_CIDR $PRIV_SUBNET_CIDR ($PLAN_ENV)"
	in_cidr "$C_IP" "$PRIV_SUBNET_CIDR" || die "C_IP $C_IP is not inside PRIV_SUBNET_CIDR $PRIV_SUBNET_CIDR ($PLAN_ENV)"
	# B's two NICs must sit in different vSwitches (ALLOW_SAME_SUBNET=1 keeps the rehearsal layout)
	if [ "${ALLOW_SAME_SUBNET:-0}" != 1 ] && { in_cidr "${PRIV_SUBNET_CIDR%/*}" "$SUBNET_CIDR" || in_cidr "${SUBNET_CIDR%/*}" "$PRIV_SUBNET_CIDR"; }; then
		die "PRIV_SUBNET_CIDR $PRIV_SUBNET_CIDR overlaps SUBNET_CIDR $SUBNET_CIDR: B's eth0 and eth1 must be in different vSwitches ($PLAN_ENV)"
	fi
	case $B_PRIV_ADDR_MODE in static | dhcp) ;; *) die "B_PRIV_ADDR_MODE must be static or dhcp ($PLAN_ENV)" ;; esac ;;
esac
SYNC_USER=${SUDO_USER:-root}
export DEBIAN_FRONTEND=noninteractive
# proxy-client writes /etc/environment; honor it in this script too
if [ -r /etc/environment ]; then set -a; . /etc/environment; set +a; fi

# ---------------------------------------------------------------- helpers
need_reach() { # LABEL URL: fail fast with a pointer to the STEPS.md
	curl -sS -m 8 -o /dev/null "$2" 2>/dev/null || die "cannot reach $1 ($2). This host has no (or a blocked) route to it: see STEPS.md R00 and the appendix on egress without a public IP. Nothing was changed for this step."
}

apt_update_once() {
	[ -z "${APT_UPDATED:-}" ] || return 0
	apt-get update -y >/dev/null 2>&1 || die "apt-get update failed: the apt mirror is unreachable from this host (STEPS.md R00 / appendix)"
	APT_UPDATED=1
}
apt_install() { apt-get install -y --no-install-recommends "$@" >/dev/null; }

base_packages() {
	log "base packages"
	apt_update_once
	apt_install ca-certificates curl wget git rsync openssh-client openssh-server procps iproute2 \
		bsdextrautils jq openssl python3 tar xz-utils gzip perl
}

iface_has() { ip -o -4 addr show dev "$NET_IF" | grep -q " $1/"; }
has_ip() { ip -o -4 addr show | grep -q " $1/"; }

render_kit() {
	log "render templates from plan.env into $KIT"
	rm -rf "$KIT"
	mkdir -p "$KIT"
	PLAN_ENV=$PLAN_ENV "$HERE/render.sh" "$KIT"
	chmod -R a+rX "$KIT"
}

sysctl_setup() {
	log "sysctl: rmem_max/wmem_max/rmem_default 8388608, backlog, ephemeral ports 60000-65535"
	cat >/etc/sysctl.d/90-freesbc-perf.conf <<-'EOF'
		# FreeSBC asks for 4 MiB receive / 1 MiB send per UDP SIP socket; the kernel caps it.
		net.core.rmem_max = 8388608
		net.core.wmem_max = 8388608
		# Thousands of RTP flows: deeper input queues, more UDP memory (pages).
		net.core.netdev_max_backlog = 50000
		net.ipv4.udp_mem = 786432 1048576 1572864
		# RTP ranges run up to 59999 (FreeSBC 10000-59999, FreeSWITCH 20000-59999);
		# keep the kernel's outgoing TCP source ports out of them.
		net.ipv4.ip_local_port_range = 60000 65535
		# SIPp 3.6.1 ignores -rtp_buffsize: at the 208 KiB default C's -rtp_echo
		# socket dropped ~10% of 50k pps (2026-10-18). Applies to new sockets on
		# all three hosts, FreeSBC's RTP sockets on B included (noted in the report).
		net.core.rmem_default = 8388608
	EOF
	sysctl -q --system >/dev/null
}

limits_setup() {
	log "nofile 1048576 (PAM sessions and systemd services)"
	cat >/etc/security/limits.d/90-freesbc-perf.conf <<-'EOF'
		* soft nofile 1048576
		* hard nofile 1048576
		root soft nofile 1048576
		root hard nofile 1048576
		* soft nproc unlimited
		* hard nproc unlimited
	EOF
	mkdir -p /etc/systemd/system.conf.d
	cat >/etc/systemd/system.conf.d/90-freesbc-perf.conf <<-'EOF'
		[Manager]
		DefaultLimitNOFILE=1048576
		DefaultLimitNPROC=infinity
	EOF
	systemctl daemon-reexec
}

# Every host carries the shared key ~/.ssh/aicc-dev-ecs.pem (placed by the operator,
# never created or printed here). Fix a loose mode; report loudly when it is missing.
ssh_pem_check() {
	pem="$1/.ssh/aicc-dev-ecs.pem"
	if [ ! -f "$pem" ]; then
		warn "MISSING $pem: ssh between hosts will not work until the operator copies it here (mode 600, owner $OPS_USER)"
		return 0
	fi
	if [ "$(stat -c %a "$pem")" != 600 ]; then
		chmod 600 "$pem"
		log "set $pem to mode 600"
	fi
	chown "$OPS_USER:$OPS_USER" "$pem"
}

# A stale ~/.ssh/aicc-dev-ecs.pem.pub that does not belong to the pem makes OpenSSH
# offer the wrong public key first and ssh between the hosts fails. 0 = fine
# (no .pub, or it matches); 1 = mismatch.
pem_pub_ok() {
	pem="/home/$OPS_USER/.ssh/aicc-dev-ecs.pem"
	[ -f "$pem" ] && [ -f "$pem.pub" ] || return 0
	want=$(ssh-keygen -y -P "" -f "$pem" 2>/dev/null | awk '{print $1 " " $2}')
	have=$(awk '{print $1 " " $2; exit}' "$pem.pub")
	[ -n "$want" ] || return 0   # unreadable or encrypted pem: nothing to compare
	[ "$want" = "$have" ]
}

ensure_ops_user() {
	log "user $OPS_USER"
	if ! id "$OPS_USER" >/dev/null 2>&1; then
		[ "$OPS_USER" != ecs-user ] || die "user ecs-user does not exist on this host (set OPS_USER=<login user>)"
		useradd -m -s /bin/bash "$OPS_USER"
	fi
	# ecs-user already has passwordless sudo from the image; another user gets a sudoers file.
	if [ "$OPS_USER" != ecs-user ] && [ "${PERFOPS_PASSWORDLESS_SUDO:-1}" = 1 ]; then
		# Throwaway rehearsal instances: the agent and the operator need root for
		# systemctl, docker, sysctl checks. Do not copy this to a real host.
		printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$OPS_USER" >/etc/sudoers.d/90-$OPS_USER
		chmod 0440 /etc/sudoers.d/90-$OPS_USER
	fi
	home=$(getent passwd "$OPS_USER" | cut -d: -f6)
	install -d -m 700 -o "$OPS_USER" -g "$OPS_USER" "$home/.ssh"
	touch "$home/.ssh/authorized_keys"
	# the operator's own key (the one that logged in as the sudo user, or root) works for OPS_USER too
	for src in "/home/$SYNC_USER/.ssh/authorized_keys" /home/ecs-user/.ssh/authorized_keys /root/.ssh/authorized_keys; do
		[ -s "$src" ] || continue
		[ "$src" != "$home/.ssh/authorized_keys" ] || continue
		while IFS= read -r k; do
			[ -n "$k" ] && ! grep -qxF "$k" "$home/.ssh/authorized_keys" && printf '%s\n' "$k" >>"$home/.ssh/authorized_keys"
		done <"$src"
	done
	ssh_pem_check "$home"
	pem_pub_ok || warn "$home/.ssh/aicc-dev-ecs.pem.pub does not match the pem (OpenSSH would offer the wrong key): mv $home/.ssh/aicc-dev-ecs.pem.pub $home/.ssh/aicc-dev-ecs.pem.pub.stale"
	# keep any existing ~/.ssh/config: install the kit's aliases as an include
	if [ -f "$KIT/ssh_config" ]; then
		install -d -m 700 -o "$OPS_USER" -g "$OPS_USER" "$home/.ssh/config.d"
		install -m 600 -o "$OPS_USER" -g "$OPS_USER" "$KIT/ssh_config" "$home/.ssh/config.d/perf-kit"
		touch "$home/.ssh/config"
		if ! grep -qxF 'Include config.d/perf-kit' "$home/.ssh/config"; then
			{ printf 'Include config.d/perf-kit\n'; cat "$home/.ssh/config"; } >"$home/.ssh/config.new"
			mv "$home/.ssh/config.new" "$home/.ssh/config"
		fi
		chmod 600 "$home/.ssh/config"
		chown "$OPS_USER:$OPS_USER" "$home/.ssh/config"
	fi
	chmod 600 "$home/.ssh/authorized_keys"
	chown "$OPS_USER:$OPS_USER" "$home/.ssh/authorized_keys"
}

layout() {
	log "layout: $PERF, results, out"
	echo "$1" >/etc/perf-role
	# the checkout stays owned by the user that rsyncs it; OPS_USER owns what it writes
	if [ "$SYNC_USER" != root ]; then chown -R "$SYNC_USER" "$REPO" 2>/dev/null || true; fi
	install -d -m 755 "$REPO/results/$1" "$PERF/out"
	chown -R "$OPS_USER:$OPS_USER" "$REPO/results" "$PERF/out"
	chmod +x "$PERF"/run.sh "$PERF"/sample.sh "$HERE"/*.sh "$HERE"/freesbc-use 2>/dev/null || true
}

# init_progress: the cross-day checkpoint, created once (never overwritten).
init_progress() {
	[ -f "$REPO/results/progress.md" ] && return 0
	cp "$HERE/progress.template.md" "$REPO/results/progress.md"
	chown "$OPS_USER:$OPS_USER" "$REPO/results/progress.md"
}

# extra_ips TAG IFACE PRIMARY_IP EXTRA_IP... : give the extra addresses to IFACE.
#
# Case 1, IFACE is NET_IF (the primary ENI): the extras are secondary IPs on it;
# netplan merges them with cloud-init's DHCP file by interface id.
#
# Case 2, IFACE is another interface (a second ENI in the same vSwitch): it gets
# the extras as static addresses and no default route. Both NICs then sit in one
# subnet, which breaks plain routing, so this adds (a) source-based policy
# routing: a packet sourced from an ENI's address leaves through that ENI (table
# 100 for PRIMARY_IP via NET_IF, table 101 for the extras via IFACE), because the
# VPC drops a packet whose source is not the sending ENI's address; (b) rp_filter=2
# (loose) so replies and requests that arrive on the "other" NIC are not dropped
# by the strict reverse-path check; (c) arp_ignore=1/arp_announce=2 so each NIC
# answers ARP only for its own addresses.
extra_ips() {
	tag=$1 iface=$2 primary=$3; shift 3
	ip link show "$iface" >/dev/null 2>&1 || die "interface $iface does not exist: fix NET_IF/A_EXTRA_IF/B_PRIV_IF in $PLAN_ENV (STEPS.md R00 shows the names)"
	ip link show "$NET_IF" >/dev/null 2>&1 || die "interface $NET_IF does not exist: fix NET_IF in $PLAN_ENV"
	addrs=""
	for a in "$@"; do addrs="$addrs, $a/$PREFIX_LEN"; done
	addrs=${addrs#, }
	f=/etc/netplan/61-perf-$tag.yaml
	if [ "$iface" = "$NET_IF" ]; then
		cat >"$f" <<-EOF
			network:
			  version: 2
			  ethernets:
			    $iface:
			      addresses: [$addrs]
		EOF
		chmod 600 "$f"
		netplan generate
		# take effect now without bouncing the interface; netplan applies it at boot
		for a in "$@"; do ip addr replace "$a/$PREFIX_LEN" dev "$iface"; done
		return 0
	fi
	log "$tag: second NIC $iface in the same subnet: static address, no default route, source-based routing"
	gw=$(ip -4 route show default dev "$NET_IF" | awk '{print $3; exit}')
	[ -n "$gw" ] || die "no default route on $NET_IF (needed for the policy table)"
	{
		echo "network:"
		echo "  version: 2"
		echo "  ethernets:"
		echo "    $NET_IF:"
		echo "      routes:"
		echo "        - to: $SUBNET_CIDR"
		echo "          scope: link"
		echo "          table: 100"
		echo "        - to: default"
		echo "          via: $gw"
		echo "          table: 100"
		echo "      routing-policy:"
		echo "        - from: $primary"
		echo "          table: 100"
		echo "    $iface:"
		echo "      dhcp4: false"
		echo "      dhcp6: false"
		echo "      optional: true"
		echo "      addresses: [$addrs]"
		echo "      routes:"
		echo "        - to: $SUBNET_CIDR"
		echo "          scope: link"
		echo "          table: 101"
		echo "      routing-policy:"
		for a in "$@"; do
			echo "        - from: $a"
			echo "          table: 101"
		done
	} >"$f"
	chmod 600 "$f"
	netplan generate
	ip link set "$iface" up
	for a in "$@"; do ip addr replace "$a/$PREFIX_LEN" dev "$iface"; done
	# runtime copy of the netplan routes and rules (idempotent)
	ip route replace "$SUBNET_CIDR" dev "$NET_IF" src "$primary" table 100
	ip route replace default via "$gw" dev "$NET_IF" table 100
	ip route replace "$SUBNET_CIDR" dev "$iface" table 101
	ip rule show | grep -q "from $primary lookup 100" || ip rule add from "$primary" table 100
	for a in "$@"; do ip rule show | grep -q "from $a lookup 101" || ip rule add from "$a" table 101; done
	cat >/etc/sysctl.d/92-perf-multihome.conf <<-EOF
		net.ipv4.conf.all.rp_filter = 2
		net.ipv4.conf.default.rp_filter = 2
		net.ipv4.conf.$NET_IF.rp_filter = 2
		net.ipv4.conf.$iface.rp_filter = 2
		net.ipv4.conf.all.arp_ignore = 1
		net.ipv4.conf.all.arp_announce = 2
	EOF
	sysctl -q -p /etc/sysctl.d/92-perf-multihome.conf
}

# private_nic: B's second ENI (B_PRIV_IF) sits in the private vSwitch, a different
# subnet from eth0. It gets B_PRIV_IP as a static address (or by DHCP) and no
# default route: the connected route to PRIV_SUBNET_CIDR is all FreeSBC's private
# plane needs (it talks to C only), and eth0 keeps the default route. Different
# subnets mean no asymmetric routing, so no policy routing and no rp_filter or
# arp tricks (extra_ips keeps those for the case where both NICs share a subnet).
private_nic() {
	iface=$B_PRIV_IF
	ip link show "$iface" >/dev/null 2>&1 || die "interface $iface does not exist: attach B's second ENI (private vSwitch) in the console, or fix B_PRIV_IF in $PLAN_ENV (STEPS.md R01, R00)"
	[ "$iface" != "$NET_IF" ] || die "B_PRIV_IF must be a different interface than NET_IF when the private vSwitch is a separate subnet"
	log "private NIC $iface: $B_PRIV_IP/$PRIV_PREFIX_LEN ($B_PRIV_ADDR_MODE), no default route"
	rm -f /etc/netplan/61-perf-b-priv.yaml   # the same-subnet layout of an earlier run
	f=/etc/netplan/62-perf-b-priv.yaml
	{
		echo "network:"
		echo "  version: 2"
		echo "  ethernets:"
		echo "    $iface:"
		echo "      dhcp6: false"
		echo "      optional: true"
		if [ "$B_PRIV_ADDR_MODE" = dhcp ]; then
			echo "      dhcp4: true"
			echo "      dhcp4-overrides:"
			echo "        use-routes: false"
			echo "        use-dns: false"
		else
			echo "      dhcp4: false"
			echo "      addresses: [$B_PRIV_IP/$PRIV_PREFIX_LEN]"
		fi
	} >"$f"
	chmod 600 "$f"
	netplan generate
	ip link set "$iface" up
	ip addr replace "$B_PRIV_IP/$PRIV_PREFIX_LEN" dev "$iface"   # now; netplan applies it at boot
	ip route del default dev "$iface" 2>/dev/null || true
	while ip rule del from "$B_PRIV_IP" 2>/dev/null; do :; done
}

# SIPp's play_pcap_audio opens a raw IPv4 socket; without CAP_NET_RAW it exits 255.
sipp_setcap() {
	apt_update_once
	apt_install libcap2-bin
	setcap cap_net_raw+ep "$(readlink -f "$(command -v sipp)")"
	log "sipp: $(getcap "$(readlink -f "$(command -v sipp)")")"
}

install_sipp() {
	if command -v sipp >/dev/null 2>&1 && sipp -v 2>&1 | grep -q "$SIPP_VERSION" && sipp -v 2>&1 | grep -qi pcap; then
		log "SIPp $SIPP_VERSION with pcap already installed"
		sipp_setcap
		return 0
	fi
	log "SIPp $SIPP_VERSION: build with pcap play (about 3 to 5 minutes)"
	apt_update_once
	apt_install build-essential cmake pkg-config libpcap-dev libgsl-dev libncurses-dev
	if ! (
		set -e
		src=/usr/local/src
		mkdir -p $src
		cd $src
		rm -rf sipp-$SIPP_VERSION sipp-$SIPP_VERSION.tar.gz
		if [ -s "$SIPP_LOCAL" ]; then cp "$SIPP_LOCAL" sipp-$SIPP_VERSION.tar.gz; else curl -fsSL -m 120 -o sipp-$SIPP_VERSION.tar.gz "$SIPP_URL"; fi
		echo "$SIPP_SHA256  sipp-$SIPP_VERSION.tar.gz" | sha256sum -c - >/dev/null
		tar xzf sipp-$SIPP_VERSION.tar.gz
		cd sipp-$SIPP_VERSION
		cmake . -DUSE_PCAP=1 -DUSE_GSL=1 -DUSE_SSL=0 -DUSE_SCTP=0 >/dev/null
		make -j"$(nproc)" sipp >/dev/null
		install -m 755 sipp /usr/local/bin/sipp
	); then
		log "WARNING: source build failed (no github access? put the tarball at $SIPP_LOCAL); falling back to Ubuntu's sip-tester package (version differs)"
		apt_install sip-tester
		[ -x /usr/local/bin/sipp ] || ln -sf "$(command -v sipp)" /usr/local/bin/sipp
	fi
	sipp_setcap
}

install_go() {
	want=$(awk '/^go /{print $2; exit}' "$REPO/go.mod")
	[ -n "$want" ] || die "no go directive in $REPO/go.mod"
	if [ -x /usr/local/go/bin/go ] && [ "$(/usr/local/go/bin/go env GOVERSION)" = "go$want" ]; then
		log "Go $want already installed"
	else
		need_reach "the Go download site" "$GO_DL/go$want.linux-amd64.tar.gz"
		log "Go $want from $GO_DL"
		curl -fsSL -o /tmp/go.tgz "$GO_DL/go$want.linux-amd64.tar.gz"
		rm -rf /usr/local/go
		tar -C /usr/local -xzf /tmp/go.tgz
		rm -f /tmp/go.tgz
	fi
	cat >/etc/profile.d/go.sh <<-'EOF'
		export PATH=$PATH:/usr/local/go/bin
	EOF
}

go_build() { # OUTPUT PACKAGE [ldflags]
	need_reach "the Go module proxy" "${GOPROXY%%,*}"
	(
		cd "$REPO"
		export PATH=$PATH:/usr/local/go/bin GOTOOLCHAIN=local GOPROXY="$GOPROXY" CGO_ENABLED=0 HOME=/root
		go build -trimpath ${3:+-ldflags "$3"} -o "$1" "$2"
	)
}

pi_hint() { log "next: the matching step in STEPS.md (pi is already installed)"; }

# Any host may carry an extra NIC in the same subnet that the kit does not use
# (STEPS.md R00; currently A's eth1, left DOWN). Loose reverse-path filtering keeps
# replies and requests from being dropped; it is harmless on a one-NIC host.
loose_rp_filter() {
	printf 'net.ipv4.conf.all.rp_filter = 2\nnet.ipv4.conf.default.rp_filter = 2\n' >/etc/sysctl.d/92-perf-rpfilter.conf
	sysctl -q -p /etc/sysctl.d/92-perf-rpfilter.conf
}

# Self-check: one default route only, and an unused eth1 is DOWN or has no default route.
extra_nic_ok() {
	[ "$(ip -4 route show default | wc -l)" -le 1 ] || return 1
	ip link show eth1 >/dev/null 2>&1 || return 0
	[ "$NET_IF" = eth1 ] && return 0
	[ "$B_PRIV_IF" = eth1 ] && return 0
	ip -br link show eth1 | grep -q ' DOWN ' && return 0
	[ -z "$(ip -4 route show default dev eth1)" ]
}

# ---------------------------------------------------------------- roles
role_loadgen() {
	base_packages
	render_kit
	sysctl_setup
	limits_setup
	ensure_ops_user
	log "extra IPs $A_CARRIERGEN_IP $A_CARRIER_UAS_IP ${A_LOADGEN2_IP:-} on $A_EXTRA_IF (/$PREFIX_LEN, same subnet as the primary)"
	has_ip "$A_IP" || die "A_IP $A_IP is not on this host"
	# shellcheck disable=SC2086
	extra_ips a-extra "$A_EXTRA_IF" "$A_IP" "$A_CARRIERGEN_IP" "$A_CARRIER_UAS_IP" ${A_LOADGEN2_IP:-}
	loose_rp_filter
	install_sipp
	install_go
	log "build webrtcload"
	go_build /usr/local/bin/webrtcload ./test/perf/webrtcload
	layout loadgen
	init_progress
	pi_hint
}

role_sbc() {
	base_packages
	render_kit
	sysctl_setup
	limits_setup
	ensure_ops_user
	has_ip "$B_PUB_IP" || die "B_PUB_IP $B_PUB_IP is not on this host"
	if [ "$PRIV_SUBNET_CIDR" = "$SUBNET_CIDR" ]; then
		log "private IP $B_PRIV_IP on $B_PRIV_IF (/$PREFIX_LEN, same subnet as the primary $B_PUB_IP)"
		extra_ips b-priv "$B_PRIV_IF" "$B_PUB_IP" "$B_PRIV_IP"
	else
		private_nic
	fi
	loose_rp_filter
	install_go
	log "build freesbc ($FREESBC_VERSION)"
	go_build /usr/local/bin/freesbc ./cmd/freesbc "-X main.version=$FREESBC_VERSION"
	log "freesbc user, certificate, systemd unit"
	id freesbc >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin freesbc
	install -d -m 750 -o root -g freesbc /etc/freesbc
	if [ ! -s /etc/freesbc/cert.pem ]; then
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
			-keyout /etc/freesbc/key.pem -out /etc/freesbc/cert.pem \
			-days 30 -subj "/CN=freesbc-rehearsal" >/dev/null 2>&1
	fi
	chown root:freesbc /etc/freesbc/cert.pem /etc/freesbc/key.pem
	chmod 640 /etc/freesbc/cert.pem /etc/freesbc/key.pem
	install -m 644 "$REPO/packaging/freesbc.service" /etc/systemd/system/freesbc.service
	mkdir -p /etc/systemd/system/freesbc.service.d
	cat >/etc/systemd/system/freesbc.service.d/perf.conf <<-EOF
		[Service]
		LimitNOFILE=1048576
		LimitNPROC=infinity
		# Go soft limit from plan.env B_GOMEMLIMIT (6GiB for the 8 GiB box, 7.35 GiB usable).
		Environment=GOMEMLIMIT=$B_GOMEMLIMIT
	EOF
	if [ -n "$B_MEMORY_MAX" ]; then
		# optional cgroup cap (plan.env B_MEMORY_MAX), not used on the 8 GiB box
		printf 'MemoryMax=%s\n' "$B_MEMORY_MAX" >>/etc/systemd/system/freesbc.service.d/perf.conf
	fi
	install -m 755 "$HERE/freesbc-use" /usr/local/bin/freesbc-use
	install -m 755 "$HERE/sbc-cores.sh" /usr/local/bin/sbc-cores
	install -m 755 "$HERE/hostmon.sh" /usr/local/bin/hostmon
	systemctl daemon-reload
	for f in "$KIT"/configs/*.yaml; do
		/usr/local/bin/freesbc check -c "$f" >/dev/null || die "freesbc check failed for $f"
	done
	layout sbc
	log "freesbc is NOT started: pick a config with 'freesbc-use fs|ast|sipp'"
	pi_hint
}

# docker_registry_mirror: write the account accelerator into daemon.json (only when
# DOCKER_REGISTRY_MIRROR is set) and restart docker if that changed anything.
docker_registry_mirror() {
	[ -n "$DOCKER_REGISTRY_MIRROR" ] || return 0
	want=$(printf '{"registry-mirrors":["%s"]}\n' "$DOCKER_REGISTRY_MIRROR")
	if [ -f /etc/docker/daemon.json ] && [ "$(cat /etc/docker/daemon.json)" = "$want" ]; then return 0; fi
	log "docker: registry mirror from plan.env into /etc/docker/daemon.json"
	mkdir -p /etc/docker
	[ ! -f /etc/docker/daemon.json ] || cp -p /etc/docker/daemon.json /etc/docker/daemon.json.orig
	printf '%s\n' "$want" >/etc/docker/daemon.json
	systemctl restart docker
	i=0
	until docker info >/dev/null 2>&1; do
		i=$((i + 1)); [ $i -le 15 ] || die "docker did not come back after the daemon.json change"
		sleep 1
	done
}

# docker_image_ready: local image, then the docker save tarball, then FS_IMAGE_PULL
# (when set), then a pull of FS_IMAGE through the registry mirror (or Docker Hub).
docker_image_ready() {
	if docker image inspect "$FS_IMAGE" >/dev/null 2>&1; then return 0; fi
	if [ -s "$FS_IMAGE_TAR" ]; then
		log "FreeSWITCH: docker load $FS_IMAGE_TAR"
		docker load -i "$FS_IMAGE_TAR" >/dev/null
		docker image inspect "$FS_IMAGE" >/dev/null 2>&1 || die "$FS_IMAGE_TAR did not provide $FS_IMAGE (docker images shows what it loaded; set FS_IMAGE to that name)"
		return 0
	fi
	if [ -n "$FS_IMAGE_PULL" ] && [ "$FS_IMAGE_PULL" != "$FS_IMAGE" ]; then
		log "FreeSWITCH: pull $FS_IMAGE_PULL (several hundred MB)"
		if docker pull "$FS_IMAGE_PULL" >/dev/null; then
			docker tag "$FS_IMAGE_PULL" "$FS_IMAGE"
			return 0
		fi
		log "FreeSWITCH: pull $FS_IMAGE_PULL failed, trying $FS_IMAGE"
	fi
	if [ -z "$DOCKER_REGISTRY_MIRROR" ]; then
		need_reach "no usable FreeSWITCH image: not local, no FS_IMAGE_TAR at $FS_IMAGE_TAR, DOCKER_REGISTRY_MIRROR is empty in $PLAN_ENV and Docker Hub is unreachable. Fix: put the Alibaba console accelerator URL (容器镜像服务 -> 镜像加速器) into DOCKER_REGISTRY_MIRROR, or copy a docker save file (STEPS.md R05)" https://registry-1.docker.io/v2/
	fi
	log "FreeSWITCH: pull $FS_IMAGE (several hundred MB)${DOCKER_REGISTRY_MIRROR:+ through the registry mirror}"
	docker pull "$FS_IMAGE" >/dev/null || die "docker pull $FS_IMAGE failed (STEPS.md R05: check DOCKER_REGISTRY_MIRROR, or use FS_IMAGE_TAR)"
}

# fs_param FILE NAME VALUE: set an active <param> of switch.conf.xml, or add it
# right after <settings> when the stock file only has it commented out.
fs_param() {
	if grep -qE "^[[:space:]]*<param name=\"$2\"" "$1"; then
		sed -i -E "s#^([[:space:]]*<param name=\"$2\" value=\")[^\"]*(\"/>)#\1$3\2#" "$1"
	else
		sed -i -E "0,/<settings>/s#<settings>#<settings>\n    <param name=\"$2\" value=\"$3\"/>#" "$1"
	fi
}

fs_prepare_conf() {
	if [ ! -d "$FS_CONF/sip_profiles" ]; then
		docker_image_ready
		docker rm -f fs-tmp >/dev/null 2>&1 || true
		docker create --name fs-tmp "$FS_IMAGE" >/dev/null
		mkdir -p "$FS_CONF"
		docker cp fs-tmp:/usr/share/freeswitch/conf/vanilla/. "$FS_CONF/"
		docker rm fs-tmp >/dev/null
	fi
	# Only the perf profile: drop the stock internal/external profiles (they bind
	# 5060 and 5080 on every address and would collide with SIPp and Asterisk).
	rm -rf "$FS_CONF"/sip_profiles/internal.xml "$FS_CONF"/sip_profiles/external.xml \
		"$FS_CONF"/sip_profiles/internal-ipv6.xml "$FS_CONF"/sip_profiles/external-ipv6.xml \
		"$FS_CONF"/sip_profiles/internal "$FS_CONF"/sip_profiles/external \
		"$FS_CONF"/sip_profiles/external-ipv6 "$FS_CONF"/sip_profiles/internal-ipv6
	sed "s/10\.77\.0\.10/$C_IP/g" "$PERF/freeswitch/sip_profiles/perf.xml" >"$FS_CONF/sip_profiles/perf.xml"
	cp "$PERF/freeswitch/dialplan/perfload.xml" "$FS_CONF/dialplan/perfload.xml"
	# event socket on loopback only; verto (8081/8082 on every address) not needed
	sed -i 's#name="listen-ip" value="::"#name="listen-ip" value="127.0.0.1"#' "$FS_CONF/autoload_configs/event_socket.conf.xml"
	sed -i 's#^\( *\)<load module="mod_verto"/>#\1<!-- <load module="mod_verto"/> -->#' "$FS_CONF/autoload_configs/modules.conf.xml"
	# The perf profile has no digest: allow only FreeSBC's private address.
	# Create the freesbc_priv ACL (referenced by perf.xml apply-inbound-acl and
	# apply-register-acl) from plan.env's B_PRIV_IP; default deny.
	acl="$FS_CONF/autoload_configs/acl.conf.xml"
	if [ -f "$acl" ] && ! grep -q 'name="freesbc_priv"' "$acl"; then
		sed -i "s#<network-lists>#<network-lists>\n    <list name=\"freesbc_priv\" default=\"deny\">\n      <node type=\"allow\" cidr=\"$B_PRIV_IP/32\"/>\n    </list>#" "$acl"
	fi
	# stock session limits (30 sps, 1000 sessions) would show up as 503s.
	# Formal run: 1000+ CPS and several thousand sessions, a wide RTP range, quiet logs.
	sw="$FS_CONF/autoload_configs/switch.conf.xml"
	fs_param "$sw" sessions-per-second "$FS_SPS"
	fs_param "$sw" max-sessions "$FS_MAX_SESSIONS"
	fs_param "$sw" rtp-start-port "$FS_RTP_START"
	fs_param "$sw" rtp-end-port "$FS_RTP_END"
	# the stock config logs at debug: at 1000 CPS that alone costs cores
	fs_param "$sw" loglevel warning
	[ ! -f "$FS_CONF/autoload_configs/logfile.conf.xml" ] || \
		sed -i -E 's#(<map name="all" value=")[^"]*("/>)#\1warning,err,crit,alert\2#' "$FS_CONF/autoload_configs/logfile.conf.xml"
}

# fs_version: what the running FreeSWITCH reports, for example "FreeSWITCH Version 1.10.12-release ...".
fs_version() { docker exec "$FS_NAME" fs_cli -x version 2>/dev/null | grep -m1 -i freeswitch; }

fs_run() {
	log "FreeSWITCH: container $FS_NAME, host network, profile perf on $C_IP:5090"
	docker_image_ready
	docker rm -f "$FS_NAME" >/dev/null 2>&1 || true
	mkdir -p /var/log/freeswitch-perf
	docker run -d --name "$FS_NAME" --restart unless-stopped --network host \
		--ulimit nofile=1048576:1048576 --ulimit nproc=-1 \
		-v "$FS_CONF:/etc/freeswitch" -v /var/log/freeswitch-perf:/var/log/freeswitch \
		--entrypoint /usr/bin/freeswitch "$FS_IMAGE" \
		-nf -nonat -nc -conf /etc/freeswitch -log /var/log/freeswitch -db /tmp -run /tmp >/dev/null
	printf '#!/bin/sh\nexec docker exec -i %s fs_cli "$@"\n' "$FS_NAME" >/usr/local/bin/fs_cli
	chmod 755 /usr/local/bin/fs_cli
	i=0
	until docker exec "$FS_NAME" fs_cli -x 'sofia status profile perf' 2>/dev/null | grep -q "$C_IP:5090"; do
		i=$((i + 1))
		[ $i -le 40 ] || { docker logs --tail 30 "$FS_NAME" >&2; die "FreeSWITCH profile perf did not come up on $C_IP:5090"; }
		sleep 2
	done
	fs_version >"$KIT/freeswitch-version" 2>/dev/null || true
	log "FreeSWITCH version: $(cat "$KIT/freeswitch-version" 2>/dev/null) (image $FS_IMAGE)"
}

asterisk_users() {
	[ "$ASTERISK_USERS" -ge 1 ] && [ "$ASTERISK_USERS" -le 500 ] || die "ASTERISK_USERS must be 1..500"
	awk -v n="$ASTERISK_USERS" -v src="$B_PRIV_IP" -v ip="$C_IP" 'BEGIN {
		list = ""
		for (i = 1; i <= n; i++) list = list (list == "" ? "" : ",") sprintf("u%06d,w%06d", i, i)
		print "; Generated by provision.sh: one endpoint for FreeSBC, one aor per user."
		print "[perf]"
		print "type=endpoint"
		print "transport=transport-perf"
		print "context=perfload"
		print "disallow=all"
		print "allow=ulaw,alaw"
		print "dtmf_mode=rfc4733"
		print "direct_media=no"
		print "rewrite_contact=no"
		print "force_rport=no"
		print "rtp_symmetric=no"
		print "ice_support=no"
		print "media_encryption=no"
		print "rtp_timeout=60"
		print "media_address=" ip
		print "aors=" list
		print ""
		print "[perf]"
		print "type=identify"
		print "endpoint=perf"
		print "match=" src
		print ""
		print "[perf-aor](!)"
		print "type=aor"
		print "max_contacts=1"
		print "remove_existing=yes"
		print "minimum_expiration=30"
		print "default_expiration=300"
		print "maximum_expiration=86400"
		print ""
		for (i = 1; i <= n; i++) printf "[u%06d](perf-aor)\n[w%06d](perf-aor)\n", i, i
	}' >/etc/asterisk/pjsip_perf_users.conf
}

role_switch() {
	base_packages
	render_kit
	sysctl_setup
	limits_setup
	ensure_ops_user
	has_ip "$C_IP" || die "C_IP $C_IP is not on this host"
	install_sipp
	log "packages: docker.io, asterisk, sshfs"
	apt_update_once
	apt_install docker.io sshfs asterisk
	systemctl enable --now docker >/dev/null 2>&1
	docker_registry_mirror
	fs_prepare_conf
	fs_run
	log "Asterisk: pjsip on $C_IP:5080, $ASTERISK_USERS users per prefix"
	for f in pjsip.conf extensions.conf rtp.conf modules.conf; do
		[ -f "/etc/asterisk/$f.orig" ] || { [ -f "/etc/asterisk/$f" ] && cp -p "/etc/asterisk/$f" "/etc/asterisk/$f.orig"; } || true
	done
	install -m 640 -o asterisk -g asterisk "$KIT/asterisk/pjsip.conf" /etc/asterisk/pjsip.conf
	install -m 640 -o asterisk -g asterisk "$KIT/asterisk/rtp.conf" /etc/asterisk/rtp.conf
	install -m 640 -o asterisk -g asterisk "$HERE/asterisk/extensions.conf" /etc/asterisk/extensions.conf
	# chan_sip would bind 0.0.0.0:5060 and block the SIPp UAS
	grep -q '^noload *=> *chan_sip.so' /etc/asterisk/modules.conf || sed -i '/^\[modules\]/a noload => chan_sip.so' /etc/asterisk/modules.conf
	asterisk_users
	chown asterisk:asterisk /etc/asterisk/pjsip_perf_users.conf
	chmod 640 /etc/asterisk/pjsip_perf_users.conf
	systemctl enable asterisk >/dev/null 2>&1
	systemctl restart asterisk
	i=0
	until asterisk -rx 'pjsip show endpoint perf' 2>/dev/null | grep -q 'Endpoint:  *perf'; do
		i=$((i + 1))
		[ $i -le 30 ] || { journalctl -u asterisk -n 30 --no-pager >&2; die "Asterisk did not load endpoint perf"; }
		sleep 2
	done
	layout switch
	pi_hint
}

role_pi() {
	[ -f /etc/perf-role ] || die "run provision.sh <loadgen|sbc|switch> first"
	prole=$(cat /etc/perf-role)
	ensure_ops_user
	nodev=$(node --version 2>/dev/null | sed 's/^v//' || true)
	if [ -z "$nodev" ] || [ "$(printf '22.19.0\n%s\n' "$nodev" | sort -V | head -1)" != 22.19.0 ]; then
		need_reach "deb.nodesource.com" https://deb.nodesource.com
		log "Node.js 22.x from NodeSource (Ubuntu's apt Node is too old for pi)"
		apt_update_once
		curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null
		apt_install nodejs
	fi
	log "pi coding agent (npm, --ignore-scripts)"
	npm install -g --ignore-scripts ${NPM_REGISTRY:+--registry "$NPM_REGISTRY"} @earendil-works/pi-coding-agent >/dev/null
	home=$(getent passwd "$OPS_USER" | cut -d: -f6)
	install -d -m 700 -o "$OPS_USER" -g "$OPS_USER" "$home/.pi" "$home/.pi/agent"
	if [ ! -f "$home/.pi/agent/models.json" ]; then
		# Fallback in case pi's built-in catalog lacks deepseek-flash (unverified).
		# If it clashes with the built-in provider, rename the provider here to
		# deepseek-custom and pass --provider deepseek-custom.
		cat >"$home/.pi/agent/models.json" <<-'EOF'
			{"providers":{"deepseek":{"baseUrl":"https://api.deepseek.com","api":"openai-completions","apiKey":"$DEEPSEEK_API_KEY","models":[{"id":"deepseek-flash"}]}}}
		EOF
		chown "$OPS_USER:$OPS_USER" "$home/.pi/agent/models.json"
		chmod 600 "$home/.pi/agent/models.json"
	fi
	# The API key never goes into the repo or this script: the operator writes
	# it with pi-set-key (mode 600, outside the checkout).
	if [ ! -f "$home/.pi-env" ]; then
		printf '# DEEPSEEK_API_KEY=... (use pi-set-key)\n' >"$home/.pi-env"
		chown "$OPS_USER:$OPS_USER" "$home/.pi-env"
		chmod 600 "$home/.pi-env"
	fi
	grep -q 'pi-env' "$home/.profile" || printf '\n# pi agent: API key from a mode-600 file\n[ -r "$HOME/.pi-env" ] && { set -a; . "$HOME/.pi-env"; set +a; }\n' >>"$home/.profile"
	chown "$OPS_USER:$OPS_USER" "$home/.profile"
	cat >/usr/local/bin/pi-set-key <<-'EOF'
		#!/bin/sh
		# Store the DeepSeek API key for the ops user (ecs-user), mode 600. Usage:
		#   sudo pi-set-key        (prompts without echo)
		set -eu
		[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"
		printf 'DeepSeek API key: ' >&2
		stty -echo; read -r key; stty echo; printf '\n' >&2
		[ -n "$key" ] || { echo "empty key" >&2; exit 1; }
		u=${OPS_USER:-ecs-user}
		home=$(getent passwd "$u" | cut -d: -f6)
		umask 077
		printf 'DEEPSEEK_API_KEY=%s\n' "$key" >"$home/.pi-env"
		chown "$u:$u" "$home/.pi-env"
		echo "written to $home/.pi-env (mode 600)" >&2
	EOF
	cat >/usr/local/bin/pi-start <<-'EOF'
		#!/bin/sh
		# Start pi in this host's agent directory so its AGENTS.md is loaded.
		set -eu
		role=$(cat /etc/perf-role)
		[ -r "$HOME/.pi-env" ] && { set -a; . "$HOME/.pi-env"; set +a; }
		cd "/opt/freesbc/test/perf/hosts/agents/$role"
		exec pi --provider deepseek --model deepseek-flash "$@"
	EOF
	chmod 755 /usr/local/bin/pi-set-key /usr/local/bin/pi-start
	log "pi installed for $prole; run: sudo pi-set-key, then as $OPS_USER: pi-start"
}

role_fetch_sipp() {
	if [ -s "$SIPP_LOCAL" ] && echo "$SIPP_SHA256  $SIPP_LOCAL" | sha256sum -c - >/dev/null 2>&1; then
		log "$SIPP_LOCAL already present, sha256 ok"
		exit 0
	fi
	curl -fsSL -m 120 -o "$SIPP_LOCAL.part" "$SIPP_URL" || die "cannot download $SIPP_URL"
	echo "$SIPP_SHA256  $SIPP_LOCAL.part" | sha256sum -c - >/dev/null || { rm -f "$SIPP_LOCAL.part"; die "sha256 mismatch for the SIPp tarball"; }
	mv "$SIPP_LOCAL.part" "$SIPP_LOCAL"
	chmod 644 "$SIPP_LOCAL"
	log "$SIPP_LOCAL downloaded, sha256 ok"
	exit 0
}

role_authkey() {
	ensure_ops_user
	home=$(getent passwd "$OPS_USER" | cut -d: -f6)
	n=0
	while IFS= read -r k; do
		case $k in ssh-* | ecdsa-*) ;; *) continue ;; esac
		grep -qxF "$k" "$home/.ssh/authorized_keys" || { printf '%s\n' "$k" >>"$home/.ssh/authorized_keys"; n=$((n + 1)); }
	done
	log "added $n key(s) to $home/.ssh/authorized_keys"
	[ ! -f "$home/.ssh/id_ed25519.pub" ] || { log "public key of $OPS_USER on this host (fallback only):"; cat "$home/.ssh/id_ed25519.pub"; }
	exit 0
}

# ---------------------------------------------------------------- C's internet egress
# Path 1 (OS route): C routes its default via A, A masquerades C. The Alibaba
# VPC router may not deliver a packet to an in-subnet next hop that the guest
# OS chose; egress-client tests it and rolls back when it does not work.
EGRESS_RULES=/usr/local/sbin/perf-egress-rules
EGRESS_UNIT=/etc/systemd/system/perf-egress.service

role_egress_gw() {
	if [ "$ARG2" = undo ]; then
		log "egress-gw undo"
		systemctl disable --now perf-egress.service >/dev/null 2>&1 || true
		if [ -x "$EGRESS_RULES" ]; then "$EGRESS_RULES" del || true; fi
		rm -f "$EGRESS_RULES" "$EGRESS_UNIT" /etc/sysctl.d/91-perf-egress.conf
		systemctl daemon-reload
		sysctl -w net.ipv4.ip_forward=0 >/dev/null
		iptables -P FORWARD ACCEPT
		return 0
	fi
	log "egress-gw: forward and masquerade $C_IP only"
	command -v iptables >/dev/null 2>&1 || { apt_update_once; apt_install iptables; }
	iface=$(ip -o -4 route show default | awk '{print $5; exit}')
	[ -n "$iface" ] || die "no default route on this host"
	printf 'net.ipv4.ip_forward = 1\n' >/etc/sysctl.d/91-perf-egress.conf
	sysctl -q -p /etc/sysctl.d/91-perf-egress.conf
	cat >"$EGRESS_RULES" <<-EOF
		#!/bin/sh
		# Installed by provision.sh egress-gw. "add" (default) is idempotent; "del" removes the rules.
		set -eu
		op=\${1:-add}
		rule() { # table chain args...
			t=\$1; c=\$2; shift 2
			if [ "\$op" = add ]; then iptables -t "\$t" -C "\$c" "\$@" 2>/dev/null || iptables -t "\$t" -A "\$c" "\$@"
			else iptables -t "\$t" -D "\$c" "\$@" 2>/dev/null || true; fi
		}
		rule nat POSTROUTING -s $C_IP/32 ! -d $SUBNET_CIDR -o $iface -j MASQUERADE
		rule filter FORWARD -s $C_IP/32 -j ACCEPT
		rule filter FORWARD -d $C_IP/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
		if [ "\$op" = add ]; then iptables -P FORWARD DROP; fi
	EOF
	chmod 755 "$EGRESS_RULES"
	cat >"$EGRESS_UNIT" <<-EOF
		[Unit]
		Description=FreeSBC rehearsal: NAT for C's internet egress
		After=network-online.target
		Wants=network-online.target

		[Service]
		Type=oneshot
		RemainAfterExit=yes
		ExecStart=$EGRESS_RULES add
		ExecStop=$EGRESS_RULES del

		[Install]
		WantedBy=multi-user.target
	EOF
	systemctl daemon-reload
	systemctl enable --now perf-egress.service >/dev/null 2>&1
	systemctl restart perf-egress.service
	iptables -t nat -S POSTROUTING | grep -q "$C_IP" || die "MASQUERADE rule missing"
	log "egress-gw ready; now on C: provision.sh egress-client"
}

role_egress_client() {
	if [ "$ARG2" = undo ]; then
		log "egress-client undo"
		rm -f "/etc/netplan/63-perf-egress.yaml"
		ip route del default via "$A_IP" dev "$NET_IF" metric 50 2>/dev/null || true
		return 0
	fi
	has_ip "$C_IP" || die "this is not C ($C_IP not on this host)"
	log "egress-client: default route via $A_IP (metric 50) on $NET_IF; the subnet's connected route is untouched"
	ip route replace default via "$A_IP" dev "$NET_IF" metric 50
	ok=""
	for u in https://mirrors.aliyun.com https://golang.google.cn; do
		code=$(curl -sS -m 8 -o /dev/null -w '%{http_code}' "$u" 2>/dev/null || true)
		log "  $u -> $code"
		case $code in 2* | 3*) ok=1 ;; esac
	done
	if [ -z "$ok" ]; then
		ip route del default via "$A_IP" dev "$NET_IF" metric 50 2>/dev/null || true
		log "default route now: $(ip -4 route show default | tr '\n' ';')"
		die "the OS route via A does not carry internet traffic (the VPC router does not forward it). Rolled back. Next: STEPS.md appendix option (a) VPC route table, or (b) provision.sh proxy-gw / proxy-client"
	fi
	cat >/etc/netplan/63-perf-egress.yaml <<-EOF
		network:
		  version: 2
		  ethernets:
		    $NET_IF:
		      routes:
		        - to: default
		          via: $A_IP
		          metric: 50
	EOF
	chmod 600 /etc/netplan/63-perf-egress.yaml
	netplan generate
	log "egress-client OK and persisted in /etc/netplan/63-perf-egress.yaml"
}

# Path 3 (proxy): tinyproxy on A, allowed only from C; C's apt, docker, curl,
# git, go, npm and pi use it.
role_proxy_gw() {
	if [ "$ARG2" = undo ]; then
		log "proxy-gw undo"
		systemctl disable --now tinyproxy >/dev/null 2>&1 || true
		return 0
	fi
	log "proxy-gw: tinyproxy on $A_IP:$PROXY_PORT, allowed from $C_IP only"
	apt_update_once
	apt_install tinyproxy
	cat >/etc/tinyproxy/tinyproxy.conf <<-EOF
		# Written by provision.sh proxy-gw (FreeSBC rehearsal). C only.
		User tinyproxy
		Group tinyproxy
		Port $PROXY_PORT
		Listen $A_IP
		Timeout 600
		LogLevel Warning
		LogFile "/var/log/tinyproxy/tinyproxy.log"
		PidFile "/run/tinyproxy/tinyproxy.pid"
		MaxClients 50
		Allow $C_IP
		ConnectPort 443
		ConnectPort 80
		DisableViaHeader Yes
	EOF
	systemctl enable tinyproxy >/dev/null 2>&1
	systemctl restart tinyproxy
	sleep 1
	ss -Hltn "sport = :$PROXY_PORT" | grep -q "$A_IP" || die "tinyproxy is not listening on $A_IP:$PROXY_PORT"
	log "proxy-gw ready; security group of A must admit tcp $PROXY_PORT from $C_IP (STEPS.md). Now on C: provision.sh proxy-client"
}

role_proxy_client() {
	url=http://$A_IP:$PROXY_PORT
	nop="localhost,127.0.0.1,$SUBNET_CIDR,100.100.0.0/16,.cloud.aliyuncs.com,.aliyuncs.com"
	if [ "$ARG2" = undo ]; then
		log "proxy-client undo"
		rm -f /etc/apt/apt.conf.d/95perf-proxy /etc/systemd/system/docker.service.d/http-proxy.conf /etc/npmrc
		sed -i '/^# BEGIN perf-proxy/,/^# END perf-proxy/d' /etc/environment
		git config --system --unset http.proxy 2>/dev/null || true
		git config --system --unset https.proxy 2>/dev/null || true
		systemctl daemon-reload
		return 0
	fi
	log "proxy-client: everything on this host that needs the internet uses $url"
	cat >/etc/apt/apt.conf.d/95perf-proxy <<-EOF
		Acquire::http::Proxy "$url";
		Acquire::https::Proxy "$url";
		# the Alibaba-internal mirror is reachable directly
		Acquire::http::Proxy::mirrors.cloud.aliyuncs.com "DIRECT";
		Acquire::https::Proxy::mirrors.cloud.aliyuncs.com "DIRECT";
	EOF
	mkdir -p /etc/systemd/system/docker.service.d
	cat >/etc/systemd/system/docker.service.d/http-proxy.conf <<-EOF
		[Service]
		Environment="HTTP_PROXY=$url" "HTTPS_PROXY=$url" "NO_PROXY=$nop"
	EOF
	touch /etc/environment
	sed -i '/^# BEGIN perf-proxy/,/^# END perf-proxy/d' /etc/environment
	cat >>/etc/environment <<-EOF
		# BEGIN perf-proxy
		http_proxy=$url
		https_proxy=$url
		HTTP_PROXY=$url
		HTTPS_PROXY=$url
		no_proxy=$nop
		NO_PROXY=$nop
		NODE_USE_ENV_PROXY=1
		# END perf-proxy
	EOF
	printf 'proxy=%s\nhttps-proxy=%s\n' "$url" "$url" >/etc/npmrc
	git config --system http.proxy "$url"
	git config --system https.proxy "$url"
	systemctl daemon-reload
	if systemctl is-active --quiet docker; then systemctl restart docker; fi
	for u in https://mirrors.aliyun.com https://golang.google.cn https://api.deepseek.com; do
		code=$(curl -sS -m 10 -x "$url" -o /dev/null -w '%{http_code}' "$u" 2>/dev/null || true)
		log "  via proxy: $u -> $code"
	done
	if command -v node >/dev/null 2>&1; then
		n=$(HTTPS_PROXY=$url NODE_USE_ENV_PROXY=1 node -e "fetch('https://api.deepseek.com').then(r=>console.log(r.status),e=>console.log('ERR '+e.cause?.code))" 2>&1 || true)
		log "  node (pi) via proxy: api.deepseek.com -> $n  (401 = reachable; ERR = this Node does not honour NODE_USE_ENV_PROXY)"
	fi
	log "proxy-client done; new ssh sessions pick up /etc/environment"
}

# ---------------------------------------------------------------- self-check
FAILS=0
check() { # NAME command...
	name=$1; shift
	if "$@" >/dev/null 2>&1; then printf 'PASS  %s\n' "$name"; else printf 'FAIL  %s\n' "$name"; FAILS=$((FAILS + 1)); fi
}
skip() { printf 'SKIP  %s\n' "$*"; }
sysctl_ge() { [ "$(sysctl -n "$1")" -ge "$2" ]; }
nofile_ok() { [ "$(su "$OPS_USER" -c 'ulimit -n')" -ge 1048576 ]; }
sipp_cap_ok() { getcap "$(readlink -f "$(command -v sipp)")" | grep -q cap_net_raw; }
ssh_pem_present() { [ -f "/home/$OPS_USER/.ssh/aicc-dev-ecs.pem" ]; }
ping_src_ok() { ping -c1 -W2 -I "$1" "$2"; }
info() { printf 'INFO  %s\n' "$*"; }
sipp_ok() { sipp -v 2>&1 | grep -qi pcap && sipp -h 2>&1 | grep -q rtp_echo; }
port_free() { [ -z "$(ss -Hlun "sport = :$1")" ]; }
port_bound() { [ -n "$(ss -Hlun "sport = :$1")" ]; }
ssh_alias_ok() { su "$OPS_USER" -c "ssh -o BatchMode=yes -o ConnectTimeout=5 $1 true"; }
configs_ok() { for f in "$KIT"/configs/*.yaml; do freesbc check -c "$f" || return 1; done; }
ping_ok() { ping -c1 -W2 "$1"; }

selfcheck() {
	r=$(cat /etc/perf-role 2>/dev/null || echo "")
	echo "== self-check: role ${r:-unknown} =="
	check "plan.env has no placeholder" sh -c "! grep -q '^[A-Z_]*=__ASSIGN_IN_CONSOLE__' '$PLAN_ENV'"
	check "templates rendered in $KIT" test -f "$KIT/configs/perf-rehearsal-sipp.yaml"
	[ "$r" != loadgen ] || check "progress checkpoint $REPO/results/progress.md" test -f "$REPO/results/progress.md"
	check "layout: $PERF/run.sh executable" test -x "$PERF/run.sh"
	check "layout: REMOTE_PERF=/opt/freesbc/test/perf has sipp/ and pcap/" test -d /opt/freesbc/test/perf/sipp -a -d /opt/freesbc/test/perf/pcap
	check "sysctl net.core.rmem_max >= 8388608" sysctl_ge net.core.rmem_max 8388608
	check "sysctl net.core.wmem_max >= 8388608" sysctl_ge net.core.wmem_max 8388608
	check "nofile 1048576 for $OPS_USER sessions" nofile_ok
	if ssh_pem_present; then check "ssh key ~/.ssh/aicc-dev-ecs.pem present" ssh_pem_present
	else printf 'FAIL  ssh key ~/.ssh/aicc-dev-ecs.pem missing (operator must copy it to every host before provisioning)\n'; FAILS=$((FAILS + 1)); fi
	check "user $OPS_USER has ~/.ssh/aicc-dev-ecs.pem with mode 600" sh -c "[ \"\$(stat -c %a /home/$OPS_USER/.ssh/aicc-dev-ecs.pem)\" = 600 ]"
	if pem_pub_ok; then printf 'PASS  no stale ~/.ssh/aicc-dev-ecs.pem.pub (or it matches the pem)\n'
	else
		printf 'FAIL  /home/%s/.ssh/aicc-dev-ecs.pem.pub does not match the pem: OpenSSH offers that wrong key first. Fix: mv /home/%s/.ssh/aicc-dev-ecs.pem.pub /home/%s/.ssh/aicc-dev-ecs.pem.pub.stale\n' "$OPS_USER" "$OPS_USER" "$OPS_USER"
		FAILS=$((FAILS + 1))
	fi
	info "this host: $(nproc) vCPU, $(awk '/MemTotal/ {printf "%.1f", $2/1048576}' /proc/meminfo) GiB, $(curl -s --max-time 2 http://100.100.100.200/latest/meta-data/instance/instance-type || echo unknown-type)"
	for h in "$A_IP" "$B_PUB_IP" "$C_IP"; do check "ping $h" ping_ok "$h"; done
	case $r in
	loadgen)
		check "one default route only; an unused eth1 is DOWN or has no default route" extra_nic_ok
		check "IP $A_IP present" has_ip "$A_IP"
		check "IP $A_CARRIERGEN_IP present" has_ip "$A_CARRIERGEN_IP"
		check "IP $A_CARRIER_UAS_IP present" has_ip "$A_CARRIER_UAS_IP"
		[ -z "${A_LOADGEN2_IP:-}" ] || check "IP $A_LOADGEN2_IP present (second client source)" has_ip "$A_LOADGEN2_IP"
		check "sipp $SIPP_VERSION with pcap and rtp_echo" sipp_ok
		check "sipp has cap_net_raw (getcap), needed by pcap play" sipp_cap_ok
		check "webrtcload runs" webrtcload -h
		check "python3 (pcap for holds over 8 s)" python3 -c 'import struct'
		check "ssh to sbc ($B_PUB_IP)" ssh_alias_ok sbc
		check "ssh to switch ($C_IP)" ssh_alias_ok switch
		;;
	sbc)
		check "ssh to loadgen ($A_IP)" ssh_alias_ok loadgen
		check "ssh to switch ($C_IP)" ssh_alias_ok switch
		check "one default route only; an unused eth1 is DOWN or has no default route" extra_nic_ok
		check "IP $B_PUB_IP present" has_ip "$B_PUB_IP"
		check "IP $B_PRIV_IP present on $B_PRIV_IF" sh -c "ip -o -4 addr show dev $B_PRIV_IF | grep -q ' $B_PRIV_IP/'"
		[ "$B_PRIV_IF" = "$NET_IF" ] || check "second NIC $B_PRIV_IF: no default route" test -z "$(ip -4 route show default dev "$B_PRIV_IF")"
		check "private plane: ping $C_IP from $B_PRIV_IP" ping_src_ok "$B_PRIV_IP" "$C_IP"
		if [ "$PRIV_SUBNET_CIDR" = "$SUBNET_CIDR" ]; then
			check "policy routing (same-subnet NICs): from $B_PRIV_IP via table 101, from $B_PUB_IP via table 100" sh -c "ip rule show | grep -q 'from $B_PRIV_IP lookup 101' && ip rule show | grep -q 'from $B_PUB_IP lookup 100'"
		else
			check "private vSwitch is a separate subnet: no policy routing rule for $B_PRIV_IP" sh -c "! ip rule show | grep -q 'from $B_PRIV_IP'"
		fi
		check "GOMEMLIMIT=$B_GOMEMLIMIT in the freesbc unit" sh -c "systemctl show freesbc -p Environment | grep -q 'GOMEMLIMIT=$B_GOMEMLIMIT'"
		if [ -n "$B_MEMORY_MAX" ]; then
			check "freesbc unit MemoryMax=$B_MEMORY_MAX" sh -c "systemctl cat freesbc | grep -q '^MemoryMax=$B_MEMORY_MAX\$'"
		else
			check "freesbc unit has no MemoryMax" sh -c "[ \"\$(systemctl show freesbc -p MemoryMax --value)\" = infinity ]"
		fi
		check "sbc-cores and hostmon installed" test -x /usr/local/bin/sbc-cores -a -x /usr/local/bin/hostmon
		check "ephemeral port range above the RTP range" sh -c "[ \"\$(sysctl -n net.ipv4.ip_local_port_range | awk '{print \$1}')\" -ge 60000 ]"
		check "freesbc binary runs" freesbc version
		check "freesbc check: the three rendered configs" configs_ok
		check "TLS cert and key readable by group freesbc" test -r /etc/freesbc/cert.pem -a -r /etc/freesbc/key.pem
		check "systemd unit freesbc.service installed" test -f /etc/systemd/system/freesbc.service
		check "curl present (sample.sh)" command -v curl
		check "freesbc-use installed" test -x /usr/local/bin/freesbc-use
		;;
	switch)
		check "ssh to loadgen ($A_IP)" ssh_alias_ok loadgen
		check "ssh to sbc ($B_PUB_IP)" ssh_alias_ok sbc
		check "IP $C_IP present" has_ip "$C_IP"
		check "private plane: ping $B_PRIV_IP from $C_IP" ping_src_ok "$C_IP" "$B_PRIV_IP"
		check "sipp $SIPP_VERSION with pcap and rtp_echo" sipp_ok
		check "sipp has cap_net_raw (getcap), needed by pcap play" sipp_cap_ok
		check "docker running" docker info
		check "FreeSWITCH container running" sh -c "[ \"\$(docker inspect -f '{{.State.Running}}' $FS_NAME)\" = true ]"
		check "FreeSWITCH profile perf on $C_IP:5090" sh -c "fs_cli -x 'sofia status profile perf' | grep -q '$C_IP:5090'"
		check "FreeSWITCH dialplan has perfload (ext 2000)" grep -q 'perf_echo' "$FS_CONF/dialplan/perfload.xml"
		check "FreeSWITCH reports its version" sh -c "fs_cli -x version | grep -qi freeswitch"
		info "FreeSWITCH: $(fs_cli -x version 2>/dev/null | grep -m1 -i freeswitch) (image $FS_IMAGE)"
		check "FreeSWITCH max-sessions raised ($FS_MAX_SESSIONS)" sh -c "fs_cli -x 'fsctl max_sessions' | grep -q $FS_MAX_SESSIONS"
		check "FreeSWITCH sessions-per-second raised ($FS_SPS)" sh -c "fs_cli -x 'fsctl sps' | grep -q $FS_SPS"
		check "asterisk active" systemctl is-active --quiet asterisk
		check "asterisk transport on 5080" sh -c "asterisk -rx 'pjsip show transports' | grep -q 5080"
		check "asterisk identify by $B_PRIV_IP" sh -c "asterisk -rx 'pjsip show identifies' | grep -q '$B_PRIV_IP'"
		check "asterisk aor u000001 and w000001" sh -c "asterisk -rx 'pjsip show aors' | grep -q 'u000001' && asterisk -rx 'pjsip show aors' | grep -q 'w000001'"
		check "asterisk dialplan perfload 2000" sh -c "asterisk -rx 'dialplan show 2000@perfload' | grep -q Echo"
		check "chan_sip not loaded (5060 free for the SIPp UAS)" port_free 5060
		check "5090/udp bound (FreeSWITCH)" port_bound 5090
		check "5080/udp bound (Asterisk)" port_bound 5080
		check "sshfs installed" command -v sshfs
		;;
	esac
	if command -v pi >/dev/null 2>&1; then
		check "pi: node >= 22.19" sh -c 'v=$(node --version | sed s/^v//); [ "$(printf "22.19.0\n%s\n" "$v" | sort -V | head -1)" = 22.19.0 ]'
		check "pi: --list-models deepseek shows deepseek-flash" su "$OPS_USER" -c 'pi --list-models deepseek 2>&1 | grep -q deepseek-flash'
		check "pi: api.deepseek.com reachable" sh -c "[ \"\$(curl -sS -m 8 -o /dev/null -w '%{http_code}' https://api.deepseek.com)\" != 000 ]"
		if su "$OPS_USER" -c 'grep -q "^DEEPSEEK_API_KEY=." "$HOME/.pi-env"' 2>/dev/null; then
			check "pi: one-shot hostname via deepseek-flash" su "$OPS_USER" -c 'set -a; . "$HOME/.pi-env"; set +a; pi -p --provider deepseek --model deepseek-flash "run hostname -s and print only its output" 2>&1 | grep -q "$(hostname -s)"'
		else
			skip "pi: one-shot test (no key yet: run pi-set-key, then provision.sh check)"
		fi
	fi
	if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
		printf 'FAIL  ufw is active: security groups are the firewall here (ufw disable)\n'; FAILS=$((FAILS + 1))
	else
		printf 'PASS  no host firewall (security groups are the firewall)\n'
	fi
	if [ "$FAILS" -eq 0 ]; then echo "== all checks PASS =="; else echo "== $FAILS check(s) FAIL =="; fi
	[ "$FAILS" -eq 0 ]
}

case $ROLE in
loadgen) role_loadgen ;;
sbc) role_sbc ;;
switch) role_switch ;;
pi) role_pi ;;
authkey) role_authkey ;;
fetch-sipp) role_fetch_sipp ;;
egress-gw) role_egress_gw; exit 0 ;;
egress-client) role_egress_client; exit 0 ;;
proxy-gw) role_proxy_gw; exit 0 ;;
proxy-client) role_proxy_client; exit 0 ;;
check) ;;
esac
selfcheck
