#!/bin/bash
# READ-ONLY environment probe for STEPS.md R00. It changes nothing: it prints
# addresses, routes, OS facts, instance metadata and which internet endpoints
# this host can reach. Run it on each host and compare with plan.env:
#
#   ssh ecs-A 'bash -s' < test/perf/hosts/probe.sh
#   ssh ecs-B 'bash -s' < test/perf/hosts/probe.sh
#   ssh ecs-C 'bash -s' < test/perf/hosts/probe.sh
set -u
echo "### $(hostname)"
echo "-- addresses and routes"
ip -br addr
ip route
ip rule show
echo "-- OS"
# shellcheck disable=SC1091
. /etc/os-release
echo "os=$PRETTY_NAME kernel=$(uname -r) nproc=$(nproc)"
free -g | sed -n 2p
lscpu | grep 'Model name'
sudo -n true 2>/dev/null && echo "sudo=ok (passwordless)" || echo "sudo=NO (provision.sh needs it)"
echo "ufw: $(sudo -n ufw status 2>/dev/null | head -1)"
echo "-- instance metadata (100.100.100.200)"
M=http://100.100.100.200/latest/meta-data
for k in instance/instance-type zone-id vswitch-cidr-block vpc-cidr-block; do echo "$k: $(curl -s -m 3 $M/$k | tr '\n' ' ')"; done
for mac in $(curl -s -m 3 $M/network/interfaces/macs/); do
	mac=${mac%/}
	echo "mac $mac: primary=$(curl -s -m 3 "$M/network/interfaces/macs/$mac/primary-ip-address")" \
		"private-ipv4s=$(curl -s -m 3 "$M/network/interfaces/macs/$mac/private-ipv4s" | tr -d '\n')" \
		"netmask=$(curl -s -m 3 "$M/network/interfaces/macs/$mac/netmask")" \
		"gateway=$(curl -s -m 3 "$M/network/interfaces/macs/$mac/gateway")" \
		"vswitch=$(curl -s -m 3 "$M/network/interfaces/macs/$mac/vswitch-cidr-block")"
done
echo "-- apt sources"
grep -rhE '^deb |^URIs:' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | head -3
echo "-- outbound reachability (HTTP status; 000 = no route / blocked)"
for u in http://mirrors.cloud.aliyuncs.com/ubuntu/ https://mirrors.aliyun.com https://registry-1.docker.io/v2/ \
	https://proxy.golang.org https://goproxy.cn https://golang.google.cn https://api.deepseek.com \
	https://deb.nodesource.com https://registry.npmjs.org https://registry.npmmirror.com https://github.com; do
	echo "$u -> $(curl -sS -m 8 -o /dev/null -w '%{http_code}' "$u" 2>&1 | tail -c 60 | tr '\n' ' ')"
done
echo "-- reachability of the plan hosts"
PLAN=${PLAN_ENV:-/opt/freesbc/test/perf/hosts/plan.env}
if [ -r "$PLAN" ]; then
	# shellcheck disable=SC1090
	. "$PLAN"
	for ip in "$A_IP" "$B_PUB_IP" "$C_IP"; do ping -c1 -W2 "$ip" >/dev/null 2>&1 && echo "ping $ip ok" || echo "ping $ip FAIL"; done
else
	echo "(no plan.env here yet: ping the three addresses by hand)"
fi
