#!/usr/bin/env bash
# The three-server topology on one Linux host, with network namespaces.
# Used for the smoke test (smoke.sh) and for debugging configs before
# touching real servers. Needs root, iproute2 and (for nat) nftables.
#
#   ./netns.sh up [direct|nat]     ./netns.sh down
#
# direct  S2 owns its public address          (IDC / on-prem dual-homed, README T-C)
# nat     S2 sits behind a 1:1 NAT router     (cloud EIP / DMZ, README T-A, T-D):
#         public.ip 198.18.0.7 lives on the router, public.bind is 172.31.0.2
#
#   s1 (SIPp) 198.18.0.10 carrier, 198.18.0.11 phones
#   s2 (FreeSBC) public 198.18.0.7 (direct) | 172.31.0.2 (nat), private 10.77.0.2
#   s3 (switch) 10.77.0.20
# 198.18.0.0/15 is the RFC 2544 benchmarking range: never routed on the internet.
set -euo pipefail
mode=${2:-direct}
nsx() { ip netns exec "$@"; }
down() {
  for n in s1 s2 s3 gw; do ip netns del "$n" 2>/dev/null || true; done
}
veth() { # ns1 if1 ns2 if2
  ip link add "$2" netns "$1" type veth peer name "$4" netns "$3"
  nsx "$1" ip link set "$2" up; nsx "$3" ip link set "$4" up
}
case ${1:?usage: netns.sh up [direct|nat] | down} in
down) down ;;
up)
  down
  for n in s1 s2 s3; do ip netns add $n; nsx $n ip link set lo up; done
  # private LAN: S2 <-> S3 only
  veth s2 priv0 s3 lan0
  nsx s2 ip addr add 10.77.0.2/24 dev priv0
  nsx s3 ip addr add 10.77.0.20/24 dev lan0
  if [[ $mode == direct ]]; then
    veth s1 inet0 s2 pub0
    nsx s1 ip addr add 198.18.0.10/24 dev inet0
    nsx s1 ip addr add 198.18.0.11/24 dev inet0
    nsx s2 ip addr add 198.18.0.7/24 dev pub0
  else
    ip netns add gw; nsx gw ip link set lo up
    veth s1 inet0 gw inet0
    veth s2 pub0 gw vpc0
    nsx s1 ip addr add 198.18.0.10/24 dev inet0
    nsx s1 ip addr add 198.18.0.11/24 dev inet0
    nsx gw ip addr add 198.18.0.1/24 dev inet0
    nsx gw ip addr add 198.18.0.7/32 dev inet0     # the "EIP"
    nsx gw ip addr add 172.31.0.1/24 dev vpc0
    nsx s2 ip addr add 172.31.0.2/24 dev pub0
    nsx s2 ip route add default via 172.31.0.1
    nsx gw sysctl -qw net.ipv4.ip_forward=1
    nsx gw nft -f - <<'NFT'
table ip nat {
  chain pre {
    type nat hook prerouting priority dstnat;
    ip daddr 198.18.0.7 dnat to 172.31.0.2
  }
  chain post {
    type nat hook postrouting priority srcnat;
    ip saddr 172.31.0.2 snat to 198.18.0.7
  }
}
NFT
  fi
  echo "netns topology up ($mode)" ;;
esac
