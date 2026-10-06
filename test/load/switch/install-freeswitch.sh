#!/usr/bin/env bash
# Apply the load-test overlay to a stock FreeSWITCH 1.10 config tree.
#
#   ./install-freeswitch.sh [conf_dir=/etc/freeswitch] [overlay=./freeswitch]
#
# Idempotent. The stock tree is backed up once to <conf_dir>.orig.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
conf=${1:-/etc/freeswitch}
overlay=${2:-$here/freeswitch}
. "$overlay/load.env"
[[ -f $conf/vars.xml ]] || { echo "no FreeSWITCH config at $conf" >&2; exit 1; }
[[ -d $conf.orig ]] || cp -a "$conf" "$conf.orig"

# Our profiles replace the stock ones; the IPv6 twins would bind 5060/5080 too.
rm -f "$conf"/sip_profiles/internal-ipv6.xml "$conf"/sip_profiles/external-ipv6.xml
cp -r "$overlay"/sip_profiles "$overlay"/dialplan "$overlay"/directory "$overlay"/autoload_configs "$conf"/
cp "$overlay"/vars_load.xml "$conf"/

vars=$conf/vars.xml
# A LAN-only switch cannot reach a STUN server; stun-set would stall startup.
sed -i -E 's#cmd="stun-set" data="(external_(rtp|sip)_ip)=[^"]*"#cmd="set" data="\1=$${local_ip_v4}"#' "$vars"
grep -q 'vars_load.xml' "$vars" || sed -i 's#</include>#  <X-PRE-PROCESS cmd="include" data="vars_load.xml"/>\n</include>#' "$vars"

sw=$conf/autoload_configs/switch.conf.xml
sed -i -E 's#(<param name="max-sessions" value=")[0-9]+#\120000#; s#(<param name="sessions-per-second" value=")[0-9]+#\12000#' "$sw"
sed -i -E '/name="rtp-(start|end)-port"/d; /name="core-db-name"/d' "$sw"
sed -i "0,/<settings>/s##<settings>\n    <param name=\"rtp-start-port\" value=\"$FS_RTP_MIN\"/>\n    <param name=\"rtp-end-port\" value=\"$FS_RTP_MAX\"/>\n    <param name=\"core-db-name\" value=\"/dev/shm/core.db\"/>#" "$sw"

# mod_signalwire dials out to the internet at startup; this host has none.
sed -i -E 's#^(\s*)<load module="mod_signalwire"/>#\1<!-- <load module="mod_signalwire"/> -->#' "$conf/autoload_configs/modules.conf.xml"

grep -E 'max-sessions|sessions-per-second|rtp-(start|end)-port|core-db-name' "$sw"
echo "FreeSWITCH overlay applied to $conf"
