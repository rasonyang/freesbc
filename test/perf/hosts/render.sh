#!/bin/bash
# Render the templates of this kit from plan.env.
#
#   render.sh OUTDIR            writes OUTDIR/configs/perf-rehearsal-{fs,ast,sipp}.yaml,
#                               OUTDIR/ssh_config, OUTDIR/asterisk/{pjsip,rtp}.conf
#
# Environment:
#   PLAN_ENV            plan file, default plan.env next to this script
#   ALLOW_PLACEHOLDERS  1 = do not refuse __ASSIGN_IN_CONSOLE__ values (local
#                       verification only; give dummy values via PLAN_ENV instead)
# provision.sh calls this on every run, so editing plan.env and re-provisioning
# is how addresses change.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
out=${1:-}
[ -n "$out" ] || { sed -n '2,/^set -eu/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 2; }
PLAN_ENV=${PLAN_ENV:-$HERE/plan.env}
# shellcheck disable=SC1090
. "$PLAN_ENV"

keys="SUBNET_CIDR PREFIX_LEN PRIV_SUBNET_CIDR PRIV_PREFIX_LEN A_IP A_CARRIERGEN_IP A_CARRIER_UAS_IP B_PUB_IP B_PRIV_IP C_IP NET_IF"
sedargs=""
bad=""
for k in $keys; do
	v=${!k:-}
	[ -n "$v" ] || { echo "render.sh: $k is empty in $PLAN_ENV" >&2; exit 1; }
	case $v in __ASSIGN_IN_CONSOLE__) bad="$bad $k" ;; esac
	sedargs="$sedargs -e s|@$k@|$v|g"
done
if [ -n "$bad" ] && [ "${ALLOW_PLACEHOLDERS:-0}" != 1 ]; then
	echo "render.sh: placeholder not replaced in $PLAN_ENV:$bad" >&2
	echo "           create the private vSwitch and its ENI/instance in the console and write the values into plan.env (STEPS.md R01)" >&2
	exit 1
fi

render() { # SRC DST
	mkdir -p "$(dirname "$2")"
	# shellcheck disable=SC2086
	sed $sedargs "$1" >"$2"
	if grep -q '@[A-Z_]*@' "$2"; then
		echo "render.sh: unreplaced token in $2: $(grep -o '@[A-Z_]*@' "$2" | sort -u | tr '\n' ' ')" >&2
		exit 1
	fi
}
for v in fs ast sipp; do render "$HERE/templates/perf-rehearsal-$v.yaml.in" "$out/configs/perf-rehearsal-$v.yaml"; done
render "$HERE/templates/ssh_config.in" "$out/ssh_config"
render "$HERE/templates/pjsip.conf.in" "$out/asterisk/pjsip.conf"
render "$HERE/templates/rtp.conf.in" "$out/asterisk/rtp.conf"
