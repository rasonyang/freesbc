# shellcheck shell=bash
# Environment for run.sh on the loadgen host (hosts topology, rehearsal rig).
# Every address comes from plan.env. Source it, do not execute it:
#
#   cd /opt/freesbc && . test/perf/hosts/env.sh sipp       # SWITCH=sipp (default)
#   . test/perf/hosts/env.sh fs                            # real FreeSWITCH
#   . test/perf/hosts/env.sh ast                           # Asterisk
#
# The argument also tells you which `freesbc-use <x>` the sbc host must run.
# Run run.sh from /opt/freesbc: run.sh keeps users.csv, pcaps and stats under
# $HERE/out and hands the roles the same path as $REMOTE_PERF/out.

_env_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1090,SC1091
. "${PLAN_ENV:-$_env_dir/plan.env}"
for _v in A_IP A_CARRIERGEN_IP A_CARRIER_UAS_IP B_PUB_IP B_PRIV_IP C_IP; do
	case ${!_v} in
	__ASSIGN_IN_CONSOLE__ | "") echo "env.sh: $_v in plan.env is not set (STEPS.md R01)" >&2; return 2 2>/dev/null || exit 2 ;;
	esac
done

case ${1:-sipp} in
sipp) export SWITCH=sipp ;;
fs | ast) export SWITCH=freeswitch ;; # "freeswitch" here only means: start no SIPp UAS
*) echo "usage: . env.sh sipp|fs|ast" >&2; return 2 2>/dev/null || exit 2 ;;
esac
export REHEARSAL_SWITCH=${1:-sipp}

export TOPOLOGY=hosts
export REMOTE_PERF=/opt/freesbc/test/perf
export SBC_PUBLIC=$B_PUB_IP SBC_PRIVATE=$B_PRIV_IP
export LOADGEN_IP=$A_IP CARRIERGEN_IP=$A_CARRIERGEN_IP
export CARRIER_IP=$A_CARRIER_UAS_IP    # carrier UAS: runs locally on the loadgen host
export SWITCH_IP=$C_IP
export LOADGEN2_IP=${A_LOADGEN2_IP:-}   # optional second client source (M06), empty = none
export SBC_EXEC="ssh sbc sudo"         # sample.sh needs root to count the process' fds
export SWITCH_EXEC="ssh switch"        # SIPp UAS (SWITCH=sipp) and the carrier-out UAC
unset CARRIER_EXEC LOADGEN_EXEC CARRIERGEN_EXEC   # empty = local (the loadgen host)
# SIP_PORT stays 5060: it is FreeSBC's port (and the SIPp UAS port). The FreeSWITCH
# (5090) and Asterisk (5080) ports are in the FreeSBC config, not here.
unset SAMPLE_CMD
echo "rehearsal env: switch=$REHEARSAL_SWITCH SWITCH=$SWITCH sbc=$SBC_PUBLIC/$SBC_PRIVATE switch_ip=$SWITCH_IP" >&2
echo "sbc host must run: freesbc-use $REHEARSAL_SWITCH" >&2
