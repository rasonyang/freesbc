#!/usr/bin/env bash
# Render every per-host file of the load-test harness from ./env into ./out.
#
#   ./render.sh            # reads ./env, writes ./out/{sbc,switch,sipp}
#
# Then copy out/sbc to S2, out/switch to S3 and out/sipp to S1 (README §4).
# Needs: bash, envsubst (gettext-base), htpasswd (apache2-utils) or
# python3 with bcrypt, sox (for the test audio).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
env_file=${ENV_FILE:-$here/env}
[[ -f $env_file ]] || { echo "missing $env_file (cp env.example env)" >&2; exit 1; }
set -a; . "$env_file"; set +a

out=$here/out
rm -rf "$out"
mkdir -p "$out/sbc" "$out/switch/asterisk" "$out/switch/freeswitch" "$out/sipp/scenarios" "$out/sipp/data"

die() { echo "render: $*" >&2; exit 1; }
range_min() { echo "${1%-*}"; }
range_max() { echo "${1#*-}"; }

# --- sanity -------------------------------------------------------------------
[[ $SBC_PRIVATE_IP != "$SBC_PUBLIC_BIND" ]] || die "SBC_PRIVATE_IP must differ from SBC_PUBLIC_BIND"
(( USERS_A_COUNT > 0 && USERS_B_COUNT > 0 )) || die "user counts must be positive"
a_end=$((USERS_A_FIRST + USERS_A_COUNT - 1)); b_end=$((USERS_B_FIRST + USERS_B_COUNT - 1))
(( a_end < USERS_B_FIRST || b_end < USERS_A_FIRST )) || die "user ranges A and B overlap"
single_ip=0
[[ $SIPP_CLIENT_IP != "$SIPP_CARRIER_IP" ]] || single_ip=1

# --- bcrypt hash for the admin API ----------------------------------------------
# Cached per password: a fresh salt on every render would change `admin`, a
# restart-only key, and turn every activate.sh into a restart.
pw_fp=$(printf '%s' "$SBC_ADMIN_PASSWORD" | sha256sum | cut -c1-16)
cache=$here/.admin_hash
if [[ -f $cache && $(cut -d' ' -f1 "$cache") == "$pw_fp" ]]; then
  SBC_ADMIN_HASH=$(cut -d' ' -f2 "$cache")
elif command -v htpasswd >/dev/null; then
  SBC_ADMIN_HASH=$(htpasswd -bnBC 10 "" "$SBC_ADMIN_PASSWORD" | tr -d ':\n')
elif python3 -c 'import bcrypt' 2>/dev/null; then
  SBC_ADMIN_HASH=$(SBC_PW="$SBC_ADMIN_PASSWORD" python3 -c 'import bcrypt,os;print(bcrypt.hashpw(os.environ["SBC_PW"].encode(),bcrypt.gensalt(10)).decode())')
else
  die "need htpasswd (apache2-utils) or python3-bcrypt for the admin hash"
fi
echo "$pw_fp $SBC_ADMIN_HASH" >"$cache"
export SBC_ADMIN_HASH

# Only the variables named here are substituted, so ${EXTEN}, $${domain} and
# ${destination_number} in switch configs survive.
vars='$SIPP_CARRIER_IP $SIPP_CLIENT_IP $SBC_PUBLIC_IP $SBC_PUBLIC_BIND $SBC_PRIVATE_IP
      $SWITCH_IP $FS_PORT $FS_CARRIER_PORT $AST_PORT $USER_PASSWORD
      $SIPP_CARRIER_UAS_PORT $FS_RTP_MIN $FS_RTP_MAX $AST_RTP_MIN $AST_RTP_MAX'
export FS_RTP_MIN=$(range_min "$FS_RTP") FS_RTP_MAX=$(range_max "$FS_RTP")
export AST_RTP_MIN=$(range_min "$AST_RTP") AST_RTP_MAX=$(range_max "$AST_RTP")
tpl() { envsubst "$vars" <"$1" >"$2"; }

# --- S2: FreeSBC ------------------------------------------------------------------
# base-<switch>.yaml holds everything but `shield`; activate.sh appends a
# shield-<profile>.yaml, so switching profiles is a hot reload and switching
# switches is a restart.
sbc_base() { # $1 switch-addr  $2 carrier-port|0  $3 with-carriers(1|0)
  cat <<EOF
# Rendered by test/load/render.sh. Do not edit; edit env and re-render.
public:
  ip: $SBC_PUBLIC_IP
  bind: $SBC_PUBLIC_BIND
private:
  ip: $SBC_PRIVATE_IP
rtp: $SBC_RTP

edge:
  switch: [$1]
EOF
  (( $2 == 0 )) || echo "  switch_carrier_port: $2"
  echo "  listen: { udp: 5060 }"
  if (( $3 )); then
    cat <<EOF
  carriers:
    loadcarrier: $SIPP_CARRIER_IP:$SIPP_CARRIER_UAS_PORT   # T2 far end; also the inbound carrier source
EOF
  fi
  cat <<EOF

admin:
  listen: $SBC_ADMIN
  password_hash: "$SBC_ADMIN_HASH"

EOF
}
sbc_base "$SWITCH_IP:$FS_PORT" "$FS_CARRIER_PORT" 1 >"$out/sbc/base-freeswitch.yaml"
sbc_base "$SWITCH_IP:$AST_PORT" 0 1 >"$out/sbc/base-asterisk.yaml"
if (( single_ip )); then
  # One SIPp address: it cannot be a carrier source and a rate-limited phone
  # at once, so client-path tests (T3, T5, T6) get a profile without carriers.
  sbc_base "$SWITCH_IP:$FS_PORT" "$FS_CARRIER_PORT" 0 >"$out/sbc/base-freeswitch-clientonly.yaml"
  sbc_base "$SWITCH_IP:$AST_PORT" 0 0 >"$out/sbc/base-asterisk-clientonly.yaml"
fi
cp "$here/sbc/shield-load.yaml" "$here/sbc/shield-default.yaml" "$out/sbc/"
cp "$here/sbc/activate.sh" "$here/sbc/collect.sh" "$here/sbc/sbc_latency.py" \
   "$here/sbc/99-freesbc-load.conf" "$here/sbc/freesbc.service" "$out/sbc/"
printf 'SBC_ADMIN=%s\nSBC_ADMIN_PASSWORD=%q\nSBC_PUBLIC_BIND=%s\nSBC_PRIVATE_IP=%s\n' \
  "$SBC_ADMIN" "$SBC_ADMIN_PASSWORD" "$SBC_PUBLIC_BIND" "$SBC_PRIVATE_IP" >"$out/sbc/sbc.env"

# --- S3: Asterisk -----------------------------------------------------------------------
for f in "$here"/switch/asterisk/*; do
  case $f in *.tmpl) tpl "$f" "$out/switch/asterisk/$(basename "${f%.tmpl}")" ;;
             *) cp "$f" "$out/switch/asterisk/" ;; esac
done
{
  echo "; Rendered by render.sh: $USERS_A_COUNT callers + $USERS_B_COUNT agents."
  for ((u = USERS_A_FIRST; u <= a_end; u++)); do printf '[%d](load-user)\nauth=%d\naors=%d\n[%d](load-auth)\nusername=%d\n[%d](load-aor)\n\n' $u $u $u $u $u $u; done
  for ((u = USERS_B_FIRST; u <= b_end; u++)); do printf '[%d](load-user)\nauth=%d\naors=%d\n[%d](load-auth)\nusername=%d\n[%d](load-aor)\n\n' $u $u $u $u $u $u; done
} >"$out/switch/asterisk/pjsip_load_users.conf"

# --- S3: FreeSWITCH ---------------------------------------------------------------
(cd "$here/switch/freeswitch" && find . -type f) | while read -r f; do
  mkdir -p "$out/switch/freeswitch/$(dirname "$f")"
  case $f in *.tmpl) tpl "$here/switch/freeswitch/$f" "$out/switch/freeswitch/${f%.tmpl}" ;;
             *) cp "$here/switch/freeswitch/$f" "$out/switch/freeswitch/$f" ;; esac
done
mkdir -p "$out/switch/freeswitch/directory/default"
{
  echo '<include>'
  for ((u = USERS_A_FIRST; u <= a_end; u++)); do echo "  <user id=\"$u\"><params><param name=\"password\" value=\"\$\${load_password}\"/></params></user>"; done
  for ((u = USERS_B_FIRST; u <= b_end; u++)); do echo "  <user id=\"$u\"><params><param name=\"password\" value=\"\$\${load_password}\"/></params></user>"; done
  echo '</include>'
} >"$out/switch/freeswitch/directory/default/load_users.xml"
cp "$here/switch/docker-compose.yml" "$here/switch/install-asterisk.sh" \
   "$here/switch/install-freeswitch.sh" "$here/switch/Dockerfile.asterisk" \
   "$here/switch/Dockerfile.freeswitch" "$here/switch/collect.sh" "$out/switch/"

# --- S1: SIPp ---------------------------------------------------------------------
cp "$here"/sipp/scenarios/*.xml "$out/sipp/scenarios/"
cp "$here/sipp/run.sh" "$here/sipp/rtp_report.sh" "$out/sipp/"
cp "$env_file" "$out/sipp/env"
# SIPp does not expand [fieldN] inside [authentication ...], so the whole
# keyword is the CSV field: the scenarios send [field1].
{ echo SEQUENTIAL; for ((u = USERS_A_FIRST; u <= a_end; u++)); do echo "$u;[authentication username=$u password=$USER_PASSWORD]"; done; } >"$out/sipp/data/users_a.csv"
{ echo SEQUENTIAL; for ((u = USERS_B_FIRST; u <= b_end; u++)); do echo "$u;[authentication username=$u password=$USER_PASSWORD]"; done; } >"$out/sipp/data/users_b.csv"
{ echo SEQUENTIAL; for ((u = USERS_B_FIRST; u <= b_end; u++)); do echo "82$u"; done; } >"$out/sipp/data/did_agents.csv"
printf 'SEQUENTIAL\n800001\n' >"$out/sipp/data/did_echo.csv"
printf 'SEQUENTIAL\n810001\n' >"$out/sipp/data/did_hairpin.csv"
if command -v sox >/dev/null; then
  # 10 s of A-law speech-band noise: never silent, so no endpoint's VAD or
  # FreeSBC's silence watchdog can mistake it for a dead call.
  sox -n -r 8000 -c 1 -e a-law "$out/sipp/data/pcma.wav" synth 10 pinknoise band 300 3000 vol 0.3
else
  echo "render: sox not found; generate out/sipp/data/pcma.wav on S1 (README §4.3)" >&2
fi

echo "rendered into $out"
(( single_ip )) && echo "note: SIPP_CLIENT_IP == SIPP_CARRIER_IP, client tests need the *-clientonly profile" || true
