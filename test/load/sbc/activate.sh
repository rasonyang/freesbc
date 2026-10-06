#!/usr/bin/env bash
# Install a rendered FreeSBC config on S2 and apply it.
#
#   ./activate.sh <base> <shield>
#   ./activate.sh freeswitch load            # base-freeswitch.yaml + shield-load.yaml
#   ./activate.sh asterisk default
#   ./activate.sh freeswitch-clientonly load
#
# Shield-only changes are hot reloads (the running process's file watcher
# picks up the atomic rename). Any other change restarts the service,
# because every other key is restart-only.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
base=$here/base-$1.yaml shield=$here/shield-$2.yaml
dst=${FREESBC_CONFIG:-/etc/freesbc/freesbc.yaml}
bin=${FREESBC_BIN:-/usr/local/bin/freesbc}
[[ -f $base && -f $shield ]] || { echo "unknown base or shield profile" >&2; exit 2; }

tmp=$(mktemp "$(dirname "$dst")/.freesbc.XXXXXX")
cat "$base" "$shield" >"$tmp"
"$bin" check -c "$tmp"
chmod 0640 "$tmp"; chown --reference="$dst" "$tmp" 2>/dev/null || true

restart=1
if [[ -f $dst ]] && diff -q <(sed '/^shield:/,$d' "$dst") <(sed '/^shield:/,$d' "$tmp") >/dev/null; then
  restart=0
fi
mv -f "$tmp" "$dst"
if (( restart )) && [[ -n ${NO_SYSTEMD:-} ]]; then
  echo "installed $1/$2; restart-only keys changed: restart FreeSBC yourself"
elif (( restart )); then
  systemctl restart freesbc
  echo "activated $1/$2 (restarted)"
else
  echo "activated $1/$2 (hot reload; check the log for \"config reloaded\")"
fi
