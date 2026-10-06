#!/usr/bin/env bash
# Install the load-test Asterisk config (Ubuntu 24.04: apt install asterisk).
#
#   ./install-asterisk.sh [conf_dir=/etc/asterisk] [overlay=./asterisk]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
conf=${1:-/etc/asterisk}
overlay=${2:-$here/asterisk}
[[ -d $conf ]] || { echo "no Asterisk config at $conf" >&2; exit 1; }
[[ -d $conf.orig ]] || cp -a "$conf" "$conf.orig"
# Start from an empty tree: stock sample configs open ports (IAX, HTTP, ...)
# and define endpoints the test does not want.
find "$conf" -maxdepth 1 -type f -name '*.conf' -delete
cp "$overlay"/*.conf "$conf"/
echo "Asterisk overlay installed in $conf"
