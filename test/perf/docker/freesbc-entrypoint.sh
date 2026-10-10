#!/bin/sh
# Generate a self-signed certificate for edge.listen.wss on first start, then
# exec freesbc so it is PID 1 (run.sh samples /proc/1 as a fallback).
set -e
mkdir -p /etc/freesbc
if [ ! -s /etc/freesbc/cert.pem ]; then
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
		-keyout /etc/freesbc/key.pem -out /etc/freesbc/cert.pem \
		-days 30 -subj "/CN=freesbc-perf" >/dev/null 2>&1
fi
exec /usr/local/bin/freesbc "$@"
