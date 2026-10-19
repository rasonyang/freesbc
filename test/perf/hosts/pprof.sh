#!/bin/bash
# Profiles of FreeSBC at the peak of a running load (M07). Run on A while a run.sh plateau is up:
#
#   test/perf/hosts/pprof.sh TAG [CPU_SECONDS]       TAG: for example m01-call-3000cps
#
# Writes to /opt/freesbc/results/<date>/pprof/: TAG-cpu.pb.gz (default 30 s), TAG-goroutine.txt
# (debug=1, top 60 lines), TAG-heap.pb.gz, TAG-allocs.pb.gz and, once, freesbc-linux (the binary
# that matches them: go tool pprof -top freesbc-linux TAG-cpu.pb.gz). The admin API is on B's
# loopback, so curl runs on B through ssh.
set -eu
tag=${1:?usage: pprof.sh TAG [CPU_SECONDS]}
secs=${2:-30}
d=/opt/freesbc/results/$(date +%F)/pprof
mkdir -p "$d"
adm="curl -s -u admin:perf"
ssh sbc "$adm -o /tmp/$tag-cpu.pb.gz 'localhost:8081/debug/pprof/profile?seconds=$secs'"
ssh sbc "$adm 'localhost:8081/debug/pprof/goroutine?debug=1'" | head -60 >"$d/$tag-goroutine.txt"
ssh sbc "$adm -o /tmp/$tag-heap.pb.gz 'localhost:8081/debug/pprof/heap'"
ssh sbc "$adm -o /tmp/$tag-allocs.pb.gz 'localhost:8081/debug/pprof/allocs'"
for k in cpu heap allocs; do scp -q "sbc:/tmp/$tag-$k.pb.gz" "$d/$tag-$k.pb.gz"; done
[ -f "$d/freesbc-linux" ] || scp -q sbc:/usr/local/bin/freesbc "$d/freesbc-linux"
ls -l "$d"/"$tag"-*
