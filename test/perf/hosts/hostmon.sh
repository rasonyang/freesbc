#!/bin/sh
# Whole-host sampler for any host (installed as /usr/local/bin/hostmon on the sbc host).
#
#   hostmon.sh OUT.csv [INTERVAL_S [PROC,PROC...]]     runs until killed (default interval 5 s)
#
# Columns: ts, cpu_pct (whole host, 100 = every vCPU busy), cpu_max_core_pct, load1, load5, load15,
# mem_used_mb (MemTotal - MemAvailable), udp_rcvbuf_errors, udp_in_errors, net_rx_pps, net_tx_pps
# (all non-loopback interfaces), then per named process (matched on /proc/<pid>/comm, for example
# freesbc, sipp, freeswitch): <name>_cpu_pct (100 = one core, summed over the matches), <name>_maxproc_cpu_pct
# (the busiest single process of that name: ~100 for a SIPp instance means it is saturated, it is mostly
# single-threaded) and <name>_rss_mb. rigcheck.sh reads these.
# Use it on B for the competitor comparison and on A and C to see whether the generator or the
# switch, and not FreeSBC, is the bottleneck. Start it with nohup or tmux; stop it with kill.
set -eu
out=${1:-}
[ -n "$out" ] || { sed -n '2,/^set -eu/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 2; }
exec python3 -I - "$out" "${2:-5}" "${3:-}" <<'PY'
import os, sys, time
out, iv, names = sys.argv[1], float(sys.argv[2]), [n for n in sys.argv[3].split(",") if n]
hz = os.sysconf("SC_CLK_TCK")
def stat():
    cpus = {}
    for l in open("/proc/stat"):
        if l.startswith("cpu"):
            f = l.split(); v = list(map(int, f[1:9]))
            cpus[f[0]] = (sum(v), v[3] + v[4])
    return cpus
def net():
    rx = tx = 0
    for l in list(open("/proc/net/dev"))[2:]:
        n, d = l.split(":"); d = d.split()
        if n.strip() != "lo": rx += int(d[1]); tx += int(d[9])
    return rx, tx
def udp():
    h = None
    for l in open("/proc/net/snmp"):
        if l.startswith("Udp:"):
            f = l.split()
            if h is None: h = f
            else:
                d = dict(zip(h, f)); return int(d["RcvbufErrors"]), int(d["InErrors"])
    return 0, 0
def procs():
    r = {n: [0, 0, {}] for n in names}
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try:
            c = open(f"/proc/{p}/comm").read().strip()
            if c not in r: continue
            f = open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()
            tk = int(f[11]) + int(f[12])
            r[c][0] += tk
            r[c][2][p] = tk
            for l in open(f"/proc/{p}/status"):
                if l.startswith("VmRSS:"): r[c][1] += int(l.split()[1]) // 1024
        except OSError:
            pass
    return r
hdr = "ts,cpu_pct,cpu_max_core_pct,load1,load5,load15,mem_used_mb,udp_rcvbuf_errors,udp_in_errors,net_rx_pps,net_tx_pps"
for n in names: hdr += f",{n}_cpu_pct,{n}_maxproc_cpu_pct,{n}_rss_mb"
new = not os.path.exists(out) or os.path.getsize(out) == 0
f = open(out, "a", buffering=1)
if new: f.write(hdr + "\n")
ps, pn, pp, pt = stat(), net(), procs(), time.time()
while True:
    time.sleep(iv)
    s, n, p, t = stat(), net(), procs(), time.time()
    dt = t - pt
    def pct(k):
        dtot = s[k][0] - ps[k][0]
        return 100.0 * (dtot - (s[k][1] - ps[k][1])) / dtot if dtot else 0.0
    mx = max(pct(k) for k in s if k != "cpu")
    la = open("/proc/loadavg").read().split()[:3]
    mem = {l.split(":")[0]: int(l.split()[1]) for l in open("/proc/meminfo")}
    ub, ui = udp()
    row = [int(t), f"{pct('cpu'):.1f}", f"{mx:.1f}", *la, (mem["MemTotal"] - mem["MemAvailable"]) // 1024, ub, ui,
           int((n[0] - pn[0]) / dt), int((n[1] - pn[1]) / dt)]
    for nm in names:
        mxp = max([(v - pp[nm][2].get(k, v)) for k, v in p[nm][2].items()] or [0])
        row += [f"{(p[nm][0] - pp[nm][0]) / hz / dt * 100:.0f}", f"{mxp / hz / dt * 100:.0f}", p[nm][1]]
    f.write(",".join(map(str, row)) + "\n")
    ps, pn, pp, pt = s, n, p, t
PY
