#!/usr/bin/env python3
"""Per-message latency added by FreeSBC, from two captures taken on S2.

Capture both NICs at the same time on the FreeSBC host (one clock, so the
deltas are exact), then compare:

    tcpdump -i <public-if>  -s 0 -B 65536 -w pub.pcap  udp &
    tcpdump -i <private-if> -s 0 -B 65536 -w priv.pcap udp &
    ... run a load step ...
    ./sbc_latency.py pub.pcap priv.pcap --sip-ports 5060,5080,5160

SIP: a message is keyed by (Call-ID, CSeq, method or status code). FreeSBC is
a proxy, so Call-ID and CSeq are the same on both sides of it; the first
sighting on each NIC is used, which ignores retransmissions.

RTP: a packet is keyed by (SSRC, sequence number, timestamp). FreeSBC relays
the RTP header unchanged, so the same key appears on both NICs; this gives
the relay's own per-packet latency, the number that matters for a voice
pipeline. Capture whole packets (-s 0): a truncated SIP message loses its
Call-ID and CSeq, and a G.711 packet is only ~214 bytes anyway. Check
tcpdump's "dropped by kernel" line: a lossy capture under-reports nothing
but makes the sample smaller.

Needs tshark. Prints p50/p90/p99/p99.9/max in milliseconds per message kind.
"""
import argparse
import subprocess
import sys
from collections import defaultdict


def tshark(pcap, display_filter, fields, decode_as):
    cmd = ["tshark", "-r", pcap, "-n", "-Y", display_filter, "-T", "fields",
           "-E", "separator=\t", "-E", "occurrence=f",
           "-o", "rtp.heuristic_rtp:TRUE"]
    for d in decode_as:
        cmd += ["-d", d]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    for line in out.splitlines():
        cols = line.split("\t")
        if len(cols) == len(fields) and cols[0]:
            yield cols


def first_seen(rows, keyfn):
    seen = {}
    for r in rows:
        k = keyfn(r)
        if k is not None and k not in seen:
            seen[k] = float(r[0])
    return seen


def pct(sorted_vals, p):
    if not sorted_vals:
        return float("nan")
    i = min(len(sorted_vals) - 1, max(0, int(round(p / 100.0 * len(sorted_vals))) - 1))
    return sorted_vals[i]


def report(title, pub, priv, kindfn):
    by_kind = defaultdict(list)
    for k, t_pub in pub.items():
        t_priv = priv.get(k)
        if t_priv is not None:
            by_kind[kindfn(k)].append(abs(t_priv - t_pub) * 1000.0)
    print(f"\n{title}")
    print(f"{'kind':<14}{'n':>9}{'p50':>9}{'p90':>9}{'p99':>9}{'p99.9':>9}{'max':>9}   (ms)")
    for kind in sorted(by_kind):
        v = sorted(by_kind[kind])
        print(f"{kind:<14}{len(v):>9}{pct(v,50):>9.3f}{pct(v,90):>9.3f}{pct(v,99):>9.3f}"
              f"{pct(v,99.9):>9.3f}{v[-1]:>9.3f}")
    if not by_kind:
        print("  no message seen on both NICs (check the ports and the capture filter)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pub")
    ap.add_argument("priv")
    ap.add_argument("--sip-ports", default="5060,5080,5160",
                    help="UDP ports to decode as SIP (switch ports included)")
    ap.add_argument("--no-rtp", action="store_true")
    a = ap.parse_args()
    decode = [f"udp.port=={p},sip" for p in a.sip_ports.split(",") if p]

    sip_fields = ["frame.time_epoch", "sip.Call-ID", "sip.CSeq.seq", "sip.CSeq.method", "sip.Status-Code"]

    def sip_key(r):
        # CSeq number: a 407'd INVITE and its authenticated retry differ.
        _, callid, seq, method, status = r
        if not callid or not seq or not method:
            return None
        return (callid, seq + " " + method, status or method)

    pub = first_seen(tshark(a.pub, "sip", sip_fields, decode), sip_key)
    priv = first_seen(tshark(a.priv, "sip", sip_fields, decode), sip_key)
    report("SIP: time between the two NICs, per message kind",
           pub, priv, lambda k: f"{k[2]} ({k[1].split()[-1]})" if k[2].isdigit() else k[2])

    if not a.no_rtp:
        rtp_fields = ["frame.time_epoch", "rtp.ssrc", "rtp.seq", "rtp.timestamp"]
        rk = lambda r: (r[1], r[2], r[3]) if r[1] else None
        pub = first_seen(tshark(a.pub, "rtp && !sip", rtp_fields, decode), rk)
        priv = first_seen(tshark(a.priv, "rtp && !sip", rtp_fields, decode), rk)
        report("RTP: relay latency per packet", pub, priv, lambda k: "rtp")
    return 0


if __name__ == "__main__":
    sys.exit(main())
