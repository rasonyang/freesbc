#!/usr/bin/env python3
"""Generate a G.711 PCMU (payload type 0) pcap for SIPp's play_pcap_audio.

Usage: gen_pcap.py [-s SECONDS] [-o OUT.pcap]

One RTP packet every 20 ms (160 bytes of mu-law, a 440 Hz tone), wrapped in
Ethernet/IPv4/UDP so SIPp can replay it. SIPp rewrites the addresses, ports
and SSRC at play time and only keeps the inter-packet timing and payload.
Standard library only.
"""
import argparse
import math
import struct


def lin2ulaw(sample):
    bias, clip = 0x84, 32635
    sign = 0x80 if sample < 0 else 0
    if sample < 0:
        sample = -sample
    sample = min(sample, clip) + bias
    exp = 7
    mask = 0x4000
    while exp > 0 and not (sample & mask):
        exp -= 1
        mask >>= 1
    mant = (sample >> (exp + 3)) & 0x0F
    return ~(sign | (exp << 4) | mant) & 0xFF


def checksum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-s", "--seconds", type=int, default=10)
    ap.add_argument("-o", "--out", default="g711u.pcap")
    a = ap.parse_args()
    pkts = a.seconds * 50
    with open(a.out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(pkts):
            payload = bytes(
                lin2ulaw(int(8000 * math.sin(2 * math.pi * 440 * (i * 160 + n) / 8000)))
                for n in range(160)
            )
            rtp = struct.pack("!BBHII", 0x80, 0, i & 0xFFFF, i * 160, 0x1234ABCD) + payload
            udp = struct.pack("!HHHH", 6000, 6000, 8 + len(rtp), 0) + rtp
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), i & 0xFFFF, 0, 64, 17, 0,
                             bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
            ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
            eth = bytes(6) + bytes(6) + b"\x08\x00"
            frame = eth + ip + udp
            t = i * 20000
            f.write(struct.pack("<IIII", t // 1000000, t % 1000000, len(frame), len(frame)))
            f.write(frame)


if __name__ == "__main__":
    main()
