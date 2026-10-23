# ==============================================================================
# File Name:     survivor.py
# Author:        Eva Tate and Giselle Wu, assisted by Claude Code
# Course:        CS60: Computer Networks
# Assignment:    Lab 4: Physical layer - Radio Signal Strength
# Date:          October 23, 2026
#
# Description:   Survivor program (Exercise 1). Puts the adapter in monitor mode
#                and repeatedly transmits a custom 802.11 beacon (RadioTap +
#                broadcast data frame) that rescuers can detect and measure.
#                Usage: sudo python3 survivor.py <iface> <channel> [--id N]
#                       [--rate HZ] [--status N]
#
# ==============================================================================

import argparse
import os
import random
import struct
import subprocess
import time

from scapy.all import RadioTap, Dot11, Raw, conf

# Beacon payload: magic, survivor id, sequence number, battery %, status code
# (status: 0 = OK, 1 = injured, 2 = trapped / needs urgent help)
MAGIC = b"SARB"
BEACON_FMT = "!4sIIBB"


def survivor_mac(sid):
    """Locally administered MAC derived from the survivor id (unique per survivor)."""
    return "02:5a:%02x:%02x:%02x:%02x" % ((sid >> 24) & 0xFF, (sid >> 16) & 0xFF,
                                          (sid >> 8) & 0xFF, sid & 0xFF)


def build_beacon(sid, seq, battery, status):
    payload = struct.pack(BEACON_FMT, MAGIC, sid, seq, battery, status)
    mac = survivor_mac(sid)
    dot11 = Dot11(type=2, subtype=0, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    return RadioTap() / dot11 / Raw(payload)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("iface")
    ap.add_argument("channel", type=int)
    ap.add_argument("--id", type=lambda x: int(x, 0), default=random.getrandbits(32))
    ap.add_argument("--rate", type=float, default=10.0, help="beacons per second")
    ap.add_argument("--status", type=int, default=0)
    ap.add_argument("--battery", type=int, default=100)
    args = ap.parse_args()

    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.sh")
    subprocess.run([script, args.iface, str(args.channel)], check=True)

    print("Survivor 0x%08x transmitting %.0f beacons/s (Ctrl-C to stop)" % (args.id, args.rate))
    sock = conf.L2socket(iface=args.iface)
    seq = 0
    try:
        while True:
            sock.send(build_beacon(args.id, seq, args.battery, args.status))
            seq = (seq + 1) & 0xFFFFFFFF
            time.sleep(1.0 / args.rate)
    except KeyboardInterrupt:
        print("\nStopped after %d beacons" % seq)


if __name__ == "__main__":
    main()
