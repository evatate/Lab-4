# ==============================================================================
# File Name:     keyexchange.py
# Author:        Eva Tate and Giselle Wu, assisted by Claude Code
# Course:        CS60: Computer Networks
# Assignment:    Lab 4: Physical layer - Radio Signal Strength
# Date:          October 23, 2026
#
# Description:   Exercise 2: both devices run this same program. They pick roles
#                automatically, trade n frames while measuring RSSI, derive key
#                bits from the RSSI, exchange which indices they used (not bit
#                values), keep the common bits, and confirm the keys match with
#                an HMAC commitment.
#                Usage: sudo python3 keyexchange.py <iface> <channel>
#                       [--n 300] [--z 0.5] [--save rssi.csv]
#
# Frame format (802.11 data frame under RadioTap, payload after the header):
#   magic "KEYX" | type (1B) | session id (4B) | index (2B) | extra length (2B) | extra
# Types: READY, ACK, PING, PONG, END, IDX, COMMIT, CONFIRM
#
# ==============================================================================

import argparse
import hmac
import os
import queue
import random
import struct
import subprocess
import sys
import time

from scapy.all import RadioTap, Dot11, Raw, AsyncSniffer, conf

import keylogic as kl

MAGIC = b"KEYX"
HDR = "!4sBIHH"
HLEN = struct.calcsize(HDR)
READY, ACK, PING, PONG, END, IDX, COMMIT, CONFIRM = range(1, 9)

LISTEN_SECS = (1.5, 3.0)   # random listen window before declaring ourselves initiator
INIT_WAIT = 20.0           # initiator gives up if no responder answers
PING_TIMEOUT = 0.1         # per-frame wait for the reply; skip the index on timeout
HANDSHAKE_TIMEOUT = 8.0    # END / COMMIT retransmission window
RESP_IDLE = 20.0           # responder gives up if the initiator goes quiet


class Radio:
    def __init__(self, iface):
        self.mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.getrandbits(8) for _ in range(5))
        self.sock = conf.L2socket(iface=iface)
        self.q = queue.Queue()
        self.no_rssi = 0          # frames seen without an RSSI field
        self.sniffer = AsyncSniffer(iface=iface, prn=self._rx, store=False)
        self.sniffer.start()
        time.sleep(0.5)

    def _rx(self, pkt):
        if not pkt.haslayer(Dot11) or pkt[Dot11].addr2 == self.mac:
            return
        rssi = getattr(pkt, "dBm_AntSignal", None)
        if rssi is None:
            self.no_rssi += 1
            return
        body = bytes(pkt[Dot11].payload)   # scapy may parse this as LLC, so search for magic
        i = body.find(MAGIC)
        if i < 0 or len(body) - i < HLEN:
            return
        _, t, sess, idx, elen = struct.unpack(HDR, body[i:i + HLEN])
        extra = body[i + HLEN:i + HLEN + elen]
        if len(extra) == elen:
            self.q.put((t, sess, idx, extra, rssi))

    def send(self, t, sess, idx=0, extra=b""):
        payload = struct.pack(HDR, MAGIC, t, sess, idx, len(extra)) + extra
        dot11 = Dot11(type=2, subtype=0, addr1="ff:ff:ff:ff:ff:ff", addr2=self.mac, addr3=self.mac)
        self.sock.send(RadioTap() / dot11 / Raw(payload))

    def recv(self, timeout):
        try:
            return self.q.get(timeout=max(timeout, 0.001))
        except queue.Empty:
            return None

    def close(self):
        try:
            self.sniffer.stop()
        except Exception:
            pass


def determine_role(radio):
    """Returns (role, initiator nonce, responder nonce) or None on timeout."""
    mine = random.getrandbits(32)
    end = time.time() + random.uniform(*LISTEN_SECS)
    print("Listening for an initiator...")
    while time.time() < end:
        m = radio.recv(0.1)
        if m and m[0] == READY:
            radio.send(ACK, m[1], extra=struct.pack("!I", mine))
            return "responder", m[1], mine

    print("No initiator heard; acting as initiator and sending READY frames...")
    deadline = time.time() + INIT_WAIT
    next_tx = 0
    while time.time() < deadline:
        if time.time() >= next_tx:
            radio.send(READY, mine)
            next_tx = time.time() + 0.1
        m = radio.recv(0.05)
        if not m:
            continue
        t, sess, idx, extra, _ = m
        if t == ACK and sess == mine and len(extra) >= 4:
            return "initiator", mine, struct.unpack("!I", extra[:4])[0]
        if t == READY and sess > mine:   # both started at once: higher nonce wins as initiator
            radio.send(ACK, sess, extra=struct.pack("!I", mine))
            return "responder", sess, mine
    return None


def run_initiator(radio, ni, nr, n, z):
    rssi = {}
    for i in range(n):
        radio.send(PING, ni, i)
        deadline = time.time() + PING_TIMEOUT
        while time.time() < deadline:
            m = radio.recv(deadline - time.time())
            if m and m[0] == PONG and m[1] == ni and m[2] == i:
                rssi[i] = m[4]
                break
    bits = kl.compute_bits(rssi, z)
    mask = kl.pack_mask(sorted(bits), n)

    other = None
    end = time.time() + HANDSHAKE_TIMEOUT
    while time.time() < end and other is None:
        radio.send(END, ni, n, mask)
        m = radio.recv(0.1)
        if m and m[0] == IDX and m[1] == ni:
            other = kl.unpack_mask(m[3], n)
    if other is None:
        return rssi, bits, None, "", "no response to END (responder lost?)"

    indices, key = kl.common_key(bits, other)
    if not key:
        return rssi, bits, indices, key, "no common bits"
    tag = kl.commit_tag(key, b"init", ni, nr, indices)
    expect = kl.commit_tag(key, b"resp", ni, nr, indices)
    end = time.time() + HANDSHAKE_TIMEOUT
    while time.time() < end:
        radio.send(COMMIT, ni, 0, tag)
        m = radio.recv(0.1)
        if m and m[0] == CONFIRM and m[1] == ni:
            return rssi, bits, indices, key, "MATCH" if hmac.compare_digest(m[3], expect) else "MISMATCH"
    return rssi, bits, indices, key, "no CONFIRM received"


def run_responder(radio, ni, nr, z):
    rssi, bits, indices, key = {}, {}, None, ""
    status = "initiator went quiet"
    idle = time.time() + RESP_IDLE
    done_at = None
    while True:
        if done_at and time.time() > done_at:
            break
        if time.time() > idle:
            break
        m = radio.recv(0.2)
        if not m or m[1] != ni:
            continue
        t, _, idx, extra, r = m
        idle = time.time() + RESP_IDLE
        if t == READY:
            radio.send(ACK, ni, extra=struct.pack("!I", nr))
        elif t == PING:
            rssi[idx] = r
            radio.send(PONG, ni, idx)
        elif t == END:
            n = idx
            if not bits:
                bits = kl.compute_bits(rssi, z)
            other = kl.unpack_mask(extra, n)
            radio.send(IDX, ni, n, kl.pack_mask(sorted(bits), n))
            indices, key = kl.common_key(bits, other)
            if not key:   # initiator will abort too; linger for retransmitted ENDs, then stop
                status = "no common bits"
                done_at = done_at or time.time() + 3.0
        elif t == COMMIT and key:
            ok = hmac.compare_digest(extra, kl.commit_tag(key, b"init", ni, nr, indices))
            radio.send(CONFIRM, ni, 0, kl.commit_tag(key, b"resp", ni, nr, indices))
            status = "MATCH" if ok else "MISMATCH"
            done_at = done_at or time.time() + 2.0   # linger so retransmitted COMMITs get answered
    return rssi, bits, indices, key, status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("iface")
    ap.add_argument("channel", type=int)
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--z", type=float, default=0.5)
    ap.add_argument("--save", help="write index,rssi CSV here")
    args = ap.parse_args()

    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.sh")
    subprocess.run([script, args.iface, str(args.channel)], check=True)

    radio = Radio(args.iface)
    try:
        r = determine_role(radio)
        if r is None:
            print("Timed out: no responder heard.")
            return 1
        role, ni, nr = r
        print("Role: %s (session %08x)" % (role.upper(), ni))
        if role == "initiator":
            print("Exchanging %d frames - wave your hand between the devices now!" % args.n)
            rssi, bits, indices, key, status = run_initiator(radio, ni, nr, args.n, args.z)
        else:
            print("Responding to frames - wave your hand between the devices now!")
            rssi, bits, indices, key, status = run_responder(radio, ni, nr, args.z)
    finally:
        no_rssi = radio.no_rssi
        radio.close()
    if no_rssi:
        print("WARNING: %d received frames had no RSSI field (driver not reporting signal?)" % no_rssi)

    if args.save:
        with open(args.save, "w") as f:
            f.write("index,rssi\n")
            for i in sorted(rssi):
                f.write("%d,%d\n" % (i, rssi[i]))
    if role == "initiator":
        print("\nFrames lost (no reply)     : %d of %d" % (args.n - len(rssi), args.n))
    print("\nFrames with RSSI measured : %d" % len(rssi))
    print("Bits derived (z=%.2f)      : %d" % (args.z, len(bits)))
    print("Bits in common             : %s" % (len(indices) if indices is not None else "n/a"))
    print("Key (%d bits)              : %s" % (len(key), key))
    if key:
        print("Key SHA-256 fingerprint    : %s" % kl.fingerprint(key))
    print("Key confirmation           : %s" % status)
    return 0 if status == "MATCH" else 1


if __name__ == "__main__":
    sys.exit(main())
