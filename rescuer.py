# ==============================================================================
# File Name:     rescuer.py
# Author:        Eva Tate and Giselle Wu, assisted by Claude Code
# Course:        CS60: Computer Networks
# Assignment:    Lab 4: Physical layer - Radio Signal Strength
# Date:          October 23, 2026
#
# Description:   Rescuer program (Exercise 1). Puts the adapter in monitor mode,
#                sniffs for survivor beacons on a background thread, and shows
#                a live ncurses table of each survivor's RSSI, trend (closer /
#                farther), and time since the last beacon.
#                Usage: sudo python3 rescuer.py <iface> <channel>
#
# ==============================================================================

import argparse
import curses
import os
import struct
import subprocess
import threading
import time
from collections import deque

from scapy.all import sniff, Dot11

MAGIC = b"SARB"
BEACON_FMT = "!4sIIBB"
BEACON_LEN = struct.calcsize(BEACON_FMT)
STATUS = {0: "OK", 1: "INJURED", 2: "URGENT"}
STALE_SECS = 5.0     # mark survivors not heard recently as lost
TREND_WINDOW = 8     # samples per half of the trend comparison
TREND_DB = 1.0       # dB change needed to call it closer/farther

survivors = {}       # id -> dict of state
lock = threading.Lock()
stop_event = threading.Event()
sniff_error = []     # set if the sniffer thread dies, so the UI can say so


def get_rssi(pkt):
    """RSSI in dBm from the RadioTap header (None if the driver didn't report it)."""
    return getattr(pkt, "dBm_AntSignal", None)


def handle_packet(pkt):
    if not pkt.haslayer(Dot11):
        return
    # Scapy may dissect our payload as LLC, so search the raw frame body
    body = bytes(pkt[Dot11].payload)
    i = body.find(MAGIC)
    data = body[i:i + BEACON_LEN] if i >= 0 else b""
    if len(data) < BEACON_LEN:
        return
    rssi = get_rssi(pkt)
    if rssi is None:
        return
    _, sid, seq, battery, status = struct.unpack(BEACON_FMT, data[:BEACON_LEN])
    now = time.time()
    with lock:
        s = survivors.setdefault(sid, {"hist": deque(maxlen=2 * TREND_WINDOW),
                                       "count": 0, "last": now})
        if now - s["last"] > STALE_SECS:
            s["hist"].clear()   # reappeared after being lost: don't trend on old samples
        s["hist"].append(rssi)
        s.update(rssi=rssi, seq=seq, battery=battery, status=status, last=now)
        s["count"] += 1


def sniffer(iface):
    try:
        sniff(iface=iface, prn=handle_packet, store=False,
              stop_filter=lambda p: stop_event.is_set())
    except Exception as e:
        sniff_error.append(str(e))


def trend(hist):
    """Compare mean of the newest samples to the previous ones."""
    h = list(hist)
    if len(h) < 2 * TREND_WINDOW:
        return "...", 0
    old = sum(h[:TREND_WINDOW]) / TREND_WINDOW
    new = sum(h[TREND_WINDOW:]) / TREND_WINDOW
    if new - old >= TREND_DB:
        return "CLOSER  ^", 1
    if old - new >= TREND_DB:
        return "FARTHER v", -1
    return "steady  -", 0


def bar(rssi, width=20):
    """Map -90..-30 dBm onto a bar."""
    frac = max(0.0, min(1.0, (rssi + 90) / 60.0))
    n = int(frac * width)
    return "#" * n + "." * (width - n)


def put(stdscr, y, text, attr=0):
    """addstr that clips to the window instead of crashing on small terminals."""
    maxy, maxx = stdscr.getmaxyx()
    if y >= maxy or maxx < 2:
        return
    try:
        stdscr.addstr(y, 0, text[:maxx - 1], attr)
    except curses.error:
        pass


def ui(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)
    curses.init_pair(2, curses.COLOR_RED, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_WHITE, -1)

    while True:
        if stdscr.getch() in (ord("q"), ord("Q")):
            break
        stdscr.erase()
        put(stdscr, 0, "SEARCH & RESCUE LOCATOR  (q to quit)", curses.A_BOLD)
        put(stdscr, 2, "%-12s %6s  %-20s %-10s %-8s %5s %6s" %
            ("SURVIVOR", "RSSI", "SIGNAL", "TREND", "STATUS", "BATT", "SEEN"),
            curses.A_UNDERLINE)
        now = time.time()
        with lock:
            rows = sorted(survivors.items(), key=lambda kv: kv[1]["rssi"], reverse=True)
            snap = [(sid, dict(s)) for sid, s in rows]
            hists = {sid: list(s["hist"]) for sid, s in rows}
        for i, (sid, s) in enumerate(snap):
            age = now - s["last"]
            label, d = trend(hists[sid])
            if age > STALE_SECS:
                label, color = "lost", curses.color_pair(4) | curses.A_DIM
            else:
                color = curses.color_pair(1 if d > 0 else 2 if d < 0 else 3)
            line = "0x%08x %4d dBm  %-20s %-10s %-8s %4d%% %5.1fs ago" % (
                sid, s["rssi"], bar(s["rssi"]), label,
                STATUS.get(s["status"], "?"), s["battery"], age)
            put(stdscr, 3 + i, line, color)
        if sniff_error:
            put(stdscr, 4, "SNIFFER ERROR: " + sniff_error[0], curses.color_pair(2))
        elif not snap:
            put(stdscr, 4, "Listening... no survivors detected yet.")
        stdscr.refresh()
        time.sleep(0.1)
    stop_event.set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("iface")
    ap.add_argument("channel", type=int)
    args = ap.parse_args()

    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.sh")
    subprocess.run([script, args.iface, str(args.channel)], check=True)
    time.sleep(1)

    t = threading.Thread(target=sniffer, args=(args.iface,), daemon=True)
    t.start()
    curses.wrapper(ui)


if __name__ == "__main__":
    main()
