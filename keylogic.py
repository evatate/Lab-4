# ==============================================================================
# File Name:     keylogic.py
# Author:        Eva Tate and Giselle Wu, assisted by Claude Code
# Course:        CS60: Computer Networks
# Assignment:    Lab 4: Physical layer - Radio Signal Strength
# Date:          October 23, 2026
#
# Description:   Radio-independent logic for Exercise 2: turning RSSI lists into
#                key bits, keeping the bits both devices used, and creating /
#                checking a commitment (HMAC) to the key without revealing it.
#
# ==============================================================================

import hashlib
import hmac
import statistics
import struct


def compute_bits(rssi, z):
    """rssi: {index: dBm}. Returns {index: 0/1} for indices whose RSSI is more
    than z standard deviations above (1) or below (0) this device's own mean."""
    if len(rssi) < 2:
        return {}
    vals = list(rssi.values())
    mean = statistics.mean(vals)
    sd = statistics.pstdev(vals)
    if sd == 0:
        return {}
    bits = {}
    for i, v in rssi.items():
        if v > mean + z * sd:
            bits[i] = 1
        elif v < mean - z * sd:
            bits[i] = 0
    return bits


def pack_mask(indices, n):
    """Bitmask of which indices (0..n-1) were used. Indices only, never bit values."""
    mask = bytearray((n + 7) // 8)
    for i in indices:
        mask[i // 8] |= 1 << (i % 8)
    return bytes(mask)


def unpack_mask(mask, n):
    return [i for i in range(n) if i // 8 < len(mask) and mask[i // 8] & (1 << (i % 8))]


def common_key(bits, other_used):
    """Keep only indices used by both devices. Returns (indices, key string)."""
    common = sorted(set(bits) & set(other_used))
    return common, "".join(str(bits[i]) for i in common)


def commit_tag(key, role, n_init, n_resp, indices):
    """HMAC keyed with the key bits over a role label, both session nonces, and the
    common indices. Reveals nothing usable about the key to a listener, but anyone
    holding the same key computes the same tag."""
    data = role + struct.pack("!II", n_init, n_resp) + pack_mask(indices, max(indices) + 1 if indices else 0)
    return hmac.new(key.encode(), data, hashlib.sha256).digest()


def fingerprint(key):
    return hashlib.sha256(key.encode()).hexdigest()[:16]
