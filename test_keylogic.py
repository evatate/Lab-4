# ==============================================================================
# File Name:     test_keylogic.py
# Author:        Eva Tate and Giselle Wu, assisted by Claude Code
# Course:        CS60: Computer Networks
# Assignment:    Lab 4: Physical layer - Radio Signal Strength
# Date:          October 23, 2026
#
# Description:   Simulates two devices measuring correlated, noisy RSSI (with
#                dropped frames) and checks that keylogic produces matching keys.
#
# ==============================================================================

import random
import keylogic as kl

random.seed(1)
N = 300
base, s = [], -50.0
for _ in range(N):                 # slowly varying "hand wave" signal
    s += random.gauss(0, 2)
    s = max(-80, min(-30, s))
    base.append(s)

for z in (0.25, 0.5, 1.0):
    A = {i: round(base[i] + random.gauss(0, 1)) for i in range(N) if random.random() > 0.05}
    B = {i: round(base[i] + random.gauss(0, 1)) for i in range(N) if random.random() > 0.05}
    ba, bb = kl.compute_bits(A, z), kl.compute_bits(B, z)
    ua = kl.unpack_mask(kl.pack_mask(ba, N), N)
    ub = kl.unpack_mask(kl.pack_mask(bb, N), N)
    ia, ka = kl.common_key(ba, ub)
    ib, kb = kl.common_key(bb, ua)
    print("z=%.2f  A used %3d  B used %3d  common %3d  keys equal: %s" %
          (z, len(ba), len(bb), len(ia), ka == kb))
    ta = kl.commit_tag(ka, b"init", 1, 2, ia)
    assert ia == ib and len(ka) > 0
    if ka == kb:
        assert ta == kl.commit_tag(kb, b"init", 1, 2, ib)
    else:
        assert ta != kl.commit_tag(kb, b"init", 1, 2, ib)
print("OK")
