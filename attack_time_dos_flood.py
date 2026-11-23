#!/usr/bin/env python3
"""Flood DoS vs the rate limit -- the regime where rate-limiting is the defence.

Two DoS modes with ORTHOGONAL defences:

  TARGETED (overflow one pair): offline-bound. Needs 2s+1 colliding items on a
    fixed pair -> grinding (2s+1)*nB^2/2 hashes. Online footprint tiny (2s+1).
    Defended by: crypto hash (vs a weak attacker). Rate limit barely bites.
    -> see attack_time_dos_sweep.py

  FLOOD (overflow the whole filter): online-bound, HASH-INDEPENDENT. Any random
    item fills a bucket, no grinding needed; the attacker must simply submit
    ~nB*s items to fill the filter to failure. total = nB*s / R_lim.
    Defended by: a LOW rate limit. Hash irrelevant.

So the two defences do not overlap: low rate limit stops flood; crypto hash
stops targeted (vs a weak attacker). A robust deployment needs both.

Real anchor: Auth0 rate-limit tiers (free 2/s, essentials 25/s, revocation 35/s,
production 100/s, private-cloud 1500/s and 6000/s).
"""
import csv

S = 2
R_TIERS = {"free 2/s": 2, "essentials 25/s": 25, "revocation 35/s": 35,
           "production 100/s": 100, "priv-cloud 1500/s": 1500, "priv-cloud 6000/s": 6000}
NB_VALUES = [2**10, 2**14, 2**16, 2**18, 2**20]


def fmt(sec):
    if sec < 1:      return f"{sec*1000:.1f} ms"
    if sec < 60:     return f"{sec:.1f} s"
    if sec < 3600:   return f"{sec/60:.1f} min"
    if sec < 86400:  return f"{sec/3600:.1f} h"
    if sec < 3.15e7: return f"{sec/86400:.1f} days"
    return f"{sec/3.15e7:.1f} years"


if __name__ == "__main__":
    rows = []
    print(f"FLOOD DoS total time = nB*s / R_lim   (s={S}, hash-independent)\n")
    header = f"{'nB':>8} | " + " | ".join(f"{t:>17}" for t in R_TIERS)
    print(header); print("-" * len(header))
    for nB in NB_VALUES:
        items = nB * S                      # items to submit to fill to failure
        cells = []
        for tier, R in R_TIERS.items():
            total = items / R
            cells.append(fmt(total))
            rows.append({"nB": nB, "items_to_submit": items, "tier": tier, "R_lim": R,
                         "flood_total_s": f"{total:.4g}", "flood_total_h": fmt(total)})
        print(f"{nB:>8} | " + " | ".join(f"{c:>17}" for c in cells))

    with open("attack_time_dos_flood.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["nB", "items_to_submit", "tier", "R_lim",
                                          "flood_total_s", "flood_total_h"])
        w.writeheader(); w.writerows(rows)
    print("\nData written to attack_time_dos_flood.csv.")
    print("\nReading: flood is purely online-bound and hash-independent; a LOW rate limit")
    print("is the only defence (free 2/s makes even a small filter take hours). Contrast:")
    print("targeted is offline-bound, defended by the hash, not the rate limit. Orthogonal.")
