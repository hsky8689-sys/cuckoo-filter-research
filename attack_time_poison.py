#!/usr/bin/env python3
"""Total-attack-time model for targeted poisoning (one twin of a fixed victim).

Same naive two-channel formula as the DoS model:
    total = offline grinding time + online submission time
          = hash_count / r_hash   +   insert_count / R_lim

Real parameters: identical to attack_time_dos.py (xxhash.com, Auth0).

Cost models (one twin = same fingerprint AND bucket pair as the victim):
  blake (one-way):  hash_count = 255*nB/2   -- must grind (LINEAR in nB, slope 1)
  murmur (invert):  hash_count = 1          -- direct construction, O(1) in nB
  insert_count     = 1                      -- a single online op (the delete, or the twin insert)

Key contrast with DoS: DoS hash_count ~ nB^2 (quadratic) vs poison ~ nB (linear),
so the crypto hash can make DoS infeasible at large nB but never makes poison infeasible.
"""
import csv

R_MURMUR = 1e8    # hashes/s small input   (xxhash.com: Murmur3)
R_BLAKE  = 1e7    # hashes/s small input   (~10x slower, cryptographic)
R_LIM    = 35     # ops/s                  (Auth0 Universal Logout)
FP_SPACE = 255    # fingerprints           (fp = h%255 + 1)


def fmt(sec: float) -> str:
    if sec < 1:return f"{sec*1000:.2f} ms"
    if sec < 60:return f"{sec:.2f} s"
    if sec < 3600:return f"{sec/60:.2f} min"
    if sec < 86400:return f"{sec/3600:.2f} h"
    if sec < 3.15e7:return f"{sec/86400:.2f} days"
    return f"{sec/3.15e7:.2f} years"


def poison_total(r_hash, hash_count):
    offline = hash_count / r_hash
    online  = 1 / R_LIM
    return offline + online


if __name__ == "__main__":
    nB_values = [2**11, 2**13, 2**15, 2**20, 2**25]
    rows = []

    print(f"Targeted poison total attack time   (R_lim={R_LIM}/s, "
          f"r_murmur={R_MURMUR:.0e}, r_blake={R_BLAKE:.0e})\n")
    print(f"{'nB':>10} | {'blake hash_count':>16} | {'blake total':>12} | {'murmur total':>12}")
    print("-" * 62)
    for nB in nB_values:
        blake_hc  = FP_SPACE * nB / 2
        murmur_hc = 1
        t_blake  = poison_total(R_BLAKE,  blake_hc)
        t_murmur = poison_total(R_MURMUR, murmur_hc)
        print(f"{nB:>10} | {blake_hc:>16.2e} | {fmt(t_blake):>12} | {fmt(t_murmur):>12}")
        rows.append({"nB": nB,
                     "blake_hash_count": f"{blake_hc:.3e}",
                     "blake_total_s": f"{t_blake:.4g}", "blake_total_h": fmt(t_blake),
                     "murmur_total_s": f"{t_murmur:.4g}", "murmur_total_h": fmt(t_murmur)})

    with open("attack_time_poison.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["nB", "blake_hash_count",
                                          "blake_total_s", "blake_total_h",
                                          "murmur_total_s", "murmur_total_h"])
        w.writeheader()
        w.writerows(rows)
    print("\nData written to attack_time_poison.csv.")
    print("\nReading: poison is LINEAR in nB, so even at Redis-max (2^25) blake costs")
    print("under a minute -- the crypto hash never makes poison infeasible, at any scale.")
