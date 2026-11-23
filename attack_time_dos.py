#!/usr/bin/env python3
"""Total-attack-time model for targeted DoS (overflow one fixed bucket pair).

Naive two-channel formula:
    total = offline grinding time + online submission time
          = hash_count / r_hash   +   insert_count / R_lim

Real parameters (sources):
  r_murmur, r_blake : hash throughput on small inputs. From xxhash.com / SMHasher:
                      Murmur3 ~3.9 GB/s, Blake2 ~1.1 GB/s (small-data velocity 56 vs 5.1).
                      On a ~16-byte jti this is ~1e8 vs ~1e7 hashes/s (single core, order of mag).
  R_lim             : Auth0 Universal Logout (token revocation) rate limit = 35 req/s.
  s                 : bucket size (RedisBloom default = 2).

Cost models (targeted overflow of one pair, needs 2s+1 items on it):
  blake (one-way):  hash_count = (2s+1)*nB^2/2   -- must grind (slope 2 in nB)
  murmur (invert):  hash_count = 2s+1            -- direct construction, O(1) in nB
  insert_count     = 2s+1                        -- only the useful items are submitted
"""
import csv

R_MURMUR = 1e8    # hashes/s on small input   (xxhash.com: Murmur3 fast)
R_BLAKE  = 1e7    # hashes/s on small input   (~10x slower, cryptographic)
R_LIM    = 35     # inserts/s                 (Auth0 Universal Logout)
S        = 2      # bucket size               (RedisBloom default)


def fmt(sec: float) -> str:
    if sec < 1:return f"{sec*1000:.2f} ms"
    if sec < 60:return f"{sec:.2f} s"
    if sec < 3600:return f"{sec/60:.2f} min"
    if sec < 86400:return f"{sec/3600:.2f} h"
    if sec < 3.15e7:return f"{sec/86400:.2f} days"
    return f"{sec/3.15e7:.2f} years"


def dos_total(nB, s, r_hash, hash_count):
    offline = hash_count / r_hash
    online  = (2*s + 1) / R_LIM
    return offline, online, offline + online


if __name__ == "__main__":
    # realistic deny-list sizes (2^11..2^15) + Redis-scale (2^20, 2^25)
    nB_values = [2**11, 2**13, 2**15, 2**20, 2**25]
    rows = []

    print(f"Targeted DoS total attack time   (s={S}, R_lim={R_LIM}/s, "
          f"r_murmur={R_MURMUR:.0e}, r_blake={R_BLAKE:.0e})\n")
    print(f"{'nB':>10} | {'blake hash_count':>16} | {'blake total':>12} | {'murmur total':>12}")
    print("-" * 62)
    for nB in nB_values:
        blake_hc  = (2*S + 1) * nB * nB / 2
        murmur_hc = (2*S + 1)
        _, _, t_blake  = dos_total(nB, S, R_BLAKE,  blake_hc)
        _, _, t_murmur = dos_total(nB, S, R_MURMUR, murmur_hc)
        print(f"{nB:>10} | {blake_hc:>16.2e} | {fmt(t_blake):>12} | {fmt(t_murmur):>12}")
        rows.append({"nB": nB, "s": S,
                     "blake_hash_count": f"{blake_hc:.3e}",
                     "blake_total_s": f"{t_blake:.4g}", "blake_total_h": fmt(t_blake),
                     "murmur_total_s": f"{t_murmur:.4g}", "murmur_total_h": fmt(t_murmur)})

    with open("attack_time_dos.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["nB", "s", "blake_hash_count",
                                          "blake_total_s", "blake_total_h",
                                          "murmur_total_s", "murmur_total_h"])
        w.writeheader()
        w.writerows(rows)
    print("\nData written to attack_time_dos.csv.")
    print("\nReading: blake stays cheap at deny-list scale (2^11-2^15) and only becomes")
    print("infeasible at Redis-max nB (2^25); murmur is online-bound (~0.14 s) at every scale.")
