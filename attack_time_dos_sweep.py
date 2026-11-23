#!/usr/bin/env python3
"""Diversified DoS feasibility sweep: filter size x attacker grinding power.

The single-scenario view ("only the rate limit saves you") holds for a WEAK
attacker at small nB. This sweep adds the attacker-power axis, which reveals a
2D landscape: the crypto-hash defence works only against a weak attacker at
large nB, and collapses as the attacker gains grinding power (GPU / botnet).

total = hash_count / r_blake_eff  +  (2s+1) / R_lim
feasible(T) <=> total < T

Real anchors:
  nB <= 2^20  : RedisBloom max initial capacity per sub-filter (redis.io CF.RESERVE)
  r_blake 1e7 : single core (xxhash.com small-data rate)
  R_lim 35/s  : Auth0 Universal Logout
"""
import csv

R_LIM = 35
S = 2
R_BLAKE_1CORE = 1e7     # hashes/s, single core

# attacker power multipliers over single-core blake
ATTACKERS = {"1-core": 1, "many-core (x100)": 100, "GPU/botnet (x1000)": 1000}
NB_VALUES = [2**10, 2**12, 2**14, 2**16, 2**18, 2**20]
TTLS = {"1h": 3600, "24h": 86400}


def fmt(sec):
    if sec < 1:      return f"{sec*1000:.1f} ms"
    if sec < 60:     return f"{sec:.1f} s"
    if sec < 3600:   return f"{sec/60:.1f} min"
    if sec < 86400:  return f"{sec/3600:.1f} h"
    if sec < 3.15e7: return f"{sec/86400:.1f} days"
    return f"{sec/3.15e7:.1f} years"


if __name__ == "__main__":
    rows = []
    print(f"DoS blake total time by filter size x attacker power   (s={S}, R_lim={R_LIM}/s)\n")
    header = f"{'nB':>8} | " + " | ".join(f"{a:>18}" for a in ATTACKERS)
    print(header); print("-" * len(header))
    for nB in NB_VALUES:
        hc = (2*S + 1) * nB * nB / 2
        cells = []
        for a, mult in ATTACKERS.items():
            total = hc / (R_BLAKE_1CORE * mult) + (2*S + 1) / R_LIM
            cells.append(fmt(total))
            rows.append({"nB": nB, "attacker": a, "r_blake_eff": R_BLAKE_1CORE*mult,
                         "blake_total_s": f"{total:.4g}", "blake_total_h": fmt(total),
                         "feasible_1h": total < TTLS["1h"],
                         "feasible_24h": total < TTLS["24h"]})
        print(f"{nB:>8} | " + " | ".join(f"{c:>18}" for c in cells))

    # murmur reference: always online-bound
    murmur_total = 1/1e8 * (2*S+1) + (2*S+1)/R_LIM
    print(f"\nmurmur (any nB, any attacker): {fmt(murmur_total)}  -- always online-bound")

    with open("attack_time_dos_sweep.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["nB", "attacker", "r_blake_eff",
                                          "blake_total_s", "blake_total_h",
                                          "feasible_1h", "feasible_24h"])
        w.writeheader(); w.writerows(rows)
    print("\nData written to attack_time_dos_sweep.csv.")
