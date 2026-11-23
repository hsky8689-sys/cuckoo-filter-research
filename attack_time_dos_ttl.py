#!/usr/bin/env python3
"""DoS total-attack-time vs the TTL window.

Builds on attack_time_dos.py: an attack is only feasible if it completes within
the TTL window T -- otherwise the planted items expire before 2s+1 are
simultaneously live on the target pair, and the attack self-defeats.

    feasible  <=>  total_attack_time < T

Two deployment scenarios:
  - auth deny-list: nB is COUPLED to T, since the filter holds every jti revoked
    within the token lifetime: nB ~ R_iss * T * f / (s * load). With R_iss=100/s,
    f=1% (CRLite), s=2, load=0.5 this gives nB ~ T (rounded to a power of two).
  - caching filter: nB is LARGE and fixed (millions of entries), independent of
    the token TTL.

Real parameters: xxhash.com (hash rates) + Auth0 (TTL regimes, R_lim).
"""
import csv

R_MURMUR = 1e8    # hashes/s small input   (xxhash.com)
R_BLAKE  = 1e7    # hashes/s small input   (~10x slower, cryptographic)
R_LIM    = 35     # inserts/s              (Auth0 Universal Logout)
S        = 2      # bucket size            (RedisBloom default)


def fmt(sec: float) -> str:
    if sec < 1:        return f"{sec*1000:.2f} ms"
    if sec < 60:       return f"{sec:.2f} s"
    if sec < 3600:     return f"{sec/60:.2f} min"
    if sec < 86400:    return f"{sec/3600:.2f} h"
    if sec < 3.15e7:   return f"{sec/86400:.2f} days"
    return f"{sec/3.15e7:.2f} years"


def dos_total(nB, r_hash, hash_count):
    return hash_count / r_hash + (2*S + 1) / R_LIM


if __name__ == "__main__":
    # (label, nB, TTL seconds)
    scenarios = [
        ("auth 10min (MFA)", 512,      600),      # nB ~ T, coupled
        ("auth 1h",          4096,     3600),
        ("auth 24h (default)", 131072, 86400),
        ("cache 1h",         2**20,    3600),      # nB large, fixed
        ("cache 24h",        2**25,    86400),
    ]
    rows = []

    print(f"DoS feasibility vs TTL window   (s={S}, R_lim={R_LIM}/s)\n")
    print(f"{'scenario':>20} | {'nB':>9} | {'T':>7} | {'blake total':>11} | "
          f"{'blake?':>11} | {'murmur total':>12} | {'murmur?':>8}")
    print("-" * 95)
    for label, nB, T in scenarios:
        blake_hc  = (2*S + 1) * nB * nB / 2
        t_blake   = dos_total(nB, R_BLAKE,  blake_hc)
        t_murmur  = dos_total(nB, R_MURMUR, 2*S + 1)
        blake_ok  = "FEASIBLE" if t_blake  < T else "self-defeat"
        murmur_ok = "FEASIBLE" if t_murmur < T else "self-defeat"
        print(f"{label:>20} | {nB:>9} | {fmt(T):>7} | {fmt(t_blake):>11} | "
              f"{blake_ok:>11} | {fmt(t_murmur):>12} | {murmur_ok:>8}")
        rows.append({"scenario": label, "nB": nB, "T_s": T,
                     "blake_total_s": f"{t_blake:.4g}", "blake_total_h": fmt(t_blake),
                     "blake_feasible": blake_ok,
                     "murmur_total_s": f"{t_murmur:.4g}", "murmur_total_h": fmt(t_murmur),
                     "murmur_feasible": murmur_ok})

    with open("attack_time_dos_ttl.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["scenario", "nB", "T_s",
                                          "blake_total_s", "blake_total_h", "blake_feasible",
                                          "murmur_total_s", "murmur_total_h", "murmur_feasible"])
        w.writeheader()
        w.writerows(rows)
    print("\nData written to attack_time_dos_ttl.csv.")
    print("\nReading: in auth (nB coupled to T) every regime is FEASIBLE for both hashes")
    print("-- the hash does not save you. In caching (large fixed nB) blake SELF-DEFEATS")
    print("because the quadratic grind exceeds the TTL window, while murmur stays feasible.")
