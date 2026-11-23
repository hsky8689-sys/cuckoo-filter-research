#!/usr/bin/env python3
"""s at FIXED capacity: does a bigger bucket make the attacks cheaper?

A client fixes the number of SLOTS C (what it passes as capacity to
CF.RESERVE); the number of buckets then follows, nB = C / s. Earlier runs
varied s at fixed nB (so s only entered through (2s+1) or not at all).
Here s moves nB too. Predictions (blake2 / one-way hash, targeted grind):

  DoS    cost = (2s+1) * nB^2 / 2   with nB = C/s   ~  (2s+1)/s^2 * C^2/2
  poison cost = nB * 255 / 2                        ~  C * 255 / (2 s)

Measured with the existing grind_dos / grind_twin (no new attack code).
Usage: python3 experiment_fixedN.py C reps_dos reps_poison
"""
import csv
import sys

from hashes import blake2_64
from experiment_dos import grind_dos, predicted_cost
from experiment_poison import grind_twin, predicted_twin_cost


def stats(xs):
    n = len(xs)
    m = sum(xs) / n
    var = sum((x - m) ** 2 for x in xs) / (n - 1)
    return m, 1.96 * (var / n) ** 0.5


if __name__ == "__main__":
    C, reps_d, reps_p = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    rows = []
    print(f"C={C} slots (fixed), blake2_64; reps DoS={reps_d}, poison={reps_p}")
    print(f"{'s':>2} {'nB':>5} | {'DoS mean':>10} {'+-CI':>8} {'pred':>9} {'ratio':>6} "
          f"| {'poison mean':>11} {'+-CI':>7} {'pred':>8} {'ratio':>6}")
    for s in (1, 2, 4):
        nB = C // s
        dm, dc = stats([grind_dos(nB, s, blake2_64) for _ in range(reps_d)])
        pm, pc = stats([grind_twin(nB, blake2_64) for _ in range(reps_p)])
        dp, pp = predicted_cost(nB, s), predicted_twin_cost(nB)
        rows.append(dict(C=C, s=s, nB=nB, reps_dos=reps_d, dos_mean=dm, dos_ci95=dc,
                         dos_pred=dp, dos_ratio=dm / dp, reps_poison=reps_p,
                         poison_mean=pm, poison_ci95=pc, poison_pred=pp,
                         poison_ratio=pm / pp))
        print(f"{s:>2} {nB:>5} | {dm:>10.0f} {dc:>8.0f} {dp:>9.0f} {dm/dp:>6.3f} "
              f"| {pm:>11.0f} {pc:>7.0f} {pp:>8.0f} {pm/pp:>6.3f}", flush=True)
    b = rows[0]
    print("\ncost relative to s=1 (measured vs predicted):")
    for r in rows:
        print(f"s={r['s']}: DoS {r['dos_mean']/b['dos_mean']:.3f} "
              f"(pred {r['dos_pred']/b['dos_pred']:.3f})   "
              f"poison {r['poison_mean']/b['poison_mean']:.3f} "
              f"(pred {r['poison_pred']/b['poison_pred']:.3f})")
    with open(f"fixedN_C{C}.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
