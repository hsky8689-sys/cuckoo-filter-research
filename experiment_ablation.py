#!/usr/bin/env python3
"""Hash ablation for the targeted DoS attack: same goal (2s+1 items on a fixed
target pair), two hashes, two cost regimes.

  - blake2 arm (one-way): the attacker CANNOT invert -> grinds candidates until
    (2s+1) of them land on the pair. Cost = number of candidates generated (each
    = one forward evaluation). Predicted (2s+1)*nB^2/2. Theta(nB^2) scaling ->
    slope 2.

  - murmur arm (invertible): the attacker builds directly, by inversion, (2s+1)
    items on the pair. Cost = number of inversions = 2s+1, INDEPENDENT of nB.
    O(1) -> slope 0.

The metric is counted in "hash-level operations": forward evaluations for blake,
inversions for murmur. One inversion = ~6 multiplications + a few xors, i.e.
roughly the cost of one forward evaluation -- so the comparison is fair, it does
not hide work inside the inversion.

Per-cell metrics: mean over >=30 repetitions (the blake arm is stochastic; the
murmur arm is deterministic), 95% confidence interval, measured/predicted ratio,
log-log slope.
"""
import csv
import math
from hashes import blake2_64
from experiment_dos import grind_dos, predicted_cost
from murmur_invert import craft_items_on_pair


def loglog_slope(xs, ys) -> float:
    """Slope of the linear regression of log(y) on log(x)."""
    lx = [math.log(x) for x in xs]
    ly = [math.log(y) for y in ys]
    n = len(xs)
    mx, my = sum(lx) / n, sum(ly) / n
    num = sum((a - mx) * (b - my) for a, b in zip(lx, ly))
    den = sum((a - mx) ** 2 for a in lx)
    return num / den


def blake_arm(nB_values, s, reps):
    """Stochastic grinding; returns mean, CI95, predicted and ratio per nB."""
    rows = {}
    for nB in nB_values:
        costs = [grind_dos(nB, s, blake2_64) for _ in range(reps)]
        mean = sum(costs) / len(costs)
        var = sum((c - mean) ** 2 for c in costs) / (len(costs) - 1)
        stderr = (var / len(costs)) ** 0.5
        pred = predicted_cost(nB, s)
        rows[nB] = {"mean": mean, "ci95": 1.96 * stderr,
                    "pred": pred, "ratio": mean / pred}
    return rows


def murmur_arm(nB_values, s):
    """Direct construction; cost = number of inversions = 2s+1, deterministic.
    We actually build the items (the proof they land on the pair lives in
    murmur_invert, verified at module level)."""
    rows = {}
    for nB in nB_values:
        items = craft_items_on_pair(nB, 2 * s + 1)
        rows[nB] = {"cost": len(items), "pred": 2 * s + 1, "ratio": 1.0}
    return rows


if __name__ == "__main__":
    nB_values = [8, 16, 32, 64]
    reps = 100
    csv_rows = []

    print("=== HASH ABLATION: targeted DoS cost (operations vs nB) ===")
    print(f"reps={reps} on the blake arm (stochastic); the murmur arm is deterministic\n")

    for s in (1, 2, 4):
        b = blake_arm(nB_values, s, reps)
        m = murmur_arm(nB_values, s)
        need = 2 * s + 1
        print(f"--- s = {s}   (overflow needs 2s+1 = {need} items on the pair) ---")
        print(f"{'nB':>4} | {'blake mean':>11} | {'95% CI':>9} | "
              f"{'pred (2s+1)nB^2/2':>17} | {'ratio':>6} | {'murmur cost':>11}")
        for nB in nB_values:
            rb, rm = b[nB], m[nB]
            print(f"{nB:>4} | {rb['mean']:>11.1f} | {rb['ci95']:>9.1f} | "
                  f"{rb['pred']:>17.1f} | {rb['ratio']:>6.3f} | {rm['cost']:>11}")
            csv_rows.append({"s": s, "nB": nB,
                             "blake_mean": f"{rb['mean']:.2f}",
                             "blake_ci95": f"{rb['ci95']:.2f}",
                             "blake_pred": f"{rb['pred']:.2f}",
                             "blake_ratio": f"{rb['ratio']:.4f}",
                             "murmur_cost": rm['cost']})
        bslope = loglog_slope(nB_values, [b[nB]['mean'] for nB in nB_values])
        mcosts = [m[nB]['cost'] for nB in nB_values]
        mslope = loglog_slope(nB_values, mcosts)   # constant y -> slope 0
        print(f"  log-log slope vs nB:  blake = {bslope:.3f} (predicted 2)   "
              f"murmur = {mslope:.3f} (predicted 0)\n")

    with open("ablation_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["s", "nB", "blake_mean", "blake_ci95",
                                          "blake_pred", "blake_ratio", "murmur_cost"])
        w.writeheader()
        w.writerows(csv_rows)
    print("Data written to ablation_results.csv (for the log-log figure in the chapter).")
