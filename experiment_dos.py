#!/usr/bin/env python3
"""Monte Carlo validation of C(v=2): the DoS attacker's cost to force
overflow on a single, fixed, minimal (|V'|=2) bucket pair.

Methodology (the structural/offline model, not a literal insert-by-insert
run against a live filter): the attacker grinds jti candidates and counts
every one whose (h1 mod nB, h2 mod nB) lands exactly on a fixed target
pair. Overflow is forced once (2s+1) such items exist (the |E'|>s|V'|
condition, for the minimal case |V'|=2). The measured cost is the total
number of candidates generated (hits + misses) until that happens.

Today's run uses blake2_64 only (the "clean", no-known-shortcut hash) --
this is the arm that should actually confirm the nB^2 scaling. The Murmur
arm is handled analytically/qualitatively in the write-up, not simulated
here (see the discussion on why: no verified implementation to build on).
"""
import csv
import math
from cuckoo_filter import CF, MASK64
from hashes import blake2_64
from jti_gen import random_jti


def loglog_slope(xs, ys) -> float:
    """Slope of the linear regression of log(y) on log(x); for a power law
    y = A*x^p this slope recovers the exponent p."""
    lx = [math.log(x) for x in xs]
    ly = [math.log(y) for y in ys]
    n = len(xs)
    mx, my = sum(lx) / n, sum(ly) / n
    num = sum((a - mx) * (b - my) for a, b in zip(lx, ly))
    den = sum((a - mx) ** 2 for a in lx)
    return num / den


def pick_target_pair(nB, fp_ref=1):
    """A guaranteed-reachable bucket pair: bucket 0 and its alt() under
    a fixed reference fingerprint."""
    i0 = 0
    i1 = CF.alt(fp_ref, i0) % nB
    return frozenset((i0, i1))


def bucket_pair(jti: str, nB: int, hashfunc) -> frozenset:
    h = hashfunc(jti.encode('utf-8')) & MASK64
    fp = h % 255 + 1
    h1 = h % nB
    h2 = CF.alt(fp, h) % nB
    return frozenset((h1, h2))


def grind_dos(nB: int, s: int, hashfunc) -> int:
    """One trial: grind jti's until (2s+1) of them hash to the same
    fixed target pair. Returns the total number of candidates tried."""
    target = pick_target_pair(nB)
    hits_needed = 2 * s + 1
    hits = 0
    tries = 0
    while hits < hits_needed:
        tries += 1
        if bucket_pair(random_jti(), nB, hashfunc) == target:
            hits += 1
    return tries


def predicted_cost(nB: int, s: int) -> float:
    # P(match) = 2/nB**2 (not 4/nB**2 -- see derivation note), so cost = hits_needed / P
    return (2 * s + 1) * nB * nB / 2


def run_sweep(nB_values, s, hashfunc, reps):
    results = {}
    for nB in nB_values:
        costs = [grind_dos(nB, s, hashfunc) for _ in range(reps)]
        mean = sum(costs) / len(costs)
        variance = sum((c - mean) ** 2 for c in costs) / (len(costs) - 1)
        stderr = (variance / len(costs)) ** 0.5
        results[nB] = {
            "costs": costs,
            "mean": mean,
            "stderr": stderr,
            "predicted": predicted_cost(nB, s),
        }
    return results


if __name__ == "__main__":
    s = 2
    nB_values = [8, 16, 32, 64]
    reps = 30

    results = run_sweep(nB_values, s, blake2_64, reps)

    print(f"s={s}, reps={reps}, hash=blake2_64")
    print(f"{'nB':>5} | {'measured mean':>14} | {'95% CI (+/-)':>13} | {'predicted':>10} | {'ratio':>6}")
    csv_rows = []
    for nB in nB_values:
        r = results[nB]
        ci95 = 1.96 * r["stderr"]
        ratio = r["mean"] / r["predicted"]
        print(f"{nB:>5} | {r['mean']:>14.1f} | {ci95:>13.1f} | {r['predicted']:>10.1f} | {ratio:>6.3f}")
        csv_rows.append({"s": s, "nB": nB, "reps": reps,
                         "measured_mean": f"{r['mean']:.2f}", "ci95": f"{ci95:.2f}",
                         "predicted": f"{r['predicted']:.2f}", "ratio": f"{ratio:.4f}"})

    slope = loglog_slope(nB_values, [results[nB]["mean"] for nB in nB_values])
    print(f"\nlog-log slope vs nB = {slope:.3f} (predicted 2, i.e. cost ~ nB^2)")

    with open("dos_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["s", "nB", "reps", "measured_mean",
                                          "ci95", "predicted", "ratio"])
        w.writeheader()
        w.writerows(csv_rows)
    print("Data written to dos_results.csv.")
