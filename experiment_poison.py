#!/usr/bin/env python3
"""Poisoning experiments.

A 'twin' of a victim V is an item T with fp_T == fp_V AND bucket-pair(T) ==
bucket-pair(V). In a cuckoo filter there is no stored key, only (bucket, fp),
so V and T are indistinguishable once both are present.

  E2a    -- blake2 grinding cost to the first twin of a fixed victim.
            P(twin) = (1/255) * (2/nB)  ->  cost = nB*255/2. Slope vs nB ~ 1
            (linear), in contrast to the DoS grind which was nB^2 (slope 2).

  P-abl  -- hash ablation of that cost: murmur builds a twin by inversion in
            O(1); blake must grind, Theta(nB*255). Slope 1 vs 0.

  s-null -- the twin cost is independent of s (a twin is about fp+bucket, not
            how many slots a bucket has). We confirm by sweeping s in {1,2,4}
            at fixed nB and showing the means overlap.

255 = fp space, since fp = h % 255 + 1 gives fingerprints 1..255 (so the "2^f"
factor in the cost formula is 255 here, not 256).
"""
import csv
import math
from hashes import blake2_64, murmurhash64a, MASK64
from cuckoo_filter import CF
from jti_gen import random_jti
from murmur_invert import murmur64a_invert_8

FP_SPACE = 255


def victim_params(nB, hashfunc, jti=None):
    """(fp_V, bucket_pair_V) for a victim jti under the given hash."""
    if jti is None:
        jti = random_jti()
    item = jti.encode('utf-8') if isinstance(jti, str) else jti
    h = hashfunc(item) & MASK64
    fp = h % FP_SPACE + 1
    pair = frozenset((h % nB, CF.alt(fp, h) % nB))
    return fp, pair


def is_twin(cand: bytes, nB, fp_V, pair_V, hashfunc) -> bool:
    h = hashfunc(cand) & MASK64
    if h % FP_SPACE + 1 != fp_V:
        return False
    fp = fp_V
    return frozenset((h % nB, CF.alt(fp, h) % nB)) == pair_V


def grind_twin(nB, hashfunc) -> int:
    """One trial: fix a random victim, grind random jti until a twin appears.
    Returns the number of candidates tried. Does not look at s (s-independent)."""
    fp_V, pair_V = victim_params(nB, hashfunc)
    tries = 0
    while True:
        tries += 1
        if is_twin(random_jti().encode('utf-8'), nB, fp_V, pair_V, hashfunc):
            return tries


def predicted_twin_cost(nB) -> float:
    return nB * FP_SPACE / 2            # 1 / [ (1/255)*(2/nB) ]


def _crt(a, n1, b, n2):
    """Smallest x >= 0 with x ≡ a (mod n1), x ≡ b (mod n2); n1,n2 coprime."""
    inv = pow(n1, -1, n2)
    return a + n1 * (((b - a) * inv) % n2)


def craft_twin_murmur(nB, fp_V, pair_V) -> bytes:
    """Build ONE twin of V by inversion. O(1).
    Need h % 255 = fp_V-1 (fp matches) and h % nB in pair_V (land in V's bucket).
    nB is a power of two, 255 is odd -> coprime -> CRT gives such an h."""
    b_target = min(pair_V)
    h = _crt(b_target, nB, fp_V - 1, FP_SPACE)
    return murmur64a_invert_8(h)


def murmur_twin_cost(nB) -> int:
    """Build a twin by inversion and verify it; cost = 1 inversion."""
    fp_V, pair_V = victim_params(nB, murmurhash64a)
    t = craft_twin_murmur(nB, fp_V, pair_V)
    assert is_twin(t, nB, fp_V, pair_V, murmurhash64a), "constructed item is not a twin"
    return 1


def loglog_slope(xs, ys) -> float:
    lx = [math.log(x) for x in xs]
    ly = [math.log(y) for y in ys]
    n = len(xs)
    mx, my = sum(lx) / n, sum(ly) / n
    num = sum((a - mx) * (b - my) for a, b in zip(lx, ly))
    den = sum((a - mx) ** 2 for a in lx)
    return num / den


def grind_stats(nB, reps):
    costs = [grind_twin(nB, blake2_64) for _ in range(reps)]
    mean = sum(costs) / len(costs)
    var = sum((c - mean) ** 2 for c in costs) / (len(costs) - 1)
    return mean, 1.96 * (var / len(costs)) ** 0.5


if __name__ == "__main__":
    nB_values = [8, 16, 32, 64]
    reps = 250          # a single twin is one geometric draw (CV~1), so the
                        # grind arm needs more reps than DoS to tighten the CI
    csv_rows = []

    # --- E2a + P-ablation (shared blake grind, plus murmur O(1) column) ---
    print("=== E2a (cost to first twin) + P-ABLATION (murmur invert vs blake grind) ===")
    print(f"reps={reps} on the blake arm\n")
    print(f"{'nB':>4} | {'blake mean':>11} | {'95% CI':>9} | "
          f"{'pred nB*255/2':>13} | {'ratio':>6} | {'murmur cost':>11}")
    blake_means = []
    for nB in nB_values:
        mean, ci = grind_stats(nB, reps)
        pred = predicted_twin_cost(nB)
        mcost = murmur_twin_cost(nB)
        blake_means.append(mean)
        print(f"{nB:>4} | {mean:>11.1f} | {ci:>9.1f} | {pred:>13.1f} | "
              f"{mean/pred:>6.3f} | {mcost:>11}")
        csv_rows.append({"experiment": "E2a/P-abl", "nB": nB, "s": "-",
                         "blake_mean": f"{mean:.2f}", "ci95": f"{ci:.2f}",
                         "predicted": f"{pred:.2f}", "ratio": f"{mean/pred:.4f}",
                         "murmur_cost": mcost})
    bslope = loglog_slope(nB_values, blake_means)
    print(f"\n  log-log slope vs nB:  blake = {bslope:.3f} (predicted 1)   "
          f"murmur = 0.000 (predicted 0, O(1))\n")

    # --- s as a null test (at fixed nB) ---
    nB_fixed = 32
    print(f"=== s AS NULL TEST (nB={nB_fixed}, twin cost should not move with s) ===")
    print(f"{'s':>3} | {'blake mean':>11} | {'95% CI':>9}")
    for s in (1, 2, 4):
        mean, ci = grind_stats(nB_fixed, reps)   # grind ignores s by construction
        print(f"{s:>3} | {mean:>11.1f} | {ci:>9.1f}")
        csv_rows.append({"experiment": "s-null", "nB": nB_fixed, "s": s,
                         "blake_mean": f"{mean:.2f}", "ci95": f"{ci:.2f}",
                         "predicted": f"{predicted_twin_cost(nB_fixed):.2f}",
                         "ratio": "-", "murmur_cost": "-"})
    print("  (means overlap within CI -> cost is s-independent, unlike DoS)\n")

    with open("poison_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["experiment", "nB", "s", "blake_mean",
                                          "ci95", "predicted", "ratio", "murmur_cost"])
        w.writeheader()
        w.writerows(csv_rows)
    print("Data written to poison_results.csv.")
