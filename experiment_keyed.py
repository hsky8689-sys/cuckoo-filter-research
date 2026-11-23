#!/usr/bin/env python3
"""Client-side defence: key the jti before it reaches the filter.

Defence (no change to Redis): the application sends CF.ADD(PRF(secret, jti))
instead of CF.ADD(jti). Redis still applies its own MurmurHash64A, but to a
value the attacker cannot predict. Here: PRF = keyed BLAKE2b (64-bit tag),
then MurmurHash64A, i.e. exactly "murmur applied on a keyed tag".

What this module measures (all Monte Carlo, on our CF class / same key
arithmetic as experiment_poison.py):

  K1 flood   -- blind attacker (cannot target) inserts random jti until the
                first insertion failure. Predicted: ~ alpha(s)*nB*s inserts,
                i.e. the hash-independent flood cost, linear in nB*s.
  K2 poison  -- blind attacker plants M random jti; fraction of victims that
                get a twin vs. 1-(1-p)^M, with p = P(twin) per planted item.
                Expected twin count per victim ~ 255*nB/2 INSERTIONS (same
                count as grinding, but now every try is an online insertion).
  K3 crafted -- twins crafted by murmur inversion (O(1) when the hash is
                public) are replayed against the keyed filter: success should
                collapse from 100% to ~p.
  Sizing     -- analytic table (from the validated K2 / K1 formulas):
                minimal nB so the attack does not fit in the TTL window.

Only reads/uses existing modules; nothing in them is modified.
"""
import csv
import hashlib
import math
import os
import statistics
import sys
import time

from hashes import murmurhash64a
from cuckoo_filter import CF
from jti_gen import random_jti
from experiment_poison import victim_params, craft_twin_murmur, FP_SPACE

C = 0x5bd1e995


def keyed_hash(key: bytes):
    """Redis' hash applied to a keyed 64-bit tag of the item."""
    def h(item):
        if isinstance(item, str):
            item = item.encode('utf-8')
        tag = hashlib.blake2b(item, digest_size=8, key=key).digest()
        return murmurhash64a(tag)
    return h


def item_key(h: int, nB: int):
    """(fp, sorted bucket pair): two items are twins iff these are equal."""
    fp = h % FP_SPACE + 1
    b1, b2 = h % nB, CF.alt(fp, h) % nB
    return fp, min(b1, b2), max(b1, b2)


def ci95(xs):
    if len(xs) < 2:
        return 0.0
    return 1.96 * statistics.stdev(xs) / math.sqrt(len(xs))


# ---------------------------------------------------------------- K1 flood
def flood_once(nB, s):
    cf = CF(nB, s, ef=0, hashfunc=keyed_hash(os.urandom(16)))
    n = 0
    while cf.add(random_jti()) == "ok":
        n += 1
    return n                      # successful inserts before the first failure


def run_flood(nBs, ss, reps):
    rows = []
    for s in ss:
        for nB in nBs:
            xs = [flood_once(nB, s) for _ in range(reps)]
            m = statistics.mean(xs)
            rows.append(dict(s=s, nB=nB, reps=reps, inserts_mean=m,
                             ci95=ci95(xs), alpha_hat=m / (nB * s),
                             targeted_online_inserts=2 * s + 1,
                             online_ratio_blind_vs_targeted=(m + 1) / (2 * s + 1)))
            print(f"flood s={s} nB={nB:4d}: inserts={m:8.1f} +-{ci95(xs):6.1f}"
                  f"  alpha_hat={m/(nB*s):.3f}", flush=True)
    return rows


# --------------------------------------------------------------- K2 poison
def p_per_fp(nB):
    """P(a random item is a twin of a victim with fingerprint f), per f."""
    out = []
    for f in range(1, FP_SPACE + 1):
        d = (f * C) % nB
        out.append((1.0 / FP_SPACE) * (1 if d == 0 else 2) / nB)
    return out


def theory_frac(nB, M):
    ps = p_per_fp(nB)
    return sum(1 - (1 - p) ** M for p in ps) / len(ps)


def poison_trial(nB, checkpoints, n_victims):
    H = keyed_hash(os.urandom(16))
    first = {}
    for i in range(max(checkpoints)):
        k = item_key(H(random_jti()), nB)
        if k not in first:
            first[k] = i
    hit = [0] * len(checkpoints)
    for _ in range(n_victims):
        idx = first.get(item_key(H(random_jti()), nB))
        if idx is None:
            continue
        for j, M in enumerate(checkpoints):
            if idx < M:
                hit[j] += 1
    return [h / n_victims for h in hit]


def run_poison(nBs, trials, n_victims, cs=(0.25, 0.5, 1, 2, 3, 4)):
    rows = []
    for nB in nBs:
        mean0 = nB * FP_SPACE / 2
        cps = [max(1, round(c * mean0)) for c in cs]
        t0 = time.time()
        per = [poison_trial(nB, cps, n_victims) for _ in range(trials)]
        for j, (c, M) in enumerate(zip(cs, cps)):
            xs = [p[j] for p in per]
            m, th = statistics.mean(xs), theory_frac(nB, M)
            rows.append(dict(nB=nB, c=c, M_inputs=M, trials=trials,
                             victims=n_victims, frac_mean=m, ci95=ci95(xs),
                             predicted=th, ratio=m / th))
            print(f"poison nB={nB:4d} M={M:7d} (c={c:4}): frac={m:.4f} "
                  f"+-{ci95(xs):.4f}  pred={th:.4f}  ratio={m/th:.3f}", flush=True)
        print(f"  ({time.time()-t0:.0f}s)", flush=True)
    return rows


# -------------------------------------------------------------- K3 crafted
def run_crafted(nBs, N):
    rows = []
    H = keyed_hash(os.urandom(16))
    for nB in nBs:
        hits = ctrl = 0
        n_ctrl = min(N, 20000)
        for i in range(N):
            jti = random_jti()
            fpV, pairV = victim_params(nB, murmurhash64a, jti)    # attacker's view
            twin = craft_twin_murmur(nB, fpV, pairV)              # O(1) crafting
            hits += (item_key(H(jti), nB) == item_key(H(twin), nB))
            if i < n_ctrl:                                        # unkeyed control
                ctrl += (item_key(murmurhash64a(jti.encode()), nB) ==
                         item_key(murmurhash64a(twin), nB))
        ps = p_per_fp(nB)
        p = sum(ps) / len(ps)
        rows.append(dict(nB=nB, N=N, keyed_hits=hits, keyed_rate=hits / N,
                         expected_p=p, unkeyed_rate=ctrl / n_ctrl))
        print(f"crafted nB={nB}: unkeyed success={ctrl/n_ctrl:.3f}  "
              f"keyed success={hits}/{N}={hits/N:.2e}  expected p={p:.2e}", flush=True)
    return rows


# ----------------------------------------------------------------- sizing
def sizing_rows():
    rows = []
    for T, tl in ((600, "10 min (MFA)"), (3600, "1 h"), (86400, "24 h")):
        for R, rl in ((35, "35/s revocation"), (100, "100/s production")):
            for eps in (0.5, 0.01):
                L = -math.log(1 - eps)
                nB_poison = 2 * T * R / (FP_SPACE * L)   # P(twin in window) <= eps
                rows.append(dict(T=tl, rate=rl, eps=eps,
                                 attacker_inserts=T * R,
                                 nB_min_poison=nB_poison,
                                 slots_to_resist_flood_N0=T * R))
    return rows


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    quick = len(sys.argv) > 1 and sys.argv[1] == "quick"
    nBs = (32, 64) if quick else (64, 128, 256, 512, 1024)
    reps, trials, vict = (10, 3, 100) if quick else (200, 30, 1000)
    which = sys.argv[2] if len(sys.argv) > 2 else "all"
    if len(sys.argv) > 3:                      # optional: nB list, trials, csv tag
        nBs = tuple(int(x) for x in sys.argv[3].split(","))
        trials = int(sys.argv[4])
    tag = sys.argv[5] if len(sys.argv) > 5 else ""
    if which in ("all", "flood"):
        write_csv(f"keyed_flood{tag}.csv", run_flood(nBs, (1, 2, 4), reps))
    if which in ("all", "poison"):
        write_csv(f"keyed_poison{tag}.csv", run_poison(nBs, trials, vict))
    if which in ("all", "crafted"):
        write_csv("keyed_crafted.csv",
                  run_crafted((32, 64), 20000 if quick else 400000))
    if which in ("all", "sizing"):
        rows = sizing_rows()
        write_csv("keyed_sizing.csv", rows)
        for r in rows:
            print(f"T={r['T']:12s} {r['rate']:17s} eps={r['eps']:<4}: "
                  f"nB_min(poison)={r['nB_min_poison']:>12,.0f}   "
                  f"flood needs > {r['slots_to_resist_flood_N0']:>10,} free slots")
