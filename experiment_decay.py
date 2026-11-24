#!/usr/bin/env python3
"""Naive per-bucket TTL decay (Section 5 proposal, baseline version).

Every slot carries an expiry (in attempt-time units: one tick per insertion
attempt, matching the request-rate R used elsewhere so that T0 = T_token*R
converts a real TTL into attempt-units). Every time a bucket is probed
(on ANY insertion attempt, successful or not -- this mirrors the two
positions _find_available checks), if that bucket's recent touch rate
exceeds the rate expected under pure background load (rate0 = 2/nB, the
chance a specific bucket is one of the two a random item touches), every
occupant's expiry is pulled forward by k*(rate_hat/rate0 - 1)^p.

This reimplements a minimal single-layer table with the same bucket and
kicking rules as CF (_find_available/_ko in cuckoo_filter.py, verified
there against cuckoo.c), plus the expiry bookkeeping CF has no notion of.
cuckoo_filter.py itself is not modified. Kicking relocates an existing
occupant -- its expiry travels with it unchanged, it is not refreshed.

Three things are measured, each the direct operationalisation of a
question raised before building this: does decay make the one-shot
overflow itself harder (self-decay during the attacker's own burst), does
it make an achieved overflow recover on its own afterwards, and what does
recovery cost an innocent bystander sharing the same bucket.
"""
import csv
import statistics
from collections import deque

from cuckoo_filter import CF
from hashes import murmurhash64a, MASK64
from jti_gen import random_jti
from murmur_invert import craft_items_on_pair

FP_SPACE = 255


class DecayTable:
    """Single-layer cuckoo table (ef=0 semantics) with per-slot expiry and
    per-bucket decay-on-anomalous-touch. Slots are [fp, expiry, owner];
    `owner` is experimenter bookkeeping only, invisible to the table logic."""

    def __init__(self, nB, s, T0, window, k, p, num=20, hashfunc=murmurhash64a):
        self.nB, self.s, self.T0 = nB, s, T0
        self.window, self.k, self.p, self.num = window, k, p, num
        self.hashfunc = hashfunc
        self.b = [[None] * s for _ in range(nB)]
        self.touch_hist = [deque() for _ in range(nB)]
        self.t = 0
        self.rate0 = 2.0 / nB

    def _params(self, item):
        if isinstance(item, str):
            item = item.encode('utf-8')
        h = self.hashfunc(item) & MASK64
        return h % self.nB, h % FP_SPACE + 1

    def _touch_and_expire(self, i):
        now = self.t
        hist = self.touch_hist[i]
        hist.append(now)
        while hist and hist[0] <= now - self.window:
            hist.popleft()
        rate_hat = len(hist) / self.window
        if rate_hat > self.rate0 and self.k:
            extra = self.k * (rate_hat / self.rate0 - 1) ** self.p
            for slot in self.b[i]:
                if slot is not None:
                    slot[1] -= extra
        for k_, slot in enumerate(self.b[i]):
            if slot is not None and slot[1] <= now:
                self.b[i][k_] = None

    def _free(self, i):
        for k_, slot in enumerate(self.b[i]):
            if slot is None:
                return k_
        return None

    def _ko(self, h1, fp, expiry, owner):
        snap = [row[:] for row in self.b]
        ii, victim = h1, 0
        for _ in range(self.num):
            self.b[ii][victim], old = [fp, expiry, owner], self.b[ii][victim]
            fp, expiry, owner = old
            ii = CF.alt(fp, ii) % self.nB
            k_ = self._free(ii)
            if k_ is not None:
                self.b[ii][k_] = [fp, expiry, owner]
                return True
            victim = (victim + 1) % self.s
        self.b = snap
        return False

    def add(self, item, owner="background"):
        self.t += 1
        h1, fp = self._params(item)
        h2 = CF.alt(fp, h1) % self.nB
        for i in {h1, h2}:
            self._touch_and_expire(i)
        for i in (h1, h2):
            k_ = self._free(i)
            if k_ is not None:
                self.b[i][k_] = [fp, self.t + self.T0, owner]
                return "ok"
        if self._ko(h1, fp, self.t + self.T0, owner):
            return "ok"
        return "overflow"

    def occupancy(self, i):
        return sum(1 for slot in self.b[i] if slot is not None)

    def has_owner(self, i, owner):
        return any(slot is not None and slot[2] == owner for slot in self.b[i])

    def find_owner_anywhere(self, owner):
        return any(slot is not None and slot[2] == owner
                   for bucket in self.b for slot in bucket)

    def free_in(self, i):
        return self._free(i) is not None


def run_trial(nB, s, T0, window, k, p, n_before, attacker_budget, n_after, run_attack=True):
    """n_before: neutral background warmup BEFORE the victim is placed (context
    only). Victim is placed on the pair. If run_attack: attacker items follow,
    counted until the first overflow. Then n_after background attempts run
    (this is the recovery/exposure window, used both to see whether the pair
    frees up again and, with no attack, as the pure collateral-damage check).
    Victim survival is checked across the WHOLE table (ordinary kicking can
    relocate it without deleting it; only decay removes a slot outright)."""
    dt = DecayTable(nB, s, T0, window, k, p)
    for _ in range(n_before):
        dt.add(random_jti())
    pair_items = craft_items_on_pair(nB, 1 + (attacker_budget if run_attack else 0))
    dt.add(pair_items[0], owner="victim")
    pair0, pair1 = 0, CF.alt(1, 0) % nB          # fp_ref=1, matches craft_items_on_pair

    overflow_at = None
    if run_attack:
        for i, a in enumerate(pair_items[1:], start=1):
            r = dt.add(a, owner="attacker")
            if r == "overflow" and overflow_at is None:
                overflow_at = i

    recovery_at = None
    for i in range(1, n_after + 1):
        dt.add(random_jti())
        if dt.free_in(pair0) or dt.free_in(pair1):
            recovery_at = i
            break

    victim_survived = dt.find_owner_anywhere("victim")
    return overflow_at, recovery_at, victim_survived


def run(nB, s, T0, window, ks, p, n_before, attacker_budget, n_after, reps):
    rows = []
    for k in ks:
        ov, rec, surv, rec_none = [], [], 0, 0
        for _ in range(reps):
            o, r, v = run_trial(nB, s, T0, window, k, p, n_before, attacker_budget, n_after)
            if o is not None:
                ov.append(o)
            if r is not None:
                rec.append(r)
            else:
                rec_none += 1
            surv += v
        ov_mean = statistics.mean(ov) if ov else float("nan")
        rec_mean = statistics.mean(rec) if rec else float("nan")
        rows.append(dict(k=k, p=p, reps=reps,
                         overflow_reached_pct=100 * len(ov) / reps,
                         inserts_to_overflow_mean=round(ov_mean, 2),
                         recovered_pct=100 * len(rec) / reps,
                         recovery_time_mean=round(rec_mean, 1),
                         never_recovered_pct=100 * rec_none / reps,
                         bystander_survived_pct=100 * surv / reps))
        print(f"k={k:5} p={p}: overflow reached {100*len(ov)/reps:5.1f}% "
              f"(mean {ov_mean:.2f} inserts)  "
              f"recovered {100*len(rec)/reps:5.1f}% (mean {rec_mean:.1f})  "
              f"bystander survived {100*surv/reps:5.1f}%", flush=True)
    return rows


def run_collateral(nB, s, T0, window, ks, p, n_attempts, reps):
    """No attacker at all: pure background load AFTER the victim is placed.
    Checks whether decay fires on ordinary traffic (it should not, if rate0
    is calibrated correctly)."""
    rows = []
    for k in ks:
        surv = 0
        for _ in range(reps):
            _, _, v = run_trial(nB, s, T0, window, k, p, 0, 0, n_attempts, run_attack=False)
            surv += v
        rows.append(dict(k=k, p=p, reps=reps, bystander_survived_pct=100 * surv / reps))
        print(f"[collateral] k={k:5} p={p}: bystander survived {100*surv/reps:5.1f}% "
              f"over {n_attempts} pure-background attempts", flush=True)
    return rows


if __name__ == "__main__":
    nB, s, T0, window = 256, 2, 2000, 50
    p = 1
    n_before, attacker_budget, n_after = 100, 5 * (2 * s + 1), 300
    reps = 300

    print("=== attack scenario (k=0 is the no-decay baseline) ===")
    rows = run(nB, s, T0, window, (0, 20, 50, 100, 200), p, n_before, attacker_budget, n_after, reps)
    with open("decay_attack_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print("\n=== collateral-damage control (no attacker, background only) ===")
    rows2 = run_collateral(nB, s, T0, window, (0, 20, 50, 100, 200), p, n_before + attacker_budget + n_after, reps)
    with open("decay_collateral_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows2[0].keys()))
        w.writeheader()
        w.writerows(rows2)
