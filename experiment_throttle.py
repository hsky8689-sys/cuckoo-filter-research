#!/usr/bin/env python3
"""Corrected variant of Section 5.1: throttle NEW arrivals into a hot
bucket, instead of decaying what is already resident there.

A per-bucket sliding-window touch counter is checked BEFORE an insertion
attempt touches the table at all: if the bucket's recent rate exceeds
k_mult * rate0 (rate0 = 2/nB, the rate one bucket sees under pure
background load), the attempt is rejected outright -- existing occupants
are never read or written, so a bystander already sitting there cannot be
evicted by this mechanism (unlike Section 5.1). This is a minimal single-
layer table (ef=0 semantics) built the same way as experiment_decay.py's
DecayTable, sharing CF's bucket/kicking rules; cuckoo_filter.py is
untouched.
"""
import csv
import statistics
from collections import deque

from cuckoo_filter import CF
from hashes import murmurhash64a, MASK64
from jti_gen import random_jti
from murmur_invert import craft_items_on_pair

FP_SPACE = 255


class ThrottleTable:
    def __init__(self, nB, s, window, k_mult, num=20, hashfunc=murmurhash64a):
        self.nB, self.s, self.window, self.k_mult, self.num = nB, s, window, k_mult, num
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

    def _rate(self, i):
        hist = self.touch_hist[i]
        while hist and hist[0] <= self.t - self.window:
            hist.popleft()
        return len(hist) / self.window

    def _free(self, i):
        for k_, slot in enumerate(self.b[i]):
            if slot is None:
                return k_
        return None

    def _ko(self, h1, fp, owner):
        snap = [row[:] for row in self.b]
        ii, victim = h1, 0
        for _ in range(self.num):
            self.b[ii][victim], old = [fp, owner], self.b[ii][victim]
            fp, owner = old
            ii = CF.alt(fp, ii) % self.nB
            k_ = self._free(ii)
            if k_ is not None:
                self.b[ii][k_] = [fp, owner]
                return True
            victim = (victim + 1) % self.s
        self.b = snap
        return False

    def try_add(self, item, owner="background"):
        """'throttled' (never touched the table) | 'ok' | 'overflow'."""
        self.t += 1
        h1, fp = self._params(item)
        h2 = CF.alt(fp, h1) % self.nB
        gate = {h1, h2}
        if self.k_mult is not None and any(self._rate(i) > self.k_mult * self.rate0 for i in gate):
            return "throttled"
        for i in gate:
            self.touch_hist[i].append(self.t)
        for i in (h1, h2):
            k_ = self._free(i)
            if k_ is not None:
                self.b[i][k_] = [fp, owner]
                return "ok"
        if self._ko(h1, fp, owner):
            return "ok"
        return "overflow"

    def find_owner_anywhere(self, owner):
        return any(slot is not None and slot[1] == owner
                   for bucket in self.b for slot in bucket)


def run_trial(nB, s, window, k_mult, raw_budget, n_innocent, n_before=0):
    tb = ThrottleTable(nB, s, window, k_mult)
    for _ in range(n_before):
        tb.try_add(random_jti())
    pair_items = craft_items_on_pair(nB, 1 + raw_budget + n_innocent)
    tb.try_add(pair_items[0], owner="victim")

    accepted = throttled_attacker = 0
    overflow_at_raw = None
    innocent_results = []
    i = 1
    for a in pair_items[1:1 + raw_budget]:
        r = tb.try_add(a, owner="attacker")
        if r == "throttled":
            throttled_attacker += 1
        elif r == "ok":
            accepted += 1
        elif r == "overflow" and overflow_at_raw is None:
            overflow_at_raw = i
        i += 1
    # innocent bystander requests landing on the SAME pair, interleaved
    # right after the attacker's burst, while the gate is still hot
    for a in pair_items[1 + raw_budget:]:
        innocent_results.append(tb.try_add(a, owner="innocent"))

    victim_survived = tb.find_owner_anywhere("victim")
    innocent_throttled = sum(1 for r in innocent_results if r == "throttled")
    return dict(overflow_at_raw=overflow_at_raw, accepted=accepted,
               throttled_attacker=throttled_attacker,
               victim_survived=victim_survived,
               innocent_throttled=innocent_throttled, n_innocent=n_innocent)


def run(nB, s, window, k_mults, raw_budget, n_innocent, reps):
    rows = []
    for k_mult in k_mults:
        res = [run_trial(nB, s, window, k_mult, raw_budget, n_innocent) for _ in range(reps)]
        ov = [r["overflow_at_raw"] for r in res if r["overflow_at_raw"] is not None]
        acc = [r["accepted"] for r in res]
        surv = sum(r["victim_survived"] for r in res)
        inn_th = sum(r["innocent_throttled"] for r in res)
        inn_tot = sum(r["n_innocent"] for r in res)
        label = "none" if k_mult is None else k_mult
        rows.append(dict(
            k_mult=label, reps=reps,
            overflow_reached_pct=round(100 * len(ov) / reps, 1),
            raw_attempts_to_overflow_mean=round(statistics.mean(ov), 1) if ov else float("nan"),
            accepted_mean=round(statistics.mean(acc), 1),
            victim_survived_pct=round(100 * surv / reps, 1),
            innocent_throttled_pct=round(100 * inn_th / inn_tot, 1) if inn_tot else float("nan")))
        print(f"k_mult={label:>5}: overflow reached {rows[-1]['overflow_reached_pct']:5.1f}% "
              f"(raw attempts {rows[-1]['raw_attempts_to_overflow_mean']})  "
              f"accepted/budget={rows[-1]['accepted_mean']}/{raw_budget}  "
              f"victim survives {rows[-1]['victim_survived_pct']:5.1f}%  "
              f"innocent throttled {rows[-1]['innocent_throttled_pct']:5.1f}%", flush=True)
    return rows


if __name__ == "__main__":
    nB, s, window = 256, 2, 50
    raw_budget, n_innocent, reps = 5000, 20, 300
    k_mults = (None, 50, 20, 10, 5, 3, 2)
    rows = run(nB, s, window, k_mults, raw_budget, n_innocent, reps)
    with open("throttle_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
