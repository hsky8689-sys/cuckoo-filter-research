#!/usr/bin/env python3
"""Faithful Python reimplementation of the RedisBloom cuckoo filter's CRUD
operations (src/cuckoo.c), verified line-by-line against the real source.

Only Add / Contains / Delete live here -- no attack-simulation logic.
Attack code (grinding, Monte Carlo runners) belongs in separate experiment
scripts that import this module and call add()/contains()/delete() on it.

Key facts, verified directly against cuckoo.c (not assumed):

- A single hash call produces BOTH h1 and the fingerprint -- they are not
  independent sources of randomness:
      hash = MurmurHash64A(item, seed=0)      # CUCKOO_GEN_HASH
      fp   = hash % 255 + 1                   # 1..255, 0 is reserved (NULLFP)
      h1   = hash
      h2   = h1 ^ (fp * 0x5bd1e995)           # getAltHash
  Bucket index = (h1 or h2) % numBuckets, computed at lookup time.

- Insert searches all layers newest -> oldest for a free slot (no kicking),
  then kicks ONLY in the newest layer, capped at `num` (default 20)
  iterations, rolling back on failure, then grows a new layer.

- Delete searches layers newest -> oldest; within a layer, checks bucket at
  h1 then bucket at h2, removes the first matching fingerprint it finds.

- Contains/Check searches ALL layers (order doesn't matter for existence).

Compaction after >10% deletes (CuckooFilter_Compact) is intentionally left
out -- it's a system-level optimization orthogonal to the adversarial
structural model this project studies.
"""
import copy
from hashes import murmurhash64a

MASK64 = 0xFFFFFFFFFFFFFFFF


class Layer:
    def __init__(self, nB, s):
        self.nB, self.s = nB, s
        self.b = [[None] * s for _ in range(nB)]


class CF:
    def __init__(self, nB1, s, num=20, ef=1, Lcap=32, hashfunc=murmurhash64a):
        self.nB1, self.s, self.num, self.ef, self.Lcap = nB1, s, num, ef, Lcap
        self.hashfunc = hashfunc
        self.layers = [Layer(nB1, s)]

    def _lookup_params(self, item):
        if isinstance(item, str):
            item = item.encode('utf-8')
        h = self.hashfunc(item) & MASK64
        fp = h % 255 + 1                        # CuckooFingerprint: 1..255
        return h, fp

    @staticmethod
    def alt(fp, i):                             # getAltHash
        return (i ^ ((fp * 0x5bd1e995) & MASK64)) & MASK64

    # ---- low-level bucket helpers ----
    def _free(self, bucket):
        for k, v in enumerate(bucket):
            if v is None:
                return k
        return None

    def _find_available(self, L, h1, fp):       # Filter_FindAvailable
        for loc in (h1 % L.nB, self.alt(fp, h1) % L.nB):
            k = self._free(L.b[loc])
            if k is not None:
                return loc, k
        return None

    def _ko(self, L, h1, fp):                   # Filter_KOInsert
        snap = copy.deepcopy(L.b)
        ii, victim = h1 % L.nB, 0
        for _ in range(self.num):
            L.b[ii][victim], fp = fp, L.b[ii][victim]
            ii = self.alt(fp, ii) % L.nB
            k = self._free(L.b[ii])
            if k is not None:
                L.b[ii][k] = fp
                return True
            victim = (victim + 1) % self.s
        L.b = snap                               # roll back
        return False

    def _grow(self):
        self.layers.append(Layer(self.nB1 * self.ef ** len(self.layers), self.s))

    def _insert_fp(self, h1, fp):
        for L in reversed(self.layers):
            pos = self._find_available(L, h1, fp)
            if pos:
                L.b[pos[0]][pos[1]] = fp
                return "ok"
        if self._ko(self.layers[-1], h1, fp):    # kicking only in newest layer
            return "ok"
        if self.ef == 0:
            return "nospace"
        self._grow()
        return self._insert_fp(h1, fp)

    def insert(self, h1, fp):                    # command level (rebloom.c:674)
        if len(self.layers) >= self.Lcap:
            return "MAXEXP"
        return self._insert_fp(h1, fp)

    def add(self, item) -> str:
        h1, fp = self._lookup_params(item)
        return self.insert(h1, fp)

    def contains(self, item) -> bool:
        h1, fp = self._lookup_params(item)
        for L in self.layers:
            for loc in (h1 % L.nB, self.alt(fp, h1) % L.nB):
                if fp in L.b[loc]:
                    return True
        return False

    def delete(self, item) -> bool:
        h1, fp = self._lookup_params(item)
        for L in reversed(self.layers):
            for loc in (h1 % L.nB, self.alt(fp, h1) % L.nB):
                bucket = L.b[loc]
                if fp in bucket:
                    bucket[bucket.index(fp)] = None
                    return True
        return False


if __name__ == "__main__":
    cf = CF(nB1=64, s=2)
    assert cf.add("jti-alice-001") == "ok"
    assert cf.add("jti-bob-002") == "ok"
    assert cf.contains("jti-alice-001") is True
    assert cf.contains("jti-nobody-999") is False
    assert cf.delete("jti-alice-001") is True
    assert cf.contains("jti-alice-001") is False
    assert cf.delete("jti-alice-001") is False    # already gone
    print("CRUD sanity checks passed")
