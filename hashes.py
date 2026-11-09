#!/usr/bin/env python3
"""Real hash functions for the cuckoo-filter DoS/poisoning simulation.

Two candidates, matching the "hash ablation" design from the experiment chapter:

1. murmurhash64a  -- the actual hash Redis uses for h1 in its cuckoo filter
   (MurmurHash64A, Austin Appleby, MurmurHash2 family). This is the one with
   the documented cheap-preimage shortcut (Filic et al., ~258 evaluations),
   so grinding against it is expected to be roughly constant-cost, NOT
   growing with nB as the structural formula predicts.

   Verified line-by-line against Appleby's reference implementation
   (public domain), smhasher/MurmurHash2.cpp:
   https://chromium.googlesource.com/external/smhasher/+/5b8fd3c31a58b87b80605dca7a64fad6cb3f8a0f/MurmurHash2.cpp
   Redis itself ships the same algorithm as MurmurHash64A in src/util.c.

2. blake2_64 -- the "clean" / non-invertible candidate for the ablation.
   BLAKE2b truncated to 64 bits has no known cheap-preimage shortcut, so
   grinding against it should actually show the predicted nB^2 scaling
   (C(v=2)) / nB*2^f scaling (C_poison).

   hashlib.blake2b is in the Python standard library (no extra dependency),
   and supports a native digest_size parameter, so no manual truncation bugs.

Both take raw bytes in and return an unsigned 64-bit int, so they're
interchangeable as the h1 (and, via a second call, h2/fingerprint) source
in the CF class.
"""
import hashlib
import struct

MASK64 = 0xFFFFFFFFFFFFFFFF


def murmurhash64a(data: bytes, seed: int = 0) -> int:
    """MurmurHash64A (Appleby, MurmurHash2 family) -- what Redis actually
    uses for h1 in the cuckoo filter."""
    m = 0xc6a4a7935bd1e995
    r = 47

    h = (seed ^ ((len(data) * m) & MASK64)) & MASK64

    nblocks = len(data) // 8
    for i in range(nblocks):
        k = struct.unpack_from('<Q', data, i * 8)[0]
        k = (k * m) & MASK64
        k ^= k >> r
        k = (k * m) & MASK64
        h ^= k
        h = (h * m) & MASK64

    tail = data[nblocks * 8:]
    n = len(tail)
    # deliberate fallthrough, exactly mirroring the reference C switch()
    if n >= 7:
        h ^= tail[6] << 48
    if n >= 6:
        h ^= tail[5] << 40
    if n >= 5:
        h ^= tail[4] << 32
    if n >= 4:
        h ^= tail[3] << 24
    if n >= 3:
        h ^= tail[2] << 16
    if n >= 2:
        h ^= tail[1] << 8
    if n >= 1:
        h ^= tail[0]
        h = (h * m) & MASK64

    h ^= h >> r
    h = (h * m) & MASK64
    h ^= h >> r

    return h & MASK64


def blake2_64(data: bytes, seed: int = 0) -> int:
    """BLAKE2b truncated to 64 bits -- the "no known shortcut" hash used
    as the ablation control against murmurhash64a."""
    digest = hashlib.blake2b(data, digest_size=8,
                              key=seed.to_bytes(8, 'little', signed=False) if seed else b'').digest()
    return struct.unpack('<Q', digest)[0]


if __name__ == "__main__":
    # sanity checks (not claims of correctness against an external test
    # vector -- just structural properties any correct hash must satisfy)
    a = murmurhash64a(b"hello")
    b = murmurhash64a(b"hello")
    c = murmurhash64a(b"world")
    assert a == b, "murmurhash64a must be deterministic"
    assert a != c, "murmurhash64a must differ on different input"
    assert murmurhash64a(b"hello", seed=1) != a, "seed must change the output"
    assert murmurhash64a(b"") == 0, "empty input, seed 0 -> h stays 0 through every mixing step"

    x = blake2_64(b"hello")
    y = blake2_64(b"hello")
    z = blake2_64(b"world")
    assert x == y and x != z
    assert blake2_64(b"hello", seed=1) != x

    print("murmurhash64a(b'hello') =", hex(a))
    print("blake2_64(b'hello')     =", hex(x))
    print("all sanity checks passed")
