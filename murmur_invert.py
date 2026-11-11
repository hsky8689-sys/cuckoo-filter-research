#!/usr/bin/env python3
"""Inversarea MurmurHash64A (seed=0, input de exact 8 octeti) + constructia
O(1) a itemelor pe o pereche-tinta fixa.

De ce 8 octeti: pentru un input de un singur bloc (fara tail), fiecare pas al
lui MurmurHash64A este algebric inversabil:
  - inmultirea cu m este bijectie mod 2^64 (m e impar -> are invers modular);
  - xor-shift `h ^= h >> 47` cu 47 >= 32 se inverseaza prin `h ^= h >> 47`
    (shiftarea atinge doar bitii de jos, deci bitii de sus se recupereaza direct).

Asa ca, dat un output H dorit, construim DIRECT un input de 8 octeti care
produce H -- fara trial-and-error. Asta e exact scurtatura pe care un hash
one-way (blake2) NU o permite.

Verificat prin round-trip contra hashes.murmurhash64a (acelasi algoritm pe
care-l foloseste filtrul).
"""
import struct

from cuckoo_filter import CF
from hashes import murmurhash64a, MASK64

M = 0xc6a4a7935bd1e995          # constanta MurmurHash2 (= 0x...5bd1e995)
R = 47
MINV = pow(M, -1, 1 << 64)      # inversul modular al lui M mod 2^64


def _undo_xorshift(y: int) -> int:
    """Inverseaza y = x ^ (x >> 47). Valid pentru orice shift >= 32."""
    return y ^ (y >> R)


def murmur64a_invert_8(H: int) -> bytes:
    """Dat H, intoarce 8 octeti `data` a.i. murmurhash64a(data) == H.
    O(1): cateva inmultiri si xor-uri, niciun trial-and-error."""
    # --- inverseaza finalizarea: H = (( (h1 ^ h1>>R)*M ) ^ ...>>R) ---
    b = _undo_xorshift(H)
    a = (b * MINV) & MASK64
    h1 = _undo_xorshift(a)
    # --- inverseaza pasul de bloc: h1 = ((h0 ^ k_mixed) * M) ---
    h0 = (8 * M) & MASK64                       # seed=0, len=8
    k_mixed = ((h1 * MINV) & MASK64) ^ h0
    # --- inverseaza amestecul cheii: k_mixed = (( (k*M) ^ (k*M)>>R ) * M) ---
    u = (k_mixed * MINV) & MASK64               # = t ^ (t>>R), unde t = k*M
    t = _undo_xorshift(u)
    k = (t * MINV) & MASK64
    return struct.pack('<Q', k)


def target_pair(nB: int, fp_ref: int = 1) -> frozenset:
    """Aceeasi pereche-tinta ca bratul blake (experiment_dos.pick_target_pair):
    bucket 0 si alt-ul lui sub fingerprint-ul de referinta."""
    return frozenset((0, CF.alt(fp_ref, 0) % nB))


def craft_items_on_pair(nB: int, count: int) -> list[bytes]:
    """Construieste `count` iteme DISTINCTE care aterizeaza toate pe perechea-
    tinta {0, i1}, prin inversare. O(1) per item (independent de nB).

    Cum: pentru nB putere de 2, mod nB = mascarea bitilor de jos, iar alt() e XOR,
    deci (h % nB, alt(fp,h) % nB) = (a, a ^ ((fp*0x5bd1e995) & (nB-1))) unde
    a = h & (nB-1). Alegem H ≡ 0 (mod nB) si H ≡ 0 (mod 255) -> a=0, fp=1 ->
    perechea devine {0, (0x5bd1e995 & (nB-1))} = tinta. Orice H = j*255*nB merge;
    inversam fiecare -> input distinct, aceeasi pereche."""
    step = 255 * nB                              # asigura H%nB==0 si H%255==0
    items = []
    j = 0
    while len(items) < count:
        H = j * step
        items.append(murmur64a_invert_8(H))
        j += 1
    return items


if __name__ == "__main__":
    import os

    # 1) round-trip: inversarea produce exact output-ul cerut
    ok = 0
    for _ in range(100_000):
        H = int.from_bytes(os.urandom(8), 'little')
        data = murmur64a_invert_8(H)
        assert murmurhash64a(data) == H, f"round-trip esuat la H={H:#018x}"
        ok += 1
    print(f"[1] round-trip inversare: {ok}/100000 OK "
          f"(murmur64a(invert(H)) == H pentru fiecare H aleator)")

    # 2) itemele construite aterizeaza TOATE pe perechea-tinta
    for nB in (8, 16, 32, 64):
        s = 2
        tgt = target_pair(nB)
        items = craft_items_on_pair(nB, 2 * s + 1)
        assert len(set(items)) == len(items), "itemele nu sunt distincte"
        for data in items:
            h = murmurhash64a(data)
            fp = h % 255 + 1
            pair = frozenset((h % nB, CF.alt(fp, h) % nB))
            assert pair == tgt, f"nB={nB}: item pe {set(pair)}, nu pe {set(tgt)}"
        print(f"[2] nB={nB:>2}: {len(items)} iteme distincte, toate pe perechea "
              f"{sorted(tgt)}  (construite cu {len(items)} inversari, 0 grinding)")

    print("\nToate verificarile au trecut.")
