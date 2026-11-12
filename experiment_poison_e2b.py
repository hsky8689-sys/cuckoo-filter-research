#!/usr/bin/env python3
"""E2b -- revocation bypass (false negative) via the cuckoo-filter false-delete.

Deterministic demonstration, not a probability. A twin T of a revoked victim V
shares (bucket-pair, fingerprint) with V, so the filter cannot tell them apart.

Scenario A (deny-list EXPOSES delete to the attacker -- e.g. an un-revoke /
  token-refresh path): the attacker never inserts anything. It crafts a twin T
  (same fp, same bucket -- a "faked fingerprint") and calls delete(T). The filter
  removes V's entry. contains(V) flips True -> False: the revocation is defeated.

Scenario B (delete happens ONLY on TTL expiry -- an external/system factor): the
  attacker inserts its own twin T; T later expires and the system deletes it.
  Two fp_V entries existed, delete removes one, V's own copy survives, so
  contains(V) stays True: no bypass. (Defensive observation.)

Both outcomes are deterministic across random victims, both twin orientations and
all s. The cost to obtain the twin is E2a / P-ablation and is not repeated here.
"""
from cuckoo_filter import CF
from hashes import murmurhash64a
from jti_gen import random_jti
from experiment_poison import victim_params, craft_twin_murmur


def scenario_A(nB, s) -> bool:
    """Attacker calls delete on a crafted twin it NEVER inserted.
    Returns True if the revocation is defeated (contains(V) becomes False)."""
    cf = CF(nB1=nB, s=s, hashfunc=murmurhash64a)
    V = random_jti()
    cf.add(V)
    assert cf.contains(V)                        # revocation active
    fp_V, pair_V = victim_params(nB, murmurhash64a, V)
    T = craft_twin_murmur(nB, fp_V, pair_V)      # faked fingerprint, same bucket
    cf.delete(T)                                 # attacker-invoked; T never added
    return cf.contains(V) is False               # True == bypass


def scenario_B(nB, s) -> bool:
    """Attacker's twin is inserted, then deleted on expiry.
    Returns True if the victim survives (no bypass)."""
    cf = CF(nB1=nB, s=s, hashfunc=murmurhash64a)
    V = random_jti()
    cf.add(V)
    fp_V, pair_V = victim_params(nB, murmurhash64a, V)
    T = craft_twin_murmur(nB, fp_V, pair_V)
    cf.add(T)                                    # attacker's own revoked twin
    cf.delete(T)                                 # T expires -> system deletes it
    return cf.contains(V) is True                # True == victim survived (safe)


if __name__ == "__main__":
    trials = 1000
    print("=== E2b: revocation bypass via false-delete (deterministic demo) ===\n")
    for s in (1, 2, 4):
        for nB in (8, 16, 32, 64):
            a = sum(scenario_A(nB, s) for _ in range(trials))
            b = sum(scenario_B(nB, s) for _ in range(trials))
            print(f"s={s} nB={nB:>2} | A (delete exposed): bypass {a:>4}/{trials}"
                  f"  | B (expiry only): victim survived {b:>4}/{trials}")
    print("\nA: one crafted twin + one attacker delete defeats the revocation -- always.")
    print("B: when delete is only TTL-driven, the victim's own copy survives -- always.")
