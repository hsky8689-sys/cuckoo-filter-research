#!/usr/bin/env python3
"""jti generation for the attacker-crafting side of the experiment.

Threat model (committed): the attacker has full crafting power over jti
values AND the deny-list does NOT enforce a token format -- any string the
attacker submits reaches the cuckoo filter. This is the worst-case
assumption, and it is the one that makes the hash choice matter: against an
invertible hash the attacker can submit the raw bytes obtained by inverting
the hash to a chosen bucket (see murmur_invert.py), a capability a strict
uuid4-format check at the deny-list boundary would have removed.

This module supplies the candidate stream for the blake2 arm only. blake2
is one-way, so its grinding cost is format-insensitive -- any uniform random
source yields the same ~nB^2/2 cost. We use uuid.uuid4() as that source
because it mirrors how real jti's are produced (CSPRNG via os.urandom, not
the predictable Mersenne Twister). The murmur arm does NOT draw from here;
it submits the raw 8-byte strings returned by the inverter.
"""
import uuid


def random_jti() -> str:
    """One cryptographically-random, UUID4-format jti string."""
    return str(uuid.uuid4())


def random_jtis(n: int) -> list[str]:
    """n independent random jti's (e.g. to pre-populate a filter's background load)."""
    return [random_jti() for _ in range(n)]


if __name__ == "__main__":
    sample = random_jtis(5)
    for jti in sample:
        print(jti)
    assert len(set(random_jtis(10_000))) == 10_000, "collision in 10k draws -- shouldn't happen"
    print("uniqueness sanity check passed (10,000 draws, 0 collisions)")
