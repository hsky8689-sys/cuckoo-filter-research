#!/usr/bin/env python3
"""jti generation for the attacker-crafting side of the experiment.

Per the threat model: the attacker has full crafting power over jti values
(worst-case assumption, isolates the filter from system-level JTI-issuance
policy). "Full crafting power" still means *valid-format* jti's -- a real
revocation deny-list would reject malformed tokens before they ever reach
the cuckoo filter, so the attacker's candidates must look like real jti's,
just chosen adversarially.

Format: UUID v4 string (the common real-world jti convention -- it's what
a JWT library, and your own Authnomaly project, would generate for a real
token). Backed by uuid.uuid4(), which is seeded from os.urandom -- a CSPRNG,
not Python's default Mersenne Twister (`random` module). This matters:
"randomly generated" isn't a weakness here, it's literally how real jti's
are produced in production; the only thing that WOULD be a weakness is
using a predictable RNG, which this avoids.
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
