#!/usr/bin/env python3
"""Check the fixed Poseidon profile against the reference round inequalities.

The equations follow the Poseidon parameter-selection procedure and the
additional Groebner-basis check from https://eprint.iacr.org/2023/537.
Reference implementation:
https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage
Its round-selection routine applies to Poseidon as well as Poseidon2.
This checks parameter selection; it does not prove the assumed collision curve.
"""

from math import ceil, comb, floor, gcd, log, log2
from pathlib import Path
import re


PARAMETERS = Path(__file__).resolve().parents[2] / "include/laminate/params.hpp"
source = PARAMETERS.read_text()


def parameter(name):
    match = re.search(r"\b" + name + r"\s*=\s*([0-9']+)", source)
    if match is None:
        raise AssertionError(f"missing numeric parameter: {name}")
    return int(match.group(1).replace("'", ""))


def admissible(p, width, alpha, target, full, partial):
    field_bits = ceil(log2(p))
    required = max(
        6 if target <= floor(log2(p) - (alpha - 1) / 2) * (width + 1) else 10,
        1 + ceil(min(target, field_bits) / log2(alpha))
        + ceil(log(width, alpha)) - partial,
        min(target, log2(p)) / log2(alpha) - partial,
        width - 1 + min(target / (width + 1), log2(p) / 2)
        / log2(alpha) - partial,
        (width - 2 + target / (2 * log2(alpha)) - partial) / (width - 1),
    )
    r = width // 3
    upper = (full - 1) * width + 2 * partial + r + r * (full // 2) + alpha
    lower = r * (full // 2) + partial + alpha
    algebraic_cost = ceil(2 * log2(comb(upper, lower)))
    return full >= ceil(required) and algebraic_cost >= target


p = parameter("kOuterFieldOrder")
width = parameter("kPoseidonWidth")
rate = parameter("kPoseidonRate")
digest = parameter("kPoseidonDigestElements")
target = parameter("kPoseidonDesignSecurityBits")
assert gcd(5, p - 1) == 1, "x^5 must permute the field"
assert width - rate == digest == 6
assert target >= ceil(3 * log2(p)), "round target must cover the birthday scale"

candidates = []
for partial in range(1, 100):
    for full in range(4, 100, 2):
        if admissible(p, width, 5, target, full, partial):
            # Add the reference security margins after testing each candidate.
            selected_full = full + 2
            selected_partial = ceil(1.075 * partial)
            candidates.append((width * selected_full + selected_partial,
                               selected_full, selected_partial))
_, full, partial = min(candidates)
assert (full, partial) == (parameter("kPoseidonFullRounds"),
                           parameter("kPoseidonPartialRounds"))
print(f"Poseidon round checks passed: width={width}, rate={rate}, "
      f"capacity={width-rate}, digest={digest}, rounds={full}+{partial}")
