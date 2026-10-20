#!/usr/bin/env python3
"""Check the published distance bound and production queries exactly.

Run directly with Python 3 or through CTest when Python is available.
See docs/WIDE_GATE_SOUNDNESS.md for policy and paper references.
"""
from fractions import Fraction
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
FIELD = 65537**8
K = 65536
TARGET = 112
PUBLISHED_DISTANCE = Fraction(6965, 10000)
DEFAULT_QUERIES = 300


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    header = (ROOT / "include/laminate/basefold/foldable.hpp").read_text()
    default = re.search(r"\bkDefaultQueries\s*=\s*(\d+)\s*;", header)
    require(default is not None, "missing production default query count")
    require(int(default.group(1)) == DEFAULT_QUERIES,
            "production default query count differs from the certificate")
    source = (ROOT / "src/basefold/foldable_query_policy.cpp").read_text()
    match = re.search(r"kMinimumQueries\s*=\s*\{([^}]+)\}", source)
    require(match is not None, "missing production query table")
    counts = [int(value) for value in re.findall(r"\d+", match.group(1))]
    require(len(counts) == 41, "certificate covers exactly message logs 0..40")
    require((K << TARGET) < FIELD, "conservative folding error exceeds target")
    require(27 * (1 << 123) < (1 << 128), "shared setup error exceeds target")

    n, zeros = 65536, 8192
    distances = []
    for variables in range(41):
        if variables <= 13:
            distance = Fraction(7, 8)  # RS distance is strictly greater.
        else:
            log_n = n.bit_length() - 1
            numerator = log_n + 5 * n // 4 + 2 * zeros + 129
            slack = (numerator + 125) // 126
            require(5 * n // 4 + 2 * zeros + 1 - 126 * slack <= -128,
                    "one random extension exceeds its setup failure budget")
            require(4 * zeros < FIELD, "field bound in zero-count proof fails")
            zeros, n = 2 * zeros + slack, 2 * n
            require(3 * zeros < n, "hierarchy distance is not above 2/3")
            distance = Fraction(n - zeros, n)
        distances.append(distance)
        require(distance > PUBLISHED_DISTANCE,
                f"published distance bound fails at message log {variables}")
        if variables:
            require(distance <= distances[variables - 1],
                    "distance bound does not cover smaller child codes")
        radius = distance / 3
        for step in range(variables + 1):
            child_distance = distances[variables - step]
            require(3 * radius <= child_distance,
                    "three-codeword radius exceeds a hierarchy distance")
            require(2 * radius < child_distance, "decoding is not unique")
            if step < variables:
                radius *= Fraction(K - 1, K)
        miss = 1 - radius
        a, b = miss.numerator, miss.denominator
        queries = counts[variables]
        require((a**queries << TARGET) <= b**queries,
                f"query count fails at message log {variables}")
        require((a**(queries - 1) << TARGET) > b**(queries - 1),
                f"query count is not minimal at message log {variables}")
        require((a**DEFAULT_QUERIES << TARGET) < b**DEFAULT_QUERIES,
                f"default {DEFAULT_QUERIES} fails the strict query bound "
                f"at message log {variables}")
        require(queries <= DEFAULT_QUERIES,
                "default 300 does not cover every shape")
    print("PASS: all 41 distance bounds exceed 6965/10000; "
          f"minimum D_40 = {distances[-1]}")
    print(f"PASS: all 41 minimum query counts ({min(counts)}..{max(counts)}), "
          "default 300 strict 2^-112 query bound, local 2^-112 and shared "
          "setup 2^-123 checked with exact arithmetic")


if __name__ == "__main__":
    main()
