#!/usr/bin/env python3
"""Check the evaluated well-formedness envelope with exact integer arithmetic.

The summaries certify message counts, not encoded mask norms. The published
mask-weight envelope is checked against the existing C++ capacity fixture.
Runtime setup recomputes mask weights and applies the admission inequalities.
See docs/WELL_FORMEDNESS_THEOREMS.md#evaluated-workload-checks.
"""
from math import isqrt
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
PUBLISHED_R = 517
PUBLISHED_WEIGHT_UPPER = 114_670
REPORTS = (
    "folded-balancedLaned-summary.md",
    "folded-mulHeavy-summary.md",
    "laned-b1-balancedLaned-summary.md",
    "laned-b128-balancedLaned-summary.md",
    "laned-b16384-balancedLaned-summary.md",
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def literal(source, name):
    match = re.search(rf"\b{re.escape(name)}\s*=\s*([\d']+)(?:ULL|U)?\s*;", source)
    require(match is not None, f"missing integer literal {name}")
    return int(match.group(1).replace("'", ""))


def aligned_messages(report, digest_bytes):
    text = report.read_text()
    require("**PASS**" in text, f"{report.name}: not a passing report")
    rounds = re.findall(
        r"\| server \| `((?:folded|laned)\.(?:affine|multiplication)"
        r"\.sumcheck_round\.reduction_\d+\.source_\d+"
        r"\.(?:ciphertext_index|slot_index)\.round_\d+)`", text)
    terminals = re.findall(
        r"\| server \| `((?:folded|laned)\.reduction\.reduction_\d+\.source_\d+)`",
        text)
    require(rounds and terminals, f"{report.name}: missing reduction spans")
    require(len(rounds) == len(set(rounds)), f"{report.name}: duplicate rounds")
    require(len(terminals) == len(set(terminals)),
            f"{report.name}: duplicate terminal messages")
    # Setup uses one terminal message per reduction and one message per
    # sumcheck round. Each message becomes one aligned ciphertext.
    count = len(rounds) + len(terminals)
    match = re.search(
        r"`server\.proof\.committed_gkr\.commitment_digest_bytes` \| ([\d,]+) B",
        text)
    require(match is not None, f"{report.name}: missing digest byte count")
    measured_bytes = int(match.group(1).replace(",", ""))
    require(measured_bytes == count * digest_bytes,
            f"{report.name}: span count and encrypted-message digests disagree")
    require(count <= PUBLISHED_R, f"{report.name}: exceeds published r envelope")
    print(f"{report.name}: {len(rounds)} sumcheck + {len(terminals)} terminal = {count}")
    return count


def main():
    params = (ROOT / "include/laminate/params.hpp").read_text()
    modulus = literal(params, "kOuterFieldOrder")
    plaintext = literal(params, "kBaseFieldOrder")
    beta = literal(params, "kSelectedPackingHonestErrorBound")
    tests = literal(params, "kPackingWellFormednessRepetitions")
    digest_bytes = 8 * literal(params, "kPoseidonDigestElements")
    require((modulus, plaintext, beta, tests) ==
            (1_053_858_393_162_252_289, 65_537, 17_781, 120),
            "selected constants changed: review the published profile")
    require(modulus.bit_length() == 60, "final modulus must be 60 bits")
    p = plaintext * beta + (plaintext - 1) // 2
    require(p == 1_165_346_165, "published partial-decryption cap changed")

    fixture = (ROOT / "tests/packing/evaluation/test_well_formedness.cpp").read_text()
    capacity = re.search(
        r"compute_packing_modulus_capacity\(\s*kOuterFieldOrder,\s*"
        r"([\d']+),\s*([\d']+),\s*([\d']+)\)", fixture)
    require(capacity is not None, "missing selected-profile capacity fixture")
    fixture_values = tuple(int(value.replace("'", "")) for value in capacity.groups())
    require(fixture_values == (plaintext, PUBLISHED_R, PUBLISHED_WEIGHT_UPPER),
            "published envelope differs from the C++ capacity fixture")

    counts = [aligned_messages(ROOT / "bench_outputs" / name, digest_bytes)
              for name in REPORTS]
    require(max(counts) == PUBLISHED_R, "published maximum differs from reports")

    # With c=37/4, detection is 333 P r <= 2 Q. Replacing sqrt(r) by
    # ceil(sqrt(r)) and W_Sigma by W_upper gives a stronger no-wrap test.
    root = isqrt(PUBLISHED_R)
    ceiling = root + (root * root < PUBLISHED_R)
    detection = 333 * p * PUBLISHED_R
    no_wrap = 111 * p * ceiling * PUBLISHED_WEIGHT_UPPER
    require(detection <= 2 * modulus, "modular detection premise fails")
    require(no_wrap < modulus, "strict packing no-wrap premise fails")
    print(f"P={p}, ceil(sqrt(r))={ceiling}")
    print(f"detection: {detection} <= {2 * modulus}")
    print(f"no wrap: {no_wrap} < {modulus}")
    print("PASS: five evaluated message counts and both integer admission "
          "inequalities for the published mask-weight envelope")


if __name__ == "__main__":
    main()
