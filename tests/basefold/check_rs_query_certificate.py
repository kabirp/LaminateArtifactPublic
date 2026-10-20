#!/usr/bin/env python3
"""Verify the RS policy's numerical certificate using exact arithmetic.

This checks parameter substitutions, not the proximity-gap theorems.
See docs/BASEFOLD_SOUNDNESS.md for their hypotheses and sources. The companion
test_basefold_soundness.cpp checks the compiled policy and shape limits.
"""
from fractions import Fraction
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
K = 512
DISTANCE = Fraction(7, 8)
INITIAL_RADIUS = Fraction(223, 512)
QUERY_TARGET_BITS = 112


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def integer_parameter(source, name, seen=()):
    """Read a named integer literal or alias, tolerating C++ formatting."""
    require(name not in seen, f"cyclic parameter alias: {name}")
    match = re.search(r"\b" + re.escape(name) + r"\s*=\s*([^;]+);", source)
    require(match is not None, f"missing parameter: {name}")
    expression = match.group(1).strip()
    literal = re.fullmatch(r"([0-9][0-9']*)(?:[uUlL]*)", expression)
    if literal:
        return int(literal.group(1).replace("'", ""))
    require(re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", expression) is not None,
            f"expected a literal or alias for {name}, got {expression!r}")
    return integer_parameter(source, expression, (*seen, name))


def main():
    parameters = (ROOT / "include/laminate/params.hpp").read_text()

    def parameter(name):
        return integer_parameter(parameters, name)

    log_rate = parameter("kGateMleBaseFoldLogRate")
    queries = parameter("kGateMleBaseFoldQueries")
    require(log_rate == 3, "certificate requires inverse rate 8")
    require(queries == 150, "certificate requires the selected 150 queries")
    require(parameter("kTranscriptPackingBaseFoldLogRate") == log_rate,
            "packing rate differs from the certified RS rate")
    require(parameter("kTranscriptPackingBaseFoldQueries") == queries,
            "packing query count differs from the certified RS policy")
    require(parameter("kBaseFoldIntegrityTargetBits") == 110,
            "RS integrity target changed")

    base_field = parameter("kBaseFieldOrder")
    extension_degree = parameter("kExtensionDegree")
    outer_field = parameter("kOuterFieldOrder")
    gate_domain_log = parameter("kBaseFieldTwoAdicity")
    packing_domain_log = parameter("kOuterFieldTwoAdicity")
    require(base_field == 65537 and extension_degree == 8,
            "gate challenge field changed")
    require(outer_field == 1053858393162252289,
            "packing challenge field changed")
    require((base_field - 1) % (1 << gate_domain_log) == 0,
            "gate field does not support its claimed RS domain")
    require((outer_field - 1) % (1 << packing_domain_log) == 0,
            "packing field does not support its claimed RS domain")
    require(gate_domain_log - log_rate == 13,
            "gate RS message-size limit changed")
    max_folds = packing_domain_log - log_rate
    require(max_folds == 34, "packing RS message-size limit changed")

    gate_field = base_field**extension_degree
    packing_field = outer_field**2
    require(gate_field > 1 << 128, "gate field lower bound fails")
    require(packing_field > 1 << 119, "packing field lower bound fails")
    require((K << 119) < gate_field, "rounded gate folding bound fails")
    require((K << 110) < packing_field, "rounded packing folding bound fails")

    def challenge_threshold(radius):
        return (DISTANCE / radius - 1) / (DISTANCE - 2 * radius)

    initial_threshold = challenge_threshold(INITIAL_RADIUS)
    require(initial_threshold == Fraction(57600, 223),
            "published challenge-threshold calculation fails")
    require(initial_threshold < K, "512 good challenges do not suffice")
    require(DISTANCE / 2 - INITIAL_RADIUS == Fraction(1, 512),
            "published code-length cutoff fails")

    small_lengths = set()
    for message_log in range(max_folds + 1):
        radius = INITIAL_RADIUS
        for step in range(message_log + 1):
            code_length = 1 << (message_log - step + log_rate)
            require(2 * radius < DISTANCE, "radius is not uniquely decodable")
            if code_length >= 512:
                require(DISTANCE / 3 <= radius <= DISTANCE / 2 -
                        Fraction(1, code_length),
                        f"large-code radius condition fails at {message_log=}, {step=}")
                require(challenge_threshold(radius) <= initial_threshold < K,
                        f"large-code challenge threshold fails at {message_log=}, {step=}")
            else:
                small_lengths.add(code_length)
                require(K > code_length and radius < Fraction(7, 16),
                        f"small-code theorem condition fails at {message_log=}, {step=}")
            if step < message_log:
                next_radius = radius * Fraction(K - 1, K)
                require(next_radius * K / (K - 1) == radius,
                        "common-agreement radius does not recover the previous radius")
                radius = next_radius
        miss = 1 - radius
        require(miss < Fraction(19, 32),
                f"published miss bound fails at {message_log=}")
        require(miss**queries < Fraction(1, 1 << QUERY_TARGET_BITS),
                f"terminal query certificate fails at {message_log=}")

    require(small_lengths == {8, 16, 32, 64, 128, 256},
            "small-code cases differ from the published certificate")
    miss_bound = Fraction(19, 32)
    for exponent, bits in ((2, 1), (3, 2), (4, 3)):
        require(miss_bound**exponent < Fraction(1, 1 << bits),
                "integer policy's query rounding inequality fails")
    require(miss_bound**queries < Fraction(1, 1 << QUERY_TARGET_BITS),
            "published 150-query inequality fails")
    print("PASS: RS proximity-gap hypotheses, all message logs 0..34, "
          "terminal error <2^-112, and both field bounds checked exactly")


if __name__ == "__main__":
    main()
