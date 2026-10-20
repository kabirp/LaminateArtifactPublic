#!/usr/bin/env python3
"""Reproduce Laminate's concrete Phalanx and Blind Fractal comparison estimates.

Run with Python 3 (standard library only), or add --json for detailed counts.

The estimates deliberately favor prior work. We supply an encrypted witness in
the required field and layout for free, omitting payload evaluation, witness
reduction, and any increase in witness size. We charge only selected prover
stages and proof-ciphertext decryption on the client. The proof-size calculations
use favorable formats and omit other data where noted below.

One proof covers the whole circuit, which favors communication and client costs.
These are partial estimates for the published schemes, not full request timings.
See docs/PRIOR_WORK_ESTIMATES.md in the public artifact for sources and scope.
"""

# Blind Fractal's counting model and primitive timings are described in
# KU Leuven - COSIC's blind_zkSNARKs estimator, commit
# 006d5cdff27479d7568646752e46982efbcb8164. See the guide for source links.

import argparse
import json
import math
from fractions import Fraction


ESTIMATE_INTRO = (
    "Each row estimates one proof for the full circuit from an encrypted witness. "
    "Server estimates count selected stages. Proof data excludes some messages, "
    "and client estimates cover proof-ciphertext decryption only."
)
N = 2**14
PACK = 256
# (log2 circuit size, radix, inverse width). These minimize counted NTT cost
# among power-of-two choices with depth limits 5, 4, and 5, respectively.
BF_PARAMETERS = ((20, 8, 1), (27, 64, 2), (34, 64, 4))
# Seconds per (addition, plaintext-ciphertext multiplication, automorphism).
# The source prices the first stage at 420 bits, then 360, 360, and 300 bits.
# Retain these small-instance prices at every size, with no extra charge for
# larger ciphertext moduli or memory and disk traffic at large circuit sizes.
PRICES = {
    "unpacking": (0.00014, 0.00034, 0.00724),
    "matrix products": (0.00012, 0.00028, 0.00552),
    "inverse NTTs": (0.00012, 0.00028, 0.00552),
    "forward NTTs": (0.00010, 0.00024, 0.00398),
}
# Round down our measured single-limb BGV decryption/unpacking time. All other
# client work, including input encryption and output decryption, is omitted.
DECRYPT_SECONDS = 0.00040


def log2_exact(value):
    assert value > 0 and value & (value - 1) == 0
    return value.bit_length() - 1


def expected_hits(population, groups, draws):
    """Expected equal-sized groups hit by sampling without replacement."""
    assert groups > 0 and population % groups == 0 and 0 <= draws <= population
    group_size = population // groups
    all_subsets = math.comb(population, draws)
    avoiding_subsets = math.comb(population - group_size, draws)
    # Exact arithmetic keeps a small hit probability from rounding to zero.
    return float(Fraction(groups * (all_subsets - avoiding_subsets), all_subsets))


def matrix_ops(length, row_weight=None, repetitions=1, halfzero=False):
    """Count matrix-vector additions, pt-ct multiplications, and automorphisms."""
    assert length % PACK == 0
    nonzeros = length if row_weight is None else row_weight
    packed_rows = length // PACK
    diagonals = expected_hits(length * PACK, length, nonzeros * PACK)
    direct_rotations = expected_hits(
        (PACK - 1) * length, PACK - 1, nonzeros * (PACK - 1)
    )
    baby_steps = 1 << ((log2_exact(PACK) + 1) // 2)
    giant_steps = PACK // baby_steps
    grouped_rotations = baby_steps - 1 + packed_rows * (giant_steps - 1)
    # Skip known-zero products in the zero-padded forward transform.
    divisor = 2 if halfzero else 1
    # Each nonzero diagonal needs one product. Adding the products costs one less.
    products_per_row = diagonals / divisor
    copies = repetitions * packed_rows
    # Give the prover the cheaper of direct and baby-step/giant-step rotations.
    return (
        copies * (products_per_row - 1),
        copies * products_per_row,
        copies * min(direct_rotations, grouped_rotations) / divisor,
    )


def ntt_ops(length, base, width, repetitions=4, halfzero=False):
    """Count row butterflies and the packed matrix product for the columns."""
    column_length = PACK * width
    assert length % column_length == 0
    log_row_length = log2_exact(length // column_length)
    assert log_row_length % log2_exact(base) == 0
    row_stages = log_row_length // log2_exact(base)
    assert row_stages + 1 <= 5
    row_arithmetic = repetitions * row_stages * (base - 1) * (length // PACK)
    column_counts = matrix_ops(
        column_length,
        repetitions=repetitions * (length // column_length),
        halfzero=halfzero and width > 1,
    )
    return tuple(
        count + row_arithmetic if operation < 2 else count
        for operation, count in enumerate(column_counts)
    )


def occupied(groups, queries=101):
    """Expected groups hit by independent FRI queries sampled with replacement."""
    return -groups * math.expm1(queries * math.log1p(-1 / groups)) if groups > 1 else 1.0


def bf_openings(log_size):
    """Count paired FRI openings once per ciphertext, plus the final ciphertext."""
    domain, slots = 2 ** (log_size + 1), 16
    depth = log2_exact(domain // slots)
    # Repeated queries share an opening. Count distinct ciphertexts, not paths,
    # across five initial polynomial tables and the subsequent FRI levels.
    return 1 + 5 * occupied(domain // slots) + sum(
        occupied(domain // (2 ** (i - 1) * slots)) for i in range(2, depth + 1)
    )


def blind_fractal(log_size, base, width):
    size = 2**log_size
    # Follow the source's dimension-12288 model with timings measured at 16384.
    # Count only unpacking, three matrix products, and four initial encodings.
    # All later prover stages, including FRI, are omitted.
    operations = {
        "unpacking": (0, size // PACK, size // PACK),
        "matrix products": matrix_ops(size, row_weight=3, repetitions=3),
        "inverse NTTs": ntt_ops(size, base, width),
        "forward NTTs": ntt_ops(2 * size, base, 2 * width, halfzero=True),
    }
    stages = {
        name: {"operations": counts, "seconds": sum(c * p for c, p in zip(counts, PRICES[name]))}
        for name, counts in operations.items()
    }
    count = bf_openings(log_size)
    # Use Remark 3's small output ciphertexts (dimension 768, 24-bit modulus).
    # Charge neither conversion/repacking nor hashes and other proof data.
    # At larger sizes, also omit the cost of enlarging the prover's parameters
    # to satisfy the source's noise and field-size limits.
    # The N log N-scaled BGV decryption price is a proxy for GBFV, not a timing
    # measurement of Blind Fractal's client.
    small_decrypt = DECRYPT_SECONDS * (768 * math.log2(768)) / (N * math.log2(N))
    return {
        "protocol": "Blind Fractal",
        "log2_size": log_size,
        "base": base,
        "inverse_width": width,
        "forward_width": 2 * width,
        "ntt_depth": log2_exact(size // (PACK * width)) // log2_exact(base) + 1,
        "server_hours": sum(stage["seconds"] for stage in stages.values()) / 3600,
        "expected_ciphertexts": count,
        "ciphertext_payload_MB": count * (2 * 768 * 24 / 8) / 10**6,
        "decryption_proxy_seconds": count * small_decrypt,
        "stages": stages,
    }


def phalanx(log_size):
    size = 2**log_size
    # At 2^20 use the reported full proof. For larger circuits, count only two
    # sets of 240 column openings, two response vectors, and two sumchecks.
    # Other messages and authentication paths are omitted at these larger sizes.
    count = 504 if log_size == 20 else (
        480 + 2 * ((3 * size + N * N - 1) // (N * N)) + 2 * (log_size - 14)
    )
    return {
        "protocol": "Phalanx",
        "log2_size": log_size,
        # Scale only the reported 1034-second matrix-product stage. Packing,
        # commitments, sumchecks, and all payload/witness construction are free.
        "server_hours": 1034 * (size / 2**20) / 3600,
        "ciphertexts": count,
        # Use the reported average bytes per ciphertext, with no increase at
        # larger sizes. No additional modulus or witness-reduction cost is added.
        "calibrated_payload_MB": 61.4 * count / 504,
        "decryption_proxy_seconds": count * DECRYPT_SECONDS,
        # Separate storage illustration, not a charge to server time or a
        # peak-memory lower bound. Streaming could avoid materializing it all.
        "materialized_witness_bytes": size * (2 * N * 6 * 8),
        "materialized_witness_TB": size * (2 * N * 6 * 8) / 10**12,
        "materialized_witness_PB": size * (2 * N * 6 * 8) / 10**15,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Reproduce the concrete Phalanx and Blind Fractal estimates in Laminate."
    )
    parser.add_argument("--json", action="store_true", help="print counts, stage costs, and assumptions")
    args = parser.parse_args()
    results = [
        row for k, base, width in BF_PARAMETERS
        for row in (phalanx(k), blind_fractal(k, base, width))
    ]
    if args.json:
        print(json.dumps({
            "scope": ESTIMATE_INTRO,
            "assumptions": {
                "proofs_per_circuit": 1,
                "encrypted_witness_already_available": True,
                "blind_fractal_ring_dimension": 12288,
                "primitive_timing_ring_dimension": N,
                "blind_fractal_packing": PACK,
                "blind_fractal_output_dimension": 768,
                "blind_fractal_output_modulus_bits": 24,
                "blind_fractal_output_slots": 16,
                "blind_fractal_fri_queries": 101,
                "decryption_proxy_seconds_at_N": DECRYPT_SECONDS,
            },
            "bf_operation_order": ["addition", "pt-ct multiplication", "automorphism"],
            "bf_prices_seconds": PRICES,
            "results": results,
        }, indent=2))
    else:
        print(ESTIMATE_INTRO + "\n")
        print("| Size | Protocol | Counted server hours | Proof data (MB) | Decryption proxy seconds |")
        print("|---|---|---:|---:|---:|")
        for row in results:
            payload = row.get("calibrated_payload_MB", row.get("ciphertext_payload_MB"))
            print(f"| 2^{row['log2_size']} | {row['protocol']} | {row['server_hours']:.6f} "
                  f"| {payload:.6f} | {row['decryption_proxy_seconds']:.6f} |")
        print("\nStorage if the entire six-limb Phalanx witness is materialized:")
        for row in results:
            if row["protocol"] == "Phalanx":
                unit = "PB" if row["materialized_witness_PB"] >= 1 else "TB"
                amount = row[f"materialized_witness_{unit}"]
                print(f"  2^{row['log2_size']}: {amount:g} {unit}")


if __name__ == "__main__":
    main()
