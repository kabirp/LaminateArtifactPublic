# Shared GKR mechanics

Start from the [GKR reading map](../../README.md) and follow a variant into the
shared implementation it uses.

| Directory | Responsibility |
| --- | --- |
| [`encoding/`](encoding/) | Canonical field, size, and extension-value encodings |
| [`reduction/`](reduction/) | GateMLE claims and round representation/interpolation |
| [`dense_multiplication/`](dense_multiplication/) | Packed multiplication prover, evaluator, verification, and source storage |
| [`packed/`](packed/) | Folded/Laned proof schema, transcript observation, prepared bases, and affine verification |

Variant policies retain geometry, transcript domains, challenge rules, and
terminal checks. The shared prover/verifier loops own transcript sequencing.
[`reduction/sumcheck.hpp`](reduction/sumcheck.hpp) contains arithmetic helpers,
not a protocol scheduler.

For multiplication, read
[`dense_multiplication/prover.hpp`](dense_multiplication/prover.hpp), then
[`evaluator.hpp`](dense_multiplication/evaluator.hpp) and
[`arithmetic/ciphertext_index_rounds.hpp`](dense_multiplication/arithmetic/ciphertext_index_rounds.hpp).
Base uses a slot-preserving
[`multiplication evaluator`](../base/multiplication/evaluator.hpp).
Bounded resident parity code is in
[`dense_multiplication/reference/`](dense_multiplication/reference/).

[`dense_multiplication/source/scan.hpp`](dense_multiplication/source/scan.hpp)
checks complete live-pair and distinct-operand coverage. Cache eviction does
not discard coverage; rewind resets it. Physical read and byte counters
include rereads. Sequential first reads and random-access alias rereads use
separate readers, with both buffers charged to resource admission.

Affine kernels are variant-specific:
[Base](../base/affine/evaluator.hpp),
[Folded](../folded/affine/evaluator.hpp), and
[Laned](../laned/affine/evaluator.hpp).

Tests cover [source layout](../../../../../tests/gkr/test_dense_paired_source.cpp),
[packed multiplication verification](../../../../../tests/gkr/test_packed_dense_multiplication_verifier.cpp),
and [packed proof schemas](../../../../../tests/gkr/test_packed_proof_schema.cpp).
