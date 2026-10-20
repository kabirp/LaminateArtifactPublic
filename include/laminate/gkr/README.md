# Encrypted GKR

This directory implements the layer-reduction proof used by Base, Folded,
and Laned. It consumes a fixed payload output and returns a claim about the
input layer. Complete delegation and transcript packing belong to the
[protocol layer](../protocol/README.md).

## Shortest reading path

Each row follows layer orchestration, the round prover and its FHE evaluator,
then verification.

| Variant | Layer order | Affine reduction | Multiplication reduction | Verification |
| --- | --- | --- | --- | --- |
| Base | `BaseProver::run` in [`detail/base/prover.hpp`](detail/base/prover.hpp) | [`detail/base/affine/prover.hpp`](detail/base/affine/prover.hpp), then [`evaluator.hpp`](detail/base/affine/evaluator.hpp) | [`detail/base/multiplication/prover.hpp`](detail/base/multiplication/prover.hpp), then [`evaluator.hpp`](detail/base/multiplication/evaluator.hpp) | [`detail/base/verifier.hpp`](detail/base/verifier.hpp) |
| Folded | `FoldedProver::prove_admitted_request` in [`detail/folded/prover.hpp`](detail/folded/prover.hpp) | [`detail/folded/affine/prover.hpp`](detail/folded/affine/prover.hpp), then [`evaluator.hpp`](detail/folded/affine/evaluator.hpp) | [`detail/folded/multiplication/prover.hpp`](detail/folded/multiplication/prover.hpp), then the shared [`prover.hpp`](detail/shared/dense_multiplication/prover.hpp) and [`evaluator.hpp`](detail/shared/dense_multiplication/evaluator.hpp) | [`detail/folded/verifier.hpp`](detail/folded/verifier.hpp) |
| Laned | `LanedProver::prove_admitted_request` in [`detail/laned/prover.hpp`](detail/laned/prover.hpp) | [`detail/laned/affine/prover.hpp`](detail/laned/affine/prover.hpp), then [`evaluator.hpp`](detail/laned/affine/evaluator.hpp) | [`detail/laned/multiplication/prover.hpp`](detail/laned/multiplication/prover.hpp), then the shared [`prover.hpp`](detail/shared/dense_multiplication/prover.hpp) and [`evaluator.hpp`](detail/shared/dense_multiplication/evaluator.hpp) | [`detail/laned/verifier.hpp`](detail/laned/verifier.hpp) |


Variant guides cover source geometry and ownership: [Base](detail/base/README.md),
[Folded](detail/folded/README.md), and [Laned](detail/laned/README.md).

## What the visible loops show

The prover and verifier files own message observation, challenge sampling,
and claim transitions. Evaluators own source scans and concrete FHE work.
Shared round types and interpolation live in
[`detail/shared/reduction/sumcheck.hpp`](detail/shared/reduction/sumcheck.hpp).

Base proves ciphertext-index rounds under FHE and leaves slot-index completion
to the client. Folded and Laned also prove slot-index rounds under FHE. Progress
events identify the variant, layer, coordinate domain, and round.

## Arithmetic and storage boundaries

Folded/Laned multiplication uses
[`detail/shared/dense_multiplication/prover.hpp`](detail/shared/dense_multiplication/prover.hpp)
and its adjacent evaluator. Base uses its slot-preserving
[`detail/base/multiplication/evaluator.hpp`](detail/base/multiplication/evaluator.hpp).
Concrete SEAL operations are in
[`src/fhe/seal/arithmetic.cpp`](../../../src/fhe/seal/arithmetic.cpp).

Sources contain live public-or-encrypted values at setup-bound levels.
Structural padding is public zero and has no ciphertext record. Admission,
source construction, readers, and reclamation are kept in the corresponding
`validation/`, `storage/`, and `source/` directories. Retirement is destructive;
callers must respect the enclosing protocol's one-shot lifecycle.

Bounded resident comparisons live under `reference/`. Some reuse canonical
recurrences, so their directory name does not imply independent arithmetic.
[`layer_reduction_sumcheck.hpp`](layer_reduction_sumcheck.hpp) supplies the
independent plaintext layer-reduction oracle.

## Public proof types

[`base.hpp`](base.hpp), [`folded.hpp`](folded.hpp), and [`laned.hpp`](laned.hpp)
define the public proof boundaries. Folded and Laned share the schema in
[`detail/shared/packed/proof.hpp`](detail/shared/packed/proof.hpp), with distinct
version and transcript identifiers. [`claims.hpp`](claims.hpp) defines layer
claims; [`ciphertext_commitment.hpp`](ciphertext_commitment.hpp) defines
committed messages. Canonical encodings and decode limits are enforced by the
source codecs, including rejection of alternate public-vector representations.

The GKR verifier requires the expected output claim, input values, provenance,
and setup binding. Complete delegation also binds these to the request and
response, and packed variants verify transcript packing. A layer-reduction
check alone is not whole-response acceptance.

Layer, source-layout, and proof-schema tests are in
[`tests/gkr/`](../../../tests/gkr/). Whole-proof comparisons include
[`test_base.cpp`](../../../tests/test_base.cpp),
[`test_folded.cpp`](../../../tests/test_folded.cpp), and
[`test_laned.cpp`](../../../tests/test_laned.cpp).
