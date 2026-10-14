# LaminateFolded GKR

Folded proves Wide payload ciphertext-index and slot-index reductions under
FHE. This directory implements inner GKR; the enclosing protocol packs and
verifies its messages.

| Entry point | Responsibility |
| --- | --- |
| [`prover.hpp`](prover.hpp) | `FoldedProver::prove_admitted_request`: header binding, layer order, source retirement, and final GateMLE opening |
| [`affine/prover.hpp`](affine/prover.hpp) | Ciphertext-index and slot-index affine rounds |
| [`affine/evaluator.hpp`](affine/evaluator.hpp) | FHE kernel; readers in [`affine/source/`](affine/source/) |
| [`multiplication/prover.hpp`](multiplication/prover.hpp) | Folded policy for the shared [`multiplication prover`](../shared/dense_multiplication/prover.hpp) |
| [`verifier.hpp`](verifier.hpp) | Whole GKR verification; variant checks in [`affine/verifier.hpp`](affine/verifier.hpp) and [`multiplication/verifier.hpp`](multiplication/verifier.hpp) |

The standalone affine entry point validates circuit/source identity. The
whole-proof path reuses setup-certified admission across layers. Multiplication
admission normalizes setup-precomputed or locally derived source plans before
entering the reduction loop.

`proving/` owns per-layer handoffs, `validation/` owns request and scratch
admission, `storage/` owns artifact options and reports, and `transport/` owns
message packing. The top-level prover marks final consumers and destructive
retirement explicitly.

[`reference/`](reference/) contains bounded resident comparisons, not a second
production mode. Its affine adapter reuses the canonical recurrence, so it is
not an independent arithmetic oracle.

[`test_folded_prover.cpp`](../../../../../tests/gkr/test_folded_prover.cpp)
checks inner GKR. Whole-protocol tests include
[`test_folded.cpp`](../../../../../tests/test_folded.cpp) and
[`test_packed_external.cpp`](../../../../../tests/protocol/test_packed_external.cpp).
