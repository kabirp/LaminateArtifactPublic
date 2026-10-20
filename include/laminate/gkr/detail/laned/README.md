# LaminateLaned GKR

Laned proves scalar computations in `B` logical lanes using compact packed
witnesses. The [payload guide](../../../payload/README.md) maps input and
witness layouts. This directory implements inner GKR; transcript packing is
handled by the enclosing protocol.

| Entry point | Responsibility |
| --- | --- |
| [`prover.hpp`](prover.hpp) | `LanedProver::prove_admitted_request`: header binding, layer order, retirement, and final GateMLE opening |
| [`affine/prover.hpp`](affine/prover.hpp) | Ciphertext-index and slot-index affine rounds |
| [`affine/evaluator.hpp`](affine/evaluator.hpp) | FHE kernel; reader and prepared-basis helpers in [`affine/source/`](affine/source/) |
| [`multiplication/prover.hpp`](multiplication/prover.hpp) | Laned policy for the shared [`multiplication prover`](../shared/dense_multiplication/prover.hpp) |
| [`verifier.hpp`](verifier.hpp) | Whole GKR verification |
| [`affine/verifier.hpp`](affine/verifier.hpp) | Laned challenge rules, constant adjustment, terminal GateMLE check, and inverse transform |
| [`multiplication/verifier.hpp`](multiplication/verifier.hpp) | Multiplication geometry and proof admission |

Standalone affine proving validates circuit/source identity. Whole-proof
proving reuses setup-bound admission across layers. Multiplication admission
normalizes source plans before the reduction loop. `validation/` and
`proving/` own these boundaries; source access remains under the corresponding
`source/` directories.

Production proving is file-backed and retirement is destructive. Progress
events distinguish source build/open/reclaim work from affine and
multiplication rounds. Bounded resident comparisons live under `reference/`
and the per-reduction `reference/` directories.

File-backed proof and rejection tests are in
[`test_laned_prover_file_backed.cpp`](../../../../../tests/gkr/test_laned_prover_file_backed.cpp),
with SEAL coverage in
[`test_laned_prover_file_backed_seal.cpp`](../../../../../tests/gkr/test_laned_prover_file_backed_seal.cpp).
