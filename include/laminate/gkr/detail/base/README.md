# LaminateBase GKR

Base preserves slotwise encrypted claims through ciphertext-index reductions
and leaves slot-index completion to the client. GKR messages are sent directly,
without transcript packing.

| Entry point | Responsibility |
| --- | --- |
| [`prover.hpp`](prover.hpp) | `BaseProver::run`: layer order, transcript sequencing, and storage retirement |
| [`affine/prover.hpp`](affine/prover.hpp) | Affine round recurrence |
| [`affine/evaluator.hpp`](affine/evaluator.hpp) | Affine FHE kernel; scan and basis helpers in [`affine/internal/`](affine/internal/) |
| [`multiplication/prover.hpp`](multiplication/prover.hpp) | Multiplication round recurrence |
| [`multiplication/evaluator.hpp`](multiplication/evaluator.hpp) | Slot-preserving multiplication kernel |
| [`verifier.hpp`](verifier.hpp) | Whole GKR verification; layer checks in [`affine/verifier.hpp`](affine/verifier.hpp) and [`multiplication/verifier.hpp`](multiplication/verifier.hpp) |

Production proving is file-backed. [`validation/`](validation/) admits requests
and scratch before transcript or filesystem mutation. [`storage/`](storage/)
owns paired multiplication artifacts and reclamation; [`proving/types.hpp`](proving/types.hpp)
defines options and compact reports. Geometry, encoding, and normalization
helpers do not own protocol sequencing.

[`reference/`](reference/) contains bounded resident comparisons. The affine
adapter reuses the canonical recurrence; the multiplication evaluator is a
separate comparator. The implementation-independent plaintext oracle is
[`layer_reduction_sumcheck.hpp`](../../layer_reduction_sumcheck.hpp).
[`testing/`](testing/) contains a retryable trace adapter for bounded tests;
production retirement remains destructive.

File-backed proof and rejection tests are in
[`test_base_prover_file_backed.cpp`](../../../../../tests/gkr/test_base_prover_file_backed.cpp),
with SEAL coverage in
[`test_base_prover_file_backed_seal.cpp`](../../../../../tests/gkr/test_base_prover_file_backed_seal.cpp).
