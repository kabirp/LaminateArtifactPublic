# Transcript packing

Folded and Laned reduce the cost of transmitting their encrypted GKR
transcript by packing its messages. This directory implements the packing
calculation and the relation that proves it was performed correctly. Base
transmits its GKR proof directly and does not use this suffix.

Read the calculation in this order: align the encrypted messages, normalize
and commit them, derive the public well-formedness tests, form the signed-digit
packed values, then prove the resulting relation with Spartan.

| Directory | Start here | Responsibility |
|---|---|---|
| [`alignment/`](alignment/) | [`layout.hpp`](alignment/layout.hpp) | Place GKR messages into aligned ciphertext slots and unpack accepted outputs. |
| [`evaluation/`](evaluation/) | [`lazy_ternary.hpp`](evaluation/lazy_ternary.hpp) | Normalize aligned values, derive transcript-bound masks, and form the well-formedness reveals and signed-digit packed values. |
| [`outer_relation/`](outer_relation/) | [`relation.hpp`](outer_relation/relation.hpp) | Define the public statement, witness assignment, and streamed R1CS relation that certifies the packing calculation. |
| [`proof/`](proof/) | [`r1cs.hpp`](proof/r1cs.hpp) | Map the relation into Spartan and the external artifact-backed prover; the structured matrix argument is grouped under [`proof/matrix/`](proof/matrix/). |
| [`analysis/`](analysis/) | [`deterministic_completeness.hpp`](analysis/deterministic_completeness.hpp) | Keep completeness bounds, honest-run measurements, operator accounting, and explicitly unbound diagnostics out of the production path. |

The server-side FHE operations are intentionally easy to locate:

- [`evaluation/phases/evaluate.hpp`](evaluation/phases/evaluate.hpp) is the
  short high-level evaluation flow;
- [`evaluation/phases/prover_linear_forms.hpp`](evaluation/phases/prover_linear_forms.hpp)
  performs the plaintext/ciphertext multiplications and linear accumulation;
- [`evaluation/phases/aligned_transcript.hpp`](evaluation/phases/aligned_transcript.hpp)
  performs rotations and the final modulus switch to the one-prime commitment
  representation.

Protocol composition lives outside this library directory. Start with the
Folded or Laned entry point in [`../protocol/README.md`](../protocol/README.md),
then follow its transcript-packing call into `protocol/packed/`.

## Composition boundary

[`outer_relation/relation.hpp`](outer_relation/relation.hpp) defines the native
coefficient relation; [`proof/r1cs.hpp`](proof/r1cs.hpp) adds commitments and
maps it into Spartan. The complete protocol also requires the client-side
secret-key well-formedness checks and unpacking. A standalone relation check
does not establish their acceptance. Appendix F, “Transcript Packing,” of the
paper specifies the construction and its guarantees.

The target-scale proof starts at
[`proof/spartan_external.hpp`](proof/spartan_external.hpp). It uses bounded
assignment and matrix-product artifacts and caller-supplied storage budgets.
Materialized assignments under `proof/reference/` are bounded comparison
paths. Analysis and unbound diagnostic results under `analysis/` do not replace
setup admission or verification.

The relation, packing calculations, and matrix construction are tested under
[`tests/packing/`](../../../tests/packing/). The resident/external composition
comparison is in
[`test_transcript_packing_external.cpp`](../../../tests/protocol/test_transcript_packing_external.cpp).
