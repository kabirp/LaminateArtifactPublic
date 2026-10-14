# Transcript packing implementation

Folded and Laned commit to encrypted GKR messages and recover them through
transcript packing. Base sends its messages directly. The construction is in
Section 6.1, “Transcript Packing Compiler,” Section F.1, “Protocol and Packing
Construction,” and Section F.1.2, “The Packing Argument.”

## Selected parameters

| Item | Executable choice |
| --- | --- |
| GKR extension/cell | `R=8`, `M=16` slots |
| Packing field | `Q=1,053,858,393,162,252,289`; challenges in `Fq2` |
| Ciphertext commitment | Poseidon, six-field digest, width 16 / rate 10 / capacity 6 |
| Well-formedness | 120 lazy-ternary tests; `c=37/4`; canonical-error cap `beta_e=17,781` |
| Digits | Four balanced radix-17 digits with magnitude at most 8 |
| PCS | Rate-1/8 RS BaseFold, 150 query paths; BLAKE2b-320 Merkle authentication |

The diagnostic quick profile uses `simpleCTHash/v2` and reduced parameters,
without a binding or target integrity claim. Setup derives message counts
from the compiled circuit: `r_logical` counts rounds while packing's `r`
also includes terminal exchanges. [Cost accounting](COST_MODEL.md#packing-work-and-memory)
distinguishes these quantities.

## Relation and proof flow

The implementation continues the same
[`single-transcript-gkr-then-packing-v1` transcript](PROTOCOLS.md#one-fiatshamir-transcript-for-the-packed-protocols)
through these stages:

1. Align messages in setup-fixed BGV-grid cosets. Normalize encrypted
   contributions to size-two, one-prime NTT coordinates over `Q`, and commit
   before the next GKR challenge.
2. Bind the complete committed GKR proof before sampling well-formedness
   coefficients. The relation checks both Boolean bits encoding each ternary
   coefficient, including the two encodings of zero.
3. Reconstruct and SHA-256-bind the logical public vector from commitments,
   challenges, reveals, and digit ciphertexts. It is not serialized a second
   time; aligned ciphertexts remain private witness data.
4. Replay GKR and authenticate gate claims; verify Spartan, factored matrix
   contributions, and PCS openings before client-secret threshold checks.
5. After those checks pass, decrypt/recompose digits, invert placement, and check
   GKR arithmetic using recorded challenges. A rejection does not advance
   the caller's transcript.

Known public zero has no ciphertext or encrypted alignment operations, while
preserving the setup-shaped statement and message order. Hidden zero remains
encrypted.

Spartan proves the complete R1CS. The factored matrix implementation uses
compact regular formulas and setup-committed coefficient tensors, avoiding
expanded matrices in the verifier key. Residual product sumchecks authenticate
tensor contributions; they do not replace the witness argument. Public-vector
binding still has linear work, and factored verification is not purely
polylogarithmic. See the [Spartan module](../include/laminate/spartan/README.md)
and Section F.1.3, “Packing Layout and Cost.”

## Admission and security boundary

[Well-formedness admission](WELL_FORMEDNESS_THEOREMS.md#exact-setup-checks)
uses actual encoded digit masks and integer inequalities. It does not prove
that every honest ciphertext meets the noise cap.
[BGV parameters](BGV_NOISE_AND_MODULUS_SWITCHING.md) distinguishes that cap,
the honest-run engineering target, and the sampled noise checks.

Section G.5, “Soundness of the Compiled Protocol,” composes packing with GKR,
and Section H.2, “Integrity Parameters,” gives the conditional concrete bound.
[Status](STATUS.md#parameters-and-security-assumptions) summarizes the
commitment, extraction, random-oracle, and adversarial-budget assumptions.

## Code and tests

| Responsibility | Source |
| --- | --- |
| Alignment and commitments | [`aligned_commitments.hpp`](../include/laminate/protocol/detail/packing/aligned_commitments.hpp) |
| Setup and admission | [`packed/setup.hpp`](../include/laminate/protocol/packed/setup.hpp) |
| Public replay and deferred GKR | [`gkr_transcript_replay.hpp`](../include/laminate/protocol/detail/packing/gkr_transcript_replay.hpp) |
| File-backed composition | [`external/prover.hpp`](../include/laminate/protocol/packed/external/prover.hpp), [`external/transcript_packing.hpp`](../include/laminate/protocol/packed/external/transcript_packing.hpp) |
| Tests and digit evaluation | [`lazy_ternary.hpp`](../include/laminate/packing/evaluation/lazy_ternary.hpp) |
| Relation and tensors | [`outer_relation/`](../include/laminate/packing/outer_relation/), [`proof/`](../include/laminate/packing/proof/) |
| Canonical formats and decoder limits | [`packed/wire/proof.hpp`](../include/laminate/protocol/packed/wire/proof.hpp) |
| Test inventory | [Packing module](../include/laminate/packing/README.md), [protocol module](../include/laminate/protocol/README.md) |

Decoders enforce format versions, dimensions, canonical encodings, and
allocation bounds. Passing those checks is parsing success, not protocol
acceptance.
