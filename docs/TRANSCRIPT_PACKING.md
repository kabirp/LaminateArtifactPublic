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

## Slot layout

Section F.1.3, “Packing Layout and Cost,” assigns each of `r` rounds a block
of `M` logical slots in an output with `N` SIMD slots, with `M` dividing `N`.
Using one-based indices, logical output `ell` contains the rounds

$$
\mathcal I_\ell
  = \{i\in[r]:(\ell-1)N/M<i\leq\ell N/M\},
\qquad \ell\in[\lceil Mr/N\rceil].
$$

A fixed public permutation $\sigma:[N]\to[N]$ maps each logical slot to
its physical SIMD slot. Message `j` of round `i` goes to

$$
s_{i,j}=\sigma\bigl(((i-1)M\bmod N)+j\bigr),
\qquad i\in[r],\quad j\in[M].
$$

The blocks within an output are disjoint, and the largest output contains
$r_{\max}=\min\{r,N/M\}$ rounds. The identity permutation places each
block in consecutive physical slots. Other permutations can reduce the
coefficient norms of the encoded masks.

The implementation selects a structured permutation with `M=16`. For
`N>=32`, the backend uses a `2 x (N/2)` BGV grid. Within each output, the
first round's 16 cells occupy the subgroup `{0, N/32, ..., 15N/32}` in the
first row, using zero-based column indices. Successive rounds use disjoint
translates of this subgroup, filling the first row and then the second. The
[protocol setup](../src/protocol/packed/setup.cpp) sets the per-output
capacity to `N/16`, so its grouping agrees with the formulas above.
The [layout interface](../include/laminate/packing/alignment/layout.hpp),
[placement implementation](../src/packing/alignment/layout.cpp), and
[message-cell map](../include/laminate/fhe/layout/fixed_message.hpp)
define this placement and its destination masks.

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

## Evaluated relation sizes

Section H.2, “Integrity Parameters,” uses the number of padded constraint rows
to bound the first Spartan row-point check. The evaluated configurations have
the following dimensions, with `N=16,384` and `ell_C` equal to the base-two
logarithm of the padded row count.

| Protocol | Payload profile | Lanes `B` | Constraint rows | Padded rows | `ell_C` |
| --- | --- | ---: | ---: | ---: | ---: |
| Laned | `target-balancedLaned` | 1 | 1,760,198,656 | 2,147,483,648 (`2^31`) | 31 |
| Laned | `target-balancedLaned` | 128 | 2,445,508,608 | 4,294,967,296 (`2^32`) | 32 |
| Laned | `target-balancedLaned` | 16,384 | 3,167,518,720 | 4,294,967,296 (`2^32`) | 32 |
| Folded | `target-balancedLaned` | — | 3,167,518,720 | 4,294,967,296 (`2^32`) | 32 |
| Folded | `target-mulHeavyPyramid` | — | 3,118,563,328 | 4,294,967,296 (`2^32`) | 32 |

The [size report](../benches/reports/packing_relation_size_report.cpp) compiles
the selected payload geometry and computes the complete packing-relation
ledger without materializing the full relation or running a proof. From the
repository root, reproduce the counts with:

```sh
cmake -S . -B build-size-report -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF -DBUILD_BENCHMARKS=ON -DLAMINATE_WITH_SEAL=OFF
cmake --build build-size-report --target laminate_packing_relation_size_report --parallel
for lanes in 1 128 16384; do
  build-size-report/benches/laminate_packing_relation_size_report \
    --protocol laned --profile target-balancedLaned --lanes "$lanes"
done
for profile in target-balancedLaned target-mulHeavyPyramid; do
  build-size-report/benches/laminate_packing_relation_size_report \
    --protocol folded --profile "$profile"
done
```

The relevant output fields are `matrix_rows` and
`spartan_padded_constraints`. The largest padded count is `2^32`, so
`ell_C <= 32` in the paper's arithmetic error calculation. The
[`A,B,C` batch](../src/packing/proof/spartan_external.cpp) uses coefficients
`1, gamma, gamma^2`. The [public-index verifier](../src/spartan/factored.cpp)
checks each tensor contribution separately with a quadratic product sumcheck
and sums the contributions deterministically. It introduces no further random
batching challenge, so the paper takes `d_batch=0`.

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
