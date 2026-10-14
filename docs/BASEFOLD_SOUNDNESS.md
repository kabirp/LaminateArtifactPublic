# Reed–Solomon BaseFold policy

Laned GateMLE and transcript-packing openings use rate-1/8 Reed–Solomon
BaseFold with 150 independently sampled query paths per opening batch.
The local interactive PCS round-by-round (RBR) target is `2^-110`, conditional
on good setup. Base/Folded Wide gates use a different code hierarchy and the
[Wide gate policy](WIDE_GATE_SOUNDNESS.md).

The proof, proximity radii, and concrete security accounting are in the
paper's Section H.2, “Integrity Parameters.” This page maps that policy to
the executable checks.

## Parameters

| Setting | Laned gates | Transcript packing |
| --- | --- | --- |
| Challenge field | `Fpk = F_{65537^8}` | `Fq2 = F_{Q^2}`, `Q = 1,053,858,393,162,252,289` |
| Code rate | 1/8 | 1/8 |
| Query paths | 150 | 150 |
| Maximum message rows per RS table | `2^13` | `2^34` |
| Maximum folds covered by the policy | 34 | 34 |

[`soundness.hpp`](../include/laminate/basefold/soundness.hpp) computes the
conservative integer bit bounds and rejects unsupported rates, dimensions,
and query counts. Setup checks every gate shard, packing witness, and
factored tensor against these limits. Diagnostic profiles make no target
integrity claim.

## Implementation and scope

Each opening uses one folding transcript. Query indices are sampled together
in one verifier challenge block, independently with replacement. Merkle
multiproof deduplication does not change these draws. The verifier checks
canonical openings and the transparent operands required by the PCS interface.

Laned affine claims form one logical gate batch, implemented as one opening
per committed table. The batch's RBR error is the maximum conditional
transition error across its openings; it does not assume a shared FRI
transcript across all tables. Laned's public gate columns are honestly
preprocessed RS codewords. Its equality-weight column batching relies on
that premise and is not a proximity claim for arbitrary malicious columns.
The packing witness is prover-chosen and uses the full proximity argument.

The selected policy bounds each folding transition by `511/|F|` and the
terminal query block by `2^-112`. Gate column/operand batching contributes
`(ceil(log2(width))+1)/|Fpk|`. The integer checks use the paper's unique-decoding
argument, without a list-decoding conjecture or a per-query security heuristic.

Section G.5, “Soundness of the Compiled Protocol,” composes these local bounds
with authentication, prefix-consistent extraction, and Fiat–Shamir. Section
H.2, “Integrity Parameters,” gives the resulting conditional `2^-50` bound
for the benchmark parameters; [Status](STATUS.md#parameters-and-security-assumptions)
summarizes its assumptions and budgets. The witness decoder in that analysis
belongs to the security reduction, not the online verifier.

Public dimension limits for the surrounding reductions are enforced in
[`challenge_limits.hpp`](../include/laminate/gkr/challenge_limits.hpp).
Packed transcript ordering and deferred GKR arithmetic are described in
[Protocols](PROTOCOLS.md#one-fiatshamir-transcript-for-the-packed-protocols).

## Source and tests

| Responsibility | Source |
| --- | --- |
| Selected integer security policy | [`soundness.hpp`](../include/laminate/basefold/soundness.hpp) |
| PCS API and module map | [`basefold.hpp`](../include/laminate/basefold/basefold.hpp), [module guide](../include/laminate/basefold/README.md) |
| Packing witness openings and canonical proof decoding | [`basefold_pcs.cpp`](../src/spartan/basefold_pcs.cpp) |
| Merkle authentication and challenge sampling | [`merkle.cpp`](../src/basefold/merkle.cpp), [`transcript.cpp`](../src/transcript/transcript.cpp) |
| Policy limits and integer bounds | [`test_basefold_soundness.cpp`](../tests/basefold/test_basefold_soundness.cpp) |
| Opening, transcript, and query behavior | [`test_basefold.cpp`](../tests/basefold/test_basefold.cpp) |
