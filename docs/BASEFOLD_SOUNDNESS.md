# Reed–Solomon BaseFold policy

Laned GateMLE and transcript-packing openings use rate-1/8 Reed–Solomon
BaseFold with 150 independently sampled query paths per opening batch.
The local interactive PCS round-by-round (RBR) target is `2^-110`, conditional
on good setup. Base/Folded Wide gates use a different code hierarchy and the
[Wide gate policy](WIDE_GATE_SOUNDNESS.md).

The paper's Section H.2, “Integrity Parameters,” gives the folding argument
and end-to-end security accounting. This page supplies the numerical
proximity-gap and query calculations and maps them to executable checks.

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

## Proximity-gap parameter checks

The folding argument needs `K = 512` distinct good challenges to force their
decoded polynomials onto one affine line. At rate `1/8`, use the conservative
relative-distance bound `d = 7/8` and radii

$$
\delta_j=\frac{223}{512}\left(\frac{511}{512}\right)^j,
\qquad 0\leq j\leq L\leq34.
$$

For code lengths `n >= 512`, apply Theorem 1.3 and the collinearity argument
in Section 2.3 of [On Proximity Gaps of Reed–Solomon Codes, November 2025
full version](https://eprint.iacr.org/2025/2055) ([author-hosted
PDF](https://www.math.toronto.edu/swastik/rs-proximity-gaps-2025.pdf)).
Its radius conditions are `d/3 <= gamma <= d/2 - 1/n`. At the largest selected
radius, `gamma = 223/512`, the sufficient number of good challenges is

$$
\frac{d/\gamma-1}{d-2\gamma}
=\frac{57600}{223}<512.
$$

The upper radius condition reduces to `1/n <= 1/512`, hence the cutoff
`n >= 512`. The exact-arithmetic check below verifies both radius conditions
and the challenge threshold at every selected radius and supported code
length. Smaller radii need no larger challenge threshold here.

The remaining encoded lengths are `8, 16, 32, 64, 128, 256`.
For them, `K > n` and every selected radius is below `7/16`. Thus
[Proximity Gaps for Reed–Solomon Codes, Theorem 4.1](https://eccc.weizmann.ac.il/report/2020/083/download)
gives the required collinearity within the unique-decoding radius.
Together, the two cases cover every child code of every supported RS table.

The common-agreement step in the paper uses
`K * delta_j / (K - 1) = delta_(j-1)`. Therefore a bad folding state can
become good at at most `K - 1 = 511` challenge values. The local folding
error is at most `511/|F|`, conservatively rounded to `512/|F|` in the paper
and the integer policy. In the two challenge fields,

$$
65537^8>2^{128},\qquad Q^2>2^{119},
$$

so the rounded folding bounds are below `2^-119` and `2^-110`, respectively.
The field orders, rates, and query counts are taken from
[`params.hpp`](../include/laminate/params.hpp) by the certificate.

## Terminal query certificate

After fixing the folding commitments, the verifier draws all query paths
independently with replacement. The terminal query block has error at most
`(1 - delta_L)^150`. The smallest radius occurs at `L = 34`, and exact
rational arithmetic gives

$$
1-\frac{223}{512}\left(\frac{511}{512}\right)^{34}
<\frac{19}{32},\qquad
\left(\frac{19}{32}\right)^{150}<2^{-112}.
$$

Thus 150 paths give terminal error below `2^-112` at every supported size.
The integer policy rounds query errors using
`(19/32)^2 < 2^-1`, `(19/32)^3 < 2^-2`, and `(19/32)^4 < 2^-3`.
For 150 queries this yields `37 * 3 + 1 = 112` bits. The local RBR bound is
the maximum of the folding, query, and applicable batching errors, as
explained below.

Run the certificate from the repository root:

```bash
python3 tests/basefold/check_rs_query_certificate.py
```

It checks the theorem's numerical hypotheses, the shrinking-radius identity,
and the query and field inequalities with exact integers and fractions.
It covers message logs `0..34`, including the small-code case, and confirms
that the named parameters in `params.hpp` match this certificate. The
existing [`test_basefold_soundness`](../tests/basefold/test_basefold_soundness.cpp)
checks the compiled policy's bit bounds and rejection of unsupported shapes.
These checks verify the substitutions used by the paper's proof, not the
proximity-gap theorems themselves.

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
| Exact proximity-gap and terminal-query calculations | [`check_rs_query_certificate.py`](../tests/basefold/check_rs_query_certificate.py) |
| Opening, transcript, and query behavior | [`test_basefold.cpp`](../tests/basefold/test_basefold.cpp) |
