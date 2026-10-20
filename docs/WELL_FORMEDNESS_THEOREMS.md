# Well-formedness admission

Folded and Laned use 120 centered-ternary tests for the ordered list of
aligned ciphertexts. The code calls this distribution *lazy ternary*:
each coefficient is the difference of two independent fair bits. The
ciphertext list is committed before those bits are sampled.

The definitions and proofs are in Section F.3, “Well-Formedness Tests,” and
Section F.4, “Proofs of the Well-Formedness Guarantees.” This page records
the executable admission boundary; [Transcript packing](TRANSCRIPT_PACKING.md)
maps the surrounding protocol.

## Selected profile

| Quantity | Value |
| --- | --- |
| Test count `T` | 120 |
| Threshold constant `c` | `37/4` |
| Canonical-error cap `beta_e` | 17,781 |
| Honest partial-decryption cap `P` | `t*beta_e + (t-1)/2`, with `t=65,537` |
| Supported ring degree `N` | At most `2^15` |
| Supported aligned-message count `r` | At most `2^20` |
| Client threshold | `floor((37/4)*P*sqrt(r))` |

Aligned ciphertexts have correction factor one at the single packing modulus
`Q`. Client threshold comparisons use centered partial-decryption coefficients,
not ciphertext components, slot values, or SEAL invariant-noise-budget bits.
Both original challenge bits are retained and constrained in the packing
relation, including the two encodings of ternary zero.

## Exact setup checks

[`well_formedness.cpp`](../src/packing/evaluation/well_formedness.cpp) computes
thresholds and admission with checked integer arithmetic. Let
`s=ceil(sqrt(r))`. The selected profile requires

```text
333*P*r <= 2*Q
111*P*s*W_upper < Q
```

`W_upper` bounds the paper's $W_{\Sigma}$ using the polynomial coefficients
of the **actual encoded signed-digit masks**. Each coefficient-offset norm
is rounded upward before summing, and the largest sum across outputs and
digits gives the integer upper bound. It is not a norm of the SIMD slot
values. The mask calculation is in
[`operator.hpp`](../include/laminate/packing/analysis/operator.hpp);
Section F.4.1, “Coefficient proof of the packing bound,” gives the justification.
Capacity calculations use the same strict comparisons as admission.

Resident and external setup validate the runtime field, geometry, detection
premise, and encoder-derived mask weights before constructing preprocessing.
Diagnostic commitment policies and nonselected repetition counts do not
inherit this selected profile's security claim.

## Evaluated workload checks

For the evaluated Folded and Laned workloads, the final modulus is
`Q=1,053,858,393,162,252,289`, and the selected honest-noise cap gives

```text
P = 65,537*17,781 + (65,537-1)/2 = 1,165,346,165.
```

The committed summaries give the following aligned-message counts. Each
sumcheck round and each layer's terminal message contributes one aligned
ciphertext, as enforced by the
[setup code](../src/protocol/packed/setup.cpp). Each round's extension-field
values are packed into one message before alignment.

| Evaluated workload | Sumcheck rounds | Terminal messages | Aligned messages `r` |
| --- | ---: | ---: | ---: |
| [Folded balancedLaned](../bench_outputs/folded-balancedLaned-summary.md) | 500 | 17 | 517 |
| [Folded mulHeavyPyramid](../bench_outputs/folded-mulHeavy-summary.md) | 492 | 17 | 509 |
| [Laned balancedLaned, B=1](../bench_outputs/laned-b1-balancedLaned-summary.md) | 270 | 17 | 287 |
| [Laned balancedLaned, B=128](../bench_outputs/laned-b128-balancedLaned-summary.md) | 382 | 17 | 399 |
| [Laned balancedLaned, B=N](../bench_outputs/laned-b16384-balancedLaned-summary.md) | 500 | 17 | 517 |

The published conservative envelope is `r<=517` and
`W_Sigma<=W_upper=114,670`. The existing
[selected-profile capacity test](../tests/packing/evaluation/test_well_formedness.cpp)
uses these bounds. The summaries independently support the message counts,
but do not contain the encoded masks needed to recompute `W_upper`.
Each setup checks its own encoder-derived mask weights using the admission
procedure above.

With `c=37/4`, the paper's premises are `Q>=18*c*P*r` and
`6*c*P*sqrt(r)*W_Sigma<Q/2`. Both are monotone in the workload bounds.
At the published envelope, `ceil(sqrt(517))=23`, and the stronger integer
checks used by the implementation give

```text
333*P*517           =     200,627,161,112,565 <= 2,107,716,786,324,504,578 = 2*Q
111*P*23*114,670    = 341,158,014,822,624,150 <  1,053,858,393,162,252,289 = Q.
```

Thus one 60-bit final modulus satisfies both premises throughout this
envelope. These are admission checks conditional on the stated honest-noise
cap. They do not estimate the probability that honest noise exceeds the cap.

Run the exact-arithmetic certificate from the repository root:

```sh
python3 tests/packing/check_evaluated_well_formedness.py
```

The certificate reads the selected constants from `params.hpp`, checks the
envelope against the C++ capacity-test fixture, and reconstructs each `r`
from the summary's sumcheck spans and terminal-message count. It also checks
the independently reported commitment bytes against `r` Poseidon digests.
It verifies the two inequalities with integers.

To recompute the mask weights from the implemented placement and SEAL's
plaintext encoder, run the
[packing capacity report](../benches/packing/packing_capacity_report.cpp)
from a [SEAL build](../README.md#build-and-run-a-small-proof):

```sh
build-seal/benches/laminate_packing_capacity_report
```

Rows with `protocol_selected=1` use four radix-17 digits. The output gives
the mask bound `W_upper`, integer threshold `tau`, and admission result
`aggregate_pass` for message counts 287, 399, and 517. The 517-message mask
bound also covers the 509-message pyramid, which uses a prefix of the same
coset placement. As in setup, admission assumes the stated honest-noise cap.

## Security and completeness boundary

Under the paper's fixed-list and modulus premises, the selected tests have
bad-accept probability at most `2^-120`. This is a pointwise guarantee for
one list fixed before the challenges, not a guarantee for adaptively chosen
lists or unaccounted retries. The sampling proof uses `2r` centered Bernoulli
summands; that convention matters for its constants.

When every aligned ciphertext satisfies the cap `P`, the probability that
the tests reject an honest transcript is at most `2^-100` for `N<=2^15`
(`2^-101` for `N=2^14`). The overall completeness bound also includes
`delta_noise`, the probability that an honest aligned ciphertext exceeds
this cap. Passing the public setup inequalities does not bound that
probability, nor do the SEAL tests used to choose the benchmark chains.
[BGV noise planning](BGV_NOISE_AND_MODULUS_SWITCHING.md) explains how the
chains and switching schedules leave room for the payload, GKR, and packing
computations, and how the remaining noise margin is tested.

Full composition also requires the paper's commitment, extraction, Spartan,
PCS, and Fiat–Shamir assumptions. The verifier checks the public packing proof
and revealed partial decryptions before using recovered messages in GKR.
The fixed-list test alone is not a complete noninteractive security claim.

## Source and tests

| Responsibility | Source |
| --- | --- |
| Thresholds, certificates, and capacity | [`well_formedness.hpp`](../include/laminate/packing/evaluation/well_formedness.hpp), [`well_formedness.cpp`](../src/packing/evaluation/well_formedness.cpp) |
| Selected constants | [`params.hpp`](../include/laminate/params.hpp) |
| Mask weights | [`operator.hpp`](../include/laminate/packing/analysis/operator.hpp) |
| Resident and external admission | [`setup.cpp`](../src/protocol/packed/setup.cpp), [`external/preprocessing.cpp`](../src/protocol/packed/external/preprocessing.cpp) |
| Honest-noise integration | [`packing_prerequisites.hpp`](../include/laminate/protocol/analysis/packing_prerequisites.hpp) |
| Integer and geometry checks | [`test_well_formedness.cpp`](../tests/packing/evaluation/test_well_formedness.cpp), [`test_transcript_packing_external_preprocessing.cpp`](../tests/protocol/test_transcript_packing_external_preprocessing.cpp) |
| Evaluated message counts and parameter arithmetic | [`check_evaluated_well_formedness.py`](../tests/packing/check_evaluated_well_formedness.py) |
