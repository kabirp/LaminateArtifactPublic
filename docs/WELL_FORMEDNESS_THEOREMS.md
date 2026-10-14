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

`W_upper` is derived from the polynomial coefficients of the **actual encoded
signed-digit masks**, rounding each inner square root upward. It is not a norm
of the SIMD slot values. The mask calculation is in
[`operator.hpp`](../include/laminate/packing/analysis/operator.hpp);
Section F.4.1, “Coefficient proof of the packing bound,” gives the justification.
Capacity calculations use the same strict comparisons as admission.

Resident and external setup validate the runtime field, geometry, detection
premise, and encoder-derived mask weights before constructing preprocessing.
Diagnostic commitment policies and nonselected repetition counts do not
inherit this selected profile's security claim.

## Security and completeness boundary

Under the paper's fixed-list and modulus premises, the selected tests have
bad-accept probability at most `2^-120`. This is a pointwise guarantee for
one list fixed before the challenges, not a guarantee for adaptively chosen
lists or unaccounted retries. The sampling proof uses `2r` centered Bernoulli
summands; that convention matters for its constants.

The honest-rejection bound is conditional on every aligned ciphertext
satisfying `P`. With the selected profile it is at most `2^-100` for
`N<=2^15` (`2^-101` for `N=2^14`), plus the probability that the honest
coefficient cap fails. Setup's public inequalities do not prove that cap.
[BGV noise planning](BGV_NOISE_AND_MODULUS_SWITCHING.md) describes the
implementation's separate honest-noise assumptions and bounded checks.

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
