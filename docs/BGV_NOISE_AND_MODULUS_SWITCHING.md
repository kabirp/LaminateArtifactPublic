# BGV parameters and noise planning

Laminate uses fixed, public, setup-bound modulus schedules. The server executes
the selected schedule without inspecting secret-key noise, choosing levels
from ciphertext contents, or retrying with another key or parameter set.

The paper defines BGV decryption and canonical error in Section 4.2.2,
“Encryption, Decryption, and Homomorphic Operations,” and Section 4.2.3,
“Noise Budget and Efficiency.” This page records the implementation's
profiles, execution boundaries, and validation limits.

## Target profiles

All target payloads have depth eight, ring degree `N=16,384`, and plaintext
modulus `t=65,537`. Base, Folded, and Laned use SEAL's `sec_level_type::none`;
this disables SEAL's standard parameter-table check and is not a security
claim. The selected classical privacy target is at least 80 bits under the
attack model in [Privacy estimates](PRIVACY_ESTIMATES.md).

Exact data/key products, primes, and attack estimates are recorded in
[Privacy estimates](PRIVACY_ESTIMATES.md). The executable definitions are the
[Base profile](../benches/protocol/base_checkpoint_benchmark.cpp),
[packed profile](../include/laminate/bench/packed_process_profile.hpp), and
[Folded pyramid constants](../include/laminate/bench/folded_pyramid_parameters.hpp).
Setup persists the actual prime chain for each run. The `noIntegrity` balanced
target enforces SEAL's `tc128` category; its pyramid target uses the 80-bit
privacy target, with a selected estimate of 98.9 bits. Both use nine data limbs
and return one 60-bit output limb. Their exact chains and output-noise check
are in [`no_integrity_parameters.hpp`](../include/laminate/bench/no_integrity_parameters.hpp).
The `local` baseline has no encryption.

## Chain and schedule contract

Data primes are ordered bottom to top as `q0,...,qL`; a switch removes the
last active prime. The separate special prime is never counted as a data
limb. The bottom prime is `q0=Q=1,053,858,393,162,252,289`, required by
Folded/Laned transcript packing. Droppable primes satisfy
`qi = 1 mod lcm(2N,t)`, preserving correction factor one.

The public schedule binds the circuit, input envelope, exact primes,
operation calibration, switch-event bound, rounding allowance, and proof
source levels. Payload drops occur only after a ciphertext multiplication
layer is complete and relinearized. The server re-derives the schedule and
validates its digest before evaluation.

Natural payload sources and normalized proof sources are separate artifacts.
Proof normalization operates on copies so it preserves the levels needed
by subsequent payload evaluation or checkpoint replay. Every reduction reads
its exact setup-selected source level on every scan; it does not switch inside
a sumcheck. Structural public zero has no ciphertext or switch event.

The schedule propagates bounds along actual wire dependencies, including
affine intermediates and forwarded values. Its multiplication debit is
calibrated, not a worst-case cryptographic bound. SEAL performs deterministic
modulus switching; applying the schedule's randomized-rounding tail model
to honestly generated inputs is an engineering heuristic. It is not a theorem
for adversarial ciphertexts or a completeness guarantee for all honest keys.
The integer allowance calculation and validation are in
[`honest_noise_schedule.cpp`](../src/payload/noise/honest_noise_schedule.cpp).

## Proof boundaries

| Variant | Affine proof-source limbs | Multiplication proof-source limbs | Policy |
| --- | ---: | ---: | --- |
| Base | 3 | 3 | `UniformBaseProofIngress/v1` |
| Folded balancedLaned | 3 | 6 | `ConservativePackedProofIngress/v1` |
| Folded mulHeavyPyramid | 4 | 6 | `ConservativePackedProofIngress/v4` |
| Laned, `B<N` | 4 | 7 | `ConservativePackedProofIngress/v3` |
| Laned, `B=N` | 4 | 6 | `ConservativePackedProofIngress/v3` |

The complete vectors are derived from public topology and bound by setup;
these are fixed profile policies, not runtime tuning inputs. Laned with
`B=N` omits the witness-packing mask/drop. Both Laned configurations retain
the transcript-packing reserve.

Ordered drops control inherited payload error before subsequent encrypted
proof operations; total modulus bit length alone does not specify that margin.

Folded/Laned aligned proof ciphertexts and final outputs are normalized to
the single packing prime `Q`. The honest-run engineering target at that
boundary is canonical-error magnitude below `2^10`; the algebraic packing
cap is `beta_e=17,781`. Neither is a count of remaining SEAL noise-budget
bits. The packing inequalities and threshold checks are documented in
[Well-formedness admission](WELL_FORMEDNESS_THEOREMS.md).

## Setup preflights and acceptance

Base mulHeavyPyramid checks target dependency cones with disposable SEAL
keys. Folded mulHeavyPyramid checks a fixed target ancestry with the actual
setup key, through payload evaluation, encrypted GKR, alignment, message
bounds, 120 packing reveals, and recovered GKR verification. It also stresses
pre-alignment amplification. The outer Spartan proof is excluded; the eventual
client request uses fresh encryption randomness. The concrete checks are in
[`target_noise_preflight.hpp`](../benches/support/target_noise_preflight.hpp) and
[`folded_target_noise_preflight.hpp`](../benches/support/folded_target_noise_preflight.hpp).

Any preflight rejection aborts setup without key resampling or a fallback
schedule. These bounded checks supplement the model; they do not cover every
source, a full-width proof, or the honest-noise tail. A target result still
requires the full client's protocol verification and the benchmark's final
acceptance checks. Quick profiles exercise reduced geometry and do not
establish target completeness.

## Diagnostics and source map

The schedule uses exact integer phase bounds for admission. The deterministic
analyzer is a separate conservative model with worst-case rounding terms.
Secret-key-assisted SEAL diagnostics measure sampled behavior; they neither
select the online schedule nor certify its tail assumptions. A cost-model
report counts operations and storage but cannot admit a modulus chain.

| Responsibility | Source |
| --- | --- |
| Packed proof-source policy | [`proof_ingress.hpp`](../include/laminate/protocol/packed/setup/proof_ingress.hpp) |
| Public honest-noise schedule | [`honest_noise_schedule.hpp`](../include/laminate/payload/noise/honest_noise_schedule.hpp), [`honest_noise_schedule.cpp`](../src/payload/noise/honest_noise_schedule.cpp) |
| Executable payload plan | [`fhe_evaluation_plan.hpp`](../include/laminate/payload/evaluation/fhe_evaluation_plan.hpp) |
| Deterministic bounds and switch policy | [`deterministic.hpp`](../include/laminate/fhe/noise/deterministic.hpp), [`modulus_switch_policy.hpp`](../include/laminate/fhe/noise/modulus_switch_policy.hpp) |
| Full-protocol prefix analysis | [`noise_completeness.hpp`](../include/laminate/protocol/analysis/noise_completeness.hpp) |
| Packed finalization checks | [`deterministic_completeness.hpp`](../include/laminate/packing/analysis/deterministic_completeness.hpp) |
| Folded setup-key preflight | [`folded_target_noise_preflight.hpp`](../benches/support/folded_target_noise_preflight.hpp) |
| SEAL calibration tool | [`seal_honest_noise_calibration.cpp`](../benches/reports/seal_honest_noise_calibration.cpp) |

Use the [build and test instructions](../README.md) and
[GCP runbook](GCP_BENCHMARKS.md) for execution.
[Benchmarking](BENCHMARKING.md) defines the report and measurement boundaries.
