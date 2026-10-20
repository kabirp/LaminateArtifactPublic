# BGV parameters and noise planning

The benchmark parameters balance the cost of ciphertext arithmetic against the
noise budget needed to finish the computation. More RNS limbs make arithmetic
more expensive. Too little noise budget can cause an honest run to fail. We
therefore tried different prime sizes and limb counts in SEAL, choosing chains
that left some spare noise budget after the relevant computations. This matters
especially for `noIntegrity`: an unnecessarily large baseline chain would make
Laminate's relative overhead look artificially small.

All four encrypted variants follow the same simple rule for payload evaluation:
relinearize and modulus-switch after each ciphertext-ciphertext multiplication
layer. Using the same rule makes the comparison easier to interpret and avoids
optimizing switching times for one variant but not another. We tune prime sizes
and limb counts within this shared rule. A broader search over switching times
could reduce the costs further.

The remaining computation determines how much budget a ciphertext needs.
`noIntegrity` needs enough for the payload and output decryption. Base also
needs to decrypt its GKR messages correctly. Folded and Laned must additionally
meet the noise limits for well-formedness and transcript packing. Their schedules
must account for both the noise inherited from the payload and the subsequent
encrypted proof operations.

The paper introduces BGV noise in Section 4.2.3, “Noise Budget and Efficiency,”
and describes the benchmarks in Section 7.1, “Methodology.” The details below
explain the parameter choices and how the implementation checks them.

## Coefficient and NTT forms

SIMD encoding uses a plaintext transform modulo `t`. Ciphertext arithmetic
uses separate NTTs, one for each active RNS prime. Coefficient form lists a
polynomial's coefficients, while NTT form lists its evaluations at that
prime's transform points. Ring products in ciphertext-ciphertext and
plaintext-ciphertext multiplication are pointwise in NTT form.

A scalar `c`, replicated across every SIMD slot, encodes as the constant
polynomial `c`. Its NTT coordinates all equal the corresponding RNS lift of
`c`, so scalar multiplication needs no nontrivial transform. The
[SEAL plaintext arithmetic](../src/fhe/seal/plaintext_basis.cpp) implements
this case directly, without allocating a slot-sized plaintext vector.

A reusable nonuniform plaintext has a coefficient encoding modulo `t` that
is independent of the ciphertext level. Before multiplication, its
coefficients must be lifted and transformed for the active RNS primes.
Modulus switching changes those primes, so cached NTT representations are
specific to a level. The same SEAL module offers both a prepared basis for
one level and a generic cache that starts from one coefficient encoding and
prepares an NTT representation for every data level. Subsequent
multiplications select the representation matching the ciphertext's level.

## Target profiles

All target payloads have depth eight, ring degree `N=16,384`, and plaintext
modulus `t=65,537`. Base, Folded, Laned, and `noIntegrity` use SEAL's
`sec_level_type::none`.
This disables SEAL's standard parameter-table check and is not a security
claim. The selected classical privacy target is at least 80 bits under the
attack model in [Privacy estimates](PRIVACY_ESTIMATES.md).

Exact data/key products, primes, and attack estimates are recorded in
[Privacy estimates](PRIVACY_ESTIMATES.md). The executable definitions are the
[Base profile](../benches/protocol/base_checkpoint_benchmark.cpp),
[packed profile](../include/laminate/bench/packed_process_profile.hpp), and
[Folded pyramid constants](../include/laminate/bench/folded_pyramid_parameters.hpp).
Setup persists the actual prime chain for each run. The `noIntegrity` targets
use 379 data bits and 434 key bits for balancedLaned, and 398 data bits and
453 key bits for mulHeavyPyramid. Their selected privacy estimates are 127.2
and 121.6 bits, respectively. Both use nine data limbs and return one 60-bit
output limb. Their exact chains and output-noise check
are in [`no_integrity_parameters.hpp`](../include/laminate/bench/no_integrity_parameters.hpp).
The `local` baseline has no encryption.

### Smaller noIntegrity candidates

We tested smaller `noIntegrity` chains to avoid inflating the baseline's cost
through an unnecessarily large modulus. The trials below include candidates
that produced incorrect plaintexts, as well as the current presets that
passed the local checks. Data bits count the exact initial ciphertext-modulus
product. Key bits also include the special key-switching prime. The
[trial summary](nointegrity-parameter-trials.json) gives the exact ordered
primes, sampling coverage, and observed failures.

| Workload | Data bits | Key bits | Local result |
| --- | ---: | ---: | --- |
| balancedLaned | 352 | 412 | Rejected: the first key passed both selected roots, but the second key failed at its first root. |
| balancedLaned | **379** | 434 | Current preset: all three independent keys passed both selected roots. |
| mulHeavyPyramid | 396 | 451 | Rejected: the first key failed at the first selected root. |
| mulHeavyPyramid | **398** | 453 | Current preset: all three independent keys passed all eight selected roots. |

Both rejected chains exhausted the noise budget and decrypted incorrectly at
the last ciphertext multiplication, before its modulus switch. These failures
would rule out the candidates even without the 15-bit reserve required by the
tests. Each rejected campaign stopped at its first failure, and the failed
samples were kept for replay.

The probes used SEAL 4.1.2 on macOS arm64 with portable kernels, the target
ring degree and plaintext modulus, and full-depth subcircuits from the target
workloads. All candidates had nine data limbs and a modulus switch after each
ciphertext-ciphertext multiplication layer. Every checked ciphertext was
compared with the clear computation across all slots, before and after
switching. For each successful root, a sum of correlated copies stressed the
target's final addition count: 65,536 terms for balancedLaned and 3,766 for
mulHeavyPyramid. The current chains retained at least 19 and 23 noise-budget
bits in these sums, respectively, above the 15-bit requirement.

These trials provide evidence for choosing the baseline parameters according
to decryption requirements, and show that smaller alternatives were tried.
They do not establish a minimum modulus or optimal runtime. Prime allocation,
ordering, and the special prime also affect noise, and fewer total bits with
the same number of limbs need not reduce the measured cost. The probes cover
selected subcircuits and correlated sums.

The full-target runs with these chains also passed the runbook's acceptance
checks on the GCP benchmark machines with SEAL's Intel HEXL backend. The client
fully decrypted each output, with final noise budgets of 19 bits for
balancedLaned and 24 bits for mulHeavyPyramid. The
[balancedLaned report](../bench_outputs/noIntegrity-balancedLaned-summary.md)
and [mulHeavyPyramid report](../bench_outputs/noIntegrity-mulHeavy-summary.md)
give server wall times of 1.61 and 5.49 hours, respectively. Each timing is from
one execution. These successful runs do not bound the probability of a noise
failure under another key or encryption sample.

Following the runbook uses the parameters compiled from its source revision.
Using these presets requires the updated source, a rebuild, and a fresh setup.

## Modulus-switching schedules

Setup fixes the exact primes, the switches during payload evaluation, and the
limb counts used by each GKR reduction. The server checks this schedule before
executing it. It does not inspect secret-key noise or adjust the schedule to the
ciphertexts it receives.

After payload evaluation is complete, GKR uses copies of the saved
intermediate ciphertexts, modulus-switched to the level required by each
reduction. A reduction uses that fixed source level throughout its sumcheck.

The Base planner estimates noise growth along the circuit's actual wire
dependencies. Its multiplication estimate comes from SEAL measurements with an
added margin, rather than the worst-case coefficient bound in the paper. The
[Base profile](../benches/protocol/base_checkpoint_benchmark.cpp) multiplies the
larger operand-error estimate by `2^36` for ciphertext multiplication followed by
relinearization. For modulus switching, it divides the inherited error by the
dropped prime and adds an estimate of rounding noise. Larger dropped primes
help until the inherited error becomes small compared with this rounding noise.

The profile permits at most ten bits of modeled noise-budget loss per payload
switch. It checks `q P' <= 2^10 P`, where `q` is the dropped prime and `P` and
`P'` are the modeled decryption-phase bounds before and after the switch.
These checks use the fixed empirical operation estimates. They do not bound
the probability of a noise failure.

The rounding estimate assumes square-root growth, as in randomized rounding.
SEAL's switches are deterministic, so using this estimate for honest ciphertexts
is a modeling assumption. The implementation evaluates this allowance with
exact integers for reproducibility. See
[`honest_noise_schedule.cpp`](../src/payload/noise/honest_noise_schedule.cpp)
for the calculation and schedule checks.

### Prime ordering

Data primes are ordered bottom to top as `q0,...,qL`. A switch removes the
last active prime. The separate special prime is not counted as a data limb.
Base, Folded, and Laned use the bottom prime
`q0=Q=1,053,858,393,162,252,289`, which Folded/Laned require for transcript
packing. The `noIntegrity` targets instead use the 60-bit output prime in
[`no_integrity_parameters.hpp`](../include/laminate/bench/no_integrity_parameters.hpp).
Droppable primes satisfy `qi = 1 mod lcm(2N,t)`, preserving correction factor one.

## Limb counts for GKR and packing

| Variant | Affine proof-source limbs | Multiplication proof-source limbs | Policy |
| --- | ---: | ---: | --- |
| Base | 3 | 3 | `UniformBaseProofIngress/v1` |
| Folded balancedLaned | 3 | 6 | `ConservativePackedProofIngress/v1` |
| Folded mulHeavyPyramid | 4 | 6 | `ConservativePackedProofIngress/v4` |
| Laned, `B<N` | 4 | 7 | `ConservativePackedProofIngress/v3` |
| Laned, `B=N` | 4 | 6 | `ConservativePackedProofIngress/v3` |

These counts are fixed by the profile and circuit during setup. They leave
room for the remaining GKR and packing operations, and were checked with SEAL
experiments. At `B=N`, Laned's witnesses are already packed, so it skips the
plaintext masking step and its modulus switch. Multiplication proof sources
therefore need six limbs rather than seven. Both Laned configurations still
reserve noise budget for transcript packing.

The packed planner works backwards through the payload circuit, keeping enough
primes for these proof sources and the later payload multiplications. The sizes
and order of the dropped primes matter too. An initial modulus bit count alone
does not describe the noise budget left for the proof.

Folded/Laned aligned proof ciphertexts and final outputs are normalized to
the single packing prime `Q`. The target for honest execution is canonical-error
magnitude below `2^10`, while the algebraic packing cap is `beta_e=17,781`.
These are error magnitudes, not counts of remaining SEAL noise-budget bits.
The packing inequalities and threshold checks are documented in
[Well-formedness admission](WELL_FORMEDNESS_THEOREMS.md).

## What the noise tests establish

Small SEAL tests check that the selected chains leave noise budget after the
operations they are meant to support. Base mulHeavyPyramid tests subcircuits
with fresh keys. Folded mulHeavyPyramid also tests a subcircuit with the
actual setup key through payload evaluation, encrypted GKR, transcript alignment,
message recovery, and well-formedness checks. It increases the message noise in
additional stress tests. These checks omit the outer Spartan proof. The concrete
tests are in
[`target_noise_preflight.hpp`](../benches/support/target_noise_preflight.hpp) and
[`folded_target_noise_preflight.hpp`](../benches/support/folded_target_noise_preflight.hpp).

A failed setup test stops the run without resampling the key or changing the
schedule. Passing it does not replace the full benchmark's client verification
and final acceptance checks. The `quick` profiles use smaller circuits and do
not establish that the target parameters suffice.

The tests and completed benchmarks demonstrate successful executions. They do
not bound the probability that another honest execution exceeds its noise cap,
the `delta_noise` term in the completeness theorem. The transcript-packing
completeness bound applies when the aligned ciphertexts satisfy that cap.
The integrity proof against a cheating server does not rely on these empirical
noise estimates. See [Well-formedness admission](WELL_FORMEDNESS_THEOREMS.md)
for the precise guarantees.

## Diagnostics and source map

The deterministic analyzer provides a separate conservative model with
worst-case rounding terms. Secret-key-assisted SEAL diagnostics measure the
noise in sampled executions. They help evaluate parameter choices before a
benchmark, but do not alter its schedule during execution or certify the
probability of an honest failure. A cost-model report counts operations and
storage without checking that a chain has enough noise budget.

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
