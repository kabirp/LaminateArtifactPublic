# Implementation scope

The Laminate artifact implements setup, encrypted payload evaluation, proving,
and verification for Base, Folded, and Laned. The benchmark runs the client and
server in separate processes, with Microsoft SEAL BGV and file-backed proving.
This is research software. [Included reports](../bench_outputs/README.md)
identify the measured configurations; CTest covers bounded execution and
resource planning.

## Capabilities

| Area | Implemented behavior |
| --- | --- |
| Payloads | Wide and B-laned DAGs compile into alternating affine and dense multiplication layers. |
| Wide evaluation | Ciphertext products, additions, rotations, and slot-varying plaintext operations. |
| Laned evaluation | B independent lanes, lane-varying plaintext addition, and uniform scalar multiplication. Rotations and nonuniform plaintext multiplication are rejected. |
| Storage | Public values stay plaintext; structural padding is virtual and repeated operands share records. Checkpoint/replay uses bounded memory and last-consumer retirement. |
| GKR | Each layer reduces to one claim. Structural multiplication wiring needs no GateMLE opening. |
| Affine GateMLE | Wide uses bounded sparse composition with local-program adjoints as fallback and generic foldable commitments. Laned uses sparse RS commitments. Setup persists the proving key. |
| Transcript packing | Folded/Laned compose alignment, well-formedness tests, digit packing, Spartan, and BaseFold openings. |
| Fiat–Shamir | GKR, gate openings, and packing share one transcript. |
| Roles | The client sends encrypted inputs and releases plaintext output only after verifying the server response. |
| Benchmarks | Reports separate reusable setup, startup, per-request computation, transport, proof bytes, and measured or modeled resources. |

The public APIs use caller-owned resource limits. Transport uses immutable
local files. Checkpoint states are consumed by a proof attempt and cannot be
resumed after interruption. See [architecture](ARCHITECTURE.md) for lifecycle
contracts and [protocols](PROTOCOLS.md) for source entry points.

## Benchmark scope

The suite covers Base and Folded on `balancedLaned` and `mulHeavyPyramid`,
and Laned on `balancedLaned` with `B=1,128,16,384`. Each target has `2^20`
payload operations, ciphertext multiplication depth 8, and ring degree
`N=16,384`. Local and FHE-only
`noIntegrity` baselines support both payloads.

[Workload definitions](BENCHMARKING.md#benchmark-workload-scope) identify the
canonical generators and explain how changing B changes the scalar workload.
The [GCP runbook](GCP_BENCHMARKS.md) specifies the reference host and execution
procedure. Setup checks memory and disk capacity before building commitments.
The [cost model](COST_MODEL.md) locates these checks and their accounting rules.

## Parameters and security assumptions

The proof-bearing and `noIntegrity` target profiles select an **80-bit classical
privacy target** under the model in [Privacy estimates](PRIVACY_ESTIMATES.md).
That guide records the exact key moduli, selected estimates, estimator revision,
and attack model. All target profiles use SEAL's `sec_level_type::none` and assess
privacy with that estimator instead of enforcing SEAL's parameter table.

For integrity, [RS BaseFold](BASEFOLD_SOUNDNESS.md) and
[Wide gate](WIDE_GATE_SOUNDNESS.md) admission check each actual opening shape
against a local arithmetic round-by-round error target of `2^-110`.
[Well-formedness admission](WELL_FORMEDNESS_THEOREMS.md) locates the integer
parameter checks. [Cryptographic primitives](../include/laminate/crypto/README.md)
identifies ciphertext commitments, transcript hashing, and PCS authentication.

For the proof-bearing benchmark parameters, Section H.2, “Integrity
Parameters,” of the paper bounds incorrect acceptance below `2^-50` under
its stated assumptions and classical adversarial budgets. These include
honest preprocessing, VCoED-compatible PCSs with prefix-consistent extraction,
independent PCS and Fiat–Shamir random oracles, and, for packed variants, the
Poseidon collision bound and packing inequalities. The work budgets include extraction and
simulation. Section G.5, “Soundness of the Compiled Protocol,” gives the
composition argument; the linked implementation guides locate its components.
Tests check implementation behavior and parameter arithmetic, not the
cryptographic assumptions.

SEAL modulus switching is deterministic. The benchmark executes a public,
setup-bound modulus schedule under the stated honest-noise model. Bounded
preflights and secret-key noise observations are diagnostics, not completeness
certificates. The
[BGV parameter guide](BGV_NOISE_AND_MODULUS_SWITCHING.md) locates fixed chains,
proof-ingress policies, and model limits.

The packed `quick` profile uses a diagnostic linear hash and reduced test and
query counts. It exercises orchestration and serialization without claiming
target integrity or privacy parameters.

## Validation

Mock tests check algebra, role transitions, codecs, resource accounting, and
rejection cases. SEAL tests add real-backend checks. Both build modes are needed
for the full test inventory, with `LAMINATE_EXTENDED_TESTS=ON` for additional
component coverage. CTest does not run the target campaign.

Follow the [artifact guide](ARTIFACT_GUIDE.md) for the review sequence and the
[benchmark validation guide](BENCHMARK_VALIDATION.md) for completed-run checks.
