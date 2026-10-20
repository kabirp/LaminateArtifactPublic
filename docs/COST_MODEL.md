# Executable cost model

The model derives operation counts, RNS-level work, resource estimates, and
proof-byte bounds from a compiled layered circuit. It does not require an
encrypted trace or FHE context and does not admit cryptographic parameters.
Measured runtime and memory come from a completed benchmark;
[Benchmarking](BENCHMARKING.md) defines those measurement boundaries.

The paper gives prover complexity in Section 5.2.1 for Base/Folded and
Section E.4 for Laned, both titled “Prover Complexity.” Section F.1.3,
“Packing Layout and Cost,” gives packing costs. For exact implementation
recurrences and counter definitions, use the code below.

## Source map

| Responsibility | Source |
| --- | --- |
| Logical operation-count API | [`schedule_cost.hpp`](../include/laminate/bench/schedule_cost.hpp) |
| Base layer recurrences | [`base_schedule_cost.cpp`](../src/bench/base_schedule_cost.cpp) |
| Folded/Laned recurrences and primitive expansion | [`schedule_cost.cpp`](../src/bench/schedule_cost.cpp) |
| RNS, runtime-calibration, and byte API | [`target_cost.hpp`](../include/laminate/bench/target_cost.hpp) |
| Concrete resource and wire accounting | [`target_cost.cpp`](../src/bench/target_cost.cpp) |
| Gate shapes and public-field work | [GateMLE guide](GATE_MLE_PERFORMANCE.md) |
| Small closed forms and executed-prover comparisons | [`test_schedule_cost.cpp`](../tests/cost_model/test_schedule_cost.cpp) |

## Interpreting operation counts

The logical model counts the complete Base/Folded/Laned proving schedule,
including witness packing, round encoding, terminal openings, and extension
arithmetic. It excludes plaintext `local` and proof-free `noIntegrity`
baselines. Counters distinguish weighted base terms, base-field arithmetic,
extension arithmetic, preparation of challenge-dependent masks, and logical
round/terminal counts. Descriptive subsets are already included in totals;
they must not be added again.

Round and terminal counts are exact. Primitive counts generally bound
execution from above: known public zero and structural padding require no
ciphertext operations, and encrypted extension values retain per-coordinate
public/encrypted tags. Private extension encryption remains dense. The
`R=8` expansion in `concrete_primitive_upper_bound(...)` is a conservative
dense bound; support-aware execution can use fewer products, switches, and
bytes. The subtraction bucket contains direct base subtractions only;
extension subtractions remain a separate logical counter.

Multiplication recurrences use live prefix and alias geometry rather than
padded width alone. Affine work uses compiled sparse coefficients. Only
affine layers require GateMLE openings, whose public-field work is separate
from ciphertext-operation counters.

## RNS ledger and runtime calibration

Payload checkpoints retain natural evaluation levels. A separate proof-source
artifact normalizes each stored live ciphertext once to the approved ingress
level. Rewinds reuse that artifact. The RNS ledger separates payload switches,
proof-ingress switches, and proof-message normalization, avoiding repeated
charges for reader scans. Public zero has no switch event.

The process benchmarks derive a per-layer schedule during setup. The standalone
formula executable instead accepts uniform `--core-rns-limbs`; it does not
consume a setup record or derive natural payload levels, and therefore reports
proof-ingress work as unavailable. Its inputs are formula parameters, not a
noise-completeness certificate. See [BGV noise planning](BGV_NOISE_AND_MODULUS_SWITCHING.md)
for the fixed benchmark schedules.

Runtime estimates require caller-supplied `TargetRuntimeCalibration` prices
for the intended hardware, RNS levels, and plaintext-preparation policy. There
are no built-in timing prices. Preparation of challenge-dependent SIMD masks
must be priced separately from FHE multiplication; reusable fixed masks belong
to setup. End-to-end server time also includes payload evaluation, I/O, proof
construction, and serialization.

## Checkpoint and resource accounting

The library default minimizes retained checkpoint bytes subject to a replay
cap. Process benchmarks minimize replay work within the admitted disk/RAM
envelope; target setup requires zero replay. The selected plan and resource
limits are setup-bound.

Capacity accounting includes persistent keys, live checkpoints and sources,
phase-local builder/sort scratch, concurrently waiting client state, and host
reserves. It charges peak simultaneously live storage, not all files ever
created. Record-read counters are I/O costs, not additional FHE operations.
The exact policies are in
[`host_resource_budget.hpp`](../include/laminate/bench/host_resource_budget.hpp),
[`packed_checkpoint_replay.hpp`](../include/laminate/bench/packed_checkpoint_replay.hpp),
and [`plan.hpp`](../include/laminate/payload/checkpoint/plan.hpp).

## Proof-byte boundaries

Encoded proofs have exact component accounting. Formula-only packed projections
use setup-derived maxima for variable-length BaseFold multiproofs, whose
actual sizes depend on query collisions and shared Merkle nodes.

Base distinguishes the generic proof, process response encoding, output
statement, and combined response. Folded/Laned distinguish committed GKR,
well-formedness reveals, digit ciphertexts, Spartan, factored matrix proofs,
and BaseFold openings. Aligned ciphertexts remain private witness data.
Reusable setup commitments and the reconstructed logical public vector are
not transported again as part of each proof.

## Packing work and memory

For Folded and Laned, `r_logical` counts ordinary BhIP rounds
(`logical_rounds` in [`ScheduleOperations`](../include/laminate/bench/schedule_cost.hpp)).
Each layer reduction also contributes one terminal exchange, counted by
`terminal_messages`. Both ordinary rounds and terminal exchanges produce one
aligned ciphertext, so packing uses
`r = logical_rounds + terminal_messages = aligned_round_ciphertexts`.
The counting rule is implemented by `add_round_encoding(...)` in
[`schedule_cost.cpp`](../src/bench/schedule_cost.cpp).

Reports separate Spartan geometry, factored tensor geometry, public-input
work, PCS commitments/openings, and their resource bounds. The public vector
has a linear read/binding cost; factored verification is not purely
polylogarithmic. The selected relation and code map are in
[Transcript packing](TRANSCRIPT_PACKING.md).

Assignment artifacts store canonical live witness runs. Matrix products,
WiringCheck, and witness PCS operations consume artifact-backed sources;
structural padding does not require a resident expanded assignment. Resource
estimates include persistent sources, simultaneously live files, and bounded
scratch/opening buffers. They exclude allocator and container overhead unless
explicitly measured, so modeled memory is not whole-process peak RSS.

`laminate_hybrid_tensor_bench` measures compact full-target algebra and a
`2^20` tensor proof. Its projections classify encoded work units, committed
field reads, and proof-byte inputs explicitly. Those projections are not a
measurement of an entire target protocol run.

## Generate a formula report

After building the benchmark targets using the [README](../README.md), run:

```sh
build/benches/laminate_target_cost_report --protocol base \
  --slots 16384 --depth 8 --width 61681
build/benches/laminate_target_cost_report --protocol folded \
  --slots 16384 --depth 8 --width 61681
build/benches/laminate_target_cost_report --protocol laned \
  --slots 16384 --lanes 128 --depth 8 --width 61681
```

These commands model the Diamond workload. They do not generate
`target-mulHeavyPyramid`. Defaults use three uniform proof limbs for Base,
six for either packed variant, and 60 bits per limb; these differ from the
process benchmark's exact per-layer chains. The output reports counts and
bytes, not calibrated runtime or parameter admission.

Mock tests compare counters with executed provers across varied geometries.
Opt-in SEAL tests check primitive buckets at actual RNS levels and encoded
proof bytes. Target measurements use the [GCP runbook](GCP_BENCHMARKS.md).
