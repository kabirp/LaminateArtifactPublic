# Benchmark profiles and cost models

This directory defines workload profiles, resource policies, and cost formulas
used by the executable programs in [`benches/`](../../../benches/README.md).
The timing harnesses and process orchestration live in that executable tree.

## Profiles and resource admission

| Header | Purpose |
| --- | --- |
| [`no_integrity_parameters.hpp`](no_integrity_parameters.hpp) | Payload-only SEAL parameters and output-noise acceptance |
| [`payload_profile.hpp`](payload_profile.hpp) | Shared `quick`, `target-balancedLaned`, and `target-mulHeavyPyramid` workload geometry |
| [`packed_process_profile.hpp`](packed_process_profile.hpp) | Folded/Laned parameters, evidence classification, and formula-derived packing dimensions |
| [`host_resource_budget.hpp`](host_resource_budget.hpp) | Disk and RAM reserves, including concurrently resident client state |
| [`packed_checkpoint_policy.hpp`](packed_checkpoint_policy.hpp) | Packed replay policy derived from the process profile |
| [`packed_checkpoint_replay.hpp`](packed_checkpoint_replay.hpp) | Replay resource estimates from schedule and ciphertext bounds |
| [`packed_setup_admission.hpp`](packed_setup_admission.hpp) | Capacity checks before constructing large packed preprocessing artifacts |

Profile geometry and proof parameters are inputs to the experiment. A quick
packed profile is explicitly classified as diagnostic stress evidence; its
successful execution does not make it an evaluation parameter point. Resource
formulas are admission bounds, while timing and whole-process memory evidence
come from the runner's measurements.

## Cost formulas

The model has a short data flow:

```text
LayeredCircuit
  -> ScheduleFormula
  -> ProverOperationLedger
  -> runtime, proof-size, memory, and verifier estimates
```

[`schedule_cost.hpp`](schedule_cost.hpp) derives the protocol's logical work
from a compiled payload circuit. [`target_cost.hpp`](target_cost.hpp) places
that work at configured RNS levels and exposes the report-facing estimates.
[`packed_checkpoint_replay.hpp`](packed_checkpoint_replay.hpp) maps the packed
evaluation schedule and calibrated ciphertext bounds into replay resources.
The non-template implementations live in
[`src/bench/`](../../../src/bench/).

For Base, the RNS ledger keeps three states distinct: a source at its natural
payload level, its one-time proof-ingress artifact, and emitted proof messages
normalized to `q0`. Reader rewinds do not repeat ingress work. Public values,
including structural zero, have no ciphertext, switch event, or serialized
ciphertext record.

A formula report's configured uniform proof-ingress level is a cost-model
input, not an admitted modulus schedule. Admission requires the component-wise
source levels and noise evidence enforced by the corresponding
process-separated target runner.

The model boundaries and implementation map are in
[`docs/COST_MODEL.md`](../../../docs/COST_MODEL.md). Executable commands and
result classifications are in
[`docs/BENCHMARKING.md`](../../../docs/BENCHMARKING.md); the executable catalog
is [`benches/README.md`](../../../benches/README.md).

Formula and admission checks are in
[`tests/cost_model/`](../../../tests/cost_model/).
