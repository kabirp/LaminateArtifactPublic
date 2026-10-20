# Benchmarking

The benchmark reports distinguish measurements from formulas and projections.
The distinction matters: a Mock run checks protocol control flow, while only
a real-SEAL run measures FHE performance.

Use these entry points:

| Goal | Entry point |
| --- | --- |
| Run a quick functional check | `laminate_protocol_bench` with the Mock backend |
| Inspect operation counts, proof bytes, or verifier work | `laminate_target_cost_report` |
| Run the direct scalar baseline | [Local benchmark runbook](LOCAL_BENCHMARKS.md) |
| Run a process-separated real-SEAL benchmark | [GCP benchmark runbook](GCP_BENCHMARKS.md) |
| Find a specialized executable | [Benchmark catalog](../benches/README.md) |
| Check the reported lattice attack costs | [Privacy estimates and reproduction](PRIVACY_ESTIMATES.md) |

## Evidence labels

Use these evidence categories when interpreting reports and formulas; the
category describes what the evidence establishes, even when a raw report uses
a more specific field name.

| Label | Meaning |
| --- | --- |
| **Measured** | The named code ran at the stated revision, backend, parameters, and host. |
| **Formula** | The compiled circuit and codec determine the value exactly. |
| **Calibrated** | A formula is priced with measured primitive costs. |
| **Projected** | A smaller run is scaled by a stated work metric. |
| **Smoke test** | A bounded real-backend run checks integration and correctness. |
| **Mock** | The functional simulator ran; its timing says nothing about FHE performance. |

A secret-key noise observation is a diagnostic measurement, not a public
completeness proof. A capacity preflight is not an execution. `quick` uses
reduced security parameters and does not qualify as target evidence. See
[Status](STATUS.md) for the selected parameters and claim boundaries, and the
paper for protocol and soundness definitions.

## Benchmark workload scope

Section 7.1, “Methodology,” of the paper describes `balancedLaned`
and `mulHeavyPyramid`. The executable profile names are
`target-balancedLaned` and `target-mulHeavyPyramid`.
[`payload_profile.hpp`](../include/laminate/bench/payload_profile.hpp) defines
their gate counts, multiplication widths, and generator settings.
Both have `2^20` payload gates, multiplicative depth eight, 64 inputs, and one
output. `mulHeavyPyramid` requires Wide operations and has no Laned profile.

[`params.hpp`](../include/laminate/params.hpp) fixes the counts by operation,
excluding compiler forwarding and padding. The reports distinguish arithmetic
from permutation wiring.

`balancedLaned` supports both Wide and Laned execution. Base and Folded run
it over all `N` slots, while Laned runs it with `B=1`, `128`, or `N=16,384`
independent lanes. The seven proof-bearing target runs are Base and Folded on
each workload, plus those three Laned runs on `balancedLaned`. The local and
noIntegrity baselines also support both workloads.

## Choosing ciphertext parameters

All encrypted variants relinearize and modulus-switch after each payload
ciphertext-ciphertext multiplication layer. The shared rule makes the comparison
easier to interpret and avoids optimizing switching times for only some variants.
Prime sizes and limb counts are tuned with SEAL tests to leave some spare noise
budget without inflating arithmetic costs. In particular, `noIntegrity` reserves
no budget for proof construction. Folded and Laned must cover the noise inherited
from the payload as well as later GKR and packing operations. See
[BGV parameters and noise planning](BGV_NOISE_AND_MODULUS_SWITCHING.md) for how
these schedules are chosen and what the noise tests establish.

## Per-request client computation

With reusable preprocessing already in RAM, the client computation per delegation
request is

```text
client computation = input encryption + output decryption + VCoED verification.
```

This is the client total shown in Base, Folded, and Laned summaries. Loading
keys and circuit preprocessing is a separate reusable startup cost. Request
binding/nonce generation, transport encoding/decoding, file reads/writes, peer
waiting, and the optional post-verification honest-output noise audit remain
separate harness timings. None enters this three-component computation total.

VCoED verification has this disjoint measured breakdown:

| Component | Work included |
| --- | --- |
| GKR transcript recovery | Recompute GKR Fiat–Shamir hashes and canonical transcript bytes; decrypt Base proof messages; for packed variants decrypt and recompose digit plaintexts and unpack the logical messages. |
| Plaintext GKR checks | Check the recovered layer reductions, response bindings and output claim, including the affine gate-opening batch and its own PCS transcript. |
| Terminal input MLE | Evaluate and check the final claim against the client's inputs. This is distinct from affine GateMLE openings. |
| Spartan packing argument, packed variants | Reconstruct and bind its public statement; verify Spartan, factored-matrix reductions and BaseFold openings. |
| Well-formedness noise checks, packed variants | Check the revealed test ciphertexts against the prescribed noise thresholds. |

The two GKR rows sum to GKR verification. GKR, terminal input MLE, the Spartan
packing argument, and well-formedness sum to VCoED verification. Output
decryption is measured once and belongs only to the client computation total,
outside proof-message recovery.
The well-formedness row is a protocol check, not the later honest-output diagnostic.

The opt-in verifier profiler switches among exclusive phases, so nested transcript
and decryption work is not counted twice. It measures actual boundaries; it does
not estimate plaintext GKR time by subtracting rounded, inclusive report timers.
Wall and process CPU times are both reported. Persistent progress-journal
callbacks are excluded. This is active computation, not end-to-end request
latency or a network-cost model.

Raw records use `timing.client.computation.schema=vcoed-client-computation-v1`.
The [client timing adapter](../benches/support/client_computation.hpp) defines
the recorded fields; the [verifier profiler](../include/laminate/protocol/metrics/profiling.hpp)
defines their boundaries. The renderer checks the timing schema and matching
protocol identities across roles.

## Build and test

Use the [quick start](../README.md#build-and-run-a-small-proof) for a small Mock
proof. For the complete reference-host build, dependency installation, and
both extended test suites, follow [GCP section 4](GCP_BENCHMARKS.md#4-build-seal-and-laminate).
Mock checks control flow; real-SEAL tests check encrypted arithmetic and proofs.
Neither runs the full target workloads.

The [test guide](../tests/README.md) describes optional coverage and test
selection. Executable targets and their implementations are listed in the
[benchmark catalog](../benches/README.md).

To inspect circuit geometry and cost formulas without constructing a trace:

```sh
build/benches/laminate_target_cost_report \
  --protocol base --slots 16384 --depth 4 --width 64
```

## Process-separated measurements

Use [the GCP runbook](GCP_BENCHMARKS.md) for real-SEAL measurements and
[the local runbook](LOCAL_BENCHMARKS.md) for direct scalar computation. The wrapper
always names the action, variant, profile, and run explicitly:

```text
benches/run_gcp.sh ACTION VARIANT PROFILE RUN
```

`VARIANT` is `local`, `noIntegrity`, `base`, `folded`, or `laned`; `PROFILE` is `quick`,
`target-balancedLaned`, or `target-mulHeavyPyramid`. `start_setup` uses `RUN=new`;
`follow_setup`, client/server launch, status, summary, and archive use
`RUN=current`. Each role is detached from the SSH session, and the current
pointer is scoped to the complete explicit profile. Use the runbook's `tmux`
sequence to keep the waiting shell alive until it has launched every role.

Laned adds one required, explicit dimension:

```text
benches/run_gcp.sh ACTION laned PROFILE RUN --lanes 1|128|16384
```

The supported workload/variant combinations are listed in the
[GCP runbook](GCP_BENCHMARKS.md#6-select-one-profile-and-variant). The runner
requires `B` explicitly for every Laned action.

For the server-backed variants, setup, client, and server are distinct OS
processes with disjoint persistent state. The online exchange has exactly one
request and one response:

```text
shared/transcript/cli-to-srv-request.bin
shared/transcript/srv-to-cli-response.bin
```

The client encrypts and publishes the request, waits without charging idle
time to its active total, then decrypts and, for proof-bearing variants,
verifies the response. The server
loads server preprocessing, evaluates the payload, constructs the proof where
applicable, and publishes the response. Overall success requires all of the
following:

1. setup reports `PASS` and exits zero;
2. the server reports `PASS` and exits zero;
3. the client reports verification `PASS`, including the required output-noise
   audit for packed targets (or completed decoding/decryption for
   `noIntegrity`), and exits zero; and
4. the summary renderer accepts the complete artifact set.

Local has only setup and a client. Its success boundary is zero exits from
both, `client.result=PASS`, and an accepted summary. It has no server,
request/response, verification, or FHE/storage-capacity qualification.

Client and server computation are each single-threaded and use distinct
physical cores, with observation on a third core. Base/Folded setup can use a
worker pool before online work. File transport measures serialization and
local I/O, not network latency.

Target profiles have fixed payload and cryptographic parameters and require
zero repeated payload replay. Setup derives the storage budget from available
disk and RAM, accounting for host reserves and concurrent role memory. Smaller
profiles permit bounded replay. See the [GCP runbook](GCP_BENCHMARKS.md) for the
host requirements and
[`host_resource_budget.hpp`](../include/laminate/bench/host_resource_budget.hpp)
for resource accounting.

## Reading the report

`summary` validates the complete run and atomically publishes
`shared/report/summary.md`. It reports the outcome, profile, scalar-gate scale,
modulus size, timings, proof/communication sizes, and memory/storage use.
Variant-specific sections expose the FHE work ledger and client verification
breakdown where applicable. Exact prime values, setup timings, commands,
process exits, and complete telemetry remain in the raw evidence.

The [benchmark catalog](../benches/README.md#reports-and-cost-models) links to
the renderers. Report presentation is defined in
[`render_concise_summary.py`](../benches/support/render_concise_summary.py).

Base and noIntegrity server totals include reusable-state loading; Folded and
Laned totals exclude their separately timed reusable startup. The separately
timed loading takes under two minutes. Server totals include payload
evaluation, proof generation, storage, and serialization, including writing
the encrypted trace to disk and reading it during proving. They exclude peer
waiting and one-time preprocessing generation. The paper uses these reported
totals, each from one execution. Its Section 7.1, “Methodology,” states the
timing boundaries used in the comparison.

When comparing reports:

- The initial ciphertext-modulus field counts data primes only. The
  [privacy estimates](PRIVACY_ESTIMATES.md) use the larger initial key modulus,
  including the special prime, and are distinct from measured timings or
  proof-integrity parameters.
- Separate client active work from time waiting for the server. A “verifier”
  subspan, a complete client total, and a setup time have different boundaries.
- Distinguish proof bytes from the complete response, which also includes
  the encrypted output and transport framing. Request bytes are separate.
- Peak process RSS includes allocations that may predate a named phase;
  admitted RAM/disk limits are model bounds, not measured peaks. Do not sum
  per-phase peaks as if they occurred simultaneously.
- Application-level file-byte counters are not physical disk traffic. A
  checkpoint reuse/alias count is also not newly written ciphertext bytes.
- Local scalar operations, logical FHE operations, and RNS-limb-weighted
  operations are distinct work units.

CPU time close to wall time shows that the process stayed compute-active. It
does not by itself prove that SEAL kernels dominate; use the FHE operation
ledger or a phase-local profile for that claim. Bounds and measurements are
also different quantities: do not sum a capacity limit with an observed peak.

### Local computation and verifier arithmetic

The [local scalar evaluator](../benches/payload/local_scalar_evaluator.cpp)
and the verifier's native GKR, Spartan, and BaseFold field checks use the same
compiler optimization settings, including automatic vectorization and native
instruction selection. These field routines do not use Intel HEXL. Record
the compiler and CPU-target metadata when comparing them. The complete client
verification span also includes SEAL-backed proof-message decryption and,
for packed variants, threshold checks, which can use HEXL. Use the named
timing spans to distinguish algebraic verification from full client cost.
The [GCP build instructions](GCP_BENCHMARKS.md#4-build-seal-and-laminate)
give the reference toolchain and dependency versions.

## Publishing results

Before retaining a result, preserve raw evidence recording:

- protocol, workload, parameters, backend, and exact modulus chain;
- clean source-snapshot revision and Release build;
- compiler, acceleration, host, and CPU affinity;
- exact command and thread count;
- units and evidence label; and
- setup, online server, active client, verification, serialization, and
  communication as separate quantities.

Measure one compute thread per online role. Only the paired client and server
of the same run should overlap. Preserve each run's original source identity
and host metadata; do not relabel measurements with a later revision or treat
results under changed parameters as the same configuration.
