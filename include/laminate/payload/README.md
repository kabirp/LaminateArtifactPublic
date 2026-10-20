# Payload circuits

This directory defines, compiles, and evaluates the computation proved by
Laminate. A payload is **Wide**, with all BGV slots participating in one
computation, or **Laned**, with `B` independent scalar computations.

## Where to start

| Task | Entry point |
| --- | --- |
| Define a payload DAG | [`circuit.hpp`](circuit.hpp): `PayloadCircuit` and `PayloadBuilder` |
| Compile for GKR | [`compiler.hpp`](compiler.hpp), producing [`ir/layered.hpp`](ir/layered.hpp) |
| Run the plaintext reference | [`evaluator.hpp`](evaluator.hpp) and [`trace.hpp`](trace.hpp) |
| Encrypt client inputs | [`input_encryption.hpp`](input_encryption.hpp) |
| Evaluate under FHE | [`wide_fhe_evaluator.hpp`](wide_fhe_evaluator.hpp) or [`laned_fhe_evaluator.hpp`](laned_fhe_evaluator.hpp) |
| Plan and execute checkpoint replay | [`checkpoint/plan.hpp`](checkpoint/plan.hpp) and [`checkpoint/session_engine.hpp`](checkpoint/session_engine.hpp) |

Supporting directories separate arithmetic and level planning (`evaluation/`),
trace identities (`trace/`), file storage (`storage/`), replay (`checkpoint/`),
noise assessment (`noise/`), and canonical circuit encoding (`setup/`).
Application code normally enters through the
[delegation APIs](../delegation/README.md).

## Circuit model

[`circuit.hpp`](circuit.hpp) defines supported operations. Plaintext
multiplication is affine; multiplication layers contain CT–CT products and
structural forwarding/padding. Laned payloads reject rotations and nonuniform
plaintext multiplication. Wide affine layers retain local operations without
expanding a dense slot matrix. [Layering](../../../docs/LAYERING.md) maps the
compiler stages and their invariants.

Laned also accepts lane-varying additive offsets, a minor extension of the paper's
same-circuit definition in Section E.1, “Overview and Prerequisites,” requiring
no change to the affine-reduction proof structure; the benchmarks use uniform
scalar offsets and are unaffected.

Laned input replication is implemented in
[`input_encryption.hpp`](input_encryption.hpp). Witness packing, its full-width
identity case, and workspace bounds are in
[`checkpoint/laned_witness_packing.hpp`](checkpoint/laned_witness_packing.hpp).
Section E.2, “Witness Packing,” of the paper defines the Laned layout.

There is no textual circuit format. With the payload headers included, this
constructs a two-input Laned computation that multiplies its inputs and scales
the result by seven:

```cpp
using namespace laminate;
using namespace laminate::payload;
constexpr std::size_t lanes = 128;
constexpr std::size_t slots = 16'384;

PayloadBuilder builder(PayloadShape::laned(lanes, slots), 2);
const std::size_t scale = builder.add_scalar_plaintext(Fp(7));
const WireId product = builder.mul(0, 1);
builder.set_outputs({builder.mul_plain(product, scale)});

PayloadCircuit payload = builder.finish();
LayeredCircuit circuit = compile(payload);
```

[`fixtures/workloads.hpp`](fixtures/workloads.hpp) provides deterministic test
and benchmark generators through `laminate_payload_fixture_support`.
[`bench/payload_profile.hpp`](../bench/payload_profile.hpp) selects benchmark
geometry; these profiles do not restrict the general IR. Compiled dimensions
can differ from generator quotas after affine compilation.

## Trace producers

Plaintext evaluation produces `SyntheticTrace` values.
[`trace/trace_crypto.hpp`](trace/trace_crypto.hpp) encrypts bounded synthetic
traces for proof comparisons; this does not measure homomorphic payload work.

The FHE evaluators start from encrypted inputs and send live wires in canonical
order to memory, file, or checkpoint sinks with `FheEvaluated` provenance.
[`trace.hpp`](trace.hpp) defines the provenance contract.

## Public and encrypted values

Live wires use `fhe::FheValue<Backend>`: a uniform public scalar, a nonuniform
public slot vector, or a ciphertext. Public arithmetic remains public; an
encrypted zero remains private. Structural padding has a protocol index but
no stored record. Padded-domain readers return a public-zero tag without
allocating a ciphertext.

## Evaluation levels

[`evaluation/fhe_evaluation_plan.hpp`](evaluation/fhe_evaluation_plan.hpp)
defines natural source levels, proof levels, and post-layer switches. Proof
normalization operates on a copy: reusable payload sources retain their
natural level. Checkpoint replay creates each proof-ingress artifact once and
reuses it across scans and rewinds.

Production Base requires a certified `HonestPayloadNoiseSchedule`. Admission
checks its setup binding, input levels, and exact prime chain; a separate plan
cannot override it. [`noise/honest_noise_schedule.hpp`](noise/honest_noise_schedule.hpp)
defines certification. Execution identity binds the circuit and serialized
inputs, and verification requires matching provenance and trace identity.

## File traces

[`storage/file_trace_store.hpp`](storage/file_trace_store.hpp) defines the
bounded trace format and decode limits. Callers supply a private destination,
byte ceiling, and free-space reserve. Live tagged records are published per
layer, with the manifest last. Opening validates circuit, provenance, trace
identity, slot count, and backend context before issuing readers.

Readers own their handles and support bounded sequential access and rewind.
`physical_bytes` measures finalized file lengths; filesystem allocation and
metadata overhead require separate admission reserves.

`ReopenableAuthenticated` validates persisted records and their integrity.
`SameProcessEphemeral` permits a consuming writer-to-reader handoff without
record hashes; it cannot be reopened after interruption. The
[trace-store implementation guide](../../../src/payload/storage/README.md)
explains these modes and private aliases. Both require exclusive directory
ownership and do not authorize concurrent file replacement by another process.

## Checkpoint replay and retirement

[`checkpoint/session_engine.hpp`](checkpoint/session_engine.hpp) publishes
selected layers and recomputes omitted relations in bounded chunks.
[`evaluation/affine_program.hpp`](evaluation/affine_program.hpp) supplies the
streaming affine schedule and intermediate lifetimes. Admission includes
caches, metadata, arithmetic workspace, and any overlap between natural and
proof-ingress artifacts.

After validating a distinct ingress artifact, execution may retire the natural
source. GKR retires sources and multiplication artifacts after their final
consumer. Failure after retirement begins is terminal for that session.

## Lifetime and reference boundaries

Evaluation contexts and circuits must outlive their in-process file/checkpoint
handoffs. Persisted preprocessing does not make an interrupted online proof
restartable.

`encrypt_compact_synthetic_trace` accepts only `SyntheticTrace`, stores one
representative per physical value, and leaves padding virtual. Use it for
bounded proof comparisons, not FHE payload measurements.

Compilation, plaintext/FHE parity, traces, and replay tests are under
[`tests/payload/`](../../../tests/payload/). Execution commands and result
classifications belong to the [benchmark guide](../../../docs/BENCHMARKING.md).
