# Architecture and code map

The implementation has one application flow for all three Laminate variants:
construct a payload, evaluate it under BGV, prove its layered computation, and
verify before releasing the plaintext output. Base, Folded, and Laned share
the payload compiler, public-or-encrypted value type, FHE backends, compact
trace machinery, and most low-level arithmetic. They differ in payload layout,
how much of GKR runs under FHE, and how the GKR messages reach the client.

The benchmark names `base`, `folded`, and `laned` select these three proof
paths. `noIntegrity` evaluates the encrypted payload without a proof, and
`local` evaluates the plaintext field computation without FHE. These baselines
measure the plaintext and encrypted payload costs.

For a first code review, follow the request/response diagram and entry points
below. [Protocols](PROTOCOLS.md) maps the paper's reductions to code;
[implementation scope](STATUS.md) records the security assumptions.

## Roles and message flow

Setup creates disjoint client and server state:

- the client owns the secret key, plaintext inputs, input encryption, output
  decryption, and proof verification;
- the server owns evaluation keys, payload evaluation, trace/checkpoint state,
  and proof construction; and
- public setup binds the payload, layered circuit, parameter profile,
  GateMLE policy, and accepted modulus schedule.

There is exactly one request and one response:

```text
Client                                      Server
  | encrypted inputs + session binding        |
  |------------------------------------------->|
  |                                            | evaluate payload under FHE
  |                                            | bind encrypted output
  |                                            | derive output point and prove
  | encrypted output + proof                   |
  |<-------------------------------------------|
  | derive the same point                      |
  | decrypt output and form its MLE claim      |
  | verify; release plaintext only on PASS     |
```

The encrypted statement fixes the request, output, output geometry, and setup
identities before the output point is sampled. The server never receives the
plaintext output-MLE claim. The client derives that claim after decrypting the
response and releases the output only if verification succeeds.

The split-process benchmark realizes this exchange with immutable files. It
demonstrates role separation and canonical serialization.

## Executable entry points

The [runbooks](README.md#runbooks-and-detailed-reference) use
[`benches/run_gcp.sh`](../benches/run_gcp.sh) to configure and launch separate
setup, client, and server processes. To follow the C++ control flow, start at
`main` in the relevant driver:

| Task | Driver |
| --- | --- |
| Small in-process proof | [`protocol_benchmark.cpp`](../benches/protocol/protocol_benchmark.cpp) |
| Base benchmark | [`base_checkpoint_benchmark.cpp`](../benches/protocol/base_checkpoint_benchmark.cpp) |
| Folded or Laned benchmark | [`packed_checkpoint_benchmark.cpp`](../benches/protocol/packed_checkpoint_benchmark.cpp) |
| Scalar local baseline | [`local_payload_benchmark.cpp`](../benches/protocol/local_payload_benchmark.cpp) |
| FHE-only baseline | [`no_integrity_benchmark.cpp`](../benches/protocol/no_integrity_benchmark.cpp) |

The drivers handle process orchestration, measurements, and report records.
Protocol logic lives in the library entry points below. Template definitions
are in headers; non-template implementations are under `src/`.

## Library entry points

The public protocol headers are intentionally small. The table below gives the
shortest path to setup, the file-backed proof path used by the benchmarks,
and verification. Bounded resident implementations live under `reference/`.

| Variant | Setup | File-backed proof | Verification |
| --- | --- | --- | --- |
| Base | [`setup.hpp`](../include/laminate/setup.hpp): `make_direct_setup`, `make_evaluation_setup`, and `make_client_setup` | [`protocol/base.hpp`](../include/laminate/protocol/base.hpp): `preflight_base` and `prove_base`; the process server calls the same path from [`delegation/base/server.hpp`](../include/laminate/delegation/base/server.hpp) | `verify_base` in [`protocol/base.hpp`](../include/laminate/protocol/base.hpp) |
| Folded | Common setup plus `make_packed_evaluation_setup` and `setup_folded_conservative` in [`protocol/packed/setup.hpp`](../include/laminate/protocol/packed/setup.hpp) | `prove_folded_response_irreversible` in [`delegation/folded/server.hpp`](../include/laminate/delegation/folded/server.hpp) | `verify_folded` in [`protocol/folded.hpp`](../include/laminate/protocol/folded.hpp) |
| Laned | Common setup plus `make_packed_evaluation_setup` and `setup_laned_conservative` in [`protocol/packed/setup.hpp`](../include/laminate/protocol/packed/setup.hpp) | `prove_laned_response_irreversible` in [`delegation/laned/server.hpp`](../include/laminate/delegation/laned/server.hpp) | `verify_laned` in [`protocol/laned.hpp`](../include/laminate/protocol/laned.hpp) |

Base proof composition continues in
[`protocol/detail/base/api_impl.hpp`](../include/laminate/protocol/detail/base/api_impl.hpp).
Folded and Laned compose checkpoint/replay GKR with the external
transcript-packing prover in
[`protocol/packed/external/prover.hpp`](../include/laminate/protocol/packed/external/prover.hpp).
Small resident comparison paths are explicitly under
[`protocol/reference/`](../include/laminate/protocol/reference/). The delegated
server APIs use file-backed proving.

To trace the main proof logic, continue through these files:

| Stage | Implementation |
| --- | --- |
| Server evaluation and response lifecycle | [`delegation/base/server/api_impl.hpp`](../include/laminate/delegation/base/server/api_impl.hpp), [`folded/server/api_impl.hpp`](../include/laminate/delegation/folded/server/api_impl.hpp), [`laned/server/api_impl.hpp`](../include/laminate/delegation/laned/server/api_impl.hpp) |
| GKR output-to-input layer loop | [`gkr/detail/base/prover.hpp`](../include/laminate/gkr/detail/base/prover.hpp), [`folded/prover.hpp`](../include/laminate/gkr/detail/folded/prover.hpp), [`laned/prover.hpp`](../include/laminate/gkr/detail/laned/prover.hpp) |
| Packed proof composition | [`protocol/packed/external/detail/prover_impl.hpp`](../include/laminate/protocol/packed/external/detail/prover_impl.hpp) |
| Complete verification | [`protocol/detail/base/api_impl.hpp`](../include/laminate/protocol/detail/base/api_impl.hpp), [`folded/verification.hpp`](../include/laminate/protocol/detail/folded/verification.hpp), [`laned/verification.hpp`](../include/laminate/protocol/detail/laned/verification.hpp) |

## Payload and trace path

[`PayloadBuilder`](../include/laminate/payload/circuit.hpp) constructs a typed,
topologically ordered ciphertext DAG. The compiler in
[`payload/compiler.hpp`](../include/laminate/payload/compiler.hpp) produces an
alternating `LayeredCircuit`:

```text
PayloadCircuit
    -> LayeredCircuit
    -> encrypted Wide or Laned evaluation
    -> compact trace or checkpoint/replay state
    -> file-backed encrypted GKR
```

Wide payloads may use rotations and slot-varying public plaintext operations.
Laned payloads place `B` independent computations in each ciphertext; they
allow lane-varying plaintext addition and uniform scalar multiplication, but
reject rotations and lane-varying plaintext multiplication.

Every stored wire is an `FheValue<Backend>`: a public scalar, a public slot
vector, or a private ciphertext. Public arithmetic remains plaintext. In
particular, structural padding and known public zero are virtual values, not
encrypted sentinels, and consume no ciphertext record or FHE operation.
Repeated dense operands are aliases of one physical record.

File-backed proving retains selected encrypted checkpoints and recomputes
missing layers as needed. Source artifacts are converted once to the modulus
level required by setup and reused across sumcheck passes. The
[payload module](../include/laminate/payload/README.md) maps the compiler,
evaluators, storage, and replay implementation.

## Proof composition

The [GKR module guide](../include/laminate/gkr/README.md) maps each variant's
output-to-input loop, layer reductions, verifiers, and FHE kernels. Affine
reductions use the circuit-specific [GateMLE provider](../include/laminate/gates/README.md);
dense multiplication wiring is structural and needs no gate opening. Use the
[paper references](README.md#paper-and-artifact) for the reduction identities.

Setup binds gate commitments to the public circuit and selected PCS policy,
and exports reusable prover state. The process server authenticates that state
against the verifier key before evaluating the payload. Missing or incompatible
persistent state rejects startup. The [GateMLE implementation map](GATE_MLE_PERFORMANCE.md)
locates the representation, query evaluation, and opening paths.

Base sends its public-or-encrypted GKR messages directly. Folded and Laned
compose encrypted GKR with [transcript packing](TRANSCRIPT_PACKING.md), whose
prover reads file-backed message artifacts. All variants bind the same encrypted
statement before deriving challenges and accept only after the complete
verification path succeeds.

## Variant differences

| Property | Base | Folded | Laned |
| --- | --- | --- | --- |
| Payload layout | Wide | Wide | `B` independent lanes |
| Coordinates reduced under FHE | Ciphertext index | Ciphertext index and every slot index | Ciphertext index, then slot chunk and lane indices |
| GKR transport | Direct public-or-encrypted messages | One committed aligned value per BhIP message, recovered through transcript packing | Same packing boundary as Folded |
| Client completion | Decrypts messages and completes the slot relation | Verifies packing, recovers messages, and replays GKR | Same high-level flow, with Laned geometry and terminal transform |
| Packing setup | None | Folded packing setup | Laned packing setup |

[Protocols](PROTOCOLS.md) maps these variant boundaries to the paper and
source. [Transcript packing](TRANSCRIPT_PACKING.md) describes the shared
Folded/Laned packing implementation and compact matrix representation.

## Module map

| Path | Responsibility |
| --- | --- |
| [`include/laminate/setup.hpp`](../include/laminate/setup.hpp) | Public, client, and server setup facade |
| [`include/laminate/delegation/`](../include/laminate/delegation/) | Application-facing client/server roles and message transport |
| [`include/laminate/payload/`](../include/laminate/payload/) | Payload IR, compilation, FHE evaluation, compact traces, and replay |
| [`include/laminate/fhe/`](../include/laminate/fhe/) | Backend contract, public-or-encrypted values, Mock, and Microsoft SEAL |
| [`include/laminate/gkr/`](../include/laminate/gkr/) | Encrypted layer-reduction claims, provers, verifiers, and FHE kernels |
| [`include/laminate/protocol/`](../include/laminate/protocol/) | Whole-proof composition and verification |
| [`include/laminate/packing/`](../include/laminate/packing/) | Transcript alignment, tests, digits, R1CS relation, and matrix argument |
| [`include/laminate/spartan/`](../include/laminate/spartan/) | Spartan, BCS16, factored matrix proof, and PCS adapter |
| [`include/laminate/basefold/`](../include/laminate/basefold/) | BaseFold commitment and opening implementation |
| [`src/`](../src/) | Non-template implementations mirroring the public modules |
| [`tests/`](../tests/) | Correctness, codec, storage, and bounded end-to-end coverage |
| [`benches/`](../benches/) | Benchmark drivers, reports, and reproducible run wrappers |
