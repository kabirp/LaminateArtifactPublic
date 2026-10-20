# Library source guide

For building and running the artifact, start with the
[project README](../../README.md). The [architecture map](../../docs/ARCHITECTURE.md)
connects executable drivers to the main setup, prover, and verifier paths.
This guide indexes library modules. Most protocol code is templated and lives
under `include/laminate/`; non-template implementations live in corresponding
[`src/`](../../src/) directories.

## Recommended reading order

1. [Payload circuits](payload/README.md): the computation, its layered circuit,
   and the trace evaluated under FHE.
2. [Setup](setup/README.md): public identities, gate-table preprocessing, and
   separate client/server capabilities.
3. [Delegation](delegation/README.md): the one-request/one-response lifecycle
   and the rule that plaintext output is released only after verification.
4. [Whole protocols](protocol/README.md): how the selected variant composes its
   proof and its persistent preprocessing.
5. [Encrypted GKR](gkr/README.md): the layer reductions, followed by
   [transcript packing](packing/README.md) and [Spartan](spartan/README.md) for
   Folded/Laned.

| Module | Role |
| --- | --- |
| [FHE](fhe/README.md) | Public/encrypted values, extension arithmetic, Mock and SEAL backends |
| [Gate MLEs](gates/README.md) | Direct circuit queries and outsourced gate-table verification |
| [BaseFold](basefold/README.md) | RS and generic foldable commitments for gate openings |
| [Finite fields](field/README.md) | Field parameters, arithmetic, transforms, and canonical encodings |
| [Multilinear polynomials](poly/README.md) | Dense/sparse MLEs, equality polynomials, and rotation predicates |
| [Transcripts](transcript/README.md) | SHA-256 Fiat–Shamir observation and challenge interfaces |
| [Poseidon](crypto/README.md) | Ciphertext commitments checked inside the packing R1CS |
| [Storage](storage/README.md) | Bounded native-field artifacts and external record sorting |
| [Benchmark support](bench/README.md) | Workload profiles, capacity policies, and cost formulas |

## Conventions used in these guides

“Production path” identifies the file-backed execution used by the process
benchmarks. It does not imply a separate security certification. `reference/`
paths are bounded comparison implementations; some reuse production arithmetic
and therefore are not independent correctness oracles. Mock execution models
the interface and operation counts without cryptographic FHE.

Setup data is reusable. An online proof's checkpoints and scratch artifacts
are disposable and can be retired while the proof is being produced. Such a
proof is not restartable merely because some of its inputs are persisted.

The `noIntegrity` baseline is a benchmark runner that evaluates the payload
without a Laminate integrity proof; it is not a fourth proof module. Consult
the [benchmark guide](../../docs/BENCHMARKING.md) for its flow and the three
proof variants. Tests mirror the modules under [`tests/`](../../tests/).
