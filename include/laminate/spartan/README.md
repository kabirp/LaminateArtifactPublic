# Spartan packing proof

This module proves the R1CS relation used by transcript packing. Relation and
witness tables use `Fq`; sumcheck and opening challenges use `Fq2`. The selected
path combines Spartan, committed factored matrix evaluation, and BaseFold.

## Reading the proof

| Entry point | Responsibility |
| --- | --- |
| [`spartan.hpp`](spartan.hpp) | Setup, proving, verification, and external prover keys |
| [`r1cs.hpp`](r1cs.hpp) | Relation and assignment metadata |
| [`sumcheck.hpp`](sumcheck.hpp) | ConstraintCheck and WiringCheck APIs |
| [`src/spartan/bcs16.cpp`](../../../src/spartan/bcs16.cpp) | Statement binding and proof composition |
| [`factored.hpp`](factored.hpp) | Committed matrix evaluation |
| [`basefold_pcs.hpp`](basefold_pcs.hpp) | Polynomial commitment, parameters, and canonical opening codec |

The public input is the logical packing statement. Its live-prefix evaluation
is linear in the public vector. Fiat–Shamir composition receives a
[`PublicCoin`](../transcript/public_coin.hpp) from the enclosing protocol.

## Matrix evaluation and setup

| Mode | Matrix representation | Intended role |
| --- | --- | --- |
| `Direct` | Sparse matrices retained by the verifier | Bounded reference |
| `Uniform` | Structured public matrix evaluator | Structured reference |
| `CommittedFactored` | Public formulas and committed residual tensors | Production packing proof |

Factored preprocessing binds relation digests, tensor shapes, and commitments
into the setup digest. The caller must derive or authenticate the intended
key; an arbitrary online prover commitment is insufficient. The compact
verifier retains neither an expanded R1CS instance nor a general matrix
oracle. Reference matrix interfaces are in [`uniform.hpp`](uniform.hpp) and
[`matrix_oracle.hpp`](matrix_oracle.hpp).

`setup_external_committed_factored` constructs an `ExternalProverKey` and a
compact `VerifierKey` using the same setup identity as resident Spartan.
Persistent role storage belongs to the [protocol layer](../protocol/README.md).

## External-memory execution

[`packing/proof/spartan_external.hpp`](../packing/proof/spartan_external.hpp)
composes the artifact-backed prover. Its assignment view stores the logical
public vector and live witness segments; structural gaps and padding remain
public zero. Matrix products, sumchecks, and commitment construction consume
that same view.

[`basefold_pcs.hpp`](basefold_pcs.hpp) declares disk and workspace bounds for
external commitment and opening. The orchestrator admits aggregate live
resources before advancing the proof and retires generated artifacts after
their last use. Transform tile size and cache radix are independent settings.

Resident/external parity is tested in
[`test_transcript_packing_external.cpp`](../../../tests/protocol/test_transcript_packing_external.cpp).
A bounded fixture checks that fixture's behavior; benchmark resource usage is
measured separately by the runners.

## BaseFold openings and encoding

[`ipcs.hpp`](ipcs.hpp) defines the multilinear commitment interface. Opening
decoding checks canonical leaves, authentication frontiers, transcript-derived
query indices, and complete byte consumption. Query collisions make opening
lengths transcript-dependent: admission uses a setup-derived upper bound,
while measurement uses actual canonical bytes.

This PCS differs from the [gate-table BaseFold](../basefold/README.md) in its
statement, fields, and encoding. Parameter defaults and dimension limits live
in [`basefold_pcs.hpp`](basefold_pcs.hpp); the
[BaseFold policy map](../../../docs/BASEFOLD_SOUNDNESS.md) identifies the local
security checks. Complete protocol acceptance additionally requires the
surrounding Spartan and Laminate verification.

Spartan, matrix, sumcheck, and PCS tests are in
[`tests/spartan/`](../../../tests/spartan/).
