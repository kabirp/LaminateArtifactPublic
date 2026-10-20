# Common setup and role separation

[`setup.hpp`](../setup.hpp) is the common setup facade for all three Laminate
variants. Setup binds a payload and its compiled layered circuit to a public
identity, then attaches the FHE capability needed by each role.

| Header | Responsibility |
| --- | --- |
| [`public.hpp`](public.hpp) | Public circuit identity, gate-MLE profile, canonical setup encoding, and setup digest |
| [`gate_mle.hpp`](gate_mle.hpp) | Deterministic outsourced gate-table preprocessing and restoration of server opening state |
| [`roles.hpp`](roles.hpp) | Checked construction of server, client, and packed-client capabilities |
| [`noise_binding.hpp`](noise_binding.hpp) | Validation and binding of accepted payload/proof schedules |

## Public setup

`make_direct_setup` makes the circuit available for direct gate-MLE queries.
`preprocess_outsourced_gate_mle_setup` additionally constructs committed gate
tables and server opening state; the public projection retains verifier
metadata. With `prover_key_directory`, setup persists server opening state and
`restore_gate_mle_prover_key` reopens it against the authenticated public setup.
Missing or incompatible saved state fails without regenerating commitments.
Reference callers that omit the directory use deterministic reconstruction.
The `DummyCommittedDirect` profile binds only diagnostic digests and is not an
outsourced polynomial commitment.

The caller must authenticate the intended public setup. Its digest binds the
public identity used by transcripts and proof IDs. Public setup validation checks
the payload and layered-circuit identities; matching dimensions alone are
insufficient.

## FHE roles and variant setup

`EvaluationSetup` owns the evaluation context and optional gate-table prover
key. `ClientSetup` owns the client context, including decryption capability.
`PackedClientSetup` pairs the latter with a matching, key-free public verifier
context used for ciphertext-coefficient checks. The server never needs the
client decryptor.

Base uses `make_evaluation_setup` and later
[`CertifiedBaseClientSetup`](../protocol/setup/base_client.hpp) for its client
API. Folded/Laned use `make_packed_evaluation_setup`, which also prepares
reusable alignment masks, and the additional
[`protocol/packed/setup.hpp`](../protocol/packed/setup.hpp) packing setup.
Persistent role artifacts and recurring online capabilities are described in
the [protocol guide](../protocol/README.md).

The schedule-binding functions validate a selected noise/level schedule and
include its identity in public setup. Their names distinguish the routine
uniform Base ingress policy from the offline exhaustive noise assessment.
The [protocol guide](../protocol/README.md) describes the selected policies;
callers must not substitute a cost-model level for an admitted schedule.

Setup identity and role-construction checks are in
[`tests/setup/test_setup.cpp`](../../../tests/setup/test_setup.cpp).
