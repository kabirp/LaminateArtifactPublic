# Laned delegation

Laned delegates `B` independent scalar computations held in SIMD lanes,
proves its lane-aware GKR transcript, and packs the transcript into the single
server response. The payload's logical lane count is distinct from the
backend's physical slot count; input replication and witness packing are implemented by
[`input_encryption.hpp`](../../payload/input_encryption.hpp) and
[`laned_witness_packing.hpp`](../../payload/checkpoint/laned_witness_packing.hpp).

Start with [`client.hpp`](client.hpp) and [`server.hpp`](server.hpp). Their
production flow, after setup, is:

1. `begin_laned_request(...)`
2. `prepare_laned_request_resources(...)`
3. `evaluate_laned_request(...)`
4. `prove_laned_response_irreversible(...)`
5. `open_laned_response(...)`
6. `verify_opened_laned_response(...)`

The client uses `PackedClientSetup`; the server uses
`AuthenticatedPackedServerOnlineState`. The latter binds the restored server
role, checkpoint geometry, and external packing setup before a request is
evaluated. `prepare_laned_request_resources` reserves the one-shot replay,
GKR, packing, and storage resources. `prove_laned_response_irreversible`
consumes the evaluated state and may retire its files. It cannot be retried
after retirement has begun.

[`server/online_evaluation.hpp`](server/online_evaluation.hpp) and
[`server/online_proving.hpp`](server/online_proving.hpp) connect these
transitions to the [external packed prover](../../protocol/packed/external/prover.hpp).
On the client, opening retains tentative plaintext privately; verification
checks both GKR and packing before releasing it. `verify_laned_response`
composes those two client transitions.

Canonical transport lives in [`wire/codec.hpp`](wire/codec.hpp), and move-only
state lives in [`session/state.hpp`](session/state.hpp). Bounded resident/file
comparators and raw-setup client helpers live under [`reference/`](reference/)
with explicit `*_reference` names. See the
[shared lifecycle and binding rules](../README.md) and
[`test_laned_delegation.cpp`](../../../../tests/test_laned_delegation.cpp).
