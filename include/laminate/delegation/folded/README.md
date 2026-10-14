# Folded delegation

Folded delegates a Wide payload, proves its folded GKR transcript, and packs
the transcript into the single server response.

Start with [`client.hpp`](client.hpp) and [`server.hpp`](server.hpp). Their
production flow, after setup, is:

1. `begin_folded_request(...)`
2. `prepare_folded_request_resources(...)`
3. `evaluate_folded_request(...)`
4. `prove_folded_response_irreversible(...)`
5. `open_folded_response(...)`
6. `verify_opened_folded_response(...)`

The client uses `PackedClientSetup`; the server uses
`AuthenticatedPackedServerOnlineState`. The latter binds the restored server
role, checkpoint geometry, and external packing setup before a request is
evaluated. `prepare_folded_request_resources` reserves the one-shot replay,
GKR, packing, and storage resources. `prove_folded_response_irreversible`
consumes the evaluated state and may retire its files. It cannot be retried
after retirement has begun.

[`server/online_evaluation.hpp`](server/online_evaluation.hpp) and
[`server/online_proving.hpp`](server/online_proving.hpp) connect these
transitions to the [external packed prover](../../protocol/packed/external/prover.hpp).
On the client, opening retains tentative plaintext privately; verification
checks both GKR and packing before releasing it. `verify_folded_response`
composes those two client transitions.

Canonical transport lives in [`wire/codec.hpp`](wire/codec.hpp), and move-only
state lives in [`session/state.hpp`](session/state.hpp). Bounded resident/file
comparators and raw-setup client helpers live under [`reference/`](reference/)
with explicit `*_reference` names. See the
[shared lifecycle and binding rules](../README.md) and
[`test_folded_delegation.cpp`](../../../../tests/test_folded_delegation.cpp).
