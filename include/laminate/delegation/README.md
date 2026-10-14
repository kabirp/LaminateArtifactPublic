# Delegation roles

Laminate uses one client request and one server response. The request contains
encrypted payload inputs. The response contains the encrypted output and the
complete proof. No variant sends an intermediate plaintext claim or performs a
second round trip.

These are typed protocol transitions. The process benchmark adapters provide
transport and persistent role setup around them. For executable commands,
use the [benchmark guide](../../../docs/BENCHMARKING.md).

| Variant | Client lifecycle | Server lifecycle | Wire codec | What differs |
|---|---|---|---|---|
| Base | [`base/client.hpp`](base/client.hpp) | [`base/server.hpp`](base/server.hpp) | [`base/wire/codec.hpp`](base/wire/codec.hpp) | Sends the encrypted GKR transcript directly |
| Folded | [`folded/client.hpp`](folded/client.hpp) | [`folded/server.hpp`](folded/server.hpp) | [`folded/wire/codec.hpp`](folded/wire/codec.hpp) | Wide payload with folded GKR and transcript packing |
| Laned | [`laned/client.hpp`](laned/client.hpp) | [`laned/server.hpp`](laned/server.hpp) | [`laned/wire/codec.hpp`](laned/wire/codec.hpp) | Laned payload with lane-aware GKR and transcript packing |

Each lifecycle header is declaration-first. Read `client.hpp` from request
creation through verification, and `server.hpp` from resource admission through
response construction. Supporting state, serialization, profiling, and
reference fixtures are nested so they do not obscure those transitions.

## One-request/one-response lifecycle

```text
client                                  server
  |                                       |
  | encrypted inputs                      |
  |-------------------------------------->|
  |                                       | evaluate payload
  |                                       | prove retained trace
  | encrypted output + complete proof     |
  |<--------------------------------------|
  | open response without releasing output
  | verify proof
  | release plaintext only on acceptance
```

The caller supplies at least 32 bytes of fresh CSPRNG output to the variant's
`make_*_client_nonce` helper. The API checks the length and consumes the
move-only nonce; the caller is responsible for the bytes' entropy. The
resulting session identifier binds that request to its sole response.
Move-only awaiting/opened states prevent reuse. Opening decrypts the output
exactly once into tentative state; verification either releases it or returns
no output.

The server owns evaluation capability but no decryptor. Production server
flows admit storage and one-shot proving resources before FHE evaluation,
retain only the trace representation needed by proving, and fail closed after
irreversible reclamation begins.

## Code map

Every variant uses the same directory vocabulary:

- `client/`: request creation, response opening, and verification definitions.
- `server/`: production admission, evaluation, and proving definitions.
- `session/`: move-only client and server state.
- `transport/`: behavior-free request and response types.
- `wire/`: bounded canonical request and response codecs.
- `profiling/`: opt-in timing adapters, outside the protocol API.
- `reference/`: bounded raw-setup and resident parity paths for tests.

Variant-specific navigation is in [`base/README.md`](base/README.md),
[`folded/README.md`](folded/README.md), and
[`laned/README.md`](laned/README.md). Shared packed-client process adapters and
the encrypted-statement binding live under [`packed/`](packed/).

## Binding and transport invariants

The setup, session, circuit, and trace identifiers appear in both messages and
the proof transcript. Folded and Laned derive the verifier's output point from
the request commitment and exact ordered encrypted output through
[`packed/statement.hpp`](packed/statement.hpp). The server therefore never
needs the plaintext output claim.

Wire decoders require caller-supplied limits before allocating ciphertexts or
proof bytes. They reject wrong domains, versions, flags, public bindings,
storage-context identities, lengths, truncation, trailing bytes, and proof
structure. C++ structs are never copied directly across a process boundary.

Production packed clients use `PackedClientSetup` or authenticated recurring
client state. Raw `ClientSetup` entry points have explicit
`*_resident_reference` names under each `reference/` directory; they are not
same-name overloads of the production API.

Server checkpoint states are in-process handoffs. Their evaluation context and
circuit must remain alive until proving finishes; persisted preprocessing does
not make an interrupted online request restartable. A failed irreversible
proof requires a fresh evaluation lifecycle, not reuse of retired trace state.

Lifecycle and bounded-wire checks are in
[`tests/delegation/`](../../../tests/delegation/), with complete packed
delegation cases in
[`test_folded_delegation.cpp`](../../../tests/test_folded_delegation.cpp) and
[`test_laned_delegation.cpp`](../../../tests/test_laned_delegation.cpp).
