# Base delegation

Start with [`client.hpp`](client.hpp) or [`server.hpp`](server.hpp). These are
the Base lifecycle entry headers. Setup is completed before these transitions:

- `begin_base_request` encrypts the client inputs and returns the sole request.
- `evaluate_base_request` evaluates the Wide
  payload and retains the admitted checkpoint state.
- `prove_base_response_irreversible` consumes that state
  and returns the sole encrypted-output-and-proof response.
- `open_base_response` and `verify_opened_base_response` decrypt tentatively,
  verify, and release the output only on acceptance.

Unlike Folded and Laned, Base sends the encrypted GKR transcript directly and
does not run the transcript-packing/Spartan suffix. `verify_base_response`
composes the open and verify transitions when separate timing is unnecessary.

Supporting code is grouped by its role:

| Directory | Contents |
| --- | --- |
| [`session/`](session/) | Move-only client and server lifecycle state |
| [`statement/`](statement/) | Fiat--Shamir binding of request and encrypted output |
| [`transport/`](transport/) | Behavior-free request and response types |
| [`wire/`](wire/) | Bounded canonical request/response codecs; start at [`wire/codec.hpp`](wire/codec.hpp) |
| [`profiling/`](profiling/) | Opt-in timing adapters, outside the protocol API |
| [`reference/`](reference/) | Small resident lifecycle/parity path used by tests |

`client.hpp` and `server.hpp` declare the lifecycle. Their
`client/api_impl.hpp` and `server/api_impl.hpp` includes lead to the individual
phase implementations:

- `client/request.hpp` encrypts and binds the sole request;
  `client/response.hpp` opens, verifies, and releases the sole response.
- `server/request_validation.hpp` checks setup, schedule, request, and RNS
  level before FHE work; `server/capacity/` derives resource floors;
  `server/evaluate_payload.hpp` publishes compact checkpoints; and
  `server/prove_response.hpp` runs file-backed GKR and constructs the response.

The wire implementation is intentionally not mixed into the lifecycle
headers. `wire/request.hpp` and `wire/response.hpp` define the public codecs;
the field and proof encodings live under `wire/detail/`.

The canonical client functions accept `CertifiedBaseClientSetup`. Tests that
deliberately exercise uncached setup use the explicitly named helpers in
[`reference/client.hpp`](reference/client.hpp), such as
`begin_base_request_resident_reference`; they are not same-name overloads in
the production API.

Server evaluation requires a certified payload schedule, checkpoint plan,
caller-owned storage, and explicit capacity limits. The evaluation result
retains output ciphertexts separately from the replay state; proving binds the
two and consumes the replay artifacts. Failure after retirement begins is
terminal for that state. See the
[shared lifecycle and binding rules](../README.md) and
[`test_base_checkpoint_delegation.cpp`](../../../../tests/delegation/test_base_checkpoint_delegation.cpp).
