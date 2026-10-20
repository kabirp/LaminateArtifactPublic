# Protocol layer

This directory composes encrypted GKR and, for Folded/Laned, transcript
packing. The [delegation APIs](../delegation/README.md) connect client requests,
server evaluation, and response verification. These lower-level prover APIs
take an evaluated payload and an output evaluation point. Only verification
requires the expected plaintext output claim.

## Entry points

| Variant | Additional setup | Production prove | Bounded reference | Verify |
| --- | --- | --- | --- | --- |
| Base | none | Checkpoint/replay [`prove_base`](base.hpp); process wrapper [`delegation::prove_base_response_irreversible`](../delegation/base/server.hpp) | [`reference::prove_base`](reference/base.hpp) | [`verify_base`](base.hpp) |
| Folded | [`setup_folded_conservative`](packed/setup.hpp) | [`delegation::prove_folded_response_irreversible`](../delegation/folded/server.hpp) | Resident and file/checkpoint comparators in [`reference/folded.hpp`](reference/folded.hpp) | [`verify_folded`](folded.hpp) |
| Laned | [`setup_laned_conservative`](packed/setup.hpp) | [`delegation::prove_laned_response_irreversible`](../delegation/laned/server.hpp) | Resident and file/checkpoint comparators in [`reference/laned.hpp`](reference/laned.hpp) | [`verify_laned`](laned.hpp) |


Base proving reaches [`detail/base/api_impl.hpp`](detail/base/api_impl.hpp).
Packed production proving reaches
[`packed/external/prover.hpp`](packed/external/prover.hpp) through the delegation
server APIs. Resident transcript-packing paths are bounded reference APIs.

| Directory | Responsibility |
| --- | --- |
| [`setup/`](setup/) | Base client certification |
| [`packed/`](packed/) | Packed setup, roles, external proving, and wire decoding |
| [`storage/`](storage/) | Persistent artifacts and capacity contracts |
| [`analysis/`](analysis/) | Offline completeness and prerequisite analysis |
| [`metrics/`](metrics/) | Timing, proof-size, and profiling tools |
| [`reference/`](reference/) | Bounded comparisons and diagnostics |
| [`detail/`](detail/) | Template bodies and private composition |

## Setup and proof-ingress policy

[`setup.hpp`](../setup.hpp) constructs the common public setup and FHE roles;
see the [setup guide](../setup/README.md). Base uses `make_evaluation_setup`.
Folded/Laned use `make_packed_evaluation_setup` and additional packing setup.

Routine setup binds a versioned proof-ingress schedule to the public circuit
and setup identity. Base's uniform policy is defined in
[`honest_noise_schedule.hpp`](../payload/noise/honest_noise_schedule.hpp).
Packed policies and their validation are defined in
[`packed/setup/proof_ingress.hpp`](packed/setup/proof_ingress.hpp).
The [process profiles](../bench/packed_process_profile.hpp) select the policy
and exact parameter chain for each workload; Folded policy selection is
profile-specific.

Schedule derivation alone does not establish noise completeness or parameter
minimality. Offline selectors are calibration tools, and setup preflight
checks do not replace full client verification. The production setup facade
does not expose uniform-level test fixtures.

## Encrypted GKR source contract

GKR consumes live-only public-or-encrypted snapshots. Encrypted values must
match the setup-bound RNS level; public values have no level. Structural
padding is public zero with no ciphertext record. Repeated scans reuse the
same snapshot. The [GKR guide](../gkr/README.md) maps the variant kernels and
bounded reference paths.

Checkpoint replay retains selected layers and recomputes omitted relations
within admitted disk and memory budgets. Sources are retired after their
last use. Failure after retirement begins is terminal for that online state;
persistent preprocessing has a separate reusable lifecycle.

## Persistent Base setup

[`storage/base_preprocessing.hpp`](storage/base_preprocessing.hpp) binds public
setup and circuit digests to the server and client SEAL state identities.
Shared metadata, server material, and client-secret material occupy disjoint
caller-owned directories. Each opener validates shared metadata and only its
own role state. The record does not serialize prepared caches or active replay
state. Its root identity must be authenticated by the deployment; a file
checksum is not a signature.

## Persistent packed setup

[`storage/packed_preprocessing.hpp`](storage/packed_preprocessing.hpp) defines
the relocatable Folded/Laned role envelope. Setup publishes a shared workload,
each role's static data and artifact tree, then the shared root manifest.
Manifests bind relative paths, exact sizes, digests, semantic identity, workload,
and role without copying artifact trees or serializing absolute paths.

Decoding and tree scans have explicit resource limits. Symlinks, multiply linked
files, unexpected entries, and overlapping roots are rejected. Each role opener
accepts its own root and the shared root only.

[`packed/preprocessing/client_static.hpp`](packed/preprocessing/client_static.hpp)
authenticates the client capability;
[`packed/online/server.hpp`](packed/online/server.hpp) owns the server's certified
setup, replay geometry, external prover setup, and GKR source plans. Recurring
APIs consume these capabilities. Request, capacity, trace, and retirement
checks remain online.

## Packed proof composition

[`packed/external/prover.hpp`](packed/external/prover.hpp) composes checkpoint
replay, encrypted GKR, reveal/assignment construction, and artifact-backed
Spartan. One-shot work-tree and packing/replay admission belong to per-request
server work, even if reserved before a request arrives. The bounded counterpart
is [`resident_transcript_packing.hpp`](detail/packing/resident_transcript_packing.hpp).

[`fiat_shamir.hpp`](fiat_shamir.hpp) defines the continuing transcript schedule.
The verifier's [public replay](detail/packing/gkr_transcript_replay.hpp)
authenticates gate openings and records challenges before plaintext recovery.
Packing, noise, and recovered-plaintext checks must all pass. Only an accepted
whole proof advances the caller's transcript.

## Proof transport and measurement

[`metrics/profiling.hpp`](metrics/profiling.hpp) instruments the same protocol
APIs; [`metrics/proof_size.hpp`](metrics/proof_size.hpp) measures canonical
encodings. [`packed/wire/proof.hpp`](packed/wire/proof.hpp) decodes setup-shaped
proofs under explicit bounds. Nested openings are length-framed and parsed by
their owning verifier; source codecs define canonical formats and versions.

Successful decoding establishes framing, not acceptance. Verification still
requires authenticated setup and request bindings. The outer delegation codec
also binds the response envelope and ciphertext storage context.

Composition, storage, and admission tests are in
[`tests/protocol/`](../../../tests/protocol/), including
[`test_transcript_packing_external.cpp`](../../../tests/protocol/test_transcript_packing_external.cpp).
Execution instructions are in the [benchmark guide](../../../docs/BENCHMARKING.md).
