# FHE boundary

This directory is the boundary between the protocol algorithms and their
homomorphic arithmetic backend. Start with [`backend.hpp`](backend.hpp) for
the required operations and role types, then follow these three layers:

1. [`value.hpp`](value.hpp) and [`extension_value.hpp`](extension_value.hpp)
   represent a value as either public plaintext or encrypted data. Their
   helpers perform public-only work on the host and call the backend only when
   an encrypted operand is present. Structural zero therefore causes no FHE
   operation.
2. [`extension.hpp`](extension.hpp) is the canonical facade for the
   extension-field helpers used by GKR. Its implementation is grouped by
   responsibility:

   - [`extension/prepared_basis.hpp`](extension/prepared_basis.hpp) prepares
     immutable slot bases outside online record scans.
   - [`extension/accumulator.hpp`](extension/accumulator.hpp) owns sparse and
     mixed public/encrypted accumulation.
   - [`extension/arithmetic.hpp`](extension/arithmetic.hpp) implements mixed
     extension arithmetic.
   - [`extension/folding.hpp`](extension/folding.hpp) implements folding,
     rotations, interpolation, and multilinear-evaluation prefixes.
   - [`extension/packing.hpp`](extension/packing.hpp) maps fixed messages to
     and from the SIMD slot grid.
   - [`extension/io.hpp`](extension/io.hpp) decrypts and serializes extension
     ciphertexts.

   One logical extension operation can expand into several base-ciphertext
   operations.
3. A call to `Backend::*` is the raw FHE-operation boundary. The required
   interface is in [`backend.hpp`](backend.hpp). For the real backend, raw
   `SealBackend::add`, `mul`, `relinearize`, `rotate`, and modulus-switch calls
   are together in
   [`src/fhe/seal/arithmetic.cpp`](../../../src/fhe/seal/arithmetic.cpp).
   Prepared plaintext operations are in
   [`plaintext_basis.cpp`](../../../src/fhe/seal/plaintext_basis.cpp), while
   the [`SEAL source map`](../../../src/fhe/seal/README.md) points to
   context/key, persistence, coefficient-commitment, and telemetry code.

This distinction matters when reading benchmark counters: logical extension
events describe protocol work, while base ciphertext calls and their RNS-limb
counts describe the concrete FHE work.

## Roles

An `EvalContext` contains only server-side evaluation capability; decryption
remains in `ClientContext`. Packed-proof clients additionally use a
`PublicVerifierContext`. This narrow projection can parse matching ciphertexts
and perform the public coefficient encodings required by transcript packing,
but it is not an `EvalContext` and contains no public/evaluation key,
relinearization key, Galois key, encryptor, decryptor, or secret key. SEAL
persists it in a canonical key-free bundle whose decoder requires an
authenticated storage identity and explicit byte, ring-degree, and RNS-chain
limits.

## Implementations

The available implementations are:

- [`mock_backend.hpp`](mock_backend.hpp): deterministic functional execution
  and operation accounting without cryptographic security.
- [`seal_backend.hpp`](seal_backend.hpp): the optional Microsoft SEAL BGV
  backend.
- [`noise/envelope_backend.hpp`](noise/envelope_backend.hpp): replay of the
  prover topology under deterministic noise bounds.
- [`noise/honest_envelope_backend.hpp`](noise/honest_envelope_backend.hpp):
  replay under the calibrated honest-input noise model.

The Mock and noise-envelope backends preserve the same API and accounting
shape, but they do not execute cryptographic FHE. Noise estimates, RNS levels,
modulus switching, and transport compaction remain part of the shared boundary
so reports compare the same logical schedule across implementations.

## Supporting modules

The root of this directory holds the reader-facing backend and arithmetic
entry points. Supporting contracts and analyses are grouped by purpose:

- [`layout/fixed_message.hpp`](layout/fixed_message.hpp) defines fixed-message
  placement; [`layout/slot_grid.hpp`](layout/slot_grid.hpp) defines the SIMD
  slot-grid geometry.
- [`noise/deterministic.hpp`](noise/deterministic.hpp) defines exact bound
  arithmetic. The envelope backends and SEAL calibration live beside it, and
  [`noise/modulus_switch_policy.hpp`](noise/modulus_switch_policy.hpp) applies
  the bound to optional level-drop planning.
- [`storage/ciphertext.hpp`](storage/ciphertext.hpp) defines the optional
  persistent-ciphertext contract;
  [`storage/value_codec.hpp`](storage/value_codec.hpp) supplies the canonical
  `FheValue` codec used by artifacts and process messages.

## Representation and level conventions

The payload field is `Fp`; an encrypted `Fpk` value is represented by up to
eight base-field ciphertext coordinates. Public coordinates and structural
zero remain public, so the number of physical ciphertext operations depends
on which coordinates are encrypted. A ciphertext hiding zero is still private
unless an operation can establish a public result from its representation.

BGV rotations follow the shared two-row SIMD grid defined by
[`layout/slot_grid.hpp`](layout/slot_grid.hpp). They are not arbitrary cyclic
permutations of one flat slot vector. Proof-ingress modulus switching targets
the exact setup-bound RNS level; it can only move down the chain. Output
transport compaction is a separate policy and may retain multiple primes.

Backend, mixed-value, extension, serialization, and noise-envelope checks are
in [`tests/fhe/`](../../../tests/fhe/). SEAL-specific tests require the optional
SEAL build; Mock runs do not establish cryptographic FHE behavior.
