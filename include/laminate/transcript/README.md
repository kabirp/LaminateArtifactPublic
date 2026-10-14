# Transcripts and public coins

This directory implements the SHA-256 Fiat–Shamir transcript used to turn
Laminate's public-coin protocols into noninteractive proofs.

[`hash.hpp`](hash.hpp) provides the fixed SHA-256 digest and canonical byte
helpers. [`transcript.hpp`](transcript.hpp) binds typed protocol messages and
derives field challenges. [`public_coin.hpp`](public_coin.hpp) is the narrower
challenge interface used by Spartan, its factored matrix argument, and
BaseFold. `PublicCoin` itself is hash-agnostic; `Transcript` supplies the
SHA-256 implementation used by the noninteractive composition.

Each transcript begins with a domain label. Observations bind labels and
length-prefixed values; challenge sampling absorbs pending observations into
the rolling hash state. Field elements are drawn by rejection sampling from
a counter-mode stream. Prover and verifier must observe the same canonical
bytes in the same order before each challenge. For encrypted GKR those bytes
encode ciphertexts, not their decrypted plaintexts.

The transcript does not select or authenticate the public setup for its
caller. Each composing protocol binds its setup, statement, and commitments
at the appropriate boundary. The observation and challenge behavior is
covered by [`tests/transcript/test_transcript.cpp`](../../../tests/transcript/test_transcript.cpp).

The Poseidon hashes inside the packing R1CS live in [`../crypto/`](../crypto/).
BaseFold Merkle trees use BLAKE2b-320; their roots are bound into the
SHA-256 transcript before challenges are sampled.
