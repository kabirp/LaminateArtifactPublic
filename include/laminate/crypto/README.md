# Poseidon ciphertext commitments

Poseidon binds the normalized ciphertexts used by transcript packing. The host
hash and the packing R1CS use the same permutation parameters and encoding.
The fixed profile in [`params.hpp`](../params.hpp) has width 16, rate 10,
and six field elements in both its capacity and digest. The permutation uses
the `x^5` S-box in 8 full and 25 partial rounds. The
[parameter check](../../../tests/crypto/check_poseidon_parameters.py) validates
the round-selection conditions. Section H.2, “Integrity Parameters,” assumes
collision advantage at most
`W^2/q^6`, where `q = 1,053,858,393,162,252,289`, for work `W <= 2^125`,
including the reduction's extraction and simulation. This assumption enters
the paper's conditional integrity bound; parameter checks and known-answer
tests do not prove it.

[`poseidon.hpp`](poseidon.hpp) exposes the permutation, sponge, and canonical
field encoding. The
[implementation](../../../src/crypto/poseidon.cpp) derives round constants
from the 80-bit Grain generator and builds a Cauchy MDS matrix from the same
stream. Both depend only on public parameters.

`poseidon_hash` embeds bytes in seven-byte chunks. `poseidon_hash_fields`
accepts native field elements. Both bind the domain, logical length, element
count, and encoding version in the capacity, and append a rate delimiter.
The packing gadget uses the native-field interface for the normalized
ciphertext metadata and coordinates. Its implementation is in
[`poseidon_template.hpp`](../packing/proof/detail/poseidon_template.hpp).
The commitment policy is `poseidon/v2`.

Fiat–Shamir statement binding uses SHA-256; PCS Merkle trees use BLAKE2b-320.
The paper models these as independent random oracles, also independent of
the Poseidon ciphertext hash.
Their implementations are under
[transcript](../transcript/README.md) and [BaseFold](../basefold/README.md).
The [transcript tests](../../../tests/transcript/test_transcript.cpp) pin
Poseidon known-answer vectors, including inputs around sponge-rate boundaries;
packing tests separately check the matching arithmetic relation.
