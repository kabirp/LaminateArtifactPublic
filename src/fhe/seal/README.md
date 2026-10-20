# Microsoft SEAL backend implementation

The public `SealBackend` contract is declared in
[`include/laminate/fhe/seal_backend.hpp`](../../../include/laminate/fhe/seal_backend.hpp).
This directory implements that contract using Microsoft SEAL BGV. The shared
[FHE guide](../../../include/laminate/fhe/README.md) explains the public/encrypted
value and extension-field layers above these raw backend operations.

| Question | File |
| --- | --- |
| Where are raw BGV add, multiply, relinearize, rotate, and modulus-switch calls? | [`arithmetic.cpp`](arithmetic.cpp) |
| Where are public plaintext operations and prepared slot bases? | [`plaintext_basis.cpp`](plaintext_basis.cpp) |
| Where are parameters, contexts, and keys constructed? | [`context.cpp`](context.cpp) |
| Where are evaluation/client/verifier contexts persisted? | [`context_bundle.cpp`](context_bundle.cpp) |
| Where are protocol and trace ciphertexts encoded? | [`ciphertext_codec.cpp`](ciphertext_codec.cpp) |
| Where are coefficient commitments and partial decryption evaluated? | [`coefficient_commitment.cpp`](coefficient_commitment.cpp) |
| Where are operation counts and modulus/noise metadata reported? | [`telemetry.cpp`](telemetry.cpp) |

`state.hpp`, `context_internal.hpp`, `arithmetic_internal.hpp`, and
`binary_codec.hpp` are private boundaries shared by the compilation units.
They do not add to the public backend API.

Context identity binds the exact RNS prime chain and parameter descriptors,
not just requested prime bit widths. Evaluation, client, and public-verifier
bundles are separate capabilities: the evaluation context has no decryptor,
and the public-verifier bundle contains parameter/encoding state without
secret or evaluation keys. Restoring a bundle requires the expected storage
identity and explicit decode limits.

The packing coefficient interface requires a size-two, one-prime, NTT-form
ciphertext and normalizes its BGV correction factor. These public coefficient
encodings are distinct from ordinary ciphertext transport bytes; their
normalization is checked before a packing commitment is constructed.

Arithmetic and role-bundle checks are in
[`test_seal_backend.cpp`](../../../tests/fhe/test_seal_backend.cpp) and
[`test_seal_context_bundle.cpp`](../../../tests/fhe/test_seal_context_bundle.cpp).
Build this directory through the project's optional SEAL configuration rather
than compiling individual implementation files.
