# Finite fields

Laminate uses two prime fields and two extension fields. Their parameters are
fixed in [`params.hpp`](../params.hpp), rather than selected at runtime.

| Type | Definition | Role | Encoded bytes |
| --- | --- | --- | --- |
| [`Fp`](fp.hpp) | Prime field with `p = 65,537` | Payload values and BGV plaintext slots | 3 |
| [`Fpk`](fpk.hpp) | `Fp[X] / (X^8 + X^3 + 1)` | Encrypted GKR and gate-table opening challenges | 24 |
| [`Fq`](fq.hpp) | Prime field with `q = 1,053,858,393,162,252,289` | Final BGV coefficient prime, packing R1CS, Poseidon, and Spartan tables | 8 |
| [`Fq2`](fq2.hpp) | `Fq[u] / (u^2 - 7)` | Spartan and its BaseFold opening challenges | 16 |

[`serialization.hpp`](serialization.hpp) defines the canonical encodings:
prime-field words are little-endian, and extension coefficients appear in
increasing degree order. Decoders reject incorrect lengths and noncanonical
residues. Constructors can reduce integers modulo the field order; wire
decoding deliberately does not accept those alternate encodings. `Fq` uses
Montgomery arithmetic internally, but its public `value()` and serialization
return canonical residues.

[`fq_ntt.hpp`](fq_ntt.hpp) and
[`fq_transform_kernels.hpp`](fq_transform_kernels.hpp) provide transforms for
the outer-field proof artifacts. `Fp` supports roots through order `2^16`;
`Fq` supports roots through order `2^37`.

The `random_element()` helpers use a standard-library pseudorandom generator.
Protocol challenges come from [`transcript/`](../transcript/README.md), and
client session entropy is supplied through the delegation APIs.

Arithmetic, serialization, and transform checks are in
[`tests/field/`](../../../tests/field/).
