# Alternating layering

The paper defines the alternating circuit and dense operand layout in
Section 5.1.1, “Class of Supported Payload Circuits,” and Section 5.1.2,
“Data Layout and Notation.” This guide locates the compiler conventions
used by the artifact.

| Responsibility | Source |
| --- | --- |
| Payload construction and validation | [`payload/circuit.hpp`](../include/laminate/payload/circuit.hpp) |
| Compiler API | [`payload/compiler.hpp`](../include/laminate/payload/compiler.hpp) |
| Lowering, forwarding, and padding | [`src/payload/compiler.cpp`](../src/payload/compiler.cpp) |
| Layer and gate representation | [`payload/ir/layered.hpp`](../include/laminate/payload/ir/layered.hpp) |
| Evaluation and storage entry points | [Payload module](../include/laminate/payload/README.md) |
| Layer reductions | [GKR module](../include/laminate/gkr/README.md) |

## Layer order and operation classes

Layers use GKR's output-to-input order. A payload of CT-CT multiplication depth
D has `2D + 2` value layers, from the output affine layer to the inputs.
Only `Mul` creates a multiplication boundary. Additions and plaintext products
belong to affine layers; Wide also admits rotations and slot-varying plaintext
multipliers. The separate FHE half-depth statistic charges plaintext products
because affine operations can consume ciphertext noise budget.

Wide affine layers retain a local operation graph, including the order of
rotations and plaintext masks. Laned layers combine affine paths into sparse
source coefficients. The compiler preserves shared nodes and validates each
layout's permitted operations.

## Logical layout and physical storage

A payload wire contains N scalar slots for Wide or B independent values for
Laned. Logical wire count, padded proof-domain size, and physical ciphertext
record count are separate quantities.

`LayerStorageLayout` maps equal operand recipes to one physical record.
Evaluation computes each record once; proof readers resolve every logical
occurrence through its alias. Structural zero padding remains virtual, while
live public constants use plaintext tags. Neither requires an encrypted zero
record.

Values that cross multiplication boundaries receive forwarding gates. These
represent identity products with public one and are evaluated without a
ciphertext multiplication. Each gate is tagged `Payload`, `Forward`, or
`Padding`, so reports separate compiler overhead from payload operations.
Laned padding also satisfies the packing geometry required by the GKR source
adapters.

## Trace provenance and validation

The synthetic reference path evaluates the clear payload and layered circuit,
checks their relation, and compares outputs before encryption. Its compact
encryptor accepts only `SyntheticTrace` provenance. Real FHE evaluation starts
from encrypted inputs and produces a distinct evaluated trace.

The compiler validates the payload and final layered circuit.
`validate_compilation_pair(...)` recompiles and compares canonical encodings
when restoring an externally supplied layered artifact. See
[`tests/payload/`](../tests/payload/) for compilation, forwarding, padding,
and evaluation parity checks. Cryptographic soundness is a separate property
of the proof protocol.
