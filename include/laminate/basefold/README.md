# BaseFold gate-table proof

This module supplies the polynomial commitments used by
[outsourced gate MLEs](../gates/README.md). Laned gate tables use the RS path
with `Fp` columns and `Fpk` claims. Wide Base/Folded tables use the generic
foldable-code path over `Fpk`. Transcript packing uses a separate
[`spartan/basefold_pcs.hpp`](../spartan/basefold_pcs.hpp) interface over `Fq`
and `Fq2`; these proof types are not interchangeable.

| Path | Entry points | Supporting code |
| --- | --- | --- |
| RS gate tables | [`basefold.hpp`](basefold.hpp) | [`commitment.hpp`](commitment.hpp), [`sumcheck.hpp`](sumcheck.hpp), [`folding.hpp`](folding.hpp), [`query.hpp`](query.hpp) |
| Wide foldable tables | [`foldable.hpp`](foldable.hpp) | [`foldable_query_policy.hpp`](foldable_query_policy.hpp) |
| Encoding and authentication | [`proof_io.hpp`](proof_io.hpp) | [`merkle.hpp`](merkle.hpp) |

Callers must bind commitment metadata, weights, and targets into their
`PublicCoin` before proving or verifying. Generic verification returns
residual operand claims; the composing protocol must discharge them.
`prove_blocks` and `verify_blocks` handle aligned transparent block operands
and check their terminal values directly. Setup commitments must be derived
from, or authenticated against, the intended circuit.

[`common.hpp`](common.hpp) uses **least-significant-bit-first** multilinear
points. The generic [`poly/`](../poly/README.md) helpers use the opposite
order, so conversions must be explicit. RS tables larger than the supported
field domain are sharded by the gate-table layer. Wide foldable commitments
use bounded disk arrays and canonical Merkle multiproofs.

Query defaults, supported dimensions, and parameter checks live in the
corresponding headers. The [BaseFold policy map](../../../docs/BASEFOLD_SOUNDNESS.md)
and [Wide gate policy map](../../../docs/WIDE_GATE_SOUNDNESS.md) identify the
security-analysis code. Their local bounds do not establish the complete
VCoED/Fiat–Shamir composition.

Correctness and malformed-proof tests are in
[`tests/basefold/`](../../../tests/basefold/).
