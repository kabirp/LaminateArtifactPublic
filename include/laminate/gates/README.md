# Gate MLEs

This directory supplies affine gate multilinear extensions to GKR. The setup
profile selects direct evaluation or openings of committed gate tables.
Multiplication uses the structural dense relation and requires no GateMLE
opening.

| Entry point | Responsibility |
| --- | --- |
| [`gate_mle.hpp`](gate_mle.hpp) | Query types, direct evaluation, and prepared sparse evaluation |
| [`canonical_tables.hpp`](canonical_tables.hpp) | Canonical table representation |
| [`outsourced.hpp`](outsourced.hpp) | Query collection and composed gate openings |
| [`wide_program.hpp`](wide_program.hpp) | Bounded affine composition and Wide representation selection |
| [`wide_opening.hpp`](wide_opening.hpp) | Wide operator and adjoint authentication |
| [`sparse_product.hpp`](sparse_product.hpp) | Sparse operator evaluation reductions |
| [`setup/gate_mle.hpp`](../setup/gate_mle.hpp) | Deterministic setup and persisted opening state |

`Direct` evaluates the layered circuit locally. `DummyCommittedDirect` binds
transcript-shape digests only and is a diagnostic, not a polynomial commitment.
`OutsourcedBaseFold` dispatches by payload geometry: Laned uses sparse wire
coefficients with RS BaseFold openings; Wide Base/Folded uses the foldable
commitment implementation.

## Wide representations and openings

[`wide_program.hpp`](wide_program.hpp) attempts exact sparse composition under
explicit work and storage limits. Successful composition produces boundary
operators without internal nodes. Otherwise, the representation retains the
local affine DAG and uses challenge-dependent adjoints. Both paths enforce
the same verification contract; the setup digest binds the selected
representation and its limits.

[`wide_opening.hpp`](wide_opening.hpp) composes operator, action, and
masked-action reductions with [`basefold/foldable.hpp`](../basefold/foldable.hpp).
It owns grouping, transcript binding, and terminal operand checks. Its
resource declarations include the bounded-buffer disk arrays used for
adjoints and folding. Bounded memory does not imply small running time:
retained DAGs still require node-by-slot work and online commitments.

For the security-analysis entry points, see the
[Wide gate policy map](../../../docs/WIDE_GATE_SOUNDNESS.md).

## Setup and verification boundary

Production setup persists server-only opening state. Reopening authenticates
it against public setup without rebuilding commitments. Reference callers
without a persisted directory reconstruct deterministic state from the
compiled circuit.

The verifier must use authenticated setup roots and geometry. A root supplied
with an online proof does not establish that it represents the intended
circuit. Wire versions, query policies, and representation limits are defined
in the source headers rather than selected by the prover.

Direct/outsourced comparisons and malformed-claim tests are in
[`tests/gates/`](../../../tests/gates/). The
[BaseFold module guide](../basefold/README.md) covers the opening API boundary.
