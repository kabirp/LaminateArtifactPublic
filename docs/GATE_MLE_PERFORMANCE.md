# GateMLE implementation

GateMLE authenticates the affine coefficients and constants requested by GKR.
Setup compiles the public circuit, commits its tables, and persists the server
proving key. The prover records queries during GKR and opens their ordered
batch afterward.

The construction is in Appendix C, “Affine Coefficients and Openings,”
including its “Compact representations” paragraph. This page describes
the implementation and measurement boundaries.

## Representation

Base/Folded setup composes sparse wire maps, shared plaintext masks, and slot
rotations under fixed support and work limits. Rotations remain analytic
actions and masks use a shared dictionary. Simple operations can compose into
a large coefficient table, and the supported composition rules or resource
limits may prevent setup from finding a compact description even when one
exists. In that case, the whole layer keeps its local affine program and uses
the reverse-trace adjoint argument. The chosen representation and limits are
bound by setup. Neither workload names nor expected outputs guide compilation.
Every affine layer of balancedLaned and mulHeavyPyramid composes without
internal adjoints at the canonical Wide geometries. General supported circuits
may require the more expensive fallback.

Laned uses structured sparse RS tables with a virtual lane-equality factor.
Neither representation materializes a full slot-expanded affine matrix.
Sparse evaluation reads canonical semantic entries; it does not require a
scan of the encoded PCS codeword for every query.

The Wide public index uses at most 256 columns. Its initial online column
combination reads all retained columns; subsequent folding operates over the
row domain. A complete target matrix is bound before column batching.
Setup columns use `HonestCodewordColumns`; prover-chosen adjoints use
`ArbitrarySingleColumn`. [Wide gate PCS](WIDE_GATE_SOUNDNESS.md#shared-commitments-and-deferred-claims)
records these interface requirements and their security scope.

## Persistent state and resources

The server reopens setup-produced sparse tables, codewords, and Merkle nodes
against the authenticated verifier key. Missing or incompatible state rejects
startup; the process runner requires the persisted key. Large foldable arrays
are checked canonically as read, with ordinary PCS verification authenticating
openings. The persisted data is a prover cache, not additional trusted verifier
input.

Resource admission charges persisted keys once, separate opening workspace,
and simultaneously live compiler/restoration buffers. Benchmark export uses
hard links on the commitment filesystem. Generic cross-filesystem copies
require enough space for both source and destination while they coexist.

## Source map

| Responsibility | Implementation |
| --- | --- |
| Sparse composition and representation digest | [`wide_program.cpp`](../src/gates/wide_program.cpp) |
| Sparse tables and public-index layout | [`canonical_tables.cpp`](../src/gates/canonical_tables.cpp), [`canonical_layout.cpp`](../src/gates/canonical_layout.cpp) |
| Prover-key persistence and reopening | [`prover_key_storage.cpp`](../src/gates/prover_key_storage.cpp) |
| Adjoint grouping and public openings | [`wide_opening.cpp`](../src/gates/wide_opening.cpp) |
| APIs and test inventory | [GateMLE module guide](../include/laminate/gates/README.md) |
| Structural planning and measurements | [Gate-only benchmark guide](../benches/gates/README.md) |

The gate-only diagnostic reports structural bounds without building
commitments, or measures setup, query preparation, openings, and verification
in its materializing modes. Setup and online work are separate. Full server
cost additionally includes payload FHE, storage, and proof composition;
use a completed protocol benchmark for that measurement.
