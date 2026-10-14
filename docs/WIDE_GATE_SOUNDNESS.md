# Wide gate PCS policy

Base/Folded affine openings use generic foldable codes over `Fpk=F_{65537^8}`.
The paper gives the construction in Appendix C, “Affine Coefficients and
Openings,” and its numerical policy in Section H.2, “Integrity Parameters.”

| Setting | Value |
| --- | --- |
| Code rate | 1/8 |
| Default query paths | 300 |
| Maximum message variables | 40 |
| Local interactive PCS RBR bound | `2^-112` |
| Shared hierarchy setup-failure bound | `2^-123` |

These local bounds assume the specified setup model and verified transparent
operands. Section H.2, “Integrity Parameters,” combines them with the
authentication, extraction, and Fiat–Shamir terms in the paper's conditional
`2^-50` benchmark bound; [Status](STATUS.md#parameters-and-security-assumptions)
summarizes its assumptions. Laned gates and packing use the
[RS policy](BASEFOLD_SOUNDNESS.md).

## Shared commitments and deferred claims

[`wide_opening.cpp`](../src/gates/wide_opening.cpp) implements the
`wide-local-adjoint-foldable` strategy. Boundary-only layers need no adjoint
commitment. For a local-program fallback, requests at the same layer/output
point share one adjoint. Equal-sized adjoints form groups of one, two, or four,
with at most `2^32` total entries; larger individual adjoints remain singletons.
The group message is concatenated before encoding.

Group roots, dimensions, members, and targets precede residual challenges.
Every member retains its local checks. Pending public-operator claims are
discharged by the final public-index opening. The verifier reconstructs exact
group membership and operands from the ordered queries.

The public index has at most 256 honestly encoded columns and one interleaved
Merkle root. Setup binds dimensions and the canonical block map. The proof
binds every public-column evaluation against every derived row operand before
sampling column weights; local sparse claims must match this complete matrix.
The verifier also evaluates the transparent block selectors and equality
operands. Decode limits include the full matrix.

`HonestCodewordColumns` applies only to setup-encoded public columns.
Prover-chosen adjoints use one arbitrary column with weight one; the interface
does not claim proximity preservation for multiple malicious columns.
`verify()` returns operand evaluations that its caller must independently
check. See the [PCS interface](../include/laminate/basefold/foldable.hpp).

## Hierarchy and encoding

The RS base supports `2^13` message entries. Larger messages use the universal
versioned hierarchy, with fixed domain-separated `(level,index)` addresses.
Its nonzero diagonals are sampled in the full extension field by unbiased
rejection sampling. SHA-256 instantiates the ideal random oracle assumed by
the distance analysis. There is no caller-selected seed or setup retry; this
is not an unconditional statistical claim about SHA-256.

The encoder uses LSB-first variables. It recursively splits Boolean values
into even entries and `odd-even`, applying the Möbius transform at the RS base.
The exact encoding and transcript order are in
[`foldable.cpp`](../src/basefold/foldable.cpp).

## Query admission and integer certificate

[`foldable_query_policy.cpp`](../src/basefold/foldable_query_policy.cpp)
selects the shape-specific minimum. Explicit counts must meet that minimum
and be at most 65,536; zero is rejected. The count is transcript-bound and
enters decoder limits. Query paths are independent draws with replacement in
one challenge block; Merkle deduplication preserves that distribution.

[`check_foldable_query_certificate.py`](../tests/basefold/check_foldable_query_certificate.py)
checks every hierarchy prefix and query-table entry with exact integer
arithmetic, including the folding, terminal-query, and shared setup bounds.
The distance recurrence and weighted-state proof are in the “Numerical
bounds” paragraph of Section H.2, “Integrity Parameters.” No floating-point estimate enters admission.

## Storage and wire boundary

Encoding, folding, and Merkle levels use disk arrays with bounded buffers.
Resource bounds include simultaneously live retained and temporary files;
caller-owned operands and witness sources are additional charges. Admission
of a shape does not imply it fits a particular host or has been benchmarked.
See [`foldable_storage.hpp`](../include/laminate/basefold/foldable_storage.hpp).

Proofs use canonical union-frontier multiproofs. Query positions are derived
from the transcript; missing, duplicate, extra, or noncanonical data is
rejected. The decoder checks dimensions and byte caps before allocation,
canonical field values, and trailing bytes. Canonical parsing is not protocol
acceptance. The encoding is in
[`foldable_io.cpp`](../src/basefold/foldable_io.cpp); the
[GateMLE guide](GATE_MLE_PERFORMANCE.md) describes integration and cost.
