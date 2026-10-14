# Protocol implementation map

LaminateBase, LaminateFolded, and LaminateLaned share payload compilation and
BGV evaluation. Their GKR and message-transport paths are separate.
[Architecture](ARCHITECTURE.md) describes the application flow; this page
connects the paper's protocols to their implementations.

## Paper references

References below identify sections of the accompanying *Laminate* paper.

| Construction | Paper reference |
| --- | --- |
| Base and Folded | Section 5.2, “Base and Folded BhIPs”; Appendix D, “Layer Reductions for Wide Payload Circuits” |
| Laned | Section E.3, “Layer Reductions” |
| Affine openings | Appendix C, “Affine Coefficients and Openings” |
| Packing | Section 6.1, “Transcript Packing Compiler” |

## Code reading path

| Concern | Base | Folded | Laned |
| --- | --- | --- | --- |
| Whole-proof API | [`base.hpp`](../include/laminate/protocol/base.hpp) | [`folded.hpp`](../include/laminate/protocol/folded.hpp) | [`laned.hpp`](../include/laminate/protocol/laned.hpp) |
| Client/server roles | [`delegation/base/`](../include/laminate/delegation/base/) | [`delegation/folded/`](../include/laminate/delegation/folded/) | [`delegation/laned/`](../include/laminate/delegation/laned/) |
| GKR traversal | [`base/prover.hpp`](../include/laminate/gkr/detail/base/prover.hpp) | [`folded/prover.hpp`](../include/laminate/gkr/detail/folded/prover.hpp) | [`laned/prover.hpp`](../include/laminate/gkr/detail/laned/prover.hpp) |
| GKR verification | [`base/verifier.hpp`](../include/laminate/gkr/detail/base/verifier.hpp) | [`folded/verifier.hpp`](../include/laminate/gkr/detail/folded/verifier.hpp) | [`laned/verifier.hpp`](../include/laminate/gkr/detail/laned/verifier.hpp) |

The [GKR module guide](../include/laminate/gkr/README.md) maps affine and
multiplication kernels. The process benchmarks use checkpoint replay and bounded
file-backed sources. Packed composition enters
[`external/prover.hpp`](../include/laminate/protocol/packed/external/prover.hpp);
bounded resident comparison APIs live under
[`protocol/reference/`](../include/laminate/protocol/reference/).

## Implementation conventions

| Convention | Executable choice |
| --- | --- |
| Fields | `Fp`: BGV plaintext field, `p=65,537`; `Fpk`: degree-eight GKR extension; `Fq`: packing field, `Q=1,053,858,393,162,252,289`; `Fq2`: quadratic packing-proof challenge field |
| MLE addresses | MSB-first: Wide `[ciphertext index | slot]`, Laned `[packed-ciphertext index | chunk | lane]`; gate PCS adapters convert to BaseFold's LSB-first order |
| Slots and placement | Two-row BGV grid; packed messages occupy setup-fixed disjoint cosets |
| Affine GateMLE | Base/Folded: `wide-local-adjoint-foldable`; Laned: `structured-sparse-basefold` |
| Laned language | Uniform plaintext multiplication and lane-varying public addition; rotations and nonuniform multiplication are rejected |
| Multiplication | Dense CT–CT wiring with no GateMLE opening; one claim passes between layers by selector interpolation |

Normalizing a ciphertext to `Q` leaves its plaintext field unchanged. Logical
wire occurrences may alias a physical ciphertext record. The
[layering guide](LAYERING.md) describes these compiler/storage conventions;
[GateMLE](GATE_MLE_PERFORMANCE.md) describes affine preprocessing.

### Encrypted-source contract

Each encrypted proof source has an exact setup-bound RNS level. Repeated scans
reuse that source without another switch. Public zero and padding have no
ciphertext; hidden zero inputs remain encrypted. Extension values retain
public/encrypted tags per coordinate. These tags affect physical arithmetic
and wire size, so logical value counts are not ciphertext counts.

The source adapters and resource limits are in the
[GKR module](../include/laminate/gkr/README.md). Fixed ingress levels and the
limits of the noise model are in [BGV parameters](BGV_NOISE_AND_MODULUS_SWITCHING.md).

### One Fiat–Shamir transcript for the packed protocols

`single-transcript-gkr-then-packing-v1` binds GKR, gate openings, and packing
in one transcript. Public replay authenticates gate claims and records GKR
challenges. Packing continues that transcript; the client checks recovered
GKR arithmetic with the recorded challenges. Rejection leaves the caller's
transcript unchanged. See [packing verification order](TRANSCRIPT_PACKING.md#relation-and-proof-flow)
and [`gkr_transcript_replay.hpp`](../include/laminate/protocol/detail/packing/gkr_transcript_replay.hpp).

## LaminateBase

Base transports tagged extension-field messages directly and leaves the slot
relation to the client. Its affine terminal's `PartialGateMleVector` is bound
before a random slot challenge and authenticated with one full GateMLE query.
The delegated roles bind the encrypted output and request/setup/session
identities before deriving the output point; the server receives no plaintext
output-MLE claim.

## LaminateFolded

Folded encodes each two-element round message into a fixed slot-sparse cell.
Slot rounds use fixed operand checkpoints rather than feeding a round's
ciphertext into the next round. Its packed response carries committed GKR
messages, well-formedness reveals, digit outputs, and the packing proof.
Aligned ciphertext coordinates remain private witness data.

## LaminateLaned

Laned uses the same packed response boundary with lane-aware source adapters.
Affine sources are lane-weighted; multiplication sources are not. The affine
prover and verifier share deterministic resampling for singular lane challenges
and the terminal change of point. See Section E.3.1, “Affine Layer Reduction,”
and the
[Laned kernels](../include/laminate/gkr/detail/laned/).

## Validation and security scope

The [GKR tests](../tests/gkr/), [delegation tests](../tests/delegation/), and
[protocol tests](../tests/protocol/) cover reductions, binding, serialization,
and real-backend bounded execution. [Cryptographic primitives](../include/laminate/crypto/README.md)
identifies hash roles; decoders bind and validate the selected wire formats.
These tests do not establish honest-noise tails or the paper's extraction
assumptions. [Status](STATUS.md) states the scope of the artifact's claims.
