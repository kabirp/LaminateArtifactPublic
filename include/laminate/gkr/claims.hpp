#ifndef LAMINATE_GKR_CLAIMS_HPP
#define LAMINATE_GKR_CLAIMS_HPP

/// @file claims.hpp
/// @brief Standard one- and two-point GKR layer claims.

#include "laminate/fhe/layout/slot_grid.hpp"
#include "laminate/field/fpk.hpp"
#include "laminate/transcript/transcript.hpp"

#include <span>
#include <string_view>
#include <variant>
#include <vector>

namespace laminate::gkr {

/// Reporting identity of the dense multiplication-to-source transition.
inline constexpr std::string_view kGkrClaimTransition =
    "selector-interpolation-v1";

/// Multiplication messages and terminal check, independent of claim transition.
inline constexpr std::string_view kGkrMultiplicationReduction =
    "gruen-stripped-h0-v1";

/// Claim that the current layer MLE evaluates to `value` at `point`.
struct SingleClaim {
    std::vector<Fpk> point;
    Fpk value = Fpk::zero();

    bool operator==(const SingleClaim &) const = default;
};

/// Standard random linear combination of two claims about the same layer:
///     value = first.value + challenge * second.value.
/// Generic affine-query batching utility. Whole GKR layer transitions use
/// SingleClaim: multiplication endpoints share all coordinates except the
/// selector, so they are interpolated into one evaluation claim instead.
struct BatchedClaim {
    SingleClaim first;
    SingleClaim second;
    Fpk challenge = Fpk::zero();
    Fpk value = Fpk::zero();

    bool operator==(const BatchedClaim &) const = default;
};

using LayerClaim = std::variant<SingleClaim, BatchedClaim>;

/// Observe one claimed evaluation as a proof message. The point is included
/// even when it was transcript-derived, preventing dimension/order misuse.
void observe_claim(const SingleClaim &claim, Transcript &transcript);

/// Observe both component claims, sample the batching challenge, and return
/// their standard linear combination. Component point dimensions must match.
BatchedClaim batch_claims(const SingleClaim &first, const SingleClaim &second,
                          Transcript &transcript);

/// Evaluate an [MSB wire-index | MSB slot-index] layer MLE without flattening
/// it into a second full table. Wire count and slot width must be powers of two.
Fpk evaluate_layer_mle(std::span<const fhe::SlotVector> layer,
                       std::span<const Fpk> point);

/// Evaluate a compact logical input in the zero-padded prefix of an MLE table.
///
/// Arguments:
/// - `logical_input` is one plaintext for a wide/Folded computation, or one
///   base-field element per lane for a Laned computation.
/// - `point` indexes the full table containing `logical_input` followed by
///   zero padding.
///
/// Preconditions: `logical_input.size()` is a nonzero power of two, and
/// `point` has at least `log2(logical_input.size())` coordinates.
/// Postcondition: returns the full zero-padded table MLE while reading exactly
/// `logical_input.size()` base-field values.
Fpk evaluate_prefix_input_mle(std::span<const Fp> logical_input,
                              std::span<const Fpk> point);

SingleClaim make_layer_claim(std::span<const fhe::SlotVector> layer,
                             std::vector<Fpk> point);

/// Plaintext terminal input check. The batched form checks the combined claim
/// directly; it also checks that its recorded component values produce the
/// recorded combined value under the transcript challenge.
bool verify_terminal_claim(std::span<const fhe::SlotVector> input_layer,
                           const SingleClaim &claim);
bool verify_terminal_claim(std::span<const fhe::SlotVector> input_layer,
                           const BatchedClaim &claim);
bool verify_terminal_claim(std::span<const fhe::SlotVector> input_layer,
                           const LayerClaim &claim);

/// Check a claim against a compact input followed by implicit zero padding.
bool verify_prefix_input_claim(std::span<const Fp> logical_input,
                               const SingleClaim &claim);
bool verify_prefix_input_claim(std::span<const Fp> logical_input,
                               const BatchedClaim &claim);
bool verify_prefix_input_claim(std::span<const Fp> logical_input,
                               const LayerClaim &claim);

} // namespace laminate::gkr

#endif // LAMINATE_GKR_CLAIMS_HPP
