#ifndef LAMINATE_GATES_MASKED_ACTION_HPP
#define LAMINATE_GATES_MASKED_ACTION_HPP

/// Local plaintext multiplication is diagonal in slots. For fixed row/source
/// wire points its gate coefficient is sum_{a,s} W(a) P(a,s) eq(r,s) eq(t,s).
/// Two quadratic sumchecks reduce this to W(alpha) and P(alpha,beta). The
/// composing protocol must authenticate those two public-table evaluations.

#include "laminate/gates/quadratic_product.hpp"

namespace laminate::gates {

struct MaskedActionProof {
    QuadraticProductProof masks;
    QuadraticProductProof slots;
    bool operator==(const MaskedActionProof &) const = default;
};

struct MaskedActionReduction {
    std::vector<Fpk> mask_point_msb;
    std::vector<Fpk> slot_point_msb;
    Fpk mask_weight = Fpk::zero();
    Fpk plaintext = Fpk::zero();
};

struct MaskedActionOutput {
    MaskedActionProof proof;
    MaskedActionReduction reduction;
};

/// MLE of the pointwise product of two Boolean equality tables. This is not
/// generally equal to eq(left,point)*eq(right,point) off the Boolean cube.
Fpk evaluate_diagonal_equality(std::span<const Fpk> left_msb,
                              std::span<const Fpk> right_msb,
                              std::span<const Fpk> point_msb);

/// `plaintext_rows[a]` is the Boolean slot table of mask a. Both dimensions
/// are powers of two; padded masks are all zero. Mask weights have already
/// bound the row and source wire points of the local sparse edge polynomial.
MaskedActionOutput prove_masked_action(
    std::span<const Fpk> mask_weights,
    std::span<const std::vector<Fp>> plaintext_rows,
    std::span<const Fpk> output_slot_msb,
    std::span<const Fpk> source_slot_msb, const Fpk &claim,
    PublicCoin &coin);

std::optional<MaskedActionReduction> verify_masked_action(
    std::size_t mask_variables, std::span<const Fpk> output_slot_msb,
    std::span<const Fpk> source_slot_msb, const Fpk &claim,
    const MaskedActionProof &proof, PublicCoin &coin);

} // namespace laminate::gates

#endif
