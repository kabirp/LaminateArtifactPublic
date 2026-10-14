#include "laminate/gates/masked_action.hpp"

#include "laminate/basefold/common.hpp"

#include <limits>
#include <stdexcept>

namespace laminate::gates {
namespace {

std::vector<Fpk> reversed(std::span<const Fpk> point) {
    return {point.rbegin(), point.rend()};
}

std::vector<Fpk> diagonal_table(std::span<const Fpk> left,
                                std::span<const Fpk> right) {
    if (left.size() != right.size() ||
        left.size() >= std::numeric_limits<std::size_t>::digits) {
        throw std::invalid_argument("masked action: invalid slot points");
    }
    const auto a = basefold::equality_evaluations(reversed(left));
    const auto b = basefold::equality_evaluations(reversed(right));
    std::vector<Fpk> result(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] * b[i];
    }
    return result;
}

void observe_begin(std::size_t mask_variables, std::span<const Fpk> output,
                   std::span<const Fpk> source, PublicCoin &coin) {
    coin.observe("wide-gates/masked-action/v1", mask_variables);
    coin.observe("wide-gates/masked-action/output-slots",
                 basefold::serialize_values(output));
    coin.observe("wide-gates/masked-action/source-slots",
                 basefold::serialize_values(source));
}

} // namespace

Fpk evaluate_diagonal_equality(std::span<const Fpk> left,
                               std::span<const Fpk> right,
                               std::span<const Fpk> point) {
    if (left.size() != right.size() || left.size() != point.size()) {
        throw std::invalid_argument("diagonal equality: point mismatch");
    }
    Fpk value = Fpk::one();
    for (std::size_t i = 0; i < point.size(); ++i) {
        value *= (Fpk::one() - left[i]) * (Fpk::one() - right[i]) *
                     (Fpk::one() - point[i]) +
                 left[i] * right[i] * point[i];
    }
    return value;
}

MaskedActionOutput prove_masked_action(
    std::span<const Fpk> weights, std::span<const std::vector<Fp>> plaintexts,
    std::span<const Fpk> output_slot, std::span<const Fpk> source_slot,
    const Fpk &claim, PublicCoin &coin) {
    if (weights.empty() || plaintexts.size() > weights.size() ||
        (weights.size() & (weights.size() - 1)) != 0) {
        throw std::invalid_argument("masked action: invalid mask dimension");
    }
    const auto diagonal = diagonal_table(output_slot, source_slot);
    std::vector<Fpk> contractions(weights.size(), Fpk::zero());
    Fpk actual = Fpk::zero();
    for (std::size_t mask = 0; mask < plaintexts.size(); ++mask) {
        if (plaintexts[mask].size() != diagonal.size()) {
            throw std::invalid_argument(
                "masked action: invalid plaintext width");
        }
        for (std::size_t slot = 0; slot < diagonal.size(); ++slot) {
            contractions[mask] += diagonal[slot] * plaintexts[mask][slot];
        }
        actual += weights[mask] * contractions[mask];
    }
    if (actual != claim) {
        throw std::invalid_argument("masked action: incorrect claim");
    }
    observe_begin(basefold::log2_exact(weights.size()), output_slot,
                  source_slot, coin);
    auto masks = prove_quadratic_product({weights.begin(), weights.end()},
                                         std::move(contractions), claim, coin);
    const auto equality =
        basefold::equality_evaluations(masks.reduction.point_lsb);
    std::vector<Fpk> bound_plaintext(diagonal.size(), Fpk::zero());
    for (std::size_t mask = 0; mask < plaintexts.size(); ++mask) {
        for (std::size_t slot = 0; slot < diagonal.size(); ++slot) {
            bound_plaintext[slot] += equality[mask] * plaintexts[mask][slot];
        }
    }
    auto slots = prove_quadratic_product(std::move(bound_plaintext), diagonal,
                                         masks.reduction.right, coin);
    MaskedActionReduction reduction{reversed(masks.reduction.point_lsb),
                                    reversed(slots.reduction.point_lsb),
                                    masks.reduction.left, slots.reduction.left};
    return {{std::move(masks.proof), std::move(slots.proof)},
            std::move(reduction)};
}

std::optional<MaskedActionReduction>
verify_masked_action(std::size_t mask_variables,
                     std::span<const Fpk> output_slot,
                     std::span<const Fpk> source_slot, const Fpk &claim,
                     const MaskedActionProof &proof, PublicCoin &coin) {
    if (output_slot.size() != source_slot.size()) {
        return std::nullopt;
    }
    observe_begin(mask_variables, output_slot, source_slot, coin);
    const auto masks =
        verify_quadratic_product(mask_variables, claim, proof.masks, coin);
    if (!masks) {
        return std::nullopt;
    }
    const auto slots = verify_quadratic_product(
        output_slot.size(), masks->right, proof.slots, coin);
    if (!slots) {
        return std::nullopt;
    }
    const auto slot_point = reversed(slots->point_lsb);
    if (slots->right !=
        evaluate_diagonal_equality(output_slot, source_slot, slot_point)) {
        return std::nullopt;
    }
    return MaskedActionReduction{reversed(masks->point_lsb), slot_point,
                                 masks->left, slots->left};
}

} // namespace laminate::gates
