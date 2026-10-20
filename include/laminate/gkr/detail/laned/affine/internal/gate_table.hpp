#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_GATE_TABLE_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_GATE_TABLE_HPP

/// @file gate_table.hpp
/// @brief Public affine coefficients used by Laned layer reductions.

#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/laned/geometry/point.hpp"
#include "laminate/gkr/detail/shared/reduction/affine_round.hpp"
#include "laminate/poly/eq.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::laned_detail {

/// Build the public coefficient table A(current_claim, source_wire).
/// Its entries multiply source ciphertexts as plaintext scalars; constructing
/// and folding this table performs no FHE operation.
inline std::vector<Fpk> affine_active_table(
    const payload::LayeredCircuit &circuit, std::size_t layer,
    const packing::LanedPackingLayout &output_layout,
    const packing::LanedPackingLayout &source_layout,
    const LayerClaim &current_claim) {
    const auto &affine =
        std::get<payload::AffineLayer>(circuit.layers.at(layer));
    const std::size_t active_count =
        source_layout.padded_ciphertext_count *
        source_layout.chunks_per_ciphertext();
    std::vector<Fpk> table(active_count, Fpk::zero());

    const auto add_claim = [&](const SingleClaim &claim,
                               const Fpk &batch_weight) {
        const LanedPointCoordinates output =
            split_laned_point(output_layout, claim.point);
        const std::vector<Fpk> output_weights =
            poly::eq_evaluations(output.wire);
        for (std::size_t gate = 0; gate < affine.gates.size(); ++gate) {
            const Fpk gate_weight = batch_weight * output.padding_weight *
                                    output_weights[gate];
            for (const payload::AffineTerm &term :
                 affine.gates[gate].terms) {
                if (term.source >= source_layout.original_wire_count) {
                    throw std::logic_error(
                        "LaminateLaned affine term exceeds source layout");
                }
                table[term.source] +=
                    gate_weight * Fpk::from_base(term.coefficient);
            }
        }
    };
    if (const auto *single = std::get_if<SingleClaim>(&current_claim)) {
        add_claim(*single, Fpk::one());
    } else {
        const BatchedClaim &batched = std::get<BatchedClaim>(current_claim);
        add_claim(batched.first, Fpk::one());
        add_claim(batched.second, batched.challenge);
    }
    return table;
}

/// Rolling MSB-prefix contraction of the public coefficient table.
/// Round evaluations and sampled-challenge binds process a geometric series,
/// so total host-field work is linear in the original table.
class AffineGateTableFoldState {
  public:
    explicit AffineGateTableFoldState(std::span<const Fpk> table)
        : current_(table.begin(), table.end()) {
        if (current_.empty() ||
            (current_.size() & (current_.size() - 1U)) != 0) {
            throw std::invalid_argument(
                "LaminateLaned affine gate table is not a power of two");
        }
    }

    ::laminate::gkr::detail::AffineRoundPair<std::vector<Fpk>>
    round_evaluations(
        const ::laminate::gkr::detail::AffineRoundEvaluationPoints &points) {
        return {.at_one = fold_at(points.at_one),
                .at_two = fold_at(points.at_two)};
    }

    void bind(const Fpk &value) {
        if (current_.size() != 1U) {
            current_ = fold_at(value);
        }
    }

    std::uint64_t entries_processed() const { return entries_processed_; }

  private:
    std::vector<Fpk> fold_at(const Fpk &value) {
        if (current_.size() == 1U) {
            return current_;
        }
        const std::size_t half = current_.size() / 2U;
        std::vector<Fpk> result(half);
        for (std::size_t suffix = 0; suffix < half; ++suffix) {
            result[suffix] = current_[suffix] +
                value * (current_[half + suffix] - current_[suffix]);
        }
        if (half > std::numeric_limits<std::uint64_t>::max() -
                       entries_processed_) {
            throw std::overflow_error(
                "LaminateLaned affine gate-table work overflows u64");
        }
        entries_processed_ += static_cast<std::uint64_t>(half);
        return result;
    }

    std::vector<Fpk> current_;
    std::uint64_t entries_processed_ = 0;
};

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_GATE_TABLE_HPP
