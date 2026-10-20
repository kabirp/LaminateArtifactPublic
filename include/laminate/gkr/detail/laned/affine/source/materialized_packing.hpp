#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_MATERIALIZED_PACKING_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_MATERIALIZED_PACKING_HPP

/// @file materialized_packing.hpp
/// @brief Reusable low-width packed source for Laned affine reductions.

#include "laminate/fhe/extension.hpp"
#include "laminate/gkr/detail/laned/affine/diagnostics/statistics.hpp"
#include "laminate/gkr/detail/laned/affine/source/chunk_batches.hpp"
#include "laminate/gkr/detail/laned/affine/source/prefix_weights.hpp"
#include "laminate/gkr/detail/laned/affine/source/scan.hpp"
#include "laminate/gkr/detail/laned/affine/types.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::laned_detail::affine_detail {

inline bool use_materialized_packed_source(
    const packing::LanedPackingLayout &layout) {
    return layout.logical_ciphertext_count <=
           kLanedAffineMaterializedPackedCiphertextLimit;
}

/// Pack a compact B-periodic source once, then evaluate every affine round by
/// applying general SIMD masks to the resulting S/N ciphertexts.
///
/// If `C=N/B`, the challenge-independent packed value is
///
///   P[p] = sum_c Rot(cB, first_B(W[pC+c])).
///
/// Round masks combine the ciphertext-prefix, GateMLE, and lane-equality
/// factors. Linearity makes this exactly the same polynomial as the streaming
/// scalar-weight-and-place evaluator, while avoiding a source scan and one
/// extension rotation per chunk in every ciphertext-index round.
template <fhe::FheBackend Backend>
class MaterializedAffinePackedSource {
  public:
    bool built() const noexcept { return !values_.empty(); }

    std::size_t value_count() const noexcept { return values_.size(); }

    template <typename Reader, typename ValidateSource>
    void load_packed(Reader &reader,
                     const packing::LanedPackingLayout &layout,
                     ValidateSource &&validate_source,
                     LanedAffineStatistics *statistics) {
        if (built() || !use_materialized_packed_source(layout)) {
            throw std::logic_error(
                "Laned affine eager packed source has invalid state");
        }
        values_.reserve(layout.logical_ciphertext_count);
        while (auto value = reader.next()) {
            validate_source(*value);
            values_.push_back(std::move(*value));
        }
        if (values_.size() != layout.logical_ciphertext_count) {
            throw std::runtime_error(
                "Laned affine eager packed source has the wrong size");
        }
        if (statistics != nullptr) {
            statistics->materialized_packed_source_values =
                static_cast<std::uint64_t>(std::count_if(
                    values_.begin(), values_.end(),
                    [](const auto &value) {
                        return !value.is_public_zero();
                    }));
        }
    }

    template <typename Reader, typename ValidateSource,
              typename Progress>
    void build(const typename Backend::EvalContext &eval, Reader &reader,
               const packing::LanedPackingLayout &layout,
               const payload::LayerWireSupport &support,
               ValidateSource &&validate_source,
               Progress &&progress,
               LanedAffineStatistics *statistics) {
        if (built()) {
            return;
        }
        if (!use_materialized_packed_source(layout) ||
            support.padded_wire_count != layout.original_wire_count) {
            throw std::invalid_argument(
                "Laned affine materialized source has invalid geometry");
        }

        values_.assign(layout.logical_ciphertext_count,
                       fhe::FheValue<Backend>::public_zero());
        const std::size_t chunks = layout.chunks_per_ciphertext();
        fhe::SlotVector first_chunk(layout.slot_count, Fp::zero());
        std::fill_n(first_chunk.begin(), layout.lane_count, Fp::one());
        const fhe::FheValue<Backend> public_first_chunk =
            fhe::FheValue<Backend>::public_slots(first_chunk);
        std::optional<fhe::PreparedFpSlotBasis<Backend>> prepared_first_chunk;

        std::size_t completed = 0;
        scan_source_layer<Backend>(
            reader, layout.original_wire_count, support.live_wire_count,
            statistics,
            [&](std::size_t wire,
                const fhe::FheValue<Backend> &source) {
                validate_source(source);
                const std::size_t packed = wire / chunks;
                const std::size_t chunk = wire % chunks;
                if (packed >= values_.size()) {
                    throw std::logic_error(
                        "Laned affine materialized packed index drifted");
                }

                fhe::FheValue<Backend> term;
                if (chunks == 1U) {
                    term = source;
                } else if (source.is_encrypted()) {
                    if (!prepared_first_chunk) {
                        prepared_first_chunk =
                            fhe::prepare_fp_slot_basis<Backend>(
                                eval, source.ciphertext(), first_chunk);
                    }
                    term = fhe::FheValue<Backend>::from_ciphertext(
                        fhe::mul_plain_prepared<Backend>(
                            eval, source.ciphertext(),
                            *prepared_first_chunk));
                    note(statistics,
                         &LanedAffineStatistics::
                             materialized_source_plain_multiplications,
                         1);
                } else {
                    term = fhe::value_mul<Backend>(
                        eval, source, public_first_chunk);
                }

                if (chunks != 1U && chunk != 0U) {
                    term = fhe::value_rotate<Backend>(
                        eval, term,
                        fhe::grid_inverse(layout.slot_count,
                                          chunk * layout.lane_count));
                    note(statistics,
                         &LanedAffineStatistics::
                             materialized_source_rotations,
                         1);
                }
                const bool accumulated =
                    !values_[packed].is_public_zero();
                fhe::value_add_assign<Backend>(
                    eval, values_[packed], std::move(term));
                if (accumulated) {
                    note(statistics,
                         &LanedAffineStatistics::
                             materialized_source_additions,
                             1);
                }
                ++completed;
                constexpr std::size_t kProgressInterval = 1024U;
                if (completed == support.live_wire_count ||
                    completed % kProgressInterval == 0U) {
                    progress(completed, support.live_wire_count);
                }
            });

        if (statistics != nullptr) {
            statistics->materialized_packed_source_values =
                static_cast<std::uint64_t>(std::count_if(
                    values_.begin(), values_.end(),
                    [](const auto &value) {
                        return !value.is_public_zero();
                    }));
        }
    }

    LanedAffineRoundEvaluations<Backend> evaluate_ciphertext_round(
        const typename Backend::EvalContext &eval,
        const packing::LanedPackingLayout &layout,
        std::span<const Fpk> lane_weights,
        const LanedAffineGateRestrictions &gate_values,
        std::span<const Fpk> at_one_prefix_weights,
        std::span<const Fpk> at_two_prefix_weights,
        std::size_t ciphertext_index_variables,
        LanedAffineStatistics *statistics) const {
        require_built_shape(layout, lane_weights);
        return {
            .at_one = evaluate_endpoint(
                eval, layout, lane_weights, gate_values.at_one,
                at_one_prefix_weights, ciphertext_index_variables,
                statistics),
            .at_two = evaluate_endpoint(
                eval, layout, lane_weights, gate_values.at_two,
                at_two_prefix_weights, ciphertext_index_variables,
                statistics),
        };
    }

    fhe::ExtensionValue<Backend> build_slot_checkpoint(
        const typename Backend::EvalContext &eval,
        const packing::LanedPackingLayout &layout,
        std::span<const Fpk> lane_weights,
        std::span<const Fpk> ciphertext_weights,
        LanedAffineStatistics *statistics) const {
        require_built_shape(layout, lane_weights);
        if (ciphertext_weights.size() !=
            layout.padded_ciphertext_count) {
            throw std::invalid_argument(
                "Laned affine materialized checkpoint weights have the "
                "wrong size");
        }
        fhe::MixedExtensionAccumulator<Backend> accumulator;
        for (std::size_t packed = 0; packed < values_.size(); ++packed) {
            if (values_[packed].is_public_zero()) {
                continue;
            }
            const std::vector<Fpk> mask = packed_mask(
                layout, lane_weights, ciphertext_weights[packed], {},
                packed);
            accumulate_masked(eval, accumulator, values_[packed], mask,
                              statistics);
        }
        if (statistics != nullptr) {
            statistics->peak_retained_extension_checkpoints = std::max(
                statistics->peak_retained_extension_checkpoints,
                std::size_t{1});
        }
        return std::move(accumulator).finish(eval);
    }

  private:
    using Counter = std::uint64_t LanedAffineStatistics::*;

    static void note(LanedAffineStatistics *statistics, Counter counter,
                     std::uint64_t amount) {
        if (statistics != nullptr) {
            checked_accumulate(statistics->*counter, amount,
                               "Laned affine materialized-source counter");
        }
    }

    void require_built_shape(
        const packing::LanedPackingLayout &layout,
        std::span<const Fpk> lane_weights) const {
        if (!built() || values_.size() != layout.logical_ciphertext_count ||
            lane_weights.size() != layout.lane_count) {
            throw std::logic_error(
                "Laned affine materialized source is not ready");
        }
    }

    static std::vector<Fpk> packed_mask(
        const packing::LanedPackingLayout &layout,
        std::span<const Fpk> lane_weights, const Fpk &packed_weight,
        std::span<const Fpk> gate_suffix, std::size_t packed) {
        std::vector<Fpk> result(layout.slot_count, Fpk::zero());
        const std::size_t chunks = layout.chunks_per_ciphertext();
        for (std::size_t chunk = 0; chunk < chunks; ++chunk) {
            const std::size_t wire = packed * chunks + chunk;
            if (wire >= layout.original_wire_count) {
                break;
            }
            const Fpk gate = gate_suffix.empty()
                                 ? Fpk::one()
                                 : gate_suffix[
                                       wire & (gate_suffix.size() - 1U)];
            const Fpk wire_weight = packed_weight * gate;
            for (std::size_t lane = 0; lane < layout.lane_count; ++lane) {
                result[chunk * layout.lane_count + lane] =
                    wire_weight * lane_weights[lane];
            }
        }
        return result;
    }

    static void accumulate_masked(
        const typename Backend::EvalContext &eval,
        fhe::MixedExtensionAccumulator<Backend> &accumulator,
        const fhe::FheValue<Backend> &source, std::span<const Fpk> mask,
        LanedAffineStatistics *statistics) {
        accumulator.accumulate_scaled_slots(eval, source, mask);
        note(statistics,
             &LanedAffineStatistics::materialized_packed_mask_applications,
             1);
        note(statistics,
             &LanedAffineStatistics::materialized_packed_mask_elements,
             static_cast<std::uint64_t>(mask.size()));
        note(statistics,
             &LanedAffineStatistics::online_slot_vectors_constructed, 1);
    }

    fhe::ExtensionValue<Backend> evaluate_endpoint(
        const typename Backend::EvalContext &eval,
        const packing::LanedPackingLayout &layout,
        std::span<const Fpk> lane_weights,
        std::span<const Fpk> gate_suffix,
        std::span<const Fpk> prefix_weights,
        std::size_t ciphertext_index_variables,
        LanedAffineStatistics *statistics) const {
        if (gate_suffix.empty() ||
            (gate_suffix.size() & (gate_suffix.size() - 1U)) != 0U) {
            throw std::invalid_argument(
                "Laned affine materialized gate suffix is malformed");
        }
        const bool retain_zero_terms =
            fhe::forces_challenge_independent_topology<Backend>(eval);
        fhe::MixedExtensionAccumulator<Backend> accumulator;
        for (std::size_t packed = 0; packed < values_.size(); ++packed) {
            if (values_[packed].is_public_zero()) {
                continue;
            }
            const Fpk packed_weight = cached_prefix_weight(
                prefix_weights, packed, ciphertext_index_variables,
                statistics);
            if (packed_weight.is_zero() && !retain_zero_terms) {
                continue;
            }
            const std::vector<Fpk> mask = packed_mask(
                layout, lane_weights, packed_weight, gate_suffix, packed);
            accumulate_masked(eval, accumulator, values_[packed], mask,
                              statistics);
        }
        return fhe::ext_fold<Backend>(
            eval, std::move(accumulator).finish(eval));
    }

    std::vector<fhe::FheValue<Backend>> values_;
};

} // namespace laminate::gkr::laned_detail::affine_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_MATERIALIZED_PACKING_HPP
