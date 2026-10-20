#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_REFERENCE_CIPHERTEXT_ROUND_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_REFERENCE_CIPHERTEXT_ROUND_HPP

/// @file ciphertext_round.hpp
/// @brief Reference source scans for Laned affine ciphertext-index rounds.

#include "laminate/gkr/detail/laned/affine/arithmetic/lane_placement.hpp"
#include "laminate/gkr/detail/laned/affine/types.hpp"
#include "laminate/gkr/detail/laned/geometry/layout.hpp"
#include "laminate/payload/trace/encrypted_trace.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"
#include "laminate/poly/eq.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::laned_detail {

inline std::vector<Fpk> affine_prefix_weights(
    std::span<const Fpk> prefix) {
    return poly::eq_evaluations(
        std::vector<Fpk>(prefix.begin(), prefix.end()));
}

inline Fpk affine_prefix_weight(
    std::span<const Fpk> weights, std::size_t index,
    std::size_t variables) {
    if (weights.empty() ||
        (weights.size() & (weights.size() - 1U)) != 0U) {
        throw std::invalid_argument(
            "LaminateLaned affine prefix weights are not a power of two");
    }
    const std::size_t bound_variables = log2_exact(
        weights.size(), "LaminateLaned affine prefix weights");
    if (bound_variables > variables ||
        index >= poly::hypercube_size(variables)) {
        throw std::invalid_argument(
            "LaminateLaned affine prefix-weight lookup is out of range");
    }
    return weights[index >> (variables - bound_variables)];
}

/// Compute both evaluations sent in one ciphertext-index round.
/// For `a in {1,2}` the kernel evaluates
///
///   R_j(a) = FoldSlots(sum_w eq(prefix || a, packed(w))
///                            * A_a(w) * PlaceLanes(W[w])).
///
/// `eq` and `A_a` are public extension-field scalars. The source loop below
/// performs one public-scalar multiplication/addition per retained term;
/// lane placement then performs prepared public products, rotations, adds,
/// and a slot fold. There is no ciphertext-ciphertext multiplication.
template <fhe::FheBackend Backend>
LanedAffineRoundEvaluations<Backend>
affine_ciphertext_round_evaluations(
    const typename Backend::EvalContext &eval,
    const payload::EncryptedTraceLayer<Backend> &source,
    const payload::LayerWireSupport &source_support,
    const packing::LanedPackingLayout &layout,
    std::span<const Fpk> lane_weights,
    const LanedAffineGateRestrictions &gate_values,
    std::span<const Fpk> prefix,
    const LanedAffineRoundEvaluationPoints &round_points,
    std::span<const detail::MixedPreparedFpkSlotBasis<Backend>>
        prepared_bases) {
    const std::size_t ciphertext_index_variables = log2_exact(
        layout.padded_ciphertext_count,
        "LaminateLaned affine ciphertext variables");
    using PublicVectors =
        ::laminate::gkr::detail::AffineRoundPair<std::vector<Fpk>>;
    PublicVectors bounds;
    PublicVectors witness_prefix_weights;
    const auto prepare_endpoint =
        [&](const Fpk &point, const std::vector<Fpk> &gate_suffix,
            std::vector<Fpk> &bound, std::vector<Fpk> &prefix_weights) {
        bound.assign(prefix.begin(), prefix.end());
        bound.push_back(point);
        if (bound.size() > ciphertext_index_variables) {
            throw std::invalid_argument(
                "LaminateLaned affine ciphertext prefix is too long");
        }
        if (gate_suffix.empty() ||
            (gate_suffix.size() & (gate_suffix.size() - 1U)) != 0U) {
            throw std::invalid_argument(
                "LaminateLaned affine gate suffix is malformed");
        }
        prefix_weights = affine_prefix_weights(bound);
    };
    prepare_endpoint(round_points.at_one, gate_values.at_one,
                     bounds.at_one, witness_prefix_weights.at_one);
    prepare_endpoint(round_points.at_two, gate_values.at_two,
                     bounds.at_two, witness_prefix_weights.at_two);
    if (source_support.padded_wire_count != layout.original_wire_count ||
        source_support.live_wire_count != source.wires.size() ||
        lane_weights.size() != layout.lane_count ||
        prepared_bases.size() != 1U) {
        throw std::invalid_argument(
            "LaminateLaned affine ciphertext round shape mismatch");
    }

    const std::size_t chunks = layout.chunks_per_ciphertext();
    const bool retain_zero_terms =
        fhe::forces_challenge_independent_topology<Backend>(eval);
    using MixedExtension = fhe::MixedExtensionAccumulator<Backend>;
    ::laminate::gkr::detail::AffineRoundPair<
        std::vector<MixedExtension>>
        chunk_aggregates{
            .at_one = std::vector<MixedExtension>(chunks),
            .at_two = std::vector<MixedExtension>(chunks)};
    for (std::size_t live_wire = 0; live_wire < source.wires.size();
         ++live_wire) {
        const std::size_t wire = source_support.padded_index_of(live_wire);
        const std::size_t packed = wire / chunks;
        const std::size_t chunk = wire % chunks;
        const auto accumulate_at_endpoint =
            [&](const std::vector<Fpk> &prefix_weights,
                const std::vector<Fpk> &gate_suffix,
                std::vector<MixedExtension> &aggregates) {
            const Fpk witness_interpolation = affine_prefix_weight(
                prefix_weights, packed, ciphertext_index_variables);
            const Fpk gate =
                gate_suffix[wire & (gate_suffix.size() - 1U)];
            const Fpk scalar = witness_interpolation * gate;
            if (scalar.is_zero() && !retain_zero_terms) {
                return;
            }
            accumulate_laned_scalar_source<Backend>(
                eval, aggregates[chunk], source.wires[live_wire], scalar);
        };
        accumulate_at_endpoint(
            witness_prefix_weights.at_one, gate_values.at_one,
            chunk_aggregates.at_one);
        accumulate_at_endpoint(
            witness_prefix_weights.at_two, gate_values.at_two,
            chunk_aggregates.at_two);
    }

    const auto finish_endpoint = [&](auto &aggregates) {
        auto placed = apply_laned_lane_bases<Backend>(
            eval, aggregates, prepared_bases);
        return fhe::ext_fold<Backend>(eval, placed);
    };
    return {
        .at_one = finish_endpoint(chunk_aggregates.at_one),
        .at_two = finish_endpoint(chunk_aggregates.at_two),
    };
}

/// Materialize the one encrypted value reused by every slot round:
///
///   C = sum_w eq(r_ct, packed(w)) * PlaceLanes(W[w]).
///
/// This is one resident source scan. Its only FHE work is public-scalar
/// accumulation, prepared public lane placement, rotations, and additions.
template <fhe::FheBackend Backend>
fhe::ExtensionValue<Backend> affine_slot_checkpoint(
    const typename Backend::EvalContext &eval,
    const payload::EncryptedTraceLayer<Backend> &source,
    const payload::LayerWireSupport &source_support,
    const packing::LanedPackingLayout &layout,
    std::span<const Fpk> lane_weights,
    std::span<const Fpk> ciphertext_point,
    std::span<const detail::MixedPreparedFpkSlotBasis<Backend>>
        prepared_bases) {
    const std::size_t ciphertext_index_variables = log2_exact(
        layout.padded_ciphertext_count,
        "LaminateLaned affine checkpoint variables");
    if (ciphertext_point.size() != ciphertext_index_variables ||
        source_support.padded_wire_count != layout.original_wire_count ||
        source_support.live_wire_count != source.wires.size() ||
        lane_weights.size() != layout.lane_count ||
        prepared_bases.size() != 1U) {
        throw std::invalid_argument(
            "LaminateLaned affine checkpoint shape mismatch");
    }
    const std::vector<Fpk> owned_point(ciphertext_point.begin(),
                                       ciphertext_point.end());
    const std::vector<Fpk> ciphertext_weights =
        poly::eq_evaluations(owned_point);
    const std::size_t chunks = layout.chunks_per_ciphertext();
    const bool retain_zero_terms =
        fhe::forces_challenge_independent_topology<Backend>(eval);
    std::vector<fhe::MixedExtensionAccumulator<Backend>>
        chunk_aggregates(chunks);
    for (std::size_t live_wire = 0; live_wire < source.wires.size();
         ++live_wire) {
        const std::size_t wire = source_support.padded_index_of(live_wire);
        const Fpk packed_weight = ciphertext_weights[wire / chunks];
        if (packed_weight.is_zero() && !retain_zero_terms) {
            continue;
        }
        accumulate_laned_scalar_source<Backend>(
            eval, chunk_aggregates[wire % chunks],
            source.wires[live_wire], packed_weight);
    }
    return apply_laned_lane_bases<Backend>(
        eval, chunk_aggregates, prepared_bases);
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_REFERENCE_CIPHERTEXT_ROUND_HPP
