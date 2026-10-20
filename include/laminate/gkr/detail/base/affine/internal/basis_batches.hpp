#ifndef LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_BASIS_BATCHES_HPP
#define LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_BASIS_BATCHES_HPP

/// @file basis_batches.hpp
/// @brief Bounded GateMLE rotation-basis accumulation for Base affine GKR.

#include "laminate/fhe/extension.hpp"
#include "laminate/gkr/detail/base/affine/internal/gate_mle.hpp"
#include "laminate/gkr/detail/base/affine/internal/source_prefix.hpp"
#include "laminate/gkr/detail/base/affine/internal/source_reader.hpp"
#include "laminate/gkr/detail/shared/reduction/affine_round.hpp"
#include "laminate/poly/eq.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::base_detail {

/// Maximum number of distinct rotation bases accumulated in one affine
/// source pass. Each basis needs two extension-ciphertext accumulators for
/// the transmitted evaluations. Larger rotation sets are evaluated in
/// additional sequential passes instead of growing the resident working set.
inline constexpr std::size_t kResidentAffineRotationBasisLimit = 8;

namespace base_affine_detail {

/// Public GateMLE restrictions needed at x=1 and x=2 in one sumcheck round.
struct AffineRoundRestriction {
    /// GateMLE restricted at the two transmitted round points.
    ::laminate::gkr::detail::AffineRoundPair<
        PreparedAffineGateMle::Bound>
        gate_mle;
    std::span<const PreparedAffineGateMle::Basis> rotation_bases;
    std::size_t suffix_count = 0;
};

inline AffineRoundRestriction restrict_affine_round(
    const payload::LayerWireSupport &support,
    const PreparedAffineGateMle &prepared_gate,
    std::span<const PreparedAffineGateMle::Basis> rotation_bases,
    const PreparedAffineGateMle::RollingBinding &rolling_gate,
    const SparseSourcePrefixWeights &source_prefix,
    const ::laminate::gkr::detail::AffineRoundEvaluationPoints &points,
    std::size_t ciphertext_index_variables,
    BaseAffineStatistics *statistics) {
    if (support.padded_wire_count !=
            poly::hypercube_size(ciphertext_index_variables) ||
        source_prefix.variables() != ciphertext_index_variables ||
        source_prefix.bound_variables() >= ciphertext_index_variables) {
        throw std::invalid_argument(
            "LaminateBase affine ciphertext-index domain mismatch");
    }

    AffineRoundRestriction result{
        .gate_mle = {
            .at_one = rolling_gate.evaluate_next(points.at_one),
            .at_two = rolling_gate.evaluate_next(points.at_two)},
        .rotation_bases = rotation_bases,
        .suffix_count = poly::hypercube_size(
            ciphertext_index_variables -
            source_prefix.bound_variables() - 1U),
    };
    if (rolling_gate.bound_variables() !=
            source_prefix.bound_variables() ||
        result.gate_mle.at_one.suffix_count != result.suffix_count ||
        result.gate_mle.at_two.suffix_count != result.suffix_count) {
        throw std::logic_error(
            "LaminateBase prepared affine round suffix mismatch");
    }

    if (statistics != nullptr) {
        const std::uint64_t terms = checked_u64(
            prepared_gate.weighted_term_count(),
            "Base affine public gate terms");
        if (terms > std::numeric_limits<std::uint64_t>::max() / 2U) {
            throw std::overflow_error(
                "Base affine public gate candidate visits overflow");
        }
        checked_accumulate(
            statistics->public_gate_term_candidate_visits, 2U * terms,
            "Base affine public gate candidate visits");
        statistics->distinct_rotation_bases = std::max(
            statistics->distinct_rotation_bases,
            result.rotation_bases.size());
    }
    return result;
}

template <fhe::FheBackend Backend>
struct AffineBasisBatch {
    using SparseExtension = fhe::SparseExtensionAccumulator<Backend>;

    /// Basis accumulators contributing to R_j(1) and R_j(2).
    ::laminate::gkr::detail::AffineRoundPair<
        std::vector<SparseExtension>>
        encrypted;
    /// Known-public contributions, kept symbolic at both round points.
    ::laminate::gkr::detail::AffineRoundPair<
        std::vector<fhe::ExtensionValue<Backend>>>
        public_values;
    std::optional<typename Backend::Ciphertext> level_reference;
};

template <fhe::FheBackend Backend>
struct AffineRoundSums {
    ::laminate::gkr::detail::AffineRoundPair<
        std::optional<typename Backend::ExtCiphertext>>
        encrypted;
    ::laminate::gkr::detail::AffineRoundPair<
        fhe::ExtensionValue<Backend>>
        public_values;
};

template <fhe::FheBackend Backend>
std::size_t retained_accumulator_count(
    const AffineBasisBatch<Backend> &batch,
    const AffineRoundSums<Backend> &round_sums) {
    std::size_t result =
        static_cast<std::size_t>(round_sums.encrypted.at_one.has_value()) +
        static_cast<std::size_t>(round_sums.encrypted.at_two.has_value());
    const auto count_nonempty = [](const auto &values) {
        return static_cast<std::size_t>(std::count_if(
            values.begin(), values.end(),
            [](const auto &value) { return !value.empty(); }));
    };
    result += count_nonempty(batch.encrypted.at_one);
    result += count_nonempty(batch.encrypted.at_two);
    return result;
}

/// Scan the compact source once for a bounded batch of rotation bases.
///
/// For a transmitted point x in {1, 2}, each live Boolean wire u contributes
///
///   eq((r_<j, x), u_<j+1>) * GateMLE(r_out; r_<j, x, u_>j) * W(u).
///
/// Both factors before W are public. Public W(u) remains symbolic; encrypted
/// W(u) crosses the FHE boundary only through scalar-times-ciphertext
/// accumulation. The affine reduction performs no ciphertext-ciphertext
/// multiplication.
template <fhe::FheBackend Backend, typename Reader>
AffineBasisBatch<Backend> scan_rotation_basis_batch(
    const typename Backend::EvalContext &eval, Reader &reader,
    const payload::LayerWireSupport &support,
    const AffineRoundRestriction &round,
    const SparseSourcePrefixWeights &source_prefix,
    const ::laminate::gkr::detail::AffineRoundEvaluationPoints &points,
    std::size_t batch_begin, std::size_t batch_end,
    bool retain_challenge_zero_terms,
    const AffineRoundSums<Backend> &round_sums,
    BaseAffineStatistics *statistics) {
    const std::size_t batch_size = batch_end - batch_begin;
    AffineBasisBatch<Backend> batch{
        .encrypted = {
            .at_one = std::vector<
                typename AffineBasisBatch<Backend>::SparseExtension>(
                batch_size),
            .at_two = std::vector<
                typename AffineBasisBatch<Backend>::SparseExtension>(
                batch_size)},
        .public_values = {
            .at_one = std::vector<fhe::ExtensionValue<Backend>>(batch_size),
            .at_two = std::vector<fhe::ExtensionValue<Backend>>(batch_size)},
    };

    scan_active_source<Backend>(
        reader, support, statistics,
        [&](std::size_t live_ordinal, std::size_t padded_index,
            const fhe::FheValue<Backend> &source_value) {
            const std::size_t suffix = padded_index % round.suffix_count;
            const auto source_weights = source_prefix.evaluate_next(
                live_ordinal, padded_index, points, statistics);
            if (source_value.is_encrypted() && !batch.level_reference) {
                batch.level_reference = source_value.ciphertext();
            }

            const auto accumulate_at_point =
                [&](const Fpk &source_weight,
                    const PreparedAffineGateMle::Bound &gate_mle,
                    std::vector<typename AffineBasisBatch<Backend>::
                                    SparseExtension> &encrypted,
                    std::vector<fhe::ExtensionValue<Backend>> &public_values,
                    bool require_at_one_support) {
                if (require_at_one_support &&
                    !source_prefix.next_at_one_has_public_support(
                        padded_index)) {
                    return;
                }
                gate_mle.for_each_sparse_basis_coefficient(
                    suffix, retain_challenge_zero_terms,
                    [&](const auto &term) {
                        if (term.basis < batch_begin ||
                            term.basis >= batch_end) {
                            return;
                        }
                        const Fpk scalar =
                            source_weight * term.coefficient;
                        if (scalar.is_zero() &&
                            !retain_challenge_zero_terms) {
                            return;
                        }
                        const std::size_t local_basis =
                            term.basis - batch_begin;
                        if (source_value.is_public()) {
                            fhe::extension_add_assign<Backend>(
                                eval, public_values.at(local_basis),
                                fhe::promote_extension_value<Backend>(
                                    eval, source_value, scalar));
                        } else {
                            // This is the per-term online FHE operation:
                            // multiply the encrypted source by a public Fpk
                            // scalar and add it to the sparse accumulator.
                            encrypted.at(local_basis)
                                .accumulate_scaled_base(
                                    eval, source_value.ciphertext(), scalar);
                        }
                        if (statistics != nullptr &&
                            source_value.is_encrypted()) {
                            checked_accumulate(
                                statistics->source_scalar_promotions, 1,
                                "Base affine source scalar promotions");
                            statistics
                                ->peak_retained_extension_accumulators =
                                std::max(
                                    statistics
                                        ->peak_retained_extension_accumulators,
                                    retained_accumulator_count(batch,
                                                               round_sums));
                        }
                    });
            };

            accumulate_at_point(
                source_weights.at_one, round.gate_mle.at_one,
                batch.encrypted.at_one, batch.public_values.at_one, true);
            accumulate_at_point(
                source_weights.at_two, round.gate_mle.at_two,
                batch.encrypted.at_two, batch.public_values.at_two, false);
        });
    if (statistics != nullptr && batch.level_reference) {
        checked_accumulate(
            statistics->rotation_basis_batches, 1,
            "Base affine rotation-basis batches");
    }
    return batch;
}

inline void record_prepared_basis_storage(
    const auto &storage, BaseAffineStatistics *statistics) {
    if (statistics == nullptr) {
        return;
    }
    checked_accumulate(
        statistics->prepared_basis_level_representations,
        checked_u64(storage.level_representations,
                    "Base affine prepared level representations"),
        "Base affine prepared level representations");
    checked_accumulate(
        statistics->prepared_basis_ntt_bytes,
        checked_u64(storage.ntt_coefficient_bytes,
                    "Base affine prepared NTT bytes"),
        "Base affine prepared NTT bytes");
    checked_accumulate(
        statistics->prepared_basis_host_bytes,
        checked_u64(storage.host_basis_bytes,
                    "Base affine prepared host bytes"),
        "Base affine prepared host bytes");
}

/// Prepare the public slot polynomials at the ciphertext's current RNS level.
/// These objects make the later GateMLE application a plaintext-ciphertext
/// product. A complete small basis set is cached across sumcheck rounds.
template <fhe::FheBackend Backend>
std::span<const fhe::PreparedFpkSlotBasis<Backend>>
prepare_rotation_basis_batch(
    const typename Backend::EvalContext &eval,
    const AffineRoundRestriction &round,
    const AffineBasisBatch<Backend> &batch,
    std::size_t batch_begin, std::size_t batch_end,
    std::size_t slot_index_variables, bool cache_complete_reduction,
    std::vector<fhe::PreparedFpkSlotBasis<Backend>>
        *reduction_prepared_bases,
    std::vector<fhe::PreparedFpkSlotBasis<Backend>> &local_prepared,
    BaseAffineStatistics *statistics) {
    if (!batch.level_reference) {
        return {};
    }
    if (cache_complete_reduction && !reduction_prepared_bases->empty()) {
        return *reduction_prepared_bases;
    }

    auto &destination = cache_complete_reduction
                            ? *reduction_prepared_bases
                            : local_prepared;
    const std::size_t batch_size = batch_end - batch_begin;
    destination.reserve(batch_size);
    for (std::size_t basis = batch_begin; basis < batch_end; ++basis) {
        if (round.rotation_bases[basis].slots.size() !=
            poly::hypercube_size(slot_index_variables)) {
            throw std::logic_error(
                "LaminateBase prepared affine slot width mismatch");
        }
        destination.push_back(fhe::prepare_fpk_slot_basis<Backend>(
            eval, *batch.level_reference,
            round.rotation_bases[basis].slots));
        record_prepared_basis_storage(destination.back().storage,
                                      statistics);
    }
    if (statistics != nullptr) {
        checked_accumulate(
            statistics->prepared_rotation_bases,
            checked_u64(destination.size(),
                        "Base affine prepared rotation basis count"),
            "Base affine prepared rotation basis count");
    }
    return destination;
}

/// Apply prepared public slot polynomials to encrypted scalar sums, then
/// merge this bounded batch into `R_j(1)` and `R_j(2)`.
template <fhe::FheBackend Backend>
void apply_rotation_basis_batch(
    const typename Backend::EvalContext &eval,
    const AffineRoundRestriction &round,
    AffineBasisBatch<Backend> batch, std::size_t batch_begin,
    std::span<const fhe::PreparedFpkSlotBasis<Backend>> prepared,
    AffineRoundSums<Backend> &round_sums,
    BaseAffineStatistics *statistics) {
    const std::size_t batch_size = batch.encrypted.at_one.size();
    if (batch.encrypted.at_two.size() != batch_size ||
        batch.public_values.at_one.size() != batch_size ||
        batch.public_values.at_two.size() != batch_size) {
        throw std::logic_error(
            "LaminateBase affine batch endpoint sizes drifted");
    }
    if (batch.level_reference && prepared.size() != batch_size) {
        throw std::logic_error(
            "LaminateBase affine prepared batch size drifted");
    }
    if (statistics != nullptr) {
        statistics->peak_retained_prepared_rotation_bases = std::max(
            statistics->peak_retained_prepared_rotation_bases,
            prepared.size());
    }

    const auto apply_at_point =
        [&](std::vector<typename AffineBasisBatch<Backend>::SparseExtension>
                &encrypted,
            std::vector<fhe::ExtensionValue<Backend>> &public_values,
            std::optional<typename Backend::ExtCiphertext> &encrypted_sum,
            fhe::ExtensionValue<Backend> &public_sum) {
        for (std::size_t basis = 0; basis < batch_size; ++basis) {
            if (!encrypted[basis].empty()) {
                const bool direct_base_promotion =
                    encrypted[basis].has_only_coefficient_zero();
                fhe::accumulate_extension<Backend>(
                    eval, encrypted_sum, std::move(encrypted[basis])
                        .apply_prepared_basis(eval, prepared[basis]));
                if (statistics != nullptr) {
                    if (direct_base_promotion) {
                        checked_accumulate(
                            statistics->prepared_base_promotion_applications,
                            1, "Base affine prepared base promotions");
                    }
                    checked_accumulate(
                        statistics->prepared_rotation_basis_applications,
                        1, "Base affine prepared-basis applications");
                    checked_accumulate(
                        statistics->avoided_online_slot_vector_elements,
                        checked_u64(
                            Backend::slot_count(eval),
                            "Base affine avoided online vector elements"),
                        "Base affine avoided online vector elements");
                }
            }
            if (!public_values[basis].is_public_zero()) {
                fhe::extension_add_assign<Backend>(
                    eval, public_sum,
                    fhe::scale_extension_value<Backend>(
                        eval, public_values[basis],
                        round.rotation_bases[batch_begin + basis].slots));
            }
        }
    };
    apply_at_point(batch.encrypted.at_one, batch.public_values.at_one,
                   round_sums.encrypted.at_one,
                   round_sums.public_values.at_one);
    apply_at_point(batch.encrypted.at_two, batch.public_values.at_two,
                   round_sums.encrypted.at_two,
                   round_sums.public_values.at_two);
}

template <fhe::FheBackend Backend>
::laminate::gkr::detail::AffineRoundPair<fhe::ExtensionValue<Backend>>
finish_affine_round(
    const typename Backend::EvalContext &eval,
    AffineRoundSums<Backend> round_sums) {
    // An all-public-zero source remains a symbolic zero. It needs neither a
    // level anchor nor an encrypted placeholder.
    const auto finish_at_point =
        [&](std::optional<typename Backend::ExtCiphertext> encrypted,
            fhe::ExtensionValue<Backend> public_value) {
        fhe::ExtensionValue<Backend> result;
        if (encrypted) {
            result = fhe::ExtensionValue<Backend>(std::move(*encrypted));
        }
        fhe::extension_add_assign<Backend>(
            eval, result, std::move(public_value));
        return result;
    };
    return {
        .at_one = finish_at_point(
            std::move(round_sums.encrypted.at_one),
            std::move(round_sums.public_values.at_one)),
        .at_two = finish_at_point(
            std::move(round_sums.encrypted.at_two),
            std::move(round_sums.public_values.at_two)),
    };
}

} // namespace base_affine_detail
} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_BASIS_BATCHES_HPP
