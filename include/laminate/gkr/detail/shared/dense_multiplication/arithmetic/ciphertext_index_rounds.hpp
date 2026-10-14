#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_ARITHMETIC_CIPHERTEXT_INDEX_ROUNDS_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_ARITHMETIC_CIPHERTEXT_INDEX_ROUNDS_HPP

/// @file ciphertext_index_rounds.hpp
/// @brief File-backed FHE kernels for packed multiplication rounds.
///
/// This file is the arithmetic destination of the Folded/Laned round
/// evaluator. It contains the complete sequential source pass and the
/// concrete ciphertext multiplications. Storage accounting is kept beside
/// the reader operations; transcript and progress logic remain in the prover.

#include "laminate/gkr/detail/shared/dense_multiplication/accumulation.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/rounds.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/scan.hpp"
#include "laminate/gkr/detail/shared/packed/prepared_basis.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::detail {

namespace dense_multiplication_ciphertext_round_detail {

namespace arithmetic = dense_multiplication_accumulation_detail;

inline constexpr char kInvalidCiphertextIndexRoundPoint[] =
    "dense multiplication expects the endpoint or X=2";

template <typename Value>
std::size_t present_round_values(
    const DenseMultiplicationRoundValues<Value> &values) {
    const auto present = [](const auto &value) {
        if constexpr (requires { value.has_value(); }) {
            return value.has_value();
        } else if constexpr (requires { value.is_public_zero(); }) {
            return !value.is_public_zero();
        } else {
            return !value.empty();
        }
    };
    return static_cast<std::size_t>(present(values.at_endpoint)) +
           static_cast<std::size_t>(present(values.at_two));
}

template <fhe::FheBackend Backend, typename Pair>
const typename Backend::Ciphertext *ciphertext_reference(const Pair &pair) {
    if (pair.left().is_encrypted()) {
        return &pair.left().ciphertext();
    }
    if (pair.right().is_encrypted()) {
        return &pair.right().ciphertext();
    }
    return nullptr;
}

template <fhe::FheBackend Backend>
void prepare_output_slot_basis(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext *level_reference,
    std::span<const Fpk> output_slot_weights,
    std::optional<MixedPreparedFpkSlotBasis<Backend>> &prepared_basis,
    FileBackedMultiplicationStatistics &statistics) {
    if (!prepared_basis) {
        prepared_basis = prepare_mixed_fpk_slot_basis<Backend>(
            eval, level_reference, output_slot_weights);
    } else if (level_reference != nullptr && !prepared_basis->encrypted) {
        prepared_basis->encrypted.emplace(prepare_fpk_slot_basis<Backend>(
            eval, *level_reference, prepared_basis->public_values));
    } else {
        return;
    }
    if (!prepared_basis->encrypted) {
        return;
    }

    multiplication_source_store_detail::checked_accumulate(
        statistics.prepared_output_slot_bases, 1,
        "file-backed multiplication prepared output basis count");
    const auto &storage = prepared_basis->encrypted->storage;
    multiplication_source_store_detail::checked_accumulate(
        statistics.prepared_basis_level_representations,
        multiplication_source_store_detail::checked_count(
            storage.level_representations,
            "file-backed multiplication prepared level representations"),
        "file-backed multiplication prepared level representations");
    multiplication_source_store_detail::checked_accumulate(
        statistics.prepared_basis_ntt_bytes,
        multiplication_source_store_detail::checked_count(
            storage.ntt_coefficient_bytes,
            "file-backed multiplication prepared NTT bytes"),
        "file-backed multiplication prepared NTT bytes");
    multiplication_source_store_detail::checked_accumulate(
        statistics.prepared_basis_host_bytes,
        multiplication_source_store_detail::checked_count(
            storage.host_basis_bytes,
            "file-backed multiplication prepared host bytes"),
        "file-backed multiplication prepared host bytes");
}

template <fhe::FheBackend Backend, typename Accumulator>
fhe::ExtensionValue<Backend> fold_product_sum_across_slots(
    const typename Backend::EvalContext &eval, Accumulator accumulator,
    const MixedPreparedFpkSlotBasis<Backend> &prepared_output_slots,
    FileBackedMultiplicationStatistics &statistics) {
    // Apply the public output-slot equality weights, then relinearize and
    // fold all SIMD slots to the replicated scalar sent by Folded/Laned.
    auto result = apply_mixed_prepared_basis<Backend>(
        eval, std::move(accumulator), prepared_output_slots);
    fhe::relinearize_extension_value<Backend>(eval, result);
    result = fhe::ext_fold<Backend>(eval, result);
    multiplication_source_store_detail::checked_accumulate(
        statistics.prepared_output_slot_basis_applications, 1,
        "file-backed multiplication prepared output basis applications");
    multiplication_source_store_detail::checked_accumulate(
        statistics.avoided_online_slot_vector_elements,
        multiplication_source_store_detail::checked_count(
            Backend::slot_count(eval),
            "file-backed multiplication avoided slot-vector elements"),
        "file-backed multiplication avoided slot-vector elements");
    return result;
}

/// First packed ciphertext-index round. L and R are still base-field
/// ciphertexts, so the scan selects low/high branches before multiplying.
template <fhe::FheBackend Backend, typename Reader>
TransmittedLayerReductionRound<fhe::ExtensionValue<Backend>>
evaluate_first_packed_ciphertext_index_round(
    const typename Backend::EvalContext &eval, Reader &reader,
    const LayerReductionRoundPoints &round_points,
    const DenseMultiplicationRoundValues<CiphertextIndexRoundWeights> &weights,
    std::span<const Fpk> output_slot_weights,
    std::optional<MixedPreparedFpkSlotBasis<Backend>> &prepared_output_slots,
    FileBackedMultiplicationStatistics &statistics) {
    // Step 1: Prepare the public output-slot basis, then pair each live
    // low/high branch during one sequential source scan.
    prepare_output_slot_basis<Backend>(
        eval, nullptr, output_slot_weights, prepared_output_slots, statistics);
    const auto scan_start = multiplication_detail::begin_scan(reader,
                                                               statistics);
    const std::size_t suffix_count = reader.domain_size() / 2U;
    DenseMultiplicationRoundValues<fhe::MixedExtensionAccumulator<Backend>>
        product_sums;
    std::optional<typename Reader::Pair> pending;
    while (pending || reader.position() < reader.size()) {
        auto low_record = pending
                              ? std::move(*pending)
                              : multiplication_detail::next_pair(reader);
        pending.reset();
        std::optional<typename Reader::Pair> high_record;
        const std::size_t suffix =
            low_record.packed_index & (suffix_count - 1U);
        const bool record_is_high =
            low_record.packed_index >= suffix_count;
        if (!record_is_high && reader.position() < reader.size()) {
            auto candidate = multiplication_detail::next_pair(reader);
            if (candidate.packed_index == suffix_count + suffix) {
                high_record = std::move(candidate);
            } else {
                pending = std::move(candidate);
            }
        }

        const auto public_zero = fhe::FheValue<Backend>::public_zero();
        const auto &low_left =
            record_is_high ? public_zero : low_record.left();
        const auto &low_right =
            record_is_high ? public_zero : low_record.right();
        const auto &high_left = record_is_high
                                    ? low_record.left()
                                    : high_record ? high_record->left()
                                                  : public_zero;
        const auto &high_right = record_is_high
                                     ? low_record.right()
                                     : high_record ? high_record->right()
                                                   : public_zero;

        const std::array<const fhe::FheValue<Backend> *, 4> branches{
            &low_left, &low_right, &high_left, &high_right};
        for (const auto *branch : branches) {
            if (branch->is_encrypted()) {
                prepare_output_slot_basis<Backend>(
                    eval, &branch->ciphertext(), output_slot_weights,
                    prepared_output_slots, statistics);
                break;
            }
        }
        const std::size_t buffered_values =
            high_record ? 2U : pending ? 2U : 0U;
        multiplication_detail::note_source_residency(
            statistics, 2U + buffered_values);

        // Step 2: Select L(endpoint,u) and R(endpoint,u), multiply the concrete
        // base ciphertexts, and add their public suffix-weighted product.
        const auto endpoint_left = arithmetic::select_base_pair_branch<Backend>(
            eval, low_left, high_left, round_points.endpoint,
            kInvalidCiphertextIndexRoundPoint);
        const auto endpoint_right =
            arithmetic::select_base_pair_branch<Backend>(
                eval, low_right, high_right, round_points.endpoint,
                kInvalidCiphertextIndexRoundPoint);
        if (arithmetic::accumulate_base_product<Backend>(
                eval, product_sums.at_endpoint, endpoint_left, endpoint_right,
                weights.at_endpoint.suffix[suffix])) {
            multiplication_detail::note_base_product(statistics);
        }

        // Step 3: Repeat the same concrete FHE product at X=2.
        const auto left_at_two = arithmetic::select_base_pair_branch<Backend>(
            eval, low_left, high_left, round_points.at_two,
            kInvalidCiphertextIndexRoundPoint);
        const auto right_at_two = arithmetic::select_base_pair_branch<Backend>(
            eval, low_right, high_right, round_points.at_two,
            kInvalidCiphertextIndexRoundPoint);
        if (arithmetic::accumulate_base_product<Backend>(
                eval, product_sums.at_two, left_at_two, right_at_two,
                weights.at_two.suffix[suffix])) {
            multiplication_detail::note_base_product(statistics);
        }
        multiplication_detail::note_extension_residency(
            statistics, present_round_values(product_sums));
    }
    multiplication_detail::finish_scan(reader, scan_start, statistics);
    if (!prepared_output_slots) {
        throw std::logic_error(
            "packed multiplication output-slot basis was not prepared");
    }

    // Step 4: Apply eq(tau_slot,s), relinearize, and fold every SIMD slot.
    return {
        .at_endpoint = fold_product_sum_across_slots<Backend>(
            eval, std::move(product_sums.at_endpoint), *prepared_output_slots,
            statistics),
        .at_two = fold_product_sum_across_slots<Backend>(
            eval, std::move(product_sums.at_two), *prepared_output_slots,
            statistics),
    };
}

/// Later packed ciphertext-index round. Prior challenges make L and R
/// extension-field values, so the scan binds each suffix group before the
/// concrete extension products.
template <fhe::FheBackend Backend, typename Reader>
TransmittedLayerReductionRound<fhe::ExtensionValue<Backend>>
evaluate_later_packed_ciphertext_index_round(
    const typename Backend::EvalContext &eval, Reader &reader,
    std::size_t ciphertext_index_variables,
    std::span<const Fpk> ciphertext_index_prefix,
    const DenseMultiplicationRoundValues<CiphertextIndexRoundWeights> &weights,
    std::span<const Fpk> output_slot_weights,
    std::optional<MixedPreparedFpkSlotBasis<Backend>> &prepared_output_slots,
    FileBackedMultiplicationStatistics &statistics) {
    // Step 1: Build equality weights for the already fixed prefix at the
    // transmitted endpoint and at X=2.
    const DenseMultiplicationRoundValues<std::vector<Fpk>> bound_weights{
        .at_endpoint = poly::eq_evaluations(weights.at_endpoint.bound_point),
        .at_two = poly::eq_evaluations(weights.at_two.bound_point),
    };
    const std::size_t suffix_variables =
        ciphertext_index_variables - ciphertext_index_prefix.size() - 1U;
    const std::size_t suffix_count = poly::hypercube_size(suffix_variables);
    DenseMultiplicationRoundValues<fhe::ExtensionValue<Backend>> product_sums;
    std::optional<typename Reader::Pair> pending;
    prepare_output_slot_basis<Backend>(
        eval, nullptr, output_slot_weights, prepared_output_slots, statistics);
    const auto scan_start = multiplication_detail::begin_scan(reader,
                                                               statistics);

    // Step 2: Bind L and R to the existing prefix within each canonical suffix
    // group. Reader buffering and accounting remain local to this scan.
    while (pending || reader.position() < reader.size()) {
        std::optional<std::size_t> suffix;
        DenseMultiplicationRoundValues<
            arithmetic::WeightedBaseAccumulator<Backend>>
            left;
        DenseMultiplicationRoundValues<
            arithmetic::WeightedBaseAccumulator<Backend>>
            right;
        while (pending || reader.position() < reader.size()) {
            auto pair = pending
                            ? std::move(*pending)
                            : multiplication_detail::next_pair(reader);
            pending.reset();
            const std::size_t bound = pair.packed_index / suffix_count;
            const std::size_t pair_suffix =
                pair.packed_index & (suffix_count - 1U);
            if (!suffix) {
                suffix = pair_suffix;
            } else if (*suffix != pair_suffix) {
                pending = std::move(pair);
                break;
            }
            prepare_output_slot_basis<Backend>(
                eval, ciphertext_reference<Backend>(pair), output_slot_weights,
                prepared_output_slots, statistics);
            multiplication_detail::note_source_residency(statistics, 2U);
            left.at_endpoint.add(eval, pair.left(),
                                 bound_weights.at_endpoint[bound]);
            right.at_endpoint.add(eval, pair.right(),
                                  bound_weights.at_endpoint[bound]);
            left.at_two.add(eval, pair.left(), bound_weights.at_two[bound]);
            right.at_two.add(eval, pair.right(), bound_weights.at_two[bound]);
            multiplication_detail::note_extension_residency(
                statistics, 4U + present_round_values(product_sums));
        }
        if (!suffix) {
            throw std::logic_error(
                "file-backed multiplication suffix group was empty");
        }

        const DenseMultiplicationRoundValues<fhe::ExtensionValue<Backend>>
            left_values{
                .at_endpoint = std::move(left.at_endpoint).finish(eval),
                .at_two = std::move(left.at_two).finish(eval),
            };
        const DenseMultiplicationRoundValues<fhe::ExtensionValue<Backend>>
            right_values{
                .at_endpoint = std::move(right.at_endpoint).finish(eval),
                .at_two = std::move(right.at_two).finish(eval),
            };

        // Step 3: Multiply the restricted extension MLEs at both transmitted
        // points and apply the remaining suffix equality weight.
        if (arithmetic::accumulate_extension_product<Backend>(
                eval, product_sums.at_endpoint, left_values.at_endpoint,
                right_values.at_endpoint,
                weights.at_endpoint.suffix[*suffix])) {
            multiplication_detail::note_extension_product(statistics);
        }
        if (arithmetic::accumulate_extension_product<Backend>(
                eval, product_sums.at_two, left_values.at_two,
                right_values.at_two, weights.at_two.suffix[*suffix])) {
            multiplication_detail::note_extension_product(statistics);
        }
        multiplication_detail::note_extension_residency(
            statistics, present_round_values(product_sums));
    }
    multiplication_detail::finish_scan(reader, scan_start, statistics);
    if (!prepared_output_slots) {
        throw std::logic_error(
            "packed multiplication output-slot basis was not prepared");
    }

    // Step 4: Apply eq(tau_slot,s), relinearize, and fold every SIMD slot.
    return {
        .at_endpoint = fold_product_sum_across_slots<Backend>(
            eval, std::move(product_sums.at_endpoint), *prepared_output_slots,
            statistics),
        .at_two = fold_product_sum_across_slots<Backend>(
            eval, std::move(product_sums.at_two), *prepared_output_slots,
            statistics),
    };
}

} // namespace dense_multiplication_ciphertext_round_detail

/// Evaluate S(endpoint) and S(2) for one Folded/Laned ciphertext-index round.
///
/// For fixed ciphertext-index prefix `r` and remaining Boolean suffix `u`,
///
///   S_j(X) = sum_u eq(tau_suffix,u)
///                    L(r,X,u) R(r,X,u).
///
/// The first round selects base-ciphertext branches before multiplication.
/// Later rounds first bind the existing prefix into extension values and then
/// multiply those values. Both cases use one sequential source-artifact pass;
/// structural padding remains the public zero and causes no FHE operation.
template <fhe::FheBackend Backend, typename Reader>
TransmittedLayerReductionRound<fhe::ExtensionValue<Backend>>
evaluate_packed_multiplication_ciphertext_round(
    const typename Backend::EvalContext &eval, Reader &reader,
    std::span<const Fpk> output_point, std::size_t ciphertext_index_variables,
    std::span<const Fpk> ciphertext_index_prefix,
    const LayerReductionRoundPoints &round_points,
    std::span<const Fpk> output_slot_weights,
    std::optional<MixedPreparedFpkSlotBasis<Backend>> &prepared_output_slots,
    FileBackedMultiplicationStatistics &statistics) {
    namespace kernel = dense_multiplication_ciphertext_round_detail;

    if (ciphertext_index_variables == 0U ||
        reader.domain_size() !=
            poly::hypercube_size(ciphertext_index_variables) ||
        ciphertext_index_prefix.size() >= ciphertext_index_variables ||
        output_slot_weights.size() != Backend::slot_count(eval)) {
        throw std::invalid_argument(
            "file-backed packed multiplication round shape mismatch");
    }

    const DenseMultiplicationRoundValues<CiphertextIndexRoundWeights> weights{
        .at_endpoint = make_ciphertext_index_round_scalar_weights(
            output_point, ciphertext_index_variables,
            ciphertext_index_prefix, round_points.endpoint),
        .at_two = make_ciphertext_index_round_scalar_weights(
            output_point, ciphertext_index_variables,
            ciphertext_index_prefix, round_points.at_two),
    };
    if (ciphertext_index_prefix.empty()) {
        return kernel::evaluate_first_packed_ciphertext_index_round<Backend>(
            eval, reader, round_points, weights, output_slot_weights,
            prepared_output_slots, statistics);
    }
    return kernel::evaluate_later_packed_ciphertext_index_round<Backend>(
        eval, reader, ciphertext_index_variables, ciphertext_index_prefix,
        weights, output_slot_weights, prepared_output_slots, statistics);
}

/// Bind the complete ciphertext-index point into L and R in one final pass.
///
///   L(r;s) = sum_i eq(r,i)L_i(s),
///   R(r;s) = sum_i eq(r,i)R_i(s).
///
/// The pass is linear and deliberately performs no ciphertext product. With
/// an empty point, used by Base's one-pair layer, the accumulator retains
/// public base-field support rather than manufacturing extension coordinates.
template <fhe::FheBackend Backend, typename Reader>
MultiplicationSlotCheckpoints<Backend>
evaluate_multiplication_slot_checkpoints(
    const typename Backend::EvalContext &eval, Reader &reader,
    std::span<const Fpk> ciphertext_index_point,
    FileBackedMultiplicationStatistics &statistics) {
    if (reader.domain_size() !=
        poly::hypercube_size(ciphertext_index_point.size())) {
        throw std::invalid_argument(
            "file-backed multiplication checkpoint shape mismatch");
    }

    // Step 1: build the public equality weights for the complete point.
    const std::vector<Fpk> owned_point(ciphertext_index_point.begin(),
                                       ciphertext_index_point.end());
    const std::vector<Fpk> weights = poly::eq_evaluations(owned_point);
    dense_multiplication_accumulation_detail::WeightedBaseAccumulator<Backend>
        left;
    dense_multiplication_accumulation_detail::WeightedBaseAccumulator<Backend>
        right;
    const auto scan_start = multiplication_detail::begin_scan(reader,
                                                               statistics);

    // Step 2: bind L and R separately. Public-zero source records remain
    // absent, and no L*R multiplication occurs in this checkpoint pass.
    while (reader.position() < reader.size()) {
        auto pair = multiplication_detail::next_pair(reader);
        multiplication_detail::note_source_residency(statistics, 2U);
        if (ciphertext_index_point.empty()) {
            left.add_public_support(eval, pair.left(),
                                    weights[pair.packed_index]);
            right.add_public_support(eval, pair.right(),
                                     weights[pair.packed_index]);
        } else {
            left.add(eval, pair.left(), weights[pair.packed_index]);
            right.add(eval, pair.right(), weights[pair.packed_index]);
        }
        multiplication_detail::note_extension_residency(statistics, 2U);
    }
    multiplication_detail::finish_scan(reader, scan_start, statistics);

    // Step 3: retain the two slot-packed source MLEs for slot reduction or
    // Base's terminal source message.
    MultiplicationSlotCheckpoints<Backend> checkpoints{
        .left = std::move(left).finish(eval),
        .right = std::move(right).finish(eval),
    };
    statistics.peak_retained_slot_checkpoints = std::max(
        statistics.peak_retained_slot_checkpoints, std::size_t{2});
    return checkpoints;
}

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_ARITHMETIC_CIPHERTEXT_INDEX_ROUNDS_HPP
