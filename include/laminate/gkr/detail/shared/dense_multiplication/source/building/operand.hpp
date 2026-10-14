#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_BUILDING_OPERAND_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_BUILDING_OPERAND_HPP

/// @file operand.hpp
/// @brief FHE packing kernel for one dense multiplication operand.

#include "laminate/gkr/detail/shared/dense_multiplication/source/descriptor.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <utility>

namespace laminate::gkr::detail::file_dense_multiplication_source_detail {

/// Pack consecutive source ciphertexts into disjoint slot chunks:
///
///   packed = sum_c rotate_c(first_chunk_mask * source_c).
///
/// Known public-zero chunks contribute nothing and never become encrypted.
/// The result is reduced immediately to the proof-ingress modulus level.
template <fhe::PersistableFheBackend Backend, typename Reader,
          typename SourceProgress>
fhe::FheValue<Backend> pack_one_sequential(
    const typename Backend::EvalContext &eval,
    Reader &reader, std::size_t expected_padded_begin,
    std::size_t live_source_count,
    const FileDenseMultiplicationSourceDescriptor &descriptor,
    std::optional<fhe::PreparedFpSlotBasis<Backend>>
        &prepared_first_chunk,
    FileDenseMultiplicationSourceBuildStatistics &statistics,
    SourceProgress &&source_progress) {
    const std::size_t chunks = descriptor.chunks_per_packed_ciphertext;
    fhe::FheValue<Backend> accumulator =
        fhe::FheValue<Backend>::public_zero();
    fhe::SlotVector first_chunk_basis(
        descriptor.shape.slot_count, Fp::zero());
    std::fill_n(first_chunk_basis.begin(), descriptor.shape.lane_count,
                Fp::one());
    const std::size_t count = std::min(chunks, live_source_count);
    for (std::size_t chunk = 0; chunk < count; ++chunk) {
        auto source = reader.next();
        if (!source ||
            source->padded_index != expected_padded_begin + chunk) {
            throw std::runtime_error(
                "packed multiplication sequential source order drifted");
        }
        checked_accumulate(statistics.source_values_read, 1,
                           "packed multiplication source read count");
        source_progress();
        if (source->value.is_encrypted()) {
            validate_dense_artifact_ingress_ciphertext<Backend>(
                eval, source->value.ciphertext(),
                descriptor.source_proof_ingress_rns_limbs,
                "dense multiplication artifact input");
        }
        statistics.peak_live_source_values = std::max(
            statistics.peak_live_source_values, std::size_t{1});

        fhe::FheValue<Backend> term;
        if (chunks == 1) {
            term = std::move(source->value);
        } else if (source->value.is_public_zero()) {
            continue;
        } else if (source->value.is_public()) {
            term = fhe::value_mul<Backend>(
                eval, source->value,
                fhe::FheValue<Backend>::public_slots(first_chunk_basis));
        } else {
            if (!prepared_first_chunk) {
                prepared_first_chunk = fhe::prepare_fp_slot_basis<Backend>(
                    eval, source->value.ciphertext(), first_chunk_basis);
                checked_accumulate(
                    statistics.prepared_chunk_bases, 1,
                    "packed multiplication prepared chunk bases");
            }
            term = fhe::FheValue<Backend>::from_ciphertext(
                fhe::mul_plain_prepared<Backend>(
                    eval, source->value.ciphertext(),
                    *prepared_first_chunk));
            checked_accumulate(
                statistics.prepared_chunk_basis_applications, 1,
                "packed multiplication prepared chunk applications");
            checked_accumulate(
                statistics.avoided_online_slot_vector_elements,
                checked_count(descriptor.shape.slot_count,
                              "packed multiplication avoided vector size"),
                "packed multiplication avoided vector elements");
        }
        if (chunks != 1 && chunk != 0) {
            term = fhe::value_rotate<Backend>(
                eval, term,
                fhe::grid_inverse(
                    descriptor.shape.slot_count,
                    chunk * descriptor.shape.lane_count));
            checked_accumulate(
                statistics.chunk_placement_rotations, 1,
                "packed multiplication chunk rotations");
        }
        fhe::value_add_assign<Backend>(eval, accumulator,
                                       std::move(term));
    }
    if (accumulator.is_encrypted()) {
        fhe::mod_switch_to_rns_limb_count<Backend>(
            eval, accumulator.ciphertext(),
            descriptor.packed_proof_ingress_rns_limbs);
        validate_dense_artifact_ingress_ciphertext<Backend>(
            eval, accumulator.ciphertext(),
            descriptor.packed_proof_ingress_rns_limbs,
            "dense multiplication artifact output");
    }
    statistics.peak_live_packed_values = std::max(
        statistics.peak_live_packed_values, std::size_t{1});
    return accumulator;
}

} // namespace laminate::gkr::detail::file_dense_multiplication_source_detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_BUILDING_OPERAND_HPP
