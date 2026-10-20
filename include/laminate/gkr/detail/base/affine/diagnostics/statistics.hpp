#ifndef LAMINATE_GKR_DETAIL_BASE_AFFINE_STATISTICS_HPP
#define LAMINATE_GKR_DETAIL_BASE_AFFINE_STATISTICS_HPP

/// @file statistics.hpp
/// @brief I/O, FHE-work, and residency counters for a Base affine reduction.

#include <cstddef>
#include <cstdint>

namespace laminate::gkr::base_detail {

struct BaseAffineStatistics {
    // Sequential compact-source traffic. Padding is counted algebraically in
    // `public_zero_positions` and never appears as a stored record.
    std::uint64_t source_scans = 0;
    std::uint64_t source_rewinds = 0;
    std::uint64_t source_ciphertexts_read = 0;
    std::uint64_t public_zero_positions = 0;
    std::uint64_t source_logical_bytes_read = 0;
    std::uint64_t source_framed_record_bytes_read = 0;

    // Peak ciphertext and extension state retained across reader advances.
    std::size_t peak_live_source_ciphertexts = 0;
    std::size_t peak_retained_extension_accumulators = 0;

    // Online FHE work induced by sparse affine terms and their public slot
    // rotation bases.
    std::uint64_t source_scalar_promotions = 0;
    std::uint64_t prepared_rotation_bases = 0;
    std::size_t distinct_rotation_bases = 0;
    std::uint64_t rotation_basis_batches = 0;
    std::size_t peak_retained_prepared_rotation_bases = 0;
    std::uint64_t prepared_basis_level_representations = 0;
    std::uint64_t prepared_basis_ntt_bytes = 0;
    std::uint64_t prepared_basis_host_bytes = 0;
    std::uint64_t prepared_rotation_basis_applications = 0;
    std::uint64_t prepared_base_promotion_applications = 0;

    // These stay zero in the production kernel: it neither builds an N-slot
    // vector nor allocates or hash-probes sparse coefficients per record.
    std::uint64_t online_slot_vectors_constructed = 0;
    std::uint64_t per_record_coefficient_allocations = 0;
    std::uint64_t per_record_coefficient_hash_probes = 0;
    std::uint64_t avoided_online_slot_vector_elements = 0;

    // Public sparse scheduling work, kept separate from backend FHE calls.
    std::uint64_t public_live_source_candidate_weight_lookups = 0;
    std::uint64_t public_live_source_weight_updates = 0;
    std::uint64_t public_gate_term_candidate_visits = 0;
    std::uint64_t public_gate_term_weight_updates = 0;
    std::uint64_t public_gate_binding_sorts = 0;
    std::uint64_t public_dense_prefix_table_entries = 0;

    bool operator==(const BaseAffineStatistics &) const = default;
};

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_AFFINE_STATISTICS_HPP
