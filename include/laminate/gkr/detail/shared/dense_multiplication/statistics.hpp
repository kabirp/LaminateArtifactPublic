#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_STATISTICS_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_STATISTICS_HPP

/// @file statistics.hpp
/// @brief I/O, FHE-work, and residency counters for one multiplication reduction.

#include <cstddef>
#include <cstdint>

namespace laminate::gkr::detail {

/// Exact counters for the canonical file-backed evaluator. Source residency
/// counts decoded artifact values owned across evaluator calls; extension
/// residency counts accumulators retained across reader advances.
struct FileBackedMultiplicationStatistics {
    std::uint64_t artifact_scans = 0;
    std::uint64_t artifact_rewinds = 0;
    std::uint64_t artifact_pairs_read = 0;
    /// Physical decodes, including rereads of evicted aliases on each scan.
    std::uint64_t artifact_values_read = 0;
    std::uint64_t artifact_logical_record_bytes_read = 0;
    std::uint64_t artifact_framed_record_bytes_read = 0;
    std::uint64_t artifact_index_bit_flips = 0;
    std::uint64_t base_products = 0;
    std::uint64_t extension_products = 0;
    std::uint64_t suffix_scalar_promotions = 0;
    std::uint64_t prepared_output_slot_bases = 0;
    std::uint64_t prepared_basis_level_representations = 0;
    std::uint64_t prepared_basis_ntt_bytes = 0;
    std::uint64_t prepared_basis_host_bytes = 0;
    std::uint64_t prepared_output_slot_basis_applications = 0;
    std::uint64_t online_slot_vectors_constructed = 0;
    std::uint64_t avoided_online_slot_vector_elements = 0;
    std::uint64_t slot_checkpoint_prefix_pairs_bound = 0;
    std::uint64_t slot_public_mask_pairs_constructed = 0;
    std::size_t peak_live_decoded_source_values = 0;
    std::size_t peak_retained_extension_accumulators = 0;
    std::size_t peak_retained_slot_checkpoints = 0;

    bool operator==(const FileBackedMultiplicationStatistics &) const = default;
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_STATISTICS_HPP
