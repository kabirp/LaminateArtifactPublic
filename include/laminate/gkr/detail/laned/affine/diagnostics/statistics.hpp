#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_STATISTICS_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_STATISTICS_HPP

/// @file statistics.hpp
/// @brief I/O, preparation, and residency counters for Laned affine GKR.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

namespace laminate::gkr::laned_detail {

/// I/O and source-residency facts for one file-backed affine reduction.
///
/// `peak_live_source_ciphertexts` counts decoded trace records owned by the
/// evaluator, not the fixed-size extension accumulators used by FHE
/// arithmetic. It is independent of the source-layer length.
struct LanedAffineStatistics {
    /// Reader passes started. The materialized backend makes one source pass;
    /// the streaming fallback makes one pass per ciphertext-index round and
    /// one final checkpoint pass.
    std::uint64_t source_scans = 0;
    /// Explicit reader rewind calls; the evaluator rewinds before every pass.
    std::uint64_t source_rewinds = 0;
    /// Indexed contiguous ranges visited across bounded chunk batches.
    /// Their union is one complete source pass per ciphertext round.
    std::uint64_t source_range_seeks = 0;
    /// Batches used to cap the number of resident extension accumulators.
    std::uint64_t chunk_batches = 0;
    std::uint64_t source_ciphertexts_read = 0;
    std::uint64_t source_logical_bytes_read = 0;
    /// Exact record-length prefixes plus ciphertext payload bytes read after
    /// the store's initial validation pass.
    std::uint64_t source_framed_record_bytes_read = 0;
    /// Fpk entries built for cached MSB-prefix equality tables. Lookups are
    /// constant-time and never rebuild an equality product per source wire.
    std::uint64_t public_prefix_weight_entries_built = 0;
    std::uint64_t public_prefix_weight_lookups = 0;
    /// Fpk cells produced while rolling the affine gate table through both
    /// transmitted points and the sampled challenge. The geometric total is
    /// O(original gate-table size), not one full contraction per round.
    std::uint64_t public_gate_table_entries_processed = 0;
    /// Challenge-dependent source coefficients use scalar plaintext
    /// multiplication. Fixed N-slot lane-placement bases are prepared once at
    /// the source level, then reused after each scan.
    std::uint64_t source_scalar_promotions = 0;
    /// Challenge-independent B-periodic source packing performed once before
    /// the materialized affine backend evaluates any sumcheck round.
    std::uint64_t materialized_source_plain_multiplications = 0;
    std::uint64_t materialized_source_rotations = 0;
    std::uint64_t materialized_source_additions = 0;
    std::uint64_t materialized_packed_source_values = 0;
    /// General Fpk SIMD masks applied to the reusable packed source. Each
    /// application replaces a complete scalar-weighted source scan.
    std::uint64_t materialized_packed_mask_applications = 0;
    std::uint64_t materialized_packed_mask_elements = 0;
    std::uint64_t prepared_lane_bases = 0;
    std::uint64_t prepared_basis_level_representations = 0;
    std::uint64_t prepared_basis_ntt_bytes = 0;
    std::uint64_t prepared_basis_host_bytes = 0;
    std::uint64_t prepared_lane_basis_applications = 0;
    std::uint64_t lane_placement_extension_rotations = 0;
    /// Each slot round binds the fixed checkpoint prefix once and constructs
    /// the pair of public R(1)/R(2) masks together.
    std::uint64_t slot_checkpoint_prefix_bindings = 0;
    std::uint64_t slot_public_mask_pairs_constructed = 0;
    std::uint64_t online_slot_vectors_constructed = 0;
    std::uint64_t avoided_online_slot_vector_elements = 0;
    /// Presence bits inspected solely to maintain the accumulator peak.
    /// This remains one per scalar promotion; telemetry never scans the
    /// complete chunk array after a source term.
    std::uint64_t accumulator_presence_observations = 0;
    std::size_t peak_live_source_ciphertexts = 0;
    std::size_t peak_chunk_batch_size = 0;
    std::size_t peak_retained_extension_accumulators = 0;
    std::size_t peak_retained_extension_checkpoints = 0;

    bool operator==(const LanedAffineStatistics &other) const = default;
};

namespace affine_detail {

inline void checked_accumulate(std::uint64_t &destination,
                               std::uint64_t value,
                               const char *description) {
    if (value > std::numeric_limits<std::uint64_t>::max() - destination) {
        throw std::overflow_error(std::string(description) +
                                  " overflows u64");
    }
    destination += value;
}

inline std::uint64_t checked_u64(std::size_t value,
                                 const char *description) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(description) +
                                      " does not fit u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

inline void note_scalar_promotion_and_peak(
    bool introduced_accumulator, std::size_t &present_accumulators,
    LanedAffineStatistics *statistics) {
    if (statistics == nullptr) {
        return;
    }
    checked_accumulate(statistics->source_scalar_promotions, 1,
                       "file-backed affine scalar promotion count");
    checked_accumulate(
        statistics->accumulator_presence_observations, 1,
        "file-backed affine accumulator presence observations");
    if (introduced_accumulator) {
        if (present_accumulators ==
            std::numeric_limits<std::size_t>::max()) {
            throw std::overflow_error(
                "file-backed affine present accumulator count overflows "
                "size_t");
        }
        ++present_accumulators;
    }
    statistics->peak_retained_extension_accumulators = std::max(
        statistics->peak_retained_extension_accumulators,
        present_accumulators);
}

} // namespace affine_detail
} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_STATISTICS_HPP
