#ifndef LAMINATE_GKR_DETAIL_FOLDED_AFFINE_STATISTICS_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_AFFINE_STATISTICS_HPP

/// @file statistics.hpp
/// @brief Measurement-only state for file-backed Folded affine reductions.

#include "laminate/gkr/detail/folded/affine/internal/ciphertext_index_equalities.hpp"
#include "laminate/gkr/detail/folded/affine/arithmetic/slot_round.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

namespace laminate::gkr::folded_detail {

/// Exact source traffic and bounded encrypted residency for one Folded affine
/// reduction. Public padding is counted but is never represented by a
/// ciphertext or returned by the active reader.
struct FoldedAffineStatistics {
    std::uint64_t source_scans = 0;
    std::uint64_t source_rewinds = 0;
    std::uint64_t source_ciphertexts_read = 0;
    std::uint64_t source_logical_bytes_read = 0;
    std::uint64_t source_framed_record_bytes_read = 0;
    std::uint64_t public_zero_positions = 0;
    std::uint64_t public_term_visits = 0;
    /// Distinct (suffix,basis) entries visited from source records after
    /// public gate terms have been reduced. This is O(live_sources * R),
    /// where R is the number of distinct rotation/claim bases, never
    /// live_sources times gate terms.
    std::uint64_t source_basis_visits = 0;
    std::uint64_t basis_reference_ciphertexts_read = 0;
    std::uint64_t basis_reference_logical_bytes_read = 0;
    std::uint64_t scalar_source_promotions = 0;
    std::uint64_t prepared_basis_applications = 0;
    /// Distinct bases in the public schedule, independent of round count.
    std::size_t prepared_basis_count = 0;
    /// Prepared handles actually constructed. This equals the distinct count
    /// when it fits one cached batch and otherwise repeats once per
    /// ciphertext-index round.
    std::uint64_t prepared_basis_preparations = 0;
    std::uint64_t ciphertext_index_round_basis_batches = 0;
    std::size_t peak_retained_prepared_bases = 0;
    std::uint64_t prepared_basis_level_representations = 0;
    std::uint64_t prepared_basis_ntt_bytes = 0;
    std::uint64_t prepared_basis_host_bytes = 0;
    /// Raw public host-field data retained by the schedule. This is exactly
    /// one N-slot equality table per claim (at most two), not one per
    /// rotation basis.
    std::size_t retained_public_claim_table_entries = 0;
    /// One N-slot permutation is generated transiently while preparing a
    /// backend basis. Backend-prepared residency is accounted separately.
    std::size_t peak_transient_public_basis_entries = 0;
    /// Production constructs no challenge-dependent N-slot plaintext in a
    /// source-record loop; this counter is an executable guardrail.
    std::uint64_t online_slot_vectors_constructed = 0;
    std::uint64_t avoided_online_slot_vector_elements = 0;
    std::size_t peak_live_source_ciphertexts = 0;
    std::size_t peak_retained_extension_accumulators = 0;
    FoldedAffineSlotRoundStatistics slot_rounds;
    CiphertextIndexEqualityStatistics ciphertext_index_equalities;

    bool operator==(const FoldedAffineStatistics &) const = default;
};

namespace folded_affine_detail {

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

} // namespace folded_affine_detail
} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_AFFINE_STATISTICS_HPP
