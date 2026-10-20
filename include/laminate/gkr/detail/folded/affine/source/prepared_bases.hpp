#ifndef LAMINATE_GKR_DETAIL_FOLDED_AFFINE_SOURCE_PREPARED_BASES_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_AFFINE_SOURCE_PREPARED_BASES_HPP

/// @file prepared_bases.hpp
/// @brief Prepare Folded affine public bases at the source RNS level.

#include "laminate/gkr/detail/folded/affine/internal/basis.hpp"
#include "laminate/gkr/detail/folded/affine/source/scan.hpp"

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::folded_detail::folded_affine_detail {

/// Find the first encrypted source record and prepare the immutable public
/// slot bases at its modulus level. Reader rewinds and byte accounting stay
/// inside this source adapter; the protocol prover sees one preparation step.
template <fhe::FheBackend Backend, typename Reader>
std::vector<detail::MixedPreparedFpkSlotBasis<Backend>>
prepare_source_level_affine_bases(
    const typename Backend::EvalContext &eval, Reader &reader,
    const AffineSparseSchedule &schedule,
    FoldedAffineStatistics &statistics) {
    if (schedule.bases.size() > kFoldedAffineCachedBasisLimit) {
        return {};
    }

    const std::uint64_t bytes_before = encoded_bytes_read(reader);
    reader.rewind();
    // Keep the owning file record alive until basis preparation finishes.
    // Resident readers return references into the trace, but file readers own
    // the decoded ciphertext in this optional record.
    auto record = reader.next();
    const typename Backend::Ciphertext *level_reference = nullptr;
    while (record) {
        level_reference = encrypted_ciphertext_ptr<Backend>(
            record_stored_value(*record));
        if (level_reference != nullptr) {
            break;
        }
        record = reader.next();
    }

    auto prepared = prepare_affine_slot_bases<Backend>(
        eval, level_reference, schedule);
    for (const auto &basis : prepared) {
        record_prepared_affine_basis<Backend>(basis, statistics);
    }
    statistics.peak_retained_prepared_bases = prepared.size();

    const std::uint64_t bytes_after = encoded_bytes_read(reader);
    if (bytes_after < bytes_before) {
        throw std::logic_error(
            "LaminateFolded affine basis-reference bytes underflow");
    }
    statistics.basis_reference_ciphertexts_read =
        level_reference != nullptr ? 1 : 0;
    statistics.basis_reference_logical_bytes_read =
        bytes_after - bytes_before;
    reader.rewind();
    return prepared;
}

} // namespace laminate::gkr::folded_detail::folded_affine_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_AFFINE_SOURCE_PREPARED_BASES_HPP
