#ifndef LAMINATE_GKR_DETAIL_FOLDED_AFFINE_BASIS_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_AFFINE_BASIS_HPP

/// @file basis.hpp
/// @brief Public basis preparation for file-backed Folded affine reductions.

#include "laminate/gkr/detail/folded/affine/internal/gate_schedule.hpp"
#include "laminate/gkr/detail/folded/affine/diagnostics/statistics.hpp"
#include "laminate/gkr/detail/shared/packed/prepared_basis.hpp"

#include <algorithm>
#include <cstddef>
#include <vector>

namespace laminate::gkr::folded_detail {

/// Maximum number of prepared public slot bases retained while an affine
/// ciphertext-index round scans the compact source.
inline constexpr std::size_t kFoldedAffineCachedBasisLimit = 8;

namespace folded_affine_detail {

/// One already-evaluated public gate term, indexed within the current basis
/// batch. Equal basis indices are combined before any source ciphertext is
/// touched.
struct PreparedTerm {
    std::size_t basis = 0;
    Fpk coefficient = Fpk::zero();
};

inline void reduce_prepared_terms(std::vector<PreparedTerm> &terms) {
    std::sort(terms.begin(), terms.end(),
              [](const PreparedTerm &left, const PreparedTerm &right) {
                  return left.basis < right.basis;
              });
    std::size_t output = 0;
    for (std::size_t input = 0; input < terms.size();) {
        const std::size_t basis = terms[input].basis;
        Fpk coefficient = Fpk::zero();
        do {
            coefficient += terms[input].coefficient;
            ++input;
        } while (input < terms.size() && terms[input].basis == basis);
        terms[output++] = PreparedTerm{basis, coefficient};
    }
    terms.resize(output);
}

} // namespace folded_affine_detail

/// Prepare the immutable full-slot bases once, before any online source scan.
template <fhe::FheBackend Backend>
std::vector<detail::MixedPreparedFpkSlotBasis<Backend>>
prepare_affine_slot_bases(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext *level_reference,
    const AffineSparseSchedule &schedule) {
    std::vector<detail::MixedPreparedFpkSlotBasis<Backend>> result;
    result.reserve(schedule.bases.size());
    for (std::size_t basis = 0; basis < schedule.bases.size(); ++basis) {
        const std::vector<Fpk> values =
            affine_slot_basis_values(schedule, basis);
        result.push_back(detail::prepare_mixed_fpk_slot_basis<Backend>(
            eval, level_reference, values));
    }
    return result;
}

/// Record the backend storage introduced by one encrypted prepared basis.
template <fhe::FheBackend Backend>
void record_prepared_affine_basis(
    const detail::MixedPreparedFpkSlotBasis<Backend> &basis,
    FoldedAffineStatistics &statistics) {
    if (!basis.encrypted) {
        return;
    }
    folded_affine_detail::checked_accumulate(
        statistics.prepared_basis_preparations, 1,
        "Folded affine prepared basis count");
    folded_affine_detail::checked_accumulate(
        statistics.prepared_basis_level_representations,
        folded_affine_detail::checked_u64(
            basis.encrypted->storage.level_representations,
            "Folded affine prepared level representations"),
        "Folded affine prepared level representations");
    folded_affine_detail::checked_accumulate(
        statistics.prepared_basis_ntt_bytes,
        folded_affine_detail::checked_u64(
            basis.encrypted->storage.ntt_coefficient_bytes,
            "Folded affine prepared NTT bytes"),
        "Folded affine prepared NTT bytes");
    folded_affine_detail::checked_accumulate(
        statistics.prepared_basis_host_bytes,
        folded_affine_detail::checked_u64(
            basis.encrypted->storage.host_basis_bytes,
            "Folded affine prepared host bytes"),
        "Folded affine prepared host bytes");
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_AFFINE_BASIS_HPP
