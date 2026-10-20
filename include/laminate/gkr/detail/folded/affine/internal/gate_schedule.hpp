#ifndef LAMINATE_GKR_DETAIL_FOLDED_AFFINE_SCHEDULE_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_AFFINE_SCHEDULE_HPP

/// @file gate_schedule.hpp
/// @brief Sparse public gate schedule for a Folded affine reduction.

#include "laminate/gkr/claims.hpp"
#include "laminate/gates/gate_mle.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/gkr/detail/folded/affine/internal/ciphertext_index_equalities.hpp"
#include "laminate/poly/eq.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::folded_detail {

/// One generic prepared slot basis belonging to one current output claim.
struct AffineSlotBasis {
    std::size_t claim = 0;
    std::size_t rotation = 0;
};

/// One nonzero public term of the affine gate MLE.
struct AffineSparseTerm {
    std::size_t source = 0;
    std::size_t basis = 0;
    Fpk coefficient = Fpk::zero();
};

/// Sparse source/basis decomposition of the public affine gate polynomial.
/// Wide DAGs use the same reverse-propagated bases as the Base prover, including
/// nonuniform diagonal multipliers. Challenge-induced zero weights remain in
/// the schedule for conservative noise accounting.
struct AffineSparseSchedule {
    /// Output equality tables retain the slot geometry. Generated schedules
    /// read their actual generic basis vectors from prepared_claims.
    std::vector<std::vector<Fpk>> claim_boolean_values;
    std::vector<AffineSlotBasis> bases;
    std::vector<AffineSparseTerm> terms;
    std::vector<gates::PreparedDirectAffineMle> prepared_claims;
};

inline std::size_t affine_slot_count(
    const AffineSparseSchedule &schedule) {
    if (schedule.claim_boolean_values.empty() ||
        schedule.claim_boolean_values.front().empty()) {
        throw std::invalid_argument(
            "LaminateFolded affine schedule has no claim slot table");
    }
    const std::size_t slot_count =
        schedule.claim_boolean_values.front().size();
    for (const auto &claim : schedule.claim_boolean_values) {
        if (claim.size() != slot_count) {
            throw std::invalid_argument(
                "LaminateFolded affine claim slot tables differ in size");
        }
    }
    return slot_count;
}

inline Fpk affine_slot_basis_value(
    const AffineSparseSchedule &schedule, std::size_t basis,
    std::size_t slot) {
    const std::size_t slot_count = affine_slot_count(schedule);
    if (basis >= schedule.bases.size() || slot >= slot_count) {
        throw std::out_of_range(
            "LaminateFolded affine slot-basis index is out of range");
    }
    const AffineSlotBasis &descriptor = schedule.bases[basis];
    if (descriptor.claim >= schedule.claim_boolean_values.size()) {
        throw std::logic_error(
            "LaminateFolded affine slot basis names an invalid claim");
    }
    if (!schedule.prepared_claims.empty()) {
        return schedule.prepared_claims.at(descriptor.claim)
            .rotation_slot_basis(descriptor.rotation)[slot];
    }
    const std::size_t destination = fhe::grid_source(
        slot_count, fhe::grid_inverse(slot_count, descriptor.rotation), slot);
    return schedule.claim_boolean_values[descriptor.claim][destination];
}

inline std::vector<Fpk> affine_slot_basis_values(
    const AffineSparseSchedule &schedule, std::size_t basis) {
    const std::size_t slot_count = affine_slot_count(schedule);
    std::vector<Fpk> result(slot_count, Fpk::zero());
    for (std::size_t slot = 0; slot < slot_count; ++slot) {
        result[slot] = affine_slot_basis_value(schedule, basis, slot);
    }
    return result;
}

inline AffineSparseSchedule make_affine_sparse_schedule(
    const payload::LayeredCircuit &circuit, std::size_t layer,
    const LayerClaim &current_claim) {
    const std::size_t output_ciphertext_index_variables =
        base_detail::ciphertext_index_variables(circuit, layer);
    const std::size_t slot_variables =
        base_detail::slot_index_variables(circuit);
    AffineSparseSchedule result;
    const gates::DirectGateMle provider(circuit);
    const auto add_claim = [&](const SingleClaim &claim,
                               const Fpk &batch_weight,
                               std::size_t claim_index) {
        if (claim.point.size() !=
            output_ciphertext_index_variables + slot_variables) {
            throw std::invalid_argument(
                "LaminateFolded affine output point shape mismatch");
        }
        const std::vector<Fpk> output_slot(
            claim.point.begin() + static_cast<std::ptrdiff_t>(
                output_ciphertext_index_variables), claim.point.end());
        result.claim_boolean_values.push_back(poly::eq_evaluations(output_slot));
        auto prepared = provider.prepare_affine(layer, claim.point);
        const std::size_t offset = result.bases.size();
        for (std::size_t basis = 0; basis < prepared.rotation_basis_count(); ++basis) {
            result.bases.push_back(AffineSlotBasis{claim_index, basis});
        }
        for (const auto &term : prepared.weighted_terms()) {
            result.terms.push_back(AffineSparseTerm{
                term.source, offset + term.rotation_index,
                batch_weight * term.coefficient});
        }
        result.prepared_claims.push_back(std::move(prepared));
    };
    if (const auto *single = std::get_if<SingleClaim>(&current_claim)) {
        add_claim(*single, Fpk::one(), 0);
    } else {
        const BatchedClaim &batched = std::get<BatchedClaim>(current_claim);
        add_claim(batched.first, Fpk::one(), 0);
        add_claim(batched.second, batched.challenge, 1);
    }
    return result;
}

/// Evaluate every slot basis at a complete ciphertext-index point.
inline std::vector<Fpk> affine_basis_weights(
    const AffineSparseSchedule &schedule,
    std::span<const Fpk> ciphertext_index_point,
    std::size_t ciphertext_index_variables,
    PreparedCiphertextIndexEqualities *ciphertext_index_equalities = nullptr) {
    std::vector<Fpk> result(schedule.bases.size(), Fpk::zero());
    for (const AffineSparseTerm &term : schedule.terms) {
        result[term.basis] +=
            term.coefficient *
            (ciphertext_index_equalities
                 ? ciphertext_index_equalities->fixed(term.source)
                 : ciphertext_index_equality_prefix(
                       ciphertext_index_point, term.source,
                       ciphertext_index_variables));
    }
    return result;
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_AFFINE_SCHEDULE_HPP
