#ifndef LAMINATE_GKR_DETAIL_LANED_PROVING_AFFINE_LAYER_HPP
#define LAMINATE_GKR_DETAIL_LANED_PROVING_AFFINE_LAYER_HPP

/// @file affine_layer.hpp
/// @brief One Laned affine reduction and its file-retirement handoff.

#include "laminate/gkr/detail/laned/prover.hpp"

namespace laminate::gkr::laned_detail {

template <fhe::PersistableFheBackend Backend, typename TraceSource>
LayerClaim LanedProver<Backend, TraceSource>::reduce_affine_layer(
    std::size_t layer, const LayerClaim &current,
    EncryptedLanedProof<Backend> &proof, FileLanedGkrReport &report) {
    LanedAffineStatistics statistics;

    // ===== Laminate affine protocol and FHE arithmetic ================
    // Step 1: Prove
    //   claim - constant = sum_x GateMLE(claim, x) * SourceMLE(x).
    LanedAffineLayerReductionResult<Backend> reduction =
        prove_admitted_affine<Backend>(
            setup_.context, circuit_, trace_, affine_source_admission_,
            admitted_layer_support_.at(layer + 1U), layer, current,
            transcript_, proof_ingress_rns_limbs_by_layer_.at(layer + 1U),
            transport_.reserved_mult_depth, &gate_claims_,
            commitment_function_, &statistics, options_.progress);

    // ===== Disk/source lifecycle ======================================
    // Step 2: Retain the reduction and transformed source claim before
    // retiring the compact source layer that produced them.
    LayerClaim next = reduction.next_claim;
    proof.reductions.emplace_back(std::move(reduction.proof));
    std::optional<payload::FileTraceLayerRetirementReport>
        trace_retirement = retire_trace_layer(layer + 1U);

    // Reporting only; these counters are not part of Fiat--Shamir.
    report.reductions.push_back(FileLanedReductionReport{
        layer,
        payload::LayerKind::Affine,
        std::move(statistics),
        std::nullopt,
        std::nullopt,
        std::move(trace_retirement),
        0,
    });
    return next;
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_PROVING_AFFINE_LAYER_HPP
