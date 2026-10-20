#ifndef LAMINATE_GKR_DETAIL_FOLDED_PROVING_AFFINE_LAYER_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_PROVING_AFFINE_LAYER_HPP

/// @file affine_layer.hpp
/// @brief One Folded affine reduction and its file-retirement handoff.

#include "laminate/gkr/detail/folded/prover.hpp"

namespace laminate::gkr::folded_detail {

template <fhe::PersistableFheBackend Backend, typename TraceSource>
LayerClaim FoldedProver<Backend, TraceSource>::reduce_affine_layer(
    std::size_t layer, const LayerClaim &current,
    EncryptedFoldedProof<Backend> &proof, FileFoldedGkrReport &report) {
    FoldedAffineStatistics statistics;

    // ===== Laminate affine protocol and FHE arithmetic ================
    // Step 1: Prove the Folded affine reduction. Ciphertext-index and
    // slot-index rounds are reported separately by `prove_affine`.
    FoldedAffineReductionResult<Backend> reduction =
        prove_admitted_affine<Backend>(
        setup_.context, circuit_, trace_, affine_source_admission_,
        admitted_layer_support_.at(layer + 1U), layer, current, transcript_,
        transport_.reserved_mult_depth, &gate_claims_, commitment_function_,
        &statistics, options_.progress);

    // ===== Disk/source lifecycle ======================================
    // Step 2: Give the proof and next-layer claim their protocol owners before
    // retiring the compact source layer that produced them.
    LayerClaim next = reduction.next_claim;
    proof.reductions.emplace_back(std::move(reduction.proof));
    std::optional<payload::FileTraceLayerRetirementReport> retirement =
        retire_trace_layer(layer + 1U);

    // Reporting only; these counters are not part of Fiat--Shamir.
    report.reductions.push_back(FileFoldedReductionReport{
        layer,
        payload::LayerKind::Affine,
        std::move(statistics),
        std::nullopt,
        std::nullopt,
        std::move(retirement),
        0});
    return next;
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_PROVING_AFFINE_LAYER_HPP
