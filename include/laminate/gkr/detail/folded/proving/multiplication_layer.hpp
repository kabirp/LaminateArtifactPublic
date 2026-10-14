#ifndef LAMINATE_GKR_DETAIL_FOLDED_PROVING_MULTIPLICATION_LAYER_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_PROVING_MULTIPLICATION_LAYER_HPP

/// @file multiplication_layer.hpp
/// @brief One Folded multiplication reduction and its artifact lifecycle.

#include "laminate/gkr/detail/folded/prover.hpp"

namespace laminate::gkr::folded_detail {

template <fhe::PersistableFheBackend Backend, typename TraceSource>
LayerClaim FoldedProver<Backend, TraceSource>::reduce_multiplication_layer(
    std::size_t layer, std::size_t multiplication_source_index,
    const LayerClaim &current, EncryptedFoldedProof<Backend> &proof,
    FileFoldedGkrReport &report) {
    const auto *single = std::get_if<SingleClaim>(&current);
    if (single == nullptr ||
        multiplication_source_index >= normalized_scratch_.size() ||
        multiplication_source_index >=
            multiplication_source_plans_.size()) {
        throw std::logic_error(
            "LaminateFolded multiplication claim ledger drifted");
    }
    const FileFoldedMultiplicationScratch &scratch =
        normalized_scratch_[multiplication_source_index];
    const auto &source_plan =
        multiplication_source_plans_[multiplication_source_index];
    if (scratch.reduction_layer != layer) {
        throw std::logic_error(
            "LaminateFolded multiplication scratch layer drifted");
    }

    // ===== Disk/source lifecycle before protocol work =================
    // Step 1: Materialize and authenticate the canonical dense L/R pair
    // artifact. The compact trace remains authoritative until this succeeds.
    storage::PreparedMultiplicationArtifact<Backend> artifact =
        storage::prepare_multiplication_artifact<Backend>(
            setup_.context, trace_, source_plan, scratch, options_.progress);

    // Step 2: The authenticated artifact is now authoritative, so the compact
    // trace layer can retire before the repeated sumcheck scans.
    std::optional<payload::FileTraceLayerRetirementReport> retirement =
        retire_trace_layer(layer + 1U);

    // ===== Laminate multiplication protocol and FHE arithmetic ========
    // Step 3: Prove
    //   claim = sum_(i,s) eq(output_point,(i,s)) L(i,s) R(i,s).
    // Telemetry distinguishes ciphertext-index rounds, which scan the pair
    // artifact, from slot-index rounds, which fold encrypted checkpoints.
    FoldedMultiplicationStatistics statistics;
    FoldedMultiplicationReductionResult<Backend> reduction =
        prove_multiplication<Backend>(
            setup_.context, circuit_, artifact.source, layer, *single,
            transcript_, transport_.reserved_mult_depth,
            commitment_function_, &statistics, options_.progress);
    LayerClaim next = reduction.next_claim;
    proof.reductions.emplace_back(std::move(reduction.proof));

    // ===== Disk/source lifecycle after protocol work ==================
    // Step 4: Preserve accounting, then reclaim the consumed artifact when
    // this proof owns an irreversible no-retry session.
    const FileFoldedMultiplicationArtifactReport artifact_report =
        artifact.report;
    const std::uint64_t reclaimed =
        storage::reclaim_multiplication_artifact(
            std::move(artifact.source), layer,
            artifact.report.storage.physical_bytes,
            reclaim_completed_multiplication_scratch_, options_.progress);

    // Reporting only; no field below enters Fiat--Shamir.
    report.reductions.push_back(FileFoldedReductionReport{
        layer,
        payload::LayerKind::Multiplication,
        std::nullopt,
        artifact_report,
        std::move(statistics),
        std::move(retirement),
        reclaimed});
    return next;
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_PROVING_MULTIPLICATION_LAYER_HPP
