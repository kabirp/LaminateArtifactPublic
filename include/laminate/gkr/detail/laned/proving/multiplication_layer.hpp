#ifndef LAMINATE_GKR_DETAIL_LANED_PROVING_MULTIPLICATION_LAYER_HPP
#define LAMINATE_GKR_DETAIL_LANED_PROVING_MULTIPLICATION_LAYER_HPP

/// @file multiplication_layer.hpp
/// @brief One Laned multiplication reduction and its artifact lifecycle.

#include "laminate/gkr/detail/laned/prover.hpp"

namespace laminate::gkr::laned_detail {

template <fhe::PersistableFheBackend Backend, typename TraceSource>
LayerClaim LanedProver<Backend, TraceSource>::reduce_multiplication_layer(
    std::size_t layer, std::size_t multiplication_index,
    const LayerClaim &current, EncryptedLanedProof<Backend> &proof,
    FileLanedGkrReport &report) {
    const SingleClaim *single = std::get_if<SingleClaim>(&current);
    if (single == nullptr ||
        multiplication_index >= multiplication_scratch_plan_.size() ||
        multiplication_index >= multiplication_source_plans_.size()) {
        throw std::logic_error(
            "file-backed Laned multiplication claim ledger drifted");
    }
    const LanedMultiplicationArtifactPlan &artifact_plan =
        multiplication_scratch_plan_[multiplication_index];
    const auto &source_plan =
        multiplication_source_plans_[multiplication_index];
    if (artifact_plan.reduction_layer != layer) {
        throw std::logic_error(
            "file-backed Laned multiplication layer ledger drifted");
    }

    // ===== Disk/source lifecycle before protocol work =================
    // Step 1: Convert the compact trace layer into the canonical file-backed
    // `[left | right]` source consumed by the multiplication sumcheck.
    storage::PreparedMultiplicationArtifact<Backend> artifact =
        storage::prepare_multiplication_artifact<Backend>(
            setup_.context, trace_, source_plan, artifact_plan,
            options_.progress);

    // Step 2: The authenticated artifact now owns every live left/right
    // operand, so the compact trace layer has no later consumer.
    std::optional<payload::FileTraceLayerRetirementReport>
        trace_retirement = retire_trace_layer(layer + 1U);

    // ===== Laminate multiplication protocol and FHE arithmetic ========
    // Step 3: Prove Out(x,s)=Left(x,s)Right(x,s). Telemetry distinguishes the
    // ciphertext-index rounds, which scan the artifact and multiply under
    // FHE, from the slot-index rounds, which use the retained checkpoint.
    ::laminate::gkr::detail::FileBackedMultiplicationStatistics statistics;
    LanedMultiplicationLayerReductionResult<Backend> reduction =
        prove_multiplication<Backend>(
            setup_.context, circuit_, artifact.source, layer, *single,
            transcript_, transport_.reserved_mult_depth,
            commitment_function_, &statistics, options_.progress);
    LayerClaim next = reduction.next_claim;
    proof.reductions.emplace_back(std::move(reduction.proof));

    // ===== Disk/source lifecycle after protocol work ==================
    // Step 4: Reclaim the consumed pair artifact when this no-retry flow owns
    // it. Reporting records I/O and arithmetic without changing Fiat--Shamir.
    const std::uint64_t scratch_reclaimed_physical_bytes =
        storage::reclaim_multiplication_artifact(
            std::move(artifact.source), layer,
            artifact.write_report.report.physical_bytes,
            reclaim_completed_multiplication_scratch_, options_.progress);
    report.reductions.push_back(FileLanedReductionReport{
        layer,
        payload::LayerKind::Multiplication,
        std::nullopt,
        std::move(artifact.write_report),
        std::move(statistics),
        std::move(trace_retirement),
        scratch_reclaimed_physical_bytes,
    });
    return next;
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_PROVING_MULTIPLICATION_LAYER_HPP
