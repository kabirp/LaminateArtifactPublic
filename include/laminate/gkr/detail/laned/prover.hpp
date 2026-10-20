#ifndef LAMINATE_GKR_DETAIL_LANED_PROVER_HPP
#define LAMINATE_GKR_DETAIL_LANED_PROVER_HPP

/// @file prover.hpp
/// @brief Canonical file-backed LaminateLaned GKR prover.
///
/// Start reading at `LanedProver::prove_admitted_request`. It shows the
/// complete output-to-input protocol order directly:
///
/// 1. Bind the proof header, GateMLE setup, and output point.
/// 2. Retire the no-longer-needed output trace artifact.
/// 3. Reduce every affine or multiplication layer under FHE.
/// 4. Publish the one opening for all accumulated GateMLE claims.
///
/// Each layer helper keeps disk lifecycle visibly separate from protocol
/// arithmetic. The actual affine sequential scan lives under `affine/source/`
/// and dense multiplication scans live under
/// `detail/shared/dense_multiplication/source/`; the corresponding FHE kernels
/// live under `dense_multiplication/arithmetic/`. Bounded in-memory parity and
/// diagnostic implementations live under `reference/`.

#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/laned/affine/prover.hpp"
#include "laminate/gkr/detail/laned/multiplication/prover.hpp"
#include "laminate/gkr/detail/laned/proving/types.hpp"
#include "laminate/gkr/detail/laned/storage/multiplication_artifact.hpp"
#include "laminate/gkr/detail/laned/validation/request.hpp"
#include "laminate/setup.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace laminate::protocol::detail {
struct PackedExternalGkrAccess;
}

namespace laminate::gkr::laned_detail {

/// Mutable proof and claim state of one file-backed Laned GKR traversal.
/// `current_claim` always names the layer reduced next; the scratch index
/// names that multiplication layer's prevalidated dense-pair artifact.
template <fhe::PersistableFheBackend Backend>
struct LanedGkrProvingState {
    /// Proof bytes and non-transcript storage report accumulated so far.
    FileLanedGkrResult<Backend> result;
    /// Claim consumed by the next output-to-input layer reduction.
    LayerClaim current_claim;
    /// Next entry in the ordered multiplication scratch plan.
    std::size_t multiplication_index = 0;
};

/// Top-level production prover for LaminateLaned GKR.
///
/// The encrypted trace and multiplication operands stay file-backed. Proof
/// messages, the Fiat--Shamir transcript, and the current GKR claim remain in
/// memory. Request identity, geometry, scratch directories, and hard storage
/// limits are validated before the first artifact write.
template <fhe::PersistableFheBackend Backend, typename TraceSource>
class LanedProver {
  public:
    LanedProver(
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit,
        TraceSource &trace,
        const EvaluationSetup<Backend> &setup,
        std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
        std::span<const Fpk> output_point, Transcript &transcript,
        FileLanedGkrOptions options,
        ProofTransportPolicy transport = {},
        PackedMessageCommitmentFunction<Backend>
            commitment_function = {},
        bool reclaim_completed_multiplication_scratch = false,
        std::optional<std::span<const ::laminate::gkr::detail::
                                    DenseMultiplicationSourcePlan>>
            preprocessed_multiplication_source_plans = std::nullopt)
        : payload_(payload), circuit_(circuit), trace_(trace), setup_(setup),
          affine_source_admission_(
              LanedAffineSourceAdmission::from_certified_identity(
                  circuit, trace, setup.public_setup.layered_digest)),
          proof_ingress_rns_limbs_by_layer_(
              proof_ingress_rns_limbs_by_layer.begin(),
              proof_ingress_rns_limbs_by_layer.end()),
          output_claim_{std::vector<Fpk>(output_point.begin(),
                                         output_point.end()),
                        Fpk::zero()},
          transcript_(transcript), options_(std::move(options)),
          profile_{ProtocolVariant::LaminateLaned,
                   setup.public_setup.gate_mle_profile,
                   CrossRoundPacking::None},
          gate_claims_(circuit, setup.public_setup, transcript),
          transport_(transport),
          commitment_function_(std::move(commitment_function)),
          reclaim_completed_multiplication_scratch_(
              reclaim_completed_multiplication_scratch),
          preprocessed_multiplication_source_plans_(
              preprocessed_multiplication_source_plans) {}

    /// Validate identity, geometry, scratch limits, and every destination
    /// without observing a transcript message or writing an artifact.
    void validate_before_writes() {
        if (preprocessed_multiplication_source_plans_) {
            // Static claim geometry was certified with these source plans at
            // server startup. Online admission checks only request-varying
            // trace identity, storage state, and scratch capacity.
            validate_preprocessed_request_identity();
            bind_preprocessed_scratch_options();
        } else {
            validate_request_identity();
            validate_scratch_options();
            validate_static_claim_flow();
        }
    }

    FileLanedGkrResult<Backend> run() {
        // ===== Read-only request admission ================================
        // Step 1: Bind all trace identities, source layouts, and disk limits
        // before observing Fiat--Shamir or creating an artifact.
        validate_before_writes();

        // ===== Admitted Laminate protocol ================================
        // Step 2: Run the canonical file-backed protocol. The packed external
        // server calls the same method after performing admission separately.
        return prove_admitted_request();
    }

  private:
    friend struct ::laminate::protocol::detail::PackedExternalGkrAccess;

    /// Run a request whose identity and storage plan were already admitted.
    /// This is private except for the packed external server path, which must
    /// place request timing after static validation.
    FileLanedGkrResult<Backend> prove_admitted_request() {
        // ===== Laminate protocol initialization ============================
        // Step 1: Bind the proof header, GateMLE setup, and output point.
        LanedGkrProvingState<Backend> state{
            FileLanedGkrResult<Backend>{}, LayerClaim{output_claim_}};
        state.result.proof = begin_proof();
        state.result.report.reductions.reserve(
            circuit_.layers.size() - 1U);

        // ===== Disk/source lifecycle =======================================
        // Step 2: The proof header and public output claim now retain all
        // information needed from layer zero, so its trace file may retire.
        state.result.report.output_trace_retirement = retire_trace_layer(0);

        // ===== Laminate GKR protocol and FHE arithmetic ====================
        // Step 3: Walk from the claimed output toward the input. Every layer
        // helper owns one complete reduction and returns the next GKR claim.
        for (std::size_t layer = 0; layer + 1U < circuit_.layers.size();
             ++layer) {
            const payload::LayerKind kind =
                payload::layer_kind(circuit_.layers[layer]);
            RuntimeProgressSpan reduction_progress(
                options_.progress, reduction_progress_event(layer, kind));

            if (kind == payload::LayerKind::Affine) {
                state.current_claim = reduce_affine_layer(
                    layer, state.current_claim, state.result.proof,
                    state.result.report);
            } else {
                state.current_claim = reduce_multiplication_layer(
                    layer, state.multiplication_index,
                    state.current_claim, state.result.proof,
                    state.result.report);
                ++state.multiplication_index;
            }
            reduction_progress.finish();
        }
        // ===== Disk/source lifecycle completion ===========================
        // Step 4: Confirm that each admitted multiplication artifact was used
        // once and an irreversible trace retained no payload files.
        validate_completed_storage_lifecycle(state);

        // ===== Laminate protocol completion ================================
        // Step 5: Publish the single opening for all GateMLE claims collected
        // during the affine reductions.
        RuntimeProgressSpan gate_progress(
            options_.progress,
            RuntimeProgressEvent{
                .stage = RuntimeProgressStage::LanedGateMleFinish});
        state.result.proof.gate_mle_opening =
            gate_claims_.finish(setup_.gate_mle_prover_key);
        gate_progress.finish();
        return std::move(state.result);
    }

    void validate_completed_storage_lifecycle(
        const LanedGkrProvingState<Backend> &state) const {
        if (state.multiplication_index !=
                multiplication_scratch_plan_.size() ||
            state.multiplication_index !=
                multiplication_source_plans_.size()) {
            throw std::logic_error(
                "LaminateLaned multiplication scratch ledger drifted");
        }
        if constexpr (requires(const TraceSource &source) {
                          source.report().all_payload_artifacts_retired;
                          source.report().live_physical_bytes;
                      }) {
            if (!trace_.report().all_payload_artifacts_retired ||
                trace_.report().live_physical_bytes != 0) {
                throw std::logic_error(
                    "LaminateLaned proof retained a payload artifact");
            }
        }
    }

    // Request-admission helpers. These never write an artifact.
    void validate_preprocessed_request_identity();
    void bind_preprocessed_scratch_options();
    void validate_static_claim_flow() const;
    void validate_request_identity();
    void validate_scratch_options();

    std::optional<payload::FileTraceLayerRetirementReport>
    retire_trace_layer(std::size_t layer) {
        if constexpr (requires(TraceSource &source) {
                          source.retire_layer(layer);
                      }) {
            RuntimeProgressSpan retirement_progress(
                options_.progress,
                RuntimeProgressEvent{
                    .stage = RuntimeProgressStage::
                        LanedTraceLayerRetirement,
                    .source_layer = layer,
                });
            auto report = trace_.retire_layer(layer);
            retirement_progress.finish();
            return report;
        } else {
            return std::nullopt;
        }
    }

    RuntimeProgressEvent reduction_progress_event(
        std::size_t layer, payload::LayerKind kind) const {
        return RuntimeProgressEvent{
            .stage = RuntimeProgressStage::LanedReduction,
            .layer_kind =
                kind == payload::LayerKind::Affine
                    ? RuntimeProgressLayerKind::Affine
                    : RuntimeProgressLayerKind::Multiplication,
            .reduction_layer = layer,
            .source_layer = layer + 1U,
        };
    }

    // Protocol helpers. These own transcript-visible messages and claims.
    EncryptedLanedProof<Backend> begin_proof() {
        EncryptedLanedProof<Backend> proof;
        proof.header = ProofHeader{
            kEncryptedLanedProofVersion,
            profile_,
            trace_.descriptor().provenance,
            trace_.descriptor().circuit_id,
            setup_digest(setup_.public_setup),
            trace_.descriptor().trace_id,
            circuit_.layers.size()};
        proof.reductions.reserve(circuit_.layers.size() - 1U);
        observe_proof_header(proof.header, transcript_);
        gates::observe_gate_mle_setup(setup_.public_setup, transcript_);
        base_detail::observe_output_point(output_claim_.point, transcript_);
        return proof;
    }

    LayerClaim reduce_affine_layer(
        std::size_t layer, const LayerClaim &current,
        EncryptedLanedProof<Backend> &proof,
        FileLanedGkrReport &report);

    LayerClaim reduce_multiplication_layer(
        std::size_t layer, std::size_t multiplication_index,
        const LayerClaim &current, EncryptedLanedProof<Backend> &proof,
        FileLanedGkrReport &report);

    /// Public payload semantics authenticated by setup.
    const payload::PayloadCircuit &payload_;
    /// Layered arithmetization traversed from output to input.
    const payload::LayeredCircuit &circuit_;
    /// File-backed trace whose consumed layers may be retired in order.
    TraceSource &trace_;
    /// FHE context, public GateMLE setup, and its prover key.
    const EvaluationSetup<Backend> &setup_;
    /// One setup-bound circuit/source identity check reused by every affine
    /// reduction. No layer is allowed to hash the circuit again.
    LanedAffineSourceAdmission affine_source_admission_;
    /// Required source RNS level for each reduction boundary.
    std::vector<std::size_t> proof_ingress_rns_limbs_by_layer_;
    /// Public output point with an encrypted-prover value placeholder.
    SingleClaim output_claim_;
    /// Fiat--Shamir state shared by all reductions in proof order.
    Transcript &transcript_;
    /// Scratch roots, storage limits, and progress callback.
    FileLanedGkrOptions options_;
    /// Variant and GateMLE mode bound into the proof header.
    ProtocolProfile profile_;
    /// Affine GateMLE claims accumulated into one final opening.
    ::laminate::gkr::detail::ProverGateClaims gate_claims_;
    /// Per-layer compact support established once by request admission.
    std::vector<payload::LayerWireSupport> admitted_layer_support_;
    /// Physical aliases derived beside support for standalone admission.
    /// Setup-preprocessed requests use their certified source plans instead.
    std::vector<payload::LayerStorageLayout> admitted_layer_storage_;
    /// Message-compaction policy for encrypted proof transport.
    ProofTransportPolicy transport_;
    /// Optional binding applied to packed messages in transcript order.
    PackedMessageCommitmentFunction<Backend> commitment_function_;
    /// Validated multiplication layer-to-artifact map in proof order.
    std::vector<LanedMultiplicationArtifactPlan>
        multiplication_scratch_plan_;
    /// Plans derived here for a standalone proof request.
    std::vector<::laminate::gkr::detail::
                    DenseMultiplicationSourcePlan>
        owned_multiplication_source_plans_;
    /// The one admitted plan sequence consumed by multiplication layers.
    std::span<const ::laminate::gkr::detail::
                  DenseMultiplicationSourcePlan>
        multiplication_source_plans_;
    /// Whether consumed multiplication artifacts belong to this attempt.
    bool reclaim_completed_multiplication_scratch_ = false;
    /// Optional setup-preprocessed plans supplied to request admission.
    /// Presence is meaningful even when no multiplication layers exist.
    std::optional<std::span<const ::laminate::gkr::detail::
                                DenseMultiplicationSourcePlan>>
        preprocessed_multiplication_source_plans_;
};

} // namespace laminate::gkr::laned_detail

// Support definitions are grouped by responsibility. The protocol-order loop
// above remains the single production entry.
#include "laminate/gkr/detail/laned/validation/scratch.hpp"
#include "laminate/gkr/detail/laned/validation/request_admission.hpp"
#include "laminate/gkr/detail/laned/proving/affine_layer.hpp"
#include "laminate/gkr/detail/laned/proving/multiplication_layer.hpp"

namespace laminate::gkr::laned_detail {

/// Validate a retryable file store and every GKR scratch declaration without
/// changing the store, scratch directories, or caller transcript.
template <fhe::PersistableFheBackend Backend>
void validate_laned_gkr_request(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    std::span<const Fpk> output_point,
    const FileLanedGkrOptions &options) {
    Transcript validation_transcript(
        "LaminateImpl/Laned/FileGkrPreflight/v1");
    LanedProver<
        Backend, const payload::FileEncryptedTraceStore<Backend>> prover(
        payload, circuit, trace, setup,
        proof_ingress_rns_limbs_by_layer, output_point,
        validation_transcript, options);
    prover.validate_before_writes();
}

/// Produce a Laned GKR proof from a validated, retryable file-backed trace.
template <fhe::PersistableFheBackend Backend>
FileLanedGkrResult<Backend> prove_laned_gkr(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    std::span<const Fpk> output_point, Transcript &transcript,
    FileLanedGkrOptions options,
    ProofTransportPolicy transport = {},
    PackedMessageCommitmentFunction<Backend> commitment_function = {}) {
    return LanedProver<
               Backend,
               const payload::FileEncryptedTraceStore<Backend>>(
               payload, circuit, trace, setup,
               proof_ingress_rns_limbs_by_layer, output_point, transcript,
               std::move(options), transport,
               std::move(commitment_function))
        .run();
}

/// Produce a Laned GKR proof while retiring consumed trace and scratch files.
/// The caller must explicitly authorize the no-retry lifecycle.
template <fhe::PersistableFheBackend Backend>
FileLanedGkrResult<Backend> prove_laned_gkr_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::FileEncryptedTraceReclamationSession<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    std::span<const Fpk> output_point, Transcript &transcript,
    IrreversibleFileLanedGkrOptions options,
    ProofTransportPolicy transport = {},
    PackedMessageCommitmentFunction<Backend> commitment_function = {}) {
    if (options.lifecycle !=
        payload::FileTraceSessionLifecycle::IrreversibleNoRetry) {
        throw std::invalid_argument(
            "destructive file-backed Laned proof requires "
            "IrreversibleNoRetry");
    }
    return LanedProver<
               Backend,
               payload::FileEncryptedTraceReclamationSession<Backend>>(
               payload, circuit, trace, setup,
               proof_ingress_rns_limbs_by_layer, output_point, transcript,
               std::move(options.proof), transport,
               std::move(commitment_function),
               options.reclaim_completed_multiplication_scratch)
        .run();
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_PROVER_HPP
