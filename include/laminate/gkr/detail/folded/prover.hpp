#ifndef LAMINATE_GKR_DETAIL_FOLDED_PROVER_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_PROVER_HPP

/// @file prover.hpp
/// @brief Canonical file-backed LaminateFolded GKR prover.
///
/// Start here to read the production prover. `FoldedProver::run` shows the
/// complete output-to-input protocol order. The two layer helpers below the
/// class show where affine and multiplication sumchecks enter. The affine
/// evaluator is canonical; only its low-level reader mechanics live under
/// `affine/source/`. This is the only production prover path.

#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/folded/affine/prover.hpp"
#include "laminate/gkr/detail/folded/multiplication/prover.hpp"
#include "laminate/gkr/detail/folded/storage/multiplication_artifact.hpp"
#include "laminate/gkr/detail/folded/storage/types.hpp"
#include "laminate/gkr/detail/folded/validation/request.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/runtime_progress.hpp"
#include "laminate/setup.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace laminate::protocol::detail {
struct PackedExternalGkrAccess;
}

namespace laminate::gkr::folded_detail {

/// Proves LaminateFolded GKR from the compact, file-backed encrypted trace.
///
/// The class owns protocol state, not trace storage. `TraceSource` supplies
/// sequential readers and may retire a layer after its final consumer. Disk
/// paths, scan counters, and retirement reports are diagnostics and never
/// enter Fiat--Shamir.
template <fhe::PersistableFheBackend Backend, typename TraceSource>
class FoldedProver {
  public:
    FoldedProver(
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit, TraceSource &trace,
        const EvaluationSetup<Backend> &setup,
        std::span<const Fpk> output_point, Transcript &transcript,
        FileFoldedGkrOptions options,
        std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
        ProofTransportPolicy transport = {},
        PackedMessageCommitmentFunction<Backend> commitment_function = {},
        bool reclaim_completed_multiplication_scratch = true,
        std::optional<std::span<const ::laminate::gkr::detail::
                                    DenseMultiplicationSourcePlan>>
            preprocessed_multiplication_source_plans = std::nullopt)
        : payload_(payload), circuit_(circuit), trace_(trace), setup_(setup),
          output_claim_{std::vector<Fpk>(output_point.begin(),
                                        output_point.end()),
                        Fpk::zero()},
          transcript_(transcript), options_(std::move(options)),
          profile_{ProtocolVariant::LaminateFolded,
                   setup.public_setup.gate_mle_profile,
                   CrossRoundPacking::None},
          gate_claims_(circuit, setup.public_setup, transcript),
          affine_source_admission_(
              FoldedAffineSourceAdmission::from_certified_identity(
                  circuit, trace, setup.public_setup.layered_digest)),
          proof_ingress_rns_limbs_by_layer_(
              proof_ingress_rns_limbs_by_layer.begin(),
              proof_ingress_rns_limbs_by_layer.end()),
          transport_(transport),
          commitment_function_(std::move(commitment_function)),
          reclaim_completed_multiplication_scratch_(
              reclaim_completed_multiplication_scratch),
          preprocessed_multiplication_source_plans_(
              preprocessed_multiplication_source_plans) {}

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

    FileFoldedGkrResult<Backend> run() {
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

    /// Protocol state carried through the output-to-input reduction loop.
    struct OutputToInputProofState {
        /// Proof messages and non-transcript execution report built so far.
        FileFoldedGkrResult<Backend> result;
        /// Claim on the current circuit layer.
        LayerClaim claim;
        /// Next multiplication layer's validated scratch/source plan.
        std::size_t multiplication_source_index = 0;
    };

    /// Prove one request whose identities and storage resources have already
    /// passed the read-only admission boundary.
    FileFoldedGkrResult<Backend> prove_admitted_request() {
        OutputToInputProofState state;

        // ===== Laminate protocol initialization ==========================
        // Step 1: Bind the proof header and the client's output point before
        // emitting a layer-reduction message.
        state.result.proof = bind_proof_header_and_output_claim();
        state.result.report.reductions.reserve(circuit_.layers.size() - 1U);
        state.claim = LayerClaim{output_claim_};

        // ===== Disk/source lifecycle =====================================
        // Step 2: Layer zero has no remaining server-side consumer once its
        // output claim is bound. This report is not transcript data.
        state.result.report.output_trace_retirement = retire_trace_layer(0);

        // ===== Laminate GKR protocol and FHE arithmetic ==================
        // Step 3: Reduce the claim from the output layer to the input layer.
        // Each call owns one complete affine or multiplication sumcheck and
        // returns the claim consumed by the next reduction.
        for (std::size_t layer = 0; layer + 1U < circuit_.layers.size();
             ++layer) {
            const payload::LayerKind kind =
                payload::layer_kind(circuit_.layers[layer]);
            RuntimeProgressSpan reduction_progress(
                options_.progress, reduction_progress_event(layer, kind));

            if (kind == payload::LayerKind::Affine) {
                state.claim = reduce_affine_layer(
                    layer, state.claim, state.result.proof,
                    state.result.report);
            } else {
                state.claim = reduce_multiplication_layer(
                    layer, state.multiplication_source_index, state.claim,
                    state.result.proof, state.result.report);
                ++state.multiplication_source_index;
            }
            reduction_progress.finish();
        }

        // ===== Disk/source lifecycle completion ==========================
        // Step 4: Every multiplication source plan must have been consumed,
        // and an irreversible trace must now be empty.
        validate_completed_storage_lifecycle(state);

        // ===== Laminate protocol completion ==============================
        // Step 5: Open the preprocessed GateMLE commitment after all layer
        // evaluations have been appended in proof order.
        RuntimeProgressSpan gate_progress(
            options_.progress,
            RuntimeProgressEvent{
                .stage = RuntimeProgressStage::FoldedGateMleFinish});
        state.result.proof.gate_mle_opening =
            gate_claims_.finish(setup_.gate_mle_prover_key);
        gate_progress.finish();
        return std::move(state.result);
    }

    void validate_completed_storage_lifecycle(
        const OutputToInputProofState &state) const {
        if (state.multiplication_source_index != normalized_scratch_.size() ||
            state.multiplication_source_index !=
                multiplication_source_plans_.size()) {
            throw std::logic_error(
                "LaminateFolded multiplication scratch ledger drifted");
        }
        if constexpr (requires(const TraceSource &source) {
                          source.report().all_payload_artifacts_retired;
                          source.report().live_physical_bytes;
                      }) {
            if (!trace_.report().all_payload_artifacts_retired ||
                trace_.report().live_physical_bytes != 0) {
                throw std::logic_error(
                    "LaminateFolded proof retained a payload artifact");
            }
        }
    }

    void validate_preprocessed_request_identity();
    void bind_preprocessed_scratch_options();
    void validate_request_identity();
    void validate_static_claim_flow() const;
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
                        FoldedTraceLayerRetirement,
                    .source_layer = layer,
                });
            auto report = trace_.retire_layer(layer);
            retirement_progress.finish();
            return report;
        }
        return std::nullopt;
    }

    RuntimeProgressEvent reduction_progress_event(
        std::size_t layer, payload::LayerKind kind) const {
        return RuntimeProgressEvent{
            .stage = RuntimeProgressStage::FoldedReduction,
            .layer_kind =
                kind == payload::LayerKind::Affine
                    ? RuntimeProgressLayerKind::Affine
                    : RuntimeProgressLayerKind::Multiplication,
            .reduction_layer = layer,
            .source_layer = layer + 1U,
        };
    }

    EncryptedFoldedProof<Backend> bind_proof_header_and_output_claim() {
        EncryptedFoldedProof<Backend> proof;
        proof.header = ProofHeader{
            kEncryptedFoldedProofVersion,
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
        EncryptedFoldedProof<Backend> &proof,
        FileFoldedGkrReport &report);

    LayerClaim reduce_multiplication_layer(
        std::size_t layer, std::size_t multiplication_source_index,
        const LayerClaim &current, EncryptedFoldedProof<Backend> &proof,
        FileFoldedGkrReport &report);

    /// Public payload and its canonical layered arithmetization.
    const payload::PayloadCircuit &payload_;
    const payload::LayeredCircuit &circuit_;
    /// Compact trace source; destructive implementations retire consumed
    /// layers.
    TraceSource &trace_;
    /// Evaluation context and preprocessed GateMLE prover key.
    const EvaluationSetup<Backend> &setup_;
    /// Initial single claim at layer zero; its value is hidden from the
    /// server.
    SingleClaim output_claim_;
    /// Fiat--Shamir state shared by all Folded layer reductions.
    Transcript &transcript_;
    /// Storage policy, quotas, and measurement callback; not transcript data.
    FileFoldedGkrOptions options_;
    /// Fixed Folded transcript domain and GateMLE commitment mode.
    ProtocolProfile profile_;
    ::laminate::gkr::detail::ProverGateClaims gate_claims_;
    /// One setup-bound circuit/source identity check reused by every affine
    /// reduction. No layer is allowed to hash the circuit again.
    FoldedAffineSourceAdmission affine_source_admission_;
    /// Per-layer compact support established once by request admission.
    std::vector<payload::LayerWireSupport> admitted_layer_support_;
    /// Physical aliases derived beside support for standalone admission.
    /// Setup-preprocessed requests consume their already certified source
    /// plans and leave this vector empty.
    std::vector<payload::LayerStorageLayout> admitted_layer_storage_;
    /// Exact modulus level expected for every trace layer at proof ingress.
    std::vector<std::size_t> proof_ingress_rns_limbs_by_layer_;
    /// Message packing and retained-depth policy for the encrypted transcript.
    ProofTransportPolicy transport_;
    PackedMessageCommitmentFunction<Backend> commitment_function_;
    /// Validated output-to-input scratch plan for multiplication layers.
    std::vector<FileFoldedMultiplicationScratch> normalized_scratch_;
    /// Plans derived here for a standalone proof request.
    std::vector<::laminate::gkr::detail::
                    DenseMultiplicationSourcePlan>
        owned_multiplication_source_plans_;
    /// The one admitted plan sequence consumed by the production layer loop.
    /// It names either the owned plans above or setup-preprocessed plans.
    std::span<const ::laminate::gkr::detail::
                  DenseMultiplicationSourcePlan>
        multiplication_source_plans_;
    /// Whether each canonical pair artifact is deleted after its reduction.
    bool reclaim_completed_multiplication_scratch_ = true;
    /// Optional setup-preprocessed plans supplied to request admission.
    /// Presence is meaningful even for a circuit with no multiplication.
    std::optional<std::span<const ::laminate::gkr::detail::
                                DenseMultiplicationSourcePlan>>
        preprocessed_multiplication_source_plans_;
};

template <fhe::PersistableFheBackend Backend>
using FileFoldedGkrProver = FoldedProver<
    Backend, const payload::FileEncryptedTraceStore<Backend>>;

} // namespace laminate::gkr::folded_detail

// Support definitions are grouped by responsibility. The protocol-order loop
// above remains the single production entry.
#include "laminate/gkr/detail/folded/validation/request_admission.hpp"
#include "laminate/gkr/detail/folded/proving/affine_layer.hpp"
#include "laminate/gkr/detail/folded/proving/multiplication_layer.hpp"

namespace laminate::gkr::folded_detail {

// -------------------------------------------------------------------------
// Public file-backed entry points.
// -------------------------------------------------------------------------

template <fhe::PersistableFheBackend Backend>
void validate_folded_gkr_request(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point,
    const FileFoldedGkrOptions &options,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    ProofTransportPolicy transport = {}) {
    Transcript validation_transcript(
        "LaminateImpl/Folded/FileGkrPreflight/v1");
    FileFoldedGkrProver<Backend> prover(
        payload, circuit, trace, setup, output_point, validation_transcript,
        options, proof_ingress_rns_limbs_by_layer, transport);
    prover.validate_before_writes();
}

template <fhe::PersistableFheBackend Backend>
FileFoldedGkrResult<Backend> prove_folded_gkr(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    FileFoldedGkrOptions options,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    ProofTransportPolicy transport = {},
    PackedMessageCommitmentFunction<Backend> commitment_function = {}) {
    return FileFoldedGkrProver<Backend>(
               payload, circuit, trace, setup, output_point, transcript,
               std::move(options), proof_ingress_rns_limbs_by_layer,
               transport, std::move(commitment_function), true)
        .run();
}

template <fhe::PersistableFheBackend Backend, typename TraceSource>
FileFoldedGkrResult<Backend> prove_folded_gkr_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit, TraceSource &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    IrreversibleFileFoldedGkrOptions options,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    ProofTransportPolicy transport = {},
    PackedMessageCommitmentFunction<Backend> commitment_function = {}) {
    if (options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !options.reclaim_completed_multiplication_scratch) {
        throw std::invalid_argument(
            "destructive LaminateFolded proof requires "
            "IrreversibleNoRetry and immediate scratch reclamation");
    }
    return FoldedProver<Backend, TraceSource>(
               payload, circuit, trace, setup, output_point, transcript,
               std::move(options.proof), proof_ingress_rns_limbs_by_layer,
               transport, std::move(commitment_function), true)
        .run();
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_PROVER_HPP
