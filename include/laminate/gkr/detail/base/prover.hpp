#ifndef LAMINATE_GKR_DETAIL_BASE_PROVER_HPP
#define LAMINATE_GKR_DETAIL_BASE_PROVER_HPP

/// @file prover.hpp
/// @brief Proof-order implementation for the file-backed LaminateBase prover.
///
/// Start at `BaseProver::run`: it performs read-only request admission, then
/// shows the complete output-to-input protocol order. Each multiplication
/// helper visibly fences artifact preparation and reclamation away from the
/// encrypted sumcheck call. This is the only production prover path.

#include "laminate/gkr/detail/base/proving/types.hpp"
#include "laminate/setup.hpp"

#include "laminate/gkr/detail/base/affine/prover.hpp"
#include "laminate/gkr/detail/base/multiplication/prover.hpp"
#include "laminate/gkr/detail/base/storage/multiplication_artifact.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/base/validation/request.hpp"
#include "laminate/gkr/detail/base/validation/admission.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace laminate::gkr::base_detail {

/// One no-retry Base proof session over a compact active-wire source.
/// Filesystem paths, replay choices, and I/O reports never enter the proof
/// transcript.
template <fhe::PersistableFheBackend Backend, typename TraceSource>
class BaseProver {
  public:
    BaseProver(
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit, TraceSource &trace,
        const EvaluationSetup<Backend> &setup,
        std::span<const Fpk> output_point, Transcript &transcript,
        FileEncryptedBaseGkrOptions options)
        : payload_(payload), circuit_(circuit), trace_(trace), setup_(setup),
          affine_source_admission_(
              BaseAffineSourceAdmission::from_certified_identity(
                  circuit, trace, setup.public_setup.layered_digest)),
          output_claim_{std::vector<Fpk>(output_point.begin(),
                                            output_point.end()),
                           Fpk::zero()},
          transcript_(transcript),
          options_(std::move(options)),
          profile_{ProtocolVariant::LaminateBase,
                   setup.public_setup.gate_mle_profile,
                   CrossRoundPacking::None},
          provider_(circuit),
          gate_claims_(circuit, setup.public_setup, transcript) {}

    /// Complete all identity, claim-flow, scratch-path, lower-bound quota,
    /// and capacity checks without observing the transcript or writing.
    void validate_before_writes() {
        auto validated = validation::validate_base_request(
            payload_, circuit_, trace_, setup_, output_claim_, profile_,
            options_);
        normalized_scratch_ =
            std::move(validated.multiplication_scratch);
        admitted_layer_support_ = std::move(validated.layer_support);
        admitted_multiplication_source_plans_ =
            std::move(validated.multiplication_source_plans);
    }

    FileBaseGkrResult<Backend> run() {
        // ===== Read-only request admission ================================
        // Step 1: Bind all trace identities, live-wire support, and disk
        // limits before observing Fiat--Shamir or creating an artifact.
        validate_before_writes();

        FileBaseGkrResult<Backend> result;

        // ===== Laminate protocol initialization ===========================
        // Step 2: Bind the proof header, GateMLE setup, and output point.
        // `begin_proof()` performs only in-memory proof construction and the
        // canonical transcript observations. An irreversible outer protocol
        // passes a staged transcript copy; it publishes that copy only after
        // this run succeeds. Retiring layer zero immediately afterward is
        // the trace's observable no-retry boundary.
        result.proof = begin_proof();
        result.report.reductions.reserve(circuit_.layers.size() - 1U);

        // ===== Disk/source lifecycle ======================================
        // Step 3: Retire the claimed output layer. Its public claim is now
        // transcript-bound, so no later server-side phase reads this file.
        result.report.output_trace_retirement = retire_trace_layer(0);

        // ===== Laminate GKR protocol and FHE arithmetic ===================
        // Step 4: Reduce each logical layer from output toward input. The
        // layer helpers keep their source/artifact lifecycle visibly separate
        // from the affine or multiplication FHE call.
        LayerClaim current_claim{output_claim_};
        std::size_t multiplication_index = 0;
        for (std::size_t layer = 0; layer + 1U < circuit_.layers.size();
             ++layer) {
            const payload::LayerKind kind =
                payload::layer_kind(circuit_.layers[layer]);
            RuntimeProgressSpan reduction_progress(
                options_.progress, reduction_progress_event(layer, kind));

            // GKR carries one claim from the output toward the inputs. An
            // affine layer produces another single claim; multiplication
            // interpolates its terminal endpoints into one selector claim.
            if (kind == payload::LayerKind::Affine) {
                current_claim = reduce_affine_layer(
                    layer, current_claim, result.proof, result.report);
            } else {
                current_claim = reduce_multiplication_layer(
                    layer, multiplication_index, current_claim,
                    result.proof, result.report);
                ++multiplication_index;
            }
            reduction_progress.finish();
        }

        // ===== Disk/source lifecycle completion ===========================
        // Step 5: Confirm that each admitted multiplication artifact was used
        // once and an irreversible trace retained no payload files.
        validate_completed_storage_lifecycle(multiplication_index);

        // ===== Laminate protocol completion ===============================
        // Step 6: Open the preprocessed affine GateMLE commitment after every
        // layer claim has been registered.
        RuntimeProgressSpan gate_progress(
            options_.progress, gate_mle_progress_event());
        result.proof.gate_mle_opening =
            gate_claims_.finish(setup_.gate_mle_prover_key);
        gate_progress.finish();
        return result;
    }

  private:
    void validate_completed_storage_lifecycle(
        std::size_t multiplication_index) const {
        if (multiplication_index != normalized_scratch_.size() ||
            multiplication_index !=
                admitted_multiplication_source_plans_.size()) {
            throw std::logic_error(
                "Base multiplication scratch ledger drifted");
        }
        if constexpr (requires(const TraceSource &source) {
                          source.report().all_payload_artifacts_retired;
                          source.report().live_physical_bytes;
                      }) {
            if (!trace_.report().all_payload_artifacts_retired ||
                trace_.report().live_physical_bytes != 0) {
                throw std::logic_error(
                    "Base proof retained a payload artifact");
            }
        }
    }
    RuntimeProgressEvent reduction_progress_event(
        std::size_t layer, payload::LayerKind kind) const {
        return RuntimeProgressEvent{
            .stage = RuntimeProgressStage::BaseReduction,
            .layer_kind =
                kind == payload::LayerKind::Affine
                    ? RuntimeProgressLayerKind::Affine
                    : RuntimeProgressLayerKind::Multiplication,
            .reduction_layer = layer,
            .source_layer = layer + 1U,
        };
    }

    RuntimeProgressEvent gate_mle_progress_event() const {
        return RuntimeProgressEvent{
            .stage = RuntimeProgressStage::BaseGateMleFinish};
    }

    std::optional<payload::FileTraceLayerRetirementReport>
    retire_trace_layer(std::size_t layer) {
        if constexpr (requires(TraceSource &source) {
                          source.retire_layer(layer);
                      }) {
            RuntimeProgressSpan retirement_progress(
                options_.progress,
                RuntimeProgressEvent{
                    .stage = RuntimeProgressStage::BaseTraceLayerRetirement,
                    .source_layer = layer,
                });
            auto report = trace_.retire_layer(layer);
            retirement_progress.finish();
            return report;
        }
        return std::nullopt;
    }

    EncryptedBaseProof<Backend> begin_proof() {
        EncryptedBaseProof<Backend> proof;
        proof.header = ProofHeader{
            kEncryptedBaseProofVersion,
            profile_,
            trace_.descriptor().provenance,
            trace_.descriptor().circuit_id,
            setup_digest(setup_.public_setup),
            trace_.descriptor().trace_id,
            circuit_.layers.size()};
        proof.reductions.reserve(circuit_.layers.size() - 1U);
        observe_proof_header(proof.header, transcript_);
        gates::observe_gate_mle_setup(setup_.public_setup, transcript_);
        observe_output_point(output_claim_.point, transcript_);
        return proof;
    }

    LayerClaim reduce_affine_layer(
        std::size_t layer, const LayerClaim &current,
        EncryptedBaseProof<Backend> &proof, FileBaseGkrReport &report) {
        // ===== Laminate affine protocol and FHE arithmetic ================
        // Step 1: Prove
        //   claim - constant = sum_x GateMLE(claim, x) * SourceMLE(x).
        // Per-round telemetry identifies every ciphertext-index scan.
        BaseAffineStatistics statistics;
        auto reduction = prove_admitted_affine_reduction<Backend>(
            setup_.context, circuit_, trace_, affine_source_admission_,
            admitted_layer_support_.at(layer + 1U), layer, current,
            provider_, transcript_, &gate_claims_, &statistics,
            options_.progress);
        LayerClaim next = reduction.next_claim;
        proof.reductions.emplace_back(std::move(reduction.proof));

        // ===== Disk/source lifecycle ======================================
        // Step 2: The proof now owns the source-layer claim, so retire the
        // compact trace artifact that produced it.
        auto retirement = retire_trace_layer(layer + 1U);
        report.reductions.push_back(FileBaseReductionReport{
            layer,
            payload::LayerKind::Affine,
            std::move(statistics),
            std::nullopt,
            std::nullopt,
            std::move(retirement),
            0,
        });
        return next;
    }

    LayerClaim reduce_multiplication_layer(
        std::size_t layer, std::size_t multiplication_index,
        const LayerClaim &current, EncryptedBaseProof<Backend> &proof,
        FileBaseGkrReport &report) {
        const auto *single = std::get_if<SingleClaim>(&current);
        if (single == nullptr ||
            multiplication_index >= normalized_scratch_.size()) {
            throw std::logic_error(
                "Base multiplication claim ledger drifted");
        }
        const FileBaseMultiplicationScratch &scratch =
            normalized_scratch_[multiplication_index];
        const detail::DenseMultiplicationSourcePlan &source_plan =
            admitted_multiplication_source_plans_.at(multiplication_index);
        if (scratch.reduction_layer != layer ||
            source_plan.descriptor_template.reduction_layer != layer) {
            throw std::logic_error(
                "Base multiplication layer ledger drifted");
        }

        // ===== Disk/source lifecycle before protocol work =================
        // Step 1: Build and authenticate the alias-aware dense pair artifact.
        // No sumcheck arithmetic or transcript observation occurs here.
        auto artifact =
            storage::prepare_multiplication_artifact<Backend>(
                setup_.context, trace_, source_plan, scratch,
                options_.progress);

        // Step 2: The authenticated artifact now owns every live operand, so
        // the compact trace layer has no later consumer.
        auto retirement = retire_trace_layer(layer + 1U);

        // ===== Laminate multiplication protocol and FHE arithmetic ========
        // Step 3: Reduce every ciphertext-index coordinate, then publish the
        // two slot-packed terminal source MLEs.
        detail::FileBackedMultiplicationStatistics statistics;
        auto reduction = prove_multiplication_reduction<Backend>(
            setup_.context, circuit_, artifact.source, layer, *single,
            transcript_, &statistics, options_.progress);
        LayerClaim next = reduction.next_claim;
        proof.reductions.emplace_back(std::move(reduction.proof));

        // ===== Disk/source lifecycle after protocol work ==================
        // Step 4: The pair artifact is dead after the terminal source
        // evaluation. Preserve its fixed-size report, then reclaim its files.
        const FileBaseMultiplicationArtifactReport artifact_report =
            artifact.report;
        const std::uint64_t reclaimed =
            storage::reclaim_multiplication_artifact(
                std::move(artifact.source), layer,
                artifact_report.storage.physical_bytes, options_.progress);
        // The report retains only fixed-size geometry and exact byte/I/O
        // counters; setup-derived alias metadata remains local to the
        // reclaimed artifact.
        report.reductions.push_back(FileBaseReductionReport{
            layer,
            payload::LayerKind::Multiplication,
            std::nullopt,
            artifact_report,
            std::move(statistics),
            std::move(retirement),
            reclaimed,
        });
        return next;
    }

    const payload::PayloadCircuit &payload_;
    const payload::LayeredCircuit &circuit_;
    TraceSource &trace_;
    const EvaluationSetup<Backend> &setup_;
    /// Setup-certified evidence reused by every affine reduction. Consuming
    /// it checks a fixed-size digest and never hashes the circuit again.
    BaseAffineSourceAdmission affine_source_admission_;
    SingleClaim output_claim_;
    Transcript &transcript_;
    FileEncryptedBaseGkrOptions options_;
    ProtocolProfile profile_;
    gates::DirectGateMle provider_;
    ::laminate::gkr::detail::ProverGateClaims gate_claims_;
    /// Canonical support established once by whole-request admission.
    std::vector<payload::LayerWireSupport> admitted_layer_support_;
    std::vector<FileBaseMultiplicationScratch> normalized_scratch_;
    /// Circuit-static pair/alias plans established by the same admission.
    std::vector<detail::DenseMultiplicationSourcePlan>
        admitted_multiplication_source_plans_;
};

template <fhe::PersistableFheBackend Backend, typename TraceSource>
void validate_base_gkr_irreversible_request(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit, const TraceSource &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point,
    const FileEncryptedBaseGkrOptions &options) {
    const SingleClaim output_claim{
        std::vector<Fpk>(output_point.begin(), output_point.end()),
        Fpk::zero()};
    const ProtocolProfile profile{
        ProtocolVariant::LaminateBase,
        setup.public_setup.gate_mle_profile,
        CrossRoundPacking::None};
    (void)validation::validate_base_request(
        payload, circuit, trace, setup, output_claim, profile, options);
}

/// Irreversible prover for either a file-reclamation session or a checkpoint-
/// replay trace. Static preflight precedes the first transcript observation,
/// file write, and retirement. Once layer zero is retired, every failure is a
/// terminal session failure.
template <fhe::PersistableFheBackend Backend, typename TraceSource>
FileBaseGkrResult<Backend> prove_base_gkr_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit, TraceSource &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    FileEncryptedBaseGkrOptions options) {
    return BaseProver<Backend, TraceSource>(
               payload, circuit, trace, setup, output_point, transcript,
               std::move(options))
        .run();
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_PROVER_HPP
