#ifndef LAMINATE_PAYLOAD_CHECKPOINT_SESSION_ENGINE_HPP
#define LAMINATE_PAYLOAD_CHECKPOINT_SESSION_ENGINE_HPP

/// @file session_engine.hpp
/// @brief Publication, replay, proof-ingress, and retirement session engine.

#include "laminate/payload/checkpoint/readers.hpp"
#include "laminate/payload/checkpoint/detail/relation_alias.hpp"
#include "laminate/payload/checkpoint/detail/relation_progress.hpp"
#include "laminate/payload/checkpoint/laned_witness_packing.hpp"
#include "laminate/payload/evaluation/proof_ciphertext_normalization.hpp"
#include "laminate/payload/evaluation/slot_encoding.hpp"
#include "laminate/payload/evaluation/detail/fhe_evaluation_core.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace laminate::payload {

namespace checkpoint_replay_execution_detail {

class ScopedOperationTimer {
  public:
    explicit ScopedOperationTimer(FileTraceStoreOperationTiming &destination)
        : destination_(&destination), wall_start_(Clock::now()),
          cpu_start_(std::clock()) {}

    ~ScopedOperationTimer() { finish(); }

    FileTraceStoreOperationTiming snapshot() const {
        if (destination_ == nullptr) {
            return {};
        }
        const auto wall_end = Clock::now();
        const std::clock_t cpu_end = std::clock();
        return {
            std::chrono::duration<double, std::milli>(wall_end - wall_start_)
                .count(),
            cpu_start_ == static_cast<std::clock_t>(-1) ||
                    cpu_end == static_cast<std::clock_t>(-1)
                ? 0.0
                : 1000.0 * static_cast<double>(cpu_end - cpu_start_) /
                      static_cast<double>(CLOCKS_PER_SEC),
        };
    }

    void finish() {
        if (destination_ == nullptr) {
            return;
        }
        *destination_ += snapshot();
        destination_ = nullptr;
    }

    ScopedOperationTimer(const ScopedOperationTimer &) = delete;
    ScopedOperationTimer &operator=(const ScopedOperationTimer &) = delete;

  private:
    using Clock = std::chrono::steady_clock;
    FileTraceStoreOperationTiming *destination_;
    Clock::time_point wall_start_;
    std::clock_t cpu_start_;
};

} // namespace checkpoint_replay_execution_detail

/// Move-only trace source which either publishes compact forward checkpoints
/// for later replay or, for small Laned layouts, publishes a compact S' copy
/// immediately after each completed forward layer. The replay path prepares a
/// separate proof-ingress artifact at the setup-bound level; the eager Laned
/// path needs neither replay nor per-wire reverse proof ingress. Both Laned
/// and Wide payloads use the same admitted storage lifecycle. A layer
/// artifact contains only canonical distinct values; circuit-public
/// plaintexts stay symbolic, structural padding is synthesized, and logical
/// aliases reread their representative without materializing copies.
///
/// The completed payload's live output values are returned in RAM;
/// the planner charges that retention independently of the relation chunk.
/// After publication succeeds, every replay or retirement failure is
/// terminal for this instance: predecessors may already have been deleted,
/// no retry/resume journal exists, and the caller must discard the session
/// and clean its private root. Construction therefore requires the explicit
/// `IrreversibleNoRetry` lifecycle.
///
/// Each layer is independently reclaimable and therefore owns a complete
/// one-layer v4 manifest. A problem built with the planner's shared-manifest
/// target formulas is not directly executable here: replace every layer's
/// `checkpoint_bytes` with
/// `standalone_checkpoint_layer_artifact_bytes(...)` and re-run planning.
template <fhe::PersistableFheBackend Backend>
class PayloadCheckpointReplayTrace {
  private:
    struct LayerArtifact {
        std::size_t layer = 0;
        bool checkpoint = false;
        FileTraceStoreWriteReport report;
        trace_storage::SerializedTraceStore store;
        bool backing_attributed_to_checkpoint = false;
    };

  public:
    static PayloadCheckpointReplayTrace publish(
        const typename Backend::EvalContext &eval,
        const PayloadCircuit &payload, const LayeredCircuit &circuit,
        std::span<const typename Backend::Ciphertext> encrypted_inputs,
        const FheEvaluationPlan &evaluation,
        const PayloadCheckpointReplayProblem &problem,
        const PayloadCheckpointReplayBudgets &budgets,
        const PayloadCheckpointReplayPlan &plan,
        PayloadCheckpointReplayExecutionOptions options,
        std::vector<fhe::FheValue<Backend>> &output) {
        CertifiedPayloadCheckpointReplayStatic certified =
            certify_payload_checkpoint_replay_static(
                payload,
                derive_certified_canonical_trace_layout(circuit),
                evaluation, problem, budgets, plan);
        return publish_certified_with_schedule_binding(
            eval, certified, encrypted_inputs, std::move(options), output,
            std::nullopt, std::nullopt);
    }

    /// Publish from workload-static geometry certified before the recurring
    /// request. All request/session, backend-context, root, capacity, and
    /// artifact-integrity checks remain online; circuit/layout/replan work
    /// does not.
    static PayloadCheckpointReplayTrace publish_certified(
        const typename Backend::EvalContext &eval,
        const CertifiedPayloadCheckpointReplayStatic &certified,
        std::span<const typename Backend::Ciphertext> encrypted_inputs,
        PayloadCheckpointReplayExecutionOptions options,
        std::vector<fhe::FheValue<Backend>> &output) {
        return publish_certified_with_schedule_binding(
            eval, certified, encrypted_inputs, std::move(options), output,
            std::nullopt, std::nullopt);
    }

    /// Evaluate only the client-visible payload output through the same
    /// bounded, file-backed relation engine used by checkpoint replay.  No
    /// replay checkpoint, proof-ingress artifact, or checkpoint-set metadata
    /// is published.  Each natural source layer is retired as soon as its
    /// successor is published, and the output artifact is retired after its
    /// values have been loaded for the caller.
    ///
    /// The certified output-only plan contributes its setup-validated
    /// adjacent-layer artifact bounds and ciphertext chunk size. The returned
    /// trace is an accounting handle only: it owns no live payload artifact
    /// and cannot be used as a GKR source.
    /// Publication follows the FileTraceStore contract; it does not make this
    /// in-process lifecycle resumable after a crash or power loss.
    static PayloadCheckpointReplayTrace publish_output_only_certified(
        const typename Backend::EvalContext &eval,
        const CertifiedPayloadCheckpointReplayStatic &certified,
        std::span<const typename Backend::Ciphertext> encrypted_inputs,
        PayloadCheckpointReplayExecutionOptions options,
        std::vector<fhe::FheValue<Backend>> &output,
        std::optional<Digest> expected_trace_id = std::nullopt) {
        return publish_certified_with_schedule_binding(
            eval, certified, encrypted_inputs, std::move(options), output,
            std::nullopt, std::nullopt, std::move(expected_trace_id), true);
    }

    /// Authenticated-request form. The ciphertexts are serialized once to
    /// derive their trace identity, which must equal `expected_trace_id`
    /// before any layer artifact or FHE output is published.
    static PayloadCheckpointReplayTrace publish_certified(
        const typename Backend::EvalContext &eval,
        const CertifiedPayloadCheckpointReplayStatic &certified,
        const Digest &expected_trace_id,
        std::span<const typename Backend::Ciphertext> encrypted_inputs,
        PayloadCheckpointReplayExecutionOptions options,
        std::vector<fhe::FheValue<Backend>> &output) {
        return publish_certified_with_schedule_binding(
            eval, certified, encrypted_inputs, std::move(options), output,
            std::nullopt, std::nullopt, expected_trace_id);
    }

    /// Publish a checkpoint trace whose proof-ingress view is authenticated
    /// by the setup-fixed schedule. An optional offline proof-noise assessment
    /// is carried when present, but routine fixed-policy setup does not require
    /// an operational proof replay. The exact executable plan is checked before
    /// directories are created or FHE work begins.
    static PayloadCheckpointReplayTrace publish_authenticated(
        const typename Backend::EvalContext &eval,
        const PayloadCircuit &payload, const LayeredCircuit &circuit,
        std::span<const typename Backend::Ciphertext> encrypted_inputs,
        const CertifiedHonestPayloadSchedule &certified_schedule,
        const PayloadCheckpointReplayProblem &problem,
        const PayloadCheckpointReplayBudgets &budgets,
        const PayloadCheckpointReplayPlan &plan,
        PayloadCheckpointReplayExecutionOptions options,
        std::vector<fhe::FheValue<Backend>> &output) {
        certified_schedule.validate_circuit_digest(digest(circuit));
        const HonestPayloadNoiseSchedule &schedule =
            certified_schedule.schedule();
        const bool fixed_uniform_policy =
            schedule.base_proof_ingress_policy ==
            kUniformBaseProofIngressPolicyV1;
        const bool exact_assessment =
            schedule.base_proof_noise_assessment &&
            schedule.base_proof_noise_assessment->report_accepts();
        if (!schedule.payload_model_accepts() ||
            (!fixed_uniform_policy && !exact_assessment)) {
            throw std::invalid_argument(
                "authenticated checkpoint replay requires either the fixed "
                "uniform Base proof policy or an exact accepting assessment");
        }
        std::optional<Digest> proof_assessment_digest =
            certified_schedule.proof_assessment_digest();
        if (schedule.base_proof_noise_assessment) {
            if (!schedule.base_proof_noise_assessment->report_accepts()) {
                throw std::invalid_argument(
                    "authenticated checkpoint replay cannot carry a "
                    "rejecting Base proof-noise assessment");
            }
            if (!proof_assessment_digest) {
                throw std::logic_error(
                    "certified checkpoint schedule omitted its assessment "
                    "digest");
            }
        }
        CertifiedPayloadCheckpointReplayStatic certified =
            certify_payload_checkpoint_replay_static(
                payload,
                derive_certified_canonical_trace_layout(circuit),
                schedule.evaluation_plan, problem, budgets, plan);
        return publish_certified_with_schedule_binding(
            eval, certified, encrypted_inputs, std::move(options), output,
            certified_schedule.digest(),
            proof_assessment_digest);
    }

    /// Compatibility boundary for callers that have not retained a setup
    /// certificate. Exact semantic validation occurs once here; the certified
    /// implementation performs no second derivation.
    static PayloadCheckpointReplayTrace publish_authenticated(
        const typename Backend::EvalContext &eval,
        const PayloadCircuit &payload, const LayeredCircuit &circuit,
        std::span<const typename Backend::Ciphertext> encrypted_inputs,
        const HonestPayloadNoiseSchedule &schedule,
        const PayloadCheckpointReplayProblem &problem,
        const PayloadCheckpointReplayBudgets &budgets,
        const PayloadCheckpointReplayPlan &plan,
        PayloadCheckpointReplayExecutionOptions options,
        std::vector<fhe::FheValue<Backend>> &output) {
        CertifiedHonestPayloadSchedule certified =
            certify_honest_payload_noise_schedule(circuit, schedule);
        return publish_authenticated(
            eval, payload, circuit, encrypted_inputs, certified, problem,
            budgets, plan, std::move(options), output);
    }

    PayloadCheckpointReplayTrace(const PayloadCheckpointReplayTrace &) =
        delete;
    PayloadCheckpointReplayTrace &operator=(
        const PayloadCheckpointReplayTrace &) = delete;
    PayloadCheckpointReplayTrace(
        PayloadCheckpointReplayTrace &&) noexcept = default;
    PayloadCheckpointReplayTrace &operator=(
        PayloadCheckpointReplayTrace &&) noexcept = default;

    const EncryptedTraceDescriptor &descriptor() const {
        return descriptor_;
    }
    const Digest &backend_context_id() const {
        return backend_context_id_;
    }
    bool matches_backend_context(
        const typename Backend::EvalContext &eval) const {
        return backend_context_id_ == Backend::storage_context_id(eval);
    }
    const Digest &layered_circuit_id() const {
        return layered_circuit_id_;
    }
    const std::optional<Digest> &
    authenticated_honest_payload_noise_schedule_digest() const {
        return authenticated_honest_payload_noise_schedule_digest_;
    }
    const std::optional<Digest> &
    authenticated_honest_base_proof_noise_assessment_digest() const {
        return authenticated_honest_base_proof_noise_assessment_digest_;
    }
    const PayloadCheckpointReplayExecutionReport &report() const {
        return report_;
    }
    const PayloadCheckpointReplayProblem &problem() const {
        return *problem_;
    }
    const PayloadCheckpointReplayBudgets &budgets() const {
        return *budgets_;
    }
    const PayloadCheckpointReplayPlan &plan() const { return *plan_; }
    bool uses_eager_laned_witness_packing() const noexcept {
        return eager_laned_witness_packing_;
    }
    bool is_output_only() const noexcept { return output_only_; }

    /// The first file-backed GKR handoff retires the logical output layer and
    /// crosses the no-retry boundary. A true value remains terminal even when
    /// later proof work throws before all artifacts are retired.
    bool proof_attempt_started() const noexcept {
        return output_retirement_observed_;
    }
    const std::filesystem::path &directory() const { return root_; }

    /// Canonical embedding of compact records in the padded protocol domain.
    const LayerWireSupport &layer_support(std::size_t layer) const {
        return trace_layout_->layout().wire_support.at(layer);
    }

    const LayerStorageLayout &layer_storage_layout(
        std::size_t layer) const {
        return trace_layout_->layout().storage.at(layer);
    }

    PayloadCheckpointReplayLayerReader<Backend>
    layer_reader(std::size_t layer) const {
        return layer_reader(layer, 0,
                            layer_support(layer).padded_wire_count);
    }

    PayloadCheckpointReplayLayerReader<Backend>
    layer_reader(std::size_t layer, std::size_t begin,
                 std::size_t end) const {
        ensure_source(layer);
        if (layer != active_source_layer_ || !proof_reader_artifact(layer)) {
            throw std::logic_error(
                "checkpoint replay source layer is not active");
        }
        const LayerWireSupport &support =
            trace_layout_->layout().wire_support.at(layer);
        const LayerStorageLayout &storage =
            trace_layout_->layout().storage.at(layer);
        if (begin > end || end > support.padded_wire_count) {
            throw std::out_of_range(
                "checkpoint replay padded range is out of bounds");
        }
        checkpoint_replay_execution_detail::accumulate(
            report_.gkr_source_reads.range_readers_opened,
            1U,
            "checkpoint GKR range readers");
        return PayloadCheckpointReplayLayerReader<Backend>(
            *eval_, storage, begin, end,
            proof_reader_artifact(layer)->store.layer_range(
                0, 0, storage.stored_wire_count,
                &report_.gkr_source_reads.storage_reads),
            report_.gkr_source_reads.encoded_ciphertext_bytes_read,
            report_.gkr_source_reads.framed_record_bytes_read);
    }

    PayloadCheckpointReplayActiveLayerReader<Backend>
    active_layer_reader(std::size_t layer) const {
        return active_layer_reader(
            layer, 0, layer_storage_layout(layer).stored_wire_count);
    }

    PayloadCheckpointReplayPackedLayerReader<Backend>
    laned_packed_layer_reader(std::size_t layer) const {
        activate_eager_laned_source(layer);
        const LayerArtifact *artifact =
            eager_laned_packed_artifacts_.at(layer)
                ? &*eager_laned_packed_artifacts_.at(layer)
                : nullptr;
        if (artifact == nullptr) {
            throw std::logic_error(
                "eager Laned packed source is missing");
        }
        checkpoint_replay_execution_detail::accumulate(
            report_.gkr_source_reads.range_readers_opened, 1U,
            "packed witness GKR readers");
        return PayloadCheckpointReplayPackedLayerReader<Backend>(
            *eval_, artifact->store.layer_range(
                        0, 0,
                        laned_packed_layouts_.at(layer)
                            .logical_ciphertext_count,
                        &report_.gkr_source_reads.storage_reads),
            report_.gkr_source_reads.encoded_ciphertext_bytes_read,
            report_.gkr_source_reads.framed_record_bytes_read);
    }

    const packing::LanedPackingLayout &
    laned_packed_layer_layout(std::size_t layer) const {
        if (!eager_laned_witness_packing_ || layer == 0 ||
            layer >= laned_packed_layouts_.size()) {
            throw std::out_of_range(
                "eager Laned packed layout is unavailable");
        }
        return laned_packed_layouts_[layer];
    }

    std::size_t laned_packed_layer_rns_limbs(std::size_t layer) const {
        if (!eager_laned_witness_packing_ || layer == 0 ||
            layer >= laned_packed_rns_limbs_.size()) {
            throw std::out_of_range(
                "eager Laned packed level is unavailable");
        }
        return laned_packed_rns_limbs_[layer];
    }

    /// Read a half-open range of storage ordinals. Returned records carry
    /// representative protocol indices; padding and aliases add no record.
    PayloadCheckpointReplayActiveLayerReader<Backend>
    active_layer_reader(std::size_t layer, std::size_t stored_begin,
                        std::size_t stored_end) const {
        ensure_source(layer);
        if (layer != active_source_layer_ || !proof_reader_artifact(layer)) {
            throw std::logic_error(
                "checkpoint replay source layer is not active");
        }
        const LayerStorageLayout &storage = layer_storage_layout(layer);
        if (stored_begin > stored_end ||
            stored_end > storage.stored_wire_count) {
            throw std::out_of_range(
                "checkpoint replay stored range is out of bounds");
        }
        checkpoint_replay_execution_detail::accumulate(
            report_.gkr_source_reads.range_readers_opened, 1U,
            "checkpoint GKR active range readers");
        return PayloadCheckpointReplayActiveLayerReader<Backend>(
            *eval_, storage,
            proof_reader_artifact(layer)->store.layer_range(
                0, stored_begin, stored_end,
                &report_.gkr_source_reads.storage_reads),
            report_.gkr_source_reads.encoded_ciphertext_bytes_read,
            report_.gkr_source_reads.framed_record_bytes_read);
    }

    /// Called by the file-backed GKR orchestrator only after it owns the proof
    /// message and next claim derived from this source.
    FileTraceLayerRetirementReport retire_layer(std::size_t layer) {
        if (!published_) {
            throw std::logic_error(
                "checkpoint replay set is not published");
        }
        if (layer == 0) {
            if (output_retirement_observed_) {
                throw std::logic_error(
                    "checkpoint replay output was retired twice");
            }
            output_retirement_observed_ = true;
            return FileTraceLayerRetirementReport{
                0, 0, total_source_retirement_bytes_,
                report_.live_physical_bytes};
        }
        if (layer != active_source_layer_ || layer != next_source_layer_) {
            throw std::logic_error(
                "checkpoint replay source retirement is out of order");
        }

        PayloadCheckpointReplaySegmentExecutionReport &segment =
            report_.segments.at(layer - 1U);
        if (eager_laned_witness_packing_) {
            if (artifacts_.at(layer) || proof_reader_artifact(layer)) {
                throw std::logic_error(
                    "eager Laned proof retained an unpacked source");
            }
            const std::uint64_t retired =
                remove_eager_laned_packed_artifact(
                    layer, &segment.replay);
            segment.packed_witness_bytes_retired_after_use = retired;
            checkpoint_replay_execution_detail::accumulate(
                total_source_retirement_bytes_, retired,
                "eager Laned witness retirement bytes");
            active_source_layer_ = kNoLayer;
            ++next_source_layer_;
            merge_io(report_.reverse_replay, segment.replay);
            segment.live_physical_bytes_after =
                report_.live_physical_bytes;
            if (next_source_layer_ == descriptor_.layers.size()) {
                if (replay_work_executed_ != 0 || metadata_live_ ||
                    report_.live_physical_bytes != 0) {
                    throw std::logic_error(
                        "eager Laned proof retained payload state");
                }
                report_.all_payload_artifacts_retired = true;
            }
            return FileTraceLayerRetirementReport{
                layer, retired, total_source_retirement_bytes_,
                report_.live_physical_bytes};
        }
        const bool selected = std::binary_search(
            plan_->selected.checkpoint_layers.begin(),
            plan_->selected.checkpoint_layers.end(), layer);
        if (!proof_reader_artifact(layer)) {
            throw std::logic_error(
                "checkpoint replay proof-ingress artifact is missing");
        }
        std::uint64_t ingress_retired = 0;
        std::uint64_t natural_retired = 0;
        if (proof_ingress_aliases_natural_.at(layer)) {
            if (!artifacts_.at(layer)) {
                throw std::logic_error(
                    "aliased proof ingress lost its natural artifact");
            }
            // A no-op ingress deliberately retains this one same-writer,
            // path-bound copy until the reduction has consumed it. Removal
            // rechecks its file identities and exact directory inventory.
            natural_retired =
                remove_artifact(layer, selected, &segment.replay);
            record_natural_source_retirement(
                layer, selected, natural_retired, segment);
        } else {
            if (artifacts_.at(layer)) {
                throw std::logic_error(
                    "distinct proof ingress retained its natural source");
            }
            ingress_retired =
                remove_proof_ingress_artifact(layer, &segment.replay);
        }
        segment.proof_ingress_bytes_retired_after_use = ingress_retired;
        const std::uint64_t retired =
            checkpoint_replay_execution_detail::checked_add(
                natural_retired, ingress_retired,
                "checkpoint source and proof-ingress retirement bytes");
        checkpoint_replay_execution_detail::accumulate(
            total_source_retirement_bytes_, ingress_retired,
            "checkpoint proof-ingress retirement bytes");
        active_source_layer_ = kNoLayer;
        ++next_source_layer_;

        if (segment.checkpoint_metadata_bytes_retired_after_use != 0) {
            remove_checkpoint_metadata();
        }
        merge_io(report_.reverse_replay, segment.replay);
        segment.live_physical_bytes_after = report_.live_physical_bytes;
        if (next_source_layer_ == descriptor_.layers.size()) {
            if (replay_work_executed_ !=
                plan_->selected.replay_work_units) {
                throw std::logic_error(
                    "checkpoint replay-work ledger drifted");
            }
            if (report_.live_physical_bytes != 0) {
                throw std::logic_error(
                    "checkpoint replay retained payload bytes after the "
                    "final source");
            }
            report_.all_payload_artifacts_retired = true;
        }
        return FileTraceLayerRetirementReport{
            layer, retired, total_source_retirement_bytes_,
            report_.live_physical_bytes};
    }

  private:
    static constexpr std::size_t kNoLayer =
        std::numeric_limits<std::size_t>::max();

    RuntimeProgressLayerKind runtime_layer_kind(std::size_t layer) const {
        return payload::layer_kind(circuit_->layers.at(layer)) ==
                       LayerKind::Affine
                   ? RuntimeProgressLayerKind::Affine
                   : RuntimeProgressLayerKind::Multiplication;
    }

    LayerArtifact *proof_reader_artifact(std::size_t layer) const {
        if (proof_ingress_aliases_natural_.at(layer)) {
            return artifacts_.at(layer) ? &*artifacts_.at(layer) : nullptr;
        }
        return proof_ingress_artifacts_.at(layer)
                   ? &*proof_ingress_artifacts_.at(layer)
                   : nullptr;
    }

    static PayloadCheckpointReplayTrace
    publish_certified_with_schedule_binding(
        const typename Backend::EvalContext &eval,
        const CertifiedPayloadCheckpointReplayStatic &certified,
        std::span<const typename Backend::Ciphertext> encrypted_inputs,
        PayloadCheckpointReplayExecutionOptions options,
        std::vector<fhe::FheValue<Backend>> &output,
        std::optional<Digest> authenticated_payload_schedule,
        std::optional<Digest> authenticated_proof_assessment,
        std::optional<Digest> expected_trace_id = std::nullopt,
        bool output_only = false) {
        const LayeredCircuit &circuit = certified.circuit();
        if (!(certified.shape() == circuit.shape) ||
            certified.input_count() != encrypted_inputs.size() ||
            encrypted_inputs.empty() || !output.empty() ||
            options.min_free_bytes == 0 ||
            options.max_checkpoint_metadata_bytes == 0 ||
            options.lifecycle !=
                FileTraceSessionLifecycle::IrreversibleNoRetry ||
            (output_only && options.eager_laned_witness_packing) ||
            Backend::slot_count(eval) != circuit.shape.slot_count ||
            // An optional proof assessment must accompany its authenticated
            // payload schedule. The fixed uniform policy needs only the schedule.
            (authenticated_proof_assessment.has_value() &&
             !authenticated_payload_schedule.has_value())) {
            throw std::invalid_argument(
                "checkpoint replay publication request mismatch");
        }
        const bool plan_is_output_only =
            certified.budgets().selection_objective ==
            PayloadCheckpointSelectionObjective::
                OutputOnlyAdjacentLayers;
        if (output_only != plan_is_output_only) {
            throw std::invalid_argument(
                "payload publication mode differs from its certified "
                "resource plan");
        }
        const std::filesystem::path root =
            checkpoint_replay_execution_detail::validate_empty_root(
                options.directory);

        PayloadCheckpointReplayTrace trace(
            eval, certified, std::move(options), root, encrypted_inputs,
            std::move(authenticated_payload_schedule),
            std::move(authenticated_proof_assessment),
            std::move(expected_trace_id), output_only);
        try {
            if (trace.output_only_) {
                trace.preflight_output_only();
            } else if (trace.eager_laned_witness_packing_) {
                trace.preflight_eager_laned_witness_packing();
            } else {
                trace.preflight_checkpoint_metadata();
            }
            trace.create_layer_directories();
            trace.publish_input(encrypted_inputs);
            output = trace.evaluate_forward();
            if (trace.forward_work_executed_ !=
                certified.plan().selected.initial_forward_work_units) {
                throw std::logic_error(
                    "checkpoint forward-work ledger drifted");
            }
            if (!trace.output_only_ &&
                !trace.eager_laned_witness_packing_) {
                trace.publish_checkpoint_metadata();
            }
            // Proving can begin after publication of either the replay
            // checkpoints or the eager Laned packed sources.
            trace.report_.checkpoint_set_published = !trace.output_only_;
            if (trace.output_only_) {
                if (trace.report_.live_physical_bytes != 0) {
                    throw std::logic_error(
                        "output-only payload artifacts were not retired");
                }
                trace.report_.all_payload_artifacts_retired = true;
            }
            trace.published_ = true;
        } catch (...) {
            output.clear();
            trace.cleanup_publication_failure_noexcept();
            throw;
        }
        return trace;
    }


#include "laminate/payload/checkpoint/detail/session_publication.inc.hpp"
#include "laminate/payload/checkpoint/detail/session_relation_evaluation.inc.hpp"
#include "laminate/payload/checkpoint/detail/session_storage_accounting.inc.hpp"

    const typename Backend::EvalContext *eval_;
    CertifiedPayloadCheckpointReplayStatic certified_;
    const CertifiedCanonicalTraceLayout *trace_layout_;
    const LayeredCircuit *circuit_;
    const PayloadCheckpointReplayProblem *problem_;
    const PayloadCheckpointReplayBudgets *budgets_;
    const PayloadCheckpointReplayPlan *plan_;
    PayloadCheckpointReplayExecutionOptions options_;
    std::filesystem::path root_;
    Digest backend_context_id_{};
    Digest layered_circuit_id_{};
    std::optional<Digest>
        authenticated_honest_payload_noise_schedule_digest_;
    std::optional<Digest>
        authenticated_honest_base_proof_noise_assessment_digest_;
    /// Natural-level payload/replay artifacts use this descriptor. The public
    /// `descriptor()` is the independently normalized proof-ingress view.
    EncryptedTraceDescriptor natural_descriptor_;
    EncryptedTraceDescriptor descriptor_;
    bool output_only_ = false;
    mutable std::vector<std::optional<LayerArtifact>> artifacts_;
    mutable std::vector<std::optional<LayerArtifact>>
        proof_ingress_artifacts_;
    mutable std::vector<bool> proof_ingress_aliases_natural_;
    mutable std::vector<std::optional<LayerArtifact>>
        eager_laned_packed_artifacts_;
    std::vector<packing::LanedPackingLayout> laned_packed_layouts_;
    std::vector<std::size_t> laned_packed_rns_limbs_;
    std::vector<std::uint64_t> laned_packed_artifact_byte_bounds_;
    std::optional<LanedWitnessMaskCache<Backend>>
        laned_witness_mask_cache_;
    std::vector<std::filesystem::path> layer_directories_;
    std::vector<std::filesystem::path> proof_ingress_directories_;
    std::vector<std::filesystem::path> eager_laned_packed_directories_;
    std::vector<std::optional<
        checkpoint_replay_execution_detail::OwnedDirectoryIdentity>>
        layer_directory_identities_;
    std::vector<std::optional<
        checkpoint_replay_execution_detail::OwnedDirectoryIdentity>>
        proof_ingress_directory_identities_;
    std::vector<std::optional<
        checkpoint_replay_execution_detail::OwnedDirectoryIdentity>>
        eager_laned_packed_directory_identities_;
    mutable PayloadCheckpointReplayExecutionReport report_;
    mutable std::size_t active_source_layer_ = kNoLayer;
    mutable std::size_t next_source_layer_ = 1;
    std::size_t live_layer_artifacts_ = 0;
    std::uint64_t forward_work_executed_ = 0;
    mutable std::uint64_t replay_work_executed_ = 0;
    std::uint64_t total_source_retirement_bytes_ = 0;
    bool published_ = false;
    bool output_retirement_observed_ = false;
    bool metadata_live_ = false;
    mutable bool metadata_validated_for_reverse_ = false;
    bool eager_laned_witness_packing_ = false;
};

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_CHECKPOINT_SESSION_ENGINE_HPP
