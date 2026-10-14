#ifndef LAMINATE_PAYLOAD_CHECKPOINT_PLAN_HPP
#define LAMINATE_PAYLOAD_CHECKPOINT_PLAN_HPP

/// @file plan.hpp
/// @brief Resource planning for sparse encrypted-payload checkpoints.

#include "laminate/payload/ir/layered.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace laminate::payload {

struct FheEvaluationPlan;
class CertifiedCanonicalTraceLayout;

/// Exact physical-byte formulas for the current file-trace framing when every
/// stored value record in a layer has the same encoded length. A layer has a
/// 40-byte header, an 8-byte length and 8-byte index entry per record, and a
/// 24-byte index header. The trace manifest has 200 fixed bytes and 96 bytes
/// per declared layer.
std::uint64_t file_trace_layer_artifact_bytes(
    std::size_t stored_record_count,
    std::uint64_t serialized_record_bytes);
std::uint64_t file_trace_manifest_fixed_bytes();
std::uint64_t file_trace_manifest_layer_descriptor_bytes();
std::uint64_t file_trace_manifest_bytes(std::size_t layer_count);

/// Exact bytes for one independently reclaimable checkpoint layer. Unlike a
/// layer inside one shared trace store, each checkpoint owns a complete
/// one-layer manifest.
std::uint64_t standalone_checkpoint_layer_artifact_bytes(
    std::size_t stored_record_count,
    std::uint64_t serialized_record_bytes);

/// Bytes in the canonical checkpoint-set identity prefix for `k` selected
/// layers. Validation owns this prefix alongside the complete metadata file.
std::uint64_t checkpoint_replay_metadata_identity_bytes(
    std::size_t selected_checkpoint_count);

/// Caller-supplied upper bounds for one encrypted layer.
///
/// Checkpoint bytes are a caller-supplied bound for the selected storage
/// model. Executable replay requires a complete independently owned one-layer
/// artifact with its records, indexes, and one-layer manifest, obtained from
/// `standalone_checkpoint_layer_artifact_bytes` and checked by
/// `validate_executable_checkpoint_artifact_accounting`. Formula-only
/// planners may model another storage layout. The two per-encrypted-value
/// bounds cover serialized staging and decoded residency respectively. Work
/// units may be measured time, primitive-weighted work, or the
/// live-contribution proxy returned by `payload_replay_work_units`; every
/// layer in one problem must use the same scale.
struct PayloadLayerResourceEstimate {
    std::size_t rns_limb_count = 0;
    std::uint64_t checkpoint_bytes = 0;
    std::uint64_t serialized_ciphertext_bytes = 0;
    std::uint64_t resident_ciphertext_bytes = 0;
    std::uint64_t replay_work_units = 0;

    /// Prefer this checkpoint during sparse selection. The circuit adapter
    /// accepts the mark only for a non-output layer at which the supplied FHE
    /// evaluation plan actually performs an after-layer modulus switch.
    bool prefer_post_modulus_switch_checkpoint = false;

    /// Per-ciphertext bounds after reduction to the proof-ingress level.
    /// Zero selects the conservative natural-level bound. Production
    /// calibration should populate both values from the target RNS level.
    std::uint64_t proof_ingress_serialized_ciphertext_bytes = 0;
    std::uint64_t proof_ingress_resident_ciphertext_bytes = 0;

    bool operator==(const PayloadLayerResourceEstimate &) const = default;
};

/// Resource and protocol geometry for one layer, in GKR order.
struct PayloadReplayLayer {
    std::size_t layer = 0;
    LayerKind kind = LayerKind::Affine;
    /// Serialized live records in canonical active-wire order. This is the
    /// count used by every disk and resident-memory formula.
    std::size_t stored_value_count = 0;
    /// Full power-of-two protocol domain. Its omitted positions are public
    /// zeros and never contribute records to a checkpoint artifact.
    std::size_t virtual_wire_count = 0;
    std::size_t rns_limb_count = 0;
    std::size_t required_proof_depth = 0;
    std::size_t modulus_switches_after_layer = 0;
    std::uint64_t checkpoint_bytes = 0;
    std::uint64_t serialized_ciphertext_bytes = 0;
    std::uint64_t resident_ciphertext_bytes = 0;
    std::uint64_t replay_work_units = 0;
    bool preferred_checkpoint = false;
    /// Resolved proof-ingress bounds. Hand-built formula problems may leave
    /// either zero to use the corresponding natural-level bound.
    std::uint64_t proof_ingress_serialized_ciphertext_bytes = 0;
    std::uint64_t proof_ingress_resident_ciphertext_bytes = 0;

    /// Semantically live wire positions before canonical storage aliases are
    /// coalesced. Zero means that a formula-only caller did not supply this
    /// optional optimization fact. Executable circuit adapters populate it
    /// exactly, so a multiplication source with fewer stored than live values
    /// may be cached once for the relation when the complete cache fits the
    /// admitted resident budget.
    std::size_t semantic_live_value_count = 0;
    /// Local affine DAG liveness cache, metadata, and arithmetic temporaries.
    /// Intermediate ciphertexts retain the preceding source layer's level.
    std::uint64_t affine_workspace_bytes = 0;

    bool operator==(const PayloadReplayLayer &) const = default;
};

/// Value-free replay problem. Layers are ordered exactly like
/// `LayeredCircuit::layers`: output first, input last. A sparse execution can
/// checkpoint source layers 1..L-1; layer zero is retained only by the full
/// trace reference profile.
struct PayloadCheckpointReplayProblem {
    std::vector<PayloadReplayLayer> layers;
    /// Manifest, directory, or other bytes independent of the selected
    /// checkpoint count.
    std::uint64_t checkpoint_set_fixed_bytes = 0;
    /// Metadata retained for every layer declared by the selected checkpoint
    /// set. It remains live until the set is retired, even after an individual
    /// layer file has reached its last consumer.
    std::uint64_t checkpoint_set_bytes_per_layer = 0;
    /// Resident bytes in an independently constructed validation identity.
    /// Formula-only planners may leave these zero. The executable checkpoint
    /// adapter installs its canonical 127-byte fixed and 8-byte-per-layer
    /// format and rejects any other values.
    std::uint64_t checkpoint_validation_identity_fixed_bytes = 0;
    std::uint64_t checkpoint_validation_identity_bytes_per_layer = 0;

    void validate() const;
};

/// Require the manifest-last, independently reclaimable artifact geometry
/// consumed by executable replay. Formula-only planners may use other storage
/// models; production execution adapters must call this before expensive
/// preprocessing.
void validate_executable_checkpoint_artifact_accounting(
    const PayloadCheckpointReplayProblem &problem);

/// Build a protocol-connected problem from the current circuit and FHE level
/// schedule. The resource vector must contain one entry per circuit layer.
PayloadCheckpointReplayProblem make_payload_checkpoint_replay_problem(
    const LayeredCircuit &circuit, const FheEvaluationPlan &evaluation_plan,
    std::span<const PayloadLayerResourceEstimate> resources,
    std::uint64_t checkpoint_set_fixed_bytes = 0,
    std::uint64_t checkpoint_set_bytes_per_layer = 0);

/// Build from an immutable circuit-bound canonical trace layout. Derivation
/// or exact certification occurs once when the token is created; this cached
/// path performs no second whole-circuit layout scan.
PayloadCheckpointReplayProblem make_payload_checkpoint_replay_problem(
    const CertifiedCanonicalTraceLayout &trace_layout,
    const FheEvaluationPlan &evaluation_plan,
    std::span<const PayloadLayerResourceEstimate> resources,
    std::uint64_t checkpoint_set_fixed_bytes = 0,
    std::uint64_t checkpoint_set_bytes_per_layer = 0);

/// A backend-neutral fallback scale. Each semantically live affine source
/// term costs one unit, and a nonzero affine constant adds one unit when the
/// gate also has a live source term. A constant-only gate remains public and
/// costs no FHE unit. Each live multiplication or forwarding output costs one
/// unit. Structural padding terms and outputs cost zero, and the input layer
/// costs zero.
/// Calibrated single-thread work should be supplied when available.
std::vector<std::uint64_t>
payload_replay_work_units(const LayeredCircuit &circuit);

/// Compute the same fallback work scale from an immutable circuit-bound
/// canonical trace layout, with no second whole-circuit layout scan.
std::vector<std::uint64_t> payload_replay_work_units(
    const CertifiedCanonicalTraceLayout &trace_layout);

/// Exact rational upper bound on total payload work. The numerator and
/// denominator describe `(initial forward work + replay work) / initial
/// forward work`; therefore the ratio must be at least one.
struct PayloadRecomputationFactorLimit {
    std::uint64_t numerator = 0;
    std::uint64_t denominator = 0;

    bool operator==(const PayloadRecomputationFactorLimit &) const = default;
};

/// Policy for choosing among schedules which already satisfy every disk, RAM,
/// chunk, and recomputation bound. `MinimumStorage` preserves the conservative
/// library default. Online proof execution may instead spend admitted disk
/// headroom to minimize repeated payload work. `OutputOnlyAdjacentLayers`
/// certifies the distinct no-proof lifecycle: retain only the current source
/// and result artifacts, retire each source after completed publication, and do
/// no checkpointing or replay.
enum class PayloadCheckpointSelectionObjective : std::uint8_t {
    MinimumStorage,
    MinimumReplayWork,
    OutputOnlyAdjacentLayers,
};

struct PayloadCheckpointReplayBudgets {
    std::uint64_t max_live_scratch_bytes = 0;
    std::uint64_t max_resident_ciphertext_bytes = 0;
    std::size_t max_ciphertexts_per_chunk = 0;
    PayloadRecomputationFactorLimit max_recomputation_factor;

    /// Non-checkpoint disk state and non-ciphertext RAM that coexist with the
    /// payload phase. These reserves are charged before any candidate is
    /// considered. Eager Laned execution includes its complete builder and
    /// prepared-mask workspace here before optional caches are selected;
    /// see eager_laned_witness_packing_resources.
    std::uint64_t reserved_live_scratch_bytes = 0;
    std::uint64_t reserved_resident_bytes = 0;

    PayloadCheckpointSelectionObjective selection_objective =
        PayloadCheckpointSelectionObjective::MinimumStorage;

    /// Complete file artifacts constructed by the reduction consumer after
    /// its source has been replayed and prepared, while that source and the
    /// remaining checkpoints are still live. An empty vector means that the
    /// caller has no such artifacts. Otherwise there must be exactly one
    /// entry per reduction, in circuit order; affine entries are normally
    /// zero and multiplication entries bound their file-backed source
    /// scratch. These phase-local overlaps are not charged during forward
    /// evaluation or unrelated replay segments.
    std::vector<std::uint64_t>
        post_replay_consumer_artifact_bytes_by_reduction;

    void validate() const;

    bool operator==(
        const PayloadCheckpointReplayBudgets &) const = default;
};

/// Full-artifact disk state at the worst edge of a forward or replay
/// segment. Arbitrary wire indices prevent generic chunk fusion across
/// layers, so a non-checkpoint input and the output being published are both
/// charged at their complete artifact sizes. Chunking bounds only RAM.
struct PayloadLayerArtifactPeak {
    std::size_t input_layer = 0;
    std::size_t output_layer = 0;
    std::uint64_t live_checkpoint_bytes = 0;
    std::uint64_t input_artifact_bytes = 0;
    bool input_counted_in_live_checkpoint_bytes = false;
    std::uint64_t additional_transient_input_bytes = 0;
    std::uint64_t output_artifact_bytes = 0;
    /// Staged proof-ingress copy coexisting with the natural input. Zero on
    /// ordinary forward/replay relation edges and on no-op ingress aliases.
    std::uint64_t proof_ingress_artifact_bytes_upper_bound = 0;
    bool transient_input_retired_after_output_publish = false;
    /// False when forward evaluation publishes this output as a retained
    /// checkpoint. Replay outputs are always transient.
    bool output_retired_after_next_layer_or_gkr = false;
    std::uint64_t peak_live_scratch_bytes = 0;

    bool operator==(const PayloadLayerArtifactPeak &) const = default;
};

/// One reverse-GKR reduction and the payload segment needed to supply it.
/// If `checkpoint_layer == required_source_layer`, the replay interval is
/// empty. Otherwise output layers in
/// `[replay_output_layer_begin,replay_output_layer_end)` are evaluated in
/// descending index order.
struct PayloadReplaySegment {
    std::size_t reduction_layer = 0;
    std::size_t required_source_layer = 0;
    std::size_t checkpoint_layer = 0;
    std::size_t replay_output_layer_begin = 0;
    std::size_t replay_output_layer_end = 0;
    std::uint64_t replay_work_units = 0;

    /// Conservative complete-artifact upper bound for the staged ingress copy.
    /// Zero means the natural artifact is already at the ingress level and is
    /// read directly without a copy.
    std::uint64_t proof_ingress_artifact_bytes_upper_bound = 0;
    /// Complete live-storage peak while natural and ingress artifacts coexist.
    std::uint64_t proof_ingress_peak_live_scratch_bytes = 0;
    /// Encoded-plus-decoded one-input/one-output staging peak, including the
    /// caller's reserved resident bytes.
    std::uint64_t proof_ingress_peak_resident_bytes = 0;

    /// Downstream reduction artifact that is built while this prepared
    /// source remains live, and the resulting complete disk envelope. The
    /// latter includes the caller's persistent reserve, remaining
    /// checkpoints, a conservative natural-level source bound, and this
    /// consumer artifact.
    std::uint64_t post_replay_consumer_artifact_bytes = 0;
    std::uint64_t post_replay_consumer_peak_live_scratch_bytes = 0;

    PayloadLayerArtifactPeak artifact_peak;
    std::size_t serialized_peak_input_layer = 0;
    std::size_t serialized_peak_output_layer = 0;
    std::uint64_t serialized_input_chunk_bytes = 0;
    std::uint64_t serialized_output_chunk_bytes = 0;
    std::size_t resident_peak_input_layer = 0;
    std::size_t resident_peak_output_layer = 0;
    std::uint64_t resident_input_chunk_bytes = 0;
    std::uint64_t resident_output_chunk_bytes = 0;
    std::uint64_t peak_resident_bytes = 0;

    /// A selected checkpoint is retired after its own source layer has been
    /// consumed. Zero means no checkpoint is retired at this step.
    std::uint64_t checkpoint_bytes_retired_after = 0;
    /// Shared checkpoint-set metadata remains live until the mandatory input
    /// checkpoint, the final GKR source, has been consumed.
    std::uint64_t fixed_metadata_bytes_retired_after = 0;
    std::uint64_t live_checkpoint_bytes_after = 0;

    bool operator==(const PayloadReplaySegment &) const = default;
};

struct PayloadCheckpointStorageProfile {
    std::vector<std::size_t> checkpoint_layers;
    std::uint64_t checkpoint_metadata_bytes = 0;
    /// Complete metadata encoding plus its independently built identity
    /// prefix. Both coexist during validation.
    std::uint64_t checkpoint_metadata_validation_buffer_bytes = 0;
    std::uint64_t checkpoint_bytes = 0;
    std::size_t chunk_ciphertexts = 0;
    /// Largest complete resident peak of an optional relation-scoped dense
    /// multiplication source cache admitted by this profile. This includes
    /// the caller reserve and one encoded preload or output staging value.
    /// Zero means that no structurally aliased cache fits. The value is also
    /// folded into `peak_resident_bytes`.
    std::uint64_t
        dense_multiplication_alias_cache_peak_resident_bytes = 0;
    /// Resident-memory charge while the complete encrypted payload output is
    /// retained for the caller. This includes the non-ciphertext reserve and
    /// both encoded and decoded bytes for every live ciphertext in output
    /// layer zero.
    std::uint64_t retained_output_peak_resident_bytes = 0;
    PayloadLayerArtifactPeak forward_artifact_peak;
    std::uint64_t forward_peak_live_scratch_bytes = 0;
    /// Largest per-source conservative ingress artifact bound and the complete
    /// disk/RAM peaks at an ingress boundary.
    std::uint64_t proof_ingress_artifact_bytes_upper_bound = 0;
    std::uint64_t proof_ingress_peak_live_scratch_bytes = 0;
    std::uint64_t proof_ingress_peak_resident_bytes = 0;
    std::uint64_t post_replay_consumer_artifact_bytes_upper_bound = 0;
    std::uint64_t post_replay_consumer_peak_live_scratch_bytes = 0;
    std::uint64_t peak_live_scratch_bytes = 0;
    std::uint64_t peak_resident_bytes = 0;
    std::uint64_t initial_forward_work_units = 0;
    std::uint64_t replay_work_units = 0;
    std::uint64_t cumulative_work_units = 0;
    bool live_scratch_feasible = false;
    bool resident_feasible = false;
    bool recomputation_feasible = false;

    bool feasible() const {
        return live_scratch_feasible && resident_feasible &&
               recomputation_feasible;
    }

    bool operator==(
        const PayloadCheckpointStorageProfile &) const = default;
};

struct PayloadCheckpointReplayPlan {
    /// Full-trace reference: every encrypted trace layer remains on disk and
    /// no payload relation is replayed. It is reported even when it exceeds the
    /// supplied budgets.
    PayloadCheckpointStorageProfile full_trace_reference;

    /// Sparse, budget-admitted checkpoint profile selected by the planner.
    PayloadCheckpointStorageProfile selected;
    std::vector<PayloadReplaySegment> reverse_gkr_segments;
    /// True when the selected set contains any non-input checkpoint which is
    /// not one of the adapter's preferred post-modulus-switch boundaries.
    bool used_nonpreferred_checkpoint = false;

    bool operator==(const PayloadCheckpointReplayPlan &) const = default;
};

/// Select a sparse checkpoint set and a uniform ciphertext chunk bound. All
/// malformed inputs and all infeasible resource requests fail before an
/// execution artifact is created.
PayloadCheckpointReplayPlan plan_payload_checkpoint_replay(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets);

/// Exact complete resident peak for caching one aliased multiplication
/// relation's decoded source values. Returns zero when the output is not a
/// multiplication, its source has no certified storage aliases, or the cache
/// does not fit the global admitted resident cap. This is shared by planning
/// and execution so the optional fast path cannot exceed the reported plan.
std::uint64_t dense_multiplication_alias_cache_peak_resident_bytes(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets,
    std::size_t output_layer);

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_CHECKPOINT_PLAN_HPP
