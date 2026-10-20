#ifndef LAMINATE_SPARTAN_BASEFOLD_PCS_HPP
#define LAMINATE_SPARTAN_BASEFOLD_PCS_HPP

/// @file basefold_pcs.hpp
/// @brief BaseFold implementation of Spartan's multilinear IPCS.

#include "laminate/params.hpp"
#include "laminate/spartan/ipcs.hpp"
#include "laminate/storage/native_field_artifact.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace laminate::spartan {

struct BaseFoldPcsParameters {
    std::size_t log_rate = kTranscriptPackingBaseFoldLogRate;
    std::size_t query_count = kTranscriptPackingBaseFoldQueries;

    bool operator==(const BaseFoldPcsParameters &) const = default;
};

/// Caller-owned destination and hard disk limits for moving an existing
/// resident BaseFold prover state into a reopenable native-field artifact.
struct BaseFoldExternalStateOptions {
    std::filesystem::path directory;
    storage::NativeFieldArtifactOptions limits;
};

struct BaseFoldExternalStateReport {
    std::uint64_t physical_bytes = 0;
    std::uint64_t message_payload_bytes = 0;
    std::uint64_t codeword_payload_bytes = 0;
    std::uint64_t merkle_tree_payload_bytes = 0;

    bool operator==(const BaseFoldExternalStateReport &) const = default;
};

enum class BaseFoldExternalCommitPhase {
    MobiusTransform,
    RateExpansion,
    NttTransform,
    MerkleTree,
    FinalPublication,
};

enum class BaseFoldExternalCommitProgressKind {
    PassStarted,
    WorkAdvanced,
    PassCompleted,
    PhaseCompleted,
};

/// The concrete storage or arithmetic subpass currently constructing the
/// commitment. These names deliberately describe work below the PCS equation;
/// they never select or alter protocol behavior.
enum class BaseFoldExternalCommitSubpass {
    SourceLocalMobius,
    LocalMobius,
    RateExpansion,
    Transpose,
    TwiddleTranspose,
    LocalNtt,
    MerkleTree,
    MessagePublication,
    CodewordPublication,
    MerklePublication,
    ArtifactPublication,
};

/// Homogeneous unit used for recent-throughput and current-pass ETA. Progress
/// never estimates across unlike subpasses.
enum class BaseFoldExternalCommitWorkUnit {
    FieldElements,
    NttButterflies,
    MerkleItems,
    PublicationSteps,
};

/// Diagnostic progress from bounded-memory BaseFold commitment construction.
/// A pass is one newly published transform artifact, final array, or final
/// artifact-publication step. `pass_*` progress is homogeneous and therefore
/// suitable for a recent-throughput/ETA estimate. Whole-commitment progress is
/// intentionally pass-count-only: summing elements across transpose and local
/// NTT subpasses would underweight the latter by their butterfly depth.
/// Callbacks are advisory: exceptions are swallowed and never change protocol
/// output or control flow.
struct BaseFoldExternalCommitProgress {
    BaseFoldExternalCommitProgressKind kind =
        BaseFoldExternalCommitProgressKind::WorkAdvanced;
    BaseFoldExternalCommitPhase phase =
        BaseFoldExternalCommitPhase::MobiusTransform;
    BaseFoldExternalCommitSubpass subpass =
        BaseFoldExternalCommitSubpass::SourceLocalMobius;
    BaseFoldExternalCommitWorkUnit work_unit =
        BaseFoldExternalCommitWorkUnit::FieldElements;
    std::size_t column_index = 0;
    std::size_t column_count = 0;
    std::uint64_t completed_passes = 0;
    std::uint64_t total_passes = 0;
    std::uint64_t phase_completed_passes = 0;
    std::uint64_t phase_total_passes = 0;
    std::uint64_t pass_completed_work_units = 0;
    std::uint64_t pass_total_work_units = 0;
    std::uint64_t pass_completed_read_bytes = 0;
    std::uint64_t pass_total_read_bytes = 0;
    std::uint64_t pass_completed_write_bytes = 0;
    std::uint64_t pass_total_write_bytes = 0;
    std::uint64_t phase_completed_read_bytes = 0;
    std::uint64_t phase_total_read_bytes = 0;
    std::uint64_t phase_completed_write_bytes = 0;
    std::uint64_t phase_total_write_bytes = 0;
    std::uint64_t pass_completed_butterflies = 0;
    std::uint64_t pass_total_butterflies = 0;
    std::uint64_t phase_completed_butterflies = 0;
    std::uint64_t phase_total_butterflies = 0;
    std::size_t radix_elements = 0;
    std::size_t row_count = 0;
    std::size_t row_size = 0;
    /// Recent homogeneous work since the preceding report from this pass.
    /// The first pass sample leaves all three recent/ETA fields zero.
    std::uint64_t recent_work_units = 0;
    std::uint64_t recent_elapsed_milliseconds = 0;
    std::uint64_t estimated_remaining_milliseconds = 0;
};

using BaseFoldExternalCommitProgressCallback =
    std::function<void(const BaseFoldExternalCommitProgress &)>;

struct BaseFoldExternalization {
    PcsCommitment commitment;
    std::shared_ptr<const IPCS::ProverState> prover_state;
    laminate::Digest artifact_identity{};
    BaseFoldExternalStateReport report;
};

/// Stable commitment-bound identity used by the external-state format.
laminate::Digest
basefold_external_state_identity(const PcsCommitment &commitment);

/// Explicit resources for bounded-memory commitment construction. Both paths
/// must name existing, empty, private directories. `block_elements` controls
/// the larger tiled-transpose/I/O buffers; `cache_radix_elements`
/// independently caps each cache-resident Mobius/NTT row (zero selects a
/// balanced factorization with rows of at most 2^17). Explicit nonzero values
/// remain hard caps. `max_working_field_bytes` covers those buffers and leaf
/// staging.
/// Reader objects, fixed digest buffers, the logarithmic Merkle frontier, and
/// allocator metadata are excluded. No directory is selected implicitly.
struct BaseFoldExternalCommitOptions {
    std::filesystem::path destination_directory;
    std::filesystem::path scratch_directory;
    std::uint64_t max_final_bytes = 0;
    std::uint64_t max_scratch_bytes = 0;
    std::uint64_t min_free_bytes = 0;
    std::uint64_t max_working_field_bytes = 0;
    std::size_t block_elements = 0;
    std::size_t cache_radix_elements = 0;
    BaseFoldExternalCommitProgressCallback progress;
};

struct BaseFoldExternalCommitReport {
    std::uint64_t source_artifact_physical_bytes = 0;
    std::uint64_t selected_source_payload_bytes = 0;
    std::uint64_t scratch_peak_physical_bytes = 0;
    std::uint64_t scratch_written_physical_bytes = 0;
    std::uint64_t scratch_deleted_physical_bytes = 0;
    std::uint64_t final_physical_bytes = 0;
    std::uint64_t final_payload_bytes = 0;
    std::uint64_t artifact_validation_bytes = 0;
    std::uint64_t positional_publication_read_bytes = 0;
    std::uint64_t positional_publication_read_operations = 0;
    /// Canonical transform/tree/final-copy payload only. Validation scans are
    /// reported separately above; file framing and stream buffering are not
    /// presented as payload I/O.
    std::uint64_t sequential_read_payload_bytes = 0;
    std::uint64_t indexed_read_payload_bytes = 0;
    std::uint64_t sequential_write_payload_bytes = 0;
    std::uint64_t indexed_write_payload_bytes = 0;
    /// Data-carrying logical transfer calls made by the transform, independent
    /// of implementation-defined iostream buffering or OS syscall counts.
    std::uint64_t sequential_read_operations = 0;
    std::uint64_t indexed_read_operations = 0;
    std::uint64_t sequential_write_operations = 0;
    std::uint64_t indexed_write_operations = 0;
    /// Explicit element-position changes requested by the transform.
    std::uint64_t read_seek_operations = 0;
    std::uint64_t write_seek_operations = 0;
    /// Exact peak interval-map entries used to prove positional output
    /// coverage. Their allocator storage is outside the field-payload counter.
    std::uint64_t peak_positional_coverage_intervals = 0;
    std::uint64_t peak_working_field_bytes = 0;
    std::size_t transform_pass_count = 0;
    std::size_t transpose_pass_count = 0;
    /// Sum of cache-resident row-layer executions. Unlike
    /// `transform_pass_count`, these do not imply another full-artifact
    /// read/write pass.
    std::uint64_t cache_resident_butterfly_layers = 0;

    bool operator==(const BaseFoldExternalCommitReport &) const = default;
};

struct BaseFoldExternalCommitment {
    BaseFoldExternalization externalization;
    BaseFoldExternalCommitReport report;
};

struct BaseFoldExternalCommitStoragePlan {
    std::uint64_t final_physical_bytes = 0;
    std::uint64_t scratch_peak_physical_bytes = 0;
    std::uint64_t minimum_working_field_bytes = 0;
    std::size_t effective_block_elements = 0;
    std::size_t effective_cache_radix_elements = 0;
    std::uint64_t peak_working_field_bytes = 0;

    bool operator==(
        const BaseFoldExternalCommitStoragePlan &) const = default;
};

struct BaseFoldExternalOpeningStoragePlan {
    std::uint64_t state_artifact_physical_bytes = 0;
    std::uint64_t scratch_peak_physical_bytes = 0;
    std::uint64_t minimum_working_field_bytes = 0;
    std::uint64_t required_working_field_bytes = 0;
    std::size_t materialized_sumcheck_entries = 0;

    bool operator==(
        const BaseFoldExternalOpeningStoragePlan &) const = default;
};

/// One physically stored run in an otherwise virtual-zero BaseFold column.
/// Logical positions address the committed power-of-two message; stored
/// positions address the selected Fq array in the source artifact.
struct BaseFoldArtifactColumnSegment {
    std::uint64_t logical_begin = 0;
    std::uint64_t stored_begin = 0;
    std::uint64_t element_count = 0;

    bool operator==(const BaseFoldArtifactColumnSegment &) const = default;
};

/// A compact artifact-backed BaseFold message column. The selected source
/// array contains exactly the concatenation of `segments`; every logical
/// coordinate outside those segments is canonically zero and is synthesized
/// while the external transform is streamed.
struct BaseFoldArtifactColumn {
    std::string array_name;
    std::uint64_t logical_evaluation_count = 0;
    std::vector<BaseFoldArtifactColumnSegment> segments;

    bool operator==(const BaseFoldArtifactColumn &) const = default;
};

/// Per-opening scratch belongs to the caller. `scratch_directory` must be one
/// existing empty private directory; the PCS creates deterministic chunk
/// artifacts only beneath it and removes every validated artifact before a
/// successful return. Pass one binds the unchanged roots while retiring
/// predecessors; pass two replays recorded challenges without touching the
/// public coin and retains only queried leaves and siblings.
/// `max_working_field_bytes` bounds
/// live Fq/Fq2 leaf and sumcheck-table payloads; proof-output storage, reader
/// objects, the logarithmic Merkle frontier, and allocator metadata are
/// outside this deterministic field-payload limit.
struct BaseFoldExternalOpeningOptions {
    std::filesystem::path scratch_directory;
    /// Complete physical bytes allowed for the immutable external state and
    /// every simultaneously live opening scratch artifact.
    std::uint64_t max_live_storage_bytes = 0;
    std::uint64_t max_total_scratch_bytes = 0;
    std::uint64_t min_free_bytes = 0;
    std::uint64_t max_working_field_bytes = 0;
    /// Maximum values in one independently published Fq2 fold chunk. The
    /// implementation rounds no values and requires a power of two. Chunks
    /// are streamed a Merkle leaf at a time, so this controls the temporary
    /// file count and the additive live-storage overlap, not resident field
    /// memory. The default 2^24-value chunk limits target successor overlap
    /// to about 256 MiB while avoiding tens of thousands of tiny artifacts.
    std::size_t fold_chunk_elements = std::size_t{1} << 24U;
};

struct BaseFoldExternalOpeningReport {
    /// Physical scratch still live when the opening returns. A successful
    /// two-pass opening always reports zero and leaves the caller's root
    /// empty.
    std::uint64_t scratch_physical_bytes = 0;
    /// Maximum complete scratch bytes live at one time. This includes the
    /// one newly published successor chunk before its consumed predecessor
    /// chunks are removed.
    std::uint64_t scratch_peak_physical_bytes = 0;
    /// Cumulative physical bytes published and removed across both passes.
    std::uint64_t scratch_written_physical_bytes = 0;
    std::uint64_t scratch_deleted_physical_bytes = 0;
    std::uint64_t pass_one_scratch_written_physical_bytes = 0;
    std::uint64_t pass_two_scratch_written_physical_bytes = 0;
    std::uint64_t scratch_chunk_artifacts_written = 0;
    std::uint64_t scratch_chunk_artifacts_deleted = 0;
    std::uint64_t pass_one_chunk_artifacts_written = 0;
    std::uint64_t pass_two_chunk_artifacts_written = 0;
    /// Each v1 chunk artifact has one array file and one manifest file.
    std::uint64_t scratch_files_written = 0;
    std::uint64_t scratch_files_deleted = 0;
    std::uint64_t peak_live_storage_bytes = 0;
    /// Whole artifact bytes read by manifest/integrity validation.
    std::uint64_t artifact_validation_bytes = 0;
    /// Immutable PCS-state portion of `artifact_validation_bytes`.
    std::uint64_t state_artifact_validation_bytes = 0;
    std::uint64_t artifact_validation_passes = 0;
    /// Subset of validation traffic used to rebind each exact chunk before
    /// deletion. This prevents cleanup from recursively deleting a replaced
    /// path under the caller's private scratch root.
    std::uint64_t scratch_deletion_validation_bytes = 0;
    /// Canonical field/digest payload bytes read in forward passes. Reader
    /// headers and standard-library stream buffers are deliberately excluded.
    std::uint64_t sequential_read_payload_bytes = 0;
    std::uint64_t sumcheck_sequential_read_payload_bytes = 0;
    std::uint64_t pass_one_fold_sequential_read_payload_bytes = 0;
    std::uint64_t pass_two_fold_sequential_read_payload_bytes = 0;
    /// Canonical field/digest payload bytes read after an element seek.
    std::uint64_t indexed_read_payload_bytes = 0;
    std::uint64_t base_query_indexed_read_payload_bytes = 0;
    std::uint64_t sequential_write_payload_bytes = 0;
    std::uint64_t pass_one_sequential_write_payload_bytes = 0;
    std::uint64_t pass_two_sequential_write_payload_bytes = 0;
    std::uint64_t peak_working_field_bytes = 0;
    std::uint64_t proof_bytes = 0;
    std::size_t from_scratch_sumcheck_rounds = 0;
    std::size_t materialized_sumcheck_entries = 0;

    bool operator==(const BaseFoldExternalOpeningReport &) const = default;
};

struct BaseFoldExternalOpening {
    PcsOpeningProof proof;
    BaseFoldExternalOpeningReport report;
};

/// Mutation-free admission result for one external opening. The required
/// working-field peak reflects the sumcheck schedule selected by the supplied
/// memory limit; scratch and free-space requirements are exact for the
/// current artifact format. A successful preflight also proves that the
/// opaque state is external and bound to the expected commitment.
struct BaseFoldExternalOpeningPreflight {
    /// Canonical path of the validated immutable external-state artifact.
    /// Composing protocols use this to reject aliased persistent inputs and
    /// scratch roots before sampling challenges.
    std::filesystem::path state_artifact_directory;
    std::uint64_t state_artifact_physical_bytes = 0;
    /// Exact peak live scratch for either fold pass, not cumulative writes.
    std::uint64_t required_scratch_physical_bytes = 0;
    /// Exact cumulative chunk-artifact publication across pass one and the
    /// deterministic query replay. Every byte is deleted before success.
    std::uint64_t required_scratch_written_physical_bytes = 0;
    std::uint64_t required_sequential_write_payload_bytes = 0;
    std::uint64_t required_chunk_artifacts_written = 0;
    std::uint64_t required_scratch_files_written = 0;
    std::uint64_t required_live_storage_bytes = 0;
    std::uint64_t required_working_field_bytes = 0;
    std::size_t materialized_sumcheck_entries = 0;

    bool operator==(const BaseFoldExternalOpeningPreflight &) const =
        default;
};

/// Move-only result of one integrity/resource scan. A composing protocol may
/// admit all openings before Fiat--Shamir and then consume each admission
/// exactly once without reopening and rescanning its immutable PCS state.
class BaseFoldExternalOpeningAdmission {
  public:
    BaseFoldExternalOpeningAdmission() = default;
    BaseFoldExternalOpeningAdmission(
        const BaseFoldExternalOpeningAdmission &) = delete;
    BaseFoldExternalOpeningAdmission &operator=(
        const BaseFoldExternalOpeningAdmission &) = delete;
    BaseFoldExternalOpeningAdmission(
        BaseFoldExternalOpeningAdmission &&) noexcept = default;
    BaseFoldExternalOpeningAdmission &operator=(
        BaseFoldExternalOpeningAdmission &&) noexcept = default;

    const BaseFoldExternalOpeningPreflight &preflight() const {
        return preflight_;
    }

  private:
    friend class BaseFoldPcs;

    std::shared_ptr<const IPCS::ProverState> validated_prover_state_;
    PcsCommitment commitment_;
    BaseFoldExternalOpeningOptions options_;
    BaseFoldExternalOpeningPreflight preflight_;
};

/// Maximum canonical opening size for a message with `2^message_log`
/// evaluations and an interleaved commitment of `width` columns. Batched
/// Merkle openings are shorter when Fiat--Shamir queries share leaves or
/// authentication nodes, so callers use this bound only for admission and
/// framing; measured proof accounting uses the actual encoded byte length.
std::size_t basefold_opening_proof_max_size_bytes(
    std::size_t message_log, std::size_t width,
    BaseFoldPcsParameters parameters = {});

/// Maximum BLAKE2b-320 work used to authenticate one opening: hashes of all
/// unique disclosed leaves plus all parent hashes needed to reduce the
/// canonical union frontiers to their committed roots. This excludes the
/// prover's commitment construction and Fiat--Shamir hashing.
std::size_t basefold_opening_max_merkle_hashes(
    std::size_t message_log, BaseFoldPcsParameters parameters = {});

/// Transparent BaseFold PCS compiled with binary BLAKE2b-320 Merkle trees.
/// The encoding batches all queried leaves at each oracle layer into one
/// canonical union-frontier multiproof. Rate and query count are explicit;
/// all algebraic challenges are sampled in Fq2. The PCS is hash-agnostic at
/// the public-coin boundary; BCS16 supplies SHA-256 Fiat--Shamir.
class BaseFoldPcs final : public IPCS {
  public:
    static constexpr std::uint64_t kSchemeIdentifier =
        0x42415345464f4c44ULL; // "BASEFOLD"

    explicit BaseFoldPcs(BaseFoldPcsParameters parameters = {});

    std::string_view name() const override { return "BaseFold/Fq/Fq2/v1"; }
    std::uint64_t scheme_identifier() const override {
        return kSchemeIdentifier;
    }

    CommitOutput commit(std::span<const Fq> evaluations) const override;
    CommitOutput commit_columns(
        const std::vector<std::vector<Fq>> &columns) const override;

    /// Commit selected Fq arrays without materializing a message column,
    /// codeword, or Merkle tree in RAM. Source order defines commitment column
    /// order; the source artifact is validated and remains untouched.
    BaseFoldExternalCommitment commit_artifact_columns(
        std::shared_ptr<const storage::NativeFieldArtifact> source,
        std::span<const std::string> source_array_names,
        BaseFoldExternalCommitOptions options) const;

    /// Formula-only storage and controlled-field-memory plan for committing
    /// `width` equally sized columns. Compact virtual-zero expansion is fused
    /// into the first cache-local Mobius pass, so `compact_columns` does not
    /// add another scratch artifact.
    BaseFoldExternalCommitStoragePlan plan_external_commit_storage(
        std::size_t logical_evaluation_count, std::size_t width,
        bool compact_columns, std::uint64_t max_working_field_bytes,
        std::size_t requested_block_elements,
        std::size_t requested_cache_radix_elements = 0) const;

    /// Compact-source counterpart of `commit_artifact_columns`. All columns
    /// have one common power-of-two logical length, but their artifacts may
    /// omit setup-known zero runs. Commitment roots and opening bytes are
    /// identical to committing the corresponding dense resident columns.
    BaseFoldExternalCommitment commit_artifact_columns(
        std::shared_ptr<const storage::NativeFieldArtifact> source,
        std::span<const BaseFoldArtifactColumn> source_columns,
        BaseFoldExternalCommitOptions options) const;

    /// Persist an already committed resident state, then return an artifact-
    /// backed state in the caller-supplied directory. Use
    /// `commit_artifact_columns` when commitment construction itself must
    /// have bounded field memory.
    BaseFoldExternalization externalize_prover_state(
        const std::shared_ptr<const ProverState> &prover_state,
        BaseFoldExternalStateOptions options) const;

    /// Reopen a completed, manifest-last external state in another process.
    /// The expected commitment determines the setup-bound artifact identity.
    std::shared_ptr<const ProverState> open_external_prover_state(
        const std::filesystem::path &directory,
        const PcsCommitment &commitment) const;

    /// Adopt an already validated or same-writer trusted artifact handle.
    /// This checks the complete BaseFold layout and commitment-bound root but
    /// deliberately does not rescan payloads. Use the path overload at every
    /// persisted or cross-process boundary.
    std::shared_ptr<const ProverState> adopt_external_prover_state(
        std::shared_ptr<const storage::NativeFieldArtifact> artifact,
        const PcsCommitment &commitment) const;

    /// Require an opaque state to be the resident BaseFold state for exactly
    /// `expected_commitment`. This does not mutate a transcript.
    void validate_resident_prover_state(
        const std::shared_ptr<const ProverState> &prover_state,
        const PcsCommitment &expected_commitment) const;

    /// Validate an external state and all deterministic opening resources
    /// without creating scratch files or mutating a transcript. The caller
    /// can therefore admit every composed opening before sampling an outer
    /// protocol challenge.
    BaseFoldExternalOpeningPreflight preflight_external_opening(
        const std::shared_ptr<const ProverState> &prover_state,
        const PcsCommitment &expected_commitment,
        const BaseFoldExternalOpeningOptions &options) const;

    /// Scan and bind one external state and its opening resources once. The
    /// returned admission owns the validated handle and exact resource plan.
    BaseFoldExternalOpeningAdmission admit_external_opening(
        const std::shared_ptr<const ProverState> &prover_state,
        const PcsCommitment &expected_commitment,
        BaseFoldExternalOpeningOptions options) const;

    /// Formula-only state, scratch, and controlled-field-memory projection.
    /// This does not open an artifact, inspect a path, or perform an integrity
    /// scan.
    BaseFoldExternalOpeningStoragePlan plan_external_opening_storage(
        const PcsCommitment &commitment,
        std::size_t fold_chunk_elements,
        std::uint64_t max_working_field_bytes) const;

    /// Bounded-field-memory opening of an artifact-backed single column.
    BaseFoldExternalOpening open_external(
        const std::shared_ptr<const ProverState> &prover_state,
        std::span<const Fq2> point, const Fq2 &claimed_value,
        BaseFoldExternalOpeningOptions options,
        PublicCoin &public_coin) const;

    BaseFoldExternalOpening open_external_admitted(
        BaseFoldExternalOpeningAdmission admission,
        std::span<const Fq2> point, const Fq2 &claimed_value,
        PublicCoin &public_coin) const;

    /// Bounded-field-memory opening of an artifact-backed linear combination.
    BaseFoldExternalOpening open_linear_combination_external(
        const std::shared_ptr<const ProverState> &prover_state,
        std::span<const Fq2> column_weights,
        std::span<const Fq2> point, const Fq2 &claimed_value,
        BaseFoldExternalOpeningOptions options,
        PublicCoin &public_coin) const;

    BaseFoldExternalOpening open_linear_combination_external_admitted(
        BaseFoldExternalOpeningAdmission admission,
        std::span<const Fq2> column_weights,
        std::span<const Fq2> point, const Fq2 &claimed_value,
        PublicCoin &public_coin) const;
    PcsOpeningProof open(
        const std::shared_ptr<const ProverState> &prover_state,
        std::span<const Fq2> point, const Fq2 &claimed_value,
        PublicCoin &public_coin) const override;
    PcsOpeningProof open_linear_combination(
        const std::shared_ptr<const ProverState> &prover_state,
        std::span<const Fq2> column_weights,
        std::span<const Fq2> point, const Fq2 &claimed_value,
        PublicCoin &public_coin) const override;
    bool verify(const PcsCommitment &commitment,
                std::span<const Fq2> point, const Fq2 &claimed_value,
                const PcsOpeningProof &proof,
                PublicCoin &public_coin) const override;
    bool verify_linear_combination(
        const PcsCommitment &commitment,
        std::span<const Fq2> column_weights,
        std::span<const Fq2> point, const Fq2 &claimed_value,
        const PcsOpeningProof &proof,
        PublicCoin &public_coin) const override;

    const BaseFoldPcsParameters &parameters() const { return parameters_; }

  private:
    CommitOutput commit_owned_columns(
        std::vector<std::vector<Fq>> columns) const;

    BaseFoldPcsParameters parameters_;
};

} // namespace laminate::spartan

#endif // LAMINATE_SPARTAN_BASEFOLD_PCS_HPP
