#ifndef LAMINATE_SPARTAN_FACTORED_HPP
#define LAMINATE_SPARTAN_FACTORED_HPP

/// @file factored.hpp
/// @brief Computation commitments for factored R1CS matrix evaluations.

#include "laminate/spartan/basefold_pcs.hpp"
#include "laminate/storage/native_field_artifact.hpp"
#include "laminate/transcript/hash.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace laminate::spartan {

/// Identifier for the factored-matrix computation-commitment profile.
inline constexpr std::uint64_t kFactoredMatrixProfileIdentifier =
    0x4641435454454e53ULL; // "FACTTENS"

/// Shape of one dense residual tensor committed as equal-length columns.
struct FactoredTensorShape {
    std::uint64_t evaluation_count = 0;
    std::uint64_t column_count = 0;

    bool operator==(const FactoredTensorShape &) const = default;
};

/// Structure-owned field payload allocated while constructing or compactly
/// evaluating one tensor operand. The materialization peak includes the
/// returned `evaluation_count`-entry operand vector; the compact peak covers
/// only allocations inside `evaluate_tensor_operand`. O(1) scalar locals and
/// allocator metadata are excluded, consistently with the outer report.
struct FactoredTensorOperandWorkingSet {
    std::uint64_t materialization_peak_field_bytes = 0;
    std::uint64_t compact_evaluation_peak_field_bytes = 0;

    bool operator==(const FactoredTensorOperandWorkingSet &) const =
        default;
};

/// Compact, verifier-visible description of a factored matrix relation.
///
/// For tensor `i`, let `T_i[j,k]` be committed column `j` at Boolean address
/// `k`, let `w_i[j]` be `tensor_column_weights`, and let `q_i[k]` be the
/// materialized operand. The residual contribution is
///
///   sum_k (sum_j w_i[j] T_i[j,k]) q_i[k].
///
/// `materialize_tensor_operand` is a prover-only linear-time operation.
/// Verification calls only `evaluate_tensor_operand`, which must evaluate the
/// operand's multilinear extension at an arbitrary MSB-first point without
/// materializing its Boolean table.
class FactoredMatrixStructure {
  public:
    virtual ~FactoredMatrixStructure() = default;

    virtual Digest circuit_digest() const = 0;
    virtual Digest structure_digest() const = 0;
    virtual std::uint64_t row_variables() const = 0;
    virtual std::uint64_t column_variables() const = 0;

    virtual std::size_t tensor_count() const = 0;
    virtual FactoredTensorShape
    tensor_shape(std::size_t tensor_index) const = 0;

    /// Exact structure-owned field-payload peaks for the two operand APIs.
    /// External proving rejects zero or sub-output materialization reports
    /// before mutating its public coin.
    virtual FactoredTensorOperandWorkingSet tensor_operand_working_set(
        std::size_t tensor_index) const = 0;

    /// Return the regular, noncommitted A/B/C matrix MLE evaluations.
    virtual std::array<Fq2, 3> regular_matrix_evaluations(
        std::span<const Fq2> row_point,
        std::span<const Fq2> column_point) const = 0;

    /// Return the verifier-derived linear combination of committed columns.
    virtual std::vector<Fq2> tensor_column_weights(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point, const Fq2 &gamma) const = 0;

    /// Materialize the Boolean operand table. Provers call this method;
    /// verifiers do not.
    virtual std::vector<Fq2> materialize_tensor_operand(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point, const Fq2 &gamma) const = 0;

    /// Evaluate the operand MLE at an MSB-first tensor point compactly.
    virtual Fq2 evaluate_tensor_operand(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point, const Fq2 &gamma,
        std::span<const Fq2> tensor_point) const = 0;
};

struct FactoredTensorCommitment {
    FactoredTensorShape shape{};
    PcsCommitment columns{};

    bool operator==(const FactoredTensorCommitment &) const = default;
};

/// Setup-bound commitment to every dense residual tensor.
struct FactoredMatrixCommitment {
    std::uint64_t profile = kFactoredMatrixProfileIdentifier;
    Digest circuit_digest{};
    Digest structure_digest{};
    std::uint64_t row_variables = 0;
    std::uint64_t column_variables = 0;
    std::vector<FactoredTensorCommitment> tensors;

    bool operator==(const FactoredMatrixCommitment &) const = default;
};

struct FactoredTensorProverKey {
    std::vector<std::vector<Fq>> columns;
    std::shared_ptr<const IPCS::ProverState> opening_state;
    enum class OpeningStateSource : std::uint8_t {
        Resident = 0,
        External = 1,
    } opening_state_source = OpeningStateSource::Resident;
};

enum class FactoredTensorColumnSource : std::uint8_t {
    Resident = 0,
    Artifact = 1,
};

struct FactoredMatrixProverKey {
    FactoredMatrixCommitment commitment;
    std::shared_ptr<const FactoredMatrixStructure> structure;
    std::vector<FactoredTensorProverKey> tensors;
    FactoredTensorColumnSource tensor_column_source =
        FactoredTensorColumnSource::Resident;
    std::shared_ptr<const storage::NativeFieldArtifact>
        tensor_columns_artifact;
};

struct FactoredMatrixVerifierKey {
    FactoredMatrixCommitment commitment;
    std::shared_ptr<const FactoredMatrixStructure> structure;
};

struct FactoredMatrixSetup {
    FactoredMatrixProverKey prover_key;
    FactoredMatrixVerifierKey verifier_key;
};

/// Caller-selected destination and hard storage limits for artifact-backed
/// preprocessing. The directory must satisfy NativeFieldArtifact's ownership
/// and emptiness requirements.
struct FactoredMatrixArtifactOptions {
    std::filesystem::path directory;
    storage::NativeFieldArtifactOptions limits;
};

/// Whether successful external preprocessing retains the staging artifact at
/// its original path or atomically transfers it into a caller-owned private
/// quarantine directory. Transfer requires sole shared ownership. This API
/// does not delete quarantined data; the caller may remove it after success.
enum class FactoredMatrixStagingOwnership : std::uint8_t {
    Retain = 0,
    MoveToQuarantineOnSuccess = 1,
};

struct FactoredTensorExternalPreprocessingReport {
    FactoredTensorShape shape{};
    Digest external_state_identity{};
    BaseFoldExternalStateReport external_state;
    BaseFoldExternalCommitReport commitment;
};

/// Formula-only cost of source-first preprocessing for one tensor. The
/// selected block size is setup policy, while every byte count is derived by
/// the same BaseFold planner used by execution.
struct FactoredTensorExternalPreprocessingPlan {
    FactoredTensorShape shape{};
    std::vector<std::string> column_names;
    BaseFoldExternalCommitStoragePlan commitment;

    bool operator==(
        const FactoredTensorExternalPreprocessingPlan &) const = default;
};

/// Formula-only plan for source-first factored-matrix preprocessing.
///
/// Constructing this object performs no artifact access and no filesystem
/// I/O. Both callers that need early admission and the executing routine use
/// this one plan, so storage and controlled-field-memory formulas cannot
/// drift across the preprocessing boundary.
struct FactoredMatrixExternalPreprocessingPlan {
    std::uint64_t staging_physical_bytes = 0;
    std::uint64_t tensor_payload_bytes = 0;
    std::uint64_t canonical_artifact_physical_bytes = 0;
    std::uint64_t external_states_physical_bytes = 0;
    std::uint64_t persistent_output_physical_bytes = 0;
    std::uint64_t conservative_peak_live_physical_bytes = 0;
    std::size_t effective_copy_block_elements = 0;
    std::uint64_t peak_copy_working_field_bytes = 0;
    std::uint64_t peak_working_field_bytes = 0;
    std::vector<FactoredTensorExternalPreprocessingPlan> tensors;

    bool operator==(
        const FactoredMatrixExternalPreprocessingPlan &) const = default;
};

struct FactoredMatrixExternalPreprocessingPlanningOptions {
    std::uint64_t staging_physical_bytes = 0;
    std::size_t copy_block_elements = 0;
    std::vector<std::size_t> tensor_commitment_block_elements;
};

/// Explicit storage and memory resources for source-first factored setup.
/// There must be one BaseFold destination/scratch pair per tensor. Every path
/// names an existing caller-owned directory and all paths must be disjoint.
struct FactoredMatrixExternalPreprocessingOptions {
    FactoredMatrixArtifactOptions tensor_columns_artifact;
    std::vector<BaseFoldExternalCommitOptions> tensor_commitments;
    FactoredMatrixStagingOwnership staging_ownership =
        FactoredMatrixStagingOwnership::Retain;
    /// Existing empty caller-owned private directory on the staging
    /// artifact's device. Successful transfer atomically renames staging into
    /// a fixed child of this namespace; the API never replaces a target.
    /// The caller must not mutate the namespace concurrently.
    std::filesystem::path staging_quarantine_directory;
    /// Global cap on the conservative live-storage peak. The peak includes
    /// staging, prior tensor states, the current tensor's exact final state
    /// and scratch peak simultaneously, and the canonical publication.
    std::uint64_t max_live_physical_bytes = 0;
    std::uint64_t max_copy_working_field_bytes = 0;
    std::size_t copy_block_elements = 0;
};

/// Exact logical and physical storage accounting for source-first setup.
/// Per-tensor reports retain BaseFold's complete I/O, scratch, and memory
/// accounting; aggregate counters describe the sequential outer operation.
struct FactoredMatrixExternalPreprocessingReport {
    std::uint64_t staging_physical_bytes = 0;
    std::uint64_t staging_validation_bytes = 0;
    std::uint64_t tensor_payload_bytes = 0;
    std::uint64_t canonical_copy_read_payload_bytes = 0;
    std::uint64_t canonical_copy_write_payload_bytes = 0;
    std::uint64_t canonical_copy_read_operations = 0;
    std::uint64_t canonical_copy_write_operations = 0;
    std::uint64_t canonical_comparison_read_payload_bytes = 0;
    std::uint64_t canonical_comparison_read_operations = 0;
    std::uint64_t canonical_artifact_physical_bytes = 0;
    std::uint64_t canonical_artifact_validation_bytes = 0;
    std::uint64_t external_states_physical_bytes = 0;
    std::uint64_t basefold_artifact_validation_bytes = 0;
    std::uint64_t basefold_sequential_read_payload_bytes = 0;
    std::uint64_t basefold_indexed_read_payload_bytes = 0;
    std::uint64_t basefold_sequential_write_payload_bytes = 0;
    std::uint64_t basefold_indexed_write_payload_bytes = 0;
    std::uint64_t basefold_scratch_peak_physical_bytes = 0;
    std::uint64_t basefold_scratch_written_physical_bytes = 0;
    std::uint64_t basefold_scratch_deleted_physical_bytes = 0;
    std::uint64_t persistent_output_physical_bytes = 0;
    std::uint64_t retained_staging_physical_bytes = 0;
    std::uint64_t quarantined_staging_physical_bytes = 0;
    std::filesystem::path staging_quarantine_artifact_path;
    std::uint64_t final_live_physical_bytes = 0;
    std::uint64_t max_live_physical_bytes = 0;
    std::uint64_t conservative_peak_live_physical_bytes = 0;
    std::uint64_t peak_copy_working_field_bytes = 0;
    std::uint64_t peak_working_field_bytes = 0;
    std::vector<FactoredTensorExternalPreprocessingReport> tensors;
};

struct FactoredMatrixExternalPreprocessing {
    FactoredMatrixSetup setup;
    FactoredMatrixExternalPreprocessingReport report;
};

/// Derive tensor shapes, canonical publication bytes, per-tensor BaseFold
/// state/scratch costs, and the complete phase-local storage peak without
/// opening an artifact or touching a path.
FactoredMatrixExternalPreprocessingPlan
plan_factored_matrix_external_preprocessing(
    const FactoredMatrixStructure &structure, const BaseFoldPcs &pcs,
    FactoredMatrixExternalPreprocessingPlanningOptions options);

/// Degree-two product-sumcheck message. The proof carries g(1),g(2), while
/// the verifier recovers g(0) from the current claim g(0)+g(1).
struct FactoredSumcheckRound {
    std::array<Fq2, 2> evaluations{};

    bool operator==(const FactoredSumcheckRound &) const = default;
};

struct FactoredTensorEvaluationProof {
    Fq2 claim{};
    std::vector<FactoredSumcheckRound> rounds;
    Fq2 terminal_tensor_value{};
    PcsOpeningProof opening;

    bool operator==(const FactoredTensorEvaluationProof &) const = default;
};

/// Authenticated evaluation of A + gamma*B + gamma^2*C at (r_x,r_y).
struct FactoredMatrixEvaluationProof {
    std::vector<FactoredTensorEvaluationProof> tensors;

    bool operator==(const FactoredMatrixEvaluationProof &) const = default;
};

/// Per-tensor caller-owned scratch for external BaseFold openings.
struct FactoredMatrixExternalProvingOptions {
    std::vector<BaseFoldExternalOpeningOptions> tensor_openings;
    /// Complete physical-byte cap for the raw-column artifact, every
    /// simultaneously retained external PCS state, the largest sequential
    /// opening scratch artifact, and `reserved_live_storage_bytes`.
    std::uint64_t max_live_storage_bytes = 0;
    /// Caller-declared concurrently live bytes outside artifacts owned by
    /// this API (for example, an enclosing protocol's proof state).
    std::uint64_t reserved_live_storage_bytes = 0;
    /// Hard cap for the complete outer field-payload ledger, including
    /// structure-owned operand caches and the BaseFold opening peak. It is
    /// checked for every tensor before the public coin is mutated.
    std::uint64_t max_working_field_bytes = 0;
};

struct FactoredMatrixExternalProvingReport {
    std::vector<BaseFoldExternalOpeningReport> tensor_openings;
    /// Raw canonical tensor-column payload scanned by component-claim and
    /// weighted-table construction. Readers are forward-only here.
    std::uint64_t tensor_column_sequential_read_payload_bytes = 0;
    std::uint64_t tensor_column_sequential_read_operations = 0;
    std::uint64_t tensor_column_read_seek_operations = 0;
    /// Full external-state scans performed by the outer all-tensor admission
    /// pass before any factored challenge is sampled.
    std::uint64_t basefold_preflight_validation_bytes = 0;
    std::uint64_t basefold_state_integrity_scans = 0;
    std::uint64_t artifact_validation_bytes = 0;
    /// Total forward payload reads, including tensor columns and BaseFold.
    std::uint64_t sequential_read_payload_bytes = 0;
    std::uint64_t indexed_read_payload_bytes = 0;
    std::uint64_t sequential_write_payload_bytes = 0;
    std::uint64_t scratch_peak_physical_bytes = 0;
    std::uint64_t scratch_written_physical_bytes = 0;
    std::uint64_t scratch_deleted_physical_bytes = 0;
    std::uint64_t scratch_chunk_artifacts_written = 0;
    std::uint64_t scratch_chunk_artifacts_deleted = 0;
    std::uint64_t scratch_files_written = 0;
    std::uint64_t scratch_files_deleted = 0;
    /// Complete physical-storage ledger at admission. Openings run
    /// sequentially, so the peak adds the largest scratch artifact rather
    /// than summing all configured scratch requirements.
    std::uint64_t tensor_columns_physical_bytes = 0;
    std::uint64_t external_states_physical_bytes = 0;
    std::uint64_t persistent_input_physical_bytes = 0;
    std::uint64_t reserved_live_storage_bytes = 0;
    std::uint64_t admitted_live_storage_bytes = 0;
    std::uint64_t peak_live_storage_bytes = 0;
    /// Complete controlled field-payload ledger for the current schedule.
    /// It counts protocol-required field-element slots in retained vectors
    /// and tables,
    /// the fixed 4096-Fq artifact buffer, accumulated factored sumcheck
    /// messages, and BaseFold's own controlled field peak. The reported peak
    /// is the maximum of actual simultaneous schedule phases, conservatively
    /// retaining the read buffer for a potentially active weighted scan.
    /// Encoded proof bytes, allocator metadata, reader objects, and O(1)
    /// scalar temporaries are excluded.
    std::uint64_t retained_column_weight_field_bytes = 0;
    std::uint64_t retained_claim_field_bytes = 0;
    std::uint64_t tensor_column_read_buffer_field_bytes = 0;
    std::uint64_t resident_product_sumcheck_field_bytes = 0;
    std::uint64_t operand_materialization_field_bytes = 0;
    std::uint64_t compact_operand_evaluation_field_bytes = 0;
    std::uint64_t product_challenge_point_field_bytes = 0;
    std::uint64_t accumulated_factored_proof_field_bytes = 0;
    std::uint64_t outer_opening_retained_field_bytes = 0;
    std::uint64_t basefold_opening_field_bytes = 0;
    std::uint64_t admitted_working_field_bytes = 0;
    std::uint64_t peak_working_field_bytes = 0;
    std::uint64_t proof_bytes = 0;
};

struct FactoredMatrixExternalProving {
    FactoredMatrixEvaluationProof proof;
    FactoredMatrixExternalProvingReport report;
};

struct FactoredMatrixExternalProvingPlan {
    FactoredMatrixExternalProvingReport report;
    std::vector<std::uint64_t> outer_opening_retained_field_bytes;
};

/// Value-free resource plan for an already-admitted set of external tensor
/// openings. This is the exact planner consumed by external proving.
FactoredMatrixExternalProvingPlan
plan_factored_matrix_evaluation_external_admitted(
    const FactoredMatrixProverKey &key,
    const FactoredMatrixExternalProvingOptions &options,
    std::span<const BaseFoldExternalOpeningPreflight> opening_admissions);

/// Commit each tensor's equal-length columns with BaseFold. The outer vector
/// is ordered by tensor, then column, then Boolean evaluation address.
FactoredMatrixSetup preprocess_factored_matrix(
    std::shared_ptr<const FactoredMatrixStructure> structure,
    std::vector<std::vector<std::vector<Fq>>> tensors,
    const IPCS &pcs);

/// Commit as in `preprocess_factored_matrix`, but persist the raw tensor
/// columns in canonical tensor-major/column-major order instead of retaining
/// the duplicate resident vectors in the factored prover key. BaseFold's
/// opaque prover state remains resident. Because the artifact identity binds
/// finalized BaseFold roots, commitment construction retains its resident
/// transient peak. Use `preprocess_factored_matrix_external` to construct
/// commitments with bounded field memory.
FactoredMatrixSetup preprocess_factored_matrix_to_artifact(
    std::shared_ptr<const FactoredMatrixStructure> structure,
    std::vector<std::vector<std::vector<Fq>>> tensors,
    const IPCS &pcs, FactoredMatrixArtifactOptions options);

/// Structure-bound identity for a raw tensor staging artifact, before PCS
/// roots exist. Arrays use the same canonical tensor-major order as the
/// finalized root-bound artifact.
Digest factored_matrix_staging_artifact_identity(
    const FactoredMatrixStructure &structure);

/// Reopen and validate a source-first staging artifact against its structure.
std::shared_ptr<const storage::NativeFieldArtifact>
open_factored_matrix_staging_artifact(
    const std::filesystem::path &directory,
    const FactoredMatrixStructure &structure);

/// Commit every staged tensor directly into an external BaseFold state, then
/// publish the canonical root-bound raw-column artifact with one bounded
/// sequential copy. No tensor columns or BaseFold state are materialized in
/// resident nested field vectors. The returned setup is directly accepted by
/// `prove_factored_matrix_evaluation_external`.
FactoredMatrixExternalPreprocessing preprocess_factored_matrix_external(
    std::shared_ptr<const FactoredMatrixStructure> structure,
    std::shared_ptr<const storage::NativeFieldArtifact> staging_artifact,
    const BaseFoldPcs &pcs,
    FactoredMatrixExternalPreprocessingOptions options);

/// Identity for the tensor-column artifact. It binds the canonical full
/// factored commitment: circuit and structure identities, matrix and tensor
/// geometry, PCS scheme/rate/query parameters, and commitment roots.
Digest factored_matrix_artifact_identity(
    const FactoredMatrixCommitment &commitment);

/// Canonical v1 array name for one tensor column. External-memory consumers
/// use this helper instead of duplicating the artifact's private ordering
/// convention.
std::string factored_matrix_tensor_column_array_name(
    std::size_t tensor_index, std::size_t column_index);

/// Reopen and validate an artifact against a factored commitment, including
/// canonical array names, order, kinds, and lengths.
std::shared_ptr<const storage::NativeFieldArtifact>
open_factored_matrix_artifact(
    const std::filesystem::path &directory,
    const FactoredMatrixCommitment &commitment);

/// Check profile, structure identity, geometry, tensor order, and BaseFold
/// parameters without accessing committed tensor evaluations.
bool valid_factored_matrix_commitment(
    const FactoredMatrixCommitment &commitment,
    const FactoredMatrixStructure &structure, const IPCS &pcs);

FactoredMatrixEvaluationProof prove_factored_matrix_evaluation(
    const FactoredMatrixProverKey &key,
    std::span<const Fq2> row_point,
    std::span<const Fq2> column_point, const Fq2 &gamma,
    const Fq2 &claimed_matrix_evaluation, const IPCS &pcs,
    PublicCoin &public_coin);

/// Produce the complete factored proof with bounded-memory BaseFold openings.
/// Scratch roots are validated before proving and cleared after each opening;
/// the report records their produced and deleted physical bytes. Product-
/// sumcheck operands and weighted tensor tables are resident; their Fq2 peak
/// is reported separately and included in resource admission.
FactoredMatrixExternalProving prove_factored_matrix_evaluation_external(
    const FactoredMatrixProverKey &key,
    std::span<const Fq2> row_point,
    std::span<const Fq2> column_point, const Fq2 &gamma,
    const Fq2 &claimed_matrix_evaluation, const BaseFoldPcs &pcs,
    FactoredMatrixExternalProvingOptions options,
    PublicCoin &public_coin);

/// Consume BaseFold admissions already validated before an enclosing
/// protocol sampled challenges. No external PCS state is reopened or
/// integrity-scanned by this overload.
FactoredMatrixExternalProving
prove_factored_matrix_evaluation_external_admitted(
    const FactoredMatrixProverKey &key,
    std::span<const Fq2> row_point,
    std::span<const Fq2> column_point, const Fq2 &gamma,
    const Fq2 &claimed_matrix_evaluation, const BaseFoldPcs &pcs,
    FactoredMatrixExternalProvingOptions options,
    std::vector<BaseFoldExternalOpeningAdmission> opening_admissions,
    PublicCoin &public_coin);

bool verify_factored_matrix_evaluation(
    const FactoredMatrixVerifierKey &key,
    std::span<const Fq2> row_point,
    std::span<const Fq2> column_point, const Fq2 &gamma,
    const Fq2 &claimed_matrix_evaluation,
    const FactoredMatrixEvaluationProof &proof, const IPCS &pcs,
    PublicCoin &public_coin);

/// Canonical bytes suitable for setup-digest and transcript binding.
std::vector<std::uint8_t> encode_factored_matrix_commitment(
    const FactoredMatrixCommitment &commitment);

/// Canonical proof bytes used for exact proof-size accounting.
void append_factored_matrix_evaluation_proof(
    const FactoredMatrixEvaluationProof &proof,
    std::vector<std::uint8_t> &output);

std::vector<std::uint8_t> encode_factored_matrix_evaluation_proof(
    const FactoredMatrixEvaluationProof &proof);

std::size_t factored_matrix_evaluation_proof_size_bytes(
    const FactoredMatrixEvaluationProof &proof);

/// Maximum canonical proof size admitted by the committed tensor shapes and
/// BaseFold parameters, without materializing the tensors or a proof.
std::size_t factored_matrix_evaluation_proof_max_size_bytes(
    const FactoredMatrixCommitment &commitment,
    BaseFoldPcsParameters parameters = {});

} // namespace laminate::spartan

#endif // LAMINATE_SPARTAN_FACTORED_HPP
