#ifndef LAMINATE_PACKING_PROOF_R1CS_HPP
#define LAMINATE_PACKING_PROOF_R1CS_HPP

/// @file r1cs.hpp
/// @brief Complete ciphertext-commitment-plus-packing R1CS for Spartan.

#include "laminate/gkr/ciphertext_commitment.hpp"
#include "laminate/packing/outer_relation/assignment.hpp"
#include "laminate/packing/outer_relation/packing_r1cs.hpp"
#include "laminate/packing/proof/r1cs/layout.hpp"
#include "laminate/spartan/r1cs.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace laminate::packing {

/// Exact constraint and variable counts before Spartan power-of-two padding.
struct ProofOfPackingR1csLedger {
    std::uint64_t aligned_ciphertexts = 0;

    // Hash each private aligned ciphertext into its logical public
    // commitment.
    std::uint64_t ciphertext_preimage_field_elements = 0;
    std::uint64_t ciphertext_commitment_constraints_per_ciphertext = 0;
    std::uint64_t ciphertext_commitment_constraints = 0;
    std::uint64_t poseidon_sbox_constraints_per_ciphertext = 0;
    std::uint64_t poseidon_checkpoint_constraints_per_ciphertext = 0;
    std::uint64_t poseidon_output_constraints_per_ciphertext = 0;
    std::uint64_t ciphertext_poseidon_constraints = 0;

    std::uint64_t total_poseidon_constraints = 0;

    std::uint64_t packing_relation_constraints = 0;
    /// Number of active equations, excluding structural zero-row gaps.
    std::uint64_t total_constraints = 0;
    /// Highest used matrix row plus one. Spartan pads this extent.
    std::uint64_t matrix_rows = 0;

    /// Exact sparse entries emitted by the Poseidon gadget; these counters are
    /// zero for another selected relation. The generic commitment counters
    /// below cover either policy. The packing suffix uses a conservative upper
    /// bound until its public NTT constants are streamed during concrete setup.
    std::uint64_t ciphertext_poseidon_nonzero_entries_per_ciphertext = 0;
    std::uint64_t ciphertext_poseidon_nonzero_entries = 0;
    std::uint64_t
        ciphertext_commitment_nonzero_entries_per_ciphertext = 0;
    std::uint64_t ciphertext_commitment_nonzero_entries = 0;
    std::uint64_t packing_relation_nonzero_entries_upper_bound = 0;
    std::uint64_t total_nonzero_entries_upper_bound = 0;
    /// False only for the explicitly dimension-only ledger. In that case all
    /// six nonzero-entry counters above are unavailable and set to zero.
    bool nonzero_entry_counts_available = false;

    // The canonical logical statement is the Spartan public input vector.
    std::uint64_t commitment_logical_inputs = 0;
    std::uint64_t packing_logical_inputs = 0;
    std::uint64_t total_logical_inputs = 0;
    std::uint64_t total_public_inputs = 0;

    std::uint64_t packing_witness_variables = 0;
    std::uint64_t ciphertext_poseidon_auxiliary_witness_variables = 0;
    std::uint64_t
        ciphertext_commitment_auxiliary_witness_variables = 0;
    std::uint64_t active_witness_variables = 0;
    /// Witness extent including rate-major structural gaps.
    std::uint64_t total_witness_variables = 0;

    bool operator==(const ProofOfPackingR1csLedger &) const = default;
};

ProofOfPackingR1csLedger
proof_of_packing_r1cs_ledger(const OuterRelationPlan &plan);

/// Exact constraint, variable, and padding inputs without synthesizing the
/// comparatively expensive Poseidon sparse-entry count. The returned marker
/// says those counters are unavailable; every dimension remains identical to
/// `proof_of_packing_r1cs_ledger(plan)`.
ProofOfPackingR1csLedger
proof_of_packing_r1cs_dimension_ledger(const OuterRelationPlan &plan);

/// Public encoders used to stream the fixed base-17 matrix at setup time.
struct ProofOfPackingR1csEncoders {
    PlaintextCoefficientEncoder centered_coefficients;
    NativePlaintextNttEncoder native_ntt;
};

struct CompiledProofOfPackingR1cs {
    spartan::R1csInstance circuit;
    ProofOfPackingR1csLedger ledger;
    ProofOfPackingR1csLayout layout;
    NativePackingOperator native_packing_operator;
    FixedPackingR1csStreamStatistics fixed_packing_statistics;
};

/// Compile the complete sparse A/B/C matrices.
///
/// Arguments:
/// - `plan` fixes every row and variable range;
/// - `packing_operator` fixes the public alignment/packing map;
/// - `encoders` produce its exact native-NTT coefficients; and
/// - `radix` is the signed decomposition used by the transmitted digits.
///
/// Preconditions: all four arguments describe the same geometry and native
/// field. Postcondition: the returned circuit hashes every aligned ciphertext,
/// enforces the packing relation, and uses the canonical logical statement as
/// its public input vector. Target Poseidon rows use the structured transposed
/// layout consumed by the reference/prover-only matrix oracle; diagnostic
/// simpleCTHash rows use a contiguous sparse recurrence.
CompiledProofOfPackingR1cs compile_proof_of_packing_r1cs(
    const OuterRelationPlan &plan,
    const PackingLinearOperator &packing_operator,
    ProofOfPackingR1csEncoders encoders, BalancedRadix radix);

/// Convert the GKR commitments into the first logical-input fields.
std::vector<Fq> proof_of_packing_commitment_logical_inputs(
    std::span<const gkr::HashCommitCT> commitments);

/// Construct the canonical logical statement
/// `[HashCommitCT fields | packed challenge words | revealed tests | digits]`.
/// Every input must have the dimensions fixed by `plan`; native coordinates
/// must be canonical. The result is the Spartan public input vector.
std::vector<Fq> make_proof_of_packing_logical_inputs(
    const OuterRelationPlan &plan,
    std::span<const gkr::HashCommitCT> commitments,
    const OuterRelationPublicInputs &packing_public_inputs);

/// Construct the canonical public input vector seen by Spartan.
std::vector<Fq> make_proof_of_packing_public_inputs(
    const OuterRelationPlan &plan,
    std::span<const gkr::HashCommitCT> commitments,
    const OuterRelationPublicInputs &packing_public_inputs);

/// Construct `[public | witness]`, including every selected commitment-gadget
/// wire, from a borrowed packing-relation assignment.
///
/// Preconditions: `commitments` and `packing_assignment` follow `plan`, and
/// each commitment opens to the aligned-coordinate slice in the assignment.
/// Postcondition: `public` contains the canonical logical statement and
/// `witness` contains the outer witness plus ciphertext-commitment auxiliaries.
/// Dimension, canonicality, or commitment mismatches throw.
spartan::R1csAssignment make_proof_of_packing_r1cs_assignment(
    const OuterRelationPlan &plan,
    std::span<const gkr::HashCommitCT> commitments,
    const OuterRelationR1csAssignmentView &packing_assignment);

/// Caller-owned resources for the complete structured Spartan assignment.
/// The destination must be an existing empty private directory. The memory
/// limit covers the coordinate, selected commitment-advice, and Fq I/O buffers
/// retained by this writer; fixed-size gadget state and allocator metadata are
/// not included in that deterministic payload count.
struct ProofOfPackingAssignmentArtifactOptions {
    std::filesystem::path directory;
    storage::NativeFieldArtifactOptions storage_limits;
    std::uint64_t max_working_bytes = 0;
    std::size_t block_elements = 0;
};

/// Value-free resource plan shared by admission and execution. The minimum
/// holds one ciphertext's coordinates, its selected commitment advice, and
/// one Fq I/O element; the selected block is the largest caller-requested
/// block within the admitted cap.
struct ProofOfPackingAssignmentArtifactPlan {
    std::uint64_t physical_bytes = 0;
    std::uint64_t retained_working_bytes = 0;
    std::uint64_t minimum_working_bytes = 0;
    std::size_t effective_block_elements = 0;
    std::uint64_t peak_working_bytes = 0;

    bool operator==(
        const ProofOfPackingAssignmentArtifactPlan &) const = default;
};

ProofOfPackingAssignmentArtifactPlan
plan_proof_of_packing_assignment_artifact(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    std::uint64_t max_working_bytes,
    std::size_t requested_block_elements);

/// Exact I/O and storage ledger for a complete assignment artifact.
struct ProofOfPackingAssignmentArtifactReport {
    std::uint64_t public_input_elements = 0;
    std::uint64_t witness_half_elements = 0;
    std::uint64_t stored_witness_elements = 0;
    std::uint64_t active_outer_witness_elements = 0;
    std::uint64_t ciphertext_commitment_auxiliary_elements = 0;
    std::uint64_t zero_witness_elements = 0;
    std::uint64_t public_payload_bytes = 0;
    std::uint64_t logical_witness_payload_bytes = 0;
    std::uint64_t stored_witness_payload_bytes = 0;
    std::uint64_t physical_bytes = 0;
    std::uint64_t source_read_payload_bytes = 0;
    std::uint64_t source_read_operations = 0;
    std::uint64_t source_seek_operations = 0;
    std::uint64_t sequential_output_payload_bytes = 0;
    std::uint64_t positional_output_payload_bytes = 0;
    std::uint64_t positional_output_write_operations = 0;
    std::uint64_t positional_publication_read_bytes = 0;
    std::uint64_t positional_publication_read_operations = 0;
    std::uint64_t artifact_validation_bytes = 0;
    std::uint64_t peak_working_bytes = 0;

    bool operator==(
        const ProofOfPackingAssignmentArtifactReport &) const = default;
};

struct ProofOfPackingAssignmentArtifact {
    std::shared_ptr<const storage::NativeFieldArtifact> artifact;
    ProofOfPackingAssignmentArtifactReport report;
};

/// Exact completed v2 assignment size, without constructing its values.
std::uint64_t proof_of_packing_assignment_artifact_physical_bytes(
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &circuit_metadata);

inline constexpr std::string_view
    kProofOfPackingAssignmentPublicInputs = "public-inputs";
inline constexpr std::string_view
    kProofOfPackingAssignmentWitnessValues = "witness-values";

/// One stored run in the otherwise zero-padded Spartan witness half.
/// `stored_begin` addresses the compact `witness-values` artifact array;
/// `logical_begin` addresses the power-of-two witness polynomial.
struct ProofOfPackingWitnessStorageSegment {
    std::uint64_t logical_begin = 0;
    std::uint64_t stored_begin = 0;
    std::uint64_t element_count = 0;

    bool operator==(
        const ProofOfPackingWitnessStorageSegment &) const = default;
};

/// Canonical live support derived from the relation-bound plan and R1CS
/// metadata. Gaps between segments and the tail through `logical_elements`
/// are known zero and have no physical representation.
struct ProofOfPackingWitnessStorageLayout {
    std::uint64_t logical_elements = 0;
    std::uint64_t stored_elements = 0;
    std::vector<ProofOfPackingWitnessStorageSegment> segments;

    bool operator==(
        const ProofOfPackingWitnessStorageLayout &) const = default;
};

ProofOfPackingWitnessStorageLayout
proof_of_packing_witness_storage_layout(
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &circuit_metadata);

/// Actual artifact I/O needed to reconstruct a logical witness range.
/// Virtual zero coordinates contribute neither elements nor operations.
struct ProofOfPackingWitnessReadReport {
    std::uint64_t stored_elements = 0;
    std::uint64_t read_operations = 0;
    std::uint64_t seek_operations = 0;

    bool operator==(
        const ProofOfPackingWitnessReadReport &) const = default;
};

/// Random-access logical view of the padded Spartan witness half. The source
/// artifact stores only the canonical live support; `read_at` synthesizes all
/// structural and power-of-two padding as zero.
class ProofOfPackingWitnessReader {
  public:
    ProofOfPackingWitnessReader(
        const OuterRelationPlan &plan,
        const spartan::R1csMetadata &circuit_metadata,
        const storage::NativeFieldArtifact &artifact);
    ~ProofOfPackingWitnessReader();

    ProofOfPackingWitnessReader(
        const ProofOfPackingWitnessReader &) = delete;
    ProofOfPackingWitnessReader &operator=(
        const ProofOfPackingWitnessReader &) = delete;
    ProofOfPackingWitnessReader(
        ProofOfPackingWitnessReader &&) noexcept;
    ProofOfPackingWitnessReader &operator=(
        ProofOfPackingWitnessReader &&) noexcept;

    std::uint64_t size() const;
    std::uint64_t stored_size() const;
    const ProofOfPackingWitnessStorageLayout &layout() const;
    ProofOfPackingWitnessReadReport read_at(
        std::uint64_t logical_begin, std::span<Fq> output);

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// Bind the complete assignment layout to the relation, exact Spartan
/// circuit metadata, source assignment files, and ordered commitments.
Digest proof_of_packing_assignment_artifact_identity(
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &outer_assignment,
    std::span<const gkr::HashCommitCT> commitments);

/// Reopen and fully validate a complete assignment artifact. Its arrays are
/// `public-inputs` and compact `witness-values`. The latter contains exactly
/// the canonical live support of the power-of-two Spartan witness half.
std::shared_ptr<const storage::NativeFieldArtifact>
open_proof_of_packing_assignment_artifact(
    const std::filesystem::path &directory,
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &outer_assignment,
    std::span<const gkr::HashCommitCT> commitments);

/// Stream the canonical outer assignment into the structured proof relation.
/// One aligned ciphertext at a time is transposed into its canonical input
/// range and used to synthesize the setup-selected commitment advice. The full
/// resident R1CS assignment is never constructed. Only live witness values
/// are written; structural gaps and Spartan padding remain virtual. Any
/// failure restores the caller-owned destination to empty.
ProofOfPackingAssignmentArtifact
write_proof_of_packing_assignment_artifact(
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &outer_assignment,
    std::span<const gkr::HashCommitCT> commitments,
    ProofOfPackingAssignmentArtifactOptions options);

} // namespace laminate::packing

#endif // LAMINATE_PACKING_PROOF_R1CS_HPP
