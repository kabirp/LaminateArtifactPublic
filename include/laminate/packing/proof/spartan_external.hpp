#ifndef LAMINATE_PACKING_PROOF_SPARTAN_EXTERNAL_HPP
#define LAMINATE_PACKING_PROOF_SPARTAN_EXTERNAL_HPP

/// @file spartan_external.hpp
/// @brief Composed artifact-backed Spartan prover for transcript packing.

#include "laminate/packing/proof/matrix/products.hpp"
#include "laminate/packing/proof/r1cs.hpp"
#include "laminate/packing/proof/matrix/wiring.hpp"
#include "laminate/runtime_progress.hpp"
#include "laminate/spartan/basefold_pcs.hpp"
#include "laminate/spartan/spartan.hpp"
#include "laminate/spartan/wiring_artifact.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>

namespace laminate::packing {

namespace detail {
struct ProofOfPackingExternalSpartanAdmissionFactory;
}

/// Every caller-owned destination and hard resource authority used by one
/// external proof. No path is inferred. Assignment and matrix products are
/// constructed before Fiat--Shamir begins; later phase failures clean their
/// own scratch but require restarting from the preceding transcript state.
struct ProofOfPackingExternalSpartanOptions {
    /// Complete cap for persistent protocol inputs, every generated
    /// destination, and the largest simultaneously live phase scratch.
    /// This outer authority replaces the nested phase-local live caps and
    /// factored reservation; callers do not estimate those independently.
    std::uint64_t max_live_storage_bytes = 0;
    ProofOfPackingAssignmentArtifactOptions assignment;
    ProofOfPackingMatrixProductArtifactOptions matrix_products;
    spartan::BaseFoldExternalCommitOptions witness_commitment;
    spartan::ConstraintSumcheckArtifactOptions constraint_sumcheck;
    ProofOfPackingWiringArtifactOptions wiring_matrix;
    spartan::WiringSumcheckArtifactOptions wiring_sumcheck;
    spartan::FactoredMatrixExternalProvingOptions factored_evaluation;
    spartan::BaseFoldExternalOpeningOptions witness_opening;
};

/// Exact aggregate storage envelope admitted before Fiat--Shamir. Persistent
/// inputs are caller-owned and remain on disk; every generated artifact and
/// scratch root is retired before a successful return.
struct ProofOfPackingExternalSpartanStorageReport {
    std::uint64_t admitted_live_storage_bytes = 0;
    std::uint64_t outer_assignment_physical_bytes = 0;
    std::uint64_t factored_tensor_columns_physical_bytes = 0;
    std::uint64_t factored_tensor_columns_validation_bytes = 0;
    std::uint64_t factored_external_states_physical_bytes = 0;
    std::uint64_t factored_external_states_validation_bytes = 0;
    std::uint64_t preprocessing_validation_bytes = 0;
    std::uint64_t persistent_input_physical_bytes = 0;
    std::uint64_t assignment_physical_bytes = 0;
    std::uint64_t matrix_products_physical_bytes = 0;
    std::uint64_t witness_state_physical_bytes = 0;
    std::uint64_t wiring_matrix_physical_bytes = 0;
    std::uint64_t assignment_construction_peak_live_storage_bytes = 0;
    std::uint64_t witness_commitment_peak_live_storage_bytes = 0;
    std::uint64_t matrix_product_construction_peak_live_storage_bytes = 0;
    std::uint64_t pre_fiat_shamir_live_storage_bytes = 0;
    std::uint64_t constraint_check_peak_live_storage_bytes = 0;
    std::uint64_t wiring_construction_peak_live_storage_bytes = 0;
    std::uint64_t wiring_check_peak_live_storage_bytes = 0;
    std::uint64_t factored_evaluation_peak_live_storage_bytes = 0;
    std::uint64_t witness_opening_peak_live_storage_bytes = 0;
    std::uint64_t peak_live_storage_bytes = 0;

    bool operator==(
        const ProofOfPackingExternalSpartanStorageReport &) const = default;
};

/// Complete proof and exact phase reports. No generated artifact escapes this
/// one-shot lifecycle: products retire after ConstraintCheck, assignment and
/// wiring after WiringCheck, and the witness PCS state after its opening.
struct ProofOfPackingExternalSpartanResult {
    spartan::Proof proof;
    ProofOfPackingAssignmentArtifactReport assignment;
    ProofOfPackingMatrixProductArtifactReport matrix_products;
    spartan::BaseFoldExternalCommitReport witness_commitment;
    spartan::ConstraintSumcheckArtifactReport constraint_sumcheck;
    ProofOfPackingWiringArtifactReport wiring_matrix;
    spartan::WiringSumcheckArtifactReport wiring_sumcheck;
    spartan::FactoredMatrixExternalProvingReport factored_evaluation;
    spartan::BaseFoldExternalOpeningReport witness_opening;
    ProofOfPackingExternalSpartanStorageReport storage;
};

/// Move-only authorization for one complete external Spartan suffix. The
/// admission validates the compact key, all preprocessed factored states,
/// every path, and the aggregate storage envelope before the caller samples
/// the lazy-ternary challenges. It requires the expected outer-assignment
/// directory to remain empty until the prefix publishes that artifact.
class ProofOfPackingExternalSpartanAdmission {
  public:
    ~ProofOfPackingExternalSpartanAdmission();
    ProofOfPackingExternalSpartanAdmission(
        ProofOfPackingExternalSpartanAdmission &&) noexcept;
    ProofOfPackingExternalSpartanAdmission &operator=(
        ProofOfPackingExternalSpartanAdmission &&) noexcept;

    ProofOfPackingExternalSpartanAdmission(
        const ProofOfPackingExternalSpartanAdmission &) = delete;
    ProofOfPackingExternalSpartanAdmission &operator=(
        const ProofOfPackingExternalSpartanAdmission &) = delete;

    const ProofOfPackingExternalSpartanStorageReport &storage_report() const;

  private:
    struct Impl;
    explicit ProofOfPackingExternalSpartanAdmission(
        std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;

    friend ProofOfPackingExternalSpartanAdmission
    admit_proof_of_packing_spartan_external(
        const OuterRelationPlan &, const ProofOfPackingR1csLayout &,
        const spartan::ExternalProverKey &,
        const std::filesystem::path &,
        std::span<const gkr::HashCommitCT>,
        std::shared_ptr<const spartan::BaseFoldPcs>,
        ProofOfPackingExternalSpartanOptions);
    friend ProofOfPackingExternalSpartanAdmission
    admit_proof_of_packing_spartan_external_before_commitments(
        const OuterRelationPlan &, const ProofOfPackingR1csLayout &,
        const spartan::ExternalProverKey &,
        const std::filesystem::path &, std::size_t,
        std::shared_ptr<const spartan::BaseFoldPcs>,
        ProofOfPackingExternalSpartanOptions);
    friend ProofOfPackingExternalSpartanAdmission
    bind_proof_of_packing_spartan_external_commitments(
        ProofOfPackingExternalSpartanAdmission,
        std::span<const gkr::HashCommitCT>);
    friend ProofOfPackingExternalSpartanResult
    prove_proof_of_packing_spartan_external_admitted(
        ProofOfPackingExternalSpartanAdmission,
        const storage::NativeFieldArtifact &,
        PublicCoin &,
        const RuntimeProgressCallback &);
    friend ProofOfPackingExternalSpartanResult
    prove_proof_of_packing_spartan_external(
        const OuterRelationPlan &, const ProofOfPackingR1csLayout &,
        const spartan::ExternalProverKey &,
        const storage::NativeFieldArtifact &,
        std::span<const gkr::HashCommitCT>,
        const spartan::BaseFoldPcs &,
        ProofOfPackingExternalSpartanOptions, PublicCoin &,
        const RuntimeProgressCallback &);
    friend struct detail::ProofOfPackingExternalSpartanAdmissionFactory;
};

/// Admit and scan the complete suffix before its future outer-assignment
/// artifact exists. `expected_outer_assignment_directory` must be an existing
/// real, empty directory and is bound into the move-only admission. The PCS
/// is retained by shared ownership so execution cannot substitute another
/// instance after Fiat--Shamir begins.
ProofOfPackingExternalSpartanAdmission
admit_proof_of_packing_spartan_external(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::ExternalProverKey &key,
    const std::filesystem::path &expected_outer_assignment_directory,
    std::span<const gkr::HashCommitCT> commitments,
    std::shared_ptr<const spartan::BaseFoldPcs> pcs,
    ProofOfPackingExternalSpartanOptions options);

/// Perform the expensive immutable-state scans and exact resource/root
/// admission before committed GKR exists. Only the exact future commitment
/// count is needed; no transcript is observed.
ProofOfPackingExternalSpartanAdmission
admit_proof_of_packing_spartan_external_before_commitments(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::ExternalProverKey &key,
    const std::filesystem::path &expected_outer_assignment_directory,
    std::size_t expected_commitment_count,
    std::shared_ptr<const spartan::BaseFoldPcs> pcs,
    ProofOfPackingExternalSpartanOptions options);

/// Bind the collector-certified commitments after GKR, without rescanning
/// immutable preprocessing. Every admitted root is revalidated first. A
/// failure consumes the admission and occurs before any packing challenge.
ProofOfPackingExternalSpartanAdmission
bind_proof_of_packing_spartan_external_commitments(
    ProofOfPackingExternalSpartanAdmission admission,
    std::span<const gkr::HashCommitCT> commitments);

/// Consume a prior admission after the prefix publishes the exact canonical
/// outer assignment. No preprocessed factored state or storage authority is
/// rescanned or re-admitted.
ProofOfPackingExternalSpartanResult
prove_proof_of_packing_spartan_external_admitted(
    ProofOfPackingExternalSpartanAdmission admission,
    const storage::NativeFieldArtifact &outer_assignment,
    PublicCoin &public_coin,
    const RuntimeProgressCallback &progress = {});

/// Produce the selected committed-factored Spartan proof without building a
/// padded assignment, expanded R1CS matrices, matrix-product vectors, or PCS
/// codewords in resident memory. The compact v2 assignment remains the one
/// witness source: virtual zero gaps are synthesized independently by
/// WiringCheck and the witness BaseFold commitment.
ProofOfPackingExternalSpartanResult prove_proof_of_packing_spartan_external(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::ExternalProverKey &key,
    const storage::NativeFieldArtifact &outer_assignment,
    std::span<const gkr::HashCommitCT> commitments,
    const spartan::BaseFoldPcs &pcs,
    ProofOfPackingExternalSpartanOptions options,
    PublicCoin &public_coin,
    const RuntimeProgressCallback &progress = {});

} // namespace laminate::packing

#endif // LAMINATE_PACKING_PROOF_SPARTAN_EXTERNAL_HPP
