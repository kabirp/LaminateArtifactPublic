#ifndef LAMINATE_PACKING_PROOF_MATRIX_PRODUCTS_HPP
#define LAMINATE_PACKING_PROOF_MATRIX_PRODUCTS_HPP

/// @file products.hpp
/// @brief Bounded-memory A z, B z, and C z products for packing Spartan.

#include "laminate/packing/proof/matrix/oracle.hpp"
#include "laminate/storage/native_field_artifact.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>

namespace laminate::packing {

/// Caller-owned destination and hard resource limits for the three Spartan
/// matrix products. The destination must be an existing empty private
/// directory. `max_working_field_bytes` covers the N-coordinate fixed-packing
/// accumulator and all live Fq I/O/cache buffers. Sparse row descriptors,
/// reader objects, fixed-size Poseidon state, and allocator metadata are not
/// included in that deterministic field-payload bound.
struct ProofOfPackingMatrixProductArtifactOptions {
    std::filesystem::path directory;
    storage::NativeFieldArtifactOptions storage_limits;
    std::uint64_t max_working_field_bytes = 0;
    std::size_t block_elements = 0;
};

struct ProofOfPackingMatrixProductArtifactPlan {
    std::uint64_t physical_bytes = 0;
    std::uint64_t retained_accumulator_bytes = 0;
    std::uint64_t minimum_working_field_bytes = 0;
    std::size_t effective_block_elements = 0;
    std::uint64_t peak_working_field_bytes = 0;

    bool operator==(
        const ProofOfPackingMatrixProductArtifactPlan &) const = default;
};

struct ProofOfPackingMatrixProductIoReport {
    std::uint64_t payload_bytes = 0;
    std::uint64_t read_operations = 0;
    std::uint64_t seek_operations = 0;

    bool operator==(
        const ProofOfPackingMatrixProductIoReport &) const = default;
};

/// Exact logical I/O and storage ledger for one completed product artifact.
struct ProofOfPackingMatrixProductArtifactReport {
    std::uint64_t stored_constraint_elements = 0;
    std::uint64_t logical_padded_constraint_elements = 0;
    std::uint64_t ciphertext_commitment_rows = 0;
    std::uint64_t ciphertext_output_rows = 0;
    std::uint64_t regular_outer_rows = 0;
    std::uint64_t fixed_packing_rows = 0;
    std::uint64_t structural_zero_rows_per_matrix = 0;
    std::uint64_t virtual_zero_rows_per_matrix = 0;
    std::uint64_t product_payload_bytes = 0;
    std::uint64_t physical_bytes = 0;
    std::uint64_t source_artifact_physical_bytes = 0;
    std::uint64_t source_artifact_validation_bytes = 0;
    std::uint64_t output_artifact_validation_bytes = 0;
    std::uint64_t sequential_output_payload_bytes = 0;
    std::uint64_t sequential_output_operations = 0;
    ProofOfPackingMatrixProductIoReport complete_assignment_io;
    ProofOfPackingMatrixProductIoReport outer_assignment_io;
    ProofOfPackingMatrixProductIoReport factored_tensor_io;
    std::uint64_t revealed_test_product_elements_read = 0;
    std::uint64_t revealed_test_product_payload_bytes = 0;
    std::uint64_t revealed_test_product_read_operations = 0;
    std::uint64_t revealed_test_product_seek_operations = 0;
    std::uint64_t fixed_owner_component_passes = 0;
    std::uint64_t maximum_regular_row_terms = 0;
    std::uint64_t fixed_accumulator_elements = 0;
    std::size_t effective_block_elements = 0;
    std::uint64_t peak_working_field_bytes = 0;

    bool operator==(
        const ProofOfPackingMatrixProductArtifactReport &) const = default;
};

struct ProofOfPackingMatrixProductArtifact {
    std::shared_ptr<const storage::NativeFieldArtifact> artifact;
    ProofOfPackingMatrixProductArtifactReport report;
};

/// Exact completed Az/Bz/Cz active-prefix artifact size.
std::uint64_t proof_of_packing_matrix_product_artifact_physical_bytes(
    const spartan::R1csMetadata &circuit_metadata);

ProofOfPackingMatrixProductArtifactPlan
plan_proof_of_packing_matrix_product_artifact(
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &circuit_metadata,
    std::uint64_t max_working_field_bytes,
    std::size_t requested_block_elements);

/// Bind a product artifact to the exact circuit metadata, compact layout,
/// complete and outer assignments, factored commitment, and raw tensor-column
/// artifact. Source file digests are included, not just their directories.
Digest proof_of_packing_matrix_product_artifact_identity(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &complete_assignment,
    const storage::NativeFieldArtifact &outer_assignment,
    const spartan::FactoredMatrixCommitment &factored_commitment,
    const storage::NativeFieldArtifact &factored_tensor_columns);

/// Reopen `az`, `bz`, and `cz`, each a canonical Fq array of exactly the
/// active matrix extent `shape.constraints`. Spartan's remaining
/// `padded_constraints - shape.constraints` rows are known zero and stay
/// virtual.
std::shared_ptr<const storage::NativeFieldArtifact>
open_proof_of_packing_matrix_product_artifact(
    const std::filesystem::path &directory,
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &complete_assignment,
    const storage::NativeFieldArtifact &outer_assignment,
    const spartan::FactoredMatrixCommitment &factored_commitment,
    const storage::NativeFieldArtifact &factored_tensor_columns);

/// Stream the canonical active-prefix matrix products without expanding A,
/// B, or C and without materializing z or any C-element product vector in
/// RAM. Power-of-two row padding remains virtual.
/// Poseidon uses the local permutation template over transposed segments;
/// regular outer rows use compact row descriptors; fixed packing A uses the
/// preprocessed tensor columns and one N-coordinate accumulator. Any failure
/// restores the caller-owned destination to empty and leaves every source
/// artifact untouched.
ProofOfPackingMatrixProductArtifact
write_proof_of_packing_matrix_product_artifact(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &complete_assignment,
    const storage::NativeFieldArtifact &outer_assignment,
    const spartan::FactoredMatrixProverKey &factored_preprocessing,
    ProofOfPackingMatrixProductArtifactOptions options);

/// Admission-only counterpart for source handles whose complete bytes and
/// identities were validated by the enclosing one-shot lifecycle. Generated
/// output is still validated before publication; existing source artifacts
/// are not reopened or rescanned.
ProofOfPackingMatrixProductArtifact
write_proof_of_packing_matrix_product_artifact_admitted_sources(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &complete_assignment,
    const storage::NativeFieldArtifact &outer_assignment,
    const spartan::FactoredMatrixProverKey &factored_preprocessing,
    ProofOfPackingMatrixProductArtifactOptions options);

} // namespace laminate::packing

#endif // LAMINATE_PACKING_PROOF_MATRIX_PRODUCTS_HPP
