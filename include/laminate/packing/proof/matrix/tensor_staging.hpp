#ifndef LAMINATE_PACKING_PROOF_TENSOR_STAGING_HPP
#define LAMINATE_PACKING_PROOF_TENSOR_STAGING_HPP

/// @file tensor_staging.hpp
/// @brief Bounded construction of fixed packing-coefficient tensors.

#include "laminate/packing/proof/matrix/oracle.hpp"
#include "laminate/packing/proof/matrix/metadata.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>

namespace laminate::packing {

/// Formula-derived storage and controlled working-memory requirements.
///
/// The working-byte ledger counts the live logical payloads returned by the
/// two public encoders, the signed decomposition, and the bounded Fq output
/// buffer. It excludes the caller-owned metadata/operator, allocator
/// metadata, vector spare capacity, and scratch internal to an encoder call.
struct ProofOfPackingTensorStagingPlan {
    PackingTensorGeometry geometry;
    std::uint64_t array_count = 0;
    std::uint64_t artifact_payload_bytes = 0;
    std::uint64_t artifact_physical_bytes = 0;
    std::size_t block_elements = 0;
    std::uint64_t output_buffer_bytes = 0;
    std::uint64_t mask_and_centered_bytes = 0;
    std::uint64_t centered_and_digit_masks_bytes = 0;
    std::uint64_t selected_digit_and_native_bytes = 0;
    std::uint64_t peak_working_bytes = 0;
    std::uint64_t encoder_invocations = 0;
    std::uint64_t live_coordinates = 0;
    std::uint64_t padded_zero_coordinates = 0;
    std::uint64_t append_operations = 0;

    bool operator==(const ProofOfPackingTensorStagingPlan &) const =
        default;
};

/// Caller-owned destination and hard setup-time limits. The destination must
/// already exist as an empty, real directory. `max_working_bytes` applies to
/// the controlled payload described above. `block_elements` is normalized to
/// at most one ring polynomial in the returned plan.
struct ProofOfPackingTensorStagingOptions {
    std::filesystem::path directory;
    storage::NativeFieldArtifactOptions storage_limits;
    std::uint64_t max_working_bytes = 0;
    std::size_t block_elements = 0;
};

struct ProofOfPackingTensorStagingReport {
    ProofOfPackingTensorStagingPlan plan;
    std::uint64_t centered_masks_encoded = 0;
    std::uint64_t signed_digit_masks_derived = 0;
    std::uint64_t native_digit_polynomials_encoded = 0;
    std::uint64_t live_coordinates_written = 0;
    std::uint64_t padded_zero_coordinates_written = 0;
    std::uint64_t append_operations = 0;
    std::uint64_t artifact_physical_bytes = 0;
    std::uint64_t artifact_validation_bytes = 0;
};

struct ProofOfPackingTensorStaging {
    std::shared_ptr<const spartan::FactoredMatrixStructure> structure;
    std::shared_ptr<const storage::NativeFieldArtifact> artifact;
    ProofOfPackingTensorStagingReport report;
};

/// Derive exact tensor geometry, artifact bytes, encoder work, and the
/// controlled memory peak without invoking either encoder or touching disk.
/// The explicit operator and radix must equal the formula-derived structured
/// metadata; this prevents setup from committing coefficients for a different
/// packing relation under the metadata's circuit identity.
ProofOfPackingTensorStagingPlan plan_proof_of_packing_tensor_staging(
    const ProofOfPackingStructuredMetadata &metadata,
    const PackingLinearOperator &packing_operator,
    const BalancedRadix &radix, std::size_t block_elements);

/// Stream the exact fixed packing tensors into a factored staging artifact.
///
/// Arrays have the same tensor-major, digit-major, owner-major, NTT-coordinate
/// order as `compile_packing_tensors`. Each array is generated separately;
/// owners beyond the live prefix are appended as public zero. Complete
/// storage, free-space, and controlled-memory admission occurs before the
/// first encoder call and before any file is created. Any later exception
/// restores the caller-owned destination to empty.
ProofOfPackingTensorStaging write_proof_of_packing_tensor_staging(
    const ProofOfPackingStructuredMetadata &metadata,
    const PackingLinearOperator &packing_operator,
    ProofOfPackingR1csEncoders encoders, const BalancedRadix &radix,
    ProofOfPackingTensorStagingOptions options);

} // namespace laminate::packing

#endif // LAMINATE_PACKING_PROOF_TENSOR_STAGING_HPP
