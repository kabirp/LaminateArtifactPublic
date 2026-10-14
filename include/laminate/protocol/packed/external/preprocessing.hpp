#ifndef LAMINATE_PROTOCOL_PACKED_EXTERNAL_PREPROCESSING_HPP
#define LAMINATE_PROTOCOL_PACKED_EXTERNAL_PREPROCESSING_HPP

/// @file preprocessing.hpp
/// @brief Formula-only, bounded preprocessing for external transcript packing.

#include "laminate/packing/proof/matrix/tensor_staging.hpp"
#include "laminate/protocol/packed/external/transcript_packing.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

namespace laminate::protocol {

/// Public relation and streaming schedule fixed before setup starts.
///
/// All block sizes are explicit. They control bounded setup buffers; changing
/// them does not change the committed relation or the resulting verifier key.
struct TranscriptPackingExternalPreprocessingSpecification {
    PackingGkrVariant variant = PackingGkrVariant::Folded;
    gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy =
        gkr::CiphertextCommitmentPolicy::poseidon_v2();
    std::size_t ring_degree = 0;
    std::size_t bhip_round_count = 0;
    packing::LazyTernaryParameters parameters;
    spartan::BaseFoldPcsParameters basefold_parameters;
    std::size_t staging_block_elements = 0;
    std::size_t canonical_copy_block_elements = 0;
    std::size_t basefold_block_elements = 0;
    ConservativePackedProofIngressPolicy proof_ingress_policy =
        ConservativePackedProofIngressPolicy::VariantDefault;
};

/// Complete setup plan derived without encoders or filesystem access.
///
/// The plan contains only compact relation geometry and exact artifact
/// formulas. In particular, constructing it cannot create an expanded R1CS,
/// a native packing-operator coefficient table, a coefficient tensor, or a
/// resident PCS state.
struct TranscriptPackingExternalPreprocessingPlan {
    PackingGkrVariant variant = PackingGkrVariant::Folded;
    std::size_t bhip_round_count = 0;
    packing::ProofOfPackingStructuredMetadata relation;
    packing::ProofOfPackingTensorStagingPlan staging;
    spartan::FactoredMatrixExternalPreprocessingPlan factored;
    std::uint64_t peak_working_bytes = 0;
};

/// Derive the exact relation, tensor geometry, BaseFold state sizes, and
/// phase-local setup peaks. This function performs no encoding and no I/O.
TranscriptPackingExternalPreprocessingPlan
plan_transcript_packing_external_preprocessing(
    const TranscriptPackingExternalPreprocessingSpecification &specification);

/// One explicit destination/scratch pair per committed coefficient tensor.
struct TranscriptPackingExternalTensorResources {
    std::filesystem::path state_directory;
    std::filesystem::path scratch_directory;
};

/// Caller-owned setup namespaces. Every path must already name a distinct,
/// empty, real directory. No path is inferred from another path.
struct TranscriptPackingExternalPreprocessingResources {
    std::filesystem::path staging_directory;
    std::filesystem::path canonical_tensor_directory;
    std::filesystem::path staging_quarantine_directory;
    std::vector<TranscriptPackingExternalTensorResources> tensors;
};

/// Hard limits for one BaseFold tensor commitment.
struct TranscriptPackingExternalTensorLimits {
    std::uint64_t max_final_physical_bytes = 0;
    std::uint64_t max_scratch_physical_bytes = 0;
    std::uint64_t min_free_bytes = 0;
    std::uint64_t max_working_field_bytes = 0;
};

/// Hard setup limits. Cap-minus-one failures are rejected during the common
/// preflight, before either public encoder is called and before a file is
/// created. The live-storage cap covers the complete phase-local plan rather
/// than a sum of disjoint setup phases.
struct TranscriptPackingExternalPreprocessingLimits {
    storage::NativeFieldArtifactOptions staging_artifact;
    std::uint64_t max_staging_working_bytes = 0;
    storage::NativeFieldArtifactOptions canonical_tensor_artifact;
    std::uint64_t max_live_physical_bytes = 0;
    std::uint64_t max_copy_working_field_bytes = 0;
    std::vector<TranscriptPackingExternalTensorLimits> tensors;
};

/// Exact reports from both streamed setup layers and staging retirement.
struct TranscriptPackingExternalPreprocessingReport {
    TranscriptPackingExternalPreprocessingPlan plan;
    packing::ProofOfPackingTensorStagingReport staging;
    spartan::FactoredMatrixExternalPreprocessingReport factored;
    std::uint64_t retired_staging_physical_bytes = 0;
    std::uint64_t final_persistent_physical_bytes = 0;
};

/// Certified common Folded/Laned setup result. The producer and verifier
/// projections retain the same variant and relation identity. The producer
/// key contains only compact formula metadata, canonical tensor columns, and
/// external BaseFold opening states.
struct TranscriptPackingExternalPreprocessing {
    TranscriptPackingExternalProverSetup prover;
    TranscriptPackingSpartanVerifierSetup verifier;
    TranscriptPackingExternalPreprocessingReport report;
};

/// Produce compact external transcript-packing preprocessing.
///
/// Formula, path, quota, free-space, and controlled-working-memory admission
/// completes before `encoders` is invoked. On success, only the canonical
/// tensor artifact and the external BaseFold states remain. Staging is moved
/// into the explicit quarantine, rebound to its expected identity, deleted,
/// and its caller-owned directory is restored empty. Every staging, scratch,
/// and quarantine root is empty on success; all roots are empty on failure.
/// Every root is an exclusively owned, disposable setup namespace and must
/// not be renamed, replaced, or mutated concurrently.
/// Persistent tensor/state destinations must already be their final paths:
/// the returned prover key retains those artifact locations and must not be
/// used after either destination is moved. A persistent role setup should
/// write directly into its fixed artifact tree, publish that tree manifest
/// last, discard this live result, and reopen it from the authenticated tree.
TranscriptPackingExternalPreprocessing
preprocess_transcript_packing_external(
    const TranscriptPackingExternalPreprocessingSpecification &specification,
    packing::ProofOfPackingR1csEncoders encoders,
    TranscriptPackingExternalPreprocessingResources resources,
    TranscriptPackingExternalPreprocessingLimits limits);

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_EXTERNAL_PREPROCESSING_HPP
