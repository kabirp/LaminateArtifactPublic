#ifndef LAMINATE_PROTOCOL_PACKED_EXTERNAL_TRANSCRIPT_PACKING_HPP
#define LAMINATE_PROTOCOL_PACKED_EXTERNAL_TRANSCRIPT_PACKING_HPP

/// @file transcript_packing.hpp
/// @brief One-shot external-memory transcript-packing prover.

#include "laminate/packing/proof/spartan_external.hpp"
#include "laminate/packing/proof/matrix/metadata.hpp"
#include "laminate/protocol/detail/packing/aligned_commitments.hpp"
#include "laminate/protocol/packed/setup.hpp"
#include "laminate/protocol/packed/proof.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace laminate::protocol {

namespace detail {
struct TranscriptPackingExternalProverInputAccess;
struct TranscriptPackingExternalAdmissionAccess;
struct TranscriptPackingExternalReferenceSetupAccess;
}

/// Immutable preprocessing certificate consumed by the external online
/// prover. Construction validates the immutable relation and keys once.
/// Each request separately checks its variant, moved input geometry, artifact
/// identities, and resource limits.
class TranscriptPackingExternalProverSetup {
  public:
    PackingGkrVariant variant() const noexcept { return variant_; }
    std::size_t bhip_round_count() const noexcept {
        return bhip_round_count_;
    }
    const packing::ProofOfPackingStructuredMetadata &relation() const {
        return relation_;
    }
    const std::shared_ptr<const spartan::BaseFoldPcs> &basefold_pcs() const {
        return basefold_pcs_;
    }
    const spartan::BaseFoldPcsParameters &basefold_parameters() const {
        return basefold_pcs_->parameters();
    }
    const spartan::ExternalProverKey &spartan_key() const {
        return spartan_key_;
    }

  private:
    TranscriptPackingExternalProverSetup(
        PackingGkrVariant variant, std::size_t bhip_round_count,
        packing::ProofOfPackingStructuredMetadata relation,
        std::shared_ptr<const spartan::BaseFoldPcs> basefold_pcs,
        spartan::ExternalProverKey spartan_key)
        : variant_(variant), bhip_round_count_(bhip_round_count),
          relation_(std::move(relation)),
          basefold_pcs_(std::move(basefold_pcs)),
          spartan_key_(std::move(spartan_key)) {}

    friend TranscriptPackingExternalProverSetup
    make_transcript_packing_external_prover_setup(
        PackingGkrVariant, std::size_t,
        packing::ProofOfPackingStructuredMetadata,
        std::shared_ptr<const spartan::BaseFoldPcs>,
        spartan::ExternalProverKey);
    friend struct detail::TranscriptPackingExternalReferenceSetupAccess;

    PackingGkrVariant variant_ = PackingGkrVariant::Folded;
    std::size_t bhip_round_count_ = 0;
    packing::ProofOfPackingStructuredMetadata relation_;
    std::shared_ptr<const spartan::BaseFoldPcs> basefold_pcs_;
    spartan::ExternalProverKey spartan_key_;
};

/// Certify compact, artifact-backed preprocessing before it is persisted or
/// admitted to an online request. The key must use the formula-derived
/// semantic circuit identity and the exact coefficient-free tensor mapping.
TranscriptPackingExternalProverSetup
make_transcript_packing_external_prover_setup(
    PackingGkrVariant variant, std::size_t bhip_round_count,
    packing::ProofOfPackingStructuredMetadata relation,
    std::shared_ptr<const spartan::BaseFoldPcs> basefold_pcs,
    spartan::ExternalProverKey spartan_key);

/// Move-only, collector-certified ownership handoff from committed GKR into
/// transcript packing. Aligned values and commitments cannot be substituted
/// independently. The wrapper destroys them and all public-coordinate
/// sidecars immediately after publishing the outer assignment.
template <ProofOfPackingBackend Backend>
class TranscriptPackingExternalProverInput {
  public:
    explicit TranscriptPackingExternalProverInput(
        detail::CollectedAlignedCommitments<Backend> collected)
        : aligned_(std::move(collected.aligned_)),
          commitments_(std::move(collected.commitments_)) {}

    TranscriptPackingExternalProverInput(
        TranscriptPackingExternalProverInput &&) noexcept = default;
    TranscriptPackingExternalProverInput &operator=(
        TranscriptPackingExternalProverInput &&) noexcept = default;
    TranscriptPackingExternalProverInput(
        const TranscriptPackingExternalProverInput &) = delete;
    TranscriptPackingExternalProverInput &operator=(
        const TranscriptPackingExternalProverInput &) = delete;

  private:
    friend struct detail::TranscriptPackingExternalProverInputAccess;

    packing::NormalizedAlignedTranscript<Backend> aligned_;
    std::vector<gkr::HashCommitCT> commitments_;
};

/// Every caller-owned output and scratch authority. No directory is derived
/// from another path. `outer_assignment.directory` must also be disjoint from
/// every mutable or immutable directory admitted by `spartan`.
struct TranscriptPackingExternalProverOptions {
    packing::OuterRelationAssignmentArtifactOptions outer_assignment;
    packing::ProofOfPackingExternalSpartanOptions spartan;
};

/// Exact prefix storage admitted before the first transcript challenge.
/// Artifact bytes and resident field-buffer bytes are reported separately;
/// the latter is controlled directly by the caller's block and memory caps.
struct TranscriptPackingExternalPrefixStorageReport {
    std::uint64_t outer_assignment_physical_bytes = 0;
    std::uint64_t outer_assignment_peak_working_field_bytes = 0;
    std::uint64_t
        outer_assignment_construction_peak_live_storage_bytes = 0;

    bool operator==(
        const TranscriptPackingExternalPrefixStorageReport &) const =
        default;
};

/// Complete no-write admission for one future external packing proof. This
/// performs the same root, preprocessing, quota, working-memory, and free-
/// space checks as proving, but does not inspect or advance a transcript.
struct TranscriptPackingExternalPreflightReport {
    TranscriptPackingExternalPrefixStorageReport prefix_storage;
    packing::ProofOfPackingExternalSpartanStorageReport spartan_storage;

    bool operator==(
        const TranscriptPackingExternalPreflightReport &) const = default;
};

/// Move-only authorization produced before irreversible GKR. It retains the
/// one expensive immutable-preprocessing scan and every exact storage/root
/// admission until collector-certified commitments become available.
/// `setup` must outlive this token.
class TranscriptPackingExternalAdmission {
  public:
    TranscriptPackingExternalAdmission(
        TranscriptPackingExternalAdmission &&other) noexcept
        : expected_variant_(other.expected_variant_),
          setup_(std::exchange(other.setup_, nullptr)),
          outer_assignment_(std::move(other.outer_assignment_)),
          mutable_roots_(std::move(other.mutable_roots_)),
          prefix_storage_(std::move(other.prefix_storage_)),
          suffix_(std::move(other.suffix_)) {}
    TranscriptPackingExternalAdmission &operator=(
        TranscriptPackingExternalAdmission &&other) noexcept {
        if (this != &other) {
            expected_variant_ = other.expected_variant_;
            setup_ = std::exchange(other.setup_, nullptr);
            outer_assignment_ = std::move(other.outer_assignment_);
            mutable_roots_ = std::move(other.mutable_roots_);
            prefix_storage_ = std::move(other.prefix_storage_);
            suffix_ = std::move(other.suffix_);
        }
        return *this;
    }
    TranscriptPackingExternalAdmission(
        const TranscriptPackingExternalAdmission &) = delete;
    TranscriptPackingExternalAdmission &operator=(
        const TranscriptPackingExternalAdmission &) = delete;

    TranscriptPackingExternalPreflightReport report() const {
        return TranscriptPackingExternalPreflightReport{
            .prefix_storage = prefix_storage_,
            .spartan_storage = suffix_.storage_report(),
        };
    }
    bool matches(
        PackingGkrVariant expected_variant,
        const TranscriptPackingExternalProverSetup &setup) const noexcept {
        return expected_variant_ == expected_variant && setup_ == &setup;
    }
    std::span<const std::filesystem::path> mutable_roots() const noexcept {
        return mutable_roots_;
    }

  private:
    TranscriptPackingExternalAdmission(
        PackingGkrVariant expected_variant,
        const TranscriptPackingExternalProverSetup *setup,
        packing::OuterRelationAssignmentArtifactOptions outer_assignment,
        std::vector<std::filesystem::path> mutable_roots,
        TranscriptPackingExternalPrefixStorageReport prefix_storage,
        packing::ProofOfPackingExternalSpartanAdmission suffix)
        : expected_variant_(expected_variant), setup_(setup),
          outer_assignment_(std::move(outer_assignment)),
          mutable_roots_(std::move(mutable_roots)),
          prefix_storage_(std::move(prefix_storage)),
          suffix_(std::move(suffix)) {}

    friend TranscriptPackingExternalAdmission
    admit_transcript_packing_external(
        PackingGkrVariant,
        const TranscriptPackingExternalProverSetup &,
        TranscriptPackingExternalProverOptions);
    friend struct detail::TranscriptPackingExternalAdmissionAccess;

    PackingGkrVariant expected_variant_ = PackingGkrVariant::Folded;
    const TranscriptPackingExternalProverSetup *setup_ = nullptr;
    packing::OuterRelationAssignmentArtifactOptions outer_assignment_;
    std::vector<std::filesystem::path> mutable_roots_;
    TranscriptPackingExternalPrefixStorageReport prefix_storage_;
    packing::ProofOfPackingExternalSpartanAdmission suffix_;
};

/// Exact reports from the streamed prefix and every external Spartan phase.
/// Generated artifacts are absent on return; byte counts describe their
/// completed, pre-retirement representations and admitted phase peaks.
struct TranscriptPackingExternalProverReport {
    TranscriptPackingExternalPrefixStorageReport prefix_storage;
    packing::OuterRelationAssignmentArtifactReport outer_assignment;
    packing::ProofOfPackingAssignmentArtifactReport spartan_assignment;
    packing::ProofOfPackingMatrixProductArtifactReport matrix_products;
    spartan::BaseFoldExternalCommitReport witness_commitment;
    spartan::ConstraintSumcheckArtifactReport constraint_sumcheck;
    packing::ProofOfPackingWiringArtifactReport wiring_matrix;
    spartan::WiringSumcheckArtifactReport wiring_sumcheck;
    spartan::FactoredMatrixExternalProvingReport factored_evaluation;
    spartan::BaseFoldExternalOpeningReport witness_opening;
    packing::ProofOfPackingExternalSpartanStorageReport storage;
};

template <packing::CoefficientWellFormednessBackend Backend>
struct TranscriptPackingExternalProverResult {
    TranscriptPackingProof<Backend> proof;
    TranscriptPackingExternalProverReport report;
};

/// Scan and admit the exact future prefix/suffix without writing an artifact
/// or observing a public coin. The returned token carries that admission
/// across irreversible GKR, avoiding a second preprocessing scan.
TranscriptPackingExternalAdmission
admit_transcript_packing_external(
    PackingGkrVariant expected_variant,
    const TranscriptPackingExternalProverSetup &setup,
    TranscriptPackingExternalProverOptions options);

/// Late-bind the collector-certified commitments, stream the prefix, and
/// consume the prior pre-GKR admission. Root revalidation and commitment
/// binding happen before the first packing challenge.
template <ProofOfPackingBackend Backend>
TranscriptPackingExternalProverResult<Backend>
prove_transcript_packing_external_admitted(
    const typename Backend::EvalContext &eval,
    const TranscriptPackingExternalProverSetup &setup,
    TranscriptPackingExternalAdmission admission,
    TranscriptPackingExternalProverInput<Backend> input,
    Transcript &packing_transcript,
    const RuntimeProgressCallback &progress = {});

/// Admit the complete artifact-backed suffix before sampling any packing
/// challenge, stream the lazy outer assignment, then consume the admission.
/// `input` is consumed even on failure. The explicit outer directory and all
/// suffix output/scratch directories are empty after success or failure.
template <ProofOfPackingBackend Backend>
TranscriptPackingExternalProverResult<Backend>
prove_transcript_packing_external(
    const typename Backend::EvalContext &eval,
    PackingGkrVariant expected_variant,
    const TranscriptPackingExternalProverSetup &setup,
    TranscriptPackingExternalProverInput<Backend> input,
    Transcript &packing_transcript,
    TranscriptPackingExternalProverOptions options,
    const RuntimeProgressCallback &progress = {});

} // namespace laminate::protocol

#include "laminate/protocol/packed/external/detail/transcript_packing_impl.hpp"

#endif // LAMINATE_PROTOCOL_PACKED_EXTERNAL_TRANSCRIPT_PACKING_HPP
