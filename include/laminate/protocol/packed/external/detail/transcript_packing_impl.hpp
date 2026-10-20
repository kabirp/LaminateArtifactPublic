#ifndef LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_TRANSCRIPT_PACKING_IMPL_HPP
#define LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_TRANSCRIPT_PACKING_IMPL_HPP

/// @file transcript_packing_impl.hpp
/// @brief Template implementation of the external packing prover lifecycle.

#include "laminate/protocol/detail/packing/resident_transcript_packing.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace laminate::protocol::detail {

struct TranscriptPackingExternalProverInputAccess {
    template <ProofOfPackingBackend Backend>
    static packing::NormalizedAlignedTranscript<Backend> &aligned(
        TranscriptPackingExternalProverInput<Backend> &input) {
        return input.aligned_;
    }

    template <ProofOfPackingBackend Backend>
    static std::vector<gkr::HashCommitCT> &commitments(
        TranscriptPackingExternalProverInput<Backend> &input) {
        return input.commitments_;
    }

    template <ProofOfPackingBackend Backend>
    static void retire(
        TranscriptPackingExternalProverInput<Backend> &input) {
        packing::NormalizedAlignedTranscript<Backend> empty_aligned;
        std::vector<gkr::HashCommitCT> empty_commitments;
        using std::swap;
        swap(input.aligned_, empty_aligned);
        swap(input.commitments_, empty_commitments);
    }
};

struct ConsumedTranscriptPackingExternalAdmission {
    PackingGkrVariant expected_variant = PackingGkrVariant::Folded;
    packing::OuterRelationAssignmentArtifactOptions outer_assignment;
    TranscriptPackingExternalPrefixStorageReport prefix_storage;
    packing::ProofOfPackingExternalSpartanAdmission suffix;
};

struct TranscriptPackingExternalAdmissionAccess {
    static ConsumedTranscriptPackingExternalAdmission take(
        TranscriptPackingExternalAdmission admission,
        const TranscriptPackingExternalProverSetup &setup) {
        if (admission.setup_ == nullptr || admission.setup_ != &setup) {
            throw std::invalid_argument(
                "external transcript-packing admission was bound to a "
                "different immutable setup");
        }
        return ConsumedTranscriptPackingExternalAdmission{
            .expected_variant = admission.expected_variant_,
            .outer_assignment =
                std::move(admission.outer_assignment_),
            .prefix_storage = std::move(admission.prefix_storage_),
            .suffix = std::move(admission.suffix_),
        };
    }
};

namespace external_packing_detail {

/// Prefix-owned cleanup for the compact outer assignment. The external
/// Spartan admission intentionally treats this directory as an immutable
/// input and therefore never retires it.
class OuterAssignmentRootGuard {
  public:
    explicit OuterAssignmentRootGuard(
        const std::filesystem::path &directory) {
        const std::filesystem::file_status status =
            std::filesystem::symlink_status(directory);
        if (!std::filesystem::is_directory(status) ||
            std::filesystem::is_symlink(status) ||
            !std::filesystem::is_empty(directory)) {
            throw std::invalid_argument(
                "external transcript-packing outer-assignment root must "
                "be an empty real directory");
        }
        directory_ = std::filesystem::canonical(directory);
#ifndef _WIN32
        struct stat identity {};
        if (::lstat(directory_.c_str(), &identity) != 0 ||
            !S_ISDIR(identity.st_mode) || S_ISLNK(identity.st_mode)) {
            throw std::filesystem::filesystem_error(
                "failed to bind external transcript-packing outer root",
                directory_, std::error_code(errno, std::generic_category()));
        }
        device_ = static_cast<std::uintmax_t>(identity.st_dev);
        inode_ = static_cast<std::uintmax_t>(identity.st_ino);
#endif
    }

    OuterAssignmentRootGuard(const OuterAssignmentRootGuard &) = delete;
    OuterAssignmentRootGuard &operator=(
        const OuterAssignmentRootGuard &) = delete;

    ~OuterAssignmentRootGuard() { clear_noexcept(); }

    void retire() {
        clear_checked();
        armed_ = false;
    }

  private:
    void validate_root() const {
#ifdef _WIN32
        const std::filesystem::file_status status =
            std::filesystem::symlink_status(directory_);
        if (!std::filesystem::is_directory(status) ||
            std::filesystem::is_symlink(status) ||
            std::filesystem::canonical(directory_) != directory_) {
#else
        struct stat identity {};
        if (::lstat(directory_.c_str(), &identity) != 0 ||
            !S_ISDIR(identity.st_mode) || S_ISLNK(identity.st_mode) ||
            static_cast<std::uintmax_t>(identity.st_dev) != device_ ||
            static_cast<std::uintmax_t>(identity.st_ino) != inode_) {
#endif
            throw std::runtime_error(
                "external transcript-packing outer-assignment root "
                "changed during proving");
        }
    }

    void clear_checked() {
        validate_root();
        for (auto entry = std::filesystem::directory_iterator(directory_);
             entry != std::filesystem::directory_iterator();) {
            const std::filesystem::path child = entry->path();
            ++entry;
            std::filesystem::remove_all(child);
        }
        if (!std::filesystem::is_empty(directory_)) {
            throw std::runtime_error(
                "external transcript-packing outer-assignment cleanup "
                "did not empty its root");
        }
    }

    void clear_noexcept() noexcept {
        if (!armed_) {
            return;
        }
        try {
            clear_checked();
        } catch (...) {
        }
    }

    std::filesystem::path directory_;
#ifndef _WIN32
    std::uintmax_t device_ = 0;
    std::uintmax_t inode_ = 0;
#endif
    bool armed_ = true;
};

inline void progress_boundary(
    const RuntimeProgressCallback &progress,
    RuntimeProgressBoundary boundary, RuntimeProgressStage stage,
    std::uint64_t work_units = 0) {
    notify_runtime_progress(
        progress,
        {.boundary = boundary, .stage = stage, .work_units = work_units});
}

inline TranscriptPackingExternalPrefixStorageReport
validate_outer_options_pre_challenge(
    const packing::OuterRelationPlan &plan,
    const packing::OuterRelationAssignmentArtifactOptions &options) {
    const std::uint64_t exact_physical =
        packing::outer_relation_assignment_artifact_physical_bytes(plan);
    const std::uint64_t working_elements =
        options.max_working_field_bytes / sizeof(Fq);
    const std::uint64_t selected_elements = std::min<std::uint64_t>(
        options.block_elements, working_elements);
    if (options.storage_limits.max_total_bytes < exact_physical ||
        options.storage_limits.min_free_bytes == 0 ||
        selected_elements == 0) {
        throw std::invalid_argument(
            "external transcript-packing outer-assignment resources are "
            "below their exact requirement");
    }
    if (options.storage_limits.min_free_bytes >
        std::numeric_limits<std::uint64_t>::max() - exact_physical) {
        throw std::overflow_error(
            "external transcript-packing outer-assignment free-space "
            "requirement overflows");
    }
    const std::uint64_t required_free =
        exact_physical + options.storage_limits.min_free_bytes;
    if (std::filesystem::space(options.directory).available <
        required_free) {
        throw std::runtime_error(
            "external transcript-packing outer-assignment root has "
            "insufficient free space");
    }
    return TranscriptPackingExternalPrefixStorageReport{
        .outer_assignment_physical_bytes = exact_physical,
        .outer_assignment_peak_working_field_bytes =
            selected_elements * sizeof(Fq),
    };
}

inline const packing::ProofOfPackingStructuredMetadata &
validate_setup_identity(
    PackingGkrVariant expected_variant,
    const TranscriptPackingExternalProverSetup &setup) {
    const auto &relation = setup.relation();
    if ((expected_variant != PackingGkrVariant::Folded &&
         expected_variant != PackingGkrVariant::Laned) ||
        setup.variant() != expected_variant ||
        setup.bhip_round_count() == 0 ||
        setup.bhip_round_count() !=
            relation.alignment_layout.placements.size() ||
        relation.relation_plan.shape.aligned_ciphertexts !=
            setup.bhip_round_count()) {
        throw std::invalid_argument(
            "external transcript-packing setup does not match the "
            "expected variant and round geometry");
    }
    return relation;
}

inline TranscriptPackingExternalProverReport take_reports(
    TranscriptPackingExternalPrefixStorageReport prefix_storage,
    packing::OuterRelationAssignmentArtifactReport outer,
    packing::ProofOfPackingExternalSpartanResult suffix) {
    return TranscriptPackingExternalProverReport{
        .prefix_storage = std::move(prefix_storage),
        .outer_assignment = std::move(outer),
        .spartan_assignment = std::move(suffix.assignment),
        .matrix_products = std::move(suffix.matrix_products),
        .witness_commitment = std::move(suffix.witness_commitment),
        .constraint_sumcheck = std::move(suffix.constraint_sumcheck),
        .wiring_matrix = std::move(suffix.wiring_matrix),
        .wiring_sumcheck = std::move(suffix.wiring_sumcheck),
        .factored_evaluation = std::move(suffix.factored_evaluation),
        .witness_opening = std::move(suffix.witness_opening),
        .storage = std::move(suffix.storage),
    };
}

} // namespace external_packing_detail
} // namespace laminate::protocol::detail

namespace laminate::protocol {

inline TranscriptPackingExternalAdmission
admit_transcript_packing_external(
    PackingGkrVariant expected_variant,
    const TranscriptPackingExternalProverSetup &setup,
    TranscriptPackingExternalProverOptions options) {
    namespace prefix = detail::external_packing_detail;
    const auto &relation =
        prefix::validate_setup_identity(expected_variant, setup);
    std::vector<std::filesystem::path> mutable_roots{
        options.outer_assignment.directory,
        options.spartan.assignment.directory,
        options.spartan.matrix_products.directory,
        options.spartan.witness_commitment.destination_directory,
        options.spartan.witness_commitment.scratch_directory,
        options.spartan.constraint_sumcheck.scratch_directory,
        options.spartan.wiring_matrix.directory,
        options.spartan.wiring_sumcheck.scratch_directory,
        options.spartan.witness_opening.scratch_directory,
    };
    for (const auto &opening :
         options.spartan.factored_evaluation.tensor_openings) {
        mutable_roots.push_back(opening.scratch_directory);
    }
    prefix::OuterAssignmentRootGuard outer_root(
        options.outer_assignment.directory);
    TranscriptPackingExternalPrefixStorageReport prefix_storage =
        prefix::validate_outer_options_pre_challenge(
            relation.relation_plan, options.outer_assignment);
    packing::ProofOfPackingExternalSpartanAdmission suffix =
        packing::admit_proof_of_packing_spartan_external_before_commitments(
            relation.relation_plan, relation.r1cs_layout,
            setup.spartan_key(), options.outer_assignment.directory,
            relation.relation_plan.shape.aligned_ciphertexts,
            setup.basefold_pcs(),
            std::move(options.spartan));
    prefix_storage
        .outer_assignment_construction_peak_live_storage_bytes =
        suffix.storage_report().persistent_input_physical_bytes;
    return TranscriptPackingExternalAdmission(
        expected_variant, &setup, std::move(options.outer_assignment),
        std::move(mutable_roots), std::move(prefix_storage),
        std::move(suffix));
}

template <ProofOfPackingBackend Backend>
TranscriptPackingExternalProverResult<Backend>
prove_transcript_packing_external_admitted(
    const typename Backend::EvalContext &eval,
    const TranscriptPackingExternalProverSetup &setup,
    TranscriptPackingExternalAdmission admission,
    TranscriptPackingExternalProverInput<Backend> input,
    Transcript &packing_transcript,
    const RuntimeProgressCallback &progress) {
    namespace prefix = detail::external_packing_detail;
    detail::ConsumedTranscriptPackingExternalAdmission consumed =
        detail::TranscriptPackingExternalAdmissionAccess::take(
            std::move(admission), setup);
    const PackingGkrVariant expected_variant = consumed.expected_variant;
    const auto &relation =
        prefix::validate_setup_identity(expected_variant, setup);
    auto &aligned =
        detail::TranscriptPackingExternalProverInputAccess::aligned(input);
    auto &commitments =
        detail::TranscriptPackingExternalProverInputAccess::commitments(
            input);
    if (aligned.layout != relation.alignment_layout ||
        aligned.ciphertext_list_digest.has_value() ||
        commitments.size() !=
            relation.relation_plan.shape.aligned_ciphertexts) {
        throw std::invalid_argument(
            "external transcript-packing input does not match its "
            "preprocessed variant and layout");
    }
    // Validate the moved normalized source before any artifact admission or
    // transcript observation. The setup itself is immutable and was fully
    // certified by make_transcript_packing_external_prover_setup.
    packing::lazy_ternary_detail::validate_aligned_transcript<Backend>(
        eval, aligned);
    prefix::OuterAssignmentRootGuard outer_root(
        consumed.outer_assignment.directory);
    TranscriptPackingExternalPrefixStorageReport prefix_storage =
        std::move(consumed.prefix_storage);
    packing::ProofOfPackingExternalSpartanAdmission suffix_admission =
        packing::bind_proof_of_packing_spartan_external_commitments(
            std::move(consumed.suffix), commitments);

    TranscriptPackingProof<Backend> proof;
    packing::OuterRelationAssignmentArtifactReport outer_report;
    packing::OuterRelationAssignmentArtifact outer_artifact;
    const std::size_t aligned_source_count = aligned.values.size();

    // The scope below is the complete lifetime of the aligned ciphertexts,
    // challenges, public overlays, and mixed reveal sources. Only encrypted
    // reveal contributions escape it.
    {
        prefix::progress_boundary(
            progress, RuntimeProgressBoundary::Begin,
            RuntimeProgressStage::TranscriptPackingRevealEvaluation);
        const std::vector<PoseidonDigest> digests =
            detail::packing_protocol_detail::commitment_digests(
                commitments);
        const packing::LazyTernaryChallengeMatrix challenges =
            packing::derive_committed_lazy_ternary_challenges(
                relation.alignment_layout, digests, packing_transcript,
                relation.parameters);
        packing::LazyTernaryEvaluation<Backend> experiment =
            packing::evaluate_lazy_ternary<Backend>(
                eval, aligned, challenges, relation.parameters);
        prefix::progress_boundary(
            progress, RuntimeProgressBoundary::End,
            RuntimeProgressStage::TranscriptPackingRevealEvaluation,
            experiment.test_values.size() +
                experiment.packed_digit_values.size());

        const std::vector<std::uint64_t> packed_challenge_words =
            packing::pack_outer_relation_challenge_bits(
                relation.relation_plan, challenges);
        const packing::OuterRelationR1csAssignmentView assignment =
            packing::borrow_outer_relation_r1cs_assignment<Backend>(
                eval, relation.relation_plan, packed_challenge_words,
                experiment.test_values, experiment.packed_digit_values,
                aligned,
                [](const typename Backend::Ciphertext &ciphertext)
                    -> std::span<const std::uint64_t> {
                    return Backend::
                        coefficient_commitment_ntt_coordinate_view(
                            ciphertext);
                });
        prefix::progress_boundary(
            progress, RuntimeProgressBoundary::Begin,
            RuntimeProgressStage::TranscriptPackingAssignment);
        outer_artifact =
            packing::write_outer_relation_assignment_artifact(
                assignment, std::move(consumed.outer_assignment));
        outer_report = outer_artifact.report;
        prefix::progress_boundary(
            progress, RuntimeProgressBoundary::End,
            RuntimeProgressStage::TranscriptPackingAssignment,
            outer_report.physical_bytes);

        proof.well_formedness_reveals =
            detail::packing_protocol_detail::
                take_encrypted_contributions<Backend>(
                    experiment.test_values);
        proof.digit_decomposed_packed_values =
            detail::packing_protocol_detail::
                take_encrypted_contributions<Backend>(
                    experiment.packed_digit_values);
    }

    // `input` is no longer needed. Its retirement is an explicit phase, and
    // completes before the external suffix receives its first callback.
    prefix::progress_boundary(
        progress, RuntimeProgressBoundary::Begin,
        RuntimeProgressStage::TranscriptPackingAlignedSourceRetirement,
        aligned_source_count);
    detail::TranscriptPackingExternalProverInputAccess::retire(input);
    prefix::progress_boundary(
        progress, RuntimeProgressBoundary::End,
        RuntimeProgressStage::TranscriptPackingAlignedSourceRetirement,
        aligned_source_count);

    prefix::progress_boundary(
        progress, RuntimeProgressBoundary::Begin,
        RuntimeProgressStage::TranscriptPackingSpartanProve);
    packing::ProofOfPackingExternalSpartanResult suffix =
        packing::prove_proof_of_packing_spartan_external_admitted(
            std::move(suffix_admission), *outer_artifact.artifact,
            packing_transcript, progress);
    prefix::progress_boundary(
        progress, RuntimeProgressBoundary::End,
        RuntimeProgressStage::TranscriptPackingSpartanProve,
        spartan::proof_size_bytes(suffix.proof));

    if (outer_report.peak_working_field_bytes !=
            prefix_storage.outer_assignment_peak_working_field_bytes ||
        outer_report.physical_bytes !=
            prefix_storage.outer_assignment_physical_bytes ||
        suffix.storage.outer_assignment_physical_bytes !=
            outer_report.physical_bytes ||
        suffix.storage.peak_live_storage_bytes >
            suffix.storage.admitted_live_storage_bytes) {
        throw std::logic_error(
            "external transcript-packing reports disagree with their "
            "pre-challenge admission");
    }
    proof.proof_of_packing = std::move(suffix.proof);
    TranscriptPackingExternalProverReport report =
        prefix::take_reports(std::move(prefix_storage),
                             std::move(outer_report), std::move(suffix));

    // Close the artifact before removing its files. Failure from this point
    // still leaves the guard armed, so the prefix root cannot escape.
    outer_artifact.artifact.reset();
    prefix::progress_boundary(
        progress, RuntimeProgressBoundary::Begin,
        RuntimeProgressStage::TranscriptPackingOuterAssignmentRetirement,
        report.outer_assignment.physical_bytes);
    outer_root.retire();
    prefix::progress_boundary(
        progress, RuntimeProgressBoundary::End,
        RuntimeProgressStage::TranscriptPackingOuterAssignmentRetirement,
        report.outer_assignment.physical_bytes);

    return TranscriptPackingExternalProverResult<Backend>{
        .proof = std::move(proof),
        .report = std::move(report),
    };
}

template <ProofOfPackingBackend Backend>
TranscriptPackingExternalProverResult<Backend>
prove_transcript_packing_external(
    const typename Backend::EvalContext &eval,
    PackingGkrVariant expected_variant,
    const TranscriptPackingExternalProverSetup &setup,
    TranscriptPackingExternalProverInput<Backend> input,
    Transcript &packing_transcript,
    TranscriptPackingExternalProverOptions options,
    const RuntimeProgressCallback &progress) {
    TranscriptPackingExternalAdmission admission =
        admit_transcript_packing_external(
            expected_variant, setup, std::move(options));
    return prove_transcript_packing_external_admitted<Backend>(
        eval, setup, std::move(admission), std::move(input),
        packing_transcript, progress);
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_TRANSCRIPT_PACKING_IMPL_HPP
