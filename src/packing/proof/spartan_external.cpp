/// @file spartan_external.cpp
/// @brief Composed artifact-backed Spartan prover for transcript packing.

#include "laminate/packing/proof/spartan_external.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <exception>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace laminate::packing {
namespace {

std::uint64_t storage_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (left > std::numeric_limits<std::uint64_t>::max() - right) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

std::uint64_t storage_sum(std::initializer_list<std::uint64_t> values,
                          const char *label) {
    std::uint64_t result = 0;
    for (const std::uint64_t value : values) {
        result = storage_add(result, value, label);
    }
    return result;
}

std::uint64_t storage_remainder(std::uint64_t capacity,
                                std::uint64_t reserved,
                                const char *label) {
    if (reserved >= capacity) {
        throw std::invalid_argument(std::string(label) +
                                    " leaves no phase-local storage");
    }
    return capacity - reserved;
}

bool zero_digest(const Digest &digest) {
    return std::all_of(digest.begin(), digest.end(),
                       [](std::uint8_t value) { return value == 0; });
}

bool path_prefix(const std::filesystem::path &prefix,
                 const std::filesystem::path &path) {
    auto left = prefix.begin();
    auto right = path.begin();
    while (left != prefix.end() && right != path.end() &&
           *left == *right) {
        ++left;
        ++right;
    }
    return left == prefix.end();
}

std::filesystem::path normalized_real_directory(
    const std::filesystem::path &directory, const char *label,
    bool require_empty) {
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(directory);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status) ||
        (require_empty && !std::filesystem::is_empty(directory))) {
        throw std::invalid_argument(std::string(label) +
                                    (require_empty
                                         ? " must be an empty real directory"
                                         : " must be a real directory"));
    }
    return std::filesystem::canonical(directory);
}

struct DirectoryIdentity {
    std::filesystem::path path;
#ifndef _WIN32
    std::uintmax_t device = 0;
    std::uintmax_t inode = 0;
#endif
};

DirectoryIdentity capture_directory_identity(
    const std::filesystem::path &path, const char *label) {
    DirectoryIdentity result{.path = path};
#ifndef _WIN32
    struct stat status {};
    if (::lstat(path.c_str(), &status) != 0) {
        throw std::filesystem::filesystem_error(
            std::string("failed to bind ") + label, path,
            std::error_code(errno, std::generic_category()));
    }
    if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) {
        throw std::invalid_argument(std::string(label) +
                                    " is not a real directory");
    }
    result.device = static_cast<std::uintmax_t>(status.st_dev);
    result.inode = static_cast<std::uintmax_t>(status.st_ino);
#endif
    return result;
}

bool same_directory_identity(const DirectoryIdentity &expected) {
#ifdef _WIN32
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(expected.path);
    return std::filesystem::is_directory(status) &&
           !std::filesystem::is_symlink(status) &&
           std::filesystem::canonical(expected.path) == expected.path;
#else
    struct stat status {};
    return ::lstat(expected.path.c_str(), &status) == 0 &&
           S_ISDIR(status.st_mode) && !S_ISLNK(status.st_mode) &&
           static_cast<std::uintmax_t>(status.st_dev) == expected.device &&
           static_cast<std::uintmax_t>(status.st_ino) == expected.inode;
#endif
}

/// Own every mutable root for the complete one-shot call. Nested phases give
/// strong cleanup for their own writes; this outer guard additionally clears
/// outputs from earlier successful phases when a later phase throws.
class ExternalProofRoots {
  public:
    ExternalProofRoots(
        std::span<const std::filesystem::path> mutable_roots,
        std::span<const std::filesystem::path> immutable_roots) {
        roots_.reserve(mutable_roots.size());
        for (const std::filesystem::path &path : mutable_roots) {
            const std::filesystem::path normalized =
                normalized_real_directory(
                    path, "external Spartan mutable root", true);
            roots_.push_back({
                .identity = capture_directory_identity(
                    normalized, "external Spartan mutable root"),
            });
        }
        inputs_.reserve(immutable_roots.size());
        for (const std::filesystem::path &path : immutable_roots) {
            const std::filesystem::path normalized =
                normalized_real_directory(
                    path, "external Spartan immutable root", false);
            inputs_.push_back(capture_directory_identity(
                normalized, "external Spartan immutable root"));
        }
        for (std::size_t left = 0; left < inputs_.size(); ++left) {
            for (std::size_t right = left + 1U; right < inputs_.size();
                 ++right) {
                reject_overlap(
                    inputs_[left].path, inputs_[right].path,
                    "external Spartan immutable roots overlap");
            }
        }
        for (std::size_t left = 0; left < roots_.size(); ++left) {
            for (std::size_t right = left + 1U; right < roots_.size();
                 ++right) {
                reject_overlap(roots_[left].identity.path,
                               roots_[right].identity.path,
                               "external Spartan mutable roots overlap");
            }
            for (const DirectoryIdentity &input : inputs_) {
                reject_overlap(
                    roots_[left].identity.path, input.path,
                    "external Spartan mutable and immutable roots overlap");
            }
        }
    }

    ExternalProofRoots(const ExternalProofRoots &) = delete;
    ExternalProofRoots &operator=(const ExternalProofRoots &) = delete;

    ~ExternalProofRoots() {
        if (!armed_) {
            return;
        }
        for (const Root &root : roots_) {
            clear_noexcept(root.identity);
        }
    }

    /// Close the pre-GKR admission's root-identity TOCTOU window without
    /// repeating any immutable artifact-content scan. Mutable destinations
    /// must still be empty; every root must retain its admitted device/inode.
    void validate_for_late_binding() const {
        for (const Root &root : roots_) {
            if (!same_directory_identity(root.identity) ||
                !std::filesystem::is_empty(root.identity.path)) {
                throw std::runtime_error(
                    "external Spartan mutable root changed after "
                    "pre-GKR admission");
            }
        }
        for (const DirectoryIdentity &input : inputs_) {
            if (!same_directory_identity(input)) {
                throw std::runtime_error(
                    "external Spartan immutable root changed after "
                    "pre-GKR admission");
            }
        }
    }

    void retire(const std::filesystem::path &path) {
        const std::filesystem::path normalized =
            normalized_real_directory(
                path, "external Spartan retirement root", false);
        auto selected = std::find_if(
            roots_.begin(), roots_.end(),
            [&](const Root &root) {
                return root.identity.path == normalized;
            });
        if (selected == roots_.end()) {
            throw std::logic_error(
                "external Spartan tried to retire an unowned root");
        }
        clear_checked(selected->identity);
        selected->retired = true;
    }

    void finish() {
        for (Root &root : roots_) {
            clear_checked(root.identity);
            root.retired = true;
        }
        armed_ = false;
    }

  private:
    struct Root {
        DirectoryIdentity identity;
        bool retired = false;
    };

    static void reject_overlap(const std::filesystem::path &left,
                               const std::filesystem::path &right,
                               const char *message) {
        if (path_prefix(left, right) || path_prefix(right, left)) {
            throw std::invalid_argument(message);
        }
    }

    static void clear_checked(const DirectoryIdentity &root) {
        if (!same_directory_identity(root)) {
            throw std::runtime_error(
                "external Spartan cleanup root changed after admission");
        }
        for (auto entry = std::filesystem::directory_iterator(root.path);
             entry != std::filesystem::directory_iterator();) {
            const std::filesystem::path child = entry->path();
            ++entry;
            std::filesystem::remove_all(child);
        }
        if (!std::filesystem::is_empty(root.path)) {
            throw std::runtime_error(
                "external Spartan cleanup did not empty its root");
        }
    }

    static void clear_noexcept(const DirectoryIdentity &root) noexcept {
        try {
            clear_checked(root);
        } catch (...) {
        }
    }

    std::vector<Root> roots_;
    std::vector<DirectoryIdentity> inputs_;
    bool armed_ = true;
};

struct ExternalProofPaths {
    std::filesystem::path assignment;
    std::filesystem::path matrix_products;
    std::filesystem::path witness_state;
    std::filesystem::path wiring_matrix;
};

void progress_boundary(const RuntimeProgressCallback &progress,
                       RuntimeProgressBoundary boundary,
                       RuntimeProgressStage stage,
                       std::uint64_t work_units = 0) {
    notify_runtime_progress(
        progress,
        {.boundary = boundary, .stage = stage, .work_units = work_units});
}

RuntimeProgressStage witness_commitment_progress_stage(
    spartan::BaseFoldExternalCommitPhase phase) noexcept {
    switch (phase) {
    case spartan::BaseFoldExternalCommitPhase::MobiusTransform:
        return RuntimeProgressStage::
            TranscriptPackingSpartanWitnessCommitmentMobius;
    case spartan::BaseFoldExternalCommitPhase::RateExpansion:
        return RuntimeProgressStage::
            TranscriptPackingSpartanWitnessCommitmentRateExpansion;
    case spartan::BaseFoldExternalCommitPhase::NttTransform:
        return RuntimeProgressStage::
            TranscriptPackingSpartanWitnessCommitmentNtt;
    case spartan::BaseFoldExternalCommitPhase::MerkleTree:
        return RuntimeProgressStage::
            TranscriptPackingSpartanWitnessCommitmentMerkleTree;
    case spartan::BaseFoldExternalCommitPhase::FinalPublication:
        return RuntimeProgressStage::
            TranscriptPackingSpartanWitnessCommitmentFinalPublication;
    }
    return RuntimeProgressStage::TranscriptPackingSpartanWitnessCommitment;
}

RuntimeProgressSubpass witness_commitment_progress_subpass(
    spartan::BaseFoldExternalCommitSubpass subpass) noexcept {
    using Source = spartan::BaseFoldExternalCommitSubpass;
    switch (subpass) {
    case Source::SourceLocalMobius:
        return RuntimeProgressSubpass::SourceLocalMobius;
    case Source::LocalMobius:
        return RuntimeProgressSubpass::LocalMobius;
    case Source::RateExpansion:
        return RuntimeProgressSubpass::RateExpansion;
    case Source::Transpose:
        return RuntimeProgressSubpass::Transpose;
    case Source::TwiddleTranspose:
        return RuntimeProgressSubpass::TwiddleTranspose;
    case Source::LocalNtt:
        return RuntimeProgressSubpass::LocalNtt;
    case Source::MerkleTree:
        return RuntimeProgressSubpass::MerkleTree;
    case Source::MessagePublication:
        return RuntimeProgressSubpass::MessagePublication;
    case Source::CodewordPublication:
        return RuntimeProgressSubpass::CodewordPublication;
    case Source::MerklePublication:
        return RuntimeProgressSubpass::MerklePublication;
    case Source::ArtifactPublication:
        return RuntimeProgressSubpass::ArtifactPublication;
    }
    return RuntimeProgressSubpass::Unspecified;
}

RuntimeProgressWorkUnit witness_commitment_progress_work_unit(
    spartan::BaseFoldExternalCommitWorkUnit work_unit) noexcept {
    using Source = spartan::BaseFoldExternalCommitWorkUnit;
    switch (work_unit) {
    case Source::FieldElements:
        return RuntimeProgressWorkUnit::FieldElements;
    case Source::NttButterflies:
        return RuntimeProgressWorkUnit::NttButterflies;
    case Source::MerkleItems:
        return RuntimeProgressWorkUnit::MerkleItems;
    case Source::PublicationSteps:
        return RuntimeProgressWorkUnit::PublicationSteps;
    }
    return RuntimeProgressWorkUnit::Unspecified;
}

void report_witness_commitment_progress(
    const RuntimeProgressCallback &progress,
    const spartan::BaseFoldExternalCommitProgress &sample) noexcept {
    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::Update,
         .stage = witness_commitment_progress_stage(sample.phase),
         .completed_steps = sample.completed_passes,
         .total_steps = sample.total_passes,
         .completed_work_units = sample.pass_completed_work_units,
         .total_work_units = sample.pass_total_work_units,
         .column_index = sample.column_index,
         .column_count = sample.column_count,
         .subpass = witness_commitment_progress_subpass(sample.subpass),
         .progress_work_unit =
             witness_commitment_progress_work_unit(sample.work_unit),
         .phase_completed_steps = sample.phase_completed_passes,
         .phase_total_steps = sample.phase_total_passes,
         .completed_read_bytes = sample.pass_completed_read_bytes,
         .total_read_bytes = sample.pass_total_read_bytes,
         .completed_write_bytes = sample.pass_completed_write_bytes,
         .total_write_bytes = sample.pass_total_write_bytes,
         .phase_completed_read_bytes = sample.phase_completed_read_bytes,
         .phase_total_read_bytes = sample.phase_total_read_bytes,
         .phase_completed_write_bytes = sample.phase_completed_write_bytes,
         .phase_total_write_bytes = sample.phase_total_write_bytes,
         .completed_butterflies = sample.pass_completed_butterflies,
         .total_butterflies = sample.pass_total_butterflies,
         .phase_completed_butterflies =
             sample.phase_completed_butterflies,
         .phase_total_butterflies = sample.phase_total_butterflies,
         .radix_elements = sample.radix_elements,
         .row_count = sample.row_count,
         .row_size = sample.row_size,
         .recent_work_units = sample.recent_work_units,
         .recent_elapsed_milliseconds = sample.recent_elapsed_milliseconds,
         .estimated_remaining_milliseconds =
             sample.estimated_remaining_milliseconds});
}

std::vector<Fq> read_public_inputs(
    const storage::NativeFieldArtifact &assignment,
    const spartan::R1csMetadata &metadata) {
    const auto &array = assignment.array(
        kProofOfPackingAssignmentPublicInputs);
    if (array.kind != storage::NativeFieldElementKind::Fq ||
        array.element_count != metadata.shape().public_inputs ||
        array.element_count > std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(
            "external Spartan public-input artifact has the wrong shape");
    }
    std::vector<Fq> result(static_cast<std::size_t>(array.element_count));
    auto reader = assignment.open_array(
        kProofOfPackingAssignmentPublicInputs);
    if (reader.read(result) != result.size()) {
        throw std::runtime_error(
            "external Spartan public-input artifact is truncated");
    }
    return result;
}

spartan::BaseFoldArtifactColumn witness_commitment_column(
    const ProofOfPackingWitnessStorageLayout &layout) {
    spartan::BaseFoldArtifactColumn result{
        .array_name =
            std::string(kProofOfPackingAssignmentWitnessValues),
        .logical_evaluation_count = layout.logical_elements,
    };
    result.segments.reserve(layout.segments.size());
    for (const ProofOfPackingWitnessStorageSegment &segment :
         layout.segments) {
        result.segments.push_back({
            .logical_begin = segment.logical_begin,
            .stored_begin = segment.stored_begin,
            .element_count = segment.element_count,
        });
    }
    return result;
}

spartan::WiringAssignmentStorageLayout wiring_assignment_layout(
    const ProofOfPackingWitnessStorageLayout &layout) {
    spartan::WiringAssignmentStorageLayout result{
        .half_size = layout.logical_elements,
    };
    result.segments.reserve(layout.segments.size());
    for (const ProofOfPackingWitnessStorageSegment &segment :
         layout.segments) {
        result.segments.push_back({
            .logical_begin = segment.logical_begin,
            .stored_begin = segment.stored_begin,
            .element_count = segment.element_count,
        });
    }
    return result;
}

void bind_expected_identity(Digest &selected, const Digest &actual,
                            const char *label) {
    if (!zero_digest(selected) && selected != actual) {
        throw std::invalid_argument(std::string(label) +
                                    " identity does not match its source");
    }
    selected = actual;
}

void admit_peak(ProofOfPackingExternalSpartanStorageReport &report,
                std::uint64_t phase_peak) {
    report.peak_live_storage_bytes =
        std::max(report.peak_live_storage_bytes, phase_peak);
    if (phase_peak > report.admitted_live_storage_bytes) {
        throw std::invalid_argument(
            "external Spartan aggregate live-storage envelope is too small");
    }
}

void require_capacity(std::uint64_t available, std::uint64_t required,
                      const char *label) {
    if (available < required) {
        throw std::invalid_argument(std::string(label) +
                                    " is below its exact requirement");
    }
}

void require_conservative_free_space(
    std::span<const std::filesystem::path> roots,
    std::uint64_t future_peak_bytes,
    std::uint64_t retained_free_bytes) {
    // Device identities are deliberately not inferred from path strings.
    // Requiring the complete future peak at every destination is conservative
    // when roots span devices and exact when they share one device. Existing
    // immutable preprocessing is already charged in filesystem occupancy and
    // is therefore excluded from `future_peak_bytes` by the caller.
    for (const std::filesystem::path &root : roots) {
        const std::uint64_t available =
            std::filesystem::space(root).available;
        if (available < future_peak_bytes ||
            retained_free_bytes > available - future_peak_bytes) {
            throw std::runtime_error(
                "external Spartan roots lack the admitted future disk "
                "envelope and free-space reserve");
        }
    }
}

void validate_admitted_outer_assignment(
    const storage::NativeFieldArtifact &outer_assignment,
    const std::filesystem::path &expected_directory,
    const OuterRelationPlan &plan, std::uint64_t expected_physical_bytes) {
    const std::filesystem::path actual_directory =
        normalized_real_directory(
            outer_assignment.directory(),
            "external Spartan outer-assignment root", false);
    if (actual_directory != expected_directory ||
        outer_assignment.identity() !=
            outer_relation_assignment_artifact_identity(plan) ||
        outer_assignment.physical_bytes() != expected_physical_bytes ||
        outer_assignment.arrays().size() != 2) {
        throw std::invalid_argument(
            "published outer assignment does not match its admission");
    }
    const storage::NativeFieldArrayDescriptor &public_inputs =
        outer_assignment.array("public-inputs");
    const storage::NativeFieldArrayDescriptor &witness =
        outer_assignment.array("witness");
    if (public_inputs.kind != storage::NativeFieldElementKind::Fq ||
        public_inputs.element_count !=
            plan.variables.public_inputs.total ||
        witness.kind != storage::NativeFieldElementKind::Fq ||
        witness.element_count != plan.variables.witness.total) {
        throw std::invalid_argument(
            "published outer assignment has the wrong layout");
    }
}

} // namespace

struct ProofOfPackingExternalSpartanAdmission::Impl {
    OuterRelationPlan plan;
    ProofOfPackingR1csLayout layout;
    spartan::ExternalProverKey key;
    std::vector<gkr::HashCommitCT> commitments;
    std::size_t expected_commitment_count = 0;
    bool commitments_bound = false;
    std::shared_ptr<const spartan::BaseFoldPcs> pcs;
    ProofOfPackingExternalSpartanOptions options;
    std::vector<spartan::BaseFoldExternalOpeningAdmission>
        factored_admissions;
    std::unique_ptr<ExternalProofRoots> roots;
    ExternalProofPaths paths;
    std::filesystem::path expected_outer_assignment_directory;
    ProofOfPackingExternalSpartanStorageReport storage;
    ProofOfPackingWitnessStorageLayout witness_layout;
    ProofOfPackingAssignmentArtifactPlan assignment_plan;
    ProofOfPackingMatrixProductArtifactPlan matrix_product_plan;
    spartan::BaseFoldExternalCommitStoragePlan witness_commit_plan;
    spartan::BaseFoldExternalOpeningStoragePlan witness_opening_plan;
    spartan::ConstraintSumcheckArtifactPlan constraint_plan;
    ProofOfPackingWiringArtifactPlan wiring_matrix_plan;
    spartan::WiringSumcheckArtifactPlan wiring_sumcheck_plan;
    spartan::FactoredMatrixExternalProvingPlan factored_plan;
};

namespace detail {

struct ProofOfPackingExternalSpartanAdmissionFactory {
    static ProofOfPackingExternalSpartanAdmission admit(
        const OuterRelationPlan &plan,
        const ProofOfPackingR1csLayout &layout,
        const spartan::ExternalProverKey &key,
        const std::filesystem::path &expected_outer_assignment_directory,
        std::size_t expected_commitment_count,
        std::shared_ptr<const spartan::BaseFoldPcs> pcs,
        ProofOfPackingExternalSpartanOptions options,
        bool require_future_outer_directory);
};

} // namespace detail

ProofOfPackingExternalSpartanAdmission::
ProofOfPackingExternalSpartanAdmission(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

ProofOfPackingExternalSpartanAdmission::
~ProofOfPackingExternalSpartanAdmission() = default;

ProofOfPackingExternalSpartanAdmission::
ProofOfPackingExternalSpartanAdmission(
    ProofOfPackingExternalSpartanAdmission &&) noexcept = default;

ProofOfPackingExternalSpartanAdmission &
ProofOfPackingExternalSpartanAdmission::operator=(
    ProofOfPackingExternalSpartanAdmission &&) noexcept = default;

const ProofOfPackingExternalSpartanStorageReport &
ProofOfPackingExternalSpartanAdmission::storage_report() const {
    if (impl_ == nullptr) {
        throw std::logic_error(
            "external Spartan admission has already been consumed");
    }
    return impl_->storage;
}

ProofOfPackingExternalSpartanAdmission
detail::ProofOfPackingExternalSpartanAdmissionFactory::admit(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::ExternalProverKey &key,
    const std::filesystem::path &expected_outer_assignment_directory,
    std::size_t expected_commitment_count,
    std::shared_ptr<const spartan::BaseFoldPcs> pcs,
    ProofOfPackingExternalSpartanOptions options,
    bool require_future_outer_directory) {
    if (pcs == nullptr) {
        throw std::invalid_argument(
            "external packing Spartan admission needs an owned PCS");
    }
    spartan::validate_external_prover_key(key, *pcs);
    if (options.max_live_storage_bytes == 0 ||
        key.options.matrix_evaluation !=
            spartan::MatrixEvaluationMode::CommittedFactored ||
        key.factored_computation == nullptr ||
        key.factored_computation->tensor_column_source !=
            spartan::FactoredTensorColumnSource::Artifact ||
        key.factored_computation->tensor_columns_artifact == nullptr ||
        options.factored_evaluation.tensor_openings.size() !=
            key.factored_computation->tensors.size()) {
        throw std::invalid_argument(
            "external packing Spartan needs artifact-backed factored "
            "preprocessing and one aggregate storage authority");
    }
    const spartan::R1csMetadata &metadata = key.circuit_metadata;
    if (expected_commitment_count != plan.shape.aligned_ciphertexts ||
        metadata.digest() !=
            key.factored_computation->commitment.circuit_digest) {
        throw std::invalid_argument(
            "external packing Spartan relation does not match its key");
    }
    if (options.assignment.storage_limits.min_free_bytes == 0 ||
        options.assignment.max_working_bytes == 0 ||
        options.assignment.block_elements == 0 ||
        options.matrix_products.storage_limits.min_free_bytes == 0 ||
        options.matrix_products.max_working_field_bytes == 0 ||
        options.matrix_products.block_elements == 0 ||
        options.witness_commitment.min_free_bytes == 0 ||
        options.witness_commitment.max_working_field_bytes == 0 ||
        options.witness_commitment.block_elements == 0 ||
        options.constraint_sumcheck.min_free_bytes == 0 ||
        options.constraint_sumcheck.max_working_field_bytes == 0 ||
        options.constraint_sumcheck.block_elements == 0 ||
        options.wiring_matrix.storage_limits.min_free_bytes == 0 ||
        options.wiring_matrix.max_working_field_bytes == 0 ||
        options.wiring_matrix.block_elements == 0 ||
        options.wiring_sumcheck.min_free_bytes == 0 ||
        options.wiring_sumcheck.max_working_field_bytes == 0 ||
        options.wiring_sumcheck.block_elements == 0 ||
        options.witness_opening.min_free_bytes == 0 ||
        options.witness_opening.max_working_field_bytes == 0) {
        throw std::invalid_argument(
            "external Spartan phase resources must be nonzero");
    }
    if (options.constraint_sumcheck.logical_domain_size != 0 &&
        options.constraint_sumcheck.logical_domain_size !=
            metadata.padded_constraints()) {
        throw std::invalid_argument(
            "ConstraintCheck logical domain does not match the circuit");
    }
    options.constraint_sumcheck.logical_domain_size =
        metadata.padded_constraints();

    auto impl = std::make_unique<ProofOfPackingExternalSpartanAdmission::Impl>();
    impl->plan = plan;
    impl->layout = layout;
    impl->key = key;
    auto validated_factored =
        std::make_shared<spartan::FactoredMatrixProverKey>(
            *key.factored_computation);
    validated_factored->tensor_columns_artifact =
        spartan::open_factored_matrix_artifact(
            key.factored_computation->tensor_columns_artifact->directory(),
            key.factored_computation->commitment);
    impl->key.factored_computation = std::move(validated_factored);
    impl->expected_commitment_count = expected_commitment_count;
    impl->pcs = std::move(pcs);
    impl->options = std::move(options);
    impl->expected_outer_assignment_directory =
        normalized_real_directory(
            expected_outer_assignment_directory,
            "external Spartan expected outer-assignment root",
            require_future_outer_directory);

    // Validate every preprocessing opening and its scratch authority before
    // the prefix samples lazy-ternary challenges. The aggregate lifecycle,
    // not the caller, supplies each nested live-storage authority.
    impl->factored_admissions.reserve(
        impl->key.factored_computation->tensors.size());
    for (std::size_t index = 0;
         index < impl->key.factored_computation->tensors.size(); ++index) {
        const spartan::FactoredTensorProverKey &tensor =
            impl->key.factored_computation->tensors[index];
        if (tensor.opening_state_source !=
            spartan::FactoredTensorProverKey::OpeningStateSource::External) {
            throw std::invalid_argument(
                "external packing Spartan requires external factored "
                "opening states");
        }
        impl->options.factored_evaluation.tensor_openings[index]
            .max_live_storage_bytes =
            impl->options.max_live_storage_bytes;
        impl->factored_admissions.push_back(
            impl->pcs->admit_external_opening(
            tensor.opening_state,
            impl->key.factored_computation->commitment.tensors[index]
                .columns,
            impl->options.factored_evaluation.tensor_openings[index]));
    }

    impl->paths = ExternalProofPaths{
        .assignment = impl->options.assignment.directory,
        .matrix_products = impl->options.matrix_products.directory,
        .witness_state =
            impl->options.witness_commitment.destination_directory,
        .wiring_matrix = impl->options.wiring_matrix.directory,
    };
    std::vector<std::filesystem::path> mutable_roots{
        impl->paths.assignment,
        impl->paths.matrix_products,
        impl->paths.witness_state,
        impl->options.witness_commitment.scratch_directory,
        impl->options.constraint_sumcheck.scratch_directory,
        impl->paths.wiring_matrix,
        impl->options.wiring_sumcheck.scratch_directory,
        impl->options.witness_opening.scratch_directory,
    };
    for (const spartan::BaseFoldExternalOpeningOptions &opening :
         impl->options.factored_evaluation.tensor_openings) {
        mutable_roots.push_back(opening.scratch_directory);
    }
    std::vector<std::filesystem::path> immutable_roots{
        impl->expected_outer_assignment_directory,
        impl->key.factored_computation->tensor_columns_artifact->directory(),
    };
    for (const auto &admission : impl->factored_admissions) {
        immutable_roots.push_back(
            admission.preflight().state_artifact_directory);
    }
    impl->roots = std::make_unique<ExternalProofRoots>(
        mutable_roots, immutable_roots);

    ProofOfPackingExternalSpartanStorageReport &storage = impl->storage;
    storage.admitted_live_storage_bytes =
        impl->options.max_live_storage_bytes;
    storage.outer_assignment_physical_bytes =
        outer_relation_assignment_artifact_physical_bytes(plan);
    storage.factored_tensor_columns_physical_bytes =
        impl->key.factored_computation->tensor_columns_artifact
            ->physical_bytes();
    storage.factored_tensor_columns_validation_bytes =
        storage.factored_tensor_columns_physical_bytes;
    for (const auto &admission : impl->factored_admissions) {
        storage.factored_external_states_physical_bytes = storage_add(
            storage.factored_external_states_physical_bytes,
            admission.preflight().state_artifact_physical_bytes,
            "factored external-state bytes");
    }
    storage.factored_external_states_validation_bytes =
        storage.factored_external_states_physical_bytes;
    storage.preprocessing_validation_bytes = storage_add(
        storage.factored_tensor_columns_validation_bytes,
        storage.factored_external_states_validation_bytes,
        "external Spartan preprocessing validation bytes");
    storage.persistent_input_physical_bytes = storage_sum(
        {storage.outer_assignment_physical_bytes,
         storage.factored_tensor_columns_physical_bytes,
         storage.factored_external_states_physical_bytes},
        "persistent external Spartan inputs");
    admit_peak(storage, storage.persistent_input_physical_bytes);

    // Every exact disk and controlled-field planner runs before the prefix
    // may publish its future assignment and sample lazy challenges.
    impl->witness_layout =
        proof_of_packing_witness_storage_layout(plan, metadata);
    impl->assignment_plan =
        plan_proof_of_packing_assignment_artifact(
            plan, layout, metadata,
            impl->options.assignment.max_working_bytes,
            impl->options.assignment.block_elements);
    impl->matrix_product_plan =
        plan_proof_of_packing_matrix_product_artifact(
            plan, metadata,
            impl->options.matrix_products.max_working_field_bytes,
            impl->options.matrix_products.block_elements);
    impl->witness_commit_plan =
        impl->pcs->plan_external_commit_storage(
            metadata.assignment_half_size(), 1, true,
            impl->options.witness_commitment.max_working_field_bytes,
            impl->options.witness_commitment.block_elements);
    const spartan::PcsCommitment planned_witness_commitment{
        .scheme = impl->pcs->scheme_identifier(),
        .evaluation_count = metadata.assignment_half_size(),
        .width = 1,
        .log_rate =
            static_cast<std::uint32_t>(impl->pcs->parameters().log_rate),
        .query_count =
            static_cast<std::uint32_t>(impl->pcs->parameters().query_count),
    };
    impl->witness_opening_plan =
        impl->pcs->plan_external_opening_storage(
            planned_witness_commitment,
            impl->options.witness_opening.fold_chunk_elements,
            impl->options.witness_opening.max_working_field_bytes);
    impl->constraint_plan =
        spartan::plan_constraint_sumcheck_artifact(
            metadata.padded_constraints(),
            impl->options.constraint_sumcheck.source_rounds,
            impl->options.constraint_sumcheck.max_working_field_bytes,
            impl->options.constraint_sumcheck.block_elements);
    impl->wiring_matrix_plan =
        plan_proof_of_packing_wiring_matrix_artifact(
            plan, layout, metadata, *impl->key.factored_computation,
            impl->options.wiring_matrix.max_working_field_bytes,
            impl->options.wiring_matrix.block_elements);
    impl->wiring_sumcheck_plan =
        spartan::plan_wiring_sumcheck_artifact(
            metadata.assignment_half_size(),
            impl->options.wiring_sumcheck.source_rounds,
            impl->options.wiring_sumcheck.max_working_field_bytes,
            impl->options.wiring_sumcheck.block_elements);

    storage.assignment_physical_bytes =
        impl->assignment_plan.physical_bytes;
    storage.matrix_products_physical_bytes =
        impl->matrix_product_plan.physical_bytes;
    storage.witness_state_physical_bytes =
        impl->witness_commit_plan.final_physical_bytes;
    storage.wiring_matrix_physical_bytes =
        impl->wiring_matrix_plan.physical_bytes;

    require_capacity(
        impl->options.assignment.storage_limits.max_total_bytes,
        storage.assignment_physical_bytes, "assignment artifact quota");
    require_capacity(
        impl->options.matrix_products.storage_limits.max_total_bytes,
        storage.matrix_products_physical_bytes,
        "matrix-product artifact quota");
    require_capacity(
        impl->options.witness_commitment.max_final_bytes,
        impl->witness_commit_plan.final_physical_bytes,
        "witness commitment final quota");
    require_capacity(
        impl->options.witness_commitment.max_scratch_bytes,
        impl->witness_commit_plan.scratch_peak_physical_bytes,
        "witness commitment scratch quota");
    require_capacity(
        impl->options.constraint_sumcheck.max_total_scratch_bytes,
        impl->constraint_plan.scratch_peak_physical_bytes,
        "ConstraintCheck scratch quota");
    require_capacity(
        impl->options.wiring_matrix.storage_limits.max_total_bytes,
        storage.wiring_matrix_physical_bytes,
        "Wiring artifact quota");
    require_capacity(
        impl->options.wiring_sumcheck.max_total_scratch_bytes,
        impl->wiring_sumcheck_plan.scratch_peak_physical_bytes,
        "WiringCheck scratch quota");
    require_capacity(
        impl->options.witness_opening.max_total_scratch_bytes,
        impl->witness_opening_plan.scratch_peak_physical_bytes,
        "witness opening scratch quota");

    const std::uint64_t constraint_reserved = storage_sum(
        {storage.persistent_input_physical_bytes,
         storage.assignment_physical_bytes,
         storage.witness_state_physical_bytes},
        "ConstraintCheck reservation");
    impl->options.constraint_sumcheck.max_live_storage_bytes =
        storage_remainder(impl->options.max_live_storage_bytes,
                          constraint_reserved,
                          "ConstraintCheck reservation");
    require_capacity(
        impl->options.constraint_sumcheck.max_live_storage_bytes,
        storage_add(storage.matrix_products_physical_bytes,
                    impl->constraint_plan.scratch_peak_physical_bytes,
                    "ConstraintCheck nested live bytes"),
        "ConstraintCheck nested live-storage quota");

    const std::uint64_t wiring_construction_reserved = storage_sum(
        {storage.outer_assignment_physical_bytes,
         storage.factored_external_states_physical_bytes,
         storage.assignment_physical_bytes,
         storage.witness_state_physical_bytes},
        "Wiring construction reservation");
    impl->options.wiring_matrix.max_live_storage_bytes =
        storage_remainder(impl->options.max_live_storage_bytes,
                          wiring_construction_reserved,
                          "Wiring construction reservation");
    require_capacity(
        impl->options.wiring_matrix.max_live_storage_bytes,
        impl->wiring_matrix_plan.peak_live_storage_bytes,
        "Wiring construction nested live-storage quota");

    const std::uint64_t wiring_check_reserved = storage_add(
        storage.persistent_input_physical_bytes,
        storage.witness_state_physical_bytes,
        "WiringCheck reservation");
    impl->options.wiring_sumcheck.max_live_storage_bytes =
        storage_remainder(impl->options.max_live_storage_bytes,
                          wiring_check_reserved,
                          "WiringCheck reservation");
    require_capacity(
        impl->options.wiring_sumcheck.max_live_storage_bytes,
        storage_sum(
            {storage.assignment_physical_bytes,
             storage.wiring_matrix_physical_bytes,
             impl->wiring_sumcheck_plan.scratch_peak_physical_bytes},
            "WiringCheck nested live bytes"),
        "WiringCheck nested live-storage quota");

    impl->options.factored_evaluation.max_live_storage_bytes =
        impl->options.max_live_storage_bytes;
    impl->options.factored_evaluation.reserved_live_storage_bytes =
        storage_add(storage.outer_assignment_physical_bytes,
                    storage.witness_state_physical_bytes,
                    "factored evaluation reservation");
    std::vector<spartan::BaseFoldExternalOpeningPreflight>
        factored_preflights;
    factored_preflights.reserve(impl->factored_admissions.size());
    for (const auto &admission : impl->factored_admissions) {
        factored_preflights.push_back(admission.preflight());
    }
    impl->factored_plan =
        spartan::plan_factored_matrix_evaluation_external_admitted(
            *impl->key.factored_computation,
            impl->options.factored_evaluation, factored_preflights);

    impl->options.witness_opening.max_live_storage_bytes =
        storage_remainder(impl->options.max_live_storage_bytes,
                          storage.persistent_input_physical_bytes,
                          "witness opening reservation");
    require_capacity(
        impl->options.witness_opening.max_live_storage_bytes,
        storage_add(
            impl->witness_opening_plan.state_artifact_physical_bytes,
            impl->witness_opening_plan.scratch_peak_physical_bytes,
            "witness opening nested live bytes"),
        "witness opening nested live-storage quota");

    storage.assignment_construction_peak_live_storage_bytes =
        storage_add(storage.persistent_input_physical_bytes,
                    storage.assignment_physical_bytes,
                    "assignment construction peak");
    storage.witness_commitment_peak_live_storage_bytes = storage_sum(
        {storage.persistent_input_physical_bytes,
         storage.assignment_physical_bytes,
         storage.witness_state_physical_bytes,
         impl->witness_commit_plan.scratch_peak_physical_bytes},
        "witness commitment peak");
    storage.matrix_product_construction_peak_live_storage_bytes =
        storage_sum(
            {storage.persistent_input_physical_bytes,
             storage.assignment_physical_bytes,
             storage.witness_state_physical_bytes,
             storage.matrix_products_physical_bytes},
            "matrix-product construction peak");
    storage.pre_fiat_shamir_live_storage_bytes =
        storage.matrix_product_construction_peak_live_storage_bytes;
    storage.constraint_check_peak_live_storage_bytes = storage_add(
        storage.pre_fiat_shamir_live_storage_bytes,
        impl->constraint_plan.scratch_peak_physical_bytes,
        "ConstraintCheck aggregate peak");
    storage.wiring_construction_peak_live_storage_bytes = storage_sum(
        {storage.persistent_input_physical_bytes,
         storage.assignment_physical_bytes,
         storage.witness_state_physical_bytes,
         storage.wiring_matrix_physical_bytes},
        "Wiring construction aggregate peak");
    storage.wiring_check_peak_live_storage_bytes = storage_add(
        storage.wiring_construction_peak_live_storage_bytes,
        impl->wiring_sumcheck_plan.scratch_peak_physical_bytes,
        "WiringCheck aggregate peak");
    storage.factored_evaluation_peak_live_storage_bytes =
        impl->factored_plan.report.peak_live_storage_bytes;
    storage.witness_opening_peak_live_storage_bytes = storage_sum(
        {storage.persistent_input_physical_bytes,
         impl->witness_opening_plan.state_artifact_physical_bytes,
         impl->witness_opening_plan.scratch_peak_physical_bytes},
        "witness opening aggregate peak");
    for (const std::uint64_t peak : {
             storage.assignment_construction_peak_live_storage_bytes,
             storage.witness_commitment_peak_live_storage_bytes,
             storage.matrix_product_construction_peak_live_storage_bytes,
             storage.constraint_check_peak_live_storage_bytes,
             storage.wiring_construction_peak_live_storage_bytes,
             storage.wiring_check_peak_live_storage_bytes,
             storage.factored_evaluation_peak_live_storage_bytes,
             storage.witness_opening_peak_live_storage_bytes,
         }) {
        admit_peak(storage, peak);
    }

    std::uint64_t retained_free_bytes = std::max({
        impl->options.assignment.storage_limits.min_free_bytes,
        impl->options.matrix_products.storage_limits.min_free_bytes,
        impl->options.witness_commitment.min_free_bytes,
        impl->options.constraint_sumcheck.min_free_bytes,
        impl->options.wiring_matrix.storage_limits.min_free_bytes,
        impl->options.wiring_sumcheck.min_free_bytes,
        impl->options.witness_opening.min_free_bytes,
    });
    for (const spartan::BaseFoldExternalOpeningOptions &opening :
         impl->options.factored_evaluation.tensor_openings) {
        retained_free_bytes =
            std::max(retained_free_bytes, opening.min_free_bytes);
    }
    const std::uint64_t existing_immutable_bytes = storage_add(
        storage.factored_tensor_columns_physical_bytes,
        storage.factored_external_states_physical_bytes,
        "existing immutable preprocessing bytes");
    if (storage.peak_live_storage_bytes < existing_immutable_bytes) {
        throw std::logic_error(
            "external Spartan peak omits immutable preprocessing");
    }
    std::vector<std::filesystem::path> future_roots = mutable_roots;
    future_roots.push_back(
        impl->expected_outer_assignment_directory);
    require_conservative_free_space(
        future_roots,
        storage.peak_live_storage_bytes - existing_immutable_bytes,
        retained_free_bytes);
    return ProofOfPackingExternalSpartanAdmission(std::move(impl));
}

ProofOfPackingExternalSpartanAdmission
admit_proof_of_packing_spartan_external(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::ExternalProverKey &key,
    const std::filesystem::path &expected_outer_assignment_directory,
    std::span<const gkr::HashCommitCT> commitments,
    std::shared_ptr<const spartan::BaseFoldPcs> pcs,
    ProofOfPackingExternalSpartanOptions options) {
    return bind_proof_of_packing_spartan_external_commitments(
        admit_proof_of_packing_spartan_external_before_commitments(
            plan, layout, key, expected_outer_assignment_directory,
            commitments.size(), std::move(pcs), std::move(options)),
        commitments);
}

ProofOfPackingExternalSpartanAdmission
admit_proof_of_packing_spartan_external_before_commitments(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::ExternalProverKey &key,
    const std::filesystem::path &expected_outer_assignment_directory,
    std::size_t expected_commitment_count,
    std::shared_ptr<const spartan::BaseFoldPcs> pcs,
    ProofOfPackingExternalSpartanOptions options) {
    return detail::ProofOfPackingExternalSpartanAdmissionFactory::admit(
        plan, layout, key, expected_outer_assignment_directory,
        expected_commitment_count, std::move(pcs), std::move(options),
        true);
}

ProofOfPackingExternalSpartanAdmission
bind_proof_of_packing_spartan_external_commitments(
    ProofOfPackingExternalSpartanAdmission admission,
    std::span<const gkr::HashCommitCT> commitments) {
    if (admission.impl_ == nullptr ||
        admission.impl_->commitments_bound) {
        throw std::invalid_argument(
            "external Spartan admission cannot bind commitments twice");
    }
    auto &impl = *admission.impl_;
    impl.roots->validate_for_late_binding();
    if (!std::filesystem::is_empty(
            impl.expected_outer_assignment_directory) ||
        commitments.size() != impl.expected_commitment_count) {
        throw std::invalid_argument(
            "external Spartan late-bound commitments or future outer root "
            "do not match the pre-GKR admission");
    }
    impl.commitments.assign(commitments.begin(), commitments.end());
    impl.commitments_bound = true;
    return admission;
}

ProofOfPackingExternalSpartanResult
prove_proof_of_packing_spartan_external_admitted(
    ProofOfPackingExternalSpartanAdmission admission,
    const storage::NativeFieldArtifact &outer_assignment,
    PublicCoin &public_coin,
    const RuntimeProgressCallback &progress) {
    if (admission.impl_ == nullptr ||
        !admission.impl_->commitments_bound) {
        throw std::invalid_argument(
            "external Spartan admission is unbound or already consumed");
    }
    std::unique_ptr<ProofOfPackingExternalSpartanAdmission::Impl> impl =
        std::move(admission.impl_);
    const spartan::BaseFoldPcs &pcs = *impl->pcs;
    validate_admitted_outer_assignment(
        outer_assignment, impl->expected_outer_assignment_directory,
        impl->plan, impl->storage.outer_assignment_physical_bytes);

    const OuterRelationPlan &plan = impl->plan;
    const ProofOfPackingR1csLayout &layout = impl->layout;
    const spartan::ExternalProverKey &key = impl->key;
    const spartan::R1csMetadata &metadata = key.circuit_metadata;
    const std::span<const gkr::HashCommitCT> commitments =
        impl->commitments;
    ProofOfPackingExternalSpartanOptions options =
        std::move(impl->options);
    std::vector<spartan::BaseFoldExternalOpeningAdmission>
        factored_admissions = std::move(impl->factored_admissions);
    ExternalProofRoots &roots = *impl->roots;
    const ExternalProofPaths &paths = impl->paths;
    const ProofOfPackingWitnessStorageLayout &witness_layout =
        impl->witness_layout;
    const ProofOfPackingAssignmentArtifactPlan &assignment_plan =
        impl->assignment_plan;
    const ProofOfPackingMatrixProductArtifactPlan &matrix_product_plan =
        impl->matrix_product_plan;
    const spartan::BaseFoldExternalCommitStoragePlan &witness_commit_plan =
        impl->witness_commit_plan;
    const std::uint64_t constraint_scratch =
        impl->constraint_plan.scratch_peak_physical_bytes;
    const std::uint64_t wiring_scratch =
        impl->wiring_sumcheck_plan.scratch_peak_physical_bytes;

    ProofOfPackingExternalSpartanResult result;
    result.storage = impl->storage;

    progress_boundary(progress, RuntimeProgressBoundary::Begin,
                      RuntimeProgressStage::
                          TranscriptPackingSpartanAssignment);
    ProofOfPackingAssignmentArtifact assignment =
        write_proof_of_packing_assignment_artifact(
            plan, metadata, outer_assignment, commitments,
            std::move(options.assignment));
    progress_boundary(
        progress, RuntimeProgressBoundary::End,
        RuntimeProgressStage::TranscriptPackingSpartanAssignment,
        assignment.report.physical_bytes);
    if (assignment.report.physical_bytes !=
            result.storage.assignment_physical_bytes ||
        assignment.report.peak_working_bytes !=
            assignment_plan.peak_working_bytes) {
        throw std::logic_error(
            "assignment artifact disagrees with aggregate preflight");
    }
    result.assignment = assignment.report;
    result.storage.assignment_physical_bytes =
        assignment.report.physical_bytes;
    result.storage.assignment_construction_peak_live_storage_bytes =
        storage_add(result.storage.persistent_input_physical_bytes,
                    result.storage.assignment_physical_bytes,
                    "assignment construction peak");
    admit_peak(
        result.storage,
        result.storage.assignment_construction_peak_live_storage_bytes);

    const spartan::BaseFoldArtifactColumn witness_column =
        witness_commitment_column(witness_layout);
    progress_boundary(
        progress, RuntimeProgressBoundary::Begin,
        RuntimeProgressStage::TranscriptPackingSpartanWitnessCommitment);
    auto nested_witness_progress =
        std::move(options.witness_commitment.progress);
    options.witness_commitment.progress =
        [progress, nested_witness_progress =
                       std::move(nested_witness_progress)](
            const spartan::BaseFoldExternalCommitProgress &sample) noexcept {
            report_witness_commitment_progress(progress, sample);
            if (nested_witness_progress) {
                try {
                    nested_witness_progress(sample);
                } catch (...) {
                    // Progress callbacks are advisory and must not affect the
                    // proof or its transcript.
                }
            }
        };
    spartan::BaseFoldExternalCommitment witness_commitment =
        pcs.commit_artifact_columns(
            assignment.artifact,
            std::span<const spartan::BaseFoldArtifactColumn>(
                &witness_column, 1),
            std::move(options.witness_commitment));
    progress_boundary(
        progress, RuntimeProgressBoundary::End,
        RuntimeProgressStage::TranscriptPackingSpartanWitnessCommitment,
        witness_commitment.report.final_physical_bytes);
    if (witness_commitment.externalization.commitment.evaluation_count !=
            metadata.assignment_half_size() ||
        witness_commitment.externalization.commitment.width != 1) {
        throw std::logic_error(
            "external packing witness commitment has the wrong shape");
    }
    if (witness_commitment.report.final_physical_bytes !=
            result.storage.witness_state_physical_bytes ||
        witness_commitment.report.scratch_peak_physical_bytes !=
            witness_commit_plan.scratch_peak_physical_bytes ||
        witness_commitment.report.peak_working_field_bytes !=
            witness_commit_plan.peak_working_field_bytes) {
        throw std::logic_error(
            "witness commitment disagrees with aggregate preflight");
    }
    result.witness_commitment = witness_commitment.report;
    result.storage.witness_state_physical_bytes =
        witness_commitment.report.final_physical_bytes;
    result.storage.witness_commitment_peak_live_storage_bytes = storage_sum(
        {result.storage.persistent_input_physical_bytes,
         result.storage.assignment_physical_bytes,
         result.storage.witness_state_physical_bytes,
         witness_commitment.report.scratch_peak_physical_bytes},
        "witness commitment peak");
    admit_peak(
        result.storage,
        result.storage.witness_commitment_peak_live_storage_bytes);

    progress_boundary(
        progress, RuntimeProgressBoundary::Begin,
        RuntimeProgressStage::TranscriptPackingSpartanMatrixProducts);
    ProofOfPackingMatrixProductArtifact matrix_products =
        write_proof_of_packing_matrix_product_artifact_admitted_sources(
            plan, layout, metadata, *assignment.artifact,
            outer_assignment, *key.factored_computation,
            std::move(options.matrix_products));
    progress_boundary(
        progress, RuntimeProgressBoundary::End,
        RuntimeProgressStage::TranscriptPackingSpartanMatrixProducts,
        matrix_products.report.physical_bytes);
    if (matrix_products.report.physical_bytes !=
            result.storage.matrix_products_physical_bytes ||
        matrix_products.report.peak_working_field_bytes !=
            matrix_product_plan.peak_working_field_bytes) {
        throw std::logic_error(
            "matrix-product artifact disagrees with aggregate preflight");
    }
    result.matrix_products = matrix_products.report;
    result.storage.matrix_products_physical_bytes =
        matrix_products.report.physical_bytes;
    result.storage.matrix_product_construction_peak_live_storage_bytes =
        storage_sum(
            {result.storage.persistent_input_physical_bytes,
             result.storage.assignment_physical_bytes,
             result.storage.witness_state_physical_bytes,
             result.storage.matrix_products_physical_bytes},
            "matrix-product construction peak");
    result.storage.pre_fiat_shamir_live_storage_bytes =
        result.storage.matrix_product_construction_peak_live_storage_bytes;
    admit_peak(
        result.storage,
        result.storage.matrix_product_construction_peak_live_storage_bytes);

    spartan::BaseFoldExternalOpeningAdmission witness_admission =
        pcs.admit_external_opening(
            witness_commitment.externalization.prover_state,
            witness_commitment.externalization.commitment,
            options.witness_opening);
    const spartan::BaseFoldExternalOpeningPreflight &witness_plan =
        witness_admission.preflight();
    if (witness_plan.state_artifact_physical_bytes !=
            impl->witness_opening_plan.state_artifact_physical_bytes ||
        witness_plan.required_scratch_physical_bytes !=
            impl->witness_opening_plan.scratch_peak_physical_bytes ||
        witness_plan.required_working_field_bytes !=
            impl->witness_opening_plan.required_working_field_bytes ||
        witness_plan.materialized_sumcheck_entries !=
            impl->witness_opening_plan.materialized_sumcheck_entries) {
        throw std::logic_error(
            "witness opening disagrees with aggregate admission");
    }
    const std::vector<Fq> public_inputs =
        read_public_inputs(*assignment.artifact, metadata);
    spartan::bind_public_statement(key.setup_digest, public_inputs,
                                   public_coin);
    result.proof.witness_commitment =
        witness_commitment.externalization.commitment;
    spartan::bind_witness_commitment(result.proof.witness_commitment,
                                     public_coin);

    const std::vector<Fq2> tau =
        public_coin.challenge_fq2_vector(metadata.row_variables());
    bind_expected_identity(
        options.constraint_sumcheck.expected_source_identity,
        matrix_products.artifact->identity(),
        "ConstraintCheck source");
    progress_boundary(
        progress, RuntimeProgressBoundary::Begin,
        RuntimeProgressStage::TranscriptPackingSpartanConstraintCheck);
    const spartan::ConstraintSumcheckArtifactOutput constraint =
        spartan::prove_constraint_sumcheck_artifact(
            *matrix_products.artifact,
            {.az = "az", .bz = "bz", .cz = "cz"}, tau, public_coin,
            std::move(options.constraint_sumcheck));
    progress_boundary(
        progress, RuntimeProgressBoundary::End,
        RuntimeProgressStage::TranscriptPackingSpartanConstraintCheck,
        matrix_products.report.stored_constraint_elements);
    result.constraint_sumcheck = constraint.report;
    if (constraint.report.scratch_peak_physical_bytes !=
            constraint_scratch ||
        constraint.report.peak_working_field_bytes !=
            impl->constraint_plan.peak_working_field_bytes ||
        constraint.report.effective_block_elements !=
            impl->constraint_plan.effective_block_elements) {
        throw std::logic_error(
            "ConstraintCheck disagrees with aggregate preflight");
    }
    result.proof.constraint_sumcheck = constraint.sumcheck.proof;
    result.proof.az_evaluation = constraint.sumcheck.az_evaluation;
    result.proof.bz_evaluation = constraint.sumcheck.bz_evaluation;
    result.proof.cz_evaluation = constraint.sumcheck.cz_evaluation;
    spartan::bind_constraint_terminal(
        result.proof.az_evaluation, result.proof.bz_evaluation,
        result.proof.cz_evaluation, public_coin);
    const Fq2 gamma = public_coin.challenge_fq2();

    progress_boundary(
        progress, RuntimeProgressBoundary::Begin,
        RuntimeProgressStage::TranscriptPackingSpartanRetirement,
        matrix_products.report.physical_bytes);
    matrix_products.artifact.reset();
    roots.retire(paths.matrix_products);
    progress_boundary(
        progress, RuntimeProgressBoundary::End,
        RuntimeProgressStage::TranscriptPackingSpartanRetirement,
        result.matrix_products.physical_bytes);

    progress_boundary(
        progress, RuntimeProgressBoundary::Begin,
        RuntimeProgressStage::TranscriptPackingSpartanWiringMatrix);
    ProofOfPackingWiringArtifact wiring_matrix =
        write_proof_of_packing_wiring_matrix_artifact_admitted_source(
            plan, layout, metadata, *key.factored_computation,
            constraint.sumcheck.point, gamma,
            std::move(options.wiring_matrix));
    progress_boundary(
        progress, RuntimeProgressBoundary::End,
        RuntimeProgressStage::TranscriptPackingSpartanWiringMatrix,
        wiring_matrix.report.physical_bytes);
    result.wiring_matrix = wiring_matrix.report;
    if (wiring_matrix.report.physical_bytes !=
            result.storage.wiring_matrix_physical_bytes ||
        wiring_matrix.report.peak_working_field_bytes !=
            impl->wiring_matrix_plan.peak_working_field_bytes ||
        wiring_matrix.report.effective_block_elements !=
            impl->wiring_matrix_plan.effective_block_elements) {
        throw std::logic_error(
            "Wiring artifact disagrees with aggregate preflight");
    }
    const Fq2 wiring_claim =
        result.proof.az_evaluation + gamma * result.proof.bz_evaluation +
        (gamma * gamma) * result.proof.cz_evaluation;
    bind_expected_identity(
        options.wiring_sumcheck.expected_matrix_identity,
        wiring_matrix.artifact->identity(),
        "WiringCheck matrix source");
    bind_expected_identity(
        options.wiring_sumcheck.expected_assignment_identity,
        assignment.artifact->identity(),
        "WiringCheck assignment source");
    progress_boundary(
        progress, RuntimeProgressBoundary::Begin,
        RuntimeProgressStage::TranscriptPackingSpartanWiringCheck);
    const spartan::WiringSumcheckArtifactOutput wiring =
        spartan::prove_wiring_sumcheck_artifact(
            *wiring_matrix.artifact, *assignment.artifact,
            {.matrix_public =
                 std::string(kProofOfPackingWiringPublicColumns),
             .matrix_witness =
                 std::string(kProofOfPackingWiringWitnessColumns),
             .assignment_public =
                 std::string(kProofOfPackingAssignmentPublicInputs),
             .assignment_witness =
                 std::string(kProofOfPackingAssignmentWitnessValues)},
            wiring_assignment_layout(witness_layout), wiring_claim,
            public_coin, std::move(options.wiring_sumcheck));
    progress_boundary(
        progress, RuntimeProgressBoundary::End,
        RuntimeProgressStage::TranscriptPackingSpartanWiringCheck,
        metadata.assignment_half_size() * 2U);
    result.wiring_sumcheck = wiring.report;
    if (wiring.report.scratch_peak_physical_bytes != wiring_scratch ||
        wiring.report.peak_working_field_bytes !=
            impl->wiring_sumcheck_plan.peak_working_field_bytes ||
        wiring.report.effective_block_elements !=
            impl->wiring_sumcheck_plan.effective_block_elements) {
        throw std::logic_error(
            "WiringCheck disagrees with aggregate preflight");
    }
    result.proof.wiring_sumcheck = wiring.sumcheck.proof;
    result.proof.matrix_evaluation = wiring.sumcheck.matrix_evaluation;
    result.proof.assignment_evaluation =
        wiring.sumcheck.assignment_evaluation;
    spartan::bind_wiring_terminal(
        result.proof.matrix_evaluation,
        result.proof.assignment_evaluation, public_coin);

    progress_boundary(
        progress, RuntimeProgressBoundary::Begin,
        RuntimeProgressStage::TranscriptPackingSpartanRetirement,
        storage_add(assignment.report.physical_bytes,
                    wiring_matrix.report.physical_bytes,
                    "Wiring retirement bytes"));
    assignment.artifact.reset();
    wiring_matrix.artifact.reset();
    roots.retire(paths.assignment);
    roots.retire(paths.wiring_matrix);
    progress_boundary(
        progress, RuntimeProgressBoundary::End,
        RuntimeProgressStage::TranscriptPackingSpartanRetirement,
        storage_add(result.assignment.physical_bytes,
                    result.wiring_matrix.physical_bytes,
                    "Wiring retirement bytes"));

    progress_boundary(
        progress, RuntimeProgressBoundary::Begin,
        RuntimeProgressStage::TranscriptPackingSpartanFactoredOpenings);
    const spartan::FactoredMatrixExternalProving factored =
        spartan::prove_factored_matrix_evaluation_external_admitted(
            *key.factored_computation, constraint.sumcheck.point,
            wiring.sumcheck.point, gamma,
            result.proof.matrix_evaluation, pcs,
            std::move(options.factored_evaluation),
            std::move(factored_admissions), public_coin);
    progress_boundary(
        progress, RuntimeProgressBoundary::End,
        RuntimeProgressStage::TranscriptPackingSpartanFactoredOpenings,
        factored.report.proof_bytes);
    result.proof.factored_evaluation = factored.proof;
    result.factored_evaluation = factored.report;
    if (factored.report.peak_live_storage_bytes !=
            result.storage.factored_evaluation_peak_live_storage_bytes ||
        factored.report.peak_working_field_bytes !=
            impl->factored_plan.report.peak_working_field_bytes) {
        throw std::logic_error(
            "factored evaluation disagrees with aggregate preflight");
    }

    const Fq2 witness_evaluation =
        spartan::derive_witness_opening_evaluation(
            public_inputs, metadata, wiring.sumcheck.point,
            result.proof.assignment_evaluation);
    const std::span<const Fq2> witness_point =
        std::span<const Fq2>(wiring.sumcheck.point).subspan(1);
    progress_boundary(
        progress, RuntimeProgressBoundary::Begin,
        RuntimeProgressStage::TranscriptPackingSpartanWitnessOpening);
    const spartan::BaseFoldExternalOpening witness_opening =
        pcs.open_external_admitted(
            std::move(witness_admission), witness_point,
            witness_evaluation, public_coin);
    progress_boundary(
        progress, RuntimeProgressBoundary::End,
        RuntimeProgressStage::TranscriptPackingSpartanWitnessOpening,
        witness_opening.report.proof_bytes);
    result.proof.witness_opening = witness_opening.proof;
    result.witness_opening = witness_opening.report;
    if (storage_add(result.storage.persistent_input_physical_bytes,
                    witness_opening.report.peak_live_storage_bytes,
                    "witness opening measured aggregate peak") !=
        result.storage.witness_opening_peak_live_storage_bytes) {
        throw std::logic_error(
            "witness opening disagrees with aggregate preflight");
    }

    progress_boundary(
        progress, RuntimeProgressBoundary::Begin,
        RuntimeProgressStage::TranscriptPackingSpartanRetirement,
        witness_commitment.report.final_physical_bytes);
    witness_commitment.externalization.prover_state.reset();
    roots.retire(paths.witness_state);
    progress_boundary(
        progress, RuntimeProgressBoundary::End,
        RuntimeProgressStage::TranscriptPackingSpartanRetirement,
        result.witness_commitment.final_physical_bytes);
    roots.finish();
    return result;
}

ProofOfPackingExternalSpartanResult prove_proof_of_packing_spartan_external(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::ExternalProverKey &key,
    const storage::NativeFieldArtifact &outer_assignment,
    std::span<const gkr::HashCommitCT> commitments,
    const spartan::BaseFoldPcs &pcs,
    ProofOfPackingExternalSpartanOptions options,
    PublicCoin &public_coin,
    const RuntimeProgressCallback &progress) {
    auto retained_pcs = std::make_shared<const spartan::BaseFoldPcs>(pcs);
    ProofOfPackingExternalSpartanAdmission admission =
        detail::ProofOfPackingExternalSpartanAdmissionFactory::admit(
            plan, layout, key, outer_assignment.directory(),
            commitments.size(),
            std::move(retained_pcs), std::move(options), false);
    // The direct API admits an already-published outer assignment, so bind
    // commitments here without applying the future-root emptiness check.
    admission.impl_->roots->validate_for_late_binding();
    admission.impl_->commitments.assign(
        commitments.begin(), commitments.end());
    admission.impl_->commitments_bound = true;
    return prove_proof_of_packing_spartan_external_admitted(
        std::move(admission), outer_assignment, public_coin, progress);
}

} // namespace laminate::packing
