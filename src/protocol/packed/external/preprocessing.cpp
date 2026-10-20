/// @file preprocessing.cpp
/// @brief Formula-only, bounded preprocessing for external transcript packing.

#include "laminate/protocol/packed/external/preprocessing.hpp"

#include "laminate/packing/proof/matrix/oracle.hpp"

#include <algorithm>
#include <bit>
#include <cerrno>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace laminate::protocol {
namespace {

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

void validate_variant(PackingGkrVariant variant) {
    if (variant != PackingGkrVariant::Folded &&
        variant != PackingGkrVariant::Laned) {
        throw std::invalid_argument(
            "external transcript-packing preprocessing has an unknown "
            "variant");
    }
}

std::filesystem::path normalize_empty_directory(
    const std::filesystem::path &requested, const char *label) {
    if (requested.empty()) {
        throw std::invalid_argument(std::string(label) + " path is empty");
    }
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(requested);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status)) {
        throw std::invalid_argument(std::string(label) +
                                    " must be a real directory");
    }
    if (!std::filesystem::is_empty(requested)) {
        throw std::invalid_argument(std::string(label) +
                                    " must be empty");
    }
    return std::filesystem::canonical(requested);
}

bool path_prefix(const std::filesystem::path &prefix,
                 const std::filesystem::path &path) {
    auto prefix_part = prefix.begin();
    auto path_part = path.begin();
    while (prefix_part != prefix.end() && path_part != path.end() &&
           *prefix_part == *path_part) {
        ++prefix_part;
        ++path_part;
    }
    return prefix_part == prefix.end();
}

bool same_device(const std::filesystem::path &left,
                 const std::filesystem::path &right) {
#ifdef _WIN32
    return left.root_name() == right.root_name();
#else
    struct stat left_status {};
    struct stat right_status {};
    if (::stat(left.c_str(), &left_status) != 0) {
        throw std::filesystem::filesystem_error(
            "failed to inspect setup storage device", left,
            std::error_code(errno, std::generic_category()));
    }
    if (::stat(right.c_str(), &right_status) != 0) {
        throw std::filesystem::filesystem_error(
            "failed to inspect setup storage device", right,
            std::error_code(errno, std::generic_category()));
    }
    return left_status.st_dev == right_status.st_dev;
#endif
}

void validate_owner_private_directory(
    const std::filesystem::path &directory, const char *label) {
#ifndef _WIN32
    struct stat status {};
    if (::stat(directory.c_str(), &status) != 0) {
        throw std::filesystem::filesystem_error(
            std::string("failed to inspect ") + label, directory,
            std::error_code(errno, std::generic_category()));
    }
    if (status.st_uid != ::geteuid() ||
        (status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        throw std::invalid_argument(
            std::string(label) + " must be owner-private");
    }
#else
    (void)directory;
    (void)label;
#endif
}

struct AdmittedRootIdentity {
    std::filesystem::path path;
#ifndef _WIN32
    std::uintmax_t device = 0;
    std::uintmax_t inode = 0;
#endif
};

AdmittedRootIdentity capture_root_identity(
    const std::filesystem::path &path) {
    AdmittedRootIdentity result{.path = path};
#ifndef _WIN32
    struct stat status {};
    if (::lstat(path.c_str(), &status) != 0) {
        throw std::filesystem::filesystem_error(
            "failed to bind setup root identity", path,
            std::error_code(errno, std::generic_category()));
    }
    if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) {
        throw std::invalid_argument(
            "setup root identity is not a real directory");
    }
    result.device = static_cast<std::uintmax_t>(status.st_dev);
    result.inode = static_cast<std::uintmax_t>(status.st_ino);
#endif
    return result;
}

bool same_root_identity(const AdmittedRootIdentity &expected) {
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

std::uint64_t directory_regular_bytes(
    const std::filesystem::path &directory) {
    std::uint64_t result = 0;
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(directory)) {
        const std::filesystem::file_status status = entry.symlink_status();
        if (std::filesystem::is_symlink(status)) {
            throw std::runtime_error(
                "setup artifact unexpectedly contains a symbolic link");
        }
        if (std::filesystem::is_regular_file(status)) {
            result = checked_add(result, entry.file_size(),
                                 "setup artifact physical bytes");
        }
    }
    return result;
}

struct AdmittedResources {
    TranscriptPackingExternalPreprocessingResources resources;
    std::filesystem::perms staging_permissions =
        std::filesystem::perms::unknown;
    std::vector<AdmittedRootIdentity> roots;
};

std::uint64_t maximum_free_space_reserve(
    const TranscriptPackingExternalPreprocessingLimits &limits) {
    std::uint64_t result = std::max(
        limits.staging_artifact.min_free_bytes,
        limits.canonical_tensor_artifact.min_free_bytes);
    for (const TranscriptPackingExternalTensorLimits &tensor :
         limits.tensors) {
        result = std::max(result, tensor.min_free_bytes);
    }
    return result;
}

AdmittedResources admit_resources(
    const TranscriptPackingExternalPreprocessingPlan &plan,
    TranscriptPackingExternalPreprocessingResources resources,
    const TranscriptPackingExternalPreprocessingLimits &limits) {
    const std::size_t tensor_count = plan.factored.tensors.size();
    if (resources.tensors.size() != tensor_count ||
        limits.tensors.size() != tensor_count ||
        limits.staging_artifact.min_free_bytes == 0 ||
        limits.canonical_tensor_artifact.min_free_bytes == 0 ||
        limits.staging_artifact.max_total_bytes <
            plan.staging.artifact_physical_bytes ||
        limits.max_staging_working_bytes <
            plan.staging.peak_working_bytes ||
        limits.canonical_tensor_artifact.max_total_bytes <
            plan.factored.canonical_artifact_physical_bytes ||
        limits.max_live_physical_bytes <
            plan.factored.conservative_peak_live_physical_bytes ||
        limits.max_copy_working_field_bytes <
            plan.factored.peak_copy_working_field_bytes) {
        throw std::invalid_argument(
            "external transcript-packing setup limits fail formula "
            "admission");
    }
    for (std::size_t tensor = 0; tensor < tensor_count; ++tensor) {
        const TranscriptPackingExternalTensorLimits &selected =
            limits.tensors[tensor];
        const spartan::FactoredTensorExternalPreprocessingPlan &required =
            plan.factored.tensors[tensor];
        if (selected.min_free_bytes == 0 ||
            selected.max_final_physical_bytes <
                required.commitment.final_physical_bytes ||
            selected.max_scratch_physical_bytes <
                required.commitment.scratch_peak_physical_bytes ||
            selected.max_working_field_bytes <
                required.commitment.peak_working_field_bytes) {
            throw std::invalid_argument(
                "external transcript-packing tensor limits fail formula "
                "admission");
        }
    }

    resources.staging_directory = normalize_empty_directory(
        resources.staging_directory, "packing tensor staging");
    resources.canonical_tensor_directory = normalize_empty_directory(
        resources.canonical_tensor_directory,
        "canonical packing tensor artifact");
    resources.staging_quarantine_directory = normalize_empty_directory(
        resources.staging_quarantine_directory,
        "packing tensor staging quarantine");
    if (!same_device(resources.staging_directory,
                     resources.staging_quarantine_directory)) {
        throw std::invalid_argument(
            "packing tensor staging and quarantine must share a device");
    }

    std::vector<std::filesystem::path> root_paths;
    root_paths.reserve(3U + 2U * tensor_count);
    root_paths.push_back(resources.staging_directory);
    root_paths.push_back(resources.canonical_tensor_directory);
    root_paths.push_back(resources.staging_quarantine_directory);
    for (std::size_t tensor = 0; tensor < tensor_count; ++tensor) {
        TranscriptPackingExternalTensorResources &selected =
            resources.tensors[tensor];
        selected.state_directory = normalize_empty_directory(
            selected.state_directory, "packing tensor BaseFold state");
        selected.scratch_directory = normalize_empty_directory(
            selected.scratch_directory,
            "packing tensor BaseFold scratch");
        root_paths.push_back(selected.state_directory);
        root_paths.push_back(selected.scratch_directory);
    }
    for (const std::filesystem::path &root : root_paths) {
        validate_owner_private_directory(root, "packing setup root");
    }
    for (std::size_t left = 0; left < root_paths.size(); ++left) {
        for (std::size_t right = left + 1U; right < root_paths.size();
             ++right) {
            std::error_code equivalent_error;
            const bool equivalent = std::filesystem::equivalent(
                root_paths[left], root_paths[right], equivalent_error);
            if (equivalent_error) {
                throw std::filesystem::filesystem_error(
                    "failed to compare setup storage paths",
                    root_paths[left], root_paths[right], equivalent_error);
            }
            if (equivalent ||
                path_prefix(root_paths[left], root_paths[right]) ||
                path_prefix(root_paths[right], root_paths[left])) {
                throw std::invalid_argument(
                    "all external transcript-packing setup roots must be "
                    "disjoint");
            }
        }
    }

    // A single conservative check on every named device ensures that every
    // more local lower-layer check remains valid after staging and earlier
    // states have been published. The caller owns these namespaces and must
    // not consume their free space concurrently with setup.
    const std::uint64_t required_free = checked_add(
        plan.factored.conservative_peak_live_physical_bytes,
        maximum_free_space_reserve(limits),
        "external transcript-packing setup free-space requirement");
    for (const std::filesystem::path &root : root_paths) {
        if (std::filesystem::space(root).available < required_free) {
            throw std::runtime_error(
                "external transcript-packing setup has insufficient free "
                "space");
        }
    }

    std::vector<AdmittedRootIdentity> roots;
    roots.reserve(root_paths.size());
    for (const std::filesystem::path &root : root_paths) {
        roots.push_back(capture_root_identity(root));
    }
    return AdmittedResources{
        .resources = std::move(resources),
        .staging_permissions = std::filesystem::symlink_status(
                                   root_paths.front())
                                   .permissions(),
        .roots = std::move(roots),
    };
}

class SetupOutputTransaction {
  public:
    explicit SetupOutputTransaction(const AdmittedResources &admission)
        : roots_(admission.roots),
          staging_(admission.resources.staging_directory),
          staging_permissions_(admission.staging_permissions) {}

    SetupOutputTransaction(const SetupOutputTransaction &) = delete;
    SetupOutputTransaction &operator=(const SetupOutputTransaction &) =
        delete;

    ~SetupOutputTransaction() {
        if (armed_) {
            rollback_noexcept();
        }
    }

    void restore_empty_staging() {
        if (std::filesystem::exists(staging_)) {
            throw std::runtime_error(
                "retired packing staging path unexpectedly reappeared");
        }
        if (!std::filesystem::create_directory(staging_)) {
            throw std::runtime_error(
                "failed to restore empty packing staging directory");
        }
        std::filesystem::permissions(
            staging_, staging_permissions_,
            std::filesystem::perm_options::replace);
        if (!std::filesystem::is_empty(staging_)) {
            throw std::runtime_error(
                "restored packing staging directory is not empty");
        }
        const auto found = std::find_if(
            roots_.begin(), roots_.end(), [&](const auto &root) {
                return root.path == staging_;
            });
        if (found == roots_.end()) {
            throw std::logic_error(
                "restored staging root is absent from setup admission");
        }
        *found = capture_root_identity(staging_);
    }

    void rollback() {
        for (const AdmittedRootIdentity &root : roots_) {
            clear_root(root, root.path == staging_);
        }
        if (!std::filesystem::exists(staging_)) {
            restore_empty_staging();
        }
        armed_ = false;
    }

    void commit() { armed_ = false; }

  private:
    static void clear_root(const AdmittedRootIdentity &root,
                           bool allow_missing) {
        if (!std::filesystem::exists(root.path)) {
            if (allow_missing) {
                return;
            }
            throw std::runtime_error(
                "admitted setup root disappeared before cleanup");
        }
        if (!same_root_identity(root)) {
            throw std::runtime_error(
                "refusing to clear a replaced setup root");
        }
        for (auto entry = std::filesystem::directory_iterator(root.path);
             entry != std::filesystem::directory_iterator();) {
            const std::filesystem::path child = entry->path();
            ++entry;
            std::filesystem::remove_all(child);
        }
        if (!std::filesystem::is_empty(root.path)) {
            throw std::runtime_error(
                "external transcript-packing setup cleanup is incomplete");
        }
    }

    void rollback_noexcept() noexcept {
        try {
            rollback();
        } catch (...) {
            // Destructors cannot report a second failure. The explicit catch
            // path below invokes rollback() and reports cleanup failures.
        }
    }

    std::vector<AdmittedRootIdentity> roots_;
    std::filesystem::path staging_;
    std::filesystem::perms staging_permissions_;
    bool armed_ = true;
};

spartan::FactoredMatrixExternalPreprocessingOptions make_factored_options(
    const TranscriptPackingExternalPreprocessingSpecification &specification,
    const AdmittedResources &admission,
    const TranscriptPackingExternalPreprocessingLimits &limits) {
    spartan::FactoredMatrixExternalPreprocessingOptions result{
        .tensor_columns_artifact = {
            .directory =
                admission.resources.canonical_tensor_directory,
            .limits = limits.canonical_tensor_artifact,
        },
        .staging_ownership =
            spartan::FactoredMatrixStagingOwnership::
                MoveToQuarantineOnSuccess,
        .staging_quarantine_directory =
            admission.resources.staging_quarantine_directory,
        .max_live_physical_bytes = limits.max_live_physical_bytes,
        .max_copy_working_field_bytes =
            limits.max_copy_working_field_bytes,
        .copy_block_elements =
            specification.canonical_copy_block_elements,
    };
    result.tensor_commitments.reserve(admission.resources.tensors.size());
    for (std::size_t tensor = 0;
         tensor < admission.resources.tensors.size(); ++tensor) {
        const TranscriptPackingExternalTensorResources &resources =
            admission.resources.tensors[tensor];
        const TranscriptPackingExternalTensorLimits &selected =
            limits.tensors[tensor];
        result.tensor_commitments.push_back({
            .destination_directory = resources.state_directory,
            .scratch_directory = resources.scratch_directory,
            .max_final_bytes = selected.max_final_physical_bytes,
            .max_scratch_bytes = selected.max_scratch_physical_bytes,
            .min_free_bytes = selected.min_free_bytes,
            .max_working_field_bytes =
                selected.max_working_field_bytes,
            .block_elements = specification.basefold_block_elements,
        });
    }
    return result;
}

void reconcile_reports(
    const TranscriptPackingExternalPreprocessingPlan &plan,
    const packing::ProofOfPackingTensorStagingReport &staging,
    const spartan::FactoredMatrixExternalPreprocessingReport &factored) {
    const spartan::FactoredMatrixExternalPreprocessingPlan &expected =
        plan.factored;
    if (!(staging.plan == plan.staging) ||
        staging.artifact_physical_bytes !=
            plan.staging.artifact_physical_bytes ||
        factored.staging_physical_bytes !=
            expected.staging_physical_bytes ||
        factored.canonical_artifact_physical_bytes !=
            expected.canonical_artifact_physical_bytes ||
        factored.external_states_physical_bytes !=
            expected.external_states_physical_bytes ||
        factored.persistent_output_physical_bytes !=
            expected.persistent_output_physical_bytes ||
        factored.conservative_peak_live_physical_bytes !=
            expected.conservative_peak_live_physical_bytes ||
        factored.peak_copy_working_field_bytes !=
            expected.peak_copy_working_field_bytes ||
        factored.peak_working_field_bytes !=
            expected.peak_working_field_bytes ||
        factored.retained_staging_physical_bytes != 0 ||
        factored.quarantined_staging_physical_bytes !=
            expected.staging_physical_bytes ||
        factored.final_live_physical_bytes !=
            checked_add(expected.persistent_output_physical_bytes,
                        expected.staging_physical_bytes,
                        "pre-retirement setup bytes") ||
        factored.tensors.size() != expected.tensors.size()) {
        throw std::logic_error(
            "external transcript-packing setup report differs from its "
            "formula plan");
    }
    for (std::size_t tensor = 0; tensor < expected.tensors.size(); ++tensor) {
        if (!(factored.tensors[tensor].shape ==
              expected.tensors[tensor].shape) ||
            factored.tensors[tensor].commitment.final_physical_bytes !=
                expected.tensors[tensor]
                    .commitment.final_physical_bytes ||
            factored.tensors[tensor]
                    .commitment.scratch_peak_physical_bytes !=
                expected.tensors[tensor]
                    .commitment.scratch_peak_physical_bytes ||
            factored.tensors[tensor]
                    .commitment.peak_working_field_bytes !=
                expected.tensors[tensor]
                    .commitment.peak_working_field_bytes) {
            throw std::logic_error(
                "external transcript-packing tensor report differs from "
                "its formula plan");
        }
    }
}

void retire_staging(
    const AdmittedResources &admission,
    const packing::ProofOfPackingStructuredMetadata &relation,
    const spartan::FactoredMatrixStructure &structure,
    const spartan::FactoredMatrixExternalPreprocessingReport &report,
    SetupOutputTransaction &transaction) {
    const std::filesystem::path expected =
        admission.resources.staging_quarantine_directory /
        "staging-artifact";
    if (report.staging_quarantine_artifact_path.empty() ||
        std::filesystem::canonical(
            report.staging_quarantine_artifact_path) !=
            std::filesystem::canonical(expected)) {
        throw std::logic_error(
            "external packing setup quarantined an unexpected artifact");
    }
    std::shared_ptr<const storage::NativeFieldArtifact> rebound =
        spartan::open_factored_matrix_staging_artifact(expected, structure);
    if (rebound->physical_bytes() !=
            report.quarantined_staging_physical_bytes ||
        rebound->identity() !=
            spartan::factored_matrix_staging_artifact_identity(structure) ||
        structure.circuit_digest() !=
            relation.circuit_metadata.digest()) {
        throw std::logic_error(
            "quarantined packing staging artifact failed retirement "
            "binding");
    }
    rebound.reset();
    if (directory_regular_bytes(expected) !=
        report.quarantined_staging_physical_bytes) {
        throw std::runtime_error(
            "quarantined packing staging bytes changed before retirement");
    }
    std::filesystem::remove_all(expected);
    if (!std::filesystem::is_empty(
            admission.resources.staging_quarantine_directory)) {
        throw std::runtime_error(
            "packing staging quarantine cleanup is incomplete");
    }
    transaction.restore_empty_staging();
}

} // namespace

TranscriptPackingExternalPreprocessingPlan
plan_transcript_packing_external_preprocessing(
    const TranscriptPackingExternalPreprocessingSpecification &specification) {
    validate_variant(specification.variant);
    specification.ciphertext_commitment_policy.validate();
    if (specification.ring_degree < 32U ||
        !std::has_single_bit(specification.ring_degree) ||
        specification.bhip_round_count == 0 ||
        specification.staging_block_elements == 0 ||
        specification.canonical_copy_block_elements == 0 ||
        specification.basefold_block_elements == 0 ||
        specification.basefold_parameters.log_rate == 0) {
        throw std::invalid_argument(
            "external transcript-packing preprocessing has invalid "
            "geometry or streaming blocks");
    }
    specification.parameters.packing_radix.validate();
    if (specification.parameters.repetitions == 0 ||
        specification.parameters.packing_radix.plaintext_modulus !=
            kBaseFieldOrder) {
        throw std::invalid_argument(
            "external transcript-packing preprocessing has invalid test "
            "parameters");
    }

    // Constructing the PCS validates query/rate parameters but creates no
    // state. Its storage planner is formula-only.
    const spartan::BaseFoldPcs pcs(specification.basefold_parameters);
    const packing::PackingLayout alignment_layout =
        packing::make_fixed_message_coset_packing_layout(
            specification.ring_degree,
            specification.bhip_round_count,
            specification.ring_degree /
                fhe::kFixedMessageCellCount);
    packing::ProofOfPackingStructuredMetadata relation =
        packing::make_proof_of_packing_structured_metadata(
            alignment_layout, specification.parameters,
            specification.ciphertext_commitment_policy);
    relation.validate();
    if (relation.packing_operator.source_ciphertext_count !=
            specification.bhip_round_count ||
        relation.packing_operator.aligned_ciphertext_count !=
            specification.bhip_round_count ||
        relation.parameters.packing_radix !=
            specification.parameters.packing_radix ||
        relation.relation_plan.shape.ciphertext_commitment_policy !=
            specification.ciphertext_commitment_policy) {
        throw std::logic_error(
            "formula-derived packing operator or radix is inconsistent");
    }

    TranscriptPackingExternalPreprocessingPlan result{
        .variant = specification.variant,
        .bhip_round_count = specification.bhip_round_count,
        .relation = std::move(relation),
    };
    result.staging = packing::plan_proof_of_packing_tensor_staging(
        result.relation, result.relation.packing_operator,
        result.relation.parameters.packing_radix,
        specification.staging_block_elements);
    const auto structure =
        packing::make_proof_of_packing_factored_structure(
            result.relation.relation_plan, result.relation.r1cs_layout,
            result.relation.tensor_mappings,
            result.relation.circuit_metadata);
    result.factored = spartan::plan_factored_matrix_external_preprocessing(
        *structure, pcs,
        {
            .staging_physical_bytes =
                result.staging.artifact_physical_bytes,
            .copy_block_elements =
                specification.canonical_copy_block_elements,
            .tensor_commitment_block_elements =
                std::vector<std::size_t>(
                    structure->tensor_count(),
                    specification.basefold_block_elements),
        });
    result.peak_working_bytes = std::max(
        result.staging.peak_working_bytes,
        result.factored.peak_working_field_bytes);
    return result;
}

TranscriptPackingExternalPreprocessing
preprocess_transcript_packing_external(
    const TranscriptPackingExternalPreprocessingSpecification &specification,
    packing::ProofOfPackingR1csEncoders encoders,
    TranscriptPackingExternalPreprocessingResources resources,
    TranscriptPackingExternalPreprocessingLimits limits) {
    const TranscriptPackingExternalPreprocessingPlan plan =
        plan_transcript_packing_external_preprocessing(specification);
    if (!encoders.centered_coefficients || !encoders.native_ntt) {
        throw std::invalid_argument(
            "external transcript-packing preprocessing needs both public "
            "encoders");
    }
    const AdmittedResources admission = admit_resources(
        plan, std::move(resources), limits);
    validate_selected_packing_well_formedness(
        plan.relation.packing_operator, encoders.centered_coefficients,
        specification.parameters, specification.ciphertext_commitment_policy);
    SetupOutputTransaction transaction(admission);
    try {
        packing::ProofOfPackingTensorStaging staged =
            packing::write_proof_of_packing_tensor_staging(
                plan.relation, plan.relation.packing_operator,
                std::move(encoders),
                plan.relation.parameters.packing_radix,
                {
                    .directory = admission.resources.staging_directory,
                    .storage_limits = limits.staging_artifact,
                    .max_working_bytes =
                        limits.max_staging_working_bytes,
                    .block_elements =
                        specification.staging_block_elements,
                });

        const auto pcs = std::make_shared<const spartan::BaseFoldPcs>(
            specification.basefold_parameters);
        spartan::FactoredMatrixExternalPreprocessing factored =
            spartan::preprocess_factored_matrix_external(
                staged.structure, std::move(staged.artifact), *pcs,
                make_factored_options(specification, admission, limits));
        reconcile_reports(plan, staged.report, factored.report);

        const auto factored_prover =
            std::make_shared<const spartan::FactoredMatrixProverKey>(
                std::move(factored.setup.prover_key));
        const auto factored_verifier =
            std::make_shared<const spartan::FactoredMatrixVerifierKey>(
                std::move(factored.setup.verifier_key));
        spartan::ExternalSetup external =
            spartan::setup_external_committed_factored(
                plan.relation.circuit_metadata, *pcs, factored_prover,
                factored_verifier);
        TranscriptPackingExternalProverSetup prover =
            make_transcript_packing_external_prover_setup(
                specification.variant, specification.bhip_round_count,
                plan.relation, pcs,
                std::move(external.prover_key));
        TranscriptPackingSpartanVerifierSetup verifier{
            .variant = specification.variant,
            .bhip_round_count = specification.bhip_round_count,
            .alignment_layout = plan.relation.alignment_layout,
            .relation_plan = plan.relation.relation_plan,
            .parameters = plan.relation.parameters,
            .radix = plan.relation.parameters.packing_radix,
            .basefold_parameters = specification.basefold_parameters,
            .spartan = std::move(external.verifier_key),
        };
        if (prover.variant() != verifier.variant ||
            prover.bhip_round_count() != verifier.bhip_round_count ||
            prover.spartan_key().setup_digest !=
            verifier.spartan.setup_digest ||
            verifier.spartan.direct_matrix != nullptr ||
            verifier.spartan.matrix_oracle != nullptr ||
            verifier.spartan.factored_computation == nullptr) {
            throw std::logic_error(
                "external transcript-packing prover/verifier projections "
                "are inconsistent");
        }

        retire_staging(admission, plan.relation,
                       *factored_prover->structure, factored.report,
                       transaction);
        for (const TranscriptPackingExternalTensorResources &tensor :
             admission.resources.tensors) {
            if (!std::filesystem::is_empty(tensor.scratch_directory)) {
                throw std::runtime_error(
                    "external packing setup left BaseFold scratch data");
            }
        }
        if (!std::filesystem::is_empty(
                admission.resources.staging_directory) ||
            !std::filesystem::is_empty(
                admission.resources.staging_quarantine_directory)) {
            throw std::runtime_error(
                "external packing setup left transient staging data");
        }
        std::uint64_t persistent_bytes = directory_regular_bytes(
            admission.resources.canonical_tensor_directory);
        for (const TranscriptPackingExternalTensorResources &tensor :
             admission.resources.tensors) {
            persistent_bytes = checked_add(
                persistent_bytes,
                directory_regular_bytes(tensor.state_directory),
                "external packing persistent bytes");
        }
        if (persistent_bytes !=
            plan.factored.persistent_output_physical_bytes) {
            throw std::logic_error(
                "external packing persistent bytes differ from plan");
        }

        TranscriptPackingExternalPreprocessingReport report{
            .plan = plan,
            .staging = std::move(staged.report),
            .factored = std::move(factored.report),
            .retired_staging_physical_bytes =
                plan.staging.artifact_physical_bytes,
            .final_persistent_physical_bytes = persistent_bytes,
        };
        transaction.commit();
        return TranscriptPackingExternalPreprocessing{
            .prover = std::move(prover),
            .verifier = std::move(verifier),
            .report = std::move(report),
        };
    } catch (...) {
        const std::exception_ptr failure = std::current_exception();
        transaction.rollback();
        std::rethrow_exception(failure);
    }
}

} // namespace laminate::protocol
