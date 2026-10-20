#ifndef LAMINATE_PROTOCOL_PACKED_PREPROCESSING_ROLES_HPP
#define LAMINATE_PROTOCOL_PACKED_PREPROCESSING_ROLES_HPP

/// @file roles.hpp
/// @brief Persistent, relocatable Folded/Laned role preprocessing.

#include "laminate/fhe/storage/ciphertext.hpp"
#include "laminate/protocol/packed/external/prover.hpp"
#include "laminate/protocol/storage/packed_preprocessing.hpp"
#include "laminate/protocol/packed/external/preprocessing.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::protocol {

inline constexpr std::uint64_t kPackedRoleStaticVersion = 2;
inline constexpr std::string_view
    kPackedServerTensorColumnsRelativePath = "tensor-columns";

/// Stable direct-child name for tensor `i`'s BaseFold opening state.
std::string packed_server_basefold_state_relative_path(
    std::size_t tensor_index);

/// Allocation limits for the canonical role-static decoder. The file-byte
/// bound is enforced before allocation; the remaining bounds constrain its
/// two variable-length lists.
struct PackedRoleStaticDecodeLimits {
    std::uint64_t max_encoded_bytes = 0;
    std::size_t max_ingress_layers = 0;
    std::size_t max_factored_tensors = 0;
    std::size_t max_relative_path_bytes = 0;
};

/// Canonical public certificate stored in each role's fixed
/// `role-static.bin` file. The two roles carry the same protocol commitment
/// but distinct role and artifact-layout bindings.
struct PackedRoleStatic {
    PackedPreprocessingRole role = PackedPreprocessingRole::Server;
    PackingGkrVariant variant = PackingGkrVariant::Folded;
    gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy =
        gkr::CiphertextCommitmentPolicy::poseidon_v2();
    Digest workload_semantic_identity{};
    Digest payload_digest{};
    Digest layered_digest{};
    Digest circuit_digest{};
    Digest public_setup_digest{};
    std::size_t ring_degree = 0;
    std::size_t bhip_round_count = 0;
    packing::LazyTernaryParameters parameters;
    spartan::BaseFoldPcsParameters basefold_parameters;
    Digest spartan_setup_digest{};
    spartan::FactoredMatrixCommitment factored_commitment;
    std::string proof_ingress_policy;
    std::vector<std::size_t> proof_ingress_rns_limbs_by_layer;
    Digest proof_ingress_schedule_digest{};
    Digest fhe_context_storage_id{};
    std::vector<std::string> artifact_relative_paths;
    Digest semantic_identity{};

    bool operator==(const PackedRoleStatic &) const = default;
};

/// Strict canonical encoding used by both client and server role files.
std::vector<std::uint8_t> encode_packed_role_static(
    const PackedRoleStatic &state);

/// Authenticate the file and role semantic identity before bounded decoding.
/// Canonical re-encoding is required byte for byte.
PackedRoleStatic decode_authenticated_packed_role_static(
    std::span<const std::uint8_t> encoded,
    PackedPreprocessingRole expected_role,
    const Digest &expected_file_digest,
    const Digest &expected_semantic_identity,
    const PackedRoleStaticDecodeLimits &limits);

/// Fixed caller-owned publication roots. `shared`, `server`, `client`, and
/// `work` must already exist as empty, owner-private, pairwise-disjoint real
/// directories. Persistent artifacts are written directly beneath
/// `server/artifacts`; `work` contains only staging and scratch directories
/// and is empty again on success.
struct PackedRolePreprocessingDirectories {
    std::filesystem::path shared;
    std::filesystem::path server;
    std::filesystem::path client;
    std::filesystem::path work;
};

struct PackedRolePreprocessingPublishLimits {
    PackedPreprocessingPublishLimits storage;
    PackedRoleStaticDecodeLimits role_static;
    TranscriptPackingExternalPreprocessingLimits transcript_packing;
};

struct PackedRolePreprocessingOpenLimits {
    PackedPreprocessingOpenLimits storage;
    PackedRoleStaticDecodeLimits role_static;
};

/// Exact fixed-tree publication totals that are available without running
/// either public encoder or touching storage. The byte count is the sum of
/// regular files below the fixed `artifacts/` root; counts exclude that root.
struct PackedRoleArtifactTreePlan {
    std::uint64_t file_count = 0;
    std::uint64_t directory_count = 0;
    std::uint64_t serialized_bytes = 0;

    bool operator==(const PackedRoleArtifactTreePlan &) const = default;
};

/// Formula-only sizing for the complete role publication. Role-static sizes
/// are exact canonical encoded lengths. The client tree is intentionally
/// empty; all external tensor and BaseFold state bytes belong to the server.
struct PackedRolePreprocessingPublicationPlan {
    TranscriptPackingExternalPreprocessingPlan transcript_packing;
    /// Exact minimum limits required to authenticate and decode the canonical
    /// workload artifact that this publication will write.
    PackedWorkloadStaticDecodeLimits workload_decode_requirements;
    std::uint64_t server_role_static_bytes = 0;
    std::uint64_t client_role_static_bytes = 0;
    PackedRoleArtifactTreePlan server_artifacts;
    PackedRoleArtifactTreePlan client_artifacts;
};

PackedRolePreprocessingPublicationPlan
plan_packed_role_preprocessing_publication(
    const CertifiedPackedWorkloadStatic &workload,
    const TranscriptPackingExternalPreprocessingSpecification &specification,
    const Digest &fhe_context_storage_id);

PackedRolePreprocessingOpenLimits packed_role_preprocessing_open_limits(
    const PackedRolePreprocessingPublishLimits &limits);

/// Backend-independent authenticated server state. Its prover key contains
/// external artifact handles opened at the role's current, relocatable path.
struct OpenedPackedServerRoleCore {
    OpenedPackedRolePreprocessing publication;
    PackedRoleStatic role_static;
    PackedExternalProverSetup prover_setup;
};

/// Backend-independent authenticated client state. This is the complete
/// compact verifier certificate and contains no external opening state or
/// evaluation-key material.
struct OpenedPackedClientRoleCore {
    OpenedPackedRolePreprocessing publication;
    PackedRoleStatic role_static;
    TranscriptPackingSpartanVerifierSetup verifier_setup;
};

namespace detail {

OpenedPackedServerRoleCore open_packed_server_role_core(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &server_directory,
    const Digest &expected_root_storage_identity,
    const Digest &expected_fhe_context_storage_id,
    const PackedRolePreprocessingOpenLimits &limits);

OpenedPackedClientRoleCore open_packed_client_role_core(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &client_directory,
    const Digest &expected_root_storage_identity,
    const Digest &expected_fhe_context_storage_id,
    const PackedRolePreprocessingOpenLimits &limits);

struct PackedRolePreprocessingCoreResult {
    PackedRootManifest root;
    TranscriptPackingExternalPreprocessingReport transcript_packing_report;
};

PackedRolePreprocessingCoreResult publish_packed_role_preprocessing_core(
    const CertifiedPackedWorkloadStatic &workload,
    const TranscriptPackingExternalPreprocessingSpecification &specification,
    packing::ProofOfPackingR1csEncoders encoders,
    const Digest &fhe_context_storage_id,
    PackedRolePreprocessingDirectories directories,
    PackedRolePreprocessingPublishLimits limits);

} // namespace detail

template <typename Backend>
concept PackedRolePreprocessingBackend =
    fhe::PersistableFheBackend<Backend> &&
    fhe::PublicVerifierFheBackend<Backend> &&
    packing::SignedDigitPackingBackend<Backend> &&
    requires(const typename Backend::ClientContext &client,
             const typename Backend::PublicVerifierContext &verifier) {
        { Backend::storage_context_id(client) } -> std::same_as<Digest>;
        { Backend::storage_context_id(verifier) } -> std::same_as<Digest>;
    };

template <PackedRolePreprocessingBackend Backend>
class OpenedPackedServerRoleState;
template <PackedRolePreprocessingBackend Backend>
class OpenedPackedClientRoleState;
template <PackedRolePreprocessingBackend Backend>
struct PackedRolePreprocessingResult;

namespace detail {

template <PackedRolePreprocessingBackend Backend>
OpenedPackedServerRoleState<Backend> bind_packed_server_role_state(
    OpenedPackedServerRoleCore core,
    const typename Backend::EvalContext &evaluation_context);

} // namespace detail

template <PackedRolePreprocessingBackend Backend>
OpenedPackedServerRoleState<Backend> open_packed_server_role_state(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &server_directory,
    const Digest &expected_root_storage_identity,
    const typename Backend::EvalContext &evaluation_context,
    const PackedRolePreprocessingOpenLimits &limits);

template <PackedRolePreprocessingBackend Backend>
OpenedPackedClientRoleState<Backend> open_packed_client_role_state(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &client_directory,
    const Digest &expected_root_storage_identity,
    const typename Backend::ClientContext &client_context,
    const typename Backend::PublicVerifierContext &verifier_context,
    const PackedRolePreprocessingOpenLimits &limits);

/// Role-owned server state plus a non-owning reference to the separately
/// restored evaluation context. The persistent protocol certificate never
/// serializes that context into `role-static.bin`.
template <PackedRolePreprocessingBackend Backend>
class OpenedPackedServerRoleState {
  public:
    const OpenedPackedServerRoleCore &core() const { return core_; }
    const typename Backend::EvalContext &evaluation_context() const {
        return *evaluation_context_;
    }
    const PackedExternalProverSetup &prover_setup() const {
        return core_.prover_setup;
    }
    const CertifiedPackedWorkloadStatic &workload() const {
        return core_.publication.workload;
    }

  private:
    OpenedPackedServerRoleState(
        OpenedPackedServerRoleCore core,
        const typename Backend::EvalContext &evaluation_context)
        : core_(std::move(core)), evaluation_context_(&evaluation_context) {}

    friend OpenedPackedServerRoleState<Backend>
    open_packed_server_role_state<Backend>(
        const std::filesystem::path &, const std::filesystem::path &,
        const Digest &, const typename Backend::EvalContext &,
        const PackedRolePreprocessingOpenLimits &);

    friend OpenedPackedServerRoleState<Backend>
    detail::bind_packed_server_role_state<Backend>(
        OpenedPackedServerRoleCore,
        const typename Backend::EvalContext &);

    OpenedPackedServerRoleCore core_;
    const typename Backend::EvalContext *evaluation_context_ = nullptr;
};

/// Role-owned client state plus references to the separately restored secret
/// client context and key-free public verifier context. No EvalContext,
/// relinearization key, or Galois key is reachable through this type.
template <PackedRolePreprocessingBackend Backend>
class OpenedPackedClientRoleState {
  public:
    const OpenedPackedClientRoleCore &core() const { return core_; }
    const typename Backend::ClientContext &client_context() const {
        return *client_context_;
    }
    const typename Backend::PublicVerifierContext &verifier_context() const {
        return *verifier_context_;
    }
    const TranscriptPackingSpartanVerifierSetup &verifier_setup() const {
        return core_.verifier_setup;
    }
    const CertifiedPackedWorkloadStatic &workload() const {
        return core_.publication.workload;
    }

  private:
    OpenedPackedClientRoleState(
        OpenedPackedClientRoleCore core,
        const typename Backend::ClientContext &client_context,
        const typename Backend::PublicVerifierContext &verifier_context)
        : core_(std::move(core)), client_context_(&client_context),
          verifier_context_(&verifier_context) {}

    friend OpenedPackedClientRoleState<Backend>
    open_packed_client_role_state<Backend>(
        const std::filesystem::path &, const std::filesystem::path &,
        const Digest &, const typename Backend::ClientContext &,
        const typename Backend::PublicVerifierContext &,
        const PackedRolePreprocessingOpenLimits &);

    OpenedPackedClientRoleCore core_;
    const typename Backend::ClientContext *client_context_ = nullptr;
    const typename Backend::PublicVerifierContext *verifier_context_ =
        nullptr;
};

template <PackedRolePreprocessingBackend Backend>
OpenedPackedServerRoleState<Backend>
detail::bind_packed_server_role_state(
    OpenedPackedServerRoleCore core,
    const typename Backend::EvalContext &evaluation_context) {
    if (Backend::storage_context_id(evaluation_context) !=
            core.role_static.fhe_context_storage_id ||
        Backend::slot_count(evaluation_context) !=
            core.publication.workload.public_setup().shape.slot_count) {
        throw std::invalid_argument(
            "packed server evaluation context does not match its opened "
            "role");
    }
    return OpenedPackedServerRoleState<Backend>(
        std::move(core), evaluation_context);
}

template <PackedRolePreprocessingBackend Backend>
OpenedPackedServerRoleState<Backend> open_packed_server_role_state(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &server_directory,
    const Digest &expected_root_storage_identity,
    const typename Backend::EvalContext &evaluation_context,
    const PackedRolePreprocessingOpenLimits &limits) {
    return detail::bind_packed_server_role_state<Backend>(
        detail::open_packed_server_role_core(
            shared_directory, server_directory,
            expected_root_storage_identity,
            Backend::storage_context_id(evaluation_context), limits),
        evaluation_context);
}

template <PackedRolePreprocessingBackend Backend>
OpenedPackedClientRoleState<Backend> open_packed_client_role_state(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &client_directory,
    const Digest &expected_root_storage_identity,
    const typename Backend::ClientContext &client_context,
    const typename Backend::PublicVerifierContext &verifier_context,
    const PackedRolePreprocessingOpenLimits &limits) {
    const Digest client_id = Backend::storage_context_id(client_context);
    if (client_id != Backend::storage_context_id(verifier_context)) {
        throw std::invalid_argument(
            "packed client and public verifier contexts do not match");
    }
    return OpenedPackedClientRoleState<Backend>(
        detail::open_packed_client_role_core(
            shared_directory, client_directory,
            expected_root_storage_identity, client_id, limits),
        client_context, verifier_context);
}

template <PackedRolePreprocessingBackend Backend>
struct PackedRolePreprocessingResult {
    PackedRootManifest root;
    TranscriptPackingExternalPreprocessingReport transcript_packing_report;
};

/// Complete persistent setup. It writes external Spartan artifacts directly
/// at their final fixed relative paths, publishes each role manifest and then
/// the shared root manifest, destroys the live setup handles, independently
/// reopens each role to authenticate the completed publication, and returns
/// only the root identity and construction report. Online roles reopen their
/// own state separately.
template <PackedRolePreprocessingBackend Backend>
PackedRolePreprocessingResult<Backend> publish_packed_role_preprocessing(
    const CertifiedPackedWorkloadStatic &workload,
    const TranscriptPackingExternalPreprocessingSpecification &specification,
    const typename Backend::EvalContext &evaluation_context,
    const typename Backend::ClientContext &client_context,
    const typename Backend::PublicVerifierContext &verifier_context,
    PackedRolePreprocessingDirectories directories,
    PackedRolePreprocessingPublishLimits limits) {
    const Digest evaluation_id =
        Backend::storage_context_id(evaluation_context);
    if (evaluation_id != Backend::storage_context_id(client_context) ||
        evaluation_id != Backend::storage_context_id(verifier_context) ||
        Backend::slot_count(evaluation_context) !=
            specification.ring_degree ||
        Backend::slot_count(client_context) != specification.ring_degree ||
        Backend::slot_count(verifier_context) !=
            specification.ring_degree) {
        throw std::invalid_argument(
            "packed role contexts or ring geometry do not match");
    }
    packing::ProofOfPackingR1csEncoders encoders{
        .centered_coefficients =
            [&evaluation_context](const fhe::SlotVector &slots) {
                return Backend::encode_centered_plaintext_coefficients(
                    evaluation_context, slots);
            },
        .native_ntt =
            [&evaluation_context](
                std::span<const std::int64_t> coefficients) {
                return Backend::encode_lowest_plaintext_ntt_coordinates(
                    evaluation_context, coefficients);
            },
    };
    detail::PackedRolePreprocessingCoreResult core =
        detail::publish_packed_role_preprocessing_core(
            workload, specification, std::move(encoders), evaluation_id,
            std::move(directories), std::move(limits));
    return PackedRolePreprocessingResult<Backend>{
        .root = std::move(core.root),
        .transcript_packing_report =
            std::move(core.transcript_packing_report),
    };
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_PREPROCESSING_ROLES_HPP
