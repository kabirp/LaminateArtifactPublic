#ifndef LAMINATE_PROTOCOL_STORAGE_PACKED_PREPROCESSING_HPP
#define LAMINATE_PROTOCOL_STORAGE_PACKED_PREPROCESSING_HPP

/// @file packed_preprocessing.hpp
/// @brief Manifest-last, relocatable Folded/Laned preprocessing ownership.

#include "laminate/protocol/packed/preprocessing/workload.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace laminate::protocol {

inline constexpr std::uint64_t kPackedRoleManifestVersion = 2;
inline constexpr std::uint64_t kPackedRootManifestVersion = 2;
inline constexpr std::string_view kPackedWorkloadStaticFilename =
    "workload-static.bin";
inline constexpr std::string_view kPackedRoleStaticFilename =
    "role-static.bin";
inline constexpr std::string_view kPackedRoleArtifactTreeDirectory =
    "artifacts";
inline constexpr std::string_view kPackedManifestFilename = "manifest.bin";

enum class PackedPreprocessingRole : std::uint64_t {
    Server = 1,
    Client = 2,
};

/// Storage commitment for a fixed-name direct child. The leaf name is implied
/// by its manifest slot and is therefore neither caller-controlled nor stored.
struct PackedStoredArtifact {
    std::uint64_t serialized_bytes = 0;
    Digest file_digest{};
    Digest semantic_identity{};

    bool operator==(const PackedStoredArtifact &) const = default;
};

enum class PackedArtifactTreeEntryKind : std::uint64_t {
    Directory = 1,
    File = 2,
};

/// One canonical entry below the fixed `artifacts/` role child. Paths use
/// portable `/` separators, are relative to that child, and contain no `.` or
/// `..` components; components contain only ASCII letters, digits, `.`, `_`,
/// and `-`. Directory entries bind empty directories as well as file parents.
struct PackedStoredArtifactTreeEntry {
    PackedArtifactTreeEntryKind kind =
        PackedArtifactTreeEntryKind::File;
    std::string relative_path;
    std::uint64_t serialized_bytes = 0;
    Digest file_digest{};

    bool operator==(const PackedStoredArtifactTreeEntry &) const = default;
};

/// Storage commitment for one caller-owned immutable artifact tree. The
/// caller supplies `semantic_identity`; the remaining fields commit the exact
/// canonical relative layout and streamed contents without naming an
/// absolute path.
struct PackedStoredArtifactTree {
    Digest semantic_identity{};
    std::uint64_t file_count = 0;
    std::uint64_t directory_count = 0;
    std::uint64_t serialized_bytes = 0;
    Digest layout_digest{};
    std::vector<PackedStoredArtifactTreeEntry> entries;

    bool operator==(const PackedStoredArtifactTree &) const = default;
};

/// One role's public metadata manifest. `semantic_identity` commits only to
/// the workload, role, role-static semantics, and tree semantics.
/// `storage_identity` additionally commits to exact role-static bytes and the
/// tree layout/content commitment. Neither commits an absolute path.
struct PackedRoleManifest {
    std::filesystem::path directory;
    PackedPreprocessingRole role = PackedPreprocessingRole::Server;
    Digest workload_semantic_identity{};
    PackedStoredArtifact role_artifact;
    PackedStoredArtifactTree artifact_tree;
    Digest semantic_identity{};
    Digest storage_identity{};
    std::uint64_t manifest_bytes = 0;
};

struct PackedRootRoleBinding {
    Digest semantic_identity{};
    Digest storage_identity{};
    std::uint64_t manifest_bytes = 0;
    Digest manifest_file_digest{};

    bool operator==(const PackedRootRoleBinding &) const = default;
};

/// Publication point for a complete role-separated preprocessing tree. Its
/// semantic identity omits paths and physical sizes. Its storage identity adds
/// exact workload and role-manifest byte commitments.
struct PackedRootManifest {
    std::filesystem::path shared_directory;
    PackedStoredArtifact workload;
    PackedRootRoleBinding server;
    PackedRootRoleBinding client;
    Digest semantic_identity{};
    Digest storage_identity{};
    std::uint64_t manifest_bytes = 0;
};

struct PackedPreprocessingPublishLimits {
    std::uint64_t max_workload_bytes = 0;
    std::uint64_t max_role_artifact_bytes = 0;
    std::uint64_t max_manifest_bytes = 0;
    std::uint64_t min_free_bytes = 0;
    /// Counts exclude the fixed artifact-tree root itself. Every child
    /// directory, including an empty one, and every file count toward the limits.
    std::uint64_t max_artifact_tree_files = 0;
    std::uint64_t max_artifact_tree_directories = 0;
    std::uint64_t max_artifact_tree_depth = 0;
    std::uint64_t max_artifact_tree_relative_path_bytes = 0;
    std::uint64_t max_artifact_tree_file_bytes = 0;
    std::uint64_t max_artifact_tree_bytes = 0;
    PackedWorkloadStaticDecodeLimits workload_decode;
};

struct PackedPreprocessingOpenLimits {
    std::uint64_t max_workload_bytes = 0;
    std::uint64_t max_role_artifact_bytes = 0;
    std::uint64_t max_manifest_bytes = 0;
    std::uint64_t max_artifact_tree_files = 0;
    std::uint64_t max_artifact_tree_directories = 0;
    std::uint64_t max_artifact_tree_depth = 0;
    std::uint64_t max_artifact_tree_relative_path_bytes = 0;
    std::uint64_t max_artifact_tree_file_bytes = 0;
    std::uint64_t max_artifact_tree_bytes = 0;
    PackedWorkloadStaticDecodeLimits workload_decode;
};

struct OpenedPackedRootPreprocessing {
    PackedRootManifest manifest;
    CertifiedPackedWorkloadStatic workload;
};

/// A role opener receives only its caller-owned role directory. The other
/// role's pathname is deliberately absent, although its public manifest
/// commitment remains bound by the shared root.
struct OpenedPackedRolePreprocessing {
    PackedRootManifest root;
    PackedRoleManifest role;
    CertifiedPackedWorkloadStatic workload;
    std::filesystem::path role_artifact_path;
    std::filesystem::path artifact_tree_path;
};

/// Write the canonical workload file into an empty shared directory. This is
/// not publication: the tree becomes usable only after the root manifest is
/// published last.
PackedStoredArtifact publish_packed_workload_static_file(
    const std::filesystem::path &shared_directory,
    const CertifiedPackedWorkloadStatic &workload,
    const PackedPreprocessingPublishLimits &limits);

/// Stream-inspect the already-created fixed `role-static.bin` and
/// `artifacts/` tree, then publish this role's manifest last. The routine does
/// not copy tree files. Both semantic identities are caller-supplied and must
/// already bind the corresponding protocol objects.
PackedRoleManifest publish_packed_role_manifest(
    const std::filesystem::path &role_directory,
    PackedPreprocessingRole role,
    const Digest &workload_semantic_identity,
    const Digest &role_artifact_semantic_identity,
    const Digest &artifact_tree_semantic_identity,
    const PackedPreprocessingPublishLimits &limits);

/// Validate the workload and both completed role directories, then publish
/// the shared root manifest last. All three directories must be distinct.
PackedRootManifest publish_packed_preprocessing_root(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &server_directory,
    const std::filesystem::path &client_directory,
    const CertifiedPackedWorkloadStatic &expected_workload,
    const PackedPreprocessingPublishLimits &limits);

/// Open the shared publication point under an externally authenticated root
/// storage identity. This checks the exact shared directory and restores the
/// immutable workload-static token without compilation or layout derivation.
OpenedPackedRootPreprocessing open_packed_preprocessing_root(
    const std::filesystem::path &shared_directory,
    const Digest &expected_root_storage_identity,
    const PackedPreprocessingOpenLimits &limits);

OpenedPackedRolePreprocessing open_packed_server_preprocessing(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &server_directory,
    const Digest &expected_root_storage_identity,
    const PackedPreprocessingOpenLimits &limits);

OpenedPackedRolePreprocessing open_packed_client_preprocessing(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &client_directory,
    const Digest &expected_root_storage_identity,
    const PackedPreprocessingOpenLimits &limits);

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_STORAGE_PACKED_PREPROCESSING_HPP
