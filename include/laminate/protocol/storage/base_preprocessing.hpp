#ifndef LAMINATE_PROTOCOL_STORAGE_BASE_PREPROCESSING_HPP
#define LAMINATE_PROTOCOL_STORAGE_BASE_PREPROCESSING_HPP

/// @file base_preprocessing.hpp
/// @brief Manifest-last ownership for persistent Base preprocessing.

#include "laminate/setup.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace laminate::protocol {

inline constexpr std::uint64_t kBasePreprocessingManifestVersion = 1;

/// Exact identity and byte commitment of one caller-owned SEAL role bundle.
/// The shared manifest records only the file's leaf name; it never embeds a
/// path or copies the bundle payload.
struct BasePreprocessingBundleFile {
    std::string filename;
    std::uint64_t serialized_bytes = 0;
    Digest file_digest{};
    Digest bundle_identity{};

    bool operator==(
        const BasePreprocessingBundleFile &) const = default;
};

/// Optional diagnostic description of the prepared-plaintext cache retained
/// by the server. Version 1 does not serialize or claim to restore that
/// backend-private cache; these exact counters are integrity-bound so its
/// separately measured ownership cannot silently disappear from a setup
/// report.
struct BasePreparedPlaintextCacheMetadata {
    std::uint64_t logical_plaintexts = 0;
    std::uint64_t level_representations = 0;
    std::uint64_t ntt_coefficient_bytes = 0;

    bool operator==(
        const BasePreparedPlaintextCacheMetadata &) const = default;
};

/// Validated v1 setup-ceremony index. This is shared public metadata, not a
/// server artifact: the evaluation and client-secret bundles remain in
/// disjoint role-owned directories. `public_setup_canonical` is the exact byte
/// string accepted by `setup_digest`; payload and layered digests are
/// recomputed from the caller's circuits on publication and open. The caller
/// must authenticate the returned manifest identity when crossing a trust
/// boundary; the format detects corruption but is not a signature.
struct BasePreprocessingManifest {
    std::filesystem::path manifest_directory;
    std::uint64_t format_version =
        kBasePreprocessingManifestVersion;
    Digest identity{};
    std::vector<std::uint8_t> public_setup_canonical;
    Digest public_setup_digest{};
    Digest payload_digest{};
    Digest layered_digest{};
    Digest circuit_digest{};
    Digest bundle_identity{};
    BasePreprocessingBundleFile evaluation_bundle;
    BasePreprocessingBundleFile client_bundle;
    std::optional<BasePreparedPlaintextCacheMetadata>
        prepared_plaintext_cache;
    std::uint64_t manifest_bytes = 0;

    bool operator==(const BasePreprocessingManifest &) const = default;
};

/// Explicit setup-ceremony inputs. `manifest_directory` must be a dedicated,
/// empty caller-owned directory. Each completed role bundle must be the sole
/// direct child of a different caller-owned directory. Only the small shared
/// manifest is created by this API; no role bundle is moved or copied.
struct BasePreprocessingManifestOptions {
    std::filesystem::path manifest_directory;
    std::filesystem::path evaluation_bundle_path;
    std::filesystem::path client_bundle_path;
    std::uint64_t max_manifest_bytes = 0;
    std::uint64_t max_bundle_bytes = 0;
    std::uint64_t min_free_bytes = 0;
    std::optional<BasePreparedPlaintextCacheMetadata>
        prepared_plaintext_cache;
};

/// Bounded open policy. The manifest limit is mandatory for every opener; the
/// bundle limit is additionally mandatory for either role-specific opener.
/// Each is checked before allocation or complete bundle validation.
struct BasePreprocessingManifestOpenLimits {
    std::uint64_t max_manifest_bytes = 0;
    std::uint64_t max_bundle_bytes = 0;
};

/// A validated server view. It owns only small manifest metadata and the
/// caller's evaluation-bundle pathname; it neither names nor accesses the
/// client-private directory.
struct OpenedBaseServerPreprocessing {
    BasePreprocessingManifest manifest;
    std::filesystem::path evaluation_bundle_path;
};

/// A validated client view. It owns only small manifest metadata and the
/// caller's private-bundle pathname; it neither names nor accesses the server
/// directory.
struct OpenedBaseClientPreprocessing {
    BasePreprocessingManifest manifest;
    std::filesystem::path client_bundle_path;
};

/// During an explicit setup ceremony, stream-validate both existing canonical
/// SEAL role bundles and publish the shared `manifest.bin` last. Publication
/// performs no FHE work and retains no bundle or replay bytes.
BasePreprocessingManifest publish_base_preprocessing_manifest(
    const PublicSetup &setup,
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    const BasePreprocessingManifestOptions &options);

/// Open only the shared public descriptor and validate its exact setup and
/// circuit binding. This function does not name or access either role bundle.
BasePreprocessingManifest open_base_preprocessing_manifest(
    const std::filesystem::path &directory,
    const PublicSetup &expected_setup,
    const payload::PayloadCircuit &expected_payload,
    const payload::LayeredCircuit &expected_layered,
    const BasePreprocessingManifestOpenLimits &limits);

/// Open the shared descriptor and the server's evaluation bundle. The client
/// bundle path is deliberately absent from this API.
OpenedBaseServerPreprocessing open_server_base_preprocessing(
    const std::filesystem::path &manifest_directory,
    const std::filesystem::path &evaluation_bundle_path,
    const PublicSetup &expected_setup,
    const payload::PayloadCircuit &expected_payload,
    const payload::LayeredCircuit &expected_layered,
    const BasePreprocessingManifestOpenLimits &limits);

/// Open the shared descriptor and the client-private bundle. The server
/// bundle path is deliberately absent from this API.
OpenedBaseClientPreprocessing open_client_base_preprocessing(
    const std::filesystem::path &manifest_directory,
    const std::filesystem::path &client_bundle_path,
    const PublicSetup &expected_setup,
    const payload::PayloadCircuit &expected_payload,
    const payload::LayeredCircuit &expected_layered,
    const BasePreprocessingManifestOpenLimits &limits);

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_STORAGE_BASE_PREPROCESSING_HPP
