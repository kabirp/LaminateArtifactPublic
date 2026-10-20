#ifndef LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_MANIFEST_HPP
#define LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_MANIFEST_HPP

/// @file manifest.hpp
/// @brief Private manifest codec and complete-layer validation contract.

#include "layer_format.hpp"

#include <functional>
#include <memory>
#include <mutex>

namespace laminate::payload::trace_store_format {

std::vector<std::uint8_t> encode_manifest(
    const Digest &backend_context_id,
    const EncryptedTraceDescriptor &descriptor,
    const FileTraceStoreWriteReport &report,
    std::span<const LayerFileSummary> layers);

struct ParsedManifest {
    Digest backend_context_id{};
    EncryptedTraceDescriptor descriptor;
    FileTraceStoreWriteReport report;
    std::vector<LayerFileSummary> layers;
};

void validate_open_limits(const FileTraceStoreOpenLimits &limits);
ParsedManifest parse_manifest(std::span<const std::uint8_t> bytes,
                              const FileTraceStoreOpenLimits &limits);

/// Process-private ownership of one same-writer layer inode. Separate store
/// namespaces may bind distinct paths to this state through hard links. The
/// counter is checked against the filesystem link count before reclamation so
/// unique live bytes can never be reclaimed twice.
struct PrivateLayerLinkState {
    FileIdentity identity;
    std::uint64_t file_size = 0;
    mutable std::mutex mutex;
    std::size_t owned_links = 1;
};

struct LayerFileInfo {
    std::filesystem::path path;
    std::uint64_t file_size = 0;
    std::uint64_t index_offset = 0;
    std::uint64_t maximum_record_bytes = 0;
    std::shared_ptr<const std::vector<std::uint64_t>> offsets;
    FileIdentity identity;
    std::shared_ptr<PrivateLayerLinkState> private_link_state;
    mutable std::mutex access_mutex;
    mutable std::size_t active_readers = 0;
    mutable bool retirement_in_progress = false;
    mutable bool retired = false;
};

std::shared_ptr<const LayerFileInfo> scan_layer_file(
    const std::filesystem::path &path, std::size_t layer_index,
    const EncryptedTraceLayerDescriptor &descriptor,
    const LayerFileSummary &summary, std::uint64_t &logical_bytes,
    std::uint64_t maximum_record_bytes,
    const std::function<void(
        std::size_t, std::size_t,
        std::span<const std::uint8_t>)> &validate_record);

} // namespace laminate::payload::trace_store_format

#endif // LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_MANIFEST_HPP
