#ifndef LAMINATE_PAYLOAD_STORAGE_VALIDATED_TRACE_STORE_STATE_HPP
#define LAMINATE_PAYLOAD_STORAGE_VALIDATED_TRACE_STORE_STATE_HPP

/// @file validated_state.hpp
/// @brief Shared private state after full manifest and layer validation.

#include "../format/manifest.hpp"

namespace laminate::payload::trace_storage {

struct SerializedTraceStore::Impl {
    std::filesystem::path directory;
    Digest backend_context_id{};
    EncryptedTraceDescriptor descriptor;
    FileTraceStoreWriteReport report;
    FileTraceStoreWriteDiagnostics write_diagnostics;
    std::vector<std::shared_ptr<const trace_store_format::LayerFileInfo>>
        layers;
    Digest manifest_id{};
    trace_store_format::FileIdentity manifest_identity;
    std::vector<trace_store_format::LayerFileSummary> layer_summaries;
    FileTraceStoreIntegrityMode integrity_mode =
        FileTraceStoreIntegrityMode::ReopenableAuthenticated;
    bool same_writer_private = false;
    bool files_removed = false;
};

} // namespace laminate::payload::trace_storage

#endif // LAMINATE_PAYLOAD_STORAGE_VALIDATED_TRACE_STORE_STATE_HPP
