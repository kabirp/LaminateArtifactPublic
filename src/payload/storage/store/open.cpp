/// @file open.cpp
/// @brief Untrusted-store validation and private-state admission.

#include "../format/manifest.hpp"
#include "validated_state.hpp"

#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <set>
#include <stdexcept>

namespace laminate::payload {
using namespace trace_store_format;

namespace trace_storage {

SerializedTraceStore::SerializedTraceStore(std::shared_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

SerializedTraceStore SerializedTraceStore::open(
    const std::filesystem::path &directory,
    const Digest &expected_backend_context_id,
    const std::function<void(const EncryptedTraceDescriptor &)> &
        validate_descriptor,
    const std::function<void(
        std::size_t, std::size_t,
        std::span<const std::uint8_t>)> &validate_record,
    FileTraceStoreOpenLimits limits) {
    validate_open_limits(limits);
    const std::filesystem::file_status directory_status =
        std::filesystem::symlink_status(directory);
    if (!std::filesystem::is_directory(directory_status)) {
        throw std::invalid_argument(
            "SerializedTraceStore: path is not a directory");
    }
    const std::filesystem::path selected_manifest = manifest_path(directory);
    FileIdentity manifest_identity;
    const std::vector<std::uint8_t> manifest_bytes = read_small_file(
        selected_manifest,
        std::min(kMaximumManifestBytes, limits.max_manifest_bytes),
        "trace-store manifest", &manifest_identity);
    ParsedManifest manifest = parse_manifest(manifest_bytes, limits);
    validate_encrypted_trace_descriptor(manifest.descriptor);
    if (manifest.backend_context_id != expected_backend_context_id) {
        throw std::invalid_argument(
            "SerializedTraceStore: backend context identity mismatch");
    }
    if (manifest.report.physical_bytes > limits.max_total_bytes) {
        throw std::runtime_error(
            "trace store exceeds caller total-byte limit");
    }
    validate_descriptor(manifest.descriptor);

    std::set<std::string> expected_names{"manifest.bin"};
    for (std::size_t layer = 0; layer < manifest.descriptor.layers.size();
         ++layer) {
        expected_names.insert(
            layer_path(directory, layer, ".bin").filename().string());
    }
    for (const std::filesystem::directory_entry &entry :
         std::filesystem::directory_iterator(directory)) {
        if (!expected_names.contains(entry.path().filename().string())) {
            throw std::runtime_error(
                "trace store contains an unexpected or partial file");
        }
    }

    auto result = std::make_shared<Impl>();
    result->directory = directory;
    result->backend_context_id = manifest.backend_context_id;
    result->descriptor = manifest.descriptor;
    result->report = manifest.report;
    result->manifest_id = sha256(manifest_bytes);
    result->manifest_identity = manifest_identity;
    result->layer_summaries = manifest.layers;
    result->layers.reserve(manifest.descriptor.layers.size());
    std::uint64_t logical_bytes = 0;
    std::uint64_t physical_bytes =
        checked_u64(manifest_bytes.size(), "manifest size");
    for (std::size_t layer = 0; layer < manifest.descriptor.layers.size();
         ++layer) {
        result->layers.push_back(scan_layer_file(
            layer_path(directory, layer, ".bin"), layer,
            manifest.descriptor.layers[layer], manifest.layers[layer],
            logical_bytes,
            std::min(kMaximumRecordBytes, limits.max_record_bytes),
            validate_record));
        physical_bytes = checked_add(
            physical_bytes, manifest.layers[layer].file_size,
            "physical trace-store bytes");
    }
    if (logical_bytes != manifest.report.logical_record_bytes ||
        physical_bytes != manifest.report.physical_bytes) {
        throw std::runtime_error("trace-store byte totals are inconsistent");
    }
    return SerializedTraceStore(std::move(result));
}

const std::filesystem::path &SerializedTraceStore::directory() const {
    return impl_->directory;
}

const Digest &SerializedTraceStore::backend_context_id() const {
    return impl_->backend_context_id;
}

const EncryptedTraceDescriptor &SerializedTraceStore::descriptor() const {
    return impl_->descriptor;
}

const FileTraceStoreWriteReport &SerializedTraceStore::report() const {
    return impl_->report;
}

const FileTraceStoreWriteDiagnostics &
SerializedTraceStore::write_diagnostics() const {
    return impl_->write_diagnostics;
}

} // namespace trace_storage
} // namespace laminate::payload
