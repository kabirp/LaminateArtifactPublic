/// @file private_alias.cpp
/// @brief Same-writer one-layer publication by an identity hard link.

#include "../format/manifest.hpp"
#include "validated_state.hpp"

#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <limits>
#include <optional>
#include <set>
#include <stdexcept>
#include <system_error>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace laminate::payload {
using namespace trace_store_format;

namespace trace_storage {
namespace {

struct OperationTimer {
    std::chrono::steady_clock::time_point wall_start =
        std::chrono::steady_clock::now();
    std::clock_t cpu_start = std::clock();

    FileTraceStoreOperationTiming stop() const {
        const auto wall_end = std::chrono::steady_clock::now();
        const std::clock_t cpu_end = std::clock();
        return {
            std::chrono::duration<double, std::milli>(wall_end - wall_start)
                .count(),
            cpu_start == static_cast<std::clock_t>(-1) ||
                    cpu_end == static_cast<std::clock_t>(-1)
                ? 0.0
                : 1000.0 * static_cast<double>(cpu_end - cpu_start) /
                      static_cast<double>(CLOCKS_PER_SEC),
        };
    }
};

bool hard_link_capability_error(const std::error_code &error) {
    return error == std::errc::cross_device_link ||
           error == std::errc::function_not_supported ||
           error == std::errc::operation_not_supported ||
           error == std::errc::operation_not_permitted ||
           error == std::errc::too_many_links;
}

bool has_identical_layer_file_geometry(
    const EncryptedTraceLayerDescriptor &source,
    const EncryptedTraceLayerDescriptor &destination) {
    return source.layout == destination.layout &&
           source.dimensions.logical_size ==
               destination.dimensions.logical_size &&
           source.required_mult_depth ==
               destination.required_mult_depth &&
           source.record_count == destination.record_count;
}

void require_private_directory_inventory(
    const std::filesystem::path &directory,
    const std::filesystem::path &layer) {
    const std::set<std::string> expected_names{
        "manifest.bin", layer.filename().string()};
    for (const std::filesystem::directory_entry &entry :
         std::filesystem::directory_iterator(directory)) {
        if (!expected_names.contains(entry.path().filename().string())) {
            throw std::runtime_error(
                "private trace store contains an unexpected file");
        }
    }
}

} // namespace

std::optional<SerializedTraceStore>
SerializedTraceStore::try_link_private_single_layer_store(
    const std::filesystem::path &destination,
    const EncryptedTraceDescriptor &destination_descriptor,
    FileTraceStoreOptions options,
    FileTraceStorePrivateLinkReport &publication) const {
    publication = {};
    if (!impl_ || impl_->files_removed ||
        !impl_->same_writer_private ||
        impl_->integrity_mode !=
            FileTraceStoreIntegrityMode::SameProcessEphemeral ||
        impl_->descriptor.layers.size() != 1U ||
        impl_->layers.size() != 1U ||
        impl_->layer_summaries.size() != 1U) {
        throw std::logic_error(
            "private layer linking requires a live same-writer ephemeral "
            "one-layer store");
    }
    if (destination.empty() || options.max_total_bytes == 0 ||
        options.min_free_bytes == 0 ||
        options.transfer_buffer_bytes == 0 ||
        options.integrity_mode !=
            FileTraceStoreIntegrityMode::SameProcessEphemeral) {
        throw std::invalid_argument(
            "private layer linking requires nonzero ephemeral store "
            "options");
    }
    validate_encrypted_trace_descriptor(destination_descriptor);
    if (destination_descriptor.layers.size() != 1U ||
        destination_descriptor.shape != impl_->descriptor.shape ||
        destination_descriptor.provenance != impl_->descriptor.provenance ||
        destination_descriptor.circuit_id != impl_->descriptor.circuit_id ||
        destination_descriptor.trace_id == impl_->descriptor.trace_id ||
        !has_identical_layer_file_geometry(
            impl_->descriptor.layers.front(),
            destination_descriptor.layers.front())) {
        throw std::invalid_argument(
            "private linked store descriptor is not a compatible distinct "
            "one-layer view");
    }

#ifdef _WIN32
    (void)destination;
    (void)options;
    return std::nullopt;
#else
    const std::shared_ptr<const LayerFileInfo> source_layer =
        impl_->layers.front();
    if (!source_layer->offsets || !source_layer->private_link_state) {
        throw std::logic_error(
            "same-writer layer is missing private link state");
    }
    std::unique_lock layer_lock(source_layer->access_mutex);
    if (source_layer->active_readers != 0 || source_layer->retired ||
        source_layer->retirement_in_progress || impl_->files_removed) {
        throw std::logic_error(
            "cannot link a private trace layer during access or retirement");
    }
    std::unique_lock backing_lock(source_layer->private_link_state->mutex);
    PrivateLayerLinkState &backing = *source_layer->private_link_state;
    if (backing.owned_links == 0 ||
        backing.identity != source_layer->identity ||
        backing.file_size != source_layer->file_size) {
        throw std::logic_error("private layer link-state drifted");
    }

    require_file_identity(source_layer->path, source_layer->identity,
                          "private source trace layer");
    require_file_identity(manifest_path(impl_->directory),
                          impl_->manifest_identity,
                          "private source trace manifest");
    require_private_directory_inventory(impl_->directory,
                                        source_layer->path);
    std::error_code link_count_error;
    const std::uintmax_t source_link_count =
        std::filesystem::hard_link_count(source_layer->path,
                                         link_count_error);
    if (link_count_error ||
        source_link_count != backing.owned_links) {
        throw std::runtime_error(
            "private source trace layer link count changed");
    }

    const std::filesystem::file_status destination_status =
        std::filesystem::symlink_status(destination);
    if (!std::filesystem::is_directory(destination_status) ||
        !std::filesystem::is_empty(destination)) {
        throw std::invalid_argument(
            "private linked-store destination must be an existing empty "
            "directory");
    }

    struct stat destination_metadata {};
    if (::lstat(destination.c_str(), &destination_metadata) != 0 ||
        !S_ISDIR(destination_metadata.st_mode)) {
        throw std::runtime_error(
            "failed to inspect private linked-store destination");
    }
    if (static_cast<std::uintmax_t>(destination_metadata.st_dev) !=
        source_layer->identity.device) {
        return std::nullopt;
    }

    const OperationTimer publication_timer;
    FileTraceStoreWriteReport report{impl_->report.logical_record_bytes, 0};
    const OperationTimer manifest_encoding_timer;
    std::vector<std::uint8_t> manifest = encode_manifest(
        impl_->backend_context_id, destination_descriptor, report,
        impl_->layer_summaries);
    report.physical_bytes = checked_add(
        source_layer->file_size,
        checked_u64(manifest.size(), "private linked manifest size"),
        "private linked store bytes");
    manifest = encode_manifest(
        impl_->backend_context_id, destination_descriptor, report,
        impl_->layer_summaries);
    publication.diagnostics.serialization += manifest_encoding_timer.stop();
    const std::uint64_t manifest_bytes =
        checked_u64(manifest.size(), "private linked manifest size");
    if (report.physical_bytes > options.max_total_bytes) {
        throw std::length_error(
            "private linked store exceeds max_total_bytes");
    }
    const OperationTimer capacity_timer;
    std::error_code capacity_error;
    const std::filesystem::space_info capacity =
        std::filesystem::space(destination, capacity_error);
    ++publication.diagnostics.capacity_probes;
    publication.diagnostics.capacity_admission += capacity_timer.stop();
    if (capacity_error || manifest_bytes > capacity.available ||
        options.min_free_bytes > capacity.available - manifest_bytes) {
        throw std::length_error(
            "private linked store would violate min_free_bytes");
    }

    const std::filesystem::path destination_layer =
        layer_path(destination, 0, ".bin");
    const std::filesystem::path destination_manifest =
        manifest_path(destination);
    const std::filesystem::path destination_manifest_partial =
        partial_manifest_path(destination);
    std::optional<FileIdentity> destination_manifest_identity;
    bool layer_linked = false;
    bool backing_incremented = false;
    try {
        std::error_code link_error;
        std::filesystem::create_hard_link(
            source_layer->path, destination_layer, link_error);
        if (link_error) {
            if (hard_link_capability_error(link_error)) {
                publication.diagnostics.drain_close_and_publication +=
                    publication_timer.stop();
                return std::nullopt;
            }
            throw std::runtime_error(
                "failed to create private trace-layer hard link: " +
                link_error.message());
        }
        layer_linked = true;
        require_file_identity(destination_layer, source_layer->identity,
                              "private linked trace layer");
        require_file_identity(source_layer->path, source_layer->identity,
                              "private source trace layer");
        link_count_error.clear();
        const std::uintmax_t linked_count =
            std::filesystem::hard_link_count(destination_layer,
                                             link_count_error);
        if (link_count_error ||
            linked_count != backing.owned_links + 1U) {
            throw std::runtime_error(
                "private linked trace layer link count drifted");
        }

        FileIoReport manifest_io;
        destination_manifest_identity = write_exclusive_partial(
            destination_manifest_partial, manifest,
            "private linked trace manifest", &manifest_io);
        publication.diagnostics.write_batches = 1;
        publication.diagnostics.write_syscalls = manifest_io.syscall_count;
        publication.diagnostics.bytes_submitted =
            manifest_io.bytes_transferred;
        publication.diagnostics.maximum_batch_bytes = manifest_bytes;
        publication.diagnostics.storage_write += manifest_io.timing;
        publish_file_no_replace(
            destination_manifest_partial, destination_manifest,
            *destination_manifest_identity,
            "private linked trace manifest");
        require_private_directory_inventory(destination, destination_layer);

        auto layer = std::make_shared<LayerFileInfo>();
        layer->path = destination_layer;
        layer->file_size = source_layer->file_size;
        layer->index_offset = source_layer->index_offset;
        layer->maximum_record_bytes = source_layer->maximum_record_bytes;
        layer->offsets = source_layer->offsets;
        layer->identity = source_layer->identity;
        layer->private_link_state = source_layer->private_link_state;

        auto linked = std::make_shared<SerializedTraceStore::Impl>();
        linked->directory = destination;
        linked->backend_context_id = impl_->backend_context_id;
        linked->descriptor = destination_descriptor;
        linked->report = report;
        linked->layers.push_back(std::move(layer));
        const OperationTimer manifest_hash_timer;
        linked->manifest_id = sha256(manifest);
        publication.diagnostics.hashing += manifest_hash_timer.stop();
        linked->manifest_identity = *destination_manifest_identity;
        linked->layer_summaries = impl_->layer_summaries;
        linked->integrity_mode =
            FileTraceStoreIntegrityMode::SameProcessEphemeral;
        linked->same_writer_private = true;

        ++backing.owned_links;
        backing_incremented = true;
        publication.reused_layer_file_bytes = source_layer->file_size;
        publication.unique_physical_bytes_added = manifest_bytes;
        publication.diagnostics.drain_close_and_publication +=
            publication_timer.stop();
        return SerializedTraceStore(std::move(linked));
    } catch (...) {
        if (destination_manifest_identity) {
            remove_owned_file_noexcept(destination_manifest_partial,
                                       *destination_manifest_identity);
            remove_owned_file_noexcept(destination_manifest,
                                       *destination_manifest_identity);
        }
        if (layer_linked) {
            remove_owned_file_noexcept(destination_layer,
                                       source_layer->identity);
        }
        if (backing_incremented) {
            --backing.owned_links;
        }
        throw;
    }
#endif
}

} // namespace trace_storage
} // namespace laminate::payload
