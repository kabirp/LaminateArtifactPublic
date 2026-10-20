/// @file reclamation.cpp
/// @brief Validated scratch removal and irreversible layer retirement.

#include "../format/retirement.hpp"
#include "validated_state.hpp"

#include "laminate/transcript/hash.hpp"

#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <vector>

namespace laminate::payload {
using namespace trace_store_format;

namespace trace_storage {

FileTraceStoreRemovalReport
SerializedTraceStore::remove_validated_files_detailed() {
    if (!impl_ || impl_->files_removed) {
        throw std::logic_error(
            "validated trace-store files were already removed");
    }
    std::vector<std::unique_lock<std::mutex>> locks;
    locks.reserve(impl_->layers.size());
    for (const auto &layer : impl_->layers) {
        locks.emplace_back(layer->access_mutex);
        if (layer->active_readers != 0) {
            throw std::logic_error(
                "cannot remove a trace store with active readers");
        }
        if (layer->retired || layer->retirement_in_progress) {
            throw std::logic_error(
                "cannot remove a partially retired trace store");
        }
    }

    std::shared_ptr<PrivateLayerLinkState> private_link_state;
    std::optional<std::unique_lock<std::mutex>> private_link_lock;
    if (impl_->layers.size() == 1U &&
        impl_->layers.front()->private_link_state) {
        private_link_state =
            impl_->layers.front()->private_link_state;
        private_link_lock.emplace(private_link_state->mutex);
        const auto &layer = impl_->layers.front();
        if (private_link_state->owned_links == 0 ||
            private_link_state->identity != layer->identity ||
            private_link_state->file_size != layer->file_size) {
            throw std::logic_error(
                "validated trace-store private link state drifted");
        }
        std::error_code link_error;
        const std::uintmax_t link_count =
            std::filesystem::hard_link_count(layer->path, link_error);
        if (link_error ||
            link_count != private_link_state->owned_links) {
            throw std::runtime_error(
                "validated trace-store layer link count changed");
        }
    } else {
        for (const auto &layer : impl_->layers) {
            if (layer->private_link_state) {
                throw std::logic_error(
                    "multi-layer trace store has private link state");
            }
        }
    }

    std::set<std::string> expected_names{"manifest.bin"};
    require_file_identity(manifest_path(impl_->directory),
                          impl_->manifest_identity,
                          "trace-store manifest");
    for (const auto &layer : impl_->layers) {
        require_file_identity(layer->path, layer->identity,
                              "trace layer file");
        expected_names.insert(layer->path.filename().string());
    }
    for (const std::filesystem::directory_entry &entry :
         std::filesystem::directory_iterator(impl_->directory)) {
        if (!expected_names.contains(entry.path().filename().string())) {
            throw std::runtime_error(
                "trace store changed before scratch reclamation");
        }
    }
    std::uint64_t layer_file_bytes = 0;
    for (const auto &layer : impl_->layers) {
        layer_file_bytes = checked_add(
            layer_file_bytes, layer->file_size,
            "validated trace-store layer bytes");
    }
    if (layer_file_bytes > impl_->report.physical_bytes) {
        throw std::logic_error(
            "validated trace-store manifest byte ledger drifted");
    }
    const std::uint64_t manifest_bytes =
        impl_->report.physical_bytes - layer_file_bytes;
    const bool reclaims_private_layer =
        !private_link_state || private_link_state->owned_links == 1U;
    for (const auto &layer : impl_->layers) {
        layer->retirement_in_progress = true;
    }

    bool removed_any = false;
    try {
        for (const auto &layer : impl_->layers) {
            if (!std::filesystem::remove(layer->path)) {
                throw std::runtime_error(
                    "failed to remove validated trace layer");
            }
            removed_any = true;
            layer->retired = true;
            layer->retirement_in_progress = false;
            if (layer->private_link_state) {
                if (private_link_state->owned_links == 0) {
                    throw std::logic_error(
                        "validated trace-store private link count "
                        "underflows");
                }
                --private_link_state->owned_links;
            }
        }
        if (!std::filesystem::remove(manifest_path(impl_->directory))) {
            throw std::runtime_error(
                "failed to remove validated trace-store manifest");
        }
        impl_->files_removed = true;
        return FileTraceStoreRemovalReport{
            impl_->report.physical_bytes,
            checked_add(
                manifest_bytes,
                reclaims_private_layer ? layer_file_bytes : 0U,
                "uniquely reclaimed trace-store bytes")};
    } catch (...) {
        if (removed_any) {
            impl_->files_removed = true;
        }
        for (const auto &layer : impl_->layers) {
            layer->retirement_in_progress = false;
        }
        throw;
    }
}

std::uint64_t SerializedTraceStore::remove_validated_files() {
    return remove_validated_files_detailed()
        .unique_physical_bytes_reclaimed;
}

struct SerializedTraceReclamationSession::Impl {
    SerializedTraceStore store;
    FileTraceRetirementJournalState state;
    Digest session_id{};
    Digest previous_id{};
    bool failed = false;

    explicit Impl(SerializedTraceStore selected_store)
        : store(std::move(selected_store)) {}
};

SerializedTraceReclamationSession::SerializedTraceReclamationSession(
    std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

SerializedTraceReclamationSession::~SerializedTraceReclamationSession() =
    default;
SerializedTraceReclamationSession::SerializedTraceReclamationSession(
    SerializedTraceReclamationSession &&) noexcept = default;
SerializedTraceReclamationSession &
SerializedTraceReclamationSession::operator=(
    SerializedTraceReclamationSession &&) noexcept = default;

SerializedTraceReclamationSession
SerializedTraceReclamationSession::begin(SerializedTraceStore store) {
    if (!store.impl_) {
        throw std::invalid_argument(
            "SerializedTraceReclamationSession: moved trace store");
    }
    for (const auto &layer : store.impl_->layers) {
        if (layer->private_link_state) {
            // A journal retirement charges the whole layer at unlink time.
            // Link-capable private stores instead require whole-store removal,
            // which serializes on the shared backing and charges the inode only
            // when its final owned name is removed.
            throw std::invalid_argument(
                "SerializedTraceReclamationSession: link-capable private "
                "stores require whole-store reclamation");
        }
    }
    const std::filesystem::path &directory = store.impl_->directory;
    std::set<std::string> expected_names{"manifest.bin"};
    for (std::size_t layer = 0; layer < store.impl_->layers.size(); ++layer) {
        const auto &info = store.impl_->layers[layer];
        require_file_identity(info->path, info->identity,
                              "trace layer file");
        expected_names.insert(info->path.filename().string());
    }
    for (const std::filesystem::directory_entry &entry :
         std::filesystem::directory_iterator(directory)) {
        if (!expected_names.contains(entry.path().filename().string())) {
            throw std::runtime_error(
                "cannot begin reclamation in a changed trace store");
        }
    }

    ParsedManifest manifest;
    manifest.backend_context_id = store.impl_->backend_context_id;
    manifest.descriptor = store.impl_->descriptor;
    manifest.report = store.impl_->report;
    manifest.layers = store.impl_->layer_summaries;
    const std::vector<std::uint8_t> session_bytes =
        encode_retirement_session(store.impl_->manifest_id, manifest);
    const std::filesystem::path partial =
        directory / "retirement-session.partial";
    write_new_published_file(partial, retirement_session_path(directory),
                             session_bytes,
                             "trace retirement-session manifest");

    auto result = std::make_unique<Impl>(std::move(store));
    result->session_id = sha256(session_bytes);
    result->previous_id = result->session_id;
    result->state.directory = directory;
    result->state.store_manifest_id = result->store.impl_->manifest_id;
    result->state.backend_context_id =
        result->store.impl_->backend_context_id;
    result->state.circuit_id = result->store.impl_->descriptor.circuit_id;
    result->state.trace_id = result->store.impl_->descriptor.trace_id;
    result->state.retired_layers.assign(
        result->store.impl_->descriptor.layers.size(), false);
    result->state.retirement_order.reserve(
        result->store.impl_->descriptor.layers.size());
    result->state.original_physical_bytes =
        result->store.impl_->report.physical_bytes;
    result->state.remaining_trace_physical_bytes =
        result->store.impl_->report.physical_bytes;
    return SerializedTraceReclamationSession(std::move(result));
}

const std::filesystem::path &
SerializedTraceReclamationSession::directory() const {
    return impl_->store.directory();
}

const Digest &SerializedTraceReclamationSession::backend_context_id() const {
    return impl_->store.backend_context_id();
}

const EncryptedTraceDescriptor &
SerializedTraceReclamationSession::descriptor() const {
    return impl_->store.descriptor();
}

const FileTraceStoreWriteReport &
SerializedTraceReclamationSession::report() const {
    return impl_->store.report();
}

ValidatedPrivateLayerRangeReader
SerializedTraceReclamationSession::layer_range(
    std::size_t layer_index, std::size_t begin, std::size_t end) const {
    if (!impl_ || impl_->failed) {
        throw std::logic_error("trace reclamation session is not usable");
    }
    return impl_->store.layer_range(layer_index, begin, end);
}

FileTraceLayerRetirementReport
SerializedTraceReclamationSession::retire_layer(std::size_t layer_index) {
    if (!impl_ || impl_->failed) {
        throw std::logic_error("trace reclamation session is not usable");
    }
    if (layer_index >= impl_->store.impl_->layers.size()) {
        throw std::out_of_range("trace layer index is out of range");
    }
    const std::shared_ptr<const LayerFileInfo> layer =
        impl_->store.impl_->layers[layer_index];
    std::unique_lock lock(layer->access_mutex);
    if (layer->retired) {
        throw std::logic_error("trace layer was already retired");
    }
    if (layer->retirement_in_progress) {
        throw std::logic_error("trace layer retirement is already active");
    }
    if (layer->active_readers != 0) {
        throw std::logic_error(
            "cannot retire a trace layer while a reader is alive");
    }
    layer->retirement_in_progress = true;

    const std::uint64_t reclaimed =
        impl_->store.impl_->layer_summaries[layer_index].file_size;
    const std::uint64_t cumulative = checked_add(
        impl_->state.reclaimed_physical_bytes, reclaimed,
        "reclaimed trace-layer bytes");
    if (cumulative > impl_->state.original_physical_bytes) {
        layer->retirement_in_progress = false;
        throw std::logic_error("trace-layer reclamation accounting overflow");
    }
    const std::uint64_t generation = impl_->state.generation + 1;
    const std::vector<std::uint8_t> event_bytes = encode_retirement_event(
        generation, layer_index, reclaimed, cumulative, impl_->previous_id,
        impl_->session_id);
    const std::filesystem::path partial = retirement_event_path(
        impl_->state.directory, generation, ".partial");
    const std::filesystem::path final = retirement_event_path(
        impl_->state.directory, generation, ".bin");

    std::optional<FileIdentity> event_identity;
    bool event_published = false;
    try {
        event_identity = write_exclusive_partial(
            partial, event_bytes, "trace retirement event");
        publish_file_no_replace(partial, final, *event_identity,
                                "trace retirement event");
        event_published = true;
        require_file_identity(layer->path, layer->identity,
                              "trace layer file");
        if (!std::filesystem::remove(layer->path)) {
            throw std::runtime_error("failed to remove retired trace layer");
        }
        layer->retired = true;
        layer->retirement_in_progress = false;
        impl_->state.retired_layers[layer_index] = true;
        impl_->state.retirement_order.push_back(layer_index);
        impl_->state.generation = generation;
        impl_->state.reclaimed_physical_bytes = cumulative;
        impl_->state.remaining_trace_physical_bytes =
            impl_->state.original_physical_bytes - cumulative;
        impl_->previous_id = sha256(event_bytes);
    } catch (...) {
        if (event_identity) {
            remove_owned_file_noexcept(partial, *event_identity);
            if (event_published && !layer->retired) {
                remove_owned_file_noexcept(final, *event_identity);
            }
        }
        if (!layer->retired) {
            layer->retirement_in_progress = false;
        } else {
            impl_->failed = true;
        }
        throw;
    }

    return FileTraceLayerRetirementReport{
        layer_index,
        reclaimed,
        cumulative,
        impl_->state.remaining_trace_physical_bytes,
    };
}

FileTraceRetirementJournalState
SerializedTraceReclamationSession::journal_state() const {
    if (!impl_) {
        throw std::logic_error("trace reclamation session was moved");
    }
    return impl_->state;
}

} // namespace trace_storage
} // namespace laminate::payload
