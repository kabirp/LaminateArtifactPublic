/// @file retirement_journal.cpp
/// @brief Inspection of immutable no-retry retirement journals.

#include "../format/retirement.hpp"

#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <set>
#include <stdexcept>

namespace laminate::payload {
using namespace trace_store_format;

FileTraceRetirementJournalState inspect_file_trace_retirement_journal(
    const std::filesystem::path &directory,
    FileTraceStoreOpenLimits limits) {
    validate_open_limits(limits);
    if (!std::filesystem::is_directory(
            std::filesystem::symlink_status(directory))) {
        throw std::invalid_argument(
            "retirement journal path is not a directory");
    }

    const std::vector<std::uint8_t> manifest_bytes = read_small_file(
        manifest_path(directory),
        std::min(kMaximumManifestBytes, limits.max_manifest_bytes),
        "trace-store manifest");
    const ParsedManifest manifest = parse_manifest(manifest_bytes, limits);
    validate_encrypted_trace_descriptor(manifest.descriptor);
    if (manifest.report.physical_bytes > limits.max_total_bytes) {
        throw std::runtime_error(
            "trace store exceeds caller total-byte limit");
    }
    const Digest manifest_id = sha256(manifest_bytes);

    const std::vector<std::uint8_t> session_bytes = read_small_file(
        retirement_session_path(directory), kRetirementSessionBytes,
        "trace retirement-session manifest");
    const ParsedRetirementSession session =
        parse_retirement_session(session_bytes, limits);
    const Digest session_id = sha256(session_bytes);
    if (session.manifest_id != manifest_id ||
        session.backend_context_id != manifest.backend_context_id ||
        session.circuit_id != manifest.descriptor.circuit_id ||
        session.trace_id != manifest.descriptor.trace_id ||
        session.layer_count != manifest.descriptor.layers.size() ||
        session.original_physical_bytes != manifest.report.physical_bytes) {
        throw std::runtime_error(
            "retirement session does not bind the trace-store manifest");
    }

    FileTraceRetirementJournalState result;
    result.directory = directory;
    result.store_manifest_id = manifest_id;
    result.backend_context_id = manifest.backend_context_id;
    result.circuit_id = manifest.descriptor.circuit_id;
    result.trace_id = manifest.descriptor.trace_id;
    result.retired_layers.assign(manifest.descriptor.layers.size(), false);
    result.original_physical_bytes = manifest.report.physical_bytes;

    std::set<std::string> expected_names{
        "manifest.bin", "retirement-session.bin"};
    Digest previous_id = session_id;
    for (std::uint64_t generation = 1;
         generation <= manifest.descriptor.layers.size(); ++generation) {
        const std::filesystem::path path =
            retirement_event_path(directory, generation, ".bin");
        if (!std::filesystem::exists(std::filesystem::symlink_status(path))) {
            break;
        }
        const std::vector<std::uint8_t> bytes = read_small_file(
            path, kRetirementEventBytes, "trace retirement event");
        const ParsedRetirementEvent event = parse_retirement_event(bytes);
        if (event.generation != generation ||
            event.layer_index >= result.retired_layers.size() ||
            result.retired_layers[event.layer_index] ||
            event.previous_id != previous_id ||
            event.session_id != session_id ||
            event.reclaimed_layer_bytes !=
                manifest.layers[event.layer_index].file_size) {
            throw std::runtime_error(
                "retirement event chain is inconsistent");
        }
        const std::uint64_t cumulative = checked_add(
            result.reclaimed_physical_bytes,
            event.reclaimed_layer_bytes,
            "reclaimed trace-layer bytes");
        if (event.cumulative_reclaimed_bytes != cumulative ||
            cumulative > result.original_physical_bytes) {
            throw std::runtime_error(
                "retirement event accounting is inconsistent");
        }
        result.retired_layers[event.layer_index] = true;
        result.retirement_order.push_back(event.layer_index);
        result.generation = generation;
        result.reclaimed_physical_bytes = cumulative;
        previous_id = sha256(bytes);
        expected_names.insert(path.filename().string());
    }
    result.remaining_trace_physical_bytes =
        result.original_physical_bytes - result.reclaimed_physical_bytes;

    for (std::size_t layer = 0; layer < result.retired_layers.size(); ++layer) {
        const std::filesystem::path path =
            layer_path(directory, layer, ".bin");
        if (result.retired_layers[layer]) {
            if (std::filesystem::exists(std::filesystem::symlink_status(path))) {
                throw std::runtime_error(
                    "retired trace layer is still present");
            }
            continue;
        }
        std::uint64_t ignored_logical_bytes = 0;
        (void)scan_layer_file(
            path, layer, manifest.descriptor.layers[layer],
            manifest.layers[layer], ignored_logical_bytes,
            std::min(kMaximumRecordBytes, limits.max_record_bytes),
            [](std::size_t, std::size_t,
               std::span<const std::uint8_t>) {});
        expected_names.insert(path.filename().string());
    }
    for (const std::filesystem::directory_entry &entry :
         std::filesystem::directory_iterator(directory)) {
        if (!expected_names.contains(entry.path().filename().string())) {
            throw std::runtime_error(
                "retirement journal contains an unexpected or partial file");
        }
    }
    return result;
}

} // namespace laminate::payload
