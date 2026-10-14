/// @file writer.cpp
/// @brief Budgeted layer writing and atomic manifest publication.

#include "../format/manifest.hpp"
#include "validated_state.hpp"

#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <ctime>
#include <limits>
#include <optional>
#include <set>
#include <stdexcept>
#include <system_error>

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

} // namespace

struct SerializedTraceWriter::Impl {
    std::filesystem::path directory;
    FileTraceStoreOptions options;
    Digest backend_context_id{};
    EncryptedTraceDescriptor descriptor;
    std::vector<std::optional<LayerFileSummary>> layer_summaries;
    std::shared_ptr<ExclusiveOutputFile> active_stream;
    std::filesystem::path active_partial_path;
    std::filesystem::path active_final_path;
    EncryptedTraceLayerDescriptor active_descriptor;
    std::vector<std::uint64_t> active_offsets;
    Digest active_digest{};
    std::uint64_t active_maximum_record_bytes = 0;
    std::size_t active_layer = 0;
    std::size_t active_written = 0;
    std::uint64_t logical_bytes = 0;
    std::uint64_t physical_bytes = 0;
    std::uint64_t reserved_bytes = 0;
    std::uint64_t manifest_bytes = 0;
    FileTraceStoreWriteDiagnostics diagnostics;
    std::vector<std::uint8_t> active_write_buffer;
    std::uint64_t active_virtual_position = 0;
    bool trace_started = false;
    bool layer_active = false;
    bool finished = false;
    bool failed = false;
    std::optional<FileIdentity> active_partial_identity;
    std::optional<FileIdentity> manifest_partial_identity;
    std::optional<FileIdentity> private_layer_identity;
    std::optional<std::uint64_t> private_layer_index_offset;
    std::optional<std::uint64_t> private_maximum_record_bytes;
    std::optional<FileIdentity> finished_manifest_identity;
    std::optional<Digest> finished_manifest_id;

    Impl(std::filesystem::path selected_directory,
         FileTraceStoreOptions selected_options,
         Digest selected_backend_context_id)
        : directory(std::move(selected_directory)),
          options(selected_options),
          backend_context_id(selected_backend_context_id) {
        const bool empty_context = std::all_of(
            backend_context_id.begin(), backend_context_id.end(),
            [](std::uint8_t byte) { return byte == 0; });
        if (directory.empty() || options.max_total_bytes == 0 ||
            options.min_free_bytes == 0 ||
            options.transfer_buffer_bytes == 0 || empty_context) {
            throw std::invalid_argument(
                "SerializedTraceWriter: directory, nonzero limits, and a "
                "nonzero backend context ID are required");
        }
        if (options.writeback_window_bytes != 0 &&
            options.writeback_window_bytes <
                kFileTraceStoreMinimumWritebackWindowBytes) {
            throw std::invalid_argument(
                "SerializedTraceWriter: writeback_window_bytes must be zero "
                "or at least 1 MiB");
        }
        if (options.max_total_bytes > static_cast<std::uint64_t>(
                                          std::numeric_limits<
                                              std::streamoff>::max())) {
            throw std::invalid_argument(
                "SerializedTraceWriter: max_total_bytes exceeds the file "
                "offset range");
        }
        const std::filesystem::file_status status =
            std::filesystem::symlink_status(directory);
        if (std::filesystem::exists(status)) {
            if (!std::filesystem::is_directory(status) ||
                !std::filesystem::is_empty(directory)) {
                throw std::invalid_argument(
                    "SerializedTraceWriter: directory must be empty");
            }
        } else {
            if (!std::filesystem::create_directory(directory)) {
                throw std::runtime_error(
                    "SerializedTraceWriter: failed to create directory");
            }
        }
    }

    ~Impl() { abort_partial(); }

    void abort_partial() noexcept {
        if (active_stream && active_stream->is_open()) {
            if (active_partial_identity && !active_partial_path.empty()) {
                try {
                    active_partial_identity = active_stream->identity(
                        active_partial_path, "partial trace layer");
                } catch (...) {
                }
            }
            try {
                active_stream->close("partial trace layer");
            } catch (...) {
            }
        }
        if (active_partial_identity && !active_partial_path.empty()) {
            remove_owned_file_noexcept(active_partial_path,
                                       *active_partial_identity);
        }
        if (manifest_partial_identity) {
            remove_owned_file_noexcept(partial_manifest_path(directory),
                                       *manifest_partial_identity);
        }
        active_partial_identity.reset();
        manifest_partial_identity.reset();
        active_write_buffer.clear();
    }

    void require_logical_budget(std::uint64_t additional) const {
        if (physical_bytes > options.max_total_bytes ||
            additional > options.max_total_bytes - physical_bytes) {
            throw std::length_error(
                "trace store exceeds max_total_bytes");
        }
    }

    void probe_physical_capacity(std::uint64_t additional) {
        require_logical_budget(additional);
        const OperationTimer timer;
        std::error_code error;
        const std::filesystem::space_info space =
            std::filesystem::space(directory, error);
        ++diagnostics.capacity_probes;
        diagnostics.capacity_admission += timer.stop();
        if (error || additional > space.available ||
            options.min_free_bytes > space.available - additional) {
            throw std::length_error(
                "trace store would violate min_free_bytes");
        }
    }

    void add_reservation(std::uint64_t additional) {
        const std::uint64_t combined = checked_add(
            reserved_bytes, additional, "reserved trace-store bytes");
        require_logical_budget(combined);
        reserved_bytes = combined;
    }

    void submit_active_batch(std::span<const std::uint8_t> bytes,
                             const char *description) {
        if (bytes.empty()) {
            return;
        }
        const OperationTimer timer;
        write_exact(*active_stream, bytes, description);
        diagnostics.output_submission += timer.stop();
        ++diagnostics.write_batches;
        diagnostics.bytes_submitted = checked_add(
            diagnostics.bytes_submitted,
            checked_u64(bytes.size(), description),
            "diagnostic submitted trace-store bytes");
        diagnostics.maximum_batch_bytes = std::max(
            diagnostics.maximum_batch_bytes,
            checked_u64(bytes.size(), description));
    }

    void flush_active_buffer() {
        if (active_write_buffer.empty()) {
            return;
        }
        submit_active_batch(active_write_buffer, "buffered trace layer");
        active_write_buffer.clear();
    }

    void append_to_active_buffer(std::span<const std::uint8_t> bytes,
                                 const char *description) {
        const std::size_t capacity = active_write_buffer.capacity();
        if (bytes.size() > capacity) {
            flush_active_buffer();
            submit_active_batch(bytes, description);
        } else {
            if (bytes.size() > capacity - active_write_buffer.size()) {
                flush_active_buffer();
            }
            active_write_buffer.insert(active_write_buffer.end(),
                                       bytes.begin(), bytes.end());
        }
        active_virtual_position = checked_add(
            active_virtual_position, checked_u64(bytes.size(), description),
            "virtual trace-layer position");
    }

    void account_and_write(std::span<const std::uint8_t> bytes,
                           std::uint64_t reservation_consumed,
                           const char *description) {
        if (reservation_consumed > reserved_bytes) {
            throw std::logic_error(
                "SerializedTraceWriter: invalid storage reservation");
        }
        const std::uint64_t length = checked_u64(bytes.size(), description);
        const std::uint64_t future = reserved_bytes - reservation_consumed;
        require_logical_budget(checked_add(
            length, future, "trace-store capacity requirement"));
        append_to_active_buffer(bytes, description);
        physical_bytes = checked_add(
            physical_bytes, length,
            "physical trace-store bytes");
        reserved_bytes = future;
    }

    void account_and_write_u64(std::uint64_t value,
                               std::uint64_t reservation_consumed,
                               const char *description) {
        if (reservation_consumed > reserved_bytes) {
            throw std::logic_error(
                "SerializedTraceWriter: invalid storage reservation");
        }
        const std::uint64_t future = reserved_bytes - reservation_consumed;
        require_logical_budget(checked_add(
            sizeof(value), future, "trace-store capacity requirement"));
        std::array<std::uint8_t, sizeof(std::uint64_t)> encoded{};
        for (std::size_t byte = 0; byte < encoded.size(); ++byte) {
            encoded[byte] = static_cast<std::uint8_t>(
                (value >> (8U * byte)) & 0xffU);
        }
        append_to_active_buffer(encoded, description);
        physical_bytes = checked_add(physical_bytes, sizeof(value),
                                     "physical trace-store bytes");
        reserved_bytes = future;
    }

    void account_and_write_record(
        std::span<const std::uint8_t> record) {
        // Check the complete framed record once, then issue one gathered
        // write. The length prefix never needs a second large buffer.
        constexpr std::uint64_t reservation_consumed =
            sizeof(std::uint64_t) + 1U;
        if (reservation_consumed > reserved_bytes) {
            throw std::logic_error(
                "SerializedTraceWriter: invalid record reservation");
        }
        const std::uint64_t length =
            checked_u64(record.size(), "record encoding");
        const std::uint64_t framed_length = checked_add(
            sizeof(std::uint64_t), length, "framed trace record");
        const std::uint64_t future =
            reserved_bytes - reservation_consumed;
        require_logical_budget(checked_add(
            framed_length, future, "trace-store capacity requirement"));

        std::array<std::uint8_t, sizeof(std::uint64_t)> encoded_length{};
        for (std::size_t byte = 0; byte < encoded_length.size(); ++byte) {
            encoded_length[byte] = static_cast<std::uint8_t>(
                (length >> (8U * byte)) & 0xffU);
        }
        if (framed_length <= active_write_buffer.capacity()) {
            const std::size_t required = checked_size(
                framed_length, "framed trace record");
            if (required > active_write_buffer.capacity() -
                               active_write_buffer.size()) {
                flush_active_buffer();
            }
            active_write_buffer.insert(active_write_buffer.end(),
                                       encoded_length.begin(),
                                       encoded_length.end());
            const OperationTimer assembly_timer;
            active_write_buffer.insert(active_write_buffer.end(),
                                       record.begin(), record.end());
            diagnostics.buffer_assembly += assembly_timer.stop();
            diagnostics.record_copy_bytes = checked_add(
                diagnostics.record_copy_bytes, length,
                "diagnostic copied trace-record bytes");
            active_virtual_position = checked_add(
                active_virtual_position, framed_length,
                "virtual framed trace-record position");
        } else {
            flush_active_buffer();
            const OperationTimer timer;
            active_stream->write_pair(encoded_length, record,
                                      "framed trace record");
            diagnostics.output_submission += timer.stop();
            ++diagnostics.write_batches;
            diagnostics.bytes_submitted = checked_add(
                diagnostics.bytes_submitted, framed_length,
                "diagnostic submitted trace-store bytes");
            diagnostics.maximum_batch_bytes = std::max(
                diagnostics.maximum_batch_bytes, framed_length);
            active_virtual_position = checked_add(
                active_virtual_position, framed_length,
                "virtual framed trace-record position");
        }
        physical_bytes = checked_add(
            physical_bytes, framed_length, "physical trace-store bytes");
        reserved_bytes = future;
    }

    void account_record_digest(std::span<const std::uint8_t> record) {
        const std::uint64_t length =
            checked_u64(record.size(), "record encoding");
        if (options.integrity_mode ==
            FileTraceStoreIntegrityMode::SameProcessEphemeral) {
            ++diagnostics.same_process_unhashed_records;
            diagnostics.same_process_unhashed_record_bytes = checked_add(
                diagnostics.same_process_unhashed_record_bytes, length,
                "diagnostic unhashed private record bytes");
            return;
        }
        const OperationTimer hashing_timer;
        active_digest = extend_layer_digest(
            active_digest, active_written, record.size(), sha256(record));
        diagnostics.hashing += hashing_timer.stop();
        ++diagnostics.authenticated_records;
        diagnostics.authenticated_record_bytes = checked_add(
            diagnostics.authenticated_record_bytes, length,
            "diagnostic authenticated record bytes");
    }
};

SerializedTraceWriter::SerializedTraceWriter(
    std::filesystem::path directory, FileTraceStoreOptions options,
    Digest backend_context_id)
    : impl_(std::make_unique<Impl>(
          std::move(directory), options, backend_context_id)) {}

SerializedTraceWriter::~SerializedTraceWriter() = default;
SerializedTraceWriter::SerializedTraceWriter(
    SerializedTraceWriter &&) noexcept = default;
SerializedTraceWriter &SerializedTraceWriter::operator=(
    SerializedTraceWriter &&) noexcept = default;

void SerializedTraceWriter::begin_trace(
    const PayloadShape &shape, TraceProvenance provenance,
    const Digest &circuit_id, const Digest &trace_id,
    std::size_t layer_count) {
    if (!impl_ || impl_->trace_started || impl_->finished || impl_->failed ||
        layer_count == 0 || layer_count > kMaximumTraceLayers) {
        throw std::logic_error("SerializedTraceWriter: invalid trace start");
    }
    shape.validate();
    (void)provenance_code(provenance);
    const std::uint64_t manifest_bytes =
        manifest_encoded_bytes(layer_count);
    if (manifest_bytes > kMaximumManifestBytes) {
        throw std::invalid_argument(
            "SerializedTraceWriter: manifest exceeds v4 limits");
    }
    const std::uint64_t layer_overhead = checked_multiply(
        checked_u64(layer_count, "layer count"),
        kLayerHeaderBytes + kIndexHeaderBytes,
        "minimum trace-layer overhead");
    const std::uint64_t initial_reservation = checked_add(
        manifest_bytes, layer_overhead, "minimum trace-store overhead");
    impl_->probe_physical_capacity(initial_reservation);
    impl_->descriptor.shape = shape;
    impl_->descriptor.provenance = provenance;
    impl_->descriptor.circuit_id = circuit_id;
    impl_->descriptor.trace_id = trace_id;
    impl_->descriptor.layers.resize(layer_count);
    impl_->layer_summaries.resize(layer_count);
    impl_->manifest_bytes = manifest_bytes;
    impl_->reserved_bytes = initial_reservation;
    impl_->trace_started = true;
}

void SerializedTraceWriter::begin_layer(
    std::size_t layer_index, TraceLayerLayout layout,
    const LayerDimensions &dimensions, std::size_t required_mult_depth,
    std::size_t record_count) {
    if (!impl_ || !impl_->trace_started || impl_->layer_active ||
        impl_->finished || impl_->failed ||
        layer_index >= impl_->layer_summaries.size() ||
        impl_->layer_summaries[layer_index].has_value()) {
        throw std::logic_error("SerializedTraceWriter: invalid layer start");
    }
    if (record_count > kMaximumRecordsPerLayer) {
        throw std::invalid_argument(
            "SerializedTraceWriter: layer exceeds v4 record limit");
    }
    const EncryptedTraceLayerDescriptor descriptor{
        layout, dimensions, required_mult_depth, record_count};
    validate_dimensions(dimensions);
    const TraceLayerLayout expected_layout =
        impl_->descriptor.shape.kind == PayloadKind::Wide
            ? TraceLayerLayout::Wide
            : TraceLayerLayout::BPeriodic;
    if (layout != expected_layout || record_count == 0 ||
        record_count > dimensions.logical_size) {
        throw std::invalid_argument(
            "SerializedTraceWriter: inconsistent layer metadata");
    }

    impl_->active_layer = layer_index;
    impl_->active_descriptor = descriptor;
    impl_->active_written = 0;
    impl_->active_maximum_record_bytes = 0;
    impl_->active_offsets.clear();
    impl_->active_offsets.reserve(record_count);
    impl_->active_write_buffer.clear();
    const std::uint64_t transfer_bytes = std::min(
        impl_->options.transfer_buffer_bytes,
        impl_->options.max_total_bytes);
    impl_->active_write_buffer.reserve(
        checked_size(transfer_bytes, "trace writer transfer buffer"));
    impl_->diagnostics.transfer_buffer_bytes = std::max(
        impl_->diagnostics.transfer_buffer_bytes, transfer_bytes);
    impl_->diagnostics.transfer_buffer_count =
        transfer_bytes == 0 ? 0 : 1;
    impl_->active_virtual_position = 0;
    impl_->add_reservation(checked_multiply(
        checked_u64(record_count, "record count"),
        kMinimumRecordAndIndexBytes,
        "minimum trace-record and index bytes"));
    // The logical maximum has already been setup-admitted. Recheck actual
    // filesystem capacity once at this layer boundary, never per record.
    impl_->probe_physical_capacity(
        impl_->options.max_total_bytes - impl_->physical_bytes);
    impl_->active_digest =
        initial_layer_digest(layer_index, record_count);
    impl_->active_partial_path =
        layer_path(impl_->directory, layer_index, ".partial");
    impl_->active_final_path =
        layer_path(impl_->directory, layer_index, ".bin");
    try {
        const std::uint64_t writeback_window = std::min(
            impl_->options.writeback_window_bytes,
            impl_->options.max_total_bytes);
        const FileWritebackPolicy writeback_policy =
            writeback_window == 0
                ? FileWritebackPolicy::Disabled
                : impl_->options.integrity_mode ==
                          FileTraceStoreIntegrityMode::SameProcessEphemeral
                      ? FileWritebackPolicy::SubmitOnly
                      : FileWritebackPolicy::BoundedWait;
        impl_->active_stream = create_exclusive_output_file(
            impl_->active_partial_path, "partial trace layer",
            writeback_policy, writeback_window);
        impl_->active_partial_identity = impl_->active_stream->identity(
            impl_->active_partial_path, "partial trace layer");
    } catch (...) {
        impl_->failed = true;
        throw;
    }
    impl_->layer_active = true;
    try {
        impl_->account_and_write(kLayerMagic, kLayerMagic.size(),
                                 "trace layer magic");
        impl_->account_and_write_u64(kFormatVersion, sizeof(std::uint64_t),
                                     "trace layer version");
        impl_->account_and_write_u64(
            checked_u64(layer_index, "layer index"), sizeof(std::uint64_t),
            "trace layer index");
        impl_->account_and_write_u64(
            checked_u64(record_count, "record count"),
            sizeof(std::uint64_t),
            "trace layer record count");
        impl_->account_and_write_u64(0, sizeof(std::uint64_t),
                                     "trace layer index placeholder");
    } catch (...) {
        impl_->abort_partial();
        impl_->layer_active = false;
        impl_->failed = true;
        throw;
    }
}

void SerializedTraceWriter::append_serialized(
    std::span<const std::uint8_t> record,
    FileTraceStoreOperationTiming serialization) {
    if (!impl_ || !impl_->layer_active || impl_->failed ||
        impl_->active_written >= impl_->active_descriptor.record_count) {
        throw std::logic_error(
            "SerializedTraceWriter: no writable record position");
    }
    if (record.empty() || record.size() > kMaximumRecordBytes) {
        throw std::invalid_argument(
            "SerializedTraceWriter: invalid record encoding length");
    }
    const std::uint64_t length =
        checked_u64(record.size(), "record length");
    try {
        impl_->diagnostics.serialization += serialization;
        impl_->active_offsets.push_back(
            impl_->active_virtual_position);
        impl_->account_and_write_record(record);
        impl_->logical_bytes = checked_add(
            impl_->logical_bytes, length, "logical record bytes");
        impl_->account_record_digest(record);
        impl_->active_maximum_record_bytes = std::max(
            impl_->active_maximum_record_bytes, length);
        ++impl_->active_written;
        ++impl_->diagnostics.records;
    } catch (...) {
        impl_->abort_partial();
        impl_->layer_active = false;
        impl_->failed = true;
        throw;
    }
}

void SerializedTraceWriter::append_serialized_direct_erased(
    std::uint64_t maximum_record_bytes, void *opaque,
    DirectAppendFunction append) {
    if (!impl_ || !impl_->layer_active || impl_->failed ||
        impl_->active_written >= impl_->active_descriptor.record_count) {
        throw std::logic_error(
            "SerializedTraceWriter: no writable record position");
    }
    if (!append || maximum_record_bytes == 0 ||
        maximum_record_bytes > kMaximumRecordBytes) {
        throw std::invalid_argument(
            "SerializedTraceWriter: invalid direct record bound");
    }
    const std::uint64_t maximum_framed = checked_add(
        sizeof(std::uint64_t), maximum_record_bytes,
        "maximum framed direct trace record");
    if (maximum_framed > impl_->active_write_buffer.capacity()) {
        std::vector<std::uint8_t> temporary;
        temporary.reserve(checked_size(maximum_record_bytes,
                                       "direct record bound"));
        const OperationTimer serialization_timer;
        append(opaque, temporary);
        const FileTraceStoreOperationTiming serialization =
            serialization_timer.stop();
        if (temporary.empty() || temporary.size() > maximum_record_bytes) {
            throw std::invalid_argument(
                "SerializedTraceWriter: direct record exceeded its bound");
        }
        append_serialized(temporary, serialization);
        return;
    }

    constexpr std::uint64_t reservation_consumed =
        sizeof(std::uint64_t) + 1U;
    try {
        if (reservation_consumed > impl_->reserved_bytes) {
            throw std::logic_error(
                "SerializedTraceWriter: invalid record reservation");
        }
        const std::uint64_t future =
            impl_->reserved_bytes - reservation_consumed;
        const std::size_t maximum_required = checked_size(
            maximum_framed, "maximum framed direct trace record");
        if (maximum_required > impl_->active_write_buffer.capacity() -
                                   impl_->active_write_buffer.size()) {
            impl_->flush_active_buffer();
        }

        impl_->active_offsets.push_back(impl_->active_virtual_position);
        const std::size_t frame_begin = impl_->active_write_buffer.size();
        impl_->active_write_buffer.resize(
            frame_begin + sizeof(std::uint64_t), 0);
        const std::size_t record_begin = impl_->active_write_buffer.size();
        const OperationTimer serialization_timer;
        append(opaque, impl_->active_write_buffer);
        impl_->diagnostics.serialization += serialization_timer.stop();
        if (impl_->active_write_buffer.size() <= record_begin) {
            throw std::invalid_argument(
                "SerializedTraceWriter: direct callback did not append a "
                "record");
        }
        const std::size_t record_size =
            impl_->active_write_buffer.size() - record_begin;
        if (record_size > maximum_record_bytes) {
            throw std::invalid_argument(
                "SerializedTraceWriter: direct record exceeded its bound");
        }
        const std::uint64_t length =
            checked_u64(record_size, "direct record encoding");
        for (std::size_t byte = 0; byte < sizeof(std::uint64_t); ++byte) {
            impl_->active_write_buffer[frame_begin + byte] =
                static_cast<std::uint8_t>(
                    (length >> (8U * byte)) & 0xffU);
        }
        const std::uint64_t framed_length = checked_add(
            sizeof(std::uint64_t), length, "framed direct trace record");
        impl_->require_logical_budget(checked_add(
            framed_length, future,
            "direct trace-store capacity requirement"));
        impl_->active_virtual_position = checked_add(
            impl_->active_virtual_position, framed_length,
            "virtual direct trace-record position");
        impl_->physical_bytes = checked_add(
            impl_->physical_bytes, framed_length,
            "physical trace-store bytes");
        impl_->reserved_bytes = future;
        impl_->logical_bytes = checked_add(
            impl_->logical_bytes, length, "logical record bytes");
        const std::span<const std::uint8_t> record(
            impl_->active_write_buffer.data() + record_begin, record_size);
        impl_->account_record_digest(record);
        impl_->active_maximum_record_bytes = std::max(
            impl_->active_maximum_record_bytes, length);
        ++impl_->active_written;
        ++impl_->diagnostics.records;
    } catch (...) {
        impl_->abort_partial();
        impl_->layer_active = false;
        impl_->failed = true;
        throw;
    }
}

void SerializedTraceWriter::finish_layer() {
    if (!impl_ || !impl_->layer_active || impl_->failed ||
        impl_->active_written != impl_->active_descriptor.record_count) {
        throw std::logic_error("SerializedTraceWriter: incomplete layer");
    }
    try {
        const OperationTimer finalization_timer;
        const std::uint64_t index_offset =
            impl_->active_virtual_position;
        // The offsets are small compared with their ciphertext layer. Emit
        // them as one contiguous index instead of one tiny write per record.
        std::vector<std::uint8_t> index;
        index.reserve(checked_size(
            checked_add(
                kIndexHeaderBytes,
                checked_multiply(
                    checked_u64(impl_->active_offsets.size(), "index count"),
                    sizeof(std::uint64_t), "trace layer index bytes"),
                "trace layer index bytes"),
            "trace layer index bytes"));
        append_magic(index, kIndexMagic);
        append_u64(index, kFormatVersion);
        append_u64(index, checked_u64(impl_->active_offsets.size(),
                                      "index count"));
        for (std::uint64_t offset : impl_->active_offsets) {
            append_u64(index, offset);
        }
        impl_->account_and_write(index, checked_u64(index.size(),
                                                    "trace layer index"),
                                 "trace layer index");

        impl_->flush_active_buffer();

        const OperationTimer offset_timer;
        write_u64_at(*impl_->active_stream, 4 * sizeof(std::uint64_t),
                     index_offset, "trace layer index offset");
        impl_->diagnostics.output_submission += offset_timer.stop();
        ++impl_->diagnostics.write_batches;
        impl_->diagnostics.bytes_submitted = checked_add(
            impl_->diagnostics.bytes_submitted,
            static_cast<std::uint64_t>(sizeof(std::uint64_t)),
            "diagnostic submitted trace-store bytes");
        impl_->diagnostics.maximum_batch_bytes = std::max(
            impl_->diagnostics.maximum_batch_bytes,
            static_cast<std::uint64_t>(sizeof(std::uint64_t)));
        const FileIdentity completed = impl_->active_stream->identity(
            impl_->active_partial_path, "partial trace layer");
        const std::uint64_t file_size = completed.size;
        impl_->active_partial_identity = completed;
        impl_->active_stream->close("trace layer");
        const FileIoReport physical = impl_->active_stream->io_report();
        impl_->diagnostics.write_syscalls = checked_add(
            impl_->diagnostics.write_syscalls, physical.syscall_count,
            "diagnostic trace-store write syscalls");
        impl_->diagnostics.writeback_files_enabled = checked_add(
            impl_->diagnostics.writeback_files_enabled,
            physical.writeback_enabled ? 1U : 0U,
            "diagnostic writeback-enabled files");
        impl_->diagnostics.writeback_files_fallback = checked_add(
            impl_->diagnostics.writeback_files_fallback,
            physical.writeback_requested && !physical.writeback_enabled
                ? 1U
                : 0U,
            "diagnostic writeback-fallback files");
        impl_->diagnostics.writeback_files_submit_only = checked_add(
            impl_->diagnostics.writeback_files_submit_only,
            physical.writeback_submit_only ? 1U : 0U,
            "diagnostic submit-only writeback files");
        impl_->diagnostics.writeback_submission_attempts = checked_add(
            impl_->diagnostics.writeback_submission_attempts,
            physical.writeback_submission_attempts,
            "diagnostic trace-store writeback submission attempts");
        impl_->diagnostics.writeback_submission_successes = checked_add(
            impl_->diagnostics.writeback_submission_successes,
            physical.writeback_submission_successes,
            "diagnostic trace-store writeback submission successes");
        impl_->diagnostics.writeback_wait_attempts = checked_add(
            impl_->diagnostics.writeback_wait_attempts,
            physical.writeback_wait_attempts,
            "diagnostic trace-store writeback wait attempts");
        impl_->diagnostics.writeback_wait_successes = checked_add(
            impl_->diagnostics.writeback_wait_successes,
            physical.writeback_wait_successes,
            "diagnostic trace-store writeback wait successes");
        impl_->diagnostics.writeback_range_bytes_submitted = checked_add(
            impl_->diagnostics.writeback_range_bytes_submitted,
            physical.writeback_range_bytes_submitted,
            "diagnostic submitted writeback range bytes");
        impl_->diagnostics.writeback_range_bytes_waited = checked_add(
            impl_->diagnostics.writeback_range_bytes_waited,
            physical.writeback_range_bytes_waited,
            "diagnostic waited writeback range bytes");
        impl_->diagnostics.maximum_writeback_submission_bytes = std::max(
            impl_->diagnostics.maximum_writeback_submission_bytes,
            physical.maximum_writeback_submission_bytes);
        impl_->diagnostics.writeback_window_bytes = std::max(
            impl_->diagnostics.writeback_window_bytes,
            physical.writeback_window_bytes);
        impl_->diagnostics.maximum_unwaited_writeback_range_bytes = std::max(
            impl_->diagnostics.maximum_unwaited_writeback_range_bytes,
            physical.maximum_unwaited_writeback_range_bytes);
        impl_->diagnostics.writeback_drains = checked_add(
            impl_->diagnostics.writeback_drains,
            physical.writeback_drains,
            "diagnostic writeback drains");
        impl_->diagnostics.writeback_drain_range_bytes = checked_add(
            impl_->diagnostics.writeback_drain_range_bytes,
            physical.writeback_drain_range_bytes,
            "diagnostic writeback drain range bytes");
        impl_->diagnostics.writeback_drains_skipped = checked_add(
            impl_->diagnostics.writeback_drains_skipped,
            physical.writeback_drains_skipped,
            "diagnostic skipped writeback drains");
        impl_->diagnostics.writeback_range_bytes_without_explicit_wait =
            checked_add(
                impl_->diagnostics.writeback_range_bytes_without_explicit_wait,
                physical.writeback_range_bytes_without_explicit_wait,
                "diagnostic writeback range bytes without explicit wait");
        impl_->diagnostics.positional_write_calls = checked_add(
            impl_->diagnostics.positional_write_calls,
            physical.positional_write_calls,
            "diagnostic positional write calls");
        impl_->diagnostics.positional_write_bytes = checked_add(
            impl_->diagnostics.positional_write_bytes,
            physical.positional_write_bytes,
            "diagnostic positional write bytes");
        impl_->diagnostics.storage_write += physical.timing;
        impl_->diagnostics.writeback_submission +=
            physical.writeback_submission;
        impl_->diagnostics.writeback_wait += physical.writeback_wait;
        publish_file_no_replace(impl_->active_partial_path,
                                impl_->active_final_path,
                                completed,
                                "trace layer");
        impl_->active_partial_identity.reset();
        impl_->descriptor.layers[impl_->active_layer] =
            impl_->active_descriptor;
        impl_->layer_summaries[impl_->active_layer] = LayerFileSummary{
            file_size,
            impl_->active_digest,
        };
        if (impl_->descriptor.layers.size() == 1U) {
            impl_->private_layer_identity = completed;
            impl_->private_layer_index_offset = index_offset;
            impl_->private_maximum_record_bytes =
                impl_->active_maximum_record_bytes;
        }
        impl_->active_partial_path.clear();
        impl_->active_final_path.clear();
        impl_->layer_active = false;
        impl_->diagnostics.drain_close_and_publication +=
            finalization_timer.stop();
    } catch (...) {
        impl_->abort_partial();
        impl_->layer_active = false;
        impl_->failed = true;
        throw;
    }
}

std::uint64_t SerializedTraceWriter::current_physical_bytes() const {
    if (!impl_ || impl_->failed) {
        throw std::logic_error(
            "SerializedTraceWriter: unavailable physical-byte count");
    }
    return impl_->physical_bytes;
}

const FileTraceStoreWriteDiagnostics &
SerializedTraceWriter::diagnostics() const {
    if (!impl_) {
        throw std::logic_error(
            "SerializedTraceWriter: diagnostics unavailable");
    }
    return impl_->diagnostics;
}

FileTraceStoreWriteDiagnostics
SerializedTraceWriter::diagnostics_snapshot() const {
    if (!impl_) {
        throw std::logic_error(
            "SerializedTraceWriter: diagnostics unavailable");
    }
    FileTraceStoreWriteDiagnostics result = impl_->diagnostics;
    // A completed layer's physical report has already been folded into
    // `diagnostics`. Include the handle report only while the layer is active,
    // otherwise a snapshot between layers would double-count it.
    if (!impl_->layer_active || !impl_->active_stream) {
        return result;
    }
    const FileIoReport physical = impl_->active_stream->io_report();
    result.write_syscalls += physical.syscall_count;
    result.writeback_files_enabled +=
        physical.writeback_enabled ? 1U : 0U;
    result.writeback_files_fallback +=
        physical.writeback_requested && !physical.writeback_enabled ? 1U
                                                                    : 0U;
    result.writeback_files_submit_only +=
        physical.writeback_submit_only ? 1U : 0U;
    result.writeback_submission_attempts +=
        physical.writeback_submission_attempts;
    result.writeback_submission_successes +=
        physical.writeback_submission_successes;
    result.writeback_wait_attempts += physical.writeback_wait_attempts;
    result.writeback_wait_successes += physical.writeback_wait_successes;
    result.writeback_range_bytes_submitted +=
        physical.writeback_range_bytes_submitted;
    result.writeback_range_bytes_waited +=
        physical.writeback_range_bytes_waited;
    result.maximum_writeback_submission_bytes = std::max(
        result.maximum_writeback_submission_bytes,
        physical.maximum_writeback_submission_bytes);
    result.writeback_window_bytes = std::max(
        result.writeback_window_bytes, physical.writeback_window_bytes);
    result.maximum_unwaited_writeback_range_bytes = std::max(
        result.maximum_unwaited_writeback_range_bytes,
        physical.maximum_unwaited_writeback_range_bytes);
    result.writeback_drains += physical.writeback_drains;
    result.writeback_drain_range_bytes +=
        physical.writeback_drain_range_bytes;
    result.writeback_drains_skipped += physical.writeback_drains_skipped;
    result.writeback_range_bytes_without_explicit_wait +=
        physical.writeback_range_bytes_without_explicit_wait;
    result.positional_write_calls += physical.positional_write_calls;
    result.positional_write_bytes += physical.positional_write_bytes;
    result.storage_write += physical.timing;
    result.writeback_submission += physical.writeback_submission;
    result.writeback_wait += physical.writeback_wait;
    return result;
}

FileTraceStoreWriteResult
SerializedTraceWriter::finish_impl(bool private_handoff) {
    if (!impl_ || !impl_->trace_started || impl_->layer_active ||
        impl_->finished || impl_->failed) {
        throw std::logic_error("SerializedTraceWriter: incomplete trace");
    }
    if (!private_handoff &&
        impl_->options.integrity_mode ==
            FileTraceStoreIntegrityMode::SameProcessEphemeral) {
        throw std::logic_error(
            "same-process ephemeral trace requires a consuming private "
            "handoff");
    }
    std::vector<LayerFileSummary> summaries;
    summaries.reserve(impl_->layer_summaries.size());
    for (const std::optional<LayerFileSummary> &summary :
         impl_->layer_summaries) {
        if (!summary) {
            throw std::logic_error("SerializedTraceWriter: missing layer");
        }
        summaries.push_back(*summary);
    }
    validate_encrypted_trace_descriptor(impl_->descriptor);

    FileTraceStoreWriteReport report{impl_->logical_bytes, 0};
    const OperationTimer manifest_encoding_timer;
    std::vector<std::uint8_t> manifest =
        encode_manifest(impl_->backend_context_id, impl_->descriptor, report,
                        summaries);
    report.physical_bytes = checked_add(
        impl_->physical_bytes,
        checked_u64(manifest.size(), "manifest length"),
        "physical trace-store bytes");
    manifest = encode_manifest(impl_->backend_context_id, impl_->descriptor,
                               report, summaries);
    impl_->diagnostics.serialization += manifest_encoding_timer.stop();
    impl_->probe_physical_capacity(
        checked_u64(manifest.size(), "manifest length"));

    const std::filesystem::path partial =
        partial_manifest_path(impl_->directory);
    const std::filesystem::path final = manifest_path(impl_->directory);
    try {
        const OperationTimer publication_timer;
        FileIoReport manifest_io;
        const FileIdentity completed = write_exclusive_partial(
            partial, manifest, "partial trace manifest", &manifest_io);
        ++impl_->diagnostics.write_batches;
        impl_->diagnostics.write_syscalls += manifest_io.syscall_count;
        impl_->diagnostics.bytes_submitted += manifest_io.bytes_transferred;
        impl_->diagnostics.maximum_batch_bytes = std::max(
            impl_->diagnostics.maximum_batch_bytes,
            checked_u64(manifest.size(), "manifest length"));
        impl_->diagnostics.storage_write += manifest_io.timing;
        impl_->manifest_partial_identity = completed;
        publish_file_no_replace(partial, final, completed,
                                "trace manifest");
        impl_->manifest_partial_identity.reset();
        impl_->finished_manifest_identity = completed;
        const OperationTimer manifest_hash_timer;
        impl_->finished_manifest_id = sha256(manifest);
        impl_->diagnostics.hashing += manifest_hash_timer.stop();
        impl_->diagnostics.drain_close_and_publication +=
            publication_timer.stop();
    } catch (...) {
        if (impl_->manifest_partial_identity) {
            remove_owned_file_noexcept(
                partial, *impl_->manifest_partial_identity);
            impl_->manifest_partial_identity.reset();
        }
        impl_->failed = true;
        throw;
    }
    impl_->physical_bytes = report.physical_bytes;
    impl_->finished = true;
    return FileTraceStoreWriteResult{
        impl_->directory,
        impl_->backend_context_id,
        impl_->descriptor,
        report,
        impl_->diagnostics,
    };
}

FileTraceStoreWriteResult SerializedTraceWriter::finish() {
    return finish_impl(false);
}

SerializedTraceStore
SerializedTraceWriter::finish_private_single_layer_store() && {
    if (!impl_ || impl_->descriptor.layers.size() != 1U) {
        throw std::logic_error(
            "same-writer private handoff requires exactly one layer");
    }
    const std::filesystem::path published_layer =
        layer_path(impl_->directory, 0, ".bin");
    const std::filesystem::path published_manifest =
        manifest_path(impl_->directory);
    const auto remove_owned_publications = [&]() noexcept {
        if (impl_->finished_manifest_identity) {
            remove_owned_file_noexcept(
                published_manifest, *impl_->finished_manifest_identity);
        }
        if (impl_->private_layer_identity) {
            remove_owned_file_noexcept(
                published_layer, *impl_->private_layer_identity);
        }
    };
    try {
        const FileTraceStoreWriteResult written = finish_impl(true);
        if (!impl_->private_layer_identity ||
            !impl_->private_layer_index_offset ||
            !impl_->private_maximum_record_bytes ||
            !impl_->finished_manifest_identity ||
            !impl_->finished_manifest_id ||
            impl_->layer_summaries.size() != 1U ||
            !impl_->layer_summaries.front()) {
            throw std::logic_error(
                "same-writer private handoff state is incomplete");
        }

        require_file_identity(
            published_layer, *impl_->private_layer_identity,
            "same-writer trace layer");
        require_file_identity(
            published_manifest, *impl_->finished_manifest_identity,
            "same-writer trace manifest");
        const std::set<std::string> expected_names{
            "manifest.bin", published_layer.filename().string()};
        for (const std::filesystem::directory_entry &entry :
             std::filesystem::directory_iterator(impl_->directory)) {
            if (!expected_names.contains(entry.path().filename().string())) {
                throw std::runtime_error(
                    "same-writer trace store contains an unexpected file");
            }
        }

        auto layer = std::make_shared<LayerFileInfo>();
        layer->path = published_layer;
        layer->file_size = impl_->private_layer_identity->size;
        layer->index_offset = *impl_->private_layer_index_offset;
        layer->maximum_record_bytes =
            *impl_->private_maximum_record_bytes;
        layer->offsets =
            std::make_shared<const std::vector<std::uint64_t>>(
                std::move(impl_->active_offsets));
        layer->identity = *impl_->private_layer_identity;
        layer->private_link_state =
            std::make_shared<PrivateLayerLinkState>();
        layer->private_link_state->identity = layer->identity;
        layer->private_link_state->file_size = layer->file_size;

        auto adopted = std::make_shared<SerializedTraceStore::Impl>();
        adopted->directory = written.directory;
        adopted->backend_context_id = written.backend_context_id;
        adopted->descriptor = written.descriptor;
        adopted->report = written.report;
        adopted->write_diagnostics = written.diagnostics;
        adopted->layers.push_back(std::move(layer));
        adopted->manifest_id = *impl_->finished_manifest_id;
        adopted->manifest_identity = *impl_->finished_manifest_identity;
        adopted->layer_summaries.push_back(
            *impl_->layer_summaries.front());
        adopted->integrity_mode = impl_->options.integrity_mode;
        adopted->same_writer_private = true;
        impl_.reset();
        return SerializedTraceStore(std::move(adopted));
    } catch (...) {
        remove_owned_publications();
        impl_->failed = true;
        throw;
    }
}

} // namespace trace_storage
} // namespace laminate::payload
