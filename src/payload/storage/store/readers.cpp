/// @file readers.cpp
/// @brief Leased range readers over fully validated layer files.

#include "../format/manifest.hpp"
#include "validated_state.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::payload {
using namespace trace_store_format;

namespace trace_storage {

class LayerReaderLease {
  public:
    explicit LayerReaderLease(std::shared_ptr<const LayerFileInfo> layer)
        : layer_(std::move(layer)) {
        std::scoped_lock lock(layer_->access_mutex);
        if (layer_->retired || layer_->retirement_in_progress) {
            throw std::logic_error("trace layer has been retired");
        }
        ++layer_->active_readers;
        active_ = true;
    }

    ~LayerReaderLease() {
        if (active_) {
            std::scoped_lock lock(layer_->access_mutex);
            --layer_->active_readers;
        }
    }

    LayerReaderLease(const LayerReaderLease &) = delete;
    LayerReaderLease &operator=(const LayerReaderLease &) = delete;

  private:
    std::shared_ptr<const LayerFileInfo> layer_;
    bool active_ = false;
};

struct ValidatedPrivateLayerRangeReader::Impl {
    // Read many contiguous records per system call. Layer records are stored
    // back to back, so one large sequential read amortizes the per-record
    // syscall and lets the device serve a single large transfer instead of
    // thousands of small ones. Uncompressed N=16384 ciphertexts run about
    // 256 KiB per RNS limb, so a full-chain record reaches a few MiB; this cap
    // still batches a dozen-plus of the widest records and hundreds of the
    // narrowest, while staying negligible against host RAM. This buffer bounds
    // the read-ahead RAM per open reader; a single record larger than it still
    // reads in one call.
    static constexpr std::uint64_t kReadAheadBytes =
        kFileTraceStoreTransferBufferBytes;
    std::shared_ptr<const LayerFileInfo> layer;
    LayerReaderLease lease;
    std::shared_ptr<BoundInputFile> input;
    std::size_t range_begin = 0;
    std::size_t range_end = 0;
    std::size_t current = 0;
    std::vector<std::uint8_t> read_ahead;
    std::uint64_t read_ahead_begin = 0;
    std::uint64_t read_ahead_size = 0;
    // Logical frontier covered by successful advisory calls. This is not a
    // cache-residency claim; ordinary reads remain the correctness path.
    std::uint64_t advised_until = 0;
    std::uint64_t read_batches = 0;
    std::uint64_t maximum_batch_bytes = 0;
    std::uint64_t prefetch_seek_disables = 0;
    bool windowed_prefetch_enabled = true;
    FileTraceStoreReadDiagnostics *aggregate_diagnostics = nullptr;
    FileTraceStoreReadDiagnostics published_diagnostics;

    Impl(std::shared_ptr<const LayerFileInfo> selected_layer,
         std::size_t begin, std::size_t end,
         FileTraceStoreReadDiagnostics *selected_aggregate_diagnostics,
         FileTraceStoreReadPattern pattern)
        : layer(std::move(selected_layer)), lease(layer),
          input(open_bound_input_file(layer->path, "trace layer file",
                                      &layer->identity)),
          range_begin(begin), range_end(end), current(begin),
          windowed_prefetch_enabled(
              pattern == FileTraceStoreReadPattern::Sequential),
          aggregate_diagnostics(selected_aggregate_diagnostics) {
        if (!windowed_prefetch_enabled) {
            input->set_access_pattern(BoundInputFile::AccessPattern::Random);
        }
    }

    FileTraceStoreReadDiagnostics diagnostics() const {
        const FileIoReport physical = input->io_report();
        return FileTraceStoreReadDiagnostics{
            .read_batches = read_batches,
            .read_syscalls = physical.syscall_count,
            .bytes_transferred = physical.bytes_transferred,
            .prefetch_requests = physical.prefetch_requests,
            .prefetch_bytes_requested = physical.prefetch_bytes_requested,
            .prefetch_fallbacks = physical.prefetch_fallbacks,
            .prefetch_seek_disables = prefetch_seek_disables,
            .prefetch_window_bytes = windowed_prefetch_enabled
                                         ? kFileTraceStorePrefetchWindowBytes
                                         : 0,
            .maximum_prefetch_request_bytes =
                physical.maximum_prefetch_request_bytes,
            .maximum_batch_bytes = maximum_batch_bytes,
            .transfer_buffer_bytes = static_cast<std::uint64_t>(
                read_ahead.capacity()),
            .storage_read = physical.timing,
            .prefetch = physical.prefetch,
        };
    }

    void publish_diagnostic_delta() noexcept {
        if (aggregate_diagnostics == nullptr) {
            return;
        }
        const FileTraceStoreReadDiagnostics current = diagnostics();
        aggregate_diagnostics->read_batches +=
            current.read_batches - published_diagnostics.read_batches;
        aggregate_diagnostics->read_syscalls +=
            current.read_syscalls - published_diagnostics.read_syscalls;
        aggregate_diagnostics->bytes_transferred +=
            current.bytes_transferred -
            published_diagnostics.bytes_transferred;
        aggregate_diagnostics->prefetch_requests +=
            current.prefetch_requests -
            published_diagnostics.prefetch_requests;
        aggregate_diagnostics->prefetch_bytes_requested +=
            current.prefetch_bytes_requested -
            published_diagnostics.prefetch_bytes_requested;
        aggregate_diagnostics->prefetch_fallbacks +=
            current.prefetch_fallbacks -
            published_diagnostics.prefetch_fallbacks;
        aggregate_diagnostics->prefetch_seek_disables +=
            current.prefetch_seek_disables -
            published_diagnostics.prefetch_seek_disables;
        aggregate_diagnostics->prefetch_window_bytes = std::max(
            aggregate_diagnostics->prefetch_window_bytes,
            current.prefetch_window_bytes);
        aggregate_diagnostics->maximum_prefetch_request_bytes = std::max(
            aggregate_diagnostics->maximum_prefetch_request_bytes,
            current.maximum_prefetch_request_bytes);
        aggregate_diagnostics->maximum_batch_bytes = std::max(
            aggregate_diagnostics->maximum_batch_bytes,
            current.maximum_batch_bytes);
        aggregate_diagnostics->transfer_buffer_bytes = std::max(
            aggregate_diagnostics->transfer_buffer_bytes,
            current.transfer_buffer_bytes);
        aggregate_diagnostics->storage_read.wall_ms +=
            current.storage_read.wall_ms -
            published_diagnostics.storage_read.wall_ms;
        aggregate_diagnostics->storage_read.cpu_ms +=
            current.storage_read.cpu_ms -
            published_diagnostics.storage_read.cpu_ms;
        aggregate_diagnostics->prefetch.wall_ms +=
            current.prefetch.wall_ms - published_diagnostics.prefetch.wall_ms;
        aggregate_diagnostics->prefetch.cpu_ms +=
            current.prefetch.cpu_ms - published_diagnostics.prefetch.cpu_ms;
        published_diagnostics = current;
    }

    ~Impl() { publish_diagnostic_delta(); }

    void require_scan_boundary() const {
        input->require_unchanged("validated private trace layer file");
    }

    // First byte beyond this range: the next record or the layer's index.
    // Read-ahead stays inside the requested records.
    std::uint64_t range_end_offset() const {
        return range_end < layer->offsets->size()
                   ? layer->offsets->at(range_end)
                   : layer->index_offset;
    }

    // Return the framed bytes of the file span [begin, end), reading a larger
    // aligned block when the span is not already buffered. The returned view
    // stays valid until the next call.
    std::span<const std::uint8_t> framed_span(std::uint64_t begin,
                                              std::uint64_t end) {
        if (begin < read_ahead_begin ||
            end > read_ahead_begin + read_ahead_size) {
            const std::uint64_t needed = end - begin;
            std::uint64_t block = windowed_prefetch_enabled
                                      ? std::min(kReadAheadBytes,
                                                 range_end_offset() - begin)
                                      : needed;
            if (block < needed) {
                block = needed;
            }
            if (windowed_prefetch_enabled) {
                const std::uint64_t range_end = range_end_offset();
                const std::uint64_t desired_prefetch_end =
                    begin + std::min(kFileTraceStorePrefetchWindowBytes,
                                     range_end - begin);
                const std::uint64_t prefetch_begin =
                    std::max(begin, advised_until);
                if (prefetch_begin < desired_prefetch_end) {
                    const std::uint64_t advised = input->prefetch(
                        prefetch_begin,
                        desired_prefetch_end - prefetch_begin);
                    advised_until = prefetch_begin + advised;
                    publish_diagnostic_delta();
                }
            }
            if (input->position("trace layer read-ahead position") != begin) {
                input->seek(begin, "trace layer read-ahead seek");
            }
            read_ahead.resize(checked_size(block, "trace layer read-ahead"));
            input->read(
                std::span<std::uint8_t>(read_ahead.data(), read_ahead.size()),
                "trace layer read-ahead");
            ++read_batches;
            maximum_batch_bytes = std::max(maximum_batch_bytes, block);
            read_ahead_begin = begin;
            read_ahead_size = block;
            publish_diagnostic_delta();
        }
        return std::span<const std::uint8_t>(
            read_ahead.data() + (begin - read_ahead_begin),
            checked_size(end - begin, "trace layer framed span"));
    }

    // Discard buffered bytes so a jump re-reads from the new position.
    void reset_read_ahead() {
        read_ahead_begin = 0;
        read_ahead_size = 0;
        advised_until = 0;
    }

    void disable_windowed_prefetch_for_seek() {
        if (windowed_prefetch_enabled) {
            input->set_access_pattern(BoundInputFile::AccessPattern::Random);
            windowed_prefetch_enabled = false;
            ++prefetch_seek_disables;
            publish_diagnostic_delta();
        }
    }
};

ValidatedPrivateLayerRangeReader::ValidatedPrivateLayerRangeReader(
    std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

ValidatedPrivateLayerRangeReader::~ValidatedPrivateLayerRangeReader() =
    default;
ValidatedPrivateLayerRangeReader::ValidatedPrivateLayerRangeReader(
    ValidatedPrivateLayerRangeReader &&) noexcept = default;
ValidatedPrivateLayerRangeReader &
ValidatedPrivateLayerRangeReader::operator=(
    ValidatedPrivateLayerRangeReader &&) noexcept = default;

std::optional<std::vector<std::uint8_t>>
ValidatedPrivateLayerRangeReader::next() {
    std::vector<std::uint8_t> result;
    const std::optional<std::span<const std::uint8_t>> record =
        next_into(result);
    if (!record) {
        return std::nullopt;
    }
    return result;
}

std::optional<std::span<const std::uint8_t>>
ValidatedPrivateLayerRangeReader::next_into(
    std::vector<std::uint8_t> &buffer) {
    const std::optional<std::span<const std::uint8_t>> view = next_view();
    if (!view) {
        return std::nullopt;
    }
    buffer.assign(view->begin(), view->end());
    return std::span<const std::uint8_t>(buffer.data(), buffer.size());
}

std::optional<std::span<const std::uint8_t>>
ValidatedPrivateLayerRangeReader::next_view() {
    if (!impl_) {
        return std::nullopt;
    }
    if (impl_->current == impl_->range_end) {
        return std::nullopt;
    }
    const std::size_t record = impl_->current;
    const std::uint64_t record_begin = impl_->layer->offsets->at(record);
    const std::uint64_t record_end =
        record + 1 < impl_->layer->offsets->size()
            ? impl_->layer->offsets->at(record + 1)
            : impl_->layer->index_offset;
    const std::uint64_t payload_begin = checked_add(
        record_begin, sizeof(std::uint64_t),
        "trace layer payload position");
    if (record_end < payload_begin) {
        throw std::runtime_error("invalid trace layer record length");
    }
    const std::uint64_t expected_length = record_end - payload_begin;
    if (expected_length == 0 ||
        expected_length > kMaximumRecordBytes ||
        expected_length > impl_->layer->maximum_record_bytes) {
        throw std::runtime_error("invalid trace layer record length");
    }
    const std::size_t length =
        checked_size(expected_length, "record length");
    // Fetch the framed record from the read-ahead block. The index-derived
    // record boundaries still bound and align every payload; the block only
    // changes how bytes reach memory.
    const std::span<const std::uint8_t> framed =
        impl_->framed_span(record_begin, record_end);
    std::uint64_t observed_length = 0;
    for (std::size_t byte = 0; byte < sizeof(std::uint64_t); ++byte) {
        observed_length |=
            static_cast<std::uint64_t>(framed[byte]) << (8U * byte);
    }
    if (observed_length != expected_length ||
        observed_length == 0 ||
        observed_length > kMaximumRecordBytes ||
        observed_length > impl_->layer->maximum_record_bytes) {
        throw std::runtime_error("invalid trace layer record length");
    }
    ++impl_->current;
    if (impl_->current == impl_->range_end) {
        impl_->require_scan_boundary();
    }
    return framed.subspan(sizeof(std::uint64_t), length);
}

void ValidatedPrivateLayerRangeReader::rewind() {
    if (!impl_) {
        throw std::logic_error("cannot rewind a moved trace layer reader");
    }
    impl_->require_scan_boundary();
    impl_->current = impl_->range_begin;
    impl_->reset_read_ahead();
    impl_->input->set_access_pattern(
        BoundInputFile::AccessPattern::Sequential);
    impl_->windowed_prefetch_enabled = true;
}

void ValidatedPrivateLayerRangeReader::seek_to(std::size_t position) {
    if (!impl_) {
        throw std::logic_error("cannot seek a moved trace layer reader");
    }
    if (position < impl_->range_begin || position > impl_->range_end) {
        throw std::out_of_range("trace layer seek is outside reader range");
    }
    if (position == impl_->current) {
        return;
    }
    impl_->require_scan_boundary();
    impl_->disable_windowed_prefetch_for_seek();
    impl_->current = position;
    impl_->reset_read_ahead();
}

std::size_t ValidatedPrivateLayerRangeReader::begin() const {
    return impl_->range_begin;
}

std::size_t ValidatedPrivateLayerRangeReader::end() const {
    return impl_->range_end;
}

std::size_t ValidatedPrivateLayerRangeReader::position() const {
    return impl_->current;
}

FileTraceStoreReadDiagnostics
ValidatedPrivateLayerRangeReader::diagnostics() const {
    if (!impl_) {
        return {};
    }
    return impl_->diagnostics();
}

ValidatedPrivateLayerRangeReader SerializedTraceStore::layer_range(
    std::size_t layer_index, std::size_t begin, std::size_t end,
    FileTraceStoreReadDiagnostics *aggregate_diagnostics,
    FileTraceStoreReadPattern pattern) const {
    if (layer_index >= impl_->layers.size()) {
        throw std::out_of_range("trace layer index is out of range");
    }
    const std::size_t count =
        impl_->layers[layer_index]->offsets->size();
    if (begin > end || end > count) {
        throw std::out_of_range("trace layer range is out of bounds");
    }
    auto reader =
        std::make_unique<ValidatedPrivateLayerRangeReader::Impl>(
            impl_->layers[layer_index], begin, end,
            aggregate_diagnostics, pattern);
    return ValidatedPrivateLayerRangeReader(std::move(reader));
}

} // namespace trace_storage
} // namespace laminate::payload
