#ifndef LAMINATE_PAYLOAD_STORAGE_FILE_TRACE_STORE_HPP
#define LAMINATE_PAYLOAD_STORAGE_FILE_TRACE_STORE_HPP

/// @file file_trace_store.hpp
/// @brief Versioned, budgeted storage for public-or-encrypted payload traces.

#include "laminate/fhe/storage/value_codec.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/setup/encoding.hpp"
#include "laminate/payload/trace/encrypted_trace.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace laminate::payload {

/// Production sequential-transfer target. Writers cap this by their admitted
/// artifact size; readers use one reusable buffer per live range reader.
inline constexpr std::uint64_t kFileTraceStoreTransferBufferBytes =
    128ULL * 1024ULL * 1024ULL;

/// Maximum sequential trace bytes whose Linux writeback may remain in flight
/// before the writer waits for the oldest prefix. This consumes the existing
/// page-cache reserve, not process-resident transfer-buffer memory.
inline constexpr std::uint64_t kFileTraceStoreWritebackWindowBytes =
    1024ULL * 1024ULL * 1024ULL;

/// Linux WILLNEED is capped by the backing device's read-ahead geometry. Keep
/// one bounded logical window ahead of each reader, but submit it as requests
/// no larger than both this ceiling and twice the measured BDI read-ahead.
/// Target hosts tune an 8 MiB BDI read-ahead, making the qualified request
/// 16 MiB. Smaller qualified requests leave explicit WILLNEED disabled and
/// rely on the one-time SEQUENTIAL advice plus ordinary kernel readahead.
inline constexpr std::uint64_t kFileTraceStorePrefetchWindowBytes =
    256ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t kFileTraceStorePrefetchRequestBytes =
    16ULL * 1024ULL * 1024ULL;

/// Maximum range passed to one Linux writeback-submission hint under either
/// completion policy. This is a syscall granularity, not a claim about
/// physical I/O or kernel queue depth.
inline constexpr std::uint64_t kFileTraceStoreWritebackSubmissionBytes =
    16ULL * 1024ULL * 1024ULL;

/// Small bounded-wait windows turn one sequential application batch into an
/// excessive number of writeback syscalls. Zero still disables writeback; an
/// enabled caller-selected window must be at least this large.
inline constexpr std::uint64_t kFileTraceStoreMinimumWritebackWindowBytes =
    1ULL * 1024ULL * 1024ULL;

/// Below this qualified Linux WILLNEED request size, ordinary SEQUENTIAL
/// readahead is cheaper than issuing hundreds or thousands of advisory calls
/// per logical window. An 8 MiB BDI readahead qualifies for the 16 MiB ceiling.
inline constexpr std::uint64_t kFileTraceStoreMinimumPrefetchRequestBytes =
    8ULL * 1024ULL * 1024ULL;

/// Metadata needed to interpret one value-aware trace layer. It intentionally
/// contains no wire values.
struct EncryptedTraceLayerDescriptor {
    TraceLayerLayout layout = TraceLayerLayout::Wide;
    LayerDimensions dimensions;
    std::size_t required_mult_depth = 0;
    /// Number of serialized distinct wire records. Padding is virtual, and
    /// identical affine recipes that feed a dense multiplication layer share
    /// one setup-derived record in a v4 trace store.
    std::size_t record_count = 0;

    bool operator==(const EncryptedTraceLayerDescriptor &other) const =
        default;
};

/// Value-free description of an encrypted proof trace.
struct EncryptedTraceDescriptor {
    PayloadShape shape;
    TraceProvenance provenance = TraceProvenance::SyntheticTrace;
    Digest circuit_id{};
    Digest trace_id{};
    std::vector<EncryptedTraceLayerDescriptor> layers;

    bool operator==(const EncryptedTraceDescriptor &other) const = default;
};

template <fhe::FheBackend Backend>
EncryptedTraceDescriptor descriptor_of(const EncryptedTrace<Backend> &trace) {
    EncryptedTraceDescriptor result;
    result.shape = trace.shape;
    result.provenance = trace.provenance;
    result.circuit_id = trace.circuit_id;
    result.trace_id = trace.trace_id;
    result.layers.reserve(trace.layers.size());
    for (const EncryptedTraceLayer<Backend> &layer : trace.layers) {
        result.layers.push_back(EncryptedTraceLayerDescriptor{
            layer.layout,
            layer.dimensions,
            layer.required_mult_depth,
            layer.wires.size(),
        });
    }
    return result;
}

/// Check descriptor invariants that do not require a circuit.
void validate_encrypted_trace_descriptor(
    const EncryptedTraceDescriptor &descriptor);

/// Require the descriptor to describe the canonical compilation of
/// `payload`. This checks the circuit digest, layer order, dimensions, layout,
/// and semantic record counts; wire values remain outside the descriptor.
void validate_encrypted_trace_descriptor_for_circuit(
    const EncryptedTraceDescriptor &descriptor,
    const PayloadCircuit &payload, const LayeredCircuit &circuit);

/// Integrity boundary for one file-backed trace store.
enum class FileTraceStoreIntegrityMode {
    ReopenableAuthenticated,
    SameProcessEphemeral,
};

/// Hard limits chosen by the caller for one store creation. Both byte limits
/// are mandatory and nonzero. `max_total_bytes` covers exact file lengths,
/// including record framing, indexes, and the manifest. `min_free_bytes` is
/// checked against physical filesystem capacity at trace and layer
/// boundaries; callers still need operational slack for allocation
/// granularity and metadata. `transfer_buffer_bytes` affects only local I/O
/// batching and never the canonical artifact. `writeback_window_bytes`
/// enables kernel writeback overlap on supported platforms. It bounds
/// foreground waits for authenticated artifacts; same-process artifacts use
/// it only to enable submit-only writeback. Zero disables the optimization;
/// an enabled caller-selected window must be at least
/// `kFileTraceStoreMinimumWritebackWindowBytes`. Unsupported platforms retain
/// ordinary writes.
/// `integrity_mode` defaults to an authenticated, reopenable artifact. The
/// same-process mode is restricted to a consuming writer-to-reader handoff:
/// it keeps canonical record bytes and inode binding, omits record hashes
/// that no process will ever validate, and uses submit-only writeback. The
/// latter never performs an explicit foreground writeback wait; ordinary
/// writes still surface errors reported synchronously by the write/close path
/// and may be throttled by the kernel, but no later completion-error guarantee
/// is added. Reopenable artifacts retain bounded waits and their layer-end
/// drain.
struct FileTraceStoreOptions {
    std::uint64_t max_total_bytes = 0;
    std::uint64_t min_free_bytes = 0;
    std::uint64_t transfer_buffer_bytes =
        kFileTraceStoreTransferBufferBytes;
    std::uint64_t writeback_window_bytes =
        kFileTraceStoreWritebackWindowBytes;
    FileTraceStoreIntegrityMode integrity_mode =
        FileTraceStoreIntegrityMode::ReopenableAuthenticated;
};

/// Caller-selected allocation limits for opening an untrusted trace store.
/// Defaults preserve the v4 format limits; a service should normally choose
/// tighter values from its admitted circuit and storage budget. Encrypted
/// records are also checked against the active backend context before backend
/// decoding.
struct FileTraceStoreOpenLimits {
    std::uint64_t max_manifest_bytes = 64ULL << 20U;
    std::uint64_t max_total_bytes =
        std::numeric_limits<std::uint64_t>::max();
    std::uint64_t max_record_bytes = 1ULL << 30U;
    std::size_t max_layers = 1ULL << 16U;
    std::size_t max_records_per_layer = 1ULL << 20U;
};

struct FileTraceStoreWriteReport {
    /// Sum of semantic record encodings, excluding store framing.
    std::uint64_t logical_record_bytes = 0;
    /// Exact bytes in the finalized layer files and manifest.
    std::uint64_t physical_bytes = 0;

    bool operator==(const FileTraceStoreWriteReport &other) const = default;
};

/// Exact result of removing one private store namespace. Namespace bytes are
/// the file lengths authenticated by that store's manifest. Unique bytes are
/// the live-byte-ledger decrement: a linked layer file is reclaimed only when
/// its last runtime-owned path is removed.
struct FileTraceStoreRemovalReport {
    std::uint64_t namespace_physical_bytes_removed = 0;
    std::uint64_t unique_physical_bytes_reclaimed = 0;

    bool operator==(const FileTraceStoreRemovalReport &) const = default;
};

/// Process-local duration for one storage operation category. These
/// diagnostics are deliberately excluded from canonical trace manifests.
struct FileTraceStoreOperationTiming {
    double wall_ms = 0.0;
    double cpu_ms = 0.0;

    FileTraceStoreOperationTiming &operator+=(
        const FileTraceStoreOperationTiming &other) {
        wall_ms += other.wall_ms;
        cpu_ms += other.cpu_ms;
        return *this;
    }

    bool operator==(const FileTraceStoreOperationTiming &) const = default;
};

/// Local write-path evidence for a newly constructed trace. This state is
/// never serialized, authenticated, or accepted from a reopened artifact.
struct FileTraceStoreWriteDiagnostics {
    std::uint64_t records = 0;
    std::uint64_t authenticated_records = 0;
    std::uint64_t authenticated_record_bytes = 0;
    std::uint64_t same_process_unhashed_records = 0;
    std::uint64_t same_process_unhashed_record_bytes = 0;
    /// Whole-record bytes copied into the transfer slab. Direct backend
    /// serialization leaves this at zero.
    std::uint64_t record_copy_bytes = 0;
    std::uint64_t capacity_probes = 0;
    std::uint64_t write_batches = 0;
    std::uint64_t write_syscalls = 0;
    std::uint64_t bytes_submitted = 0;
    std::uint64_t maximum_batch_bytes = 0;
    std::uint64_t transfer_buffer_bytes = 0;
    std::uint64_t transfer_buffer_count = 0;
    std::uint64_t writeback_files_enabled = 0;
    std::uint64_t writeback_files_fallback = 0;
    /// Files intentionally using non-waiting writeback submission because
    /// their only consumer receives the same-process bound handoff.
    std::uint64_t writeback_files_submit_only = 0;
    /// Kernel calls, including calls interrupted before retry.
    std::uint64_t writeback_submission_attempts = 0;
    /// Submission calls that returned success. This is not evidence that the
    /// corresponding pages reached stable storage.
    std::uint64_t writeback_submission_successes = 0;
    /// Kernel calls, including calls interrupted before retry.
    std::uint64_t writeback_wait_attempts = 0;
    std::uint64_t writeback_wait_successes = 0;
    /// Range bytes passed by successful advisory calls, not device traffic.
    std::uint64_t writeback_range_bytes_submitted = 0;
    std::uint64_t writeback_range_bytes_waited = 0;
    std::uint64_t maximum_writeback_submission_bytes = 0;
    std::uint64_t writeback_window_bytes = 0;
    std::uint64_t maximum_unwaited_writeback_range_bytes = 0;
    std::uint64_t writeback_drains = 0;
    std::uint64_t writeback_drain_range_bytes = 0;
    std::uint64_t writeback_drains_skipped = 0;
    std::uint64_t writeback_range_bytes_without_explicit_wait = 0;
    std::uint64_t positional_write_calls = 0;
    std::uint64_t positional_write_bytes = 0;
    FileTraceStoreOperationTiming serialization;
    FileTraceStoreOperationTiming buffer_assembly;
    FileTraceStoreOperationTiming hashing;
    FileTraceStoreOperationTiming capacity_admission;
    FileTraceStoreOperationTiming output_submission;
    FileTraceStoreOperationTiming storage_write;
    FileTraceStoreOperationTiming writeback_submission;
    FileTraceStoreOperationTiming writeback_wait;
    FileTraceStoreOperationTiming drain_close_and_publication;

    bool operator==(const FileTraceStoreWriteDiagnostics &) const = default;
};

/// Result of publishing one private one-layer store by linking an already
/// validated same-writer layer file. `reused_layer_file_bytes` remain owned
/// by one shared inode and are not charged twice. The destination's distinct
/// manifest is the only newly allocated file content. Diagnostics describe
/// that manifest publication only; they never attribute the reused layer as
/// new application I/O.
struct FileTraceStorePrivateLinkReport {
    std::uint64_t reused_layer_file_bytes = 0;
    std::uint64_t unique_physical_bytes_added = 0;
    FileTraceStoreWriteDiagnostics diagnostics;

    bool operator==(const FileTraceStorePrivateLinkReport &other) const {
        // Operational timings are intentionally not part of the semantic
        // publication result.
        return reused_layer_file_bytes == other.reused_layer_file_bytes &&
               unique_physical_bytes_added ==
                   other.unique_physical_bytes_added;
    }
};

/// Local application-read evidence for one or more validated range readers.
/// A supplied aggregate is updated after every buffered read and prefetch
/// request, so a long-lived monotone reader remains observable while active.
struct FileTraceStoreReadDiagnostics {
    std::uint64_t read_batches = 0;
    std::uint64_t read_syscalls = 0;
    std::uint64_t bytes_transferred = 0;
    /// Successful advisory submissions. Failed or unsupported hints are not
    /// included in either this count or `prefetch_bytes_requested`.
    std::uint64_t prefetch_requests = 0;
    std::uint64_t prefetch_bytes_requested = 0;
    /// Advice qualification or submission failures that caused this reader to
    /// fall back to ordinary reads. At most one is recorded per reader because
    /// explicit advice is disabled after the first failure.
    std::uint64_t prefetch_fallbacks = 0;
    /// Transitions from sequential windowed advice to ordinary reads after an
    /// actual random-access `seek_to`. A later explicit rewind restores
    /// sequential advice and permits another transition.
    std::uint64_t prefetch_seek_disables = 0;
    std::uint64_t prefetch_window_bytes = 0;
    std::uint64_t maximum_prefetch_request_bytes = 0;
    std::uint64_t maximum_batch_bytes = 0;
    std::uint64_t transfer_buffer_bytes = 0;
    FileTraceStoreOperationTiming storage_read;
    FileTraceStoreOperationTiming prefetch;

    bool operator==(const FileTraceStoreReadDiagnostics &) const = default;
};

/// Expected access pattern for a newly opened validated range. Random mode
/// disables block read-ahead and explicit page-cache advice before the first
/// record, including when that record has storage ordinal zero.
enum class FileTraceStoreReadPattern {
    Sequential,
    Random,
};

struct FileTraceStoreWriteResult {
    std::filesystem::path directory;
    /// Backend-derived public fingerprint of the encryption context. It is
    /// never supplied by the caller and is checked automatically on open.
    Digest backend_context_id{};
    EncryptedTraceDescriptor descriptor;
    FileTraceStoreWriteReport report;
    /// Present only for the writer in this process. Reopening the canonical
    /// artifact starts with an empty diagnostic report.
    FileTraceStoreWriteDiagnostics diagnostics;
};

/// Entering a reclamation session is an operational promise, not a cache
/// preference: retired layers cannot be used to retry this proof session.
enum class FileTraceSessionLifecycle {
    PreserveForRetry,
    IrreversibleNoRetry,
};

struct FileTraceReclamationOptions {
    FileTraceSessionLifecycle lifecycle =
        FileTraceSessionLifecycle::PreserveForRetry;
};

struct FileTraceLayerRetirementReport {
    std::size_t layer_index = 0;
    /// Exact finalized layer-file length removed by this operation.
    std::uint64_t reclaimed_physical_bytes = 0;
    /// Cumulative exact layer-file lengths removed by this session.
    std::uint64_t total_reclaimed_physical_bytes = 0;
    /// Original trace bytes still present, including the immutable manifest
    /// but excluding the small retirement journal.
    std::uint64_t remaining_trace_physical_bytes = 0;

    bool operator==(const FileTraceLayerRetirementReport &other) const =
        default;
};

/// Persisted, inspectable state of one explicitly irreversible session.
/// This journal diagnoses partial retirement; it is not a proof checkpoint
/// and does not make interrupted proving resumable.
struct FileTraceRetirementJournalState {
    std::filesystem::path directory;
    Digest store_manifest_id{};
    Digest backend_context_id{};
    Digest circuit_id{};
    Digest trace_id{};
    std::vector<bool> retired_layers;
    std::vector<std::size_t> retirement_order;
    std::uint64_t generation = 0;
    std::uint64_t original_physical_bytes = 0;
    std::uint64_t reclaimed_physical_bytes = 0;
    std::uint64_t remaining_trace_physical_bytes = 0;
};

/// Inspect a retirement journal and require its event chain to agree with the
/// files that remain. Throws for incomplete publication or inconsistent
/// state. This does not reopen a partially retired trace for proving.
FileTraceRetirementJournalState inspect_file_trace_retirement_journal(
    const std::filesystem::path &directory,
    FileTraceStoreOpenLimits limits = {});

/// Validated serialized-record primitives shared by trace storage,
/// checkpoint replay, and file-backed GKR.
namespace trace_storage {

class SerializedTraceStore;

/// Backend-independent writer for already serialized opaque records.
class SerializedTraceWriter {
  public:
    SerializedTraceWriter(std::filesystem::path directory,
                          FileTraceStoreOptions options,
                          Digest backend_context_id);
    ~SerializedTraceWriter();

    SerializedTraceWriter(const SerializedTraceWriter &) = delete;
    SerializedTraceWriter &operator=(const SerializedTraceWriter &) = delete;
    SerializedTraceWriter(SerializedTraceWriter &&) noexcept;
    SerializedTraceWriter &operator=(SerializedTraceWriter &&) noexcept;

    void begin_trace(const PayloadShape &shape,
                     TraceProvenance provenance,
                     const Digest &circuit_id, const Digest &trace_id,
                     std::size_t layer_count);
    void begin_layer(std::size_t layer_index, TraceLayerLayout layout,
                     const LayerDimensions &dimensions,
                     std::size_t required_mult_depth,
                     std::size_t record_count);
    void append_serialized(
        std::span<const std::uint8_t> record,
        FileTraceStoreOperationTiming serialization = {});
    /// Append one record directly into the bounded transfer slab. The
    /// callback must append between one and `maximum_record_bytes` bytes.
    /// Backends thereby avoid a second whole-ciphertext copy. If the declared
    /// maximum exceeds the slab, this transparently uses a temporary record.
    template <typename Append>
    void append_serialized_direct(std::uint64_t maximum_record_bytes,
                                  Append append) {
        append_serialized_direct_erased(
            maximum_record_bytes, &append,
            [](void *opaque, std::vector<std::uint8_t> &output) {
                (*static_cast<Append *>(opaque))(output);
            });
    }
    void finish_layer();
    /// Exact bytes currently owned by partial/final layer files. The final
    /// manifest is added only by `finish()`.
    std::uint64_t current_physical_bytes() const;
    const FileTraceStoreWriteDiagnostics &diagnostics() const;
    /// A value snapshot which includes the active file handle's physical
    /// write and writeback counters. Unlike `diagnostics()`, this is suitable
    /// for progress telemetry before `finish_layer()` folds those counters
    /// into the completed-writer aggregate.
    FileTraceStoreWriteDiagnostics diagnostics_snapshot() const;
    FileTraceStoreWriteResult finish();
    /// Finish a one-layer store and transfer the writer's exact offsets,
    /// metadata, and file identities directly into a private reader handle.
    /// This consuming same-writer handoff performs no content reread and is
    /// intentionally unavailable from a path or `FileTraceStoreWriteResult`.
    /// The caller must have validated record semantics before appending.
    SerializedTraceStore finish_private_single_layer_store() &&;

  private:
    using DirectAppendFunction =
        void (*)(void *, std::vector<std::uint8_t> &);
    void append_serialized_direct_erased(
        std::uint64_t maximum_record_bytes, void *opaque,
        DirectAppendFunction append);
    FileTraceStoreWriteResult finish_impl(bool private_handoff);
    struct Impl;
    std::unique_ptr<Impl> impl_;

    friend class SerializedTraceStore;
};

/// Range reader issued only by a fully validated `SerializedTraceStore`.
///
/// This type is constructed only after either `SerializedTraceStore::open`
/// has checked every record digest, framing boundary, index entry, and backend
/// encoding, or a consuming same-writer handoff has transferred the exact
/// identities and indexes of records emitted by that process. The store
/// directory must therefore remain private while the reader is alive. Each
/// reader binds its own handle to the admitted layer identity at construction
/// and checks that identity again at scan boundaries (rewind, actual
/// reposition, and observed end). Per-record reads recheck the framing but do
/// not repeat file-identity syscalls or record hashing.
class ValidatedPrivateLayerRangeReader {
  public:
    ~ValidatedPrivateLayerRangeReader();

    ValidatedPrivateLayerRangeReader(
        const ValidatedPrivateLayerRangeReader &) = delete;
    ValidatedPrivateLayerRangeReader &
    operator=(const ValidatedPrivateLayerRangeReader &) = delete;
    ValidatedPrivateLayerRangeReader(
        ValidatedPrivateLayerRangeReader &&) noexcept;
    ValidatedPrivateLayerRangeReader &
    operator=(ValidatedPrivateLayerRangeReader &&) noexcept;

    std::optional<std::vector<std::uint8_t>> next();
    /// View the next admitted record without copying it out of the reader's
    /// sequential block. The view is invalidated by the next reader operation.
    /// Decode or otherwise consume it before advancing, rewinding, or seeking.
    std::optional<std::span<const std::uint8_t>> next_view();
    /// Copy the next admitted record from the read-ahead block into `buffer`,
    /// reusing its allocation across calls. The returned span is the complete
    /// record and remains valid only until `buffer` is mutated. On success,
    /// `buffer.size()` is exactly the record size.
    std::optional<std::span<const std::uint8_t>>
    next_into(std::vector<std::uint8_t> &buffer);
    /// Return to the declared range beginning and restore sequential windowed
    /// page-cache advice after any prior random seek.
    void rewind();
    /// Reposition this reader within its declared half-open range while
    /// retaining the same file handle. Seeking to `end()` is allowed. Asking
    /// for the current position is a no-op and performs no identity syscall.
    /// An actual reposition disables windowed advice until the next rewind so
    /// random access cannot submit a large prefetch window per record.
    void seek_to(std::size_t position);
    std::size_t begin() const;
    std::size_t end() const;
    std::size_t position() const;
    FileTraceStoreReadDiagnostics diagnostics() const;

  private:
    struct Impl;
    explicit ValidatedPrivateLayerRangeReader(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;

    friend class SerializedTraceStore;
};

/// Validated manifest and layer indexes, without a backend dependency.
/// `open` is the only untrusted-to-private transition: it sequentially checks
/// every layer digest, record framing boundary, index entry, and caller-
/// supplied record validator before returning. The directory must remain
/// private after that transition so `layer_range` can issue efficient
/// validated-private readers.
class SerializedTraceStore {
  public:
    static SerializedTraceStore open(
        const std::filesystem::path &directory,
        const Digest &expected_backend_context_id,
        const std::function<void(const EncryptedTraceDescriptor &)> &
            validate_descriptor,
        const std::function<void(
            std::size_t, std::size_t,
            std::span<const std::uint8_t>)> &validate_record,
        FileTraceStoreOpenLimits limits = {});

    const std::filesystem::path &directory() const;
    const Digest &backend_context_id() const;
    const EncryptedTraceDescriptor &descriptor() const;
    const FileTraceStoreWriteReport &report() const;
    const FileTraceStoreWriteDiagnostics &write_diagnostics() const;
    /// Try to publish a distinct private one-layer store whose canonical
    /// record and index file is exactly this store's file. Capability-only
    /// hard-link failures return `nullopt` without changing either directory;
    /// validation, identity, or publication failures throw. Both descriptors
    /// must contain exactly one layer with identical file-shaping geometry,
    /// and this store must be a same-writer SameProcessEphemeral handoff.
    /// Payload-vs-forward origin counts may differ because they are manifest
    /// semantics and do not change the canonical record/index bytes.
    std::optional<SerializedTraceStore> try_link_private_single_layer_store(
        const std::filesystem::path &destination,
        const EncryptedTraceDescriptor &destination_descriptor,
        FileTraceStoreOptions options,
        FileTraceStorePrivateLinkReport &publication) const;
    /// Bind a new file handle to the validated layer identity and expose only
    /// the fast private-artifact reader contract.
    ValidatedPrivateLayerRangeReader layer_range(
        std::size_t layer_index, std::size_t begin,
        std::size_t end,
        FileTraceStoreReadDiagnostics *aggregate_diagnostics = nullptr,
        FileTraceStoreReadPattern pattern =
            FileTraceStoreReadPattern::Sequential) const;
    /// Remove every file belonging to this fully validated store and leave
    /// its caller-owned directory empty. Active readers or any path change
    /// reject the operation. Returns unique bytes reclaimed; for an ordinary
    /// store this equals `report().physical_bytes`, while a linked layer is
    /// charged only to its last runtime-owned path. Intended only for
    /// disposable scratch artifacts.
    std::uint64_t remove_validated_files();
    FileTraceStoreRemovalReport remove_validated_files_detailed();

  private:
    struct Impl;
    explicit SerializedTraceStore(std::shared_ptr<Impl> impl);
    std::shared_ptr<Impl> impl_;

    friend class SerializedTraceWriter;
    friend class SerializedTraceReclamationSession;
};

/// Backend-independent ownership state used by the typed reclamation session.
class SerializedTraceReclamationSession {
  public:
    static SerializedTraceReclamationSession begin(SerializedTraceStore store);
    ~SerializedTraceReclamationSession();

    SerializedTraceReclamationSession(
        const SerializedTraceReclamationSession &) = delete;
    SerializedTraceReclamationSession &operator=(
        const SerializedTraceReclamationSession &) = delete;
    SerializedTraceReclamationSession(
        SerializedTraceReclamationSession &&) noexcept;
    SerializedTraceReclamationSession &operator=(
        SerializedTraceReclamationSession &&) noexcept;

    const std::filesystem::path &directory() const;
    const Digest &backend_context_id() const;
    const EncryptedTraceDescriptor &descriptor() const;
    const FileTraceStoreWriteReport &report() const;
    ValidatedPrivateLayerRangeReader layer_range(
        std::size_t layer_index, std::size_t begin,
        std::size_t end) const;
    FileTraceLayerRetirementReport retire_layer(std::size_t layer_index);
    FileTraceRetirementJournalState journal_state() const;

  private:
    struct Impl;
    explicit SerializedTraceReclamationSession(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

/// Number of live records whose padded index is less than `padded_bound`.
inline std::size_t live_wire_rank(const LayerWireSupport &support,
                                  std::size_t padded_bound) {
    if (padded_bound > support.padded_wire_count) {
        throw std::out_of_range("padded trace range is out of bounds");
    }
    std::size_t result = 0;
    for (const LiveWireRange &range : support.live_ranges) {
        if (range.padded_begin >= padded_bound) {
            break;
        }
        result += std::min(range.wire_count,
                           padded_bound - range.padded_begin);
    }
    return result;
}

} // namespace trace_storage

/// Incremental sink for Wide and Laned FHE evaluation. A completed layer is
/// published without replacing any existing path before evaluation advances; the
/// manifest appears only after every declared layer is complete. This
/// publication order detects incomplete stores but does not promise fsync-
/// level power-loss durability. The destination must be a caller-owned
/// private directory. POSIX/macOS builds create files exclusively without
/// following symlinks and bind validation/reads to regular-file handles.
/// The Windows fallback still requires that no untrusted process can mutate
/// the private directory concurrently. The evaluation context must outlive
/// the sink.
template <fhe::PersistableFheBackend Backend>
class FileEncryptedTraceSink {
  public:
    /// Generic evaluators use this trait to emit the canonical distinct-wire
    /// layout: padding is virtual and aliases share a representative record.
    static constexpr bool stores_only_live_wires = true;

    FileEncryptedTraceSink(const typename Backend::EvalContext &eval,
                           std::filesystem::path directory,
                           FileTraceStoreOptions options)
        : eval_(&eval),
          backend_context_id_(Backend::storage_context_id(eval)),
          maximum_ciphertext_bytes_(
              Backend::storage_ciphertext_byte_limit(eval)),
          writer_(std::move(directory), options, backend_context_id_) {}

    FileEncryptedTraceSink(const FileEncryptedTraceSink &) = delete;
    FileEncryptedTraceSink &operator=(const FileEncryptedTraceSink &) =
        delete;
    FileEncryptedTraceSink(FileEncryptedTraceSink &&) noexcept = default;
    FileEncryptedTraceSink &operator=(FileEncryptedTraceSink &&) noexcept =
        default;

    void begin_trace(const PayloadShape &shape, TraceProvenance provenance,
                     const Digest &circuit_id, const Digest &trace_id,
                     std::size_t layer_count) {
        writer_.begin_trace(shape, provenance, circuit_id, trace_id,
                            layer_count);
    }

    void begin_layer(std::size_t layer_index, TraceLayerLayout layout,
                     const LayerDimensions &dimensions,
                     std::size_t required_mult_depth,
                     std::size_t record_count) {
        if (current_required_rns_limbs_ ||
            required_mult_depth == std::numeric_limits<std::size_t>::max()) {
            throw std::invalid_argument(
                "FileEncryptedTraceSink: invalid proof-ingress layer "
                "boundary");
        }
        current_required_rns_limbs_ = required_mult_depth + 1U;
        writer_.begin_layer(layer_index, layout, dimensions,
                            required_mult_depth, record_count);
    }

    void append_value(const fhe::FheValue<Backend> &value) {
        if (!current_required_rns_limbs_) {
            throw std::logic_error(
                "FileEncryptedTraceSink: no layer is active");
        }
        if (value.is_encrypted() &&
            Backend::rns_limb_count(*eval_, value.ciphertext()) !=
                *current_required_rns_limbs_) {
            throw std::invalid_argument(
                "FileEncryptedTraceSink: ciphertext is not at its exact "
                "declared proof-ingress RNS level");
        }
        const std::size_t ciphertext_tag_bytes = 1;
        if (value.is_encrypted() && maximum_ciphertext_bytes_ == 0) {
            throw std::logic_error(
                "FileEncryptedTraceSink: backend has no ciphertext byte "
                "limit");
        }
        const std::size_t slots = Backend::slot_count(*eval_);
        if ((value.is_encrypted() &&
             maximum_ciphertext_bytes_ >
                 std::numeric_limits<std::uint64_t>::max() -
                     ciphertext_tag_bytes) ||
            (!value.is_encrypted() &&
             slots > (std::numeric_limits<std::uint64_t>::max() - 1U -
                      sizeof(std::uint64_t)) /
                         sizeof(std::uint64_t))) {
            throw std::overflow_error(
                "FileEncryptedTraceSink: record byte limit overflows");
        }
        const std::uint64_t maximum_record_bytes = value.is_encrypted()
            ? maximum_ciphertext_bytes_ + ciphertext_tag_bytes
            : 1U + sizeof(std::uint64_t) +
                  static_cast<std::uint64_t>(slots) *
                      sizeof(std::uint64_t);
        writer_.append_serialized_direct(
            maximum_record_bytes,
            [&](std::vector<std::uint8_t> &output) {
                fhe::append_fhe_value_record<Backend>(*eval_, value, output);
            });
    }

    void finish_layer() {
        if (!current_required_rns_limbs_) {
            throw std::logic_error(
                "FileEncryptedTraceSink: no layer is active");
        }
        writer_.finish_layer();
        current_required_rns_limbs_.reset();
    }

    FileTraceStoreWriteDiagnostics diagnostics_snapshot() const {
        return writer_.diagnostics_snapshot();
    }

    FileTraceStoreWriteResult finish() && { return writer_.finish(); }

    /// Same-process handoff for a freshly emitted one-layer private artifact.
    /// `append_value` has already enforced canonical typed backend encodings;
    /// persisted or cross-process artifacts must still use the full opener.
    trace_storage::SerializedTraceStore
    finish_private_single_layer_store() && {
        return std::move(writer_).finish_private_single_layer_store();
    }

    const Digest &storage_context_id() const {
        return backend_context_id_;
    }

  private:
    const typename Backend::EvalContext *eval_;
    Digest backend_context_id_{};
    std::uint64_t maximum_ciphertext_bytes_ = 0;
    std::optional<std::size_t> current_required_rns_limbs_;
    trace_storage::SerializedTraceWriter writer_;
};

/// Persist an existing resident trace through the same incremental sink
/// contract. Evaluators that do not need a resident copy should write values
/// directly to `FileEncryptedTraceSink`.
template <fhe::PersistableFheBackend Backend>
FileTraceStoreWriteResult write_file_encrypted_trace(
    const typename Backend::EvalContext &eval,
    const std::filesystem::path &directory, FileTraceStoreOptions options,
    const LayeredCircuit &circuit,
    const EncryptedTrace<Backend> &trace) {
    const Digest backend_context_id = Backend::storage_context_id(eval);
    if (!trace.backend_context_id ||
        *trace.backend_context_id != backend_context_id) {
        throw std::invalid_argument(
            "write_file_encrypted_trace: trace backend context mismatch");
    }
    if (!(trace.shape == circuit.shape) ||
        trace.layers.size() != circuit.layers.size()) {
        throw std::invalid_argument(
            "write_file_encrypted_trace: trace/circuit shape mismatch");
    }
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(circuit);
    FileEncryptedTraceSink<Backend> sink(eval, directory, options);
    sink.begin_trace(trace.shape, trace.provenance, trace.circuit_id,
                     trace.trace_id, trace.layers.size());
    for (std::size_t layer_index = 0; layer_index < trace.layers.size();
         ++layer_index) {
        const EncryptedTraceLayer<Backend> &layer = trace.layers[layer_index];
        if (!(layer.dimensions ==
              layer_dimensions(circuit.layers[layer_index])) ||
            layer.wires.size() != storage[layer_index].stored_wire_count) {
            throw std::invalid_argument(
                "write_file_encrypted_trace: expected canonical stored "
                "trace layer");
        }
        sink.begin_layer(layer_index, layer.layout, layer.dimensions,
                         layer.required_mult_depth,
                         storage[layer_index].stored_wire_count);
        for (const fhe::FheValue<Backend> &value : layer.wires) {
            sink.append_value(value);
        }
        sink.finish_layer();
    }
    return std::move(sink).finish();
}

template <fhe::PersistableFheBackend Backend>
class FileEncryptedTraceLayerReader {
  public:
    std::optional<fhe::FheValue<Backend>> next() {
        if (position_ == end_) {
            return std::nullopt;
        }

        const std::optional<std::size_t> stored =
            storage_.stored_ordinal_of(position_);
        if (stored) {
            // An alias rereads its setup-derived representative. This keeps
            // the logical reader convenient without retaining duplicate
            // ciphertext objects in memory or on disk.
            reader_.seek_to(*stored);
            ++position_;
            return next_stored(reader_);
        }

        ++position_;
        return fhe::FheValue<Backend>::public_scalar(Fp::zero());
    }

    void rewind() {
        reader_.rewind();
        position_ = begin_;
    }
    std::size_t begin() const { return begin_; }
    std::size_t end() const { return end_; }
    std::size_t position() const { return position_; }
    /// Cumulative semantic-record bytes physically read by this reader,
    /// including records reread for aliases or after rewind. Structural
    /// padding contributes zero bytes.
    std::uint64_t encoded_bytes_read() const { return encoded_bytes_read_; }
    /// Number of serialized records physically read, including records reread
    /// after rewind. Public-zero padding is not a record.
    std::uint64_t serialized_records_read() const {
        return serialized_records_read_;
    }
    /// Decoded ciphertexts retained internally in addition to the value
    /// returned by `next()`. Public tags own no ciphertext.
    std::size_t resident_ciphertexts_held() const { return 0; }

  private:
    FileEncryptedTraceLayerReader(
        const typename Backend::EvalContext &eval,
        LayerStorageLayout storage, std::size_t begin, std::size_t end,
        trace_storage::ValidatedPrivateLayerRangeReader reader)
        : eval_(&eval), storage_(std::move(storage)),
          reader_(std::move(reader)), begin_(begin), end_(end),
          position_(begin) {}

    fhe::FheValue<Backend> next_stored(
        trace_storage::ValidatedPrivateLayerRangeReader &reader) {
        const std::optional<std::span<const std::uint8_t>> encoded =
            reader.next_view();
        if (!encoded) {
            throw std::runtime_error(
                "FileEncryptedTraceLayerReader: missing stored record");
        }
        if (encoded->size() >
            std::numeric_limits<std::uint64_t>::max() -
                encoded_bytes_read_) {
            throw std::overflow_error(
                "FileEncryptedTraceLayerReader: byte counter overflows");
        }
        encoded_bytes_read_ +=
            static_cast<std::uint64_t>(encoded->size());
        if (serialized_records_read_ ==
            std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                "FileEncryptedTraceLayerReader: record counter overflows");
        }
        ++serialized_records_read_;
        return fhe::decode_validated_private_fhe_value_record<Backend>(
                *eval_, *encoded);
    }

    const typename Backend::EvalContext *eval_;
    LayerStorageLayout storage_;
    trace_storage::ValidatedPrivateLayerRangeReader reader_;
    std::size_t begin_ = 0;
    std::size_t end_ = 0;
    std::size_t position_ = 0;
    std::uint64_t encoded_bytes_read_ = 0;
    std::uint64_t serialized_records_read_ = 0;

    template <fhe::PersistableFheBackend>
    friend class FileEncryptedTraceStore;
    template <fhe::PersistableFheBackend>
    friend class FileEncryptedTraceReclamationSession;
};

/// One compact trace record together with its canonical padded protocol
/// index.
template <fhe::PersistableFheBackend Backend>
struct FileEncryptedTraceActiveWire {
    std::size_t padded_index = 0;
    fhe::FheValue<Backend> value;
};

/// Reader over serialized distinct records. `begin`, `end`, and `position`
/// are storage ordinals; each returned record carries the first padded
/// protocol index represented by that record.
template <fhe::PersistableFheBackend Backend>
class FileEncryptedTraceActiveLayerReader {
  public:
    std::optional<FileEncryptedTraceActiveWire<Backend>> next() {
        const std::size_t stored = reader_.position();
        const std::optional<std::span<const std::uint8_t>> encoded =
            reader_.next_view();
        if (!encoded) {
            return std::nullopt;
        }
        if (encoded->size() >
            std::numeric_limits<std::uint64_t>::max() -
                encoded_bytes_read_) {
            throw std::overflow_error(
                "FileEncryptedTraceActiveLayerReader: byte counter "
                "overflows");
        }
        encoded_bytes_read_ +=
            static_cast<std::uint64_t>(encoded->size());
        if (serialized_records_read_ ==
            std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                "FileEncryptedTraceActiveLayerReader: record counter "
                "overflows");
        }
        ++serialized_records_read_;
        return FileEncryptedTraceActiveWire<Backend>{
            storage_.representative_padded_index_of(stored),
            fhe::decode_validated_private_fhe_value_record<Backend>(
                    *eval_, *encoded),
        };
    }

    void rewind() { reader_.rewind(); }
    /// Reposition by storage ordinal without opening another reader.
    /// Padding and logical aliases have no independent stored ordinal.
    void seek_to(std::size_t stored_position) {
        reader_.seek_to(stored_position);
    }
    std::size_t begin() const { return reader_.begin(); }
    std::size_t end() const { return reader_.end(); }
    std::size_t position() const { return reader_.position(); }
    std::uint64_t encoded_bytes_read() const { return encoded_bytes_read_; }
    std::uint64_t serialized_records_read() const {
        return serialized_records_read_;
    }

  private:
    FileEncryptedTraceActiveLayerReader(
        const typename Backend::EvalContext &eval,
        LayerStorageLayout storage,
        trace_storage::ValidatedPrivateLayerRangeReader reader)
        : eval_(&eval), storage_(std::move(storage)),
          reader_(std::move(reader)) {}

    const typename Backend::EvalContext *eval_;
    LayerStorageLayout storage_;
    trace_storage::ValidatedPrivateLayerRangeReader reader_;
    std::uint64_t encoded_bytes_read_ = 0;
    std::uint64_t serialized_records_read_ = 0;

    template <fhe::PersistableFheBackend>
    friend class FileEncryptedTraceStore;
    template <fhe::PersistableFheBackend>
    friend class FileEncryptedTraceReclamationSession;
};

/// Opened file-backed trace. Opening verifies the versioned manifest, every
/// file boundary and index, all semantic-record digests, the expected
/// circuit, and backend-context compatibility. Opening makes one sequential
/// integrity pass over the layer files. Each range reader owns a bounded
/// read-ahead buffer and decodes one value at a time. A record larger than the
/// buffer target is read into a single-record allocation. The evaluation
/// context passed to `open` must outlive the store and its readers.
/// The directory must remain private to the caller while readers are active.
template <fhe::PersistableFheBackend Backend>
class FileEncryptedTraceStore {
  public:
    static FileEncryptedTraceStore open(
        const typename Backend::EvalContext &eval,
        const std::filesystem::path &directory,
        const PayloadCircuit &payload, const LayeredCircuit &circuit,
        TraceProvenance expected_provenance,
        const Digest &expected_trace_id,
        FileTraceStoreOpenLimits limits = {}) {
        const std::uint64_t backend_limit =
            Backend::storage_ciphertext_byte_limit(eval);
        if (backend_limit == 0) {
            throw std::invalid_argument(
                "FileEncryptedTraceStore: backend ciphertext byte limit is "
                "zero");
        }
        std::vector<LayerWireSupport> support =
            canonical_trace_wire_support(circuit);
        std::vector<LayerStorageLayout> storage =
            canonical_trace_storage_layout(circuit);
        std::vector<std::size_t> required_rns_limbs;
        auto serialized = trace_storage::SerializedTraceStore::open(
            directory, Backend::storage_context_id(eval),
            [&](const EncryptedTraceDescriptor &descriptor) {
                validate_encrypted_trace_descriptor_for_circuit(
                    descriptor, payload, circuit);
                if (descriptor.provenance != expected_provenance ||
                    descriptor.trace_id != expected_trace_id) {
                    throw std::invalid_argument(
                        "FileEncryptedTraceStore: execution identity "
                        "mismatch");
                }
                required_rns_limbs.clear();
                required_rns_limbs.reserve(descriptor.layers.size());
                for (const EncryptedTraceLayerDescriptor &layer :
                     descriptor.layers) {
                    if (layer.required_mult_depth ==
                        std::numeric_limits<std::size_t>::max()) {
                        throw std::invalid_argument(
                            "FileEncryptedTraceStore: proof-ingress depth "
                            "overflows");
                    }
                    required_rns_limbs.push_back(
                        layer.required_mult_depth + 1U);
                }
            },
            [&](std::size_t layer, std::size_t,
                std::span<const std::uint8_t> encoded) {
                if (layer >= required_rns_limbs.size()) {
                    throw std::invalid_argument(
                        "FileEncryptedTraceStore: record layer is out of "
                        "range");
                }
                fhe::validate_fhe_value_record<Backend>(
                    eval, encoded, required_rns_limbs[layer], backend_limit);
            },
            limits);
        if (Backend::slot_count(eval) !=
            serialized.descriptor().shape.slot_count) {
            throw std::invalid_argument(
                "FileEncryptedTraceStore: backend slot count mismatch");
        }
        return FileEncryptedTraceStore(
            eval, std::move(serialized), digest(circuit),
            std::move(support), std::move(storage));
    }

    const std::filesystem::path &directory() const {
        return serialized_.directory();
    }

    const EncryptedTraceDescriptor &descriptor() const {
        return serialized_.descriptor();
    }

    const Digest &backend_context_id() const {
        return serialized_.backend_context_id();
    }

    /// Bind generic file-backed consumers to the evaluation context that owns
    /// the stored ciphertexts without exposing how that identity is encoded.
    bool matches_backend_context(
        const typename Backend::EvalContext &eval) const {
        return serialized_.backend_context_id() ==
               Backend::storage_context_id(eval);
    }

    const FileTraceStoreWriteReport &report() const {
        return serialized_.report();
    }

    /// Canonical identity of the exact layered circuit validated by `open`.
    const Digest &layered_circuit_id() const {
        return layered_circuit_id_;
    }

    /// Canonical embedding of compact records in the padded protocol domain.
    const LayerWireSupport &layer_support(std::size_t layer_index) const {
        return support_.at(layer_index);
    }

    const LayerStorageLayout &
    layer_storage_layout(std::size_t layer_index) const {
        return storage_.at(layer_index);
    }

    FileEncryptedTraceLayerReader<Backend>
    layer_reader(std::size_t layer_index) const {
        return layer_reader(layer_index, 0,
                            layer_support(layer_index).padded_wire_count);
    }

    FileEncryptedTraceLayerReader<Backend>
    layer_reader(std::size_t layer_index, std::size_t begin,
                 std::size_t end) const {
        const LayerWireSupport &support = layer_support(layer_index);
        const LayerStorageLayout &storage =
            layer_storage_layout(layer_index);
        if (begin > end || end > support.padded_wire_count) {
            throw std::out_of_range("padded trace range is out of bounds");
        }
        return FileEncryptedTraceLayerReader<Backend>(
            *eval_, storage, begin, end,
            serialized_.layer_range(
                layer_index, 0, storage.stored_wire_count));
    }

    FileEncryptedTraceActiveLayerReader<Backend>
    active_layer_reader(std::size_t layer_index) const {
        return active_layer_reader(
            layer_index, 0,
            layer_storage_layout(layer_index).stored_wire_count);
    }

    FileEncryptedTraceActiveLayerReader<Backend>
    active_layer_reader(std::size_t layer_index, std::size_t stored_begin,
                        std::size_t stored_end) const {
        const LayerStorageLayout &storage =
            layer_storage_layout(layer_index);
        if (stored_begin > stored_end ||
            stored_end > storage.stored_wire_count) {
            throw std::out_of_range(
                "distinct trace range is out of bounds");
        }
        return FileEncryptedTraceActiveLayerReader<Backend>(
            *eval_, storage,
            serialized_.layer_range(layer_index, stored_begin, stored_end));
    }

  private:
    FileEncryptedTraceStore(
        const typename Backend::EvalContext &eval,
        trace_storage::SerializedTraceStore serialized,
        Digest layered_circuit_id,
        std::vector<LayerWireSupport> support,
        std::vector<LayerStorageLayout> storage)
        : eval_(&eval), serialized_(std::move(serialized)),
          layered_circuit_id_(layered_circuit_id),
          support_(std::move(support)), storage_(std::move(storage)) {}

    const typename Backend::EvalContext *eval_;
    trace_storage::SerializedTraceStore serialized_;
    Digest layered_circuit_id_{};
    std::vector<LayerWireSupport> support_;
    std::vector<LayerStorageLayout> storage_;

    template <fhe::PersistableFheBackend>
    friend class FileEncryptedTraceReclamationSession;
};

/// Move-only, explicitly destructive view of a validated trace store. Readers
/// issued by this session carry layer leases; a live lease blocks retirement.
/// Retiring a layer preserves all descriptors and identities in memory while
/// permanently removing only that validated layer file.
template <fhe::PersistableFheBackend Backend>
class FileEncryptedTraceReclamationSession {
  public:
    static FileEncryptedTraceReclamationSession begin(
        FileEncryptedTraceStore<Backend> &&store,
        FileTraceReclamationOptions options) {
        if (options.lifecycle !=
            FileTraceSessionLifecycle::IrreversibleNoRetry) {
            throw std::invalid_argument(
                "FileEncryptedTraceReclamationSession: explicit "
                "IrreversibleNoRetry lifecycle is required");
        }
        const typename Backend::EvalContext *eval = store.eval_;
        const Digest layered_circuit_id = store.layered_circuit_id_;
        std::vector<LayerWireSupport> support = std::move(store.support_);
        std::vector<LayerStorageLayout> storage =
            std::move(store.storage_);
        auto serialized =
            trace_storage::SerializedTraceReclamationSession::begin(
                std::move(store.serialized_));
        return FileEncryptedTraceReclamationSession(
            *eval, std::move(serialized), layered_circuit_id,
            std::move(support), std::move(storage));
    }

    FileEncryptedTraceReclamationSession(
        const FileEncryptedTraceReclamationSession &) = delete;
    FileEncryptedTraceReclamationSession &operator=(
        const FileEncryptedTraceReclamationSession &) = delete;
    FileEncryptedTraceReclamationSession(
        FileEncryptedTraceReclamationSession &&) noexcept = default;
    FileEncryptedTraceReclamationSession &operator=(
        FileEncryptedTraceReclamationSession &&) noexcept = default;

    const std::filesystem::path &directory() const {
        return serialized_.directory();
    }
    const EncryptedTraceDescriptor &descriptor() const {
        return serialized_.descriptor();
    }
    const Digest &backend_context_id() const {
        return serialized_.backend_context_id();
    }
    bool matches_backend_context(
        const typename Backend::EvalContext &eval) const {
        return serialized_.backend_context_id() ==
               Backend::storage_context_id(eval);
    }
    const FileTraceStoreWriteReport &report() const {
        return serialized_.report();
    }
    const Digest &layered_circuit_id() const {
        return layered_circuit_id_;
    }
    const LayerWireSupport &layer_support(std::size_t layer_index) const {
        return support_.at(layer_index);
    }
    const LayerStorageLayout &
    layer_storage_layout(std::size_t layer_index) const {
        return storage_.at(layer_index);
    }

    FileEncryptedTraceLayerReader<Backend>
    layer_reader(std::size_t layer_index) const {
        return layer_reader(layer_index, 0,
                            layer_support(layer_index).padded_wire_count);
    }

    FileEncryptedTraceLayerReader<Backend>
    layer_reader(std::size_t layer_index, std::size_t begin,
                 std::size_t end) const {
        const LayerWireSupport &support = layer_support(layer_index);
        const LayerStorageLayout &storage =
            layer_storage_layout(layer_index);
        if (begin > end || end > support.padded_wire_count) {
            throw std::out_of_range("padded trace range is out of bounds");
        }
        return FileEncryptedTraceLayerReader<Backend>(
            *eval_, storage, begin, end,
            serialized_.layer_range(
                layer_index, 0, storage.stored_wire_count));
    }

    FileEncryptedTraceActiveLayerReader<Backend>
    active_layer_reader(std::size_t layer_index) const {
        return active_layer_reader(
            layer_index, 0,
            layer_storage_layout(layer_index).stored_wire_count);
    }

    FileEncryptedTraceActiveLayerReader<Backend>
    active_layer_reader(std::size_t layer_index, std::size_t stored_begin,
                        std::size_t stored_end) const {
        const LayerStorageLayout &storage =
            layer_storage_layout(layer_index);
        if (stored_begin > stored_end ||
            stored_end > storage.stored_wire_count) {
            throw std::out_of_range(
                "distinct trace range is out of bounds");
        }
        return FileEncryptedTraceActiveLayerReader<Backend>(
            *eval_, storage,
            serialized_.layer_range(layer_index, stored_begin, stored_end));
    }

    FileTraceLayerRetirementReport retire_layer(std::size_t layer_index) {
        return serialized_.retire_layer(layer_index);
    }

    FileTraceRetirementJournalState journal_state() const {
        return serialized_.journal_state();
    }

  private:
    FileEncryptedTraceReclamationSession(
        const typename Backend::EvalContext &eval,
        trace_storage::SerializedTraceReclamationSession serialized,
        Digest layered_circuit_id,
        std::vector<LayerWireSupport> support,
        std::vector<LayerStorageLayout> storage)
        : eval_(&eval), serialized_(std::move(serialized)),
          layered_circuit_id_(layered_circuit_id),
          support_(std::move(support)), storage_(std::move(storage)) {}

    const typename Backend::EvalContext *eval_;
    trace_storage::SerializedTraceReclamationSession serialized_;
    Digest layered_circuit_id_{};
    std::vector<LayerWireSupport> support_;
    std::vector<LayerStorageLayout> storage_;
};

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_STORAGE_FILE_TRACE_STORE_HPP
