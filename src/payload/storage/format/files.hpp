#ifndef LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_FILES_HPP
#define LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_FILES_HPP

/// @file files.hpp
/// @brief Private bound-handle and no-replace publication contract.

#include "laminate/payload/storage/file_trace_store.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <vector>

namespace laminate::payload::trace_store_format {

struct FileIdentity {
    std::uintmax_t device = 0;
    std::uintmax_t inode = 0;
    std::uint64_t size = 0;
    std::filesystem::file_time_type write_time{};

    bool operator==(const FileIdentity &other) const = default;
};

struct FileIoReport {
    std::uint64_t syscall_count = 0;
    std::uint64_t bytes_transferred = 0;
    std::uint64_t prefetch_requests = 0;
    std::uint64_t prefetch_bytes_requested = 0;
    std::uint64_t prefetch_fallbacks = 0;
    std::uint64_t maximum_prefetch_request_bytes = 0;
    bool writeback_requested = false;
    bool writeback_enabled = false;
    bool writeback_submit_only = false;
    /// Kernel calls, including calls interrupted before a retry.
    std::uint64_t writeback_submission_attempts = 0;
    /// Submission calls which returned success. This is not evidence that the
    /// corresponding pages were written to stable storage.
    std::uint64_t writeback_submission_successes = 0;
    std::uint64_t maximum_writeback_submission_bytes = 0;
    /// Kernel calls, including calls interrupted before a retry.
    std::uint64_t writeback_wait_attempts = 0;
    std::uint64_t writeback_wait_successes = 0;
    /// Range bytes passed by successful advisory submission/wait calls. These
    /// counters do not measure physical device traffic.
    std::uint64_t writeback_range_bytes_submitted = 0;
    std::uint64_t writeback_range_bytes_waited = 0;
    std::uint64_t writeback_window_bytes = 0;
    /// Largest range in the bounded-wait completion ledger. Submit-only
    /// writers deliberately keep no such ledger and report zero here.
    std::uint64_t maximum_unwaited_writeback_range_bytes = 0;
    std::uint64_t writeback_drains = 0;
    std::uint64_t writeback_drain_range_bytes = 0;
    std::uint64_t writeback_drains_skipped = 0;
    std::uint64_t writeback_range_bytes_without_explicit_wait = 0;
    std::uint64_t positional_write_calls = 0;
    std::uint64_t positional_write_bytes = 0;
    FileTraceStoreOperationTiming timing;
    FileTraceStoreOperationTiming prefetch;
    FileTraceStoreOperationTiming writeback_submission;
    FileTraceStoreOperationTiming writeback_wait;
};

enum class FileWritebackPolicy {
    /// Ordinary buffered writes only.
    Disabled,
    /// Submit advisory writeback and explicitly wait for bounded ranges. The
    /// close boundary detects completion errors surfaced by sync_file_range,
    /// but deliberately provides no crash-durability guarantee for file data
    /// or namespace metadata.
    BoundedWait,
    /// Submit advisory writeback without an explicit completion wait. This is
    /// suitable only for same-process ephemeral artifacts: delayed EIO or
    /// ENOSPC need not be surfaced before close, and process-restart recovery
    /// is intentionally unsupported.
    SubmitOnly,
};

class ExclusiveOutputFile {
  public:
    virtual ~ExclusiveOutputFile() = default;
    virtual bool is_open() const = 0;
    virtual void write(std::span<const std::uint8_t> bytes,
                       const char *description) = 0;
    /// Write adjacent framing and payload spans without concatenating them.
    virtual void write_pair(std::span<const std::uint8_t> first,
                            std::span<const std::uint8_t> second,
                            const char *description) = 0;
    /// Patch bytes at an existing file offset without changing the sequential
    /// write position. Implementations reject an attempted extension.
    virtual void write_at(std::uint64_t offset,
                          std::span<const std::uint8_t> bytes,
                          const char *description) = 0;
    virtual std::uint64_t position(const char *description) const = 0;
    virtual FileIdentity identity(const std::filesystem::path &path,
                                  const char *description) = 0;
    virtual FileIoReport io_report() const = 0;
    virtual void close(const char *description) = 0;
};

std::shared_ptr<ExclusiveOutputFile> create_exclusive_output_file(
    const std::filesystem::path &path, const char *description,
    FileWritebackPolicy writeback_policy = FileWritebackPolicy::Disabled,
    std::uint64_t writeback_window_bytes = 0);

class BoundInputFile {
  public:
    virtual ~BoundInputFile() = default;
    virtual const FileIdentity &identity() const = 0;
    virtual std::uint64_t size() const = 0;
    virtual void read(std::span<std::uint8_t> output,
                      const char *description) = 0;
    /// Read adjacent framing and payload spans, allowing the platform
    /// implementation to gather them into one kernel operation.
    virtual void read_pair(std::span<std::uint8_t> first,
                           std::span<std::uint8_t> second,
                           const char *description) = 0;
    virtual void seek(std::uint64_t offset,
                      const char *description) = 0;
    virtual std::uint64_t position(const char *description) const = 0;
    enum class AccessPattern {
        Sequential,
        Random,
    };
    /// Select the expected access pattern for subsequent ordinary reads.
    /// Unsupported advice is an intentional no-op.
    virtual void set_access_pattern(AccessPattern pattern) noexcept = 0;
    /// Submit advisory page-cache work and return the contiguous prefix for
    /// which every bounded advisory request succeeded. This changes
    /// performance only; it is not evidence that those bytes reached cache.
    /// Unsupported advice returns zero and leaves ordinary reads as the
    /// correctness path.
    virtual std::uint64_t prefetch(std::uint64_t offset,
                                   std::uint64_t length) noexcept = 0;
    virtual FileIoReport io_report() const = 0;
    virtual void require_unchanged(const char *description) const = 0;
};

std::shared_ptr<BoundInputFile> open_bound_input_file(
    const std::filesystem::path &path, const char *description,
    const FileIdentity *expected = nullptr);
FileIdentity file_identity(const std::filesystem::path &path,
                           const char *description);
void require_file_identity(const std::filesystem::path &path,
                           const FileIdentity &expected,
                           const char *description);
void remove_owned_file_noexcept(const std::filesystem::path &path,
                                const FileIdentity &expected) noexcept;
void publish_file_no_replace(const std::filesystem::path &partial,
                             const std::filesystem::path &final,
                             const FileIdentity &expected,
                             const char *description);
std::vector<std::uint8_t> read_small_file(
    const std::filesystem::path &path, std::uint64_t maximum_bytes,
    const char *description,
    FileIdentity *selected_identity = nullptr);
FileIdentity write_exclusive_partial(
    const std::filesystem::path &path,
    std::span<const std::uint8_t> bytes,
    const char *description,
    FileIoReport *io_report = nullptr);
void write_new_published_file(
    const std::filesystem::path &partial,
    const std::filesystem::path &final,
    std::span<const std::uint8_t> bytes,
    const char *description);

} // namespace laminate::payload::trace_store_format

#endif // LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_FILES_HPP
