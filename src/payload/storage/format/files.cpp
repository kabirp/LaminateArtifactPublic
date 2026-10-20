/// @file files.cpp
/// @brief Bound file handles, identity checks, and no-replace publication.

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "files.hpp"
#include "schema.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <ctime>
#include <fstream>
#include <limits>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#endif
#if defined(__linux__)
#include <sys/sysmacros.h>
#endif

namespace laminate::payload {
namespace trace_store_format {

namespace {

#if defined(__linux__)
constexpr std::uint64_t kSequentialReadAheadBytesPerKib = 2U * 1024U;

bool valid_linux_device_number(const std::string &candidate) noexcept {
    const auto colon = candidate.find(':');
    if (colon == 0 || colon == std::string::npos ||
        colon + 1 == candidate.size() ||
        candidate.find(':', colon + 1) != std::string::npos) {
        return false;
    }
    const auto is_digit = [](char value) {
        return value >= '0' && value <= '9';
    };
    return std::all_of(
               candidate.begin(), candidate.begin() + colon, is_digit) &&
           std::all_of(
               candidate.begin() + colon + 1, candidate.end(), is_digit);
}

bool read_linux_u64(const std::string &path, std::uint64_t &value) {
    std::ifstream input(path);
    std::uint64_t candidate = 0;
    std::string trailing;
    if (!(input >> candidate) || input >> trailing) {
        return false;
    }
    value = candidate;
    return true;
}

std::uint64_t linux_read_ahead_kib(dev_t device) {
    const std::string device_number =
        std::to_string(major(device)) + ":" + std::to_string(minor(device));
    std::uint64_t result = 0;
    if (read_linux_u64(
            "/sys/class/bdi/" + device_number + "/read_ahead_kb", result)) {
        return result;
    }

    std::ifstream partition(
        "/sys/dev/block/" + device_number + "/partition");
    if (!partition) {
        return 0;
    }
    std::ifstream parent_device(
        "/sys/dev/block/" + device_number + "/../dev");
    std::string parent_device_number;
    std::string trailing;
    if (!(parent_device >> parent_device_number) || parent_device >> trailing ||
        !valid_linux_device_number(parent_device_number) ||
        !read_linux_u64("/sys/class/bdi/" + parent_device_number +
                            "/read_ahead_kb",
                        result)) {
        return 0;
    }
    return result;
}

std::uint64_t qualified_linux_prefetch_request_bytes(dev_t device) noexcept {
    // generic_fadvise() silently caps WILLNEED at max(bdi->io_pages,
    // file->f_ra.ra_pages). POSIX_FADV_SEQUENTIAL sets the latter to twice
    // the BDI read-ahead value. Cache the read-only sysfs qualification once
    // per backing device so opening many range readers does not create a new
    // metadata-I/O path.
    try {
        static std::mutex cache_mutex;
        static std::map<std::uintmax_t, std::uint64_t> cache;
        const std::uintmax_t key = static_cast<std::uintmax_t>(device);
        std::scoped_lock lock(cache_mutex);
        if (const auto found = cache.find(key); found != cache.end()) {
            return found->second;
        }

        std::uint64_t qualified = 0;
        const std::uint64_t read_ahead_kib = linux_read_ahead_kib(device);
        if (read_ahead_kib != 0 &&
            read_ahead_kib <=
                std::numeric_limits<std::uint64_t>::max() /
                    kSequentialReadAheadBytesPerKib) {
            qualified = std::min(
                kFileTraceStorePrefetchRequestBytes,
                read_ahead_kib * kSequentialReadAheadBytesPerKib);
            const long page_size = ::sysconf(_SC_PAGESIZE);
            if (page_size <= 0) {
                qualified = 0;
            } else {
                const std::uint64_t page_bytes =
                    static_cast<std::uint64_t>(page_size);
                qualified -= qualified % page_bytes;
                if (qualified <
                    kFileTraceStoreMinimumPrefetchRequestBytes) {
                    // Small default BDI geometry would require hundreds or
                    // thousands of fadvise calls per logical window. Preserve
                    // the one-time SEQUENTIAL advice and let ordinary kernel
                    // readahead handle that host instead.
                    qualified = 0;
                }
            }
        }
        cache.emplace(key, qualified);
        return qualified;
    } catch (...) {
        return 0;
    }
}
#endif

struct IoTimer {
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

class PlatformExclusiveOutputFile final : public ExclusiveOutputFile {
  public:
    PlatformExclusiveOutputFile() = default;

    PlatformExclusiveOutputFile(const std::filesystem::path &path,
                                const char *description,
                                FileWritebackPolicy writeback_policy,
                                std::uint64_t writeback_window_bytes) {
        if ((writeback_policy == FileWritebackPolicy::Disabled) !=
            (writeback_window_bytes == 0)) {
            throw std::invalid_argument(
                "disabled writeback requires a zero window and enabled "
                "writeback requires a nonzero window");
        }
        io_report_.writeback_requested =
            writeback_policy != FileWritebackPolicy::Disabled;
        io_report_.writeback_submit_only =
            writeback_policy == FileWritebackPolicy::SubmitOnly;
        io_report_.writeback_window_bytes =
            writeback_policy == FileWritebackPolicy::BoundedWait
                ? writeback_window_bytes
                : 0;
#if defined(__linux__)
        io_report_.writeback_enabled =
            io_report_.writeback_requested;
#endif
#ifndef _WIN32
        descriptor_ = ::open(path.c_str(),
                             O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                                 O_CLOEXEC,
                             0600);
        if (descriptor_ < 0) {
            throw std::runtime_error(
                std::string("failed to create exclusive ") + description +
                ": " +
                std::error_code(errno, std::generic_category()).message());
        }
        struct stat metadata {};
        if (::fstat(descriptor_, &metadata) != 0 ||
            !S_ISREG(metadata.st_mode)) {
            close_noexcept();
            throw std::runtime_error(std::string("non-regular ") +
                                     description);
        }
#else
        if (std::filesystem::exists(std::filesystem::symlink_status(path))) {
            throw std::runtime_error(std::string(description) +
                                     " already exists");
        }
        stream_.open(path, std::ios::binary | std::ios::in |
                               std::ios::out | std::ios::trunc);
        if (!stream_) {
            throw std::runtime_error(std::string("failed to create ") +
                                     description);
        }
#endif
    }

    ~PlatformExclusiveOutputFile() override { close_noexcept(); }

    PlatformExclusiveOutputFile(
        const PlatformExclusiveOutputFile &) = delete;
    PlatformExclusiveOutputFile &operator=(
        const PlatformExclusiveOutputFile &) = delete;

    PlatformExclusiveOutputFile(
        PlatformExclusiveOutputFile &&other) noexcept {
        move_from(std::move(other));
    }

    PlatformExclusiveOutputFile &operator=(
        PlatformExclusiveOutputFile &&other) noexcept {
        if (this != &other) {
            close_noexcept();
            move_from(std::move(other));
        }
        return *this;
    }

    bool is_open() const override {
#ifndef _WIN32
        return descriptor_ >= 0;
#else
        return stream_.is_open();
#endif
    }

    void write(std::span<const std::uint8_t> bytes,
               const char *description) override {
#ifndef _WIN32
        prepare_for_writeback(bytes.size(), description);
        const std::uint64_t write_offset = position_;
        const IoTimer write_timer;
        std::size_t written = 0;
        while (written < bytes.size()) {
            const std::size_t remaining = bytes.size() - written;
            const std::size_t chunk = std::min<std::size_t>(
                remaining,
                static_cast<std::size_t>(
                    std::numeric_limits<ssize_t>::max()));
            ++io_report_.syscall_count;
            const ssize_t count = ::write(
                descriptor_, bytes.data() + written, chunk);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw std::runtime_error(std::string("failed to write ") +
                                         description);
            }
            written += static_cast<std::size_t>(count);
            io_report_.bytes_transferred +=
                static_cast<std::uint64_t>(count);
        }
        position_ = checked_add(position_, checked_u64(bytes.size(), description),
                                description);
        io_report_.timing += write_timer.stop();
        schedule_writeback(write_offset,
                           checked_u64(bytes.size(), description),
                           description);
#else
        const IoTimer write_timer;
        if (bytes.size() > static_cast<std::size_t>(
                               std::numeric_limits<std::streamsize>::max())) {
            throw std::overflow_error(std::string(description) +
                                      " exceeds streamsize");
        }
        stream_.write(reinterpret_cast<const char *>(bytes.data()),
                      static_cast<std::streamsize>(bytes.size()));
        if (!stream_) {
            throw std::runtime_error(std::string("failed to write ") +
                                     description);
        }
        ++io_report_.syscall_count;
        io_report_.bytes_transferred +=
            static_cast<std::uint64_t>(bytes.size());
        io_report_.timing += write_timer.stop();
#endif
    }

    void write_pair(std::span<const std::uint8_t> first,
                    std::span<const std::uint8_t> second,
                    const char *description) override {
#ifndef _WIN32
        const std::uint64_t requested = checked_add(
            checked_u64(first.size(), description),
            checked_u64(second.size(), description), description);
        prepare_for_writeback(requested, description);
        const std::uint64_t write_offset = position_;
        const IoTimer write_timer;
        std::array<iovec, 2> parts{
            iovec{const_cast<std::uint8_t *>(first.data()), first.size()},
            iovec{const_cast<std::uint8_t *>(second.data()), second.size()},
        };
        std::size_t part = 0;
        std::uint64_t written_total = 0;
        while (part < parts.size()) {
            ++io_report_.syscall_count;
            const ssize_t written = ::writev(
                descriptor_, parts.data() + part,
                static_cast<int>(parts.size() - part));
            if (written < 0 && errno == EINTR) {
                continue;
            }
            if (written <= 0) {
                throw std::runtime_error(std::string("failed to write ") +
                                         description);
            }
            written_total = checked_add(
                written_total, static_cast<std::uint64_t>(written),
                description);
            io_report_.bytes_transferred = checked_add(
                io_report_.bytes_transferred,
                static_cast<std::uint64_t>(written), description);
            std::size_t consumed = static_cast<std::size_t>(written);
            while (part < parts.size() &&
                   consumed >= parts[part].iov_len) {
                consumed -= parts[part].iov_len;
                ++part;
            }
            if (part < parts.size() && consumed != 0) {
                parts[part].iov_base =
                    static_cast<std::uint8_t *>(parts[part].iov_base) +
                    consumed;
                parts[part].iov_len -= consumed;
            }
        }
        position_ = checked_add(position_, written_total, description);
        io_report_.timing += write_timer.stop();
        schedule_writeback(write_offset, written_total, description);
#else
        const IoTimer write_timer;
        const auto write_part = [&](std::span<const std::uint8_t> bytes) {
            if (bytes.size() > static_cast<std::size_t>(
                                   std::numeric_limits<std::streamsize>::max())) {
                throw std::overflow_error(std::string(description) +
                                          " exceeds streamsize");
            }
            stream_.write(reinterpret_cast<const char *>(bytes.data()),
                          static_cast<std::streamsize>(bytes.size()));
            if (!stream_) {
                throw std::runtime_error(std::string("failed to write ") +
                                         description);
            }
            ++io_report_.syscall_count;
            io_report_.bytes_transferred +=
                static_cast<std::uint64_t>(bytes.size());
        };
        write_part(first);
        write_part(second);
        io_report_.timing += write_timer.stop();
#endif
    }

    void write_at(std::uint64_t offset,
                  std::span<const std::uint8_t> bytes,
                  const char *description) override {
        const std::uint64_t length = checked_u64(bytes.size(), description);
        const std::uint64_t end = checked_add(offset, length, description);
#ifndef _WIN32
        if (end > position_ ||
            offset > static_cast<std::uint64_t>(
                         std::numeric_limits<off_t>::max()) ||
            end > static_cast<std::uint64_t>(
                      std::numeric_limits<off_t>::max())) {
            throw std::overflow_error(std::string(description) +
                                      " is outside the existing file");
        }
        // pwrite leaves the sequential cursor at EOF. Preserve the bounded
        // authenticated policy's completion boundary before patching an
        // already-submitted page. Same-process scratch deliberately skips it
        // and relies on coherent page-cache reads by its bound consumer.
        if (!io_report_.writeback_submit_only) {
            drain_writeback(description);
        }
        const IoTimer write_timer;
        std::size_t written = 0;
        while (written < bytes.size()) {
            const std::size_t remaining = bytes.size() - written;
            const std::size_t chunk = std::min<std::size_t>(
                remaining,
                static_cast<std::size_t>(
                    std::numeric_limits<ssize_t>::max()));
            ++io_report_.syscall_count;
            ++io_report_.positional_write_calls;
            const ssize_t count = ::pwrite(
                descriptor_, bytes.data() + written, chunk,
                static_cast<off_t>(offset + written));
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw std::runtime_error(
                    std::string("failed to positionally write ") +
                    description);
            }
            written += static_cast<std::size_t>(count);
            io_report_.bytes_transferred = checked_add(
                io_report_.bytes_transferred,
                static_cast<std::uint64_t>(count), description);
            io_report_.positional_write_bytes = checked_add(
                io_report_.positional_write_bytes,
                static_cast<std::uint64_t>(count), description);
        }
        io_report_.timing += write_timer.stop();
#else
        const std::streampos sequential_position = stream_.tellp();
        const std::streamoff sequential_offset =
            static_cast<std::streamoff>(sequential_position);
        if (sequential_offset < 0 ||
            end > static_cast<std::uint64_t>(sequential_offset) ||
            offset > static_cast<std::uint64_t>(
                         std::numeric_limits<std::streamoff>::max())) {
            throw std::overflow_error(std::string(description) +
                                      " is outside the existing file");
        }
        const IoTimer write_timer;
        stream_.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
        if (!stream_) {
            throw std::runtime_error(std::string("failed to seek ") +
                                     description);
        }
        if (bytes.size() > static_cast<std::size_t>(
                               std::numeric_limits<std::streamsize>::max())) {
            throw std::overflow_error(std::string(description) +
                                      " exceeds streamsize");
        }
        stream_.write(reinterpret_cast<const char *>(bytes.data()),
                      static_cast<std::streamsize>(bytes.size()));
        if (!stream_) {
            throw std::runtime_error(
                std::string("failed to positionally write ") + description);
        }
        stream_.seekp(sequential_offset, std::ios::beg);
        if (!stream_) {
            throw std::runtime_error(
                std::string("failed to restore position after writing ") +
                description);
        }
        ++io_report_.syscall_count;
        ++io_report_.positional_write_calls;
        io_report_.bytes_transferred = checked_add(
            io_report_.bytes_transferred, length, description);
        io_report_.positional_write_bytes = checked_add(
            io_report_.positional_write_bytes, length, description);
        io_report_.timing += write_timer.stop();
#endif
    }

    std::uint64_t position(const char *description) const override {
#ifndef _WIN32
        if (!is_open()) {
            throw std::runtime_error(std::string("failed to inspect ") +
                                     description);
        }
        return position_;
#else
        const std::streampos position = stream_.tellp();
        if (position < 0) {
            throw std::runtime_error(std::string("failed to inspect ") +
                                     description);
        }
        return static_cast<std::uint64_t>(position);
#endif
    }

    FileIdentity identity(const std::filesystem::path &path,
                          const char *description) override {
#ifndef _WIN32
        struct stat metadata {};
        if (descriptor_ < 0 || ::fstat(descriptor_, &metadata) != 0 ||
            !S_ISREG(metadata.st_mode) || metadata.st_size < 0) {
            throw std::runtime_error(std::string("failed to inspect ") +
                                     description);
        }
        const FileIdentity selected = file_identity(path, description);
        if (selected.device != static_cast<std::uintmax_t>(metadata.st_dev) ||
            selected.inode != static_cast<std::uintmax_t>(metadata.st_ino) ||
            selected.size != static_cast<std::uint64_t>(metadata.st_size)) {
            throw std::runtime_error(std::string(description) +
                                     " path changed while writing");
        }
        return selected;
#else
        stream_.flush();
        if (!stream_) {
            throw std::runtime_error(std::string("failed to flush ") +
                                     description);
        }
        return file_identity(path, description);
#endif
    }

    FileIoReport io_report() const override { return io_report_; }

    void close(const char *description) override {
#ifndef _WIN32
        finish_writeback_on_close(description);
        const int descriptor = descriptor_;
        descriptor_ = -1;
        if (descriptor >= 0 && ::close(descriptor) != 0) {
            throw std::runtime_error(std::string("failed to close ") +
                                     description);
        }
#else
        stream_.flush();
        if (!stream_) {
            throw std::runtime_error(std::string("failed to flush ") +
                                     description);
        }
        stream_.close();
        if (stream_.fail()) {
            throw std::runtime_error(std::string("failed to close ") +
                                     description);
        }
#endif
    }

  private:
#if defined(__linux__)
    static bool writeback_is_unsupported(int error) noexcept {
        return error == ENOSYS || error == EOPNOTSUPP ||
               error == ENOTSUP;
    }

    struct WritebackCallResult {
        int result = 0;
        int error = 0;
    };

    WritebackCallResult sync_writeback(
        std::uint64_t offset, std::uint64_t length, unsigned int flags,
        FileTraceStoreOperationTiming &timing, std::uint64_t &attempts,
        std::uint64_t &successes) {
        const IoTimer timer;
        int result = 0;
        do {
            ++attempts;
            result = ::sync_file_range(
                descriptor_, static_cast<off_t>(offset),
                static_cast<off_t>(length), flags);
        } while (result != 0 && errno == EINTR);
        if (result == 0) {
            ++successes;
        }
        // Timing calls may change errno. Capture the syscall result before
        // observing clocks so fallback classification and surfaced failures
        // describe the actual terminal sync_file_range call.
        const int error = result == 0 ? 0 : errno;
        timing += timer.stop();
        return {result, error};
    }

    void disable_writeback() noexcept {
        io_report_.writeback_enabled = false;
        pending_writeback_begin_ = 0;
        pending_writeback_end_ = 0;
    }

    void wait_for_writeback_prefix(std::uint64_t length,
                                   const char *description) {
        if (!io_report_.writeback_enabled || length == 0) {
            return;
        }
        const std::uint64_t pending =
            pending_writeback_end_ - pending_writeback_begin_;
        length = std::min(length, pending);
        if (length == 0) {
            return;
        }
        const WritebackCallResult call = sync_writeback(
            pending_writeback_begin_, length,
            SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WAIT_AFTER,
            io_report_.writeback_wait,
            io_report_.writeback_wait_attempts,
            io_report_.writeback_wait_successes);
        if (call.result != 0) {
            throw std::runtime_error(
                std::string("failed to wait for writeback of ") +
                description + ": " +
                std::error_code(call.error,
                                std::generic_category()).message());
        }
        io_report_.writeback_range_bytes_waited = checked_add(
            io_report_.writeback_range_bytes_waited, length,
            "writeback waited range bytes");
        pending_writeback_begin_ += length;
        if (pending_writeback_begin_ == pending_writeback_end_) {
            pending_writeback_begin_ = 0;
            pending_writeback_end_ = 0;
        }
    }

    void track_unwaited_writeback_range(std::uint64_t offset,
                                        std::uint64_t length,
                                        const char *description) {
        if (length == 0) {
            return;
        }
        if (pending_writeback_begin_ == pending_writeback_end_) {
            pending_writeback_begin_ = offset;
            pending_writeback_end_ = checked_add(
                offset, length, "unwaited writeback range");
        } else if (offset == pending_writeback_end_) {
            pending_writeback_end_ = checked_add(
                pending_writeback_end_, length,
                "unwaited writeback range");
        } else {
            if (!io_report_.writeback_submit_only) {
                drain_writeback(description);
            }
            pending_writeback_begin_ = offset;
            pending_writeback_end_ = checked_add(
                offset, length, "unwaited writeback range");
        }
        const std::uint64_t unwaited =
            pending_writeback_end_ - pending_writeback_begin_;
        io_report_.maximum_unwaited_writeback_range_bytes = std::max(
            io_report_.maximum_unwaited_writeback_range_bytes, unwaited);
        if (!io_report_.writeback_submit_only &&
            unwaited > io_report_.writeback_window_bytes) {
            wait_for_writeback_prefix(
                unwaited - io_report_.writeback_window_bytes,
                description);
        }
    }

    [[noreturn]] void fail_writeback_submission(
        int error, const char *description) {
        std::string message =
            std::string("failed to submit writeback of ") + description +
            ": " +
            std::error_code(error, std::generic_category()).message();
        if (!io_report_.writeback_submit_only) {
            try {
                if (pending_writeback_begin_ != pending_writeback_end_) {
                    drain_writeback(description);
                }
            } catch (const std::exception &drain_error) {
                message += "; also failed to drain the successfully "
                           "submitted prefix: ";
                message += drain_error.what();
            }
        }
        throw std::runtime_error(message);
    }

    void prepare_for_writeback(std::uint64_t incoming,
                               const char *description) {
        if (!io_report_.writeback_enabled ||
            io_report_.writeback_submit_only ||
            pending_writeback_end_ == pending_writeback_begin_) {
            return;
        }
        const std::uint64_t pending =
            pending_writeback_end_ - pending_writeback_begin_;
        if (incoming >= io_report_.writeback_window_bytes) {
            wait_for_writeback_prefix(pending, description);
            return;
        }
        if (pending > io_report_.writeback_window_bytes - incoming) {
            wait_for_writeback_prefix(
                pending - (io_report_.writeback_window_bytes - incoming),
                description);
        }
    }

    void schedule_writeback(std::uint64_t offset, std::uint64_t length,
                            const char *description) {
        if (!io_report_.writeback_enabled ||
            length < kFileTraceStoreMinimumWritebackWindowBytes) {
            return;
        }
        std::uint64_t submitted = 0;
        const std::uint64_t submission_cap =
            io_report_.writeback_submit_only
                ? kFileTraceStoreWritebackSubmissionBytes
                : std::min(kFileTraceStoreWritebackSubmissionBytes,
                           io_report_.writeback_window_bytes);
        const std::uint64_t request_count =
            1U + (length - 1U) / submission_cap;
        const std::uint64_t base_request = length / request_count;
        const std::uint64_t larger_requests = length % request_count;
        for (std::uint64_t request_index = 0;
             request_index < request_count; ++request_index) {
            // Balance the range instead of leaving a tiny final syscall when
            // framing pushes a record just past an exact cap multiple.
            const std::uint64_t request =
                base_request + (request_index < larger_requests ? 1U : 0U);
            // Reserve completion-ledger capacity before each bounded request.
            // This keeps the application-tracked unwaited range at or below
            // the configured window even when one application write is larger
            // than that window. Submit-only files intentionally rely on
            // ordinary kernel dirty-page throttling instead.
            prepare_for_writeback(request, description);
            const bool first_submission_call =
                io_report_.writeback_submission_attempts == 0;
            const std::uint64_t request_offset =
                checked_add(offset, submitted, "writeback offset");
            const WritebackCallResult call = sync_writeback(
                request_offset, request, SYNC_FILE_RANGE_WRITE,
                io_report_.writeback_submission,
                io_report_.writeback_submission_attempts,
                io_report_.writeback_submission_successes);
            if (call.result != 0) {
                // A platform/filesystem capability failure is a safe fallback
                // only before this file has accepted any writeback range.
                // Once a call has succeeded, changing policy would discard
                // the bounded-wait completion ledger.
                if (writeback_is_unsupported(call.error) &&
                    first_submission_call && submitted == 0) {
                    disable_writeback();
                    return;
                }
                fail_writeback_submission(call.error, description);
            }
            io_report_.writeback_range_bytes_submitted = checked_add(
                io_report_.writeback_range_bytes_submitted, request,
                "submitted writeback range bytes");
            io_report_.maximum_writeback_submission_bytes = std::max(
                io_report_.maximum_writeback_submission_bytes, request);
            if (!io_report_.writeback_submit_only) {
                track_unwaited_writeback_range(
                    request_offset, request, description);
            }
            submitted += request;
        }
    }

    void drain_writeback(const char *description) {
        if (!io_report_.writeback_enabled ||
            io_report_.writeback_submit_only) {
            return;
        }
        const std::uint64_t pending =
            pending_writeback_end_ - pending_writeback_begin_;
        if (pending == 0) {
            return;
        }
        ++io_report_.writeback_drains;
        io_report_.writeback_drain_range_bytes = checked_add(
            io_report_.writeback_drain_range_bytes, pending,
            "writeback drain range bytes");
        wait_for_writeback_prefix(pending, description);
    }

    void finish_writeback_on_close(const char *description) {
        if (io_report_.writeback_submit_only) {
            const std::uint64_t unwaited =
                io_report_.writeback_range_bytes_submitted -
                io_report_.writeback_range_bytes_waited;
            if (unwaited != 0) {
                ++io_report_.writeback_drains_skipped;
                io_report_.writeback_range_bytes_without_explicit_wait =
                    unwaited;
            }
            return;
        }
        if (!io_report_.writeback_enabled) {
            return;
        }
        drain_writeback(description);
    }
#else
    void prepare_for_writeback(std::uint64_t,
                               const char *) noexcept {}
    void schedule_writeback(std::uint64_t, std::uint64_t,
                            const char *) noexcept {}
    void drain_writeback(const char *) noexcept {}
    void finish_writeback_on_close(const char *) noexcept {}
#endif

    void close_noexcept() noexcept {
#ifndef _WIN32
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
            descriptor_ = -1;
        }
#else
        if (stream_.is_open()) {
            stream_.close();
        }
#endif
    }

    void move_from(PlatformExclusiveOutputFile &&other) noexcept {
        io_report_ = other.io_report_;
        other.io_report_ = {};
#ifndef _WIN32
        descriptor_ = other.descriptor_;
        position_ = other.position_;
#if defined(__linux__)
        pending_writeback_begin_ = other.pending_writeback_begin_;
        pending_writeback_end_ = other.pending_writeback_end_;
#endif
        other.descriptor_ = -1;
        other.position_ = 0;
#if defined(__linux__)
        other.pending_writeback_begin_ = 0;
        other.pending_writeback_end_ = 0;
#endif
#else
        stream_ = std::move(other.stream_);
#endif
    }

#ifndef _WIN32
    int descriptor_ = -1;
    std::uint64_t position_ = 0;
#if defined(__linux__)
    std::uint64_t pending_writeback_begin_ = 0;
    std::uint64_t pending_writeback_end_ = 0;
#endif
#else
    mutable std::fstream stream_;
#endif
    FileIoReport io_report_;
};

std::shared_ptr<ExclusiveOutputFile> create_exclusive_output_file(
    const std::filesystem::path &path, const char *description,
    FileWritebackPolicy writeback_policy,
    std::uint64_t writeback_window_bytes) {
    return std::make_shared<PlatformExclusiveOutputFile>(
        path, description, writeback_policy, writeback_window_bytes);
}

void publish_file_no_replace(const std::filesystem::path &partial,
                             const std::filesystem::path &final,
                             const FileIdentity &expected,
                             const char *description) {
    require_file_identity(partial, expected, description);
    try {
        // Creating a hard link is an atomic no-replace publication: an
        // existing final path of any type makes the operation fail.
        std::filesystem::create_hard_link(partial, final);
    } catch (const std::filesystem::filesystem_error &error) {
        throw std::runtime_error(std::string("failed to publish ") +
                                 description + ": " + error.what());
    }
    require_file_identity(final, expected, description);
    require_file_identity(partial, expected, description);
    if (!std::filesystem::remove(partial)) {
        throw std::runtime_error(std::string("failed to remove published ") +
                                 description + " staging link");
    }
    require_file_identity(final, expected, description);
}

FileIdentity file_identity(const std::filesystem::path &path,
                           const char *description) {
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(path);
    if (!std::filesystem::is_regular_file(status)) {
        throw std::runtime_error(std::string("missing or non-regular ") +
                                 description);
    }
#ifndef _WIN32
    struct stat metadata {};
    if (::lstat(path.c_str(), &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) || metadata.st_size < 0) {
        throw std::runtime_error(std::string("failed to inspect ") +
                                 description);
    }
    return FileIdentity{
        static_cast<std::uintmax_t>(metadata.st_dev),
        static_cast<std::uintmax_t>(metadata.st_ino),
        static_cast<std::uint64_t>(metadata.st_size),
        std::filesystem::last_write_time(path),
    };
#else
    const std::uintmax_t raw_size = std::filesystem::file_size(path);
    if (raw_size > std::numeric_limits<std::uint64_t>::max()) {
        throw std::runtime_error(std::string(description) +
                                 " exceeds the format size limit");
    }
    return FileIdentity{
        0,
        0,
        static_cast<std::uint64_t>(raw_size),
        std::filesystem::last_write_time(path),
    };
#endif
}

void require_file_identity(const std::filesystem::path &path,
                           const FileIdentity &expected,
                           const char *description) {
    if (!(file_identity(path, description) == expected)) {
        throw std::runtime_error(std::string(description) +
                                 " was replaced after validation");
    }
}

void remove_owned_file_noexcept(const std::filesystem::path &path,
                                const FileIdentity &expected) noexcept {
#ifndef _WIN32
    struct stat metadata {};
    if (::lstat(path.c_str(), &metadata) == 0 &&
        S_ISREG(metadata.st_mode) &&
        expected.device == static_cast<std::uintmax_t>(metadata.st_dev) &&
        expected.inode == static_cast<std::uintmax_t>(metadata.st_ino)) {
        (void)::unlink(path.c_str());
    }
#else
    try {
        if (file_identity(path, "owned trace-store partial") == expected) {
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }
    } catch (...) {
    }
#endif
}

class PlatformBoundInputFile final : public BoundInputFile {
  public:
    PlatformBoundInputFile(const std::filesystem::path &path,
                           const char *description,
                           const FileIdentity *expected = nullptr)
        : path_(path) {
#ifndef _WIN32
        descriptor_ = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW |
                                               O_NONBLOCK | O_CLOEXEC);
        if (descriptor_ < 0) {
            throw std::runtime_error(
                std::string("failed to open bound ") + description + ": " +
                std::error_code(errno, std::generic_category()).message());
        }
        struct stat metadata {};
        if (::fstat(descriptor_, &metadata) != 0 ||
            !S_ISREG(metadata.st_mode) || metadata.st_size < 0) {
            close_noexcept();
            throw std::runtime_error(std::string("non-regular ") +
                                     description);
        }
        const FileIdentity selected = file_identity(path, description);
        if (selected.device != static_cast<std::uintmax_t>(metadata.st_dev) ||
            selected.inode != static_cast<std::uintmax_t>(metadata.st_ino) ||
            selected.size != static_cast<std::uint64_t>(metadata.st_size)) {
            close_noexcept();
            throw std::runtime_error(std::string(description) +
                                     " changed while opening");
        }
        identity_ = selected;
#if defined(__linux__) && defined(POSIX_FADV_SEQUENTIAL)
        // Validated trace readers consume long contiguous ranges. Tell the
        // kernel once so it can grow its normal readahead window even before
        // the range reader starts issuing explicit prefetch hints. Explicit
        // WILLNEED is enabled only when the matching BDI geometry can also be
        // read. This keeps every page-aligned request at or below Linux's
        // deterministic geometry cap; the hint remains advisory and does not
        // claim that any page reached cache.
        if (::posix_fadvise(descriptor_, 0, 0,
                            POSIX_FADV_SEQUENTIAL) == 0) {
            qualified_prefetch_request_bytes_ =
                qualified_linux_prefetch_request_bytes(metadata.st_dev);
        }
#endif
#else
        const FileIdentity selected = file_identity(path, description);
        stream_.open(path, std::ios::binary);
        if (!stream_) {
            throw std::runtime_error(std::string("failed to open ") +
                                     description);
        }
        identity_ = file_identity(path, description);
        if (!(identity_ == selected)) {
            close_noexcept();
            throw std::runtime_error(std::string(description) +
                                     " changed while opening");
        }
#endif
        if (expected != nullptr && !(identity_ == *expected)) {
            close_noexcept();
            throw std::runtime_error(std::string(description) +
                                     " was replaced after validation");
        }
    }

    ~PlatformBoundInputFile() override { close_noexcept(); }

    PlatformBoundInputFile(const PlatformBoundInputFile &) = delete;
    PlatformBoundInputFile &operator=(
        const PlatformBoundInputFile &) = delete;

    PlatformBoundInputFile(PlatformBoundInputFile &&other) noexcept {
        move_from(std::move(other));
    }

    PlatformBoundInputFile &operator=(
        PlatformBoundInputFile &&other) noexcept {
        if (this != &other) {
            close_noexcept();
            move_from(std::move(other));
        }
        return *this;
    }

    const FileIdentity &identity() const override { return identity_; }
    std::uint64_t size() const override { return identity_.size; }

    void read(std::span<std::uint8_t> output,
              const char *description) override {
        const IoTimer timer;
#ifndef _WIN32
        std::size_t consumed = 0;
        while (consumed < output.size()) {
            const std::size_t chunk = std::min<std::size_t>(
                output.size() - consumed,
                static_cast<std::size_t>(
                    std::numeric_limits<ssize_t>::max()));
            ++io_report_.syscall_count;
            const ssize_t count =
                ::read(descriptor_, output.data() + consumed, chunk);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw std::runtime_error(std::string("truncated ") +
                                         description);
            }
            consumed += static_cast<std::size_t>(count);
            io_report_.bytes_transferred +=
                static_cast<std::uint64_t>(count);
        }
        position_ = checked_add(position_, checked_u64(output.size(),
                                                       description),
                                description);
#else
        if (output.size() > static_cast<std::size_t>(
                                std::numeric_limits<std::streamsize>::max())) {
            throw std::runtime_error(std::string(description) +
                                     " exceeds streamsize");
        }
        stream_.read(reinterpret_cast<char *>(output.data()),
                     static_cast<std::streamsize>(output.size()));
        if (!stream_) {
            throw std::runtime_error(std::string("truncated ") +
                                     description);
        }
        ++io_report_.syscall_count;
        io_report_.bytes_transferred +=
            static_cast<std::uint64_t>(output.size());
#endif
        io_report_.timing += timer.stop();
    }

    void read_pair(std::span<std::uint8_t> first,
                   std::span<std::uint8_t> second,
                   const char *description) override {
        const IoTimer timer;
#ifndef _WIN32
        std::array<iovec, 2> parts{
            iovec{first.data(), first.size()},
            iovec{second.data(), second.size()},
        };
        std::size_t part = 0;
        std::uint64_t consumed_total = 0;
        while (part < parts.size()) {
            while (part < parts.size() && parts[part].iov_len == 0) {
                ++part;
            }
            if (part == parts.size()) {
                break;
            }
            ++io_report_.syscall_count;
            const ssize_t consumed = ::readv(
                descriptor_, parts.data() + part,
                static_cast<int>(parts.size() - part));
            if (consumed < 0 && errno == EINTR) {
                continue;
            }
            if (consumed <= 0) {
                throw std::runtime_error(std::string("truncated ") +
                                         description);
            }
            consumed_total = checked_add(
                consumed_total, static_cast<std::uint64_t>(consumed),
                description);
            io_report_.bytes_transferred = checked_add(
                io_report_.bytes_transferred,
                static_cast<std::uint64_t>(consumed), description);
            std::size_t remaining = static_cast<std::size_t>(consumed);
            while (part < parts.size() &&
                   remaining >= parts[part].iov_len) {
                remaining -= parts[part].iov_len;
                ++part;
            }
            if (part < parts.size() && remaining != 0) {
                parts[part].iov_base =
                    static_cast<std::uint8_t *>(parts[part].iov_base) +
                    remaining;
                parts[part].iov_len -= remaining;
            }
        }
        position_ = checked_add(position_, consumed_total, description);
#else
        const auto read_part = [&](std::span<std::uint8_t> bytes) {
            if (bytes.size() > static_cast<std::size_t>(
                                   std::numeric_limits<std::streamsize>::max())) {
                throw std::runtime_error(std::string(description) +
                                         " exceeds streamsize");
            }
            stream_.read(reinterpret_cast<char *>(bytes.data()),
                         static_cast<std::streamsize>(bytes.size()));
            if (!stream_) {
                throw std::runtime_error(std::string("truncated ") +
                                         description);
            }
            ++io_report_.syscall_count;
            io_report_.bytes_transferred +=
                static_cast<std::uint64_t>(bytes.size());
        };
        read_part(first);
        read_part(second);
#endif
        io_report_.timing += timer.stop();
    }

    void seek(std::uint64_t offset,
              const char *description) override {
        if (offset > static_cast<std::uint64_t>(
                         std::numeric_limits<std::streamoff>::max())) {
            throw std::runtime_error(std::string(description) +
                                     " exceeds file offsets");
        }
#ifndef _WIN32
        const off_t result =
            ::lseek(descriptor_, static_cast<off_t>(offset), SEEK_SET);
        if (result < 0 || static_cast<std::uint64_t>(result) != offset) {
            throw std::runtime_error(std::string("failed to seek ") +
                                     description);
        }
        position_ = offset;
#else
        stream_.clear();
        stream_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        if (!stream_) {
            throw std::runtime_error(std::string("failed to seek ") +
                                     description);
        }
#endif
    }

    std::uint64_t position(const char *description) const override {
#ifndef _WIN32
        if (descriptor_ < 0) {
            throw std::runtime_error(std::string("failed to inspect ") +
                                     description);
        }
        return position_;
#else
        const std::streampos position = stream_.tellg();
        if (position < 0) {
            throw std::runtime_error(std::string("failed to inspect ") +
                                     description);
        }
        return static_cast<std::uint64_t>(position);
#endif
    }

    void set_access_pattern(AccessPattern pattern) noexcept override {
#if defined(__linux__) && defined(POSIX_FADV_SEQUENTIAL) && \
    defined(POSIX_FADV_RANDOM)
        if (descriptor_ >= 0) {
            const int advice = pattern == AccessPattern::Sequential
                                   ? POSIX_FADV_SEQUENTIAL
                                   : POSIX_FADV_RANDOM;
            (void)::posix_fadvise(descriptor_, 0, 0, advice);
        }
#endif
        random_access_suppresses_prefetch_ =
            pattern == AccessPattern::Random;
    }

    std::uint64_t prefetch(std::uint64_t offset,
                           std::uint64_t length) noexcept override {
#if defined(__linux__) && defined(POSIX_FADV_WILLNEED)
        if (random_access_suppresses_prefetch_ ||
            prefetch_permanently_disabled_ || descriptor_ < 0 || length == 0 ||
            offset >= identity_.size) {
            return 0;
        }
        if (qualified_prefetch_request_bytes_ == 0) {
            ++io_report_.prefetch_fallbacks;
            prefetch_permanently_disabled_ = true;
            return 0;
        }
        const std::uint64_t bounded_length =
            std::min(length, identity_.size - offset);
        const std::uint64_t maximum_offset =
            static_cast<std::uint64_t>(std::numeric_limits<off_t>::max());
        if (offset > maximum_offset ||
            bounded_length > maximum_offset - offset) {
            ++io_report_.prefetch_fallbacks;
            prefetch_permanently_disabled_ = true;
            return 0;
        }
        // The constructor qualified this request size against the backing
        // device's read-ahead geometry. A successful advisory call still says
        // only that the request was submitted, never that data reached cache.
        const long page_size = ::sysconf(_SC_PAGESIZE);
        if (page_size <= 0) {
            ++io_report_.prefetch_fallbacks;
            prefetch_permanently_disabled_ = true;
            return 0;
        }
        const std::uint64_t page_bytes =
            static_cast<std::uint64_t>(page_size);
        const std::uint64_t logical_end = offset + bounded_length;
        const IoTimer timer;
        std::uint64_t cursor = offset;
        while (cursor < logical_end) {
            const std::uint64_t request_begin =
                cursor - (cursor % page_bytes);
            const std::uint64_t covered_end = std::min(
                logical_end,
                request_begin + qualified_prefetch_request_bytes_);
            std::uint64_t request_end = covered_end;
            if (const std::uint64_t remainder = request_end % page_bytes;
                remainder != 0) {
                request_end += page_bytes - remainder;
            }
            request_end = std::min(request_end, identity_.size);
            const std::uint64_t request = request_end - request_begin;
            const int result = ::posix_fadvise(
                descriptor_, static_cast<off_t>(request_begin),
                static_cast<off_t>(request), POSIX_FADV_WILLNEED);
            if (result != 0) {
                ++io_report_.prefetch_fallbacks;
                prefetch_permanently_disabled_ = true;
                break;
            }
            ++io_report_.prefetch_requests;
            io_report_.prefetch_bytes_requested += request;
            io_report_.maximum_prefetch_request_bytes = std::max(
                io_report_.maximum_prefetch_request_bytes, request);
            cursor = covered_end;
        }
        io_report_.prefetch += timer.stop();
        return cursor - offset;
#else
        (void)offset;
        (void)length;
        if (!prefetch_permanently_disabled_ &&
            !random_access_suppresses_prefetch_) {
            ++io_report_.prefetch_fallbacks;
            prefetch_permanently_disabled_ = true;
        }
        return 0;
#endif
    }

    FileIoReport io_report() const override { return io_report_; }

    void require_unchanged(const char *description) const override {
#ifndef _WIN32
        struct stat metadata {};
        if (descriptor_ < 0 || ::fstat(descriptor_, &metadata) != 0 ||
            !S_ISREG(metadata.st_mode) || metadata.st_size < 0 ||
            identity_.device !=
                static_cast<std::uintmax_t>(metadata.st_dev) ||
            identity_.inode !=
                static_cast<std::uintmax_t>(metadata.st_ino) ||
            identity_.size != static_cast<std::uint64_t>(metadata.st_size)) {
            throw std::runtime_error(std::string(description) +
                                     " changed while reading");
        }
#endif
        require_file_identity(path_, identity_, description);
    }

  private:
    void close_noexcept() noexcept {
#ifndef _WIN32
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
            descriptor_ = -1;
        }
#else
        if (stream_.is_open()) {
            stream_.close();
        }
#endif
    }

    void move_from(PlatformBoundInputFile &&other) noexcept {
        path_ = std::move(other.path_);
        identity_ = other.identity_;
        io_report_ = other.io_report_;
        prefetch_permanently_disabled_ =
            other.prefetch_permanently_disabled_;
        random_access_suppresses_prefetch_ =
            other.random_access_suppresses_prefetch_;
        qualified_prefetch_request_bytes_ =
            other.qualified_prefetch_request_bytes_;
        other.io_report_ = {};
        other.prefetch_permanently_disabled_ = false;
        other.random_access_suppresses_prefetch_ = false;
        other.qualified_prefetch_request_bytes_ = 0;
#ifndef _WIN32
        descriptor_ = other.descriptor_;
        position_ = other.position_;
        other.descriptor_ = -1;
        other.position_ = 0;
#else
        stream_ = std::move(other.stream_);
#endif
    }

    std::filesystem::path path_;
    FileIdentity identity_;
#ifndef _WIN32
    int descriptor_ = -1;
    std::uint64_t position_ = 0;
#else
    mutable std::ifstream stream_;
#endif
    FileIoReport io_report_;
    bool prefetch_permanently_disabled_ = false;
    bool random_access_suppresses_prefetch_ = false;
    std::uint64_t qualified_prefetch_request_bytes_ = 0;
};

std::shared_ptr<BoundInputFile> open_bound_input_file(
    const std::filesystem::path &path, const char *description,
    const FileIdentity *expected) {
    return std::make_shared<PlatformBoundInputFile>(
        path, description, expected);
}

} // namespace trace_store_format
} // namespace laminate::payload
