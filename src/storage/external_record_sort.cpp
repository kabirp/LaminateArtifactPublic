#include "laminate/storage/external_record_sort.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <fstream>
#include <limits>
#include <optional>
#include <queue>
#include <stdexcept>
#include <system_error>
#include <tuple>
#include <utility>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#if defined(__linux__) && defined(__GLIBC__)
#include <malloc.h>
#endif

namespace laminate::storage {
namespace {

constexpr std::array<std::uint8_t, 8> kRunMagic{
    'L', 'M', 'N', 'T', 'S', 'R', 'T', '1'};

struct PathIdentity {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint64_t size = 0;
    bool directory = false;

    bool operator==(const PathIdentity &other) const {
        return device == other.device && inode == other.inode &&
               directory == other.directory &&
               (directory || size == other.size);
    }
};

PathIdentity path_identity(const std::filesystem::path &path) {
#ifndef _WIN32
    struct stat status {};
    if (::lstat(path.c_str(), &status) != 0 ||
        (!S_ISREG(status.st_mode) && !S_ISDIR(status.st_mode))) {
        throw std::runtime_error("failed to identify external-sort path");
    }
    return {static_cast<std::uint64_t>(status.st_dev),
            static_cast<std::uint64_t>(status.st_ino),
            static_cast<std::uint64_t>(status.st_size),
            S_ISDIR(status.st_mode)};
#else
    const auto status = std::filesystem::symlink_status(path);
    if ((!std::filesystem::is_regular_file(status) &&
         !std::filesystem::is_directory(status)) ||
        std::filesystem::is_symlink(status)) {
        throw std::runtime_error("failed to identify external-sort path");
    }
    return {0, 0, std::filesystem::is_regular_file(status)
                      ? std::filesystem::file_size(path)
                      : 0,
            std::filesystem::is_directory(status)};
#endif
}

bool same_path_identity(const std::filesystem::path &path,
                        const PathIdentity &expected) {
    try {
        return path_identity(path) == expected;
    } catch (...) {
        return false;
    }
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *description) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(description) +
                                  " overflows u64");
    }
    return left + right;
}

std::uint64_t checked_u64(std::size_t value, const char *description) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(description) +
                                      " does not fit u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

void encode_u64(std::array<std::uint8_t, 8> &encoded,
                std::uint64_t value) {
    for (std::size_t byte = 0; byte < encoded.size(); ++byte) {
        encoded[byte] = static_cast<std::uint8_t>(
            value >> static_cast<unsigned>(8U * byte));
    }
}

std::uint64_t decode_u64(const std::array<std::uint8_t, 8> &encoded) {
    std::uint64_t result = 0;
    for (std::size_t byte = 0; byte < encoded.size(); ++byte) {
        result |= static_cast<std::uint64_t>(encoded[byte])
                  << static_cast<unsigned>(8U * byte);
    }
    return result;
}

class ExclusiveRunWriter {
  public:
    explicit ExclusiveRunWriter(const std::filesystem::path &path)
        : path_(path) {
#ifndef _WIN32
        descriptor_ = ::open(path.c_str(),
                             O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                             0600);
        if (descriptor_ < 0) {
            throw std::filesystem::filesystem_error(
                "failed to create external-sort run", path,
                std::error_code(errno, std::generic_category()));
        }
#else
        if (std::filesystem::exists(std::filesystem::symlink_status(path))) {
            throw std::runtime_error("external-sort run already exists");
        }
        stream_.open(path, std::ios::binary | std::ios::out);
        if (!stream_) {
            throw std::runtime_error("failed to create external-sort run");
        }
#endif
    }

    ~ExclusiveRunWriter() {
        close_noexcept();
    }

    void write(std::span<const std::uint8_t> bytes) {
#ifndef _WIN32
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            const ssize_t count = ::write(
                descriptor_, bytes.data() + offset, bytes.size() - offset);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw std::runtime_error("failed to write external-sort run");
            }
            offset += static_cast<std::size_t>(count);
        }
#else
        if (bytes.size() > static_cast<std::size_t>(
                               std::numeric_limits<std::streamsize>::max())) {
            throw std::overflow_error("external-sort write is too large");
        }
        stream_.write(reinterpret_cast<const char *>(bytes.data()),
                      static_cast<std::streamsize>(bytes.size()));
        if (!stream_) {
            throw std::runtime_error("failed to write external-sort run");
        }
#endif
    }

    void u64(std::uint64_t value) {
        std::array<std::uint8_t, 8> encoded{};
        encode_u64(encoded, value);
        write(encoded);
    }

    void close() {
#ifndef _WIN32
        if (descriptor_ >= 0 && ::close(descriptor_) != 0) {
            descriptor_ = -1;
            throw std::runtime_error("failed to close external-sort run");
        }
        descriptor_ = -1;
#else
        stream_.close();
        if (!stream_) {
            throw std::runtime_error("failed to close external-sort run");
        }
#endif
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

    std::filesystem::path path_;
#ifndef _WIN32
    int descriptor_ = -1;
#else
    std::ofstream stream_;
#endif
};

void read_exact(std::ifstream &input, std::span<std::uint8_t> output) {
    if (output.size() > static_cast<std::size_t>(
                            std::numeric_limits<std::streamsize>::max())) {
        throw std::overflow_error("external-sort read is too large");
    }
    input.read(reinterpret_cast<char *>(output.data()),
               static_cast<std::streamsize>(output.size()));
    if (!input) {
        throw std::runtime_error("truncated external-sort run");
    }
}

std::uint64_t read_u64(std::ifstream &input) {
    std::array<std::uint8_t, 8> encoded{};
    read_exact(input, encoded);
    return decode_u64(encoded);
}

} // namespace

ExternalRecordSortBudget::ExternalRecordSortBudget(
    std::uint64_t max_live_bytes, std::uint64_t min_free_bytes)
    : max_live_bytes_(max_live_bytes),
      min_free_bytes_(min_free_bytes) {
    if (max_live_bytes_ == 0 || min_free_bytes_ == 0) {
        throw std::invalid_argument(
            "external-sort budget limits must be nonzero");
    }
}

std::uint64_t ExternalRecordSortBudget::current_live_bytes() const {
    return current_live_bytes_;
}

std::uint64_t ExternalRecordSortBudget::peak_live_bytes() const {
    return peak_live_bytes_;
}

void ExternalRecordSortBudget::set_external_live_bytes(
    std::uint64_t bytes) {
    if (bytes > max_live_bytes_ ||
        current_live_bytes_ > max_live_bytes_ - bytes) {
        throw std::length_error(
            "external-sort combined temporary/output-byte limit exceeded");
    }
    external_live_bytes_ = bytes;
    peak_combined_live_bytes_ = std::max(
        peak_combined_live_bytes_,
        external_live_bytes_ + current_live_bytes_);
}

std::uint64_t ExternalRecordSortBudget::external_live_bytes() const {
    return external_live_bytes_;
}

std::uint64_t ExternalRecordSortBudget::peak_combined_live_bytes() const {
    return peak_combined_live_bytes_;
}

void ExternalRecordSortBudget::require(
    const std::filesystem::path &directory,
    std::uint64_t additional) const {
    if (external_live_bytes_ > max_live_bytes_ ||
        current_live_bytes_ > max_live_bytes_ - external_live_bytes_ ||
        additional > max_live_bytes_ - external_live_bytes_ -
                         current_live_bytes_) {
        throw std::length_error(
            "external-sort temporary-byte limit exceeded");
    }
    std::error_code error;
    const std::filesystem::space_info space =
        std::filesystem::space(directory, error);
    if (error || additional > space.available ||
        min_free_bytes_ > space.available - additional) {
        throw std::length_error(
            "external-sort would violate min_free_bytes");
    }
}

void ExternalRecordSortBudget::acquire(std::uint64_t bytes) {
    if (current_live_bytes_ > max_live_bytes_ ||
        bytes > max_live_bytes_ - current_live_bytes_) {
        throw std::logic_error("external-sort budget admission drifted");
    }
    current_live_bytes_ += bytes;
    peak_live_bytes_ = std::max(peak_live_bytes_, current_live_bytes_);
    peak_combined_live_bytes_ = std::max(
        peak_combined_live_bytes_,
        external_live_bytes_ + current_live_bytes_);
}

void ExternalRecordSortBudget::release(std::uint64_t bytes) {
    if (bytes > current_live_bytes_) {
        throw std::logic_error("external-sort budget release drifted");
    }
    current_live_bytes_ -= bytes;
}

struct ExternalSerializedRecordSorter::Impl {
    struct PendingRecord {
        std::uint64_t key = 0;
        std::uint64_t sequence = 0;
        std::shared_ptr<const std::vector<std::uint8_t>> payload;
    };

    struct Run {
        std::filesystem::path path;
        std::uint64_t records = 0;
        std::uint64_t bytes = 0;
        PathIdentity identity;
    };

    class RunReader {
      public:
        explicit RunReader(const Run &run)
            : run_(run), input_(run.path, std::ios::binary) {
            if (!same_path_identity(run.path, run.identity) || !input_ ||
                run.records >
                    (run.bytes - kExternalRecordSortRunHeaderBytes) /
                        kExternalRecordSortRecordFramingBytes) {
                throw std::runtime_error("failed to open external-sort run");
            }
            std::array<std::uint8_t, 8> magic{};
            read_exact(input_, magic);
            if (magic != kRunMagic || read_u64(input_) != run.records) {
                throw std::runtime_error("invalid external-sort run header");
            }
            advance();
        }

        bool has_value() const { return remaining_value_; }
        std::uint64_t key() const { return key_; }
        std::uint64_t sequence() const { return sequence_; }
        std::span<const std::uint8_t> payload() const { return payload_; }
        std::size_t payload_capacity() const { return payload_.capacity(); }

        void advance() {
            if (consumed_ == run_.records) {
                if (input_.peek() != std::ifstream::traits_type::eof()) {
                    throw std::runtime_error(
                        "external-sort run has trailing bytes");
                }
                remaining_value_ = false;
                return;
            }
            key_ = read_u64(input_);
            sequence_ = read_u64(input_);
            const std::uint64_t length = read_u64(input_);
            if (length == 0 ||
                length > run_.bytes ||
                length > static_cast<std::uint64_t>(
                             std::numeric_limits<std::size_t>::max())) {
                throw std::runtime_error(
                    "invalid external-sort record length");
            }
            payload_.resize(static_cast<std::size_t>(length));
            read_exact(input_, payload_);
            ++consumed_;
            remaining_value_ = true;
        }

      private:
        Run run_;
        std::ifstream input_;
        std::uint64_t consumed_ = 0;
        std::uint64_t key_ = 0;
        std::uint64_t sequence_ = 0;
        std::vector<std::uint8_t> payload_;
        bool remaining_value_ = false;
    };

    explicit Impl(ExternalRecordSortOptions selected)
        : options(std::move(selected)) {
        if (options.parent_directory.empty() ||
            options.workspace_name.empty() ||
            options.workspace_name.find('/') != std::string::npos ||
            options.workspace_name.find('\\') != std::string::npos ||
            (!options.shared_budget &&
             (options.max_live_temporary_bytes == 0 ||
              options.min_free_bytes == 0)) ||
            options.max_buffered_records == 0 ||
            options.max_buffered_payload_bytes == 0 ||
            options.merge_fan_in < 2) {
            throw std::invalid_argument("invalid external-sort options");
        }
        const auto parent_status =
            std::filesystem::symlink_status(options.parent_directory);
        if (!std::filesystem::is_directory(parent_status) ||
            std::filesystem::is_symlink(parent_status)) {
            throw std::invalid_argument(
                "external-sort parent must be a private directory");
        }
        root = options.parent_directory / options.workspace_name;
        if (!std::filesystem::create_directory(root)) {
            throw std::runtime_error(
                "external-sort workspace already exists");
        }
        root_identity = path_identity(root);
        budget = options.shared_budget
                     ? options.shared_budget
                     : std::make_shared<ExternalRecordSortBudget>(
                           options.max_live_temporary_bytes,
                           options.min_free_bytes);
#ifndef _WIN32
        std::filesystem::permissions(
            root, std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace);
#endif
    }

    ~Impl() { cleanup_noexcept(); }

    void require_capacity(std::uint64_t additional) const {
        budget->require(root, additional);
    }

    std::filesystem::path next_path(std::size_t generation) {
        return root / ("run-" + std::to_string(generation) + "-" +
                       std::to_string(next_run_id++) + ".bin");
    }

    void own(Run run) {
        budget->acquire(run.bytes);
        live_bytes = checked_add(live_bytes, run.bytes,
                                 "live external-sort bytes");
        report.temporary_bytes_written = checked_add(
            report.temporary_bytes_written, run.bytes,
            "external-sort written bytes");
        report.peak_live_temporary_bytes = std::max(
            report.peak_live_temporary_bytes, live_bytes);
        ++report.runs_created;
        owned.push_back(run);
    }

    void erase(const Run &run) {
        const auto found = std::find_if(
            owned.begin(), owned.end(), [&](const Run &candidate) {
                return candidate.path == run.path;
            });
        if (found == owned.end() || found->bytes != run.bytes ||
            !same_path_identity(run.path, run.identity) ||
            !std::filesystem::remove(run.path)) {
            throw std::runtime_error(
                "refusing to remove changed external-sort run");
        }
        live_bytes -= run.bytes;
        budget->release(run.bytes);
        report.temporary_bytes_deleted = checked_add(
            report.temporary_bytes_deleted, run.bytes,
            "external-sort deleted bytes");
        owned.erase(found);
    }

    Run write_run(std::span<const PendingRecord> records,
                  std::size_t generation) {
        std::uint64_t bytes = kExternalRecordSortRunHeaderBytes;
        for (const PendingRecord &record : records) {
            if (!record.payload || record.payload->empty()) {
                throw std::invalid_argument(
                    "external-sort record payload is empty");
            }
            bytes = checked_add(bytes,
                                kExternalRecordSortRecordFramingBytes,
                                "external-sort run framing");
            bytes = checked_add(
                bytes, checked_u64(record.payload->size(),
                                   "external-sort payload"),
                "external-sort run bytes");
        }
        require_capacity(bytes);
        const std::filesystem::path path = next_path(generation);
        try {
            ExclusiveRunWriter output(path);
            output.write(kRunMagic);
            output.u64(checked_u64(records.size(),
                                   "external-sort run records"));
            std::optional<std::pair<std::uint64_t, std::uint64_t>> previous;
            for (const PendingRecord &record : records) {
                const std::pair order{record.key, record.sequence};
                if (previous && order <= *previous) {
                    throw std::invalid_argument(
                        "external-sort order is inconsistent");
                }
                output.u64(record.key);
                output.u64(record.sequence);
                output.u64(checked_u64(record.payload->size(),
                                       "external-sort payload"));
                output.write(*record.payload);
                previous = order;
            }
            output.close();
        } catch (...) {
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
            throw;
        }
        Run run{path, checked_u64(records.size(), "run records"), bytes,
                path_identity(path)};
        try {
            own(run);
        } catch (...) {
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
            throw;
        }
        return run;
    }

    void flush() {
        if (buffer.empty()) {
            return;
        }
        sort_buffer();
        runs.push_back(write_run(buffer, 0));
        clear_buffer();
    }

    void sort_buffer() {
        std::sort(buffer.begin(), buffer.end(),
                  [](const PendingRecord &left,
                     const PendingRecord &right) {
                      return std::pair{left.key, left.sequence} <
                             std::pair{right.key, right.sequence};
                  });
    }

    void clear_buffer() {
        buffer.clear();
        buffered_payload_bytes = 0;
        buffered_payload_capacity_bytes = 0;
    }

    void release_completed_buffer() {
        // Release the payloads and record array before scanning the completed
        // artifact. A large in-memory sort can otherwise retain enough heap
        // memory to displace that artifact from the page cache.
        std::vector<PendingRecord>().swap(buffer);
        buffered_payload_bytes = 0;
        buffered_payload_capacity_bytes = 0;
#if defined(__linux__) && defined(__GLIBC__)
        (void)::malloc_trim(0);
#endif
    }

    template <typename Sink>
    void merge_group(std::span<const Run> inputs, Sink &&sink) {
        struct QueueEntry {
            std::uint64_t key = 0;
            std::uint64_t sequence = 0;
            std::size_t reader = 0;
        };
        const auto later = [](const QueueEntry &left,
                              const QueueEntry &right) {
            return std::tuple{left.key, left.sequence, left.reader} >
                   std::tuple{right.key, right.sequence, right.reader};
        };
        std::priority_queue<QueueEntry, std::vector<QueueEntry>,
                            decltype(later)>
            queue(later);
        std::vector<std::unique_ptr<RunReader>> readers;
        readers.reserve(inputs.size());
        for (const Run &run : inputs) {
            readers.push_back(std::make_unique<RunReader>(run));
            if (readers.back()->has_value()) {
                queue.push({readers.back()->key(),
                            readers.back()->sequence(),
                            readers.size() - 1U});
            }
        }
        report.maximum_open_runs =
            std::max(report.maximum_open_runs, readers.size());
        const auto account_open_payload = [&] {
            std::uint64_t open_payload = 0;
            for (const auto &reader : readers) {
                open_payload = checked_add(
                    open_payload,
                    checked_u64(reader->payload_capacity(),
                                "open external-sort payload"),
                    "open external-sort payload bytes");
            }
            report.peak_open_run_payload_bytes = std::max(
                report.peak_open_run_payload_bytes, open_payload);
        };
        account_open_payload();
        std::optional<std::pair<std::uint64_t, std::uint64_t>> previous;
        while (!queue.empty()) {
            const QueueEntry entry = queue.top();
            queue.pop();
            RunReader &reader = *readers[entry.reader];
            const std::pair order{entry.key, entry.sequence};
            if (previous && order <= *previous) {
                throw std::invalid_argument(
                    "external-sort merge order is inconsistent");
            }
            sink(entry.key, entry.sequence, reader.payload());
            previous = order;
            reader.advance();
            account_open_payload();
            if (reader.has_value()) {
                queue.push({reader.key(), reader.sequence(), entry.reader});
            }
        }
    }

    Run merge_to_run(std::span<const Run> inputs,
                     std::size_t generation) {
        std::uint64_t records = 0;
        std::uint64_t bytes = kExternalRecordSortRunHeaderBytes;
        for (const Run &run : inputs) {
            records = checked_add(records, run.records,
                                  "merged external-sort records");
            bytes = checked_add(
                bytes, run.bytes - kExternalRecordSortRunHeaderBytes,
                                "merged external-sort bytes");
        }
        require_capacity(bytes);
        const std::filesystem::path path = next_path(generation);
        try {
            ExclusiveRunWriter output(path);
            output.write(kRunMagic);
            output.u64(records);
            merge_group(inputs, [&](std::uint64_t key,
                                    std::uint64_t sequence,
                                    std::span<const std::uint8_t> payload) {
                output.u64(key);
                output.u64(sequence);
                output.u64(checked_u64(payload.size(), "merged payload"));
                output.write(payload);
            });
            output.close();
        } catch (...) {
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
            throw;
        }
        Run result{path, records, bytes, path_identity(path)};
        try {
            own(result);
        } catch (...) {
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
            throw;
        }
        for (const Run &input : inputs) {
            erase(input);
        }
        return result;
    }

    void cleanup_noexcept() noexcept {
        for (const Run &run : owned) {
            try {
                if (same_path_identity(run.path, run.identity)) {
                    if (std::filesystem::remove(run.path)) {
                        budget->release(run.bytes);
                    }
                }
            } catch (...) {
            }
        }
        try {
            if (!root.empty() && same_path_identity(root, root_identity) &&
                std::filesystem::is_empty(root)) {
                std::filesystem::remove(root);
            }
        } catch (...) {
        }
    }

    void finish_cleanup() {
        if (!owned.empty() || live_bytes != 0 ||
            report.temporary_bytes_written !=
                report.temporary_bytes_deleted ||
            !same_path_identity(root, root_identity) ||
            !std::filesystem::is_empty(root) ||
            !std::filesystem::remove(root)) {
            throw std::runtime_error(
                "external-sort workspace cleanup is incomplete");
        }
        root.clear();
    }

    ExternalRecordSortOptions options;
    std::filesystem::path root;
    PathIdentity root_identity;
    std::shared_ptr<ExternalRecordSortBudget> budget;
    std::vector<PendingRecord> buffer;
    std::vector<Run> runs;
    std::vector<Run> owned;
    ExternalRecordSortReport report;
    std::uint64_t live_bytes = 0;
    std::uint64_t buffered_payload_bytes = 0;
    std::uint64_t buffered_payload_capacity_bytes = 0;
    std::size_t next_run_id = 0;
    std::uint64_t next_sequence = 0;
    bool finished = false;
};

ExternalSerializedRecordSorter::ExternalSerializedRecordSorter(
    ExternalRecordSortOptions options)
    : impl_(std::make_unique<Impl>(std::move(options))) {}

ExternalSerializedRecordSorter::~ExternalSerializedRecordSorter() = default;

void ExternalSerializedRecordSorter::append(
    std::uint64_t destination,
    std::shared_ptr<const std::vector<std::uint8_t>> payload) {
    if (!impl_ || impl_->finished || !payload || payload->empty()) {
        throw std::logic_error("invalid external-sort append");
    }
    const std::uint64_t payload_bytes = checked_u64(
        payload->size(), "buffered external-sort payload");
    if (payload_bytes > impl_->options.max_buffered_payload_bytes) {
        throw std::length_error(
            "external-sort record exceeds buffered payload-byte cap");
    }
    if (!impl_->buffer.empty() &&
        payload_bytes > impl_->options.max_buffered_payload_bytes -
                            impl_->buffered_payload_bytes) {
        impl_->flush();
    }
    const std::uint64_t payload_capacity = checked_u64(
        payload->capacity(), "buffered external-sort payload capacity");
    impl_->buffer.push_back(
        {destination, impl_->next_sequence++, std::move(payload)});
    impl_->buffered_payload_bytes = checked_add(
        impl_->buffered_payload_bytes, payload_bytes,
        "buffered external-sort payload bytes");
    impl_->buffered_payload_capacity_bytes = checked_add(
        impl_->buffered_payload_capacity_bytes, payload_capacity,
        "buffered external-sort payload capacity bytes");
    impl_->report.records = checked_add(
        impl_->report.records, 1, "external-sort record count");
    impl_->report.payload_bytes = checked_add(
        impl_->report.payload_bytes,
        checked_u64(impl_->buffer.back().payload->size(),
                    "external-sort payload"),
        "external-sort payload bytes");
    impl_->report.peak_buffered_records = std::max(
        impl_->report.peak_buffered_records, impl_->buffer.size());
    impl_->report.peak_buffered_payload_bytes = std::max(
        impl_->report.peak_buffered_payload_bytes,
        impl_->buffered_payload_bytes);
    const std::uint64_t buffered_records = checked_u64(
        impl_->buffer.size(),
        "buffered external-sort record count");
    if (buffered_records >
        std::numeric_limits<std::uint64_t>::max() /
            sizeof(Impl::PendingRecord)) {
        throw std::overflow_error(
            "buffered external-sort record host bytes overflow");
    }
    const std::uint64_t record_host_bytes =
        buffered_records * sizeof(Impl::PendingRecord);
    impl_->report.peak_estimated_buffered_host_bytes = std::max(
        impl_->report.peak_estimated_buffered_host_bytes,
        checked_add(impl_->buffered_payload_capacity_bytes,
                    record_host_bytes,
                    "buffered external-sort estimated host bytes"));
    if (impl_->buffer.size() == impl_->options.max_buffered_records ||
        impl_->buffered_payload_bytes ==
            impl_->options.max_buffered_payload_bytes) {
        impl_->flush();
    }
}

ExternalRecordSortReport ExternalSerializedRecordSorter::write_sorted(
    const std::function<void(
        std::uint64_t, std::span<const std::uint8_t>)> &visitor) {
    if (!impl_ || impl_->finished || !visitor) {
        throw std::logic_error("invalid external-sort completion");
    }
    // A buffer which never reached its admitted cap is already the only run.
    // Sort and publish it directly: writing a temporary file only to reread
    // it into the final artifact doubles I/O without reducing residency.
    if (impl_->runs.empty() && !impl_->buffer.empty()) {
        impl_->sort_buffer();
        for (const auto &record : impl_->buffer) {
            visitor(record.key, *record.payload);
        }
        impl_->release_completed_buffer();
        impl_->report.retained_temporary_bytes = 0;
        impl_->finished = true;
        impl_->finish_cleanup();
        return impl_->report;
    }

    impl_->flush();
    impl_->report.initial_runs = checked_u64(
        impl_->runs.size(), "external-sort initial runs");
    if (impl_->runs.empty()) {
        throw std::invalid_argument("external-sort has no records");
    }
    std::size_t generation = 1;
    while (impl_->runs.size() > impl_->options.merge_fan_in) {
        std::vector<Impl::Run> next;
        for (std::size_t begin = 0; begin < impl_->runs.size();) {
            const std::size_t count = std::min(
                impl_->options.merge_fan_in, impl_->runs.size() - begin);
            next.push_back(impl_->merge_to_run(
                std::span<const Impl::Run>(impl_->runs).subspan(begin, count),
                generation));
            begin += count;
        }
        impl_->runs = std::move(next);
        ++impl_->report.merge_passes;
        ++generation;
    }
    impl_->merge_group(
        impl_->runs,
        [&](std::uint64_t key, std::uint64_t,
            std::span<const std::uint8_t> payload) {
            visitor(key, payload);
        });
    ++impl_->report.merge_passes;
    for (const Impl::Run &run : impl_->runs) {
        impl_->erase(run);
    }
    impl_->runs.clear();
    impl_->report.retained_temporary_bytes = impl_->live_bytes;
    impl_->finished = true;
    impl_->finish_cleanup();
    impl_->release_completed_buffer();
    return impl_->report;
}

} // namespace laminate::storage
