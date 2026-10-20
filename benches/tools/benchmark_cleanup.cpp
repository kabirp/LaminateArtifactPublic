/// @file benchmark_cleanup.cpp
/// @brief Safely reclaim obsolete process-separated benchmark runs.

#include "run_lifecycle_lock.hpp"

#include <array>
#include <charconv>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/mount.h>
#endif

using laminate::bench::RunLifecycleLock;
using laminate::bench::RunLifecycleLockMode;

namespace {

constexpr std::uintmax_t kMaximumBindingBytes = 4U << 20U;
constexpr std::string_view kBindingFormat = "laminate-benchmark-run-v1";
constexpr std::string_view kSetupFormat =
    "laminate-benchmark-setup-v1";
constexpr std::string_view kPackedSetupFormat =
    "laminate-packed-benchmark-setup-v1";
constexpr std::string_view kCleanupRecordFormat =
    "laminate-benchmark-cleanup-v1";

struct Options {
    std::string variant;
    std::string profile;
    std::filesystem::path keep_run;
    std::optional<std::size_t> lanes;
};

struct RunBinding {
    std::string variant;
    std::string profile;
    std::string id;
    std::optional<std::size_t> lanes;
};

struct CleanupRecord {
    std::filesystem::path record_path;
    RunBinding binding;
    std::string original_name;
    std::string tombstone_name;
};

struct ArtifactInventory {
    std::uint64_t regular_files = 0;
    std::uint64_t bytes = 0;
};

void print_usage(std::ostream &output) {
    output << "Usage:\n"
              "  laminate_benchmark_cleanup --variant "
              "local|base|folded|noIntegrity "
              "--profile quick|target-balancedLaned|target-mulHeavyPyramid "
              "--keep-run ABSOLUTE_RUN\n"
              "  laminate_benchmark_cleanup --variant laned "
              "--profile quick|target-balancedLaned|target-mulHeavyPyramid "
              "--keep-run ABSOLUTE_RUN --lanes 1|128|16384\n";
}

Options parse_options(int argc, char **argv) {
    if ((argc != 7 && argc != 9) ||
        std::string_view(argv[1]) != "--variant" ||
        std::string_view(argv[3]) != "--profile" ||
        std::string_view(argv[5]) != "--keep-run") {
        throw std::invalid_argument(
            "options must be --variant, --profile, --keep-run, and "
            "--lanes for Laned");
    }
    Options result{
        .variant = argv[2],
        .profile = argv[4],
        .keep_run = argv[6],
    };
    if (result.variant != "local" && result.variant != "base" &&
        result.variant != "folded" &&
        result.variant != "laned" && result.variant != "noIntegrity") {
        throw std::invalid_argument(
            "--variant must be local, base, folded, laned, or noIntegrity");
    }
    if (result.profile != "quick" &&
        result.profile != "target-balancedLaned" &&
        result.profile != "target-mulHeavyPyramid") {
        throw std::invalid_argument(
            "--profile must be quick, target-balancedLaned, or "
            "target-mulHeavyPyramid");
    }
    if (!result.keep_run.is_absolute() ||
        result.keep_run == result.keep_run.root_path()) {
        throw std::invalid_argument(
            "--keep-run must be an absolute run below the filesystem root");
    }
    if (result.variant == "laned") {
        if (argc != 9 || std::string_view(argv[7]) != "--lanes") {
            throw std::invalid_argument(
                "Laned cleanup requires --lanes 1, 128, or 16384");
        }
        const std::string_view encoded(argv[8]);
        std::size_t lanes = 0;
        const auto parsed = std::from_chars(
            encoded.data(), encoded.data() + encoded.size(), lanes);
        if (parsed.ec != std::errc{} ||
            parsed.ptr != encoded.data() + encoded.size() ||
            (lanes != 1 && lanes != 128 && lanes != 16'384)) {
            throw std::invalid_argument(
                "Laned cleanup requires --lanes 1, 128, or 16384");
        }
        result.lanes = lanes;
    } else if (argc != 7) {
        throw std::invalid_argument(
            "--lanes is valid only for Laned cleanup");
    }
    return result;
}

std::filesystem::file_status safe_status(
    const std::filesystem::path &path) {
    std::error_code error;
    const std::filesystem::file_status result =
        std::filesystem::symlink_status(path, error);
    if (error) {
        throw std::runtime_error("cannot inspect " + path.string() + ": " +
                                 error.message());
    }
    return result;
}

void require_private_directory(const std::filesystem::path &path,
                               std::string_view description) {
    const std::filesystem::file_status status = safe_status(path);
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_directory(status)) {
        throw std::invalid_argument(std::string(description) +
                                    " must be a real directory: " +
                                    path.string());
    }
    struct stat metadata {};
    if (::lstat(path.c_str(), &metadata) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "cannot inspect " + path.string());
    }
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
        (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        throw std::invalid_argument(
            std::string(description) +
            " must be owned by the current user and not group/world writable: " +
            path.string());
    }
}

std::string read_owner_only_file(const std::filesystem::path &path) {
    int flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK;
#if defined(O_NOFOLLOW)
    flags |= O_NOFOLLOW;
#endif
    const int descriptor = ::open(path.c_str(), flags);
    if (descriptor < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "cannot open run identity " + path.string());
    }
    const auto close_descriptor = [descriptor] { (void)::close(descriptor); };
    struct stat metadata {};
    if (::fstat(descriptor, &metadata) != 0) {
        const int saved_errno = errno;
        close_descriptor();
        throw std::system_error(saved_errno, std::generic_category(),
                                "cannot inspect run identity " + path.string());
    }
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
        (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        close_descriptor();
        throw std::invalid_argument(
            "run identity must be owner-only: " + path.string());
    }
    if (metadata.st_size < 0 ||
        static_cast<std::uintmax_t>(metadata.st_size) >
            kMaximumBindingBytes) {
        close_descriptor();
        throw std::invalid_argument(
            "run identity exceeds its size limit: " + path.string());
    }

    std::string contents;
    contents.reserve(static_cast<std::size_t>(metadata.st_size));
    std::array<char, 4096> buffer{};
    while (true) {
        const ssize_t count = ::read(descriptor, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            const int saved_errno = errno;
            close_descriptor();
            throw std::system_error(saved_errno, std::generic_category(),
                                    "cannot read run identity " + path.string());
        }
        if (count == 0) {
            break;
        }
        const auto amount = static_cast<std::size_t>(count);
        if (amount > kMaximumBindingBytes - contents.size()) {
            close_descriptor();
            throw std::invalid_argument(
                "run identity exceeds its size limit: " + path.string());
        }
        contents.append(buffer.data(), amount);
    }
    if (::close(descriptor) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "cannot close run identity " + path.string());
    }
    return contents;
}

std::map<std::string, std::string> read_key_values(
    const std::filesystem::path &path) {
    std::istringstream input(read_owner_only_file(path));
    std::map<std::string, std::string> fields;
    for (std::string line; std::getline(input, line);) {
        const std::size_t separator = line.find('=');
        if (separator == std::string::npos || separator == 0) {
            throw std::invalid_argument("malformed run identity line in " +
                                        path.string());
        }
        const std::string key = line.substr(0, separator);
        if (!fields.emplace(key, line.substr(separator + 1)).second) {
            throw std::invalid_argument("duplicate run identity field in " +
                                        path.string());
        }
    }
    return fields;
}

void require_serializable_field(std::string_view value,
                                std::size_t maximum_bytes,
                                std::string_view field,
                                const std::filesystem::path &path) {
    if (value.empty() || value.size() > maximum_bytes) {
        throw std::invalid_argument(std::string(field) +
                                    " has an invalid length in " +
                                    path.string());
    }
    for (const unsigned char character : value) {
        if (character < 0x20U || character > 0x7eU) {
            throw std::invalid_argument(std::string(field) +
                                        " is not printable ASCII in " +
                                        path.string());
        }
    }
}

std::string require_field(const std::map<std::string, std::string> &fields,
                          std::string_view key,
                          const std::filesystem::path &path) {
    const auto found = fields.find(std::string(key));
    if (found == fields.end()) {
        throw std::invalid_argument("missing " + std::string(key) + " in " +
                                    path.string());
    }
    return found->second;
}

std::size_t require_size_field(
    const std::map<std::string, std::string> &fields,
    std::string_view key, const std::filesystem::path &path) {
    const std::string encoded = require_field(fields, key, path);
    std::size_t result = 0;
    const auto parsed = std::from_chars(
        encoded.data(), encoded.data() + encoded.size(), result);
    if (parsed.ec != std::errc{} ||
        parsed.ptr != encoded.data() + encoded.size()) {
        throw std::invalid_argument("invalid " + std::string(key) +
                                    " in " + path.string());
    }
    return result;
}

RunBinding parse_binding_file(const std::filesystem::path &path,
                              std::string_view expected_format) {
    const auto fields = read_key_values(path);
    if (require_field(fields, "format", path) != expected_format) {
        throw std::invalid_argument("unrecognized run identity format in " +
                                    path.string());
    }
    RunBinding result{
        .variant = require_field(fields, "run.variant", path),
        .profile = require_field(fields, "run.profile", path),
        .id = require_field(fields, "run.id", path),
    };
    require_serializable_field(result.variant, 64, "run.variant", path);
    require_serializable_field(result.profile, 64, "run.profile", path);
    require_serializable_field(result.id, 256, "run.id", path);
    return result;
}

bool path_exists(const std::filesystem::path &path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error == std::errc::no_such_file_or_directory ||
        (!error && status.type() == std::filesystem::file_type::not_found)) {
        return false;
    }
    if (error) {
        throw std::runtime_error("cannot inspect " + path.string() + ": " +
                                 error.message());
    }
    return true;
}

std::optional<RunBinding> read_run_binding(
    const std::filesystem::path &run_directory) {
    const std::filesystem::path binding =
        run_directory / "shared" / "run-binding.txt";
    const std::filesystem::path setup_result =
        run_directory / "shared" / "setup-result.txt";
    std::optional<RunBinding> result;
    if (!path_exists(binding)) {
        return std::nullopt;
    }
    result = parse_binding_file(binding, kBindingFormat);
    if (path_exists(setup_result)) {
        const auto fields = read_key_values(setup_result);
        const std::string format = require_field(fields, "format", setup_result);
        if (format == kSetupFormat) {
            const RunBinding setup_binding =
                parse_binding_file(setup_result, kSetupFormat);
            if (result && (result->variant != setup_binding.variant ||
                           result->profile != setup_binding.profile ||
                           result->id != setup_binding.id)) {
                throw std::invalid_argument(
                    "run-binding.txt disagrees with setup-result.txt in " +
                    run_directory.string());
            }
            result = setup_binding;
        } else if (format == kPackedSetupFormat && result &&
                   (result->variant == "folded" ||
                    result->variant == "laned")) {
            // Packed setup results use their own rich reporting schema. The
            // canonical run binding remains cleanup's identity boundary, and
            // every duplicated identity field must agree with it.
            const std::string packed_variant =
                require_field(fields, "protocol.variant", setup_result);
            const std::string packed_profile =
                require_field(fields, "benchmark.profile", setup_result);
            const std::string packed_id =
                require_field(fields, "run.id", setup_result);
            const std::size_t packed_lanes =
                require_size_field(fields, "geometry.B", setup_result);
            if (packed_variant != result->variant ||
                packed_profile != result->profile ||
                packed_id != result->id ||
                (packed_variant == "folded" && packed_lanes != 0) ||
                (packed_variant == "laned" && packed_lanes != 1 &&
                 packed_lanes != 128 && packed_lanes != 16'384)) {
                throw std::invalid_argument(
                    "run-binding.txt disagrees with packed setup-result.txt in " +
                    run_directory.string());
            }
            if (packed_variant == "laned") {
                result->lanes = packed_lanes;
            }
        } else {
            throw std::invalid_argument(
                "unrecognized run identity format in " + setup_result.string());
        }
    }
    return result;
}

class ExistingActivityLock {
  public:
    explicit ExistingActivityLock(const std::filesystem::path &path) {
        if (!path_exists(path)) {
            return;
        }
        int flags = O_RDWR | O_CLOEXEC | O_NONBLOCK;
#if defined(O_NOFOLLOW)
        flags |= O_NOFOLLOW;
#endif
        descriptor_ = ::open(path.c_str(), flags);
        if (descriptor_ < 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "cannot open activity file " +
                                        path.string());
        }
        struct stat metadata {};
        if (::fstat(descriptor_, &metadata) != 0) {
            const int saved_errno = errno;
            ::close(descriptor_);
            descriptor_ = -1;
            throw std::system_error(
                saved_errno, std::generic_category(),
                "cannot inspect activity file " + path.string());
        }
        if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
            (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
            ::close(descriptor_);
            descriptor_ = -1;
            throw std::invalid_argument(
                "activity file is not a safe regular file: " +
                path.string());
        }
        if (::flock(descriptor_, LOCK_EX | LOCK_NB) != 0) {
            const int saved_errno = errno;
            ::close(descriptor_);
            descriptor_ = -1;
            if (saved_errno == EWOULDBLOCK || saved_errno == EAGAIN) {
                throw std::runtime_error("benchmark role is active: " +
                                         path.string());
            }
            throw std::system_error(saved_errno, std::generic_category(),
                                    "cannot lock activity file " +
                                        path.string());
        }
    }

    ExistingActivityLock(const ExistingActivityLock &) = delete;
    ExistingActivityLock &operator=(const ExistingActivityLock &) = delete;

    ExistingActivityLock(ExistingActivityLock &&other) noexcept
        : descriptor_(other.descriptor_) {
        other.descriptor_ = -1;
    }

    ExistingActivityLock &operator=(ExistingActivityLock &&other) noexcept {
        if (this != &other) {
            release();
            descriptor_ = other.descriptor_;
            other.descriptor_ = -1;
        }
        return *this;
    }

    ~ExistingActivityLock() { release(); }

  private:
    void release() noexcept {
        if (descriptor_ < 0) {
            return;
        }
        (void)::flock(descriptor_, LOCK_UN);
        (void)::close(descriptor_);
        descriptor_ = -1;
    }

    int descriptor_ = -1;
};

class ParentCleanupLock {
  public:
    ParentCleanupLock(const std::filesystem::path &parent,
                      const Options &options)
        : path_(parent / (".laminate-cleanup-" + options.variant + '-' +
                          options.profile + ".lock")) {
        int flags = O_RDWR | O_CREAT | O_CLOEXEC | O_NONBLOCK;
#if defined(O_NOFOLLOW)
        flags |= O_NOFOLLOW;
#endif
        descriptor_ = ::open(path_.c_str(), flags, S_IRUSR | S_IWUSR);
        if (descriptor_ < 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "cannot open cleanup coordinator " +
                                        path_.string());
        }
        struct stat metadata {};
        if (::fstat(descriptor_, &metadata) != 0) {
            const int saved_errno = errno;
            ::close(descriptor_);
            descriptor_ = -1;
            throw std::system_error(saved_errno, std::generic_category(),
                                    "cannot inspect cleanup coordinator " +
                                        path_.string());
        }
        if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
            (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
            ::close(descriptor_);
            descriptor_ = -1;
            throw std::invalid_argument(
                "cleanup coordinator must be an owner-only regular file: " +
                path_.string());
        }
        if (::flock(descriptor_, LOCK_EX | LOCK_NB) != 0) {
            const int saved_errno = errno;
            ::close(descriptor_);
            descriptor_ = -1;
            if (saved_errno == EWOULDBLOCK || saved_errno == EAGAIN) {
                throw std::runtime_error(
                    "another cleanup_old command is already active for " +
                    options.variant + '/' + options.profile);
            }
            throw std::system_error(saved_errno, std::generic_category(),
                                    "cannot lock cleanup coordinator " +
                                        path_.string());
        }
    }

    ParentCleanupLock(const ParentCleanupLock &) = delete;
    ParentCleanupLock &operator=(const ParentCleanupLock &) = delete;

    ~ParentCleanupLock() {
        if (descriptor_ < 0) {
            return;
        }
        (void)::flock(descriptor_, LOCK_UN);
        (void)::close(descriptor_);
    }

  private:
    std::filesystem::path path_;
    int descriptor_ = -1;
};

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          std::string_view description) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(description) + " overflows");
    }
    return left + right;
}

#if defined(__linux__)
std::string decode_mount_path(std::string_view encoded) {
    std::string result;
    result.reserve(encoded.size());
    for (std::size_t index = 0; index < encoded.size(); ++index) {
        if (encoded[index] == '\\' && index + 3 < encoded.size() &&
            encoded[index + 1] >= '0' && encoded[index + 1] <= '7' &&
            encoded[index + 2] >= '0' && encoded[index + 2] <= '7' &&
            encoded[index + 3] >= '0' && encoded[index + 3] <= '7') {
            const unsigned value =
                static_cast<unsigned>(encoded[index + 1] - '0') * 64U +
                static_cast<unsigned>(encoded[index + 2] - '0') * 8U +
                static_cast<unsigned>(encoded[index + 3] - '0');
            result.push_back(static_cast<char>(value));
            index += 3;
        } else {
            result.push_back(encoded[index]);
        }
    }
    return result;
}
#endif

std::vector<std::filesystem::path> mounted_paths() {
    std::vector<std::filesystem::path> result;
#if defined(__linux__)
    std::ifstream input("/proc/self/mountinfo");
    if (!input) {
        throw std::runtime_error(
            "cleanup cannot read /proc/self/mountinfo");
    }
    for (std::string line; std::getline(input, line);) {
        std::istringstream fields(line);
        std::string mount_id;
        std::string parent_id;
        std::string device;
        std::string root;
        std::string mount_point;
        if (!(fields >> mount_id >> parent_id >> device >> root >>
              mount_point)) {
            throw std::runtime_error(
                "cleanup encountered malformed /proc/self/mountinfo");
        }
        result.emplace_back(decode_mount_path(mount_point));
    }
#elif defined(__APPLE__)
    struct statfs *mounts = nullptr;
    const int count = ::getmntinfo(&mounts, MNT_NOWAIT);
    if (count <= 0 || mounts == nullptr) {
        throw std::runtime_error("cleanup cannot inspect mounted filesystems");
    }
    result.reserve(static_cast<std::size_t>(count));
    for (int index = 0; index < count; ++index) {
        result.emplace_back(mounts[index].f_mntonname);
    }
#else
    throw std::runtime_error(
        "cleanup mount-point validation is unavailable on this platform");
#endif
    return result;
}

bool is_at_or_below(const std::filesystem::path &path,
                    const std::filesystem::path &root) {
    auto path_component = path.begin();
    for (auto root_component = root.begin(); root_component != root.end();
         ++root_component, ++path_component) {
        if (path_component == path.end() ||
            *path_component != *root_component) {
            return false;
        }
    }
    return true;
}

void reject_mount_points(const std::filesystem::path &root) {
    const std::filesystem::path canonical_root =
        std::filesystem::canonical(root);
    for (const std::filesystem::path &mounted : mounted_paths()) {
        std::error_code error;
        const std::filesystem::path canonical_mount =
            std::filesystem::weakly_canonical(mounted, error);
        if (error) {
            throw std::runtime_error("cleanup cannot canonicalize mount point " +
                                     mounted.string() + ": " +
                                     error.message());
        }
        if (is_at_or_below(canonical_mount, canonical_root)) {
            throw std::invalid_argument(
                "cleanup refuses a run containing a mount point: " +
                canonical_mount.string());
        }
    }
}

ArtifactInventory inspect_tree(const std::filesystem::path &root) {
    reject_mount_points(root);
    struct stat root_metadata {};
    if (::lstat(root.c_str(), &root_metadata) != 0 ||
        !S_ISDIR(root_metadata.st_mode)) {
        throw std::runtime_error("cannot inspect cleanup root " +
                                 root.string());
    }
    const dev_t expected_device = root_metadata.st_dev;
    ArtifactInventory result;
    std::vector<std::filesystem::path> directories{root};
    while (!directories.empty()) {
        const std::filesystem::path directory =
            std::move(directories.back());
        directories.pop_back();
        std::error_code error;
        for (std::filesystem::directory_iterator iterator(directory, error), end;
             iterator != end; iterator.increment(error)) {
            if (error) {
                throw std::runtime_error("cannot scan " + directory.string() +
                                         ": " + error.message());
            }
            const std::filesystem::path path = iterator->path();
            struct stat metadata {};
            if (::lstat(path.c_str(), &metadata) != 0) {
                throw std::system_error(errno, std::generic_category(),
                                        "cannot inspect cleanup entry " +
                                            path.string());
            }
            if (S_ISLNK(metadata.st_mode)) {
                continue;
            }
            if (S_ISDIR(metadata.st_mode)) {
                if (metadata.st_dev != expected_device) {
                    throw std::invalid_argument(
                        "cleanup refuses to cross a nested filesystem: " +
                        path.string());
                }
                directories.push_back(path);
                continue;
            }
            if (!S_ISREG(metadata.st_mode)) {
                throw std::invalid_argument(
                    "cleanup refuses a non-file artifact: " + path.string());
            }
            result.regular_files =
                checked_add(result.regular_files, 1, "regular-file count");
            result.bytes = checked_add(
                result.bytes, static_cast<std::uint64_t>(metadata.st_size),
                "artifact-byte count");
        }
        if (error) {
            throw std::runtime_error("cannot scan " + directory.string() +
                                     ": " + error.message());
        }
    }
    return result;
}

std::string human_bytes(std::uint64_t bytes) {
    constexpr std::array<std::string_view, 5> units{
        "B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < units.size()) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream output;
    output << std::fixed << std::setprecision(unit == 0 ? 0 : 2) << value
           << ' ' << units[unit];
    return output.str();
}

struct CleanupCandidate {
    std::filesystem::path path;
    bool is_tombstone = false;
    RunBinding binding;
    std::optional<CleanupRecord> transaction;
    std::optional<RunLifecycleLock> lifecycle;
    std::optional<ExistingActivityLock> client_activity;
    std::optional<ExistingActivityLock> server_activity;
    ArtifactInventory inventory;
};

CleanupCandidate preflight_candidate(
    std::filesystem::path path, bool is_tombstone, RunBinding binding,
    std::optional<CleanupRecord> transaction = std::nullopt) {
    CleanupCandidate result{
        .path = std::move(path),
        .is_tombstone = is_tombstone,
        .binding = std::move(binding),
        .transaction = std::move(transaction),
    };
    if (!result.is_tombstone) {
        result.lifecycle.emplace(result.path,
                                 RunLifecycleLockMode::Exclusive);
        result.client_activity.emplace(result.path / "client" /
                                       "activity.jsonl");
        result.server_activity.emplace(result.path / "server" /
                                       "activity.jsonl");
    }
    result.inventory = inspect_tree(result.path);
    return result;
}

std::string cleanup_namespace(const Options &options) {
    std::string result =
        ".laminate-cleanup-" + options.variant + '-' + options.profile;
    if (options.lanes) {
        result += "-b" + std::to_string(*options.lanes);
    }
    return result + '-';
}

std::string cleanup_record_prefix(const Options &options) {
    return cleanup_namespace(options) + "record-";
}

std::string cleanup_tombstone_prefix(const Options &options) {
    return cleanup_namespace(options) + "run-";
}

void fsync_directory(const std::filesystem::path &path) {
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "cannot open cleanup parent " +
                                    path.string());
    }
    if (::fsync(descriptor) != 0) {
        const int saved_errno = errno;
        ::close(descriptor);
        throw std::system_error(saved_errno, std::generic_category(),
                                "cannot flush cleanup parent " +
                                    path.string());
    }
    if (::close(descriptor) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "cannot close cleanup parent " +
                                    path.string());
    }
}

std::filesystem::path fresh_cleanup_path(
    const std::filesystem::path &parent, std::string_view prefix,
    std::size_t sequence, std::string_view suffix = {},
    std::string_view companion_suffix = {}) {
    for (std::size_t attempt = 0; attempt < 1'000; ++attempt) {
        const std::filesystem::path candidate =
            parent / (std::string(prefix) + std::to_string(::getpid()) + '-' +
                      std::to_string(sequence) + '-' +
                      std::to_string(attempt) + std::string(suffix));
        const std::filesystem::path companion =
            candidate.string() + std::string(companion_suffix);
        if (!path_exists(candidate) &&
            (companion_suffix.empty() || !path_exists(companion))) {
            return candidate;
        }
    }
    throw std::runtime_error("cannot allocate a cleanup artifact name");
}

bool is_safe_filename(std::string_view name) {
    if (name.empty() || name == "." || name == "..") {
        return false;
    }
    for (const unsigned char character : name) {
        const bool alphanumeric =
            (character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9');
        const bool punctuation = character == ' ' || character == '.' ||
                                 character == '_' || character == '-' ||
                                 character == '+' || character == '@' ||
                                 character == ':';
        if (!alphanumeric && !punctuation) {
            return false;
        }
    }
    const std::filesystem::path path(name);
    return path == path.filename() && !path.is_absolute();
}

CleanupRecord read_cleanup_record(const std::filesystem::path &path,
                                  const Options &options) {
    const auto fields = read_key_values(path);
    if (require_field(fields, "format", path) != kCleanupRecordFormat) {
        throw std::invalid_argument("unrecognized cleanup record format in " +
                                    path.string());
    }
    CleanupRecord result{
        .record_path = path,
        .binding = RunBinding{
            .variant = require_field(fields, "run.variant", path),
            .profile = require_field(fields, "run.profile", path),
            .id = require_field(fields, "run.id", path),
            .lanes = options.lanes
                         ? std::optional<std::size_t>(require_size_field(
                               fields, "run.lanes", path))
                         : std::nullopt,
        },
        .original_name = require_field(fields, "original.name", path),
        .tombstone_name = require_field(fields, "tombstone.name", path),
    };
    if (result.binding.variant != options.variant ||
        result.binding.profile != options.profile ||
        result.binding.id.empty() ||
        result.binding.lanes != options.lanes) {
        throw std::invalid_argument(
            "cleanup record variant/profile disagrees with its namespace: " +
            path.string());
    }
    if (!is_safe_filename(result.original_name) ||
        !is_safe_filename(result.tombstone_name) ||
        !result.tombstone_name.starts_with(
            cleanup_tombstone_prefix(options))) {
        throw std::invalid_argument(
            "cleanup record contains an unsafe directory name: " +
            path.string());
    }
    return result;
}

void publish_cleanup_record(const CleanupRecord &record,
                            const std::filesystem::path &parent) {
    const std::string contents =
        "format=" + std::string(kCleanupRecordFormat) +
        "\nrun.variant=" + record.binding.variant +
        "\nrun.profile=" + record.binding.profile + "\nrun.id=" +
        record.binding.id +
        (record.binding.lanes
             ? "\nrun.lanes=" + std::to_string(*record.binding.lanes)
             : "") +
        "\noriginal.name=" + record.original_name +
        "\ntombstone.name=" + record.tombstone_name + "\n";
    const std::filesystem::path temporary =
        record.record_path.string() + ".partial";
    int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC;
#if defined(O_NOFOLLOW)
    flags |= O_NOFOLLOW;
#endif
    int descriptor = ::open(temporary.c_str(), flags, S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "cannot create cleanup record " +
                                    temporary.string());
    }
    bool linked = false;
    try {
        std::size_t written = 0;
        while (written != contents.size()) {
            const ssize_t count = ::write(
                descriptor, contents.data() + written,
                contents.size() - written);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw std::system_error(
                    count < 0 ? errno : EIO, std::generic_category(),
                    "cannot write cleanup record " + temporary.string());
            }
            written += static_cast<std::size_t>(count);
        }
        if (::fsync(descriptor) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "cannot flush cleanup record " +
                                        temporary.string());
        }
        if (::close(descriptor) != 0) {
            descriptor = -1;
            throw std::system_error(errno, std::generic_category(),
                                    "cannot close cleanup record " +
                                        temporary.string());
        }
        descriptor = -1;
        if (::link(temporary.c_str(), record.record_path.c_str()) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "cannot publish cleanup record " +
                                        record.record_path.string());
        }
        linked = true;
        if (::unlink(temporary.c_str()) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "cannot remove cleanup-record staging " +
                                        temporary.string());
        }
        fsync_directory(parent);
    } catch (...) {
        if (descriptor >= 0) {
            (void)::close(descriptor);
        }
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        if (linked) {
            std::filesystem::remove(record.record_path, ignored);
        }
        throw;
    }
}

void remove_cleanup_record(const std::filesystem::path &path,
                           const std::filesystem::path &parent) {
    std::error_code error;
    if (!std::filesystem::remove(path, error) || error) {
        throw std::runtime_error("cannot remove cleanup record " +
                                 path.string() +
                                 (error ? ": " + error.message() : ""));
    }
    fsync_directory(parent);
}

std::vector<CleanupRecord> read_cleanup_records(
    const std::filesystem::path &parent, const Options &options) {
    const std::string prefix = cleanup_record_prefix(options);
    constexpr std::string_view suffix = ".record";
    std::vector<CleanupRecord> result;
    std::error_code error;
    for (std::filesystem::directory_iterator iterator(parent, error), end;
         iterator != end; iterator.increment(error)) {
        if (error) {
            throw std::runtime_error("cannot scan cleanup records: " +
                                     error.message());
        }
        const auto status = iterator->symlink_status(error);
        if (error) {
            throw std::runtime_error("cannot inspect cleanup record: " +
                                     error.message());
        }
        const std::string name = iterator->path().filename().string();
        if (!std::filesystem::is_regular_file(status) ||
            std::filesystem::is_symlink(status) ||
            !name.starts_with(prefix) || !name.ends_with(suffix)) {
            continue;
        }
        result.push_back(read_cleanup_record(iterator->path(), options));
    }
    if (error) {
        throw std::runtime_error("cannot scan cleanup records: " +
                                 error.message());
    }
    return result;
}

bool same_binding(const RunBinding &left, const RunBinding &right) {
    return left.variant == right.variant && left.profile == right.profile &&
           left.id == right.id && left.lanes == right.lanes;
}

bool matches_cleanup_scope(const RunBinding &binding,
                           const Options &options) {
    return binding.variant == options.variant &&
           binding.profile == options.profile &&
           binding.lanes == options.lanes;
}

struct CleanupPlan {
    std::vector<CleanupCandidate> candidates;
    std::vector<std::filesystem::path> stale_records;
    std::vector<std::filesystem::path> cancelled_keep_records;
    std::vector<std::filesystem::path> skipped_unbound;
    ArtifactInventory total;
};

void add_recorded_transactions(
    CleanupPlan &plan, std::set<std::filesystem::path> &claimed_paths,
    const std::filesystem::path &parent,
    const std::filesystem::path &canonical_keep,
    const RunBinding &keep_binding, const Options &options) {
    for (CleanupRecord record : read_cleanup_records(parent, options)) {
        const std::filesystem::path original =
            parent / record.original_name;
        const std::filesystem::path tombstone =
            parent / record.tombstone_name;
        const bool original_exists = path_exists(original);
        const bool tombstone_exists = path_exists(tombstone);
        if (tombstone == canonical_keep) {
            throw std::invalid_argument(
                "--keep-run is an interrupted-cleanup tombstone; preserve "
                "the original run path instead: " +
                record.original_name);
        }
        if (original_exists && tombstone_exists) {
            throw std::invalid_argument(
                "cleanup record names both an original and tombstone that "
                "exist: " +
                record.record_path.string());
        }
        const bool new_original = claimed_paths.insert(original).second;
        const bool new_tombstone = claimed_paths.insert(tombstone).second;
        if (!new_original || !new_tombstone) {
            throw std::invalid_argument(
                "cleanup records claim the same run path more than once: " +
                record.record_path.string());
        }
        if (original == canonical_keep) {
            if (!same_binding(record.binding, keep_binding)) {
                throw std::invalid_argument(
                    "an interrupted cleanup record targets --keep-run with "
                    "a different run identity: " +
                    record.record_path.string());
            }
            plan.cancelled_keep_records.push_back(record.record_path);
            continue;
        }
        if (!original_exists && !tombstone_exists) {
            plan.stale_records.push_back(record.record_path);
            continue;
        }
        const std::filesystem::path selected =
            tombstone_exists ? tombstone : original;
        require_private_directory(selected, "recorded cleanup run");
        if (!tombstone_exists) {
            const std::optional<RunBinding> binding =
                read_run_binding(selected);
            if (!binding || !same_binding(*binding, record.binding)) {
                throw std::invalid_argument(
                    "cleanup record no longer matches its original run: " +
                    record.record_path.string());
            }
        } else if (const std::optional<RunBinding> binding =
                       read_run_binding(selected);
                   binding && !same_binding(*binding, record.binding)) {
            throw std::invalid_argument(
                "cleanup record no longer matches its tombstone: " +
                record.record_path.string());
        }
        plan.candidates.push_back(preflight_candidate(
            selected, tombstone_exists, record.binding, std::move(record)));
    }
}

void add_matching_siblings(
    CleanupPlan &plan,
    const std::set<std::filesystem::path> &claimed_paths,
    const std::filesystem::path &parent,
    const std::filesystem::path &canonical_keep, const Options &options) {
    std::error_code error;
    for (std::filesystem::directory_iterator iterator(parent, error), end;
         iterator != end; iterator.increment(error)) {
        if (error) {
            throw std::runtime_error("cannot scan run parent: " +
                                     error.message());
        }
        const std::filesystem::path candidate = iterator->path();
        const auto status = iterator->symlink_status(error);
        if (error) {
            throw std::runtime_error("cannot inspect run-parent entry: " +
                                     error.message());
        }
        if (std::filesystem::is_symlink(status) ||
            !std::filesystem::is_directory(status)) {
            continue;
        }
        const std::filesystem::path canonical_candidate =
            std::filesystem::canonical(candidate);
        if (canonical_candidate == canonical_keep ||
            claimed_paths.contains(canonical_candidate)) {
            continue;
        }
        require_private_directory(canonical_candidate, "candidate run");
        const std::optional<RunBinding> binding =
            read_run_binding(canonical_candidate);
        if (!binding) {
            plan.skipped_unbound.push_back(canonical_candidate);
            continue;
        }
        if (!matches_cleanup_scope(*binding, options)) {
            continue;
        }
        if (!is_safe_filename(candidate.filename().string())) {
            throw std::invalid_argument(
                "matching run has a name that cannot be recorded safely: " +
                candidate.string());
        }
        plan.candidates.push_back(
            preflight_candidate(canonical_candidate, false, *binding));
    }
    if (error) {
        throw std::runtime_error("cannot scan run parent: " + error.message());
    }

}

CleanupPlan build_cleanup_plan(const std::filesystem::path &parent,
                               const std::filesystem::path &canonical_keep,
                               const RunBinding &keep_binding,
                               const Options &options) {
    CleanupPlan plan;
    std::set<std::filesystem::path> claimed_paths;
    add_recorded_transactions(plan, claimed_paths, parent, canonical_keep,
                              keep_binding, options);
    add_matching_siblings(plan, claimed_paths, parent, canonical_keep,
                          options);
    for (const CleanupCandidate &candidate : plan.candidates) {
        plan.total.bytes =
            checked_add(plan.total.bytes, candidate.inventory.bytes,
                        "cleanup bytes");
        plan.total.regular_files =
            checked_add(plan.total.regular_files,
                        candidate.inventory.regular_files,
                        "cleanup regular files");
    }
    return plan;
}

void print_cleanup_plan(const CleanupPlan &plan, const Options &options,
                        const std::filesystem::path &canonical_keep) {
    std::cout << "Laminate run cleanup\n"
              << "  variant/profile: " << options.variant << '/'
              << options.profile << "\n";
    if (options.lanes) {
        std::cout << "  lanes: B=" << *options.lanes << "\n";
    }
    std::cout
              << "  keeping: " << canonical_keep << "\n"
              << "  runs to remove: " << plan.candidates.size() << "\n"
              << "  regular files: " << plan.total.regular_files << "\n"
              << "  apparent bytes: " << plan.total.bytes << " ("
              << human_bytes(plan.total.bytes) << ")\n";
    for (const CleanupCandidate &candidate : plan.candidates) {
        std::cout << "    remove: " << candidate.path << " ("
                  << human_bytes(candidate.inventory.bytes) << ")\n";
    }
    for (const std::filesystem::path &path : plan.skipped_unbound) {
        std::cout << "    preserved unrecognized directory: " << path << '\n';
    }
}

void retire_obsolete_records(const CleanupPlan &plan,
                             const std::filesystem::path &parent) {
    for (const std::filesystem::path &record : plan.stale_records) {
        remove_cleanup_record(record, parent);
    }
    for (const std::filesystem::path &record :
         plan.cancelled_keep_records) {
        remove_cleanup_record(record, parent);
        std::cout << "    cancelled interrupted cleanup intent for kept run: "
                  << record << '\n';
    }
}

void remove_candidate_transaction(CleanupCandidate &candidate,
                                  const std::filesystem::path &parent,
                                  const Options &options,
                                  std::size_t sequence) {
    // Durable record -> same-parent rename -> recursive removal -> parent
    // fsync -> record removal. A tombstone name alone never authorizes delete.
    if (!candidate.transaction) {
        const std::filesystem::path record_path = fresh_cleanup_path(
            parent, cleanup_record_prefix(options), sequence, ".record",
            ".partial");
        const std::filesystem::path tombstone = fresh_cleanup_path(
            parent, cleanup_tombstone_prefix(options), sequence);
        candidate.transaction = CleanupRecord{
            .record_path = record_path,
            .binding = candidate.binding,
            .original_name = candidate.path.filename().string(),
            .tombstone_name = tombstone.filename().string(),
        };
        publish_cleanup_record(*candidate.transaction, parent);
    }

    const std::filesystem::path deletion_path =
        parent / candidate.transaction->tombstone_name;
    if (!candidate.is_tombstone) {
        reject_mount_points(candidate.path);
        std::filesystem::rename(candidate.path, deletion_path);
        fsync_directory(parent);
        candidate.is_tombstone = true;
    }
    reject_mount_points(deletion_path);
    std::error_code remove_error;
    (void)std::filesystem::remove_all(deletion_path, remove_error);
    if (remove_error || path_exists(deletion_path)) {
        throw std::runtime_error(
            "cleanup stopped; retry cleanup_old to finish transaction " +
            candidate.transaction->record_path.string() +
            (remove_error ? ": " + remove_error.message() : ""));
    }
    fsync_directory(parent);
    remove_cleanup_record(candidate.transaction->record_path, parent);
}

std::size_t execute_cleanup_plan(CleanupPlan &plan,
                                 const std::filesystem::path &parent,
                                 const Options &options) {
    std::size_t removed = 0;
    for (std::size_t index = 0; index < plan.candidates.size(); ++index) {
        CleanupCandidate &candidate = plan.candidates[index];
        std::cout << '[' << index + 1 << '/' << plan.candidates.size()
                  << "] Removing " << candidate.path << "..." << std::flush;
        remove_candidate_transaction(candidate, parent, options, index);
        ++removed;
        std::cout << " done\n";
    }
    return removed;
}

int cleanup_old_runs(const Options &options) {
    require_private_directory(options.keep_run, "--keep-run");
    const std::filesystem::path canonical_keep =
        std::filesystem::canonical(options.keep_run);
    const std::filesystem::path parent = canonical_keep.parent_path();
    require_private_directory(parent, "run parent");
    if (parent.filename() != "runs") {
        throw std::invalid_argument(
            "cleanup requires --keep-run to be an immediate child of a "
            "directory named runs");
    }

    RunLifecycleLock keep_lifecycle(canonical_keep,
                                    RunLifecycleLockMode::Shared);
    ParentCleanupLock coordinator(parent, options);
    const std::optional<RunBinding> keep_binding =
        read_run_binding(canonical_keep);
    if (!keep_binding || keep_binding->variant != options.variant ||
        keep_binding->profile != options.profile ||
        keep_binding->lanes != options.lanes) {
        throw std::invalid_argument(
            options.lanes
                ? "--keep-run is not bound to the requested variant/profile/B"
                : "--keep-run is not bound to the requested variant/profile");
    }

    std::cout << "Preflighting inactive sibling runs below " << parent
              << "...\n";
    CleanupPlan plan = build_cleanup_plan(parent, canonical_keep,
                                          *keep_binding, options);
    print_cleanup_plan(plan, options, canonical_keep);
    retire_obsolete_records(plan, parent);
    if (plan.candidates.empty()) {
        std::cout << "\nNothing to remove. The kept run and all unrelated "
                     "entries were preserved.\n";
        return 0;
    }

    const std::size_t removed = execute_cleanup_plan(plan, parent, options);
    std::cout << "\nCLEANUP COMPLETE: removed " << removed << " matching run"
              << (removed == 1 ? "" : "s") << " and reclaimed "
              << human_bytes(plan.total.bytes)
              << " of apparent file data.\n"
              << "The kept run, pointer files, tmux sessions, and unrelated "
                 "profiles were not changed.\n";
    return 0;
}

} // namespace

int main(int argc, char **argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        print_usage(std::cout);
        return 0;
    }
    try {
        return cleanup_old_runs(parse_options(argc, argv));
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        print_usage(std::cerr);
        return 1;
    }
}
