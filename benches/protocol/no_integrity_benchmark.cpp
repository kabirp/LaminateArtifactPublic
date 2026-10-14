/// @file no_integrity_benchmark.cpp
/// @brief Role-separated FHE payload baseline with no integrity proof.
///
/// Setup publishes reusable key material and workload/resource metadata. The
/// client sends one encrypted request and decrypts one server response; the
/// server evaluates through the output-only adjacent-layer storage path.
/// No GKR proof or transcript-packing proof is produced. PASS records successful
/// benchmark execution and response handling, not verified computation integrity.

#include "benchmark_support.hpp"
#include "completed_result_report.hpp"
#include "no_integrity_git_state.hpp"
#include "protocol_progress.hpp"
#include "run_lifecycle_lock.hpp"

#include "laminate/bench/no_integrity_parameters.hpp"

#include "laminate/bench/host_resource_budget.hpp"
#include "laminate/fhe/seal_backend.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/fixtures/workloads.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <random>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#include <sched.h>
#endif

using namespace laminate;
using namespace laminate::bench;
using namespace laminate::fhe;
using namespace laminate::payload;

namespace {

constexpr std::size_t kSlots = std::size_t{1} << 14U;
constexpr std::size_t kInputs = kBenchmarkDiamondInputCiphertexts;
constexpr std::size_t kOutputs = kBenchmarkDiamondOutputCiphertexts;
constexpr std::size_t kChunkCiphertexts = 64;
constexpr std::uint64_t kServerResidentReserveBytes =
    8'000'000'000ULL;
constexpr std::uint64_t kPayloadStorageTransferResidentBytes =
    3U * kFileTraceStoreTransferBufferBytes;
constexpr std::uint64_t kClientResidentMarginBytes =
    4'000'000'000ULL;
constexpr std::uint64_t kPersistentDiskMarginBytes =
    2'000'000'000ULL;
constexpr std::size_t kMaximumSetupBytes = 16U << 10U;
constexpr std::string_view kSetupDomain =
    "LaminateImpl/NoIntegritySetup/v1";
constexpr std::string_view kRequestDomain =
    "LaminateImpl/NoIntegrityRequest/v1";
constexpr std::string_view kResponseDomain =
    "LaminateImpl/NoIntegrityResponse/v1";

void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          std::string_view label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

std::uint64_t checked_multiply(std::uint64_t left, std::uint64_t right,
                               std::string_view label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left * right;
}

std::size_t checked_size(std::uint64_t value, std::string_view label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(label) + " does not fit size_t");
    }
    return static_cast<std::size_t>(value);
}

std::int64_t unix_milliseconds() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string decimal_list(std::span<const std::uint64_t> values) {
    std::string result;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            result.push_back(',');
        }
        result += std::to_string(values[index]);
    }
    return result;
}

using Profile = BenchmarkPayloadProfile;

Profile profile(std::string_view name) {
    return benchmark_payload_profile(name);
}

WorkloadSpec workload_spec(const Profile &selected) {
    return benchmark_payload_workload_spec(
        selected, PayloadShape::wide(kSlots));
}

SealParameters seal_parameters(const Profile &selected) {
    return no_integrity_seal_parameters(selected);
}

struct Command {
    enum class Action { Setup, Client, Server, Status };
    Action action = Action::Status;
    std::string variant;
    std::string profile;
    std::filesystem::path run_directory;
};

bool is_process_action(std::string_view action) {
    return action == "setup" || action == "run_client" ||
           action == "run_server" || action == "status";
}

Command parse_command(int argc, char **argv) {
    if (argc != 8 || std::string_view(argv[2]) != "--variant" ||
        std::string_view(argv[4]) != "--profile" ||
        std::string_view(argv[6]) != "--run-dir") {
        throw std::invalid_argument(
            "expected ACTION --variant noIntegrity --profile "
            "quick|target-balancedLaned|target-mulHeavyPyramid --run-dir "
            "ABSOLUTE_PATH");
    }
    Command result;
    const std::string_view action(argv[1]);
    if (action == "setup") {
        result.action = Command::Action::Setup;
    } else if (action == "run_client") {
        result.action = Command::Action::Client;
    } else if (action == "run_server") {
        result.action = Command::Action::Server;
    } else if (action == "status") {
        result.action = Command::Action::Status;
    } else {
        throw std::invalid_argument("unknown noIntegrity action");
    }
    result.variant = argv[3];
    result.profile = argv[5];
    result.run_directory = argv[7];
    if (result.variant != "noIntegrity") {
        throw std::invalid_argument("variant must be exactly noIntegrity");
    }
    (void)profile(result.profile);
    if (!result.run_directory.is_absolute() ||
        result.run_directory == result.run_directory.root_path()) {
        throw std::invalid_argument(
            "--run-dir must be an absolute path below the filesystem root");
    }
    return result;
}

class Writer {
  public:
    void u64(std::uint64_t value) {
        for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
            bytes_.push_back(static_cast<std::uint8_t>(
                (value >> (8U * byte)) & 0xffU));
        }
    }
    void text(std::string_view value) {
        bytes(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(value.data()),
            value.size()));
    }
    void bytes(std::span<const std::uint8_t> value) {
        u64(value.size());
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }
    void digest(const Digest &value) {
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }
    std::vector<std::uint8_t> finish() && { return std::move(bytes_); }

  private:
    std::vector<std::uint8_t> bytes_;
};

class Reader {
  public:
    explicit Reader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}

    std::uint64_t u64(std::string_view label) {
        if (remaining() < sizeof(std::uint64_t)) {
            fail(label);
        }
        std::uint64_t result = 0;
        for (std::size_t byte = 0; byte < sizeof(result); ++byte) {
            result |= static_cast<std::uint64_t>(bytes_[cursor_++])
                      << (8U * byte);
        }
        return result;
    }
    std::vector<std::uint8_t> bytes(std::size_t maximum,
                                    std::string_view label) {
        const std::size_t size = checked_size(u64(label), label);
        if (size > maximum || remaining() < size) {
            fail(label);
        }
        std::vector<std::uint8_t> result(
            bytes_.begin() + static_cast<std::ptrdiff_t>(cursor_),
            bytes_.begin() + static_cast<std::ptrdiff_t>(cursor_ + size));
        cursor_ += size;
        return result;
    }
    std::string text(std::size_t maximum, std::string_view label) {
        const std::vector<std::uint8_t> value = bytes(maximum, label);
        return std::string(value.begin(), value.end());
    }
    Digest digest(std::string_view label) {
        if (remaining() < Digest{}.size()) {
            fail(label);
        }
        Digest result{};
        std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(cursor_),
                    result.size(), result.begin());
        cursor_ += result.size();
        return result;
    }
    void finish(std::string_view label) const {
        if (cursor_ != bytes_.size()) {
            fail(label);
        }
    }

  private:
    std::size_t remaining() const { return bytes_.size() - cursor_; }
    [[noreturn]] static void fail(std::string_view label) {
        throw std::invalid_argument("invalid " + std::string(label));
    }
    std::span<const std::uint8_t> bytes_;
    std::size_t cursor_ = 0;
};

struct SetupRecord {
    std::string variant;
    std::string profile;
    std::string git_commit;
    std::string build_type;
    std::string seal_acceleration;
    Digest run_id{};
    Digest circuit_id{};
    Digest storage_context_id{};
    Digest configuration_id{};
    std::size_t depth = 0;
    std::size_t width = 0;
    std::size_t payload_operations = 0;
    std::size_t compiled_layers = 0;
    std::size_t fresh_rns_limbs = 0;
    std::size_t fresh_modulus_product_bits = 0;
    std::size_t key_modulus_product_bits = 0;
    std::uint64_t server_bytes = 0;
    Digest server_digest{};
    std::uint64_t client_bytes = 0;
    Digest client_digest{};
    std::uint64_t request_limit = 0;
    std::uint64_t response_limit = 0;
    HostResourceBudget host_budget;
    std::uint64_t client_peak_resident_bytes = 0;
    std::uint64_t server_resident_cap_bytes = 0;
    std::uint64_t persistent_disk_reserve_bytes = 0;

    bool operator==(const SetupRecord &) const = default;
};

std::vector<std::uint8_t> encode_setup(const SetupRecord &setup) {
    Writer writer;
    writer.text(kSetupDomain);
    writer.u64(1);
    writer.text(setup.variant);
    writer.text(setup.profile);
    writer.text(setup.git_commit);
    writer.text(setup.build_type);
    writer.text(setup.seal_acceleration);
    writer.digest(setup.run_id);
    writer.digest(setup.circuit_id);
    writer.digest(setup.storage_context_id);
    writer.digest(setup.configuration_id);
    writer.u64(setup.depth);
    writer.u64(setup.width);
    writer.u64(setup.payload_operations);
    writer.u64(setup.compiled_layers);
    writer.u64(setup.fresh_rns_limbs);
    writer.u64(setup.fresh_modulus_product_bits);
    writer.u64(setup.key_modulus_product_bits);
    writer.u64(setup.server_bytes);
    writer.digest(setup.server_digest);
    writer.u64(setup.client_bytes);
    writer.digest(setup.client_digest);
    writer.u64(setup.request_limit);
    writer.u64(setup.response_limit);
    writer.u64(setup.host_budget.observed_available_disk_bytes);
    writer.u64(setup.host_budget.observed_physical_ram_bytes);
    writer.u64(setup.host_budget.max_live_disk_bytes);
    writer.u64(setup.host_budget.max_resident_ram_bytes);
    writer.u64(setup.client_peak_resident_bytes);
    writer.u64(setup.server_resident_cap_bytes);
    writer.u64(setup.persistent_disk_reserve_bytes);
    return std::move(writer).finish();
}

SetupRecord decode_setup(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    if (reader.text(128, "setup domain") != kSetupDomain ||
        reader.u64("setup version") != 1U) {
        throw std::invalid_argument("unsupported noIntegrity setup");
    }
    SetupRecord result;
    result.variant = reader.text(64, "setup variant");
    result.profile = reader.text(64, "setup profile");
    result.git_commit = reader.text(128, "setup git commit");
    result.build_type = reader.text(64, "setup build type");
    result.seal_acceleration = reader.text(128, "setup acceleration");
    result.run_id = reader.digest("setup run id");
    result.circuit_id = reader.digest("setup circuit id");
    result.storage_context_id = reader.digest("setup storage context id");
    result.configuration_id = reader.digest("setup configuration id");
    result.depth = checked_size(reader.u64("setup depth"), "setup depth");
    result.width = checked_size(reader.u64("setup width"), "setup width");
    result.payload_operations = checked_size(
        reader.u64("setup payload operations"),
        "setup payload operations");
    result.compiled_layers = checked_size(
        reader.u64("setup compiled layers"), "setup compiled layers");
    result.fresh_rns_limbs = checked_size(
        reader.u64("setup RNS limbs"), "setup RNS limbs");
    result.fresh_modulus_product_bits = checked_size(
        reader.u64("setup fresh modulus product bits"),
        "setup fresh modulus product bits");
    result.key_modulus_product_bits = checked_size(
        reader.u64("setup key modulus product bits"),
        "setup key modulus product bits");
    result.server_bytes = reader.u64("server preprocessing bytes");
    result.server_digest = reader.digest("server preprocessing digest");
    result.client_bytes = reader.u64("client preprocessing bytes");
    result.client_digest = reader.digest("client preprocessing digest");
    result.request_limit = reader.u64("request limit");
    result.response_limit = reader.u64("response limit");
    result.host_budget.observed_available_disk_bytes =
        reader.u64("observed disk");
    result.host_budget.observed_physical_ram_bytes =
        reader.u64("observed RAM");
    result.host_budget.max_live_disk_bytes = reader.u64("live disk budget");
    result.host_budget.max_resident_ram_bytes =
        reader.u64("resident RAM budget");
    result.client_peak_resident_bytes = reader.u64("client resident peak");
    result.server_resident_cap_bytes = reader.u64("server resident cap");
    result.persistent_disk_reserve_bytes =
        reader.u64("persistent disk reserve");
    reader.finish("setup trailing bytes");
    return result;
}

std::vector<std::uint8_t> read_bounded_file(
    const std::filesystem::path &path, std::uint64_t maximum) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        throw std::runtime_error("expected a safe regular file: " +
                                 path.string());
    }
    const std::uintmax_t size = std::filesystem::file_size(path, error);
    if (error || size > maximum ||
        size > static_cast<std::uintmax_t>(
                   std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error("file exceeds its bound: " + path.string());
    }
    std::ifstream input(path, std::ios::binary);
    std::vector<std::uint8_t> result(static_cast<std::size_t>(size));
    input.read(reinterpret_cast<char *>(result.data()),
               static_cast<std::streamsize>(result.size()));
    if (!input || input.peek() != std::char_traits<char>::eof()) {
        throw std::runtime_error("failed to read bounded file: " +
                                 path.string());
    }
    return result;
}

void publish_private_file(const std::filesystem::path &path,
                          std::span<const std::uint8_t> bytes) {
    const std::filesystem::path temporary =
        path.parent_path() /
        (".no-integrity-" + path.filename().string() + "." +
         std::to_string(::getpid()));
    int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC;
#if defined(O_NOFOLLOW)
    flags |= O_NOFOLLOW;
#endif
    int descriptor = ::open(temporary.c_str(), flags, S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "failed to create staged artifact");
    }
    try {
        std::size_t written = 0;
        while (written != bytes.size()) {
            const ssize_t count = ::write(
                descriptor, bytes.data() + written, bytes.size() - written);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw std::system_error(
                    count < 0 ? errno : EIO, std::generic_category(),
                    "failed to write staged artifact");
            }
            written += static_cast<std::size_t>(count);
        }
        if (::fsync(descriptor) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "failed to flush staged artifact");
        }
        if (::close(descriptor) != 0) {
            descriptor = -1;
            throw std::system_error(errno, std::generic_category(),
                                    "failed to close staged artifact");
        }
        descriptor = -1;
        if (::link(temporary.c_str(), path.c_str()) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "failed to publish immutable artifact");
        }
        if (::unlink(temporary.c_str()) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "failed to retire staged artifact");
        }
    } catch (...) {
        if (descriptor >= 0) {
            (void)::close(descriptor);
        }
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        throw;
    }
}

void publish_private_text(const std::filesystem::path &path,
                          std::string_view value) {
    publish_private_file(path, std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t *>(
                                       value.data()),
                                   value.size()));
}

void make_private_directory(const std::filesystem::path &path) {
    std::error_code error;
    if (!std::filesystem::create_directory(path, error) || error) {
        throw std::runtime_error("failed to create private directory: " +
                                 path.string());
    }
    std::filesystem::permissions(
        path, std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace, error);
    if (error) {
        throw std::runtime_error("failed to protect private directory: " +
                                 path.string());
    }
}

void create_run_tree(const std::filesystem::path &root) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(root, error);
    if (!error && status.type() != std::filesystem::file_type::not_found) {
        throw std::invalid_argument("setup run directory already exists");
    }
    error.clear();
    make_private_directory(root);
    make_private_directory(root / "shared");
    make_private_directory(root / "shared" / "transcript");
    make_private_directory(root / "shared" / "report");
    make_private_directory(root / "client");
    make_private_directory(root / "client" / "preprocessing");
    make_private_directory(root / "client" / "work");
    make_private_directory(root / "server");
    make_private_directory(root / "server" / "preprocessing");
    make_private_directory(root / "server" / "work");
}

Digest random_digest() {
    std::array<std::uint8_t, 64> entropy{};
    std::random_device random;
    for (std::uint8_t &byte : entropy) {
        byte = static_cast<std::uint8_t>(random());
    }
    return sha256(entropy);
}

class RoleActivity {
  public:
    RoleActivity(std::filesystem::path path, std::string role)
        : path_(std::move(path)), role_(std::move(role)),
          uncaught_(std::uncaught_exceptions()) {
        int flags = O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC;
#if defined(O_NOFOLLOW)
        flags |= O_NOFOLLOW;
#endif
        descriptor_ = ::open(path_.c_str(), flags, S_IRUSR | S_IWUSR);
        if (descriptor_ < 0 || ::flock(descriptor_, LOCK_EX | LOCK_NB) != 0) {
            const int saved = errno;
            if (descriptor_ >= 0) {
                (void)::close(descriptor_);
            }
            throw std::system_error(saved, std::generic_category(),
                                    "failed to claim role activity");
        }
        append("start", "starting");
        next_heartbeat_ = std::chrono::steady_clock::now() +
                          std::chrono::seconds(30);
    }
    RoleActivity(const RoleActivity &) = delete;
    RoleActivity &operator=(const RoleActivity &) = delete;
    ~RoleActivity() {
        if (!complete_ || std::uncaught_exceptions() > uncaught_) {
            append_noexcept("stop", "exception");
        }
        if (descriptor_ >= 0) {
            (void)::flock(descriptor_, LOCK_UN);
            (void)::close(descriptor_);
        }
    }
    void transition(std::string_view stage) {
        stage_ = std::string(stage);
        append("stage", stage_);
        next_heartbeat_ = std::chrono::steady_clock::now() +
                          std::chrono::seconds(30);
    }
    void heartbeat() noexcept {
        if (std::chrono::steady_clock::now() >= next_heartbeat_) {
            append_noexcept("heartbeat", stage_);
            next_heartbeat_ = std::chrono::steady_clock::now() +
                              std::chrono::seconds(30);
        }
    }
    void mark_complete() noexcept {
        complete_ = true;
        stage_ = "complete";
        append_noexcept("stop", stage_);
    }

  private:
    std::string line(std::string_view event, std::string_view stage) const {
        std::ostringstream output;
        output << '{' << "\"schema\":\"laminate-role-activity-v1\","
               << "\"role\":" << protocol_progress_json_string(role_)
               << ",\"event\":" << protocol_progress_json_string(event)
               << ",\"stage\":" << protocol_progress_json_string(stage)
               << ",\"pid\":" << static_cast<std::uint64_t>(::getpid())
               << ",\"unix_ms\":" << unix_milliseconds() << "}\n";
        return output.str();
    }
    void append(std::string_view event, std::string_view stage) {
        const std::string value = line(event, stage);
        std::size_t written = 0;
        while (written != value.size()) {
            const ssize_t count = ::write(descriptor_, value.data() + written,
                                          value.size() - written);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw std::system_error(errno, std::generic_category(),
                                        "failed to append role activity");
            }
            written += static_cast<std::size_t>(count);
        }
    }
    void append_noexcept(std::string_view event,
                         std::string_view stage) noexcept {
        try {
            append(event, stage);
        } catch (...) {
        }
    }
    std::filesystem::path path_;
    std::string role_;
    std::string stage_ = "starting";
    int descriptor_ = -1;
    int uncaught_ = 0;
    std::chrono::steady_clock::time_point next_heartbeat_;
    bool complete_ = false;
};

bool regular_file_exists(const std::filesystem::path &path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    return !error && !std::filesystem::is_symlink(status) &&
           std::filesystem::is_regular_file(status);
}

bool result_contains(const std::filesystem::path &path,
                     std::string_view line) {
    std::ifstream input(path);
    for (std::string current; std::getline(input, current);) {
        if (current == line) {
            return true;
        }
    }
    return false;
}

bool activity_is_active(const std::filesystem::path &path) {
    if (!regular_file_exists(path)) {
        return false;
    }
    int flags = O_RDWR | O_CLOEXEC;
#if defined(O_NOFOLLOW)
    flags |= O_NOFOLLOW;
#endif
    const int descriptor = ::open(path.c_str(), flags);
    if (descriptor < 0) {
        return false;
    }
    const bool active = ::flock(descriptor, LOCK_EX | LOCK_NB) != 0 &&
                        (errno == EWOULDBLOCK || errno == EAGAIN);
    if (!active) {
        (void)::flock(descriptor, LOCK_UN);
    }
    (void)::close(descriptor);
    return active;
}

Timing wait_for_artifact(const std::filesystem::path &path,
                         const std::filesystem::path &peer_failure,
                         const std::filesystem::path &peer_activity,
                         std::string_view description,
                         RoleActivity &activity) {
    Stopwatch stopwatch;
    std::optional<std::chrono::steady_clock::time_point> inactive_since;
    while (!regular_file_exists(path)) {
        if (regular_file_exists(peer_failure)) {
            const auto failure = read_bounded_file(peer_failure, 16U << 10U);
            throw std::runtime_error(
                "peer failed while waiting for " + std::string(description) +
                ": " + std::string(failure.begin(), failure.end()));
        }
        if (regular_file_exists(peer_activity) &&
            !activity_is_active(peer_activity)) {
            if (!inactive_since) {
                inactive_since = std::chrono::steady_clock::now();
            } else if (std::chrono::steady_clock::now() - *inactive_since >=
                       std::chrono::seconds(3)) {
                throw std::runtime_error(
                    "peer stopped before publishing " +
                    std::string(description));
            }
        } else {
            inactive_since.reset();
        }
        activity.heartbeat();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return stopwatch.stop();
}

class PrivateWorkDirectory {
  public:
    explicit PrivateWorkDirectory(const std::filesystem::path &parent) {
        root_ = parent / ("no-integrity-" + std::to_string(::getpid()));
        make_private_directory(root_);
    }
    ~PrivateWorkDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }
    std::filesystem::path make_child(std::string_view name) const {
        const std::filesystem::path child = root_ / std::string(name);
        make_private_directory(child);
        return child;
    }

  private:
    std::filesystem::path root_;
};

std::optional<std::uint64_t> pinned_logical_cpu() {
#if defined(__linux__)
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    if (::sched_getaffinity(0, sizeof(affinity), &affinity) == 0) {
        std::optional<std::uint64_t> selected;
        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
            if (!CPU_ISSET(cpu, &affinity)) {
                continue;
            }
            if (selected) {
                return std::nullopt;
            }
            selected = static_cast<std::uint64_t>(cpu);
        }
        return selected;
    }
#endif
    return std::nullopt;
}

void emit_identity(const Record &record, const Command &command,
                   const SetupRecord &setup) {
    const SystemInfo system = system_info();
    record.text("run.variant", command.variant);
    record.text("run.profile", command.profile);
    record.text("run.id", digest_hex(setup.run_id));
    record.text("environment.git_commit", setup.git_commit);
    record.text("environment.git_dirty", LAMINATE_NO_INTEGRITY_GIT_DIRTY);
    record.text("environment.build_type", setup.build_type);
    record.text("environment.compiler", LAMINATE_COMPILER);
    record.text("environment.seal_version", LAMINATE_SEAL_VERSION);
    record.text("environment.seal_acceleration", setup.seal_acceleration);
    record.text("environment.sha256_acceleration",
                LAMINATE_SHA256_ACCELERATION);
    record.text("environment.fhe_backend", "seal-bgv");
    record.text("environment.trace_execution",
                "file-backed-output-only");
    record.text("environment.threading", "single-cpu-process");
    const std::optional<std::uint64_t> pinned_cpu = pinned_logical_cpu();
    record.text("environment.pinned_cpu",
                pinned_cpu ? std::to_string(*pinned_cpu) : "not-observed");
    record.text("environment.os", system.os);
    record.text("environment.cpu", system.cpu);
    record.integer("environment.physical_cores", system.physical_cores);
    record.integer("environment.logical_cores", system.logical_cores);
    record.integer("environment.ram_bytes", system.ram_bytes);
    emit_cpu_feature_availability(record, system);
}

void emit_geometry_fields(const Record &record, const Profile &selected,
                          std::size_t payload_operations,
                          std::size_t compiled_layers,
                          const SealParameters &parameters,
                          std::size_t fresh_modulus_product_bits,
                          std::size_t key_modulus_product_bits) {
    record.integer("parameters.slots", kSlots);
    record.integer("parameters.payload_multiplicative_depth",
                   selected.depth);
    record.text("parameters.payload_workload",
                std::string(workload_name(selected.workload_kind)));
    record.integer("parameters.payload_width", selected.width);
    record.integer("parameters.payload_inputs", kInputs);
    record.integer("parameters.payload_outputs", kOutputs);
    record.integer("parameters.payload_operations", payload_operations);
    record.integer("parameters.payload_add_gates", selected.add_gates);
    record.integer("parameters.payload_add_plain_gates",
                   selected.add_plain_gates);
    record.integer("parameters.payload_mul_gates", selected.mul_gates);
    record.integer("parameters.payload_mul_plain_gates",
                   selected.mul_plain_gates);
    record.integer("parameters.payload_rotate_gates",
                   selected.rotate_gates);
    record.integer("parameters.compiled_layers", compiled_layers);
    record.integer("parameters.fresh_rns_limbs",
                   parameters.fresh_rns_limbs);
    record.integer("parameters.fresh_modulus_product_bits",
                   fresh_modulus_product_bits);
    record.integer("parameters.key_modulus_product_bits",
                   key_modulus_product_bits);
    record.integer("parameters.output_rns_limbs", 1);
    record.integer("parameters.plaintext_modulus", kBaseFieldOrder);
    record.text("parameters.data_primes_bottom_to_top",
                decimal_list(parameters.exact_data_primes));
    record.integer("parameters.special_prime", parameters.exact_special_prime);
    record.integer("parameters.output_modulus",
                   parameters.exact_data_primes.front());
    record.integer("parameters.output_modulus_bits",
                   std::bit_width(parameters.exact_data_primes.front()));
    record.text("parameters.modulus_switch_policy",
                "one-after-each-ctct-multiplication-layer");
    record.text("parameters.security",
                std::string(no_integrity_security_description(selected)));
    record.text("parameters.galois_keys", parameters.generate_galois_keys
                    ? "generated" : "omitted-no-rotation-gates");
    record.text("parameters.integrity", "none");
}

void emit_geometry(const Record &record, const Profile &selected,
                   const PayloadCircuit &payload,
                   const LayeredCircuit &circuit,
                   const SealParameters &parameters,
                   std::size_t fresh_modulus_product_bits,
                   std::size_t key_modulus_product_bits) {
    emit_geometry_fields(record, selected, payload.gates.size(),
                         circuit.layers.size(), parameters,
                         fresh_modulus_product_bits,
                         key_modulus_product_bits);
}

void emit_geometry(const Record &record, const Profile &selected,
                   const SetupRecord &setup,
                   const SealParameters &parameters) {
    emit_geometry_fields(record, selected, setup.payload_operations,
                         setup.compiled_layers, parameters,
                         setup.fresh_modulus_product_bits,
                         setup.key_modulus_product_bits);
}

std::vector<SealBackend::Ciphertext> encrypt_inputs(
    const SealBackend::ClientContext &context,
    std::span<const SlotVector> inputs) {
    require(SealBackend::slot_count(context) == kSlots &&
                inputs.size() == kInputs,
            "noIntegrity input geometry is invalid");
    std::vector<SealBackend::Ciphertext> result;
    result.reserve(inputs.size());
    for (const SlotVector &input : inputs) {
        require(input.size() == kSlots,
                "noIntegrity Wide input has the wrong slot count");
        result.push_back(SealBackend::encrypt(context, input));
    }
    return result;
}

std::uint64_t ciphertext_bytes_upper(std::size_t limbs) {
    return checked_add(
        checked_multiply(
            checked_multiply(2U, kSlots, "ciphertext coefficients"),
            checked_multiply(limbs, sizeof(std::uint64_t),
                             "ciphertext limb bytes"),
            "ciphertext coefficient bytes"),
        std::uint64_t{1} << 16U, "ciphertext encoding bound");
}

std::uint64_t request_bytes_upper(std::size_t limbs) {
    return checked_add(
        4096U,
        checked_multiply(kInputs,
                         checked_add(ciphertext_bytes_upper(limbs), 8U,
                                     "request record bound"),
                         "request ciphertext bound"),
        "request byte bound");
}

std::uint64_t response_bytes_upper() {
    return checked_add(4096U, ciphertext_bytes_upper(1),
                       "response byte bound");
}

PayloadCheckpointReplayProblem make_problem(
    const CertifiedCanonicalTraceLayout &trace_layout,
    const FheEvaluationPlan &evaluation,
    std::size_t fresh_limbs) {
    const LayeredCircuit &circuit = trace_layout.circuit();
    const std::vector<std::uint64_t> work =
        payload_replay_work_units(trace_layout);
    std::vector<PayloadLayerResourceEstimate> resources;
    resources.reserve(circuit.layers.size());
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        const std::size_t limbs =
            evaluation.trace.required_mult_depth_by_layer.at(layer) + 1U;
        require(limbs <= fresh_limbs,
                "payload level exceeds noIntegrity modulus chain");
        const std::uint64_t serialized = ciphertext_bytes_upper(limbs);
        const std::uint64_t resident = checked_add(
            serialized, std::uint64_t{1} << 17U,
            "resident ciphertext bound");
        resources.push_back(PayloadLayerResourceEstimate{
            .rns_limb_count = limbs,
            .checkpoint_bytes = standalone_checkpoint_layer_artifact_bytes(
                trace_layout.layout().storage.at(layer).stored_wire_count,
                serialized),
            .serialized_ciphertext_bytes = serialized,
            .resident_ciphertext_bytes = resident,
            .replay_work_units = work.at(layer),
            .prefer_post_modulus_switch_checkpoint =
                evaluation.modulus_switches_after_layer.at(layer) != 0,
            .proof_ingress_serialized_ciphertext_bytes = serialized,
            .proof_ingress_resident_ciphertext_bytes = resident,
        });
    }
    PayloadCheckpointReplayProblem result =
        make_payload_checkpoint_replay_problem(
            trace_layout, evaluation, resources, 159, 8);
    validate_executable_checkpoint_artifact_accounting(result);
    return result;
}

struct StaticExecution {
    PayloadCircuit payload;
    LayeredCircuit circuit;
    SealParameters parameters;
    CertifiedPayloadCheckpointReplayStatic certified;
};

Digest configuration_id(
    const PayloadCircuit &payload, const LayeredCircuit &circuit,
    const SealParameters &parameters,
    const PayloadCheckpointReplayBudgets &budgets,
    const PayloadCheckpointReplayPlan &plan) {
    Writer writer;
    writer.text("LaminateImpl/NoIntegrityConfiguration/v3");
    writer.digest(combined_digest(payload, circuit));
    writer.u64(parameters.fresh_rns_limbs);
    for (std::uint64_t prime : parameters.exact_data_primes) {
        writer.u64(prime);
    }
    writer.u64(parameters.exact_special_prime);
    writer.u64(budgets.max_live_scratch_bytes);
    writer.u64(budgets.max_resident_ciphertext_bytes);
    writer.u64(budgets.max_ciphertexts_per_chunk);
    writer.u64(budgets.reserved_live_scratch_bytes);
    writer.u64(budgets.reserved_resident_bytes);
    writer.u64(static_cast<std::uint8_t>(budgets.selection_objective));
    writer.u64(plan.selected.chunk_ciphertexts);
    writer.u64(
        plan.selected
            .dense_multiplication_alias_cache_peak_resident_bytes);
    writer.u64(plan.selected.peak_resident_bytes);
    return sha256(std::move(writer).finish());
}

StaticExecution make_static_execution(const Profile &selected,
                                      const SetupRecord &setup) {
    PayloadCircuit payload = make_payload_circuit(workload_spec(selected));
    LayeredCircuit circuit = compile(payload);
    SealParameters parameters = seal_parameters(selected);
    const PayloadStats stats = analyze(payload);
    require(payload.input_count == kInputs &&
                payload.outputs.size() == kOutputs &&
                payload.gates.size() == selected.operation_count &&
                stats.add_gates == selected.add_gates &&
                stats.add_plain_gates == selected.add_plain_gates &&
                stats.mul_gates == selected.mul_gates &&
                stats.ct_ct_multiplicative_depth == selected.depth,
            "noIntegrity payload geometry drifted");
    const FheEvaluationPlan evaluation =
        FheEvaluationPlan::at_evaluation_levels(
            circuit, parameters.fresh_rns_limbs - 1U);
    const std::size_t switches = static_cast<std::size_t>(std::count_if(
        evaluation.modulus_switches_after_layer.begin(),
        evaluation.modulus_switches_after_layer.end(),
        [](std::size_t count) { return count == 1U; }));
    require(switches == selected.depth &&
                evaluation.trace.required_mult_depth_by_layer.front() == 0,
            "noIntegrity modulus-switch schedule is not minimal");

    const CertifiedCanonicalTraceLayout trace_layout =
        derive_certified_canonical_trace_layout(circuit);
    PayloadCheckpointReplayProblem problem = make_problem(
        trace_layout, evaluation, parameters.fresh_rns_limbs);
    PayloadCheckpointReplayBudgets budgets{
        .max_live_scratch_bytes = setup.host_budget.max_live_disk_bytes,
        .max_resident_ciphertext_bytes = setup.server_resident_cap_bytes,
        .max_ciphertexts_per_chunk = kChunkCiphertexts,
        .max_recomputation_factor = {100, 1},
        .reserved_live_scratch_bytes =
            setup.persistent_disk_reserve_bytes,
        .reserved_resident_bytes = checked_add(
            kServerResidentReserveBytes,
            kPayloadStorageTransferResidentBytes,
            "server and payload storage-transfer reserve"),
        .selection_objective =
            PayloadCheckpointSelectionObjective::
                OutputOnlyAdjacentLayers,
    };
    PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(problem, budgets);
    require(plan.selected.feasible(),
            "noIntegrity file-backed payload plan is infeasible");
    require(plan.selected.replay_work_units == 0 &&
                plan.selected.checkpoint_layers.empty() &&
                plan.reverse_gkr_segments.empty(),
            "noIntegrity output-only plan contains proof replay state");
    const Digest configured = configuration_id(
        payload, circuit, parameters, budgets, plan);
    if (setup.configuration_id != Digest{} &&
        setup.configuration_id != configured) {
        throw std::runtime_error(
            "reconstructed noIntegrity plan differs from setup.bin");
    }
    CertifiedPayloadCheckpointReplayStatic certified =
        certify_payload_checkpoint_replay_static(
            payload, trace_layout, evaluation, problem, budgets, plan);
    return StaticExecution{std::move(payload), std::move(circuit),
                           std::move(parameters), std::move(certified)};
}

void require_benchmark_build() {
    if (std::string_view(LAMINATE_NO_INTEGRITY_GIT_DIRTY) != "false" ||
        std::string_view(LAMINATE_BUILD_TYPE) != "Release" ||
        std::string_view(LAMINATE_SEAL_ACCELERATION) !=
            "intel-hexl-runtime-dispatch") {
        throw std::runtime_error(
            "GCP noIntegrity setup requires a clean Release build with "
            "Intel HEXL runtime dispatch");
    }
    const SystemInfo::CpuFeatures features = cpu_features();
    if (!features.avx2_available || !features.avx512f_available ||
        !features.avx512dq_available ||
        !features.avx512ifma_available) {
        throw std::runtime_error(
            "GCP noIntegrity setup requires AVX2, AVX-512F, AVX-512DQ, "
            "and AVX-512IFMA");
    }
}

SetupRecord load_setup(const Command &command) {
    const SetupRecord result = decode_setup(read_bounded_file(
        command.run_directory / "shared" / "setup.bin",
        kMaximumSetupBytes));
    const Profile selected = profile(command.profile);
    const SealParameters parameters = seal_parameters(selected);
    if (result.variant != command.variant ||
        result.profile != command.profile || result.depth != selected.depth ||
        result.width != selected.width ||
        result.payload_operations != selected.operation_count ||
        result.compiled_layers == 0 ||
        result.fresh_rns_limbs != parameters.fresh_rns_limbs ||
        result.fresh_modulus_product_bits !=
            no_integrity_data_modulus_bits(parameters) ||
        result.key_modulus_product_bits !=
            no_integrity_key_modulus_bits(parameters)) {
        throw std::runtime_error(
            "command geometry differs from immutable noIntegrity setup");
    }
    if (result.git_commit != LAMINATE_NO_INTEGRITY_GIT_COMMIT ||
        result.build_type != LAMINATE_BUILD_TYPE ||
        result.seal_acceleration != LAMINATE_SEAL_ACCELERATION ||
        std::string_view(LAMINATE_NO_INTEGRITY_GIT_DIRTY) != "false") {
        throw std::runtime_error(
            "noIntegrity executable differs from immutable setup");
    }
    if (derive_host_resource_budget(
            result.host_budget.observed_available_disk_bytes,
            result.host_budget.observed_physical_ram_bytes) !=
        result.host_budget) {
        throw std::runtime_error("setup contains a noncanonical host budget");
    }
    return result;
}

void require_setup_pass(const Command &command) {
    if (!result_contains(command.run_directory / "shared" /
                             "setup-result.txt",
                         "setup.result=PASS") ||
        !result_contains(command.run_directory / "shared" /
                             "setup-process-exit.txt",
                         "process.exit_status=0")) {
        throw std::runtime_error(
            "noIntegrity online role requires completed setup PASS");
    }
}

std::vector<std::uint8_t> load_preprocessing(
    const std::filesystem::path &path, std::uint64_t expected_bytes,
    const Digest &expected_digest) {
    std::vector<std::uint8_t> result =
        read_bounded_file(path, expected_bytes);
    if (result.size() != expected_bytes || sha256(result) != expected_digest) {
        throw std::runtime_error(
            "role preprocessing differs from immutable setup");
    }
    return result;
}

struct Request {
    Digest run_id{};
    Digest circuit_id{};
    Digest storage_context_id{};
    Digest session_id{};
    std::vector<SealBackend::Ciphertext> inputs;
};

std::vector<std::uint8_t> encode_request(
    const SealBackend::ClientContext &context, const Request &request) {
    Writer writer;
    writer.text(kRequestDomain);
    writer.u64(1);
    writer.digest(request.run_id);
    writer.digest(request.circuit_id);
    writer.digest(request.storage_context_id);
    writer.digest(request.session_id);
    writer.u64(request.inputs.size());
    for (const auto &ciphertext : request.inputs) {
        writer.bytes(SealBackend::serialize_for_storage(context, ciphertext));
    }
    return std::move(writer).finish();
}

Request decode_request(const SealBackend::EvalContext &context,
                       std::span<const std::uint8_t> bytes,
                       std::uint64_t ciphertext_limit) {
    Reader reader(bytes);
    if (reader.text(128, "request domain") != kRequestDomain ||
        reader.u64("request version") != 1U) {
        throw std::invalid_argument("unsupported noIntegrity request");
    }
    Request result;
    result.run_id = reader.digest("request run id");
    result.circuit_id = reader.digest("request circuit id");
    result.storage_context_id = reader.digest("request context id");
    result.session_id = reader.digest("request session id");
    const std::size_t count = checked_size(
        reader.u64("request input count"), "request input count");
    if (count != kInputs) {
        throw std::invalid_argument("noIntegrity request input count changed");
    }
    result.inputs.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        result.inputs.push_back(SealBackend::deserialize_from_storage(
            context,
            reader.bytes(checked_size(ciphertext_limit, "ciphertext limit"),
                         "request ciphertext")));
    }
    reader.finish("request trailing bytes");
    return result;
}

struct Response {
    Digest run_id{};
    Digest circuit_id{};
    Digest storage_context_id{};
    Digest session_id{};
    SealBackend::Ciphertext output;
};

template <typename Context>
std::vector<std::uint8_t> encode_response(const Context &context,
                                          const Response &response) {
    Writer writer;
    writer.text(kResponseDomain);
    writer.u64(1);
    writer.digest(response.run_id);
    writer.digest(response.circuit_id);
    writer.digest(response.storage_context_id);
    writer.digest(response.session_id);
    writer.u64(1);
    writer.bytes(SealBackend::serialize_for_storage(context, response.output));
    return std::move(writer).finish();
}

Response decode_response(const SealBackend::ClientContext &context,
                         std::span<const std::uint8_t> bytes,
                         std::uint64_t ciphertext_limit) {
    Reader reader(bytes);
    if (reader.text(128, "response domain") != kResponseDomain ||
        reader.u64("response version") != 1U) {
        throw std::invalid_argument("unsupported noIntegrity response");
    }
    Response result;
    result.run_id = reader.digest("response run id");
    result.circuit_id = reader.digest("response circuit id");
    result.storage_context_id = reader.digest("response context id");
    result.session_id = reader.digest("response session id");
    if (reader.u64("response output count") != 1U) {
        throw std::invalid_argument("noIntegrity response must have one output");
    }
    result.output = SealBackend::deserialize_from_storage(
        context,
        reader.bytes(checked_size(ciphertext_limit, "ciphertext limit"),
                     "response ciphertext"));
    reader.finish("response trailing bytes");
    return result;
}

Digest slot_digest(const SlotVector &slots) {
    Writer writer;
    writer.text("LaminateImpl/NoIntegrityDecryptedOutput/v1");
    writer.u64(slots.size());
    for (const Fp &value : slots) {
        writer.u64(value.value());
    }
    return sha256(std::move(writer).finish());
}

Timing add_timings(std::initializer_list<Timing> timings) {
    Timing result;
    for (const Timing &timing : timings) {
        result.wall_ms += timing.wall_ms;
        result.cpu_ms += timing.cpu_ms;
    }
    return result;
}

void emit_operation_counts(const Record &record,
                           const SealBackend::OperationCounts &counts) {
    for (std::size_t index = 0;
         index < static_cast<std::size_t>(SealBackend::OperationKind::Count);
         ++index) {
        const auto kind = static_cast<SealBackend::OperationKind>(index);
        const std::string operation = SealBackend::operation_name(kind);
        record.integer("operations.server_payload_evaluation." + operation +
                           ".calls",
                       counts.calls(kind));
        record.integer("operations.server_payload_evaluation." + operation +
                           ".limb_operations",
                       counts.limb_operations(kind));
    }
}

int run_build_info() {
    for (std::string_view name :
         {"quick", "target-balancedLaned", "target-mulHeavyPyramid"}) {
        const Profile selected = profile(name);
        const SealParameters parameters = seal_parameters(selected);
        const bool pyramid = selected.tier == BenchmarkPayloadTier::TargetMulHeavy;
        const auto expected_security = pyramid ? seal::sec_level_type::none
                                              : seal::sec_level_type::tc128;
        const std::size_t key_bit_limit = pyramid ? 555U
            : static_cast<std::size_t>(seal::CoeffModulus::MaxBitCount(
                  parameters.poly_modulus_degree, expected_security));
        if (parameters.fresh_rns_limbs != selected.depth + 1U ||
            parameters.exact_data_primes.size() != parameters.fresh_rns_limbs ||
            parameters.exact_data_primes.front() == kOuterFieldOrder ||
            parameters.exact_data_primes.front() % kBaseFieldOrder != 1U ||
            parameters.security_level != expected_security ||
            no_integrity_key_modulus_bits(parameters) > key_bit_limit ||
            parameters.max_key_modulus_bits !=
                (selected.is_target() ? key_bit_limit : 0U) ||
            parameters.generate_galois_keys != (selected.rotate_gates != 0)) {
            throw std::logic_error("noIntegrity profile self-check failed");
        }
    }
    std::cout
        << "format=laminate-no-integrity-build-info-v1\n"
        << "environment.git_commit=" << LAMINATE_NO_INTEGRITY_GIT_COMMIT
        << '\n'
        << "environment.git_dirty=" << LAMINATE_NO_INTEGRITY_GIT_DIRTY
        << '\n'
        << "environment.build_type=" << LAMINATE_BUILD_TYPE << '\n'
        << "environment.seal_acceleration=" << LAMINATE_SEAL_ACCELERATION
        << '\n'
        << "environment.sha256_acceleration="
        << LAMINATE_SHA256_ACCELERATION << '\n'
        << "benchmark.variant=noIntegrity\n"
        << "protocol.integrity=none\n"
        << "protocol.exchange=one-request-one-response\n"
        << "fhe.switch_policy=one-after-each-ctct-multiplication-layer\n"
        << "fhe.target_data_limbs=9\n";
    return 0;
}

int run_setup(const Command &command, int argc, char **argv) {
    Stopwatch process_stopwatch;
    const std::int64_t started = unix_milliseconds();
    require_benchmark_build();
    create_run_tree(command.run_directory);
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    RoleActivity activity(command.run_directory / "shared" /
                              "setup-activity.jsonl",
                          "setup");
    const Profile selected = profile(command.profile);
    const Digest run_id = random_digest();
    publish_private_text(
        command.run_directory / "shared" / "run-binding.txt",
        "format=laminate-benchmark-run-v1\nrun.variant=noIntegrity\n"
        "run.profile=" + command.profile + "\nrun.id=" +
            digest_hex(run_id) + "\n");

    activity.transition("constructing_payload");
    PayloadCircuit payload = make_payload_circuit(workload_spec(selected));
    LayeredCircuit circuit = compile(payload);
    const SealParameters parameters = seal_parameters(selected);

    activity.transition("generating_fhe_preprocessing");
    auto contexts_timed = timed([&] { return SealBackend::create(parameters); });
    SealBackend::Contexts contexts = std::move(contexts_timed.first);
    std::vector<std::uint64_t> actual_moduli =
        SealBackend::coefficient_moduli(contexts.eval);
    require(actual_moduli.size() == parameters.exact_data_primes.size() + 1U &&
                actual_moduli.back() == parameters.exact_special_prime,
            "SEAL key modulus differs from the noIntegrity profile");
    actual_moduli.pop_back();
    require(actual_moduli == parameters.exact_data_primes,
            "SEAL data moduli differ from the noIntegrity profile");
    require(SealBackend::storage_context_id(contexts.eval) ==
                SealBackend::storage_context_id(contexts.client),
            "generated role contexts do not match");
    activity.transition("serializing_fhe_preprocessing");
    auto serialized_timed = timed([&] {
        return std::pair{
            SealBackend::serialize_evaluation_context_bundle(contexts.eval),
            SealBackend::serialize_client_context_bundle(contexts.client)};
    });
    std::vector<std::uint8_t> server_bytes =
        std::move(serialized_timed.first.first);
    std::vector<std::uint8_t> client_bytes =
        std::move(serialized_timed.first.second);

    activity.transition("deriving_host_capacity");
    std::error_code error;
    const auto space = std::filesystem::space(command.run_directory, error);
    require(!error, "failed to inspect benchmark filesystem");
    const SystemInfo system = system_info();
    require(system.ram_bytes != 0, "failed to inspect physical RAM");
    const HostResourceBudget host = derive_host_resource_budget(
        static_cast<std::uint64_t>(space.available), system.ram_bytes);
    const std::uint64_t request_limit =
        request_bytes_upper(parameters.fresh_rns_limbs);
    const std::uint64_t response_limit = response_bytes_upper();
    const std::uint64_t client_peak = checked_add(
        kClientResidentMarginBytes,
        checked_add(client_bytes.size(),
                    checked_multiply(2U, request_limit,
                                     "client request residency"),
                    "client preprocessing and request residency"),
        "client resident peak");
    const std::uint64_t server_cap =
        reserve_concurrent_client_ram(host, client_peak);
    require(server_cap > kServerResidentReserveBytes,
            "host cannot cover noIntegrity server resident reserve");
    const std::uint64_t persistent_disk = checked_add(
        kPersistentDiskMarginBytes,
        checked_add(
            checked_add(server_bytes.size(), client_bytes.size(),
                        "role preprocessing bytes"),
            checked_add(request_limit, response_limit,
                        "wire artifact bounds"),
            "persistent run bytes"),
        "persistent disk reserve");
    require(persistent_disk < host.max_live_disk_bytes,
            "host cannot cover persistent noIntegrity artifacts");

    SetupRecord setup{
        .variant = command.variant,
        .profile = command.profile,
        .git_commit = LAMINATE_NO_INTEGRITY_GIT_COMMIT,
        .build_type = LAMINATE_BUILD_TYPE,
        .seal_acceleration = LAMINATE_SEAL_ACCELERATION,
        .run_id = run_id,
        .circuit_id = combined_digest(payload, circuit),
        .storage_context_id = SealBackend::storage_context_id(contexts.eval),
        .depth = selected.depth,
        .width = selected.width,
        .payload_operations = payload.gates.size(),
        .compiled_layers = circuit.layers.size(),
        .fresh_rns_limbs = parameters.fresh_rns_limbs,
        .fresh_modulus_product_bits =
            SealBackend::fresh_ciphertext_modulus_bits(contexts.eval),
        .key_modulus_product_bits =
            SealBackend::key_modulus_bits(contexts.eval),
        .server_bytes = server_bytes.size(),
        .server_digest = sha256(server_bytes),
        .client_bytes = client_bytes.size(),
        .client_digest = sha256(client_bytes),
        .request_limit = request_limit,
        .response_limit = response_limit,
        .host_budget = host,
        .client_peak_resident_bytes = client_peak,
        .server_resident_cap_bytes = server_cap,
        .persistent_disk_reserve_bytes = persistent_disk,
    };
    activity.transition("certifying_output_only_plan");
    StaticExecution execution = make_static_execution(selected, setup);
    setup.configuration_id = configuration_id(
        execution.payload, execution.circuit, execution.parameters,
        execution.certified.budgets(), execution.certified.plan());
    require(execution.certified.plan().selected.chunk_ciphertexts <=
                kChunkCiphertexts,
            "noIntegrity planner exceeded its fixed chunk cap");
    std::cout << "SETUP: payload replay work = "
              << execution.certified.plan().selected.replay_work_units
              << "; remaining admitted disk headroom = "
              << execution.certified.budgets().max_live_scratch_bytes -
                     execution.certified.plan()
                         .selected.peak_live_scratch_bytes
              << " bytes" << std::endl;

    activity.transition("publishing_preprocessing");
    publish_private_file(command.run_directory / "server" /
                             "preprocessing" / "server.bin",
                         server_bytes);
    publish_private_file(command.run_directory / "client" /
                             "preprocessing" / "client.bin",
                         client_bytes);
    const std::vector<std::uint8_t> setup_bytes = encode_setup(setup);
    publish_private_file(command.run_directory / "shared" / "setup.bin",
                         setup_bytes);

    const Timing process_timing = process_stopwatch.stop();
    CompletedResultReport report(command.run_directory / "shared" /
                                 "setup-result.txt");
    const Record record(report.mirror());
    record.text("format", "laminate-benchmark-setup-v1");
    emit_identity(record, command, setup);
    emit_geometry(record, selected, payload, circuit, parameters,
                  setup.fresh_modulus_product_bits,
                  setup.key_modulus_product_bits);
    record.text("benchmark.intent",
                "fhe-payload-evaluation-without-integrity");
    record.text("integrity.result", "NOT_PROVIDED");
    record.integer("timing.setup.started_unix_ms", started);
    emit_timing(record, "setup.key_generation",
                contexts_timed.second);
    emit_timing(record, "setup.context_serialization",
                serialized_timed.second);
    emit_timing(record, "setup.process_total", process_timing);
    record.integer("storage.server_preprocessing_bytes", server_bytes.size());
    record.integer("storage.client_preprocessing_bytes", client_bytes.size());
    record.integer("storage.request_bytes_upper", request_limit);
    record.integer("storage.response_bytes_upper", response_limit);
    record.integer("storage.persistent_disk_reserve_bytes", persistent_disk);
    record.integer("storage.host_observed_available_bytes",
                   host.observed_available_disk_bytes);
    record.integer("storage.host_free_reserve_bytes",
                   kBenchmarkFreeDiskReserveBytes);
    record.integer("memory.client.admitted_peak_resident_bytes", client_peak);
    record.integer("memory.server.admitted_peak_resident_bytes", server_cap);
    record.integer("memory.host_safety_reserve_bytes",
                   kBenchmarkHostRamSafetyReserveBytes);
    record.integer("memory.host_operating_system_reserve_bytes",
                   kBenchmarkOperatingSystemRamReserveBytes);
    record.integer("memory.host_page_cache_reserve_bytes",
                   kBenchmarkPageCacheRamReserveBytes);
    record.integer("memory.payload_storage.transfer_buffer_count", 3);
    record.integer("memory.payload_storage.transfer_buffer_bytes_each",
                   kFileTraceStoreTransferBufferBytes);
    record.integer("memory.payload_storage.transfer_buffer_reserve_bytes",
                   kPayloadStorageTransferResidentBytes);
    record.integer("memory.payload_storage.writeback_window_bytes", 0);
    record.text("storage.payload_storage.ephemeral_writeback_policy",
                "linux-submit-only-with-buffered-portable-fallback");
    record.integer(
        "storage.payload_storage.maximum_writeback_submission_bytes",
        kFileTraceStoreWritebackSubmissionBytes);
    record.integer("memory.payload_storage.sequential_reader_count", 2);
    record.integer("memory.payload_storage.prefetch_window_bytes_each",
                   kFileTraceStorePrefetchWindowBytes);
    record.integer("memory.payload_storage.prefetch_page_cache_budget_bytes",
                   2U * kFileTraceStorePrefetchWindowBytes);
    record.integer("storage.payload_storage.maximum_prefetch_request_bytes",
                   kFileTraceStorePrefetchRequestBytes);
    record.integer("planner.output_only_chunk_ciphertexts",
                   execution.certified.plan().selected.chunk_ciphertexts);
    record.text("planner.execution_mode",
                "output-only-adjacent-layers");
    record.integer("planner.payload_replay_work_units",
                   execution.certified.plan().selected.replay_work_units);
    record.integer("planner.payload_checkpoint_count",
                   execution.certified.plan()
                       .selected.checkpoint_layers.size());
    record.integer("planner.payload_checkpoint_bytes",
                   execution.certified.plan().selected.checkpoint_bytes);
    record.integer(
        "storage.payload_output_only_plan.peak_live_scratch_bytes",
        execution.certified.plan().selected.peak_live_scratch_bytes);
    record.integer(
        "memory.payload_output_only_plan.peak_resident_bytes",
        execution.certified.plan().selected.peak_resident_bytes);
    record.integer(
        "memory.payload_output_only_plan.dense_multiplication_alias_cache_peak_resident_bytes",
        execution.certified.plan()
            .selected
            .dense_multiplication_alias_cache_peak_resident_bytes);
    record.integer(
        "storage.payload_output_only_plan.remaining_headroom_bytes",
        execution.certified.budgets().max_live_scratch_bytes -
            execution.certified.plan().selected.peak_live_scratch_bytes);
    record.text("environment.command", exact_command(argc, argv));
    record.text("setup.result", "PASS");
    report.publish();
    activity.mark_complete();
    std::cout << "\nSETUP PASS\nStart the client, then the server.\n";
    return 0;
}

int run_client(const Command &command, int argc, char **argv) {
    Stopwatch process_stopwatch;
    const std::int64_t started = unix_milliseconds();
    require_setup_pass(command);
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    RoleActivity activity(command.run_directory / "client" /
                              "activity.jsonl",
                          "client");
    const SetupRecord setup = load_setup(command);
    const Profile selected = profile(command.profile);
    activity.transition("loading_preprocessing");
    auto loaded = timed([&] {
        return SealBackend::deserialize_client_context_bundle(
            load_preprocessing(
                command.run_directory / "client" / "preprocessing" /
                    "client.bin",
                setup.client_bytes, setup.client_digest));
    });
    SealBackend::ClientContext context = std::move(loaded.first);
    require(context.parameters == seal_parameters(selected) &&
                SealBackend::storage_context_id(context) ==
                    setup.storage_context_id,
            "client FHE context differs from setup");

    activity.transition("constructing_deterministic_inputs");
    std::vector<SlotVector> inputs =
        make_workload_inputs(workload_spec(selected));
    activity.transition("encrypting_inputs");
    auto encrypted = timed([&] {
        return encrypt_inputs(context, inputs);
    });
    const Digest session_id = random_digest();
    Request request{setup.run_id, setup.circuit_id,
                    setup.storage_context_id, session_id,
                    std::move(encrypted.first)};
    activity.transition("encoding_request");
    auto encoded = timed([&] { return encode_request(context, request); });
    require(encoded.first.size() <= setup.request_limit,
            "encoded request exceeds setup bound");
    const std::size_t request_size = encoded.first.size();
    activity.transition("publishing_request");
    const Timing publish_timing = timed_void([&] {
        publish_private_file(command.run_directory / "shared" /
                                 "transcript" / "cli-to-srv-request.bin",
                             encoded.first);
    });
    request.inputs.clear();
    std::vector<std::uint8_t>().swap(encoded.first);
    const std::int64_t request_published = unix_milliseconds();

    activity.transition("waiting_for_server_response");
    const std::filesystem::path response_path =
        command.run_directory / "shared" / "transcript" /
        "srv-to-cli-response.bin";
    const Timing wait_timing = wait_for_artifact(
        response_path,
        command.run_directory / "server" / "failure.txt",
        command.run_directory / "server" / "activity.jsonl",
        "server response", activity);
    activity.transition("reading_response");
    auto response_bytes = timed([&] {
        return read_bounded_file(response_path, setup.response_limit);
    });
    const std::size_t response_size = response_bytes.first.size();
    activity.transition("decoding_response");
    auto decoded = timed([&] {
        return decode_response(context, response_bytes.first,
                               ciphertext_bytes_upper(1));
    });
    Response response = std::move(decoded.first);
    if (response.run_id != setup.run_id ||
        response.circuit_id != setup.circuit_id ||
        response.storage_context_id != setup.storage_context_id ||
        response.session_id != session_id ||
        SealBackend::rns_limb_count(
            SealBackend::make_public_verifier_context(context),
            response.output) != 1U) {
        throw std::runtime_error(
            "noIntegrity response binding or output level is invalid");
    }

    activity.transition("fully_decrypting_output");
    auto decrypted = timed([&] { return SealBackend::decrypt(context,
                                                              response.output); });
    require(decrypted.first.size() == kSlots,
            "decrypted noIntegrity output has the wrong slot count");
    const int noise_budget =
        SealBackend::invariant_noise_budget(context, response.output);
    require_no_integrity_output_noise_budget(noise_budget);
    const Digest output_digest = slot_digest(decrypted.first);

    const Timing online = add_timings(
        {loaded.second, encrypted.second, encoded.second, publish_timing,
         response_bytes.second, decoded.second, decrypted.second});
    const Timing process_timing = process_stopwatch.stop();
    const SystemInfo system = system_info();
    require(system.peak_rss_bytes <= setup.client_peak_resident_bytes,
            "client peak RSS exceeds setup-bound reserve");
    CompletedResultReport report(command.run_directory / "client" /
                                 "result.txt");
    const Record record(report.mirror());
    record.text("format", "laminate-benchmark-client-v2");
    emit_identity(record, command, setup);
    emit_geometry(record, selected, setup, seal_parameters(selected));
    record.integer("timing.client.started_unix_ms", started);
    record.integer("timing.client.request_published_unix_ms",
                   request_published);
    emit_timing(record, "client.load_preprocessing", loaded.second);
    emit_timing(record, "client.encrypt_inputs", encrypted.second);
    emit_timing(record, "client.encode_request", encoded.second);
    emit_timing(record, "client.publish_request", publish_timing);
    emit_timing(record, "client.wait_for_response", wait_timing);
    emit_timing(record, "client.read_response",
                response_bytes.second);
    emit_timing(record, "client.decode_response", decoded.second);
    emit_timing(record, "client.full_decrypt_output",
                decrypted.second);
    emit_timing(record, "client.per_request_total", online);
    emit_timing(record, "client.process_total", process_timing);
    record.integer("wire.request_bytes", request_size);
    record.integer("wire.response_bytes", response_size);
    record.integer("output.rns_limbs", 1);
    record.integer("output.invariant_noise_budget_bits", noise_budget);
    record.text("output.decrypted_slots_digest", digest_hex(output_digest));
    record.integer("memory.client.peak_rss_bytes", system.peak_rss_bytes);
    record.text("integrity.result", "NOT_PROVIDED");
    record.text("verification.scope",
                "response-binding-decode-and-full-decryption-only");
    record.text("environment.command", exact_command(argc, argv));
    // The common GCP lifecycle keys completion off this field.  Its scope is
    // explicitly bounded above and must never be described as proof
    // verification or computational integrity.
    record.text("verification.result", "PASS");
    report.publish();
    activity.mark_complete();
    std::cout << "\nCLIENT DECRYPTION PASS\n"
              << "No computation-integrity claim is provided.\n";
    return 0;
}

int run_server(const Command &command, int argc, char **argv) {
    Stopwatch process_stopwatch;
    const std::int64_t started = unix_milliseconds();
    require_setup_pass(command);
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    RoleActivity activity(command.run_directory / "server" /
                              "activity.jsonl",
                          "server");
    const std::filesystem::path request_path =
        command.run_directory / "shared" / "transcript" /
        "cli-to-srv-request.bin";
    activity.transition("waiting_for_client_request");
    const Timing wait_timing = wait_for_artifact(
        request_path,
        command.run_directory / "client" / "failure.txt",
        command.run_directory / "client" / "activity.jsonl",
        "client request", activity);
    const std::int64_t request_observed = unix_milliseconds();
    const SetupRecord setup = load_setup(command);
    const Profile selected = profile(command.profile);

    activity.transition("restoring_execution_plan");
    auto restored = timed([&] {
        StaticExecution execution = make_static_execution(selected, setup);
        SealBackend::EvalContext context =
            SealBackend::deserialize_evaluation_context_bundle(
                load_preprocessing(
                    command.run_directory / "server" / "preprocessing" /
                        "server.bin",
                    setup.server_bytes, setup.server_digest));
        return std::pair{std::move(execution), std::move(context)};
    });
    StaticExecution execution = std::move(restored.first.first);
    SealBackend::EvalContext context = std::move(restored.first.second);
    require(context.parameters == execution.parameters &&
                SealBackend::storage_context_id(context) ==
                    setup.storage_context_id,
            "server FHE context differs from setup");
    activity.transition("reading_request");
    auto request_bytes = timed([&] {
        return read_bounded_file(request_path, setup.request_limit);
    });
    const std::size_t request_size = request_bytes.first.size();
    activity.transition("decoding_request");
    auto decoded = timed([&] {
        return decode_request(context, request_bytes.first,
                              ciphertext_bytes_upper(
                                  execution.parameters.fresh_rns_limbs));
    });
    Request request = std::move(decoded.first);
    if (request.run_id != setup.run_id ||
        request.circuit_id != setup.circuit_id ||
        request.storage_context_id != setup.storage_context_id ||
        request.session_id == Digest{}) {
        throw std::runtime_error("noIntegrity request binding is invalid");
    }
    for (const auto &input : request.inputs) {
        require(SealBackend::rns_limb_count(context, input) ==
                    execution.parameters.fresh_rns_limbs,
                "noIntegrity input is not at the fresh level");
    }

    PrivateWorkDirectory work(command.run_directory / "server" / "work");
    const std::filesystem::path payload_root = work.make_child("payload");
    ProtocolProgressJournal progress(command.run_directory / "server" /
                                     "progress.jsonl");
    activity.transition("payload_evaluation");
    progress.phase("server.payload_evaluation");
    SealBackend::reset_counts(context);
    SealBackend::set_counting(context, true);
    auto evaluated = timed([&] {
        std::vector<FheValue<SealBackend>> output;
        auto trace = PayloadCheckpointReplayTrace<
            SealBackend>::publish_output_only_certified(
            context, execution.certified, request.inputs,
            PayloadCheckpointReplayExecutionOptions{
                .directory = payload_root,
                .min_free_bytes = kBenchmarkFreeDiskReserveBytes,
                .max_checkpoint_metadata_bytes = 1,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
                .progress = progress.callback(),
            },
            output);
        return std::pair{std::move(output), std::move(trace)};
    });
    SealBackend::set_counting(context, false);
    const SealBackend::OperationCounts counts = SealBackend::counts(context);
    std::vector<FheValue<SealBackend>> output =
        std::move(evaluated.first.first);
    auto trace = std::move(evaluated.first.second);
    require(output.size() == 1U && output.front().is_encrypted() &&
                SealBackend::rns_limb_count(
                    context, output.front().ciphertext()) == 1U,
            "output-only evaluator did not return one bottom-level ciphertext");
    require(trace.is_output_only() &&
                trace.report().all_payload_artifacts_retired &&
                trace.report().live_physical_bytes == 0 &&
                !trace.report().checkpoint_set_published &&
                trace.report().replay_work_units == 0,
            "output-only evaluator retained proof or payload state");
    require(counts.calls(SealBackend::OperationKind::Encrypt) == 0,
            "server payload baseline performed encryption");
    require(selected.rotate_gates != 0 ||
                counts.calls(SealBackend::OperationKind::Rotate) == 0,
            "rotation-free payload baseline performed a rotation");
    const auto &payload_io = trace.report().forward;

    Response response{setup.run_id, setup.circuit_id,
                      setup.storage_context_id, request.session_id,
                      std::move(output.front().ciphertext())};
    request.inputs.clear();
    activity.transition("encoding_response");
    auto encoded = timed([&] { return encode_response(context, response); });
    require(encoded.first.size() <= setup.response_limit,
            "encoded response exceeds setup bound");
    const std::size_t response_size = encoded.first.size();
    activity.transition("publishing_response");
    const Timing publish_timing = timed_void([&] {
        publish_private_file(command.run_directory / "shared" /
                                 "transcript" / "srv-to-cli-response.bin",
                             encoded.first);
    });

    const Timing online = add_timings(
        {restored.second, request_bytes.second, decoded.second,
         evaluated.second, encoded.second, publish_timing});
    const Timing process_timing = process_stopwatch.stop();
    const SystemInfo system = system_info();
    require(system.peak_rss_bytes <= setup.server_resident_cap_bytes,
            "server peak RSS exceeds setup-bound cap");
    CompletedResultReport report(command.run_directory / "server" /
                                 "result.txt");
    const Record record(report.mirror());
    record.text("format", "laminate-benchmark-server-v1");
    emit_identity(record, command, setup);
    emit_geometry(record, selected, execution.payload, execution.circuit,
                  execution.parameters,
                  setup.fresh_modulus_product_bits,
                  setup.key_modulus_product_bits);
    record.integer("timing.server.started_unix_ms", started);
    record.integer("timing.server.request_observed_unix_ms",
                   request_observed);
    emit_timing(record, "server.load_preprocessing_and_plan",
                restored.second);
    emit_timing(record, "server.wait_for_request", wait_timing);
    emit_timing(record, "server.read_request", request_bytes.second);
    emit_timing(record, "server.decode_request", decoded.second);
    emit_timing(record, "server.payload_evaluation",
                evaluated.second);
    emit_timing(record, "server.encode_response", encoded.second);
    emit_timing(record, "server.publish_response", publish_timing);
    emit_timing(record, "server.online_total", online);
    emit_timing(record, "server.process_total", process_timing);
    emit_operation_counts(record, counts);
    record.integer("wire.request_bytes", request_size);
    record.integer("wire.response_bytes", response_size);
    record.integer("storage.payload_peak_live_physical_bytes",
                   trace.report().peak_live_physical_bytes);
    record.integer("storage.payload_total_reclaimed_physical_bytes",
                   trace.report().total_reclaimed_physical_bytes);
    const auto emit_payload_timing =
        [&](std::string_view phase,
            const FileTraceStoreOperationTiming &timing) {
            const std::string prefix =
                "timing.server.payload_evaluation." + std::string(phase);
            record.real(prefix + ".wall_ms", timing.wall_ms);
            record.real(prefix + ".cpu_ms", timing.cpu_ms);
        };
    emit_payload_timing("relation_total", payload_io.relation);
    emit_payload_timing("fhe", payload_io.fhe_evaluation);
    emit_payload_timing("modulus_switch",
                        payload_io.modulus_switching);
    emit_payload_timing("deserialization", payload_io.deserialization);
    emit_payload_timing("serialization",
                        payload_io.storage_writes.serialization);
    emit_payload_timing("buffer_assembly",
                        payload_io.storage_writes.buffer_assembly);
    emit_payload_timing("hashing", payload_io.storage_writes.hashing);
    emit_payload_timing("capacity_admission",
                        payload_io.storage_writes.capacity_admission);
    emit_payload_timing("output_submission",
                        payload_io.storage_writes.output_submission);
    emit_payload_timing("storage_write",
                        payload_io.storage_writes.storage_write);
    emit_payload_timing(
        "writeback_submission",
        payload_io.storage_writes.writeback_submission);
    emit_payload_timing("writeback_wait",
                        payload_io.storage_writes.writeback_wait);
    emit_payload_timing(
        "drain_close_publication",
        payload_io.storage_writes.drain_close_and_publication);
    emit_payload_timing("storage_read",
                        payload_io.storage_reads.storage_read);
    emit_payload_timing("prefetch", payload_io.storage_reads.prefetch);
    record.integer("storage.payload_forward_capacity_probes",
                   payload_io.storage_writes.capacity_probes);
    record.integer("storage.payload_forward_write_batches",
                   payload_io.storage_writes.write_batches);
    record.integer("storage.payload_forward_write_syscalls",
                   payload_io.storage_writes.write_syscalls);
    record.integer("storage.payload_forward_read_batches",
                   payload_io.storage_reads.read_batches);
    record.integer("storage.payload_forward_read_syscalls",
                   payload_io.storage_reads.read_syscalls);
    record.integer("storage.payload_forward_application_write_bytes",
                   payload_io.storage_writes.bytes_submitted);
    record.integer("storage.payload_forward_application_read_bytes",
                   payload_io.storage_reads.bytes_transferred);
    record.integer("storage.payload_forward_authenticated_records",
                   payload_io.storage_writes.authenticated_records);
    record.integer("storage.payload_forward_authenticated_record_bytes",
                   payload_io.storage_writes.authenticated_record_bytes);
    record.integer("storage.payload_forward_same_process_unhashed_records",
                   payload_io.storage_writes.same_process_unhashed_records);
    record.integer(
        "storage.payload_forward_same_process_unhashed_record_bytes",
        payload_io.storage_writes.same_process_unhashed_record_bytes);
    record.integer("storage.payload_forward_record_copy_bytes",
                   payload_io.storage_writes.record_copy_bytes);
    record.text("storage.payload_artifact_integrity",
                "same-process-inode-bound-nonreopenable");
    record.integer("storage.payload_forward_maximum_write_batch_bytes",
                   payload_io.storage_writes.maximum_batch_bytes);
    record.integer("storage.payload_forward_maximum_read_batch_bytes",
                   payload_io.storage_reads.maximum_batch_bytes);
    record.integer("storage.payload_forward_write_transfer_buffer_bytes",
                   payload_io.storage_writes.transfer_buffer_bytes);
    record.integer("storage.payload_forward_writeback_files_enabled",
                   payload_io.storage_writes.writeback_files_enabled);
    record.integer("storage.payload_forward_writeback_files_fallback",
                   payload_io.storage_writes.writeback_files_fallback);
    record.integer("storage.payload_forward_writeback_files_submit_only",
                   payload_io.storage_writes.writeback_files_submit_only);
    record.integer("storage.payload_forward_writeback_submission_attempts",
                   payload_io.storage_writes.writeback_submission_attempts);
    record.integer("storage.payload_forward_writeback_submission_successes",
                   payload_io.storage_writes.writeback_submission_successes);
    record.integer("storage.payload_forward_writeback_wait_attempts",
                   payload_io.storage_writes.writeback_wait_attempts);
    record.integer("storage.payload_forward_writeback_wait_successes",
                   payload_io.storage_writes.writeback_wait_successes);
    record.integer("storage.payload_forward_writeback_range_bytes_submitted",
                   payload_io.storage_writes.writeback_range_bytes_submitted);
    record.integer("storage.payload_forward_writeback_range_bytes_waited",
                   payload_io.storage_writes.writeback_range_bytes_waited);
    record.integer(
        "storage.payload_forward_maximum_writeback_submission_bytes",
        payload_io.storage_writes.maximum_writeback_submission_bytes);
    record.integer("storage.payload_forward_writeback_window_bytes",
                   payload_io.storage_writes.writeback_window_bytes);
    record.integer(
        "storage.payload_forward_maximum_unwaited_writeback_range_bytes",
        payload_io.storage_writes.maximum_unwaited_writeback_range_bytes);
    record.integer("storage.payload_forward_writeback_drains",
                   payload_io.storage_writes.writeback_drains);
    record.integer("storage.payload_forward_writeback_drain_range_bytes",
                   payload_io.storage_writes.writeback_drain_range_bytes);
    record.integer("storage.payload_forward_writeback_drains_skipped",
                   payload_io.storage_writes.writeback_drains_skipped);
    record.integer(
        "storage.payload_forward_writeback_range_bytes_without_explicit_wait",
        payload_io.storage_writes.writeback_range_bytes_without_explicit_wait);
    record.integer("storage.payload_forward_positional_write_calls",
                   payload_io.storage_writes.positional_write_calls);
    record.integer("storage.payload_forward_positional_write_bytes",
                   payload_io.storage_writes.positional_write_bytes);
    record.integer("storage.payload_forward_read_transfer_buffer_bytes",
                   payload_io.storage_reads.transfer_buffer_bytes);
    record.integer("storage.payload_forward_prefetch_requests",
                   payload_io.storage_reads.prefetch_requests);
    record.integer("storage.payload_forward_prefetch_bytes_requested",
                   payload_io.storage_reads.prefetch_bytes_requested);
    record.integer("storage.payload_forward_prefetch_fallbacks",
                   payload_io.storage_reads.prefetch_fallbacks);
    record.integer("storage.payload_forward_prefetch_seek_disables",
                   payload_io.storage_reads.prefetch_seek_disables);
    record.integer("storage.payload_forward_prefetch_window_bytes",
                   payload_io.storage_reads.prefetch_window_bytes);
    record.integer(
        "storage.payload_forward_maximum_prefetch_request_bytes",
        payload_io.storage_reads.maximum_prefetch_request_bytes);
    record.integer("storage.payload_forward_encoded_bytes_read",
                   trace.report().forward.encoded_ciphertext_bytes_read);
    record.integer("storage.payload_forward_encoded_bytes_written",
                   trace.report().forward.encoded_ciphertext_bytes_written);
    record.integer("storage.payload_forward_physical_bytes_written",
                   trace.report().forward.physical_bytes_written);
    record.integer("storage.payload_forward_physical_bytes_deleted",
                   trace.report().forward.physical_bytes_deleted);
    record.integer("storage.payload_forward_identity_affine_alias_relations",
                   payload_io.identity_affine_alias_relations);
    record.integer("storage.payload_forward_identity_affine_alias_fallbacks",
                   payload_io.identity_affine_alias_fallbacks);
    record.integer(
        "storage.payload_forward_identity_affine_alias_records_reused",
        payload_io.identity_affine_alias_records_reused);
    record.integer(
        "storage.payload_forward_identity_affine_alias_layer_bytes_reused",
        payload_io.identity_affine_alias_layer_bytes_reused);
    record.integer(
        "storage.payload_forward_identity_affine_alias_unique_bytes_written",
        payload_io.identity_affine_alias_unique_bytes_written);
    record.integer(
        "storage.payload_forward_alias_cached_dense_multiplication_relations",
        payload_io.alias_cached_dense_multiplication_relations);
    record.integer(
        "storage.payload_forward_alias_cache_range_readers",
        payload_io
            .alias_cached_dense_multiplication_range_readers_opened);
    record.integer(
        "storage.payload_forward_alias_cache_distinct_source_records",
        payload_io
            .alias_cached_dense_multiplication_distinct_source_records_read);
    record.integer(
        "storage.payload_forward_alias_cache_logical_source_uses",
        payload_io.alias_cached_dense_multiplication_logical_source_uses);
    record.integer(
        "storage.payload_forward_alias_cache_generic_source_records",
        payload_io
            .alias_cached_dense_multiplication_fallback_source_records);
    record.integer("memory.payload_peak_controlled_resident_bytes",
                   trace.report().peak_controlled_resident_bytes);
    record.integer("memory.server.peak_rss_bytes", system.peak_rss_bytes);
    record.text("integrity.result", "NOT_PROVIDED");
    record.text("environment.command", exact_command(argc, argv));
    progress.emit(record);
    record.text("server.result", "PASS");
    report.publish();
    progress.mark_complete_without_verdict();
    activity.mark_complete();
    std::cout << "\nSERVER RESPONSE PUBLISHED\n"
              << "The response contains only the evaluated output "
                 "ciphertext; no proof is present.\n";
    return 0;
}

std::optional<std::string> last_complete_line(
    const std::filesystem::path &path) {
    std::ifstream input(path);
    std::optional<std::string> result;
    for (std::string line; std::getline(input, line);) {
        if (input.eof()) {
            break;
        }
        if (!line.empty()) {
            result = std::move(line);
        }
    }
    return result;
}

std::optional<std::string_view> json_value(std::string_view line,
                                           std::string_view key) {
    const std::string marker = "\"" + std::string(key) + "\":";
    const std::size_t position = line.find(marker);
    if (position == std::string_view::npos) {
        return std::nullopt;
    }
    std::size_t begin = position + marker.size();
    if (begin >= line.size()) {
        return std::nullopt;
    }
    if (line[begin] == '"') {
        ++begin;
        const std::size_t end = line.find('"', begin);
        return end == std::string_view::npos
                   ? std::nullopt
                   : std::optional(line.substr(begin, end - begin));
    }
    const std::size_t end = line.find_first_of(",}", begin);
    return line.substr(begin, end - begin);
}

std::string role_label(const std::filesystem::path &result,
                       std::string_view pass_line,
                       const std::filesystem::path &exit,
                       const std::filesystem::path &failure) {
    if (result_contains(result, pass_line) &&
        result_contains(exit, "process.exit_status=0")) {
        return "PASS";
    }
    if (regular_file_exists(failure) ||
        (regular_file_exists(exit) &&
         !result_contains(exit, "process.exit_status=0"))) {
        return "FAILED";
    }
    if (result_contains(result, pass_line)) {
        return "finishing (awaiting process exit)";
    }
    return "not complete";
}

int run_status(const Command &command) {
    if (!std::filesystem::is_directory(command.run_directory)) {
        throw std::invalid_argument("status requires an existing run");
    }
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    const std::string setup = role_label(
        command.run_directory / "shared" / "setup-result.txt",
        "setup.result=PASS",
        command.run_directory / "shared" / "setup-process-exit.txt",
        command.run_directory / "shared" / "setup-failure.txt");
    const std::string server = role_label(
        command.run_directory / "server" / "result.txt",
        "server.result=PASS",
        command.run_directory / "server" / "process-exit.txt",
        command.run_directory / "server" / "failure.txt");
    const std::string client = role_label(
        command.run_directory / "client" / "result.txt",
        "verification.result=PASS",
        command.run_directory / "client" / "process-exit.txt",
        command.run_directory / "client" / "failure.txt");
    const bool request = regular_file_exists(
        command.run_directory / "shared" / "transcript" /
        "cli-to-srv-request.bin");
    const bool response = regular_file_exists(
        command.run_directory / "shared" / "transcript" /
        "srv-to-cli-response.bin");
    std::cout << "Laminate noIntegrity " << command.profile << " status\n"
              << "  integrity: NOT PROVIDED\n"
              << "  setup: " << setup << "\n"
              << "  client request: "
              << (request ? "published" : "not published") << "\n"
              << "  server: " << server << "\n"
              << "  server response: "
              << (response ? "published" : "not published") << "\n"
              << "  client decode and full decryption: " << client << '\n';
    const bool server_active = activity_is_active(
        command.run_directory / "server" / "activity.jsonl");
    const bool client_active = activity_is_active(
        command.run_directory / "client" / "activity.jsonl");
    std::cout << "  server process: "
              << (server_active ? "ACTIVE" : "not active") << "\n"
              << "  client process: "
              << (client_active ? "ACTIVE" : "not active") << '\n';
    if (const auto line = last_complete_line(
            command.run_directory / "server" / "progress.jsonl")) {
        const auto stage = json_value(*line, "stage");
        const auto event = json_value(*line, "event");
        const auto completed = json_value(*line, "completed_steps");
        const auto total = json_value(*line, "total_steps");
        std::cout << "  server telemetry: "
                  << (event && (*event == "begin" || *event == "progress")
                          ? "current "
                          : "last ")
                  << (stage ? std::string(*stage) : "unspecified");
        if (completed && total) {
            std::cout << "; output records " << *completed << " of "
                      << *total;
        }
        std::cout << '\n';
        print_payload_relation_snapshot(std::cout, *line, json_value);
    }
    const bool failed = setup == "FAILED" || server == "FAILED" ||
                        client == "FAILED";
    if (setup == "PASS" && server == "PASS" && client == "PASS") {
        std::cout << "\nCOMPLETE: output ciphertext was fully decrypted. "
                     "This run makes no integrity claim.\n";
        return 0;
    }
    if (failed) {
        std::cout << "\nFAILED: inspect the matching failure and exit "
                     "artifacts.\n";
        return 1;
    }
    const bool abandoned_server = regular_file_exists(
                                      command.run_directory / "server" /
                                      "activity.jsonl") &&
                                  !server_active && server == "not complete";
    const bool abandoned_client = regular_file_exists(
                                      command.run_directory / "client" /
                                      "activity.jsonl") &&
                                  !client_active && client == "not complete";
    if (abandoned_server || abandoned_client) {
        std::cout << "\nINCOMPLETE AND NOT RUNNING: a role stopped without "
                     "a result.\n";
        return 1;
    }
    std::cout << "\nRUNNING OR INCOMPLETE: final completion requires all "
                 "PASS records and zero wrapper exits.\n";
    return 0;
}

void publish_failure(const Command &command,
                     std::string_view message) noexcept {
    try {
        std::filesystem::path path;
        switch (command.action) {
        case Command::Action::Setup:
            path = command.run_directory / "shared" / "setup-failure.txt";
            break;
        case Command::Action::Client:
            path = command.run_directory / "client" / "failure.txt";
            break;
        case Command::Action::Server:
            path = command.run_directory / "server" / "failure.txt";
            break;
        case Command::Action::Status:
            return;
        }
        if (std::filesystem::is_directory(path.parent_path()) &&
            !regular_file_exists(path)) {
            const std::string failure =
                "FAILED: " + std::string(message) + "\n";
            publish_private_text(path, failure);
        }
    } catch (...) {
    }
}

} // namespace

int main(int argc, char **argv) {
    configure_process_memory_runtime();
    try {
        if (argc == 2 && std::string_view(argv[1]) == "build_info") {
            return run_build_info();
        }
        if (argc > 1 && is_process_action(argv[1])) {
            const Command command = parse_command(argc, argv);
            try {
                switch (command.action) {
                case Command::Action::Setup:
                    return run_setup(command, argc, argv);
                case Command::Action::Client:
                    return run_client(command, argc, argv);
                case Command::Action::Server:
                    return run_server(command, argc, argv);
                case Command::Action::Status:
                    return run_status(command);
                }
            } catch (const std::exception &error) {
                publish_failure(command, error.what());
                throw;
            }
        }
        throw std::invalid_argument(
            "use build_info or ACTION --variant noIntegrity --profile "
            "quick|target-balancedLaned|target-mulHeavyPyramid --run-dir "
            "ABSOLUTE_PATH; see "
            "docs/GCP_BENCHMARKS.md");
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
