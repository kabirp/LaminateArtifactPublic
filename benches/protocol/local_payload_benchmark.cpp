/// @file local_payload_benchmark.cpp
/// @brief Client-only scalar payload benchmark lifecycle.
///
/// Named profiles share the payload geometry used by delegated benchmarks.
/// Setup records the workload and memory admission; run_client evaluates all
/// coordinates in one scalar process and publishes a checksum and timings.
/// The measured evaluator excludes circuit/input construction and checksum
/// computation, which have separate timing fields. There is no server role.

#include "benchmark_support.hpp"
#include "completed_result_report.hpp"
#include "local_payload_git_state.hpp"
#include "run_lifecycle_lock.hpp"

#include "../payload/local_scalar_evaluator.hpp"

#include "laminate/bench/payload_profile.hpp"
#include "laminate/payload/fixtures/workloads.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <random>
#include <span>
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

#if defined(__linux__)
#include <sched.h>
#endif

using namespace laminate;
using namespace laminate::bench;
using namespace laminate::bench::local_payload;
using namespace laminate::payload;

namespace {

constexpr std::size_t kSlots = kDefaultPolyModulusDegree;
constexpr std::size_t kMaximumSetupBytes = 16U << 10U;
constexpr std::size_t kMaximumRunBindingBytes = 1U << 10U;
constexpr std::uint64_t kResidentSafetyMarginBytes = 256U << 20U;
constexpr std::string_view kSetupFormat =
    "laminate-local-payload-setup-v1";
constexpr std::string_view kProgressSchema =
    "laminate-local-payload-progress-v1";
constexpr std::string_view kPayloadExecution =
    "indexed-cross-slot-prefix-then-coordinate-major";

using Profile = BenchmarkPayloadProfile;

void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          std::string_view description) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(description) + " overflows");
    }
    return left + right;
}

std::uint64_t checked_multiply(std::uint64_t left, std::uint64_t right,
                               std::string_view description) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(description) + " overflows");
    }
    return left * right;
}

std::int64_t unix_milliseconds() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

Profile profile(std::string_view name) {
    return benchmark_payload_profile(name);
}

WorkloadSpec workload_spec(const Profile &selected) {
    return benchmark_payload_workload_spec(
        selected, PayloadShape::wide(kSlots));
}

struct Command {
    enum class Action { Setup, Client, Status };
    Action action = Action::Status;
    std::string variant;
    std::string profile;
    std::filesystem::path run_directory;
};

bool is_process_action(std::string_view action) {
    return action == "setup" || action == "run_client" ||
           action == "status";
}

Command parse_command(int argc, char **argv) {
    if (argc != 8 || std::string_view(argv[2]) != "--variant" ||
        std::string_view(argv[4]) != "--profile" ||
        std::string_view(argv[6]) != "--run-dir") {
        throw std::invalid_argument(
            "expected ACTION --variant local --profile "
            "quick|target-balancedLaned|target-mulHeavyPyramid --run-dir "
            "ABSOLUTE_PATH");
    }
    Command result;
    const std::string_view action(argv[1]);
    if (action == "setup") {
        result.action = Command::Action::Setup;
    } else if (action == "run_client") {
        result.action = Command::Action::Client;
    } else if (action == "status") {
        result.action = Command::Action::Status;
    } else {
        throw std::invalid_argument("unknown local benchmark action");
    }
    result.variant = argv[3];
    result.profile = argv[5];
    result.run_directory = argv[7];
    if (result.variant != "local") {
        throw std::invalid_argument("variant must be exactly local");
    }
    (void)profile(result.profile);
    if (!result.run_directory.is_absolute() ||
        result.run_directory == result.run_directory.root_path()) {
        throw std::invalid_argument(
            "--run-dir must be an absolute path below the filesystem root");
    }
    return result;
}

struct OperationLedger {
    std::uint64_t add = 0;
    std::uint64_t add_plain = 0;
    std::uint64_t mul = 0;
    std::uint64_t mul_plain = 0;
    std::uint64_t rotate = 0;
    std::uint64_t scalar_additions = 0;
    std::uint64_t scalar_multiplications = 0;
    std::uint64_t scalar_permutation_wires = 0;
    std::uint64_t scalar_total = 0;
};

struct LocalPayloadStats {
    std::size_t add_gates = 0;
    std::size_t add_plain_gates = 0;
    std::size_t mul_gates = 0;
    std::size_t mul_plain_gates = 0;
    std::size_t rotate_gates = 0;
    std::size_t ct_ct_multiplicative_depth = 0;
};

LocalPayloadStats local_payload_stats(const PayloadCircuit &circuit) {
    LocalPayloadStats result;
    std::vector<std::size_t> depths(circuit.input_count, 0);
    depths.reserve(circuit.wire_count());
    for (const Gate &gate : circuit.gates) {
        std::size_t depth = depths[gate.left];
        switch (gate.op) {
        case GateOp::Add:
            ++result.add_gates;
            depth = std::max(depth, depths[gate.right]);
            break;
        case GateOp::AddPlain:
            ++result.add_plain_gates;
            break;
        case GateOp::Mul:
            ++result.mul_gates;
            depth = std::max(depth, depths[gate.right]) + 1U;
            break;
        case GateOp::MulPlain:
            ++result.mul_plain_gates;
            break;
        case GateOp::Rotate:
            ++result.rotate_gates;
            break;
        }
        depths.push_back(depth);
        result.ct_ct_multiplicative_depth =
            std::max(result.ct_ct_multiplicative_depth, depth);
    }
    return result;
}

OperationLedger operation_ledger(const LocalPayloadStats &stats,
                                 std::size_t coordinates) {
    const auto scale = [&](std::size_t gates, std::string_view name) {
        return checked_multiply(gates, coordinates, name);
    };
    OperationLedger result;
    result.add = stats.add_gates;
    result.add_plain = stats.add_plain_gates;
    result.mul = stats.mul_gates;
    result.mul_plain = stats.mul_plain_gates;
    result.rotate = stats.rotate_gates;
    result.scalar_additions = checked_add(
        scale(stats.add_gates, "local scalar Add operations"),
        scale(stats.add_plain_gates, "local scalar AddPlain operations"),
        "local scalar additions");
    result.scalar_multiplications = checked_add(
        scale(stats.mul_gates, "local scalar Mul operations"),
        scale(stats.mul_plain_gates, "local scalar MulPlain operations"),
        "local scalar multiplications");
    result.scalar_permutation_wires =
        scale(stats.rotate_gates, "local scalar permutation wires");
    result.scalar_total = checked_add(
        checked_add(result.scalar_additions, result.scalar_multiplications,
                    "local scalar arithmetic operations"),
        result.scalar_permutation_wires,
        "local scalar total operations");
    return result;
}

LocalPayloadStats require_profile_geometry(const Profile &selected,
                                           const PayloadCircuit &circuit) {
    circuit.validate();
    const LocalPayloadStats stats = local_payload_stats(circuit);
    require(circuit.shape == PayloadShape::wide(kSlots),
            "local payload is not the canonical Wide shape");
    require(circuit.input_count == selected.inputs &&
                circuit.outputs.size() == selected.outputs &&
                circuit.gates.size() == selected.operation_count,
            "local payload geometry differs from its selected profile");
    require(stats.add_gates == selected.add_gates &&
                stats.add_plain_gates == selected.add_plain_gates &&
                stats.mul_gates == selected.mul_gates &&
                stats.mul_plain_gates == selected.mul_plain_gates &&
                stats.rotate_gates == selected.rotate_gates &&
                stats.ct_ct_multiplicative_depth == selected.depth,
            "local payload operation ledger differs from its profile");
    return stats;
}

void fingerprint_word(std::uint64_t &state, std::uint64_t word) {
    constexpr std::uint64_t kPrime = 1'099'511'628'211ULL;
    for (std::size_t byte = 0; byte < sizeof(word); ++byte) {
        state ^= (word >> (8U * byte)) & 0xffU;
        state *= kPrime;
    }
}

std::uint64_t circuit_fingerprint(const PayloadCircuit &circuit) {
    std::uint64_t state = 14'695'981'039'346'656'037ULL;
    fingerprint_word(state,
                     static_cast<std::uint8_t>(circuit.shape.kind));
    fingerprint_word(state, circuit.shape.slot_count);
    fingerprint_word(state, circuit.shape.lane_count);
    fingerprint_word(state, circuit.input_count);
    fingerprint_word(state, circuit.plaintexts.size());
    for (const auto &plaintext : circuit.plaintexts) {
        fingerprint_word(state, plaintext.size());
        for (const Fp &value : plaintext) {
            fingerprint_word(state, value.value());
        }
    }
    fingerprint_word(state, circuit.gates.size());
    for (const Gate &gate : circuit.gates) {
        fingerprint_word(state, static_cast<std::uint8_t>(gate.op));
        fingerprint_word(state, gate.left);
        fingerprint_word(state, gate.right);
        fingerprint_word(state, gate.parameter);
    }
    fingerprint_word(state, circuit.outputs.size());
    for (WireId output : circuit.outputs) {
        fingerprint_word(state, output);
    }
    return state;
}

struct MemoryPlan {
    std::uint64_t scalar_wire_bytes = 0;
    std::uint64_t cross_slot_bytes = 0;
    std::uint64_t input_bytes = 0;
    std::uint64_t output_bytes = 0;
    std::uint64_t circuit_bytes = 0;
    std::uint64_t admitted_peak_resident_bytes = 0;
};

MemoryPlan memory_plan(const PayloadCircuit &circuit) {
    MemoryPlan result;
    result.scalar_wire_bytes = checked_multiply(
        circuit.wire_count(), sizeof(Fp), "scalar wire bytes");
    result.cross_slot_bytes = cross_slot_workspace_bytes(circuit);
    result.input_bytes = checked_multiply(
        checked_multiply(circuit.input_count, circuit.shape.slot_count,
                         "input field elements"),
        sizeof(Fp), "input bytes");
    result.output_bytes = checked_multiply(
        checked_multiply(circuit.outputs.size(), circuit.shape.slot_count,
                         "output field elements"),
        sizeof(Fp), "output bytes");
    result.circuit_bytes = checked_multiply(
        circuit.gates.size(), sizeof(Gate), "circuit gate bytes");
    for (const auto &plaintext : circuit.plaintexts) {
        result.circuit_bytes = checked_add(
            result.circuit_bytes,
            checked_multiply(plaintext.size(), sizeof(Fp),
                             "circuit plaintext bytes"),
            "circuit bytes");
    }
    result.admitted_peak_resident_bytes = kResidentSafetyMarginBytes;
    for (const std::uint64_t bytes : {
             result.scalar_wire_bytes, result.cross_slot_bytes, result.input_bytes,
             result.output_bytes, result.circuit_bytes}) {
        result.admitted_peak_resident_bytes = checked_add(
            result.admitted_peak_resident_bytes, bytes,
            "local client resident admission");
    }
    return result;
}

std::string random_run_id() {
    std::array<std::uint8_t, 32> bytes{};
    std::random_device random;
    for (std::uint8_t &byte : bytes) {
        byte = static_cast<std::uint8_t>(random());
    }
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::uint8_t byte : bytes) {
        output << std::setw(2) << static_cast<unsigned>(byte);
    }
    return output.str();
}

bool valid_run_id(std::string_view value) {
    return value.size() == 64 &&
           std::all_of(value.begin(), value.end(), [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

std::string encode_run_binding(std::string_view profile_name,
                               std::string_view run_id) {
    require(valid_run_id(run_id), "local run id is not canonical");
    return "format=laminate-benchmark-run-v1\nrun.variant=local\n"
           "run.profile=" +
           std::string(profile_name) + "\nrun.id=" +
           std::string(run_id) + "\n";
}

void validate_run_binding(std::span<const std::uint8_t> bytes,
                          std::string_view profile_name,
                          std::string_view run_id) {
    const std::string actual(reinterpret_cast<const char *>(bytes.data()),
                             bytes.size());
    if (actual != encode_run_binding(profile_name, run_id)) {
        throw std::invalid_argument(
            "local run binding differs from immutable setup");
    }
}

struct SetupRecord {
    std::string variant;
    std::string profile;
    std::string run_id;
    std::string git_commit;
    std::string build_type;
    std::string compiler;
    std::uint64_t circuit_fingerprint = 0;
    std::uint64_t slots = 0;
    std::uint64_t depth = 0;
    std::uint64_t width = 0;
    std::uint64_t inputs = 0;
    std::uint64_t outputs = 0;
    std::uint64_t operations = 0;
    std::uint64_t add_gates = 0;
    std::uint64_t add_plain_gates = 0;
    std::uint64_t mul_gates = 0;
    std::uint64_t mul_plain_gates = 0;
    std::uint64_t rotate_gates = 0;
    MemoryPlan memory;
};

std::string encode_setup(const SetupRecord &setup) {
    std::ostringstream output;
    output << "format=" << kSetupFormat << '\n'
           << "run.variant=" << setup.variant << '\n'
           << "run.profile=" << setup.profile << '\n'
           << "run.id=" << setup.run_id << '\n'
           << "environment.git_commit=" << setup.git_commit << '\n'
           << "environment.build_type=" << setup.build_type << '\n'
           << "environment.compiler=" << setup.compiler << '\n'
           << "payload.circuit_fingerprint="
           << setup.circuit_fingerprint << '\n'
           << "parameters.slots=" << setup.slots << '\n'
           << "parameters.payload_multiplicative_depth=" << setup.depth
           << '\n'
           << "parameters.payload_width=" << setup.width << '\n'
           << "parameters.payload_inputs=" << setup.inputs << '\n'
           << "parameters.payload_outputs=" << setup.outputs << '\n'
           << "parameters.payload_operations=" << setup.operations << '\n'
           << "parameters.payload_add_gates=" << setup.add_gates << '\n'
           << "parameters.payload_add_plain_gates="
           << setup.add_plain_gates << '\n'
           << "parameters.payload_mul_gates=" << setup.mul_gates << '\n'
           << "parameters.payload_mul_plain_gates="
           << setup.mul_plain_gates << '\n'
           << "parameters.payload_rotate_gates=" << setup.rotate_gates
           << '\n'
           << "memory.client.scalar_wire_bytes="
           << setup.memory.scalar_wire_bytes << '\n'
           << "memory.client.cross_slot_workspace_bytes="
           << setup.memory.cross_slot_bytes << '\n'
           << "memory.client.input_bytes=" << setup.memory.input_bytes
           << '\n'
           << "memory.client.output_bytes=" << setup.memory.output_bytes
           << '\n'
           << "memory.client.circuit_bytes=" << setup.memory.circuit_bytes
           << '\n'
           << "memory.client.admitted_peak_resident_bytes="
           << setup.memory.admitted_peak_resident_bytes << '\n';
    return output.str();
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
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    input.read(reinterpret_cast<char *>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    if (!input || input.peek() != std::char_traits<char>::eof()) {
        throw std::runtime_error("failed to read bounded file: " +
                                 path.string());
    }
    return bytes;
}

std::uint64_t parse_u64(std::string_view value,
                        std::string_view description) {
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(
        value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc{} ||
        parsed.ptr != value.data() + value.size()) {
        throw std::invalid_argument(std::string(description) +
                                    " is not a canonical u64");
    }
    return result;
}

SetupRecord decode_setup(std::span<const std::uint8_t> bytes) {
    const std::string text(reinterpret_cast<const char *>(bytes.data()),
                           bytes.size());
    std::map<std::string, std::string> fields;
    std::istringstream input(text);
    for (std::string line; std::getline(input, line);) {
        const std::size_t equals = line.find('=');
        if (equals == std::string::npos || equals == 0 ||
            !fields.emplace(line.substr(0, equals),
                            line.substr(equals + 1U))
                 .second) {
            throw std::invalid_argument("noncanonical local setup record");
        }
    }
    const auto value = [&](std::string_view name) -> const std::string & {
        const auto found = fields.find(std::string(name));
        if (found == fields.end()) {
            throw std::invalid_argument(
                "local setup record omits " + std::string(name));
        }
        return found->second;
    };
    if (value("format") != kSetupFormat) {
        throw std::invalid_argument("unsupported local setup record");
    }
    SetupRecord result;
    result.variant = value("run.variant");
    result.profile = value("run.profile");
    result.run_id = value("run.id");
    result.git_commit = value("environment.git_commit");
    result.build_type = value("environment.build_type");
    result.compiler = value("environment.compiler");
    result.circuit_fingerprint = parse_u64(
        value("payload.circuit_fingerprint"), "circuit fingerprint");
    result.slots = parse_u64(value("parameters.slots"), "slot count");
    result.depth = parse_u64(
        value("parameters.payload_multiplicative_depth"), "payload depth");
    result.width = parse_u64(value("parameters.payload_width"),
                             "payload width");
    result.inputs = parse_u64(value("parameters.payload_inputs"),
                              "payload inputs");
    result.outputs = parse_u64(value("parameters.payload_outputs"),
                               "payload outputs");
    result.operations = parse_u64(value("parameters.payload_operations"),
                                  "payload operations");
    result.add_gates = parse_u64(value("parameters.payload_add_gates"),
                                 "payload Add gates");
    result.add_plain_gates = parse_u64(
        value("parameters.payload_add_plain_gates"),
        "payload AddPlain gates");
    result.mul_gates = parse_u64(value("parameters.payload_mul_gates"),
                                 "payload Mul gates");
    result.mul_plain_gates = parse_u64(
        value("parameters.payload_mul_plain_gates"),
        "payload MulPlain gates");
    result.rotate_gates = parse_u64(
        value("parameters.payload_rotate_gates"), "payload Rotate gates");
    result.memory.scalar_wire_bytes = parse_u64(
        value("memory.client.scalar_wire_bytes"), "scalar wire bytes");
    result.memory.cross_slot_bytes = parse_u64(
        value("memory.client.cross_slot_workspace_bytes"), "cross-slot workspace bytes");
    result.memory.input_bytes = parse_u64(
        value("memory.client.input_bytes"), "input bytes");
    result.memory.output_bytes = parse_u64(
        value("memory.client.output_bytes"), "output bytes");
    result.memory.circuit_bytes = parse_u64(
        value("memory.client.circuit_bytes"), "circuit bytes");
    result.memory.admitted_peak_resident_bytes = parse_u64(
        value("memory.client.admitted_peak_resident_bytes"),
        "admitted peak resident bytes");
    if (!valid_run_id(result.run_id) || encode_setup(result) != text) {
        throw std::invalid_argument("local setup record is not canonical");
    }
    return result;
}

void publish_private_file(const std::filesystem::path &path,
                          std::span<const std::uint8_t> bytes) {
    const std::filesystem::path temporary =
        path.parent_path() /
        (".local-payload-" + path.filename().string() + "." +
         std::to_string(::getpid()));
    int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC;
#if defined(O_NOFOLLOW)
    flags |= O_NOFOLLOW;
#endif
    int descriptor = ::open(temporary.c_str(), flags, S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "failed to create staged local artifact");
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
                    "failed to write staged local artifact");
            }
            written += static_cast<std::size_t>(count);
        }
        if (::fsync(descriptor) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "failed to flush staged local artifact");
        }
        if (::close(descriptor) != 0) {
            descriptor = -1;
            throw std::system_error(errno, std::generic_category(),
                                    "failed to close staged local artifact");
        }
        descriptor = -1;
        if (::link(temporary.c_str(), path.c_str()) != 0) {
            throw std::system_error(
                errno, std::generic_category(),
                "failed to publish immutable local artifact");
        }
        if (::unlink(temporary.c_str()) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "failed to retire staged local artifact");
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
    publish_private_file(
        path, std::span<const std::uint8_t>(
                  reinterpret_cast<const std::uint8_t *>(value.data()),
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
    make_private_directory(root);
    make_private_directory(root / "shared");
    make_private_directory(root / "shared" / "report");
    make_private_directory(root / "client");
}

bool regular_file_exists(const std::filesystem::path &path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    return !error && !std::filesystem::is_symlink(status) &&
           std::filesystem::is_regular_file(status);
}

bool filesystem_entry_exists(const std::filesystem::path &path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error == std::errc::no_such_file_or_directory) {
        return false;
    }
    if (error) {
        throw std::filesystem::filesystem_error(
            "failed to inspect local benchmark artifact", path, error);
    }
    return status.type() != std::filesystem::file_type::not_found;
}

class RemoteArtifactsPresent final : public std::runtime_error {
  public:
    RemoteArtifactsPresent()
        : std::runtime_error(
              "Local runs must not contain a server role or "
              "request/response transcript") {}
};

void require_no_remote_artifacts(const Command &command) {
    if (filesystem_entry_exists(command.run_directory / "server") ||
        filesystem_entry_exists(command.run_directory / "shared" /
                                "transcript")) {
        throw RemoteArtifactsPresent{};
    }
}

bool result_contains(const std::filesystem::path &path,
                     std::string_view expected) {
    std::ifstream input(path);
    for (std::string line; std::getline(input, line);) {
        if (line == expected) {
            return true;
        }
    }
    return false;
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
        if (descriptor_ < 0 ||
            ::flock(descriptor_, LOCK_EX | LOCK_NB) != 0) {
            const int saved = errno;
            if (descriptor_ >= 0) {
                (void)::close(descriptor_);
            }
            throw std::system_error(saved, std::generic_category(),
                                    "failed to claim local role activity");
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
    std::string line(std::string_view event,
                     std::string_view stage) const {
        std::ostringstream output;
        output << "{\"schema\":\"laminate-role-activity-v1\","
               << "\"role\":\"" << role_ << "\",\"event\":\""
               << event << "\",\"stage\":\"" << stage
               << "\",\"pid\":"
               << static_cast<std::uint64_t>(::getpid())
               << ",\"unix_ms\":" << unix_milliseconds() << "}\n";
        return output.str();
    }

    void append(std::string_view event, std::string_view stage) {
        const std::string value = line(event, stage);
        std::size_t written = 0;
        while (written != value.size()) {
            const ssize_t count = ::write(
                descriptor_, value.data() + written, value.size() - written);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw std::system_error(
                    count < 0 ? errno : EIO, std::generic_category(),
                    "failed to append local role activity");
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

class LocalProgressJournal {
  public:
    explicit LocalProgressJournal(const std::filesystem::path &path)
        : start_(std::chrono::steady_clock::now()),
          uncaught_(std::uncaught_exceptions()) {
        int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC;
#if defined(O_NOFOLLOW)
        flags |= O_NOFOLLOW;
#endif
        descriptor_ = ::open(path.c_str(), flags, S_IRUSR | S_IWUSR);
        if (descriptor_ < 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "failed to create local progress file");
        }
        append_status("started");
    }

    LocalProgressJournal(const LocalProgressJournal &) = delete;
    LocalProgressJournal &operator=(const LocalProgressJournal &) = delete;

    ~LocalProgressJournal() {
        if (!complete_ || std::uncaught_exceptions() > uncaught_) {
            append_status_noexcept("failed");
        }
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
    }

    void phase(std::string_view stage) {
        std::ostringstream output;
        output << "{\"schema\":\"" << kProgressSchema
               << "\",\"seq\":" << sequence_++
               << ",\"event\":\"phase\",\"stage\":\"" << stage
               << "\",\"run_elapsed_ms\":" << std::fixed
               << std::setprecision(3) << elapsed_ms() << "}\n";
        append(output.str());
    }

    void update(const EvaluationProgress &progress) {
        const auto now = std::chrono::steady_clock::now();
        const bool terminal =
            progress.completed_coordinates == progress.total_coordinates;
        if (progress.completed_coordinates != 0 && !terminal &&
            now < next_update_) {
            return;
        }
        next_update_ = now + std::chrono::seconds(15);
        std::ostringstream output;
        output << "{\"schema\":\"" << kProgressSchema
               << "\",\"seq\":" << sequence_++
               << ",\"event\":\"progress\","
               << "\"stage\":\"client.local_payload_evaluation\","
               << "\"run_elapsed_ms\":" << std::fixed
               << std::setprecision(3) << elapsed_ms()
               << ",\"completed_coordinates\":"
               << progress.completed_coordinates
               << ",\"total_coordinates\":"
               << progress.total_coordinates
               << ",\"completed_scalar_operations\":"
               << progress.completed_scalar_operations
               << ",\"total_scalar_operations\":"
               << progress.total_scalar_operations << "}\n";
        append(output.str());
    }

    void mark_complete() {
        complete_ = true;
        append_status("completed");
    }

  private:
    double elapsed_ms() const {
        return std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - start_)
            .count();
    }

    void append_status(std::string_view status) {
        std::ostringstream output;
        output << "{\"schema\":\"" << kProgressSchema
               << "\",\"seq\":" << sequence_++
               << ",\"event\":\"run-status\",\"status\":\""
               << status << "\",\"run_elapsed_ms\":" << std::fixed
               << std::setprecision(3) << elapsed_ms() << "}\n";
        append(output.str());
    }

    void append_status_noexcept(std::string_view status) noexcept {
        try {
            append_status(status);
        } catch (...) {
        }
    }

    void append(std::string_view value) {
        std::size_t written = 0;
        while (written != value.size()) {
            const ssize_t count = ::write(
                descriptor_, value.data() + written, value.size() - written);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw std::system_error(
                    count < 0 ? errno : EIO, std::generic_category(),
                    "failed to append local progress");
            }
            written += static_cast<std::size_t>(count);
        }
    }

    int descriptor_ = -1;
    std::chrono::steady_clock::time_point start_;
    std::chrono::steady_clock::time_point next_update_{};
    int uncaught_ = 0;
    std::size_t sequence_ = 0;
    bool complete_ = false;
};

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
    record.text("run.id", setup.run_id);
    record.text("environment.git_commit", setup.git_commit);
    record.text("environment.git_dirty", LAMINATE_LOCAL_PAYLOAD_GIT_DIRTY);
    record.text("environment.build_type", setup.build_type);
    record.text("environment.compiler", setup.compiler);
    record.text("environment.architecture",
                LAMINATE_LOCAL_PAYLOAD_ARCHITECTURE);
    record.text("environment.cpu_target", LAMINATE_LOCAL_PAYLOAD_CPU_TARGET);
    record.text("environment.field_backend", "scalar-fp65537");
    record.text("environment.vectorization",
                LAMINATE_LOCAL_PAYLOAD_VECTORIZATION);
    record.text("environment.hexl", "not-used");
    record.text("environment.fhe_backend", "none");
    record.text("environment.threading", "single-cpu-process");
    const std::optional<std::uint64_t> pinned = pinned_logical_cpu();
    record.text("environment.pinned_cpu",
                pinned ? std::to_string(*pinned) : "not-observed");
    record.text("environment.os", system.os);
    record.text("environment.cpu", system.cpu);
    record.integer("environment.physical_cores", system.physical_cores);
    record.integer("environment.logical_cores", system.logical_cores);
    record.integer("environment.ram_bytes", system.ram_bytes);
    record.text("computation.integrity", "not-applicable");
    record.text("computation.delegation", "none");
    record.text("computation.server", "none");
}

void emit_geometry(const Record &record, const Profile &selected,
                   const LocalPayloadStats &stats,
                   std::size_t payload_operations) {
    record.text("payload.execution", std::string(kPayloadExecution));
    record.integer("parameters.slots", kSlots);
    record.integer("parameters.payload_multiplicative_depth",
                   selected.depth);
    record.text("parameters.payload_workload",
                std::string(workload_name(selected.workload_kind)));
    record.integer("parameters.payload_width", selected.width);
    record.integer("parameters.payload_inputs", selected.inputs);
    record.integer("parameters.payload_outputs", selected.outputs);
    record.integer("parameters.payload_operations", payload_operations);
    record.integer("parameters.payload_add_gates", stats.add_gates);
    record.integer("parameters.payload_add_plain_gates",
                   stats.add_plain_gates);
    record.integer("parameters.payload_mul_gates", stats.mul_gates);
    record.integer("parameters.payload_mul_plain_gates",
                   stats.mul_plain_gates);
    record.integer("parameters.payload_rotate_gates", stats.rotate_gates);
    record.integer("parameters.plaintext_modulus", kBaseFieldOrder);
}

void emit_operations(const Record &record, const OperationLedger &ledger) {
    record.integer("operations.client_local.add.calls", ledger.add);
    record.integer("operations.client_local.add_plain.calls",
                   ledger.add_plain);
    record.integer("operations.client_local.mul.calls", ledger.mul);
    record.integer("operations.client_local.mul_plain.calls",
                   ledger.mul_plain);
    record.integer("operations.client_local.rotate.calls", ledger.rotate);
    record.integer("operations.client_local.scalar_additions",
                   ledger.scalar_additions);
    record.integer("operations.client_local.scalar_multiplications",
                   ledger.scalar_multiplications);
    record.integer("operations.client_local.scalar_total",
                   ledger.scalar_total);
    record.integer("operations.client_local.scalar_permutation_wires",
                   ledger.scalar_permutation_wires);
    record.integer("operations.client_local.scalar_rotation_copies",
                   0);
}

void emit_memory_plan(const Record &record, const MemoryPlan &memory) {
    record.integer("memory.client.scalar_wire_bytes",
                   memory.scalar_wire_bytes);
    record.integer("memory.client.cross_slot_workspace_bytes",
                   memory.cross_slot_bytes);
    record.integer("memory.client.input_bytes", memory.input_bytes);
    record.integer("memory.client.output_bytes", memory.output_bytes);
    record.integer("memory.client.circuit_bytes", memory.circuit_bytes);
    record.integer("memory.client.admitted_peak_resident_bytes",
                   memory.admitted_peak_resident_bytes);
}

void require_benchmark_build() {
    if (std::string_view(LAMINATE_LOCAL_PAYLOAD_GIT_DIRTY) != "false" ||
        std::string_view(LAMINATE_BUILD_TYPE) != "Release" ||
        std::string_view(LAMINATE_LOCAL_PAYLOAD_ARCHITECTURE) != "x86-64" ||
        std::string_view(LAMINATE_LOCAL_PAYLOAD_VECTORIZATION) != "enabled" ||
        std::string_view(LAMINATE_LOCAL_PAYLOAD_CPU_TARGET) != "native") {
        throw std::runtime_error(
            "GCP local setup requires a clean x86-64 Release build with "
            "compiler vectorization enabled and the native CPU target");
    }
}

SetupRecord make_setup_record(const Command &command,
                              const Profile &selected,
                              const PayloadCircuit &circuit,
                              const LocalPayloadStats &stats,
                              const MemoryPlan &memory,
                              std::string run_id) {
    return SetupRecord{
        .variant = command.variant,
        .profile = command.profile,
        .run_id = std::move(run_id),
        .git_commit = LAMINATE_LOCAL_PAYLOAD_GIT_COMMIT,
        .build_type = LAMINATE_BUILD_TYPE,
        .compiler = LAMINATE_COMPILER,
        .circuit_fingerprint = circuit_fingerprint(circuit),
        .slots = kSlots,
        .depth = selected.depth,
        .width = selected.width,
        .inputs = selected.inputs,
        .outputs = selected.outputs,
        .operations = circuit.gates.size(),
        .add_gates = stats.add_gates,
        .add_plain_gates = stats.add_plain_gates,
        .mul_gates = stats.mul_gates,
        .mul_plain_gates = stats.mul_plain_gates,
        .rotate_gates = stats.rotate_gates,
        .memory = memory,
    };
}

SetupRecord load_setup_identity(const Command &command) {
    SetupRecord setup = decode_setup(read_bounded_file(
        command.run_directory / "shared" / "setup.bin",
        kMaximumSetupBytes));
    const Profile selected = profile(command.profile);
    if (setup.variant != command.variant ||
        setup.profile != command.profile || setup.slots != kSlots ||
        setup.depth != selected.depth || setup.width != selected.width ||
        setup.inputs != selected.inputs ||
        setup.outputs != selected.outputs ||
        setup.operations != selected.operation_count ||
        setup.add_gates != selected.add_gates ||
        setup.add_plain_gates != selected.add_plain_gates ||
        setup.mul_gates != selected.mul_gates ||
        setup.mul_plain_gates != selected.mul_plain_gates ||
        setup.rotate_gates != selected.rotate_gates) {
        throw std::runtime_error(
            "command geometry differs from immutable local setup");
    }
    return setup;
}

SetupRecord load_setup(const Command &command) {
    SetupRecord setup = load_setup_identity(command);
    if (setup.git_commit != LAMINATE_LOCAL_PAYLOAD_GIT_COMMIT ||
        setup.build_type != LAMINATE_BUILD_TYPE ||
        setup.compiler != LAMINATE_COMPILER ||
        std::string_view(LAMINATE_LOCAL_PAYLOAD_GIT_DIRTY) != "false" ||
        std::string_view(LAMINATE_LOCAL_PAYLOAD_ARCHITECTURE) != "x86-64" ||
        std::string_view(LAMINATE_LOCAL_PAYLOAD_VECTORIZATION) != "enabled" ||
        std::string_view(LAMINATE_LOCAL_PAYLOAD_CPU_TARGET) != "native") {
        throw std::runtime_error(
            "local executable differs from immutable setup");
    }
    return setup;
}

void require_run_binding(const Command &command,
                         const SetupRecord &setup) {
    validate_run_binding(
        read_bounded_file(command.run_directory / "shared" /
                              "run-binding.txt",
                          kMaximumRunBindingBytes),
        command.profile, setup.run_id);
}

void require_setup_pass(const Command &command) {
    if (!result_contains(command.run_directory / "shared" /
                             "setup-result.txt",
                         "setup.result=PASS") ||
        !result_contains(command.run_directory / "shared" /
                             "setup-process-exit.txt",
                         "process.exit_status=0")) {
        throw std::runtime_error(
            "local client requires completed setup PASS");
    }
}

int run_build_info() {
    std::cout
        << "format=laminate-local-payload-build-info-v1\n"
        << "environment.git_commit=" << LAMINATE_LOCAL_PAYLOAD_GIT_COMMIT
        << '\n'
        << "environment.git_dirty=" << LAMINATE_LOCAL_PAYLOAD_GIT_DIRTY
        << '\n'
        << "environment.build_type=" << LAMINATE_BUILD_TYPE << '\n'
        << "environment.compiler=" << LAMINATE_COMPILER << '\n'
        << "environment.architecture="
        << LAMINATE_LOCAL_PAYLOAD_ARCHITECTURE << '\n'
        << "environment.cpu_target="
        << LAMINATE_LOCAL_PAYLOAD_CPU_TARGET << '\n'
        << "benchmark.variant=local\n"
        << "benchmark.roles=client-only\n"
        << "environment.field_backend=scalar-fp65537\n"
        << "environment.vectorization="
        << LAMINATE_LOCAL_PAYLOAD_VECTORIZATION << '\n'
        << "environment.hexl=not-used\n"
        << "environment.fhe_backend=none\n"
        << "environment.threading=single-cpu-process\n"
        << "computation.integrity=not-applicable\n"
        << "computation.delegation=none\n"
        << "computation.server=none\n"
        << "payload.execution=" << kPayloadExecution << '\n'
        << "payload.worker_threads=1\n";
    return 0;
}

int run_setup(const Command &command, int argc, char **argv) {
    Stopwatch process_stopwatch;
    require_benchmark_build();
    create_run_tree(command.run_directory);
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    RoleActivity activity(command.run_directory / "shared" /
                              "setup-activity.jsonl",
                          "setup");
    const Profile selected = profile(command.profile);
    const std::string run_id = random_run_id();
    publish_private_text(
        command.run_directory / "shared" / "run-binding.txt",
        encode_run_binding(command.profile, run_id));

    activity.transition("constructing_payload");
    auto constructed = timed([&] {
        PayloadCircuit circuit = make_payload_circuit(workload_spec(selected));
        const LocalPayloadStats stats =
            require_profile_geometry(selected, circuit);
        return std::pair{std::move(circuit), stats};
    });
    PayloadCircuit circuit = std::move(constructed.first.first);
    const LocalPayloadStats stats = constructed.first.second;
    const MemoryPlan memory = memory_plan(circuit);
    const SystemInfo system = system_info();
    require(system.ram_bytes >= memory.admitted_peak_resident_bytes,
            "host RAM is below the local client resident admission");
    const SetupRecord setup = make_setup_record(
        command, selected, circuit, stats, memory, run_id);
    publish_private_text(command.run_directory / "shared" / "setup.bin",
                         encode_setup(setup));

    const Timing process = process_stopwatch.stop();
    const OperationLedger operations = operation_ledger(stats, kSlots);
    CompletedResultReport report(command.run_directory / "shared" /
                                 "setup-result.txt");
    const Record record(report.mirror());
    record.text("format", "laminate-benchmark-setup-v1");
    emit_identity(record, command, setup);
    emit_geometry(record, selected, stats, circuit.gates.size());
    emit_operations(record, operations);
    record.text("benchmark.intent",
                "client-local-scalar-payload-evaluation");
    emit_timing(record, "setup.construct_payload", constructed.second);
    emit_timing(record, "setup.process_total", process);
    emit_memory_plan(record, memory);
    record.text("environment.command", exact_command(argc, argv));
    record.text("setup.result", "PASS");
    report.publish();
    activity.mark_complete();
    std::cout << "\nSETUP PASS\nStart the local client; no server role "
                 "exists for this benchmark.\n";
    return 0;
}

int run_client(const Command &command, int argc, char **argv) {
    Stopwatch process_stopwatch;
    require_setup_pass(command);
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    require_no_remote_artifacts(command);
    RoleActivity activity(command.run_directory / "client" /
                              "activity.jsonl",
                          "client");
    LocalProgressJournal progress(command.run_directory / "client" /
                                  "progress.jsonl");
    const SetupRecord setup = load_setup(command);
    require_run_binding(command, setup);
    const Profile selected = profile(command.profile);

    activity.transition("constructing_payload");
    progress.phase("client.constructing_payload");
    auto constructed = timed([&] {
        PayloadCircuit circuit = make_payload_circuit(workload_spec(selected));
        const LocalPayloadStats stats =
            require_profile_geometry(selected, circuit);
        require(circuit_fingerprint(circuit) == setup.circuit_fingerprint,
                "local payload differs from immutable setup");
        require(memory_plan(circuit).admitted_peak_resident_bytes ==
                    setup.memory.admitted_peak_resident_bytes,
                "local client memory plan differs from immutable setup");
        return std::pair{std::move(circuit), stats};
    });
    PayloadCircuit circuit = std::move(constructed.first.first);
    const LocalPayloadStats stats = constructed.first.second;

    activity.transition("constructing_inputs");
    progress.phase("client.constructing_inputs");
    auto inputs = timed([&] {
        return make_workload_inputs(workload_spec(selected));
    });

    activity.transition("local_payload_evaluation");
    progress.phase("client.local_payload_evaluation");
    auto evaluated = timed([&] {
        return evaluate_scalar_coordinates(
            circuit, inputs.first,
            [&](const EvaluationProgress &current) {
                activity.heartbeat();
                progress.update(current);
            });
    });

    activity.transition("output_checksum");
    progress.phase("client.output_checksum");
    auto checksum = timed([&] {
        return output_checksum(evaluated.first.outputs);
    });
    const std::uint64_t output_values = checked_multiply(
        evaluated.first.outputs.size(), kSlots, "local output values");

    const Timing process = process_stopwatch.stop();
    const SystemInfo system = system_info();
    require(system.peak_rss_bytes <=
                setup.memory.admitted_peak_resident_bytes,
            "local client peak RSS exceeds setup admission");
    const OperationLedger operations = operation_ledger(stats, kSlots);
    require(evaluated.first.scalar_permutation_wires ==
                operations.scalar_permutation_wires &&
                evaluated.first.scalar_rotation_copies == 0,
            "local indexed permutation execution differs from its ledger");
    CompletedResultReport report(command.run_directory / "client" /
                                 "result.txt");
    const Record record(report.mirror());
    record.text("format", "laminate-local-payload-client-v1");
    emit_identity(record, command, setup);
    emit_geometry(record, selected, stats, circuit.gates.size());
    emit_operations(record, operations);
    emit_timing(record, "client.construct_payload", constructed.second);
    emit_timing(record, "client.construct_inputs", inputs.second);
    emit_timing(record, "client.local_payload_evaluation",
                evaluated.second);
    emit_timing(record, "client.output_checksum", checksum.second);
    emit_timing(record, "client.process_total", process);
    record.integer("output.values", output_values);
    record.integer("output.checksum", checksum.first);
    record.integer("memory.client.peak_rss_bytes", system.peak_rss_bytes);
    record.text("environment.command", exact_command(argc, argv));
    record.text("client.result", "PASS");
    report.publish();
    progress.mark_complete();
    activity.mark_complete();
    std::cout << "\nLOCAL CLIENT PASS\n"
              << "The client evaluated every payload coordinate locally; "
                 "no server, FHE, or integrity proof was used.\n";
    return 0;
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

std::optional<std::string> last_progress_line(
    const std::filesystem::path &path) {
    std::ifstream input(path);
    std::optional<std::string> result;
    for (std::string line; std::getline(input, line);) {
        if (line.find("\"event\":\"progress\"") != std::string::npos) {
            result = std::move(line);
        }
    }
    return result;
}

std::optional<std::uint64_t> json_u64(std::string_view line,
                                      std::string_view key) {
    const std::string marker = "\"" + std::string(key) + "\":";
    const std::size_t found = line.find(marker);
    if (found == std::string_view::npos) {
        return std::nullopt;
    }
    const std::size_t begin = found + marker.size();
    const std::size_t end = line.find_first_of(",}", begin);
    std::uint64_t value = 0;
    const std::string_view text = line.substr(begin, end - begin);
    const auto parsed = std::from_chars(
        text.data(), text.data() + text.size(), value);
    return parsed.ec == std::errc{} &&
                   parsed.ptr == text.data() + text.size()
               ? std::optional(value)
               : std::nullopt;
}

int run_status(const Command &command) {
    if (!std::filesystem::is_directory(command.run_directory)) {
        throw std::invalid_argument("status requires an existing local run");
    }
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    bool forbidden_remote_artifacts = false;
    try {
        require_no_remote_artifacts(command);
    } catch (const RemoteArtifactsPresent &) {
        forbidden_remote_artifacts = true;
    }
    if (result_contains(command.run_directory / "shared" /
                            "setup-result.txt",
                        "setup.result=PASS")) {
        const SetupRecord immutable_setup = load_setup_identity(command);
        require_run_binding(command, immutable_setup);
    }
    const std::string setup = role_label(
        command.run_directory / "shared" / "setup-result.txt",
        "setup.result=PASS",
        command.run_directory / "shared" / "setup-process-exit.txt",
        command.run_directory / "shared" / "setup-failure.txt");
    const std::string client = role_label(
        command.run_directory / "client" / "result.txt",
        "client.result=PASS",
        command.run_directory / "client" / "process-exit.txt",
        command.run_directory / "client" / "failure.txt");
    const bool setup_active = activity_is_active(
        command.run_directory / "shared" / "setup-activity.jsonl");
    const bool client_active = activity_is_active(
        command.run_directory / "client" / "activity.jsonl");

    std::cout << "Laminate local " << command.profile << " status\n"
              << "  computation: client-local scalar F_65537\n"
              << "  integrity: not applicable (no delegation)\n"
              << "  setup: " << setup << '\n'
              << "  server: "
              << (forbidden_remote_artifacts
                      ? "INVALID remote artifact present"
                      : "not applicable (never started)")
              << '\n'
              << "  client local payload computation: " << client << '\n'
              << "  setup process: "
              << (setup_active ? "ACTIVE" : "not active") << '\n'
              << "  client process: "
              << (client_active ? "ACTIVE" : "not active") << '\n';
    if (const auto line = last_progress_line(
            command.run_directory / "client" / "progress.jsonl")) {
        const auto coordinates = json_u64(*line, "completed_coordinates");
        const auto total_coordinates =
            json_u64(*line, "total_coordinates");
        const auto operations =
            json_u64(*line, "completed_scalar_operations");
        const auto total_operations =
            json_u64(*line, "total_scalar_operations");
        if (coordinates && total_coordinates && operations &&
            total_operations) {
            std::cout << "  client telemetry: local payload coordinates "
                      << *coordinates << " of " << *total_coordinates
                      << "; scalar circuit gates " << *operations << " of "
                      << *total_operations << '\n';
        }
    }

    if (forbidden_remote_artifacts) {
        std::cout << "\nFAILED: " << RemoteArtifactsPresent{}.what()
                  << ".\n";
        return 1;
    }
    if (setup == "PASS" && client == "PASS") {
        std::cout << "\nCOMPLETE: the client evaluated the complete payload "
                     "locally. No server or integrity claim exists.\n";
        return 0;
    }
    if (setup == "FAILED" || client == "FAILED") {
        std::cout << "\nFAILED: inspect the matching failure and exit "
                     "artifacts.\n";
        return 1;
    }
    const bool abandoned_setup = regular_file_exists(
                                     command.run_directory / "shared" /
                                     "setup-activity.jsonl") &&
                                 !setup_active && setup == "not complete";
    const bool abandoned_client = regular_file_exists(
                                      command.run_directory / "client" /
                                      "activity.jsonl") &&
                                  !client_active && client == "not complete";
    if (abandoned_setup || abandoned_client) {
        std::cout << "\nINCOMPLETE AND NOT RUNNING: a local role stopped "
                     "without a result.\n";
        return 1;
    }
    std::cout << "\nRUNNING OR INCOMPLETE: completion requires setup and "
                 "client PASS records with zero wrapper exits.\n";
    return 0;
}

// Deliberately materialize every wire in the small reference circuits. Its
// row/column formula applies each rotation separately, independently of the
// indexed evaluator's composition and bit-indexing shortcuts.
std::vector<fhe::SlotVector> reference_outputs(
    const PayloadCircuit &circuit,
    std::span<const fhe::SlotVector> inputs) {
    const std::size_t width = circuit.shape.slot_count;
    std::vector<fhe::SlotVector> wires(inputs.begin(), inputs.end());
    wires.resize(circuit.wire_count());
    for (std::size_t index = 0; index < circuit.gates.size(); ++index) {
        const Gate &gate = circuit.gates[index];
        auto &output = wires[circuit.gate_output(index)];
        output.resize(width);
        for (std::size_t coordinate = 0; coordinate < width; ++coordinate) {
            const Fp left = wires[gate.left][coordinate];
            switch (gate.op) {
            case GateOp::Add:
                output[coordinate] = left + wires[gate.right][coordinate];
                break;
            case GateOp::Mul:
                output[coordinate] = left * wires[gate.right][coordinate];
                break;
            case GateOp::AddPlain:
                output[coordinate] = left + circuit.plaintexts[gate.parameter][coordinate];
                break;
            case GateOp::MulPlain:
                output[coordinate] = left * circuit.plaintexts[gate.parameter][coordinate];
                break;
            case GateOp::Rotate: {
                const auto half = width / 2U;
                const auto row = (coordinate / half + gate.parameter / half) % 2U;
                const auto column = (coordinate % half + gate.parameter % half) % half;
                output[coordinate] = wires[gate.left][row * half + column];
                break;
            }
            }
        }
    }
    std::vector<fhe::SlotVector> outputs;
    for (const WireId wire : circuit.outputs) {
        outputs.push_back(wires[wire]);
    }
    return outputs;
}

void check_indexed_reference(const PayloadCircuit &circuit,
                             std::span<const fhe::SlotVector> inputs) {
    const auto result = evaluate_scalar_coordinates(circuit, inputs);
    const auto ledger = operation_ledger(
        local_payload_stats(circuit), circuit.shape.slot_count);
    require(result.outputs == reference_outputs(circuit, inputs),
            "indexed local evaluation differs from the vector reference");
    require(result.scalar_permutation_wires == ledger.scalar_permutation_wires &&
                result.scalar_rotation_copies == 0,
            "indexed local evaluation copied a rotation or missed a permutation");
}

int run_self_test() {
    for (const std::string_view name : {
             std::string_view{"quick"},
             std::string_view{"target-balancedLaned"},
             std::string_view{"target-mulHeavyPyramid"}}) {
        const Profile selected = profile(name);
        const PayloadCircuit fixture =
            make_payload_circuit(workload_spec(selected));
        const LocalPayloadStats stats =
            require_profile_geometry(selected, fixture);
        const OperationLedger ledger = operation_ledger(stats, kSlots);
        require(ledger.add == stats.add_gates &&
                    ledger.add_plain == stats.add_plain_gates &&
                    ledger.mul == stats.mul_gates &&
                    ledger.mul_plain == stats.mul_plain_gates &&
                    ledger.rotate == stats.rotate_gates &&
                    ledger.scalar_permutation_wires ==
                        checked_multiply(stats.rotate_gates, kSlots,
                                         "self-test permutation count") &&
                    ledger.scalar_total ==
                        checked_multiply(selected.operation_count, kSlots,
                                         "self-test scalar operation count"),
                "local profile operation ledger is inconsistent");
    }

    PayloadBuilder arithmetic(PayloadShape::wide(8), 2);
    fhe::SlotVector offset;
    offset.reserve(8);
    for (std::size_t coordinate = 0; coordinate < 8; ++coordinate) {
        offset.emplace_back(coordinate + 3U);
    }
    const std::size_t offset_id =
        arithmetic.add_plaintext(std::move(offset));
    const std::size_t scale_id = arithmetic.add_scalar_plaintext(Fp(7));
    const WireId sum = arithmetic.add(0, 1);
    const WireId shifted = arithmetic.add_plain(sum, offset_id);
    const WireId product = arithmetic.mul(shifted, 1);
    const WireId scaled = arithmetic.mul_plain(product, scale_id);
    arithmetic.set_outputs({scaled, sum});
    const PayloadCircuit circuit = arithmetic.finish();

    std::vector<fhe::SlotVector> inputs{
        fhe::SlotVector(8), fhe::SlotVector(8)};
    for (std::size_t coordinate = 0; coordinate < 8; ++coordinate) {
        inputs[0][coordinate] = Fp(2U * coordinate + 1U);
        inputs[1][coordinate] = Fp(3U * coordinate + 2U);
    }
    EvaluationProgress observed;
    const EvaluationResult evaluated = evaluate_scalar_coordinates(
        circuit, inputs,
        [&](const EvaluationProgress &progress) { observed = progress; });
    require(evaluated.outputs.size() == 2 &&
                observed.completed_coordinates == 8 &&
                observed.total_coordinates == 8 &&
                observed.completed_scalar_operations == 32 &&
                observed.total_scalar_operations == 32,
            "local scalar evaluator reported incorrect completion");
    for (std::size_t coordinate = 0; coordinate < 8; ++coordinate) {
        const Fp expected_sum =
            inputs[0][coordinate] + inputs[1][coordinate];
        const Fp expected =
            (expected_sum + Fp(coordinate + 3U)) *
            inputs[1][coordinate] * Fp(7);
        require(evaluated.outputs[0][coordinate] == expected &&
                    evaluated.outputs[1][coordinate] == expected_sum,
                "local scalar evaluator arithmetic is incorrect");
    }
    auto changed_outputs = evaluated.outputs;
    changed_outputs.front().front() += Fp::one();
    require(output_checksum(evaluated.outputs) !=
                output_checksum(changed_outputs),
            "local scalar output checksum ignored a changed value");

    // Include rotation of a computed value, both BGV rows, and an arithmetic
    // suffix. The independent index formula catches cyclic-vector rotations.
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    const auto product_wire = builder.mul(0, 1);
    const auto rotation_wire = builder.rotate(product_wire, 5);
    builder.set_outputs({builder.add(rotation_wire, 0), product_wire});
    const PayloadCircuit rotated = builder.finish();
    std::uint64_t previous_operations = 0;
    const auto rotation_result = evaluate_scalar_coordinates(
        rotated, inputs, [&](const EvaluationProgress &current) {
            require(current.completed_scalar_operations >= previous_operations,
                    "cross-slot progress regressed");
            previous_operations = current.completed_scalar_operations;
        });
    require(previous_operations == 24 &&
                rotation_result.scalar_permutation_wires == 8 &&
                rotation_result.scalar_rotation_copies == 0 &&
                cross_slot_workspace_bytes(rotated) >= 8U * sizeof(Fp) &&
                cross_slot_workspace_bytes(circuit) == 0,
            "cross-slot work or memory accounting is incorrect");
    for (std::size_t coordinate = 0; coordinate < 8; ++coordinate) {
        const auto source = ((coordinate / 4U) ^ 1U) * 4U +
                            (coordinate % 4U + 1U) % 4U;
        require(rotation_result.outputs[0][coordinate] ==
                    inputs[0][source] * inputs[1][source] + inputs[0][coordinate] &&
                    rotation_result.outputs[1][coordinate] ==
                    inputs[0][coordinate] * inputs[1][coordinate],
                "local scalar cross-slot evaluation is incorrect");
    }

    // Check every composition at widths two and eight, including identity,
    // row swaps, wraparound columns, and shared original/rotated outputs.
    for (const std::size_t width : {2U, 8U}) {
        std::vector<fhe::SlotVector> values{fhe::SlotVector(width)};
        for (std::size_t coordinate = 0; coordinate < width; ++coordinate) {
            values[0][coordinate] = Fp(11U * coordinate + 3U);
        }
        for (std::size_t first = 0; first < width; ++first) {
            for (std::size_t second = 0; second < width; ++second) {
                PayloadBuilder rotations(PayloadShape::wide(width), 1);
                const auto first_wire = rotations.rotate(0, first);
                const auto second_wire = rotations.rotate(first_wire, second);
                const auto combined = rotations.add(first_wire, second_wire);
                rotations.set_outputs({0, first_wire, second_wire, combined});
                check_indexed_reference(rotations.finish(), values);
            }
        }
    }

    // A mask belongs to its arithmetic gate's coordinates. Rotating across it
    // must not move the mask onto the coordinates of the source vector.
    PayloadBuilder mixed(PayloadShape::wide(8), 2);
    fhe::SlotVector mask(8);
    for (std::size_t coordinate = 0; coordinate < 8; ++coordinate) {
        mask[coordinate] = Fp(coordinate * coordinate + 2U);
    }
    const auto mask_id = mixed.add_plaintext(std::move(mask));
    const auto shared = mixed.mul(0, 1);
    const auto first = mixed.rotate(shared, 5);
    const auto composed = mixed.rotate(first, 3); // 5 then 3 is a row swap.
    const auto masked = mixed.mul_plain(first, mask_id);
    const auto remapped = mixed.rotate(masked, 7);
    const auto summed = mixed.add(remapped, shared);
    const auto biased = mixed.add_plain(summed, mask_id);
    const auto final = mixed.mul(biased, composed);
    (void)mixed.rotate(1, 0); // An unused rotation still has logical work.
    mixed.set_outputs({0, shared, first, composed, masked, remapped, biased, final});
    check_indexed_reference(mixed.finish(), inputs);

    // Pure rotations consume metadata only, independent of vector width.
    // Only an arithmetic ancestor adds a width-dependent prefix vector.
    const auto rotation_workspace = [](std::size_t width, bool arithmetic) {
        PayloadBuilder plan(PayloadShape::wide(width), 1);
        const auto source = arithmetic ? plan.mul(0, 0) : 0;
        const auto first = plan.rotate(source, 1);
        plan.set_outputs({plan.rotate(first, width - 1U)});
        return cross_slot_workspace_bytes(plan.finish());
    };
    require(rotation_workspace(8, false) == rotation_workspace(1024, false) &&
                rotation_workspace(1024, true) - rotation_workspace(8, true) ==
                    (1024U - 8U) * sizeof(Fp),
            "indexed rotation workspace includes materialized rotation vectors");
    bool rejected = false;

    const std::string self_test_id(64, 'a');
    const std::string binding = encode_run_binding("quick", self_test_id);
    validate_run_binding(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(binding.data()),
            binding.size()),
        "quick", self_test_id);
    std::string wrong_binding = binding;
    wrong_binding.replace(wrong_binding.find("run.variant=local"),
                          std::string_view("run.variant=local").size(),
                          "run.variant=base");
    rejected = false;
    try {
        validate_run_binding(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(
                    wrong_binding.data()),
                wrong_binding.size()),
            "quick", self_test_id);
    } catch (const std::invalid_argument &) {
        rejected = true;
    }
    require(rejected, "local client accepted a cross-variant run binding");
    std::cout << "local scalar payload self-test: PASS\n";
    return 0;
}

void publish_failure(const Command &command,
                     std::string_view message) noexcept {
    try {
        const std::filesystem::path path =
            command.action == Command::Action::Setup
                ? command.run_directory / "shared" / "setup-failure.txt"
                : command.action == Command::Action::Client
                      ? command.run_directory / "client" / "failure.txt"
                      : std::filesystem::path{};
        if (!path.empty() &&
            std::filesystem::is_directory(path.parent_path()) &&
            !regular_file_exists(path)) {
            publish_private_text(path,
                                 "FAILED: " + std::string(message) + "\n");
        }
    } catch (...) {
    }
}

} // namespace

int main(int argc, char **argv) {
    (void)::umask(S_IRWXG | S_IRWXO);
    try {
        if (argc == 2 && std::string_view(argv[1]) == "build_info") {
            return run_build_info();
        }
        if (argc == 2 && std::string_view(argv[1]) == "self_test") {
            return run_self_test();
        }
        if (argc > 1 && std::string_view(argv[1]) == "run_server") {
            throw std::invalid_argument(
                "the local benchmark has no server role");
        }
        if (argc > 1 && is_process_action(argv[1])) {
            const Command command = parse_command(argc, argv);
            try {
                switch (command.action) {
                case Command::Action::Setup:
                    return run_setup(command, argc, argv);
                case Command::Action::Client:
                    return run_client(command, argc, argv);
                case Command::Action::Status:
                    return run_status(command);
                }
            } catch (const std::exception &error) {
                publish_failure(command, error.what());
                throw;
            }
        }
        throw std::invalid_argument(
            "use build_info, self_test, or ACTION --variant local --profile "
            "quick|target-balancedLaned|target-mulHeavyPyramid --run-dir ABSOLUTE_PATH; "
            "see docs/GCP_BENCHMARKS.md");
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
