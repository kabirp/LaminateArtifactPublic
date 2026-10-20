/// @file base_report_summary.cpp
/// @brief Render a completed Base benchmark record as readable Markdown.

#include "run_lifecycle_lock.hpp"

#include "laminate/bench/host_resource_budget.hpp"
#include "laminate/bench/payload_profile.hpp"
#include "laminate/params.hpp"
#include "laminate/gkr/claims.hpp"
#include "laminate/basefold/foldable.hpp"
#include "laminate/payload/fixtures/workloads.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <locale>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace {

constexpr std::uintmax_t kMaximumReportBytes = 64ULL << 20U;
constexpr std::string_view kRendererMarker =
    "<!-- laminate-base-summary-v1 -->\n";
constexpr std::string_view kSavedResponseMarker =
    "<!-- laminate-base-saved-response-v1 -->\n";

struct Options {
    std::optional<std::filesystem::path> run_directory;
    std::optional<std::string> variant;
    std::optional<std::string> profile;
    std::optional<std::filesystem::path> output;
    std::optional<std::filesystem::path> saved_response_directory;
};

void print_usage(std::ostream &output) {
    output << "Usage: laminate_base_report_summary "
              "--run-dir RUN "
              "[--variant base] "
              "[--profile quick|target-balancedLaned|target-mulHeavyPyramid] "
              "[--output summary.md] [--saved-response-dir DIAGNOSTIC]\n";
}

std::optional<Options> parse_options(int argc, char **argv) {
    Options options;
    bool run_directory_seen = false;
    bool variant_seen = false;
    bool profile_seen = false;
    bool output_seen = false;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help") {
            print_usage(std::cout);
            return std::nullopt;
        }
        if (index + 1 >= argc) {
            throw std::invalid_argument(std::string(argument) +
                                        " expects a path");
        }
        const std::filesystem::path value(argv[++index]);
        if (value.empty()) {
            throw std::invalid_argument(std::string(argument) +
                                        " expects a nonempty path");
        }
        if (argument == "--run-dir") {
            if (run_directory_seen) {
                throw std::invalid_argument(
                    "--run-dir was specified twice");
            }
            run_directory_seen = true;
            options.run_directory = value;
        } else if (argument == "--variant") {
            if (variant_seen) {
                throw std::invalid_argument(
                    "--variant was specified twice");
            }
            variant_seen = true;
            options.variant = value.string();
            if (*options.variant != "base") {
                throw std::invalid_argument(
                    "--variant must be base");
            }
        } else if (argument == "--profile") {
            if (profile_seen) {
                throw std::invalid_argument(
                    "--profile was specified twice");
            }
            profile_seen = true;
            options.profile = value.string();
            if (*options.profile != "quick" &&
                *options.profile != "target-balancedLaned" &&
                *options.profile != "target-mulHeavyPyramid") {
                throw std::invalid_argument(
                    "--profile must be quick, target-balancedLaned, or "
                    "target-mulHeavyPyramid");
            }
        } else if (argument == "--output") {
            if (output_seen) {
                throw std::invalid_argument("--output was specified twice");
            }
            output_seen = true;
            options.output = value;
        } else if (argument == "--saved-response-dir") {
            if (options.saved_response_directory)
                throw std::invalid_argument("--saved-response-dir was specified twice");
            options.saved_response_directory = value;
        } else {
            throw std::invalid_argument("unknown option: " +
                                        std::string(argument));
        }
    }
    if (!run_directory_seen) {
        throw std::invalid_argument("--run-dir is required");
    }
    return options;
}

bool valid_key(std::string_view key) {
    if (key.empty()) {
        return false;
    }
    return std::all_of(key.begin(), key.end(), [](unsigned char character) {
        return (character >= 'a' && character <= 'z') ||
               (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9') || character == '.' ||
               character == '_' || character == '-';
    });
}

class Report {
  public:
    void insert(std::string key, std::string value, std::size_t line) {
        if (!fields_.emplace(std::move(key), std::move(value)).second) {
            throw std::runtime_error("duplicate key on line " +
                                     std::to_string(line));
        }
    }

    std::optional<std::string_view> find(std::string_view key) const {
        const auto found = fields_.find(key);
        if (found == fields_.end()) {
            return std::nullopt;
        }
        return found->second;
    }

    std::string_view require(std::string_view key) const {
        const auto value = find(key);
        if (!value) {
            throw std::runtime_error("missing required report field: " +
                                     std::string(key));
        }
        return *value;
    }

    std::optional<std::uint64_t> integer(std::string_view key) const {
        const auto raw = find(key);
        if (!raw) {
            return std::nullopt;
        }
        std::uint64_t value = 0;
        const auto parsed = std::from_chars(raw->data(),
                                            raw->data() + raw->size(), value);
        if (parsed.ec != std::errc{} ||
            parsed.ptr != raw->data() + raw->size()) {
            throw std::runtime_error("invalid unsigned integer in field: " +
                                     std::string(key));
        }
        return value;
    }

    std::optional<double> real(std::string_view key) const {
        const auto raw = find(key);
        if (!raw) {
            return std::nullopt;
        }
        std::istringstream input{std::string(*raw)};
        input.imbue(std::locale::classic());
        double value = 0;
        input >> std::noskipws >> value;
        if (!input.eof() || input.fail() || !std::isfinite(value) ||
            value < 0) {
            throw std::runtime_error("invalid nonnegative real in field: " +
                                     std::string(key));
        }
        return value;
    }

    void merge_equal(const Report &other, std::string_view source,
                     bool skip_format = false, bool skip_environment = false) {
        for (const auto &[key, value] : other.fields_) {
            if (skip_format && key == "format") {
                continue;
            }
            if (skip_environment && key.starts_with("environment.")) continue;
            const auto found = fields_.find(key);
            if (found == fields_.end()) {
                fields_.emplace(key, value);
            } else if (found->second != value) {
                const bool identity_field = key.starts_with("run.") ||
                    key.starts_with("parameters.") ||
                    key == "environment.git_commit" ||
                    key == "environment.git_dirty";
                if (identity_field) {
                    throw std::runtime_error(
                        "conflicting report field " + key + " in " +
                        std::string(source));
                }
            }
        }
    }

    void insert_if_missing(std::string key, std::string value) {
        fields_.try_emplace(std::move(key), std::move(value));
    }

  private:
    std::map<std::string, std::string, std::less<>> fields_;
};

Report read_key_value_report(const std::filesystem::path &path) {
    std::error_code error;
    const std::uintmax_t size = std::filesystem::file_size(path, error);
    if (error) {
        throw std::runtime_error("cannot inspect input report " +
                                 path.string() + ": " + error.message());
    }
    if (size > kMaximumReportBytes) {
        throw std::runtime_error("input report exceeds the 64 MiB limit");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot open input report");
    }

    Report report;
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        const std::size_t separator = line.find('=');
        if (line.empty() || separator == std::string::npos || separator == 0) {
            throw std::runtime_error("expected key=value on line " +
                                     std::to_string(line_number));
        }
        const std::string key = line.substr(0, separator);
        if (!valid_key(key)) {
            throw std::runtime_error("invalid key on line " +
                                     std::to_string(line_number));
        }
        std::string value = line.substr(separator + 1);
        if (value.find('\0') != std::string::npos) {
            throw std::runtime_error("NUL byte on line " +
                                     std::to_string(line_number));
        }
        report.insert(key, std::move(value), line_number);
    }
    if (input.bad()) {
        throw std::runtime_error("failed while reading input report");
    }
    if (line_number == 0) {
        throw std::runtime_error("input report is empty");
    }
    return report;
}

void require_zero_process_exit(const std::filesystem::path &path,
                               std::string_view role) {
    const Report exit = read_key_value_report(path);
    if (exit.require("process.exit_status") != "0") {
        throw std::runtime_error(std::string(role) +
                                 " process did not exit with status zero");
    }
}

struct SplitReports {
    Report setup;
    Report server;
    Report client;
    Report combined;
    std::optional<Report> setup_storage;
    std::optional<Report> server_storage;
    std::filesystem::path setup_path;
    std::filesystem::path server_path;
    std::filesystem::path client_path;
    std::filesystem::path setup_storage_path;
    std::filesystem::path server_storage_path;
    std::optional<Report> saved_response_provenance;
};

bool is_saved_response(const Report &report) {
    return report.find("recovery.kind") == "saved-response-client-remeasurement-v1";
}

std::string file_sha256(const std::filesystem::path &path) {
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) throw std::runtime_error("cannot open source artifact: " + path.string());
    try {
        struct stat metadata {};
        if (::fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
            metadata.st_size < 0 || static_cast<std::uint64_t>(metadata.st_size) > (8ULL << 30U))
            throw std::runtime_error("source artifact is outside its regular-file bound: " + path.string());
        laminate::Sha256Hasher hash;
        std::array<std::uint8_t, 64U << 10U> buffer{};
        std::uint64_t count = 0;
        for (;;) {
            const auto bytes = ::read(descriptor, buffer.data(), buffer.size());
            if (bytes < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error("cannot read source artifact: " + path.string());
            }
            if (bytes == 0) break;
            count += static_cast<std::uint64_t>(bytes);
            if (count > static_cast<std::uint64_t>(metadata.st_size))
                throw std::runtime_error("source artifact changed while hashing");
            hash.update({buffer.data(), static_cast<std::size_t>(bytes)});
        }
        if (count != static_cast<std::uint64_t>(metadata.st_size))
            throw std::runtime_error("source artifact changed while hashing");
        const auto digest = hash.finish();
        std::string result;
        for (const auto byte : digest) {
            result.push_back("0123456789abcdef"[byte >> 4U]);
            result.push_back("0123456789abcdef"[byte & 15U]);
        }
        ::close(descriptor);
        return result;
    } catch (...) {
        ::close(descriptor);
        throw;
    }
}

// Diagnostic summaries read an already completed source and never enroll it
// by creating a lifecycle file. Exclusive locking also excludes live roles.
class SavedSummarySourceLock {
  public:
    explicit SavedSummarySourceLock(const std::filesystem::path &source) {
        if (!source.is_absolute() || std::filesystem::canonical(source) != source)
            throw std::invalid_argument("saved-response source must be canonical and absolute");
        descriptor_ = ::open((source / "shared/lifecycle.lock").c_str(),
                             O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        struct stat metadata {};
        if (descriptor_ < 0 || ::fstat(descriptor_, &metadata) != 0 ||
            !S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
            (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
            ::flock(descriptor_, LOCK_EX | LOCK_NB) != 0) {
            if (descriptor_ >= 0) ::close(descriptor_);
            throw std::runtime_error("saved-response source is active or lacks a safe existing lifecycle lock");
        }
    }
    ~SavedSummarySourceLock() { ::flock(descriptor_, LOCK_UN); ::close(descriptor_); }
    SavedSummarySourceLock(const SavedSummarySourceLock &) = delete;
    SavedSummarySourceLock &operator=(const SavedSummarySourceLock &) = delete;
  private:
    int descriptor_ = -1;
};

void validate_saved_response_evidence(SplitReports &reports,
                                     const std::filesystem::path &source,
                                     const std::filesystem::path &diagnostic) {
    reports.saved_response_provenance = read_key_value_report(diagnostic / "provenance.txt");
    const Report &identity = *reports.saved_response_provenance;
    const Report &client = reports.client;
    const Report binding = read_key_value_report(source / "shared/run-binding.txt");
    if (client.require("format") != "laminate-base-saved-response-diagnostic-v1" ||
        identity.require("format") != "laminate-base-saved-response-diagnostic-v1" ||
        !is_saved_response(client) || client.require("diagnostic.result") != "PASS" ||
        std::filesystem::exists(diagnostic / "failure.txt"))
        throw std::runtime_error("saved-response diagnostic did not complete successfully");
    for (const auto *key : {"run.variant", "run.profile", "run.id"}) {
        if (binding.require(key) != reports.setup.require(key) ||
            client.require(key) != reports.setup.require(key))
            throw std::runtime_error("saved-response run binding disagrees with source reports");
    }
    if (binding.require("format") != "laminate-benchmark-run-v1" ||
        identity.require("source.run_id") != reports.setup.require("run.id") ||
        client.require("source.run_id") != reports.setup.require("run.id") ||
        identity.require("source.profile") != reports.setup.require("run.profile") ||
        identity.require("source.git_commit") != reports.setup.require("environment.git_commit") ||
        std::filesystem::path(identity.require("source.run_directory")) != source ||
        identity.require("source.setup_sha256") != file_sha256(source / "shared/setup.bin"))
        throw std::runtime_error("saved-response provenance disagrees with the source setup");
    for (const auto &[key, name] : std::array<std::pair<const char *, const char *>, 2>{{
             {"request.sha256", "cli-to-srv-request.bin"},
             {"response.sha256", "srv-to-cli-response.bin"}}}) {
        if (client.require(key) != file_sha256(source / "shared/transcript" / name))
            throw std::runtime_error("saved-response transcript digest disagrees with the source artifact");
    }
    if (read_key_value_report(source / "client/process-exit.txt").require("process.exit_status") != "1")
        throw std::runtime_error("saved-response source does not retain the original client failure");
    // A saved-response measurement cannot reconstruct the source process's
    // elapsed spans or peer wait.
    for (const auto *key : {"timing.client.started_unix_ms", "timing.client.finished_unix_ms",
                           "timing.client.request_published_unix_ms", "timing.client.process_total.wall_ms",
                           "timing.client.process_total.cpu_ms", "timing.client.wait_for_response.wall_ms",
                           "timing.client.wait_for_response.cpu_ms"})
        if (client.find(key)) throw std::runtime_error("saved-response report contains historical client timing");
}

std::uint64_t require_integer(const Report &report, std::string_view key) {
    const auto value = report.integer(key);
    if (!value) {
        throw std::runtime_error("missing required integer field: " +
                                 std::string(key));
    }
    return *value;
}

void validate_target_storage_snapshot(const Report &snapshot,
                                      std::string_view phase) {
    if (snapshot.require("format") !=
            "laminate-storage-provenance-v2" ||
        snapshot.require("storage.capture_phase") != phase) {
        throw std::runtime_error(
            "target storage provenance has the wrong format or phase");
    }
    const std::string_view captured =
        snapshot.require("storage.captured_at_utc");
    const auto decimal_digit = [&](std::size_t index) {
        return index < captured.size() && captured[index] >= '0' &&
               captured[index] <= '9';
    };
    constexpr std::array<std::size_t, 14> digit_positions{
        0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18};
    if (captured.size() != 20 || captured[4] != '-' ||
        captured[7] != '-' || captured[10] != 'T' ||
        captured[13] != ':' || captured[16] != ':' ||
        captured[19] != 'Z' ||
        !std::all_of(digit_positions.begin(), digit_positions.end(),
                     decimal_digit)) {
        throw std::runtime_error(
            "target storage provenance has a non-canonical UTC timestamp");
    }
    const std::string_view backend = snapshot.require("storage.backend");
    const bool local_ssd = backend == "google-local-ssd-raid0";
    const bool dedicated_block = backend == "dedicated-block";
    const bool shared_root = backend == "shared-root-filesystem";
    if (!local_ssd && !dedicated_block && !shared_root) {
        throw std::runtime_error(
            "target storage provenance has an unsupported backend");
    }
    const auto absolute_path = [&](std::string_view key,
                                   bool allow_root = false) {
        const std::filesystem::path path(snapshot.require(key));
        if (!path.is_absolute() ||
            (!allow_root && path == std::filesystem::path("/")) ||
            path.lexically_normal() != path) {
            throw std::runtime_error(
                "target storage provenance requires an absolute " +
                std::string(key));
        }
        return path;
    };
    const std::filesystem::path artifact_root =
        absolute_path("storage.artifact_root");
    absolute_path("storage.mount_source");
    const std::filesystem::path mount_target =
        absolute_path("storage.mount_target", shared_root);
    if (shared_root && mount_target != std::filesystem::path("/")) {
        throw std::runtime_error(
            "target shared-root storage must use / as "
            "storage.mount_target");
    }
    const auto is_strict_descendant =
        [](const std::filesystem::path &child,
           const std::filesystem::path &parent) {
            const std::filesystem::path relative =
                child.lexically_relative(parent);
            return !relative.empty() && relative != "." &&
                *relative.begin() != "..";
        };
    if (!is_strict_descendant(artifact_root, mount_target)) {
        throw std::runtime_error(
            "target artifact root is not below its recorded storage mount");
    }
    const std::string mount_options =
        ',' + std::string(snapshot.require("storage.mount_options")) + ',';
    if (snapshot.require("storage.filesystem_type") != "ext4" ||
        mount_options.find(",rw,") == std::string::npos ||
        (!shared_root &&
         mount_options.find(",noatime,") == std::string::npos)) {
        throw std::runtime_error(
            "target storage provenance does not describe the required "
            "ext4 filesystem and mount options");
    }
    const std::uint64_t total =
        require_integer(snapshot, "storage.filesystem_total_bytes");
    const std::uint64_t available =
        require_integer(snapshot, "storage.filesystem_available_bytes");
    if (total == 0 || available > total) {
        throw std::runtime_error(
            "target storage provenance has invalid filesystem capacity");
    }

    const auto validate_name_list = [&](std::string_view key,
                                        bool require_sorted_unique) {
        std::istringstream entries{std::string(snapshot.require(key))};
        std::string entry;
        std::string previous;
        std::size_t count = 0;
        while (std::getline(entries, entry, ',')) {
            if (entry.empty() ||
                (require_sorted_unique && !previous.empty() &&
                 entry <= previous)) {
                throw std::runtime_error(
                    "target storage provenance has an invalid " +
                    std::string(key));
            }
            previous = std::move(entry);
            ++count;
        }
        if (count == 0) {
            throw std::runtime_error(
                "target storage provenance has an empty " +
                std::string(key));
        }
        return count;
    };

    if (local_ssd) {
        const std::uint64_t member_count = require_integer(
            snapshot, "storage.local_ssd.raid_member_count");
        if (snapshot.require("storage.local_ssd.raid_level") != "raid0" ||
            member_count < 2 ||
            require_integer(snapshot,
                            "storage.local_ssd.raid_degraded_members") != 0 ||
            require_integer(snapshot,
                            "storage.local_ssd.raid_chunk_bytes") != 524'288 ||
            validate_name_list("storage.local_ssd.raid_members", true) !=
                member_count) {
            throw std::runtime_error(
                "target storage provenance is not a healthy Local SSD "
                "RAID0");
        }
    } else if (dedicated_block) {
        absolute_path("storage.dedicated_block.device");
        if (snapshot.require("storage.dedicated_block.device") !=
                snapshot.require("storage.mount_source") ||
            snapshot.require("storage.dedicated_block.device_type") !=
                "disk") {
            throw std::runtime_error(
                "target storage provenance does not describe a dedicated "
                "whole block device");
        }
        validate_name_list("storage.dedicated_block.device_ancestry", false);
        validate_name_list("storage.dedicated_block.protected_ancestry",
                           false);
    } else if (shared_root) {
        const std::filesystem::path shared_directory =
            absolute_path("storage.shared_root.directory");
        if (shared_directory !=
            std::filesystem::path("/var/lib/laminate-storage")) {
            throw std::runtime_error(
                "target shared-root storage must use "
                "/var/lib/laminate-storage");
        }
        if (snapshot.require("storage.shared_root.shares_os") != "true") {
            throw std::runtime_error(
                "target shared-root storage does not acknowledge shared "
                "OS filesystem and I/O");
        }
        if (artifact_root != shared_directory / "laminate-bench") {
            throw std::runtime_error(
                "target shared-root artifact storage must be exactly "
                "STORAGE/laminate-bench");
        }
    }
}

void validate_target_storage_pair(const Report &setup,
                                  const Report &server) {
    validate_target_storage_snapshot(setup, "setup-start");
    validate_target_storage_snapshot(server, "server-start");
    for (const std::string_view key : {
             "storage.backend", "storage.artifact_root", "storage.mount_source",
             "storage.mount_target", "storage.filesystem_type",
             "storage.filesystem_total_bytes",
         }) {
        if (setup.require(key) != server.require(key)) {
            throw std::runtime_error(
                "setup/server target storage provenance disagrees on " +
                std::string(key));
        }
    }
    const auto normalized_mount_options = [](const Report &snapshot) {
        std::istringstream input{
            std::string(snapshot.require("storage.mount_options"))};
        std::vector<std::string> options;
        std::string option;
        while (std::getline(input, option, ',')) {
            if (option.empty()) {
                throw std::runtime_error(
                    "target storage provenance has an empty mount option");
            }
            options.push_back(std::move(option));
        }
        std::sort(options.begin(), options.end());
        if (options.empty() ||
            std::adjacent_find(options.begin(), options.end()) !=
                options.end()) {
            throw std::runtime_error(
                "target storage provenance has duplicate mount options");
        }
        return options;
    };
    if (normalized_mount_options(setup) !=
        normalized_mount_options(server)) {
        throw std::runtime_error(
            "setup/server target storage provenance disagrees on "
            "storage.mount_options");
    }
    const std::string_view backend = setup.require("storage.backend");
    std::vector<std::string_view> backend_keys;
    if (backend == "google-local-ssd-raid0") {
        backend_keys = {
            "storage.local_ssd.raid_level",
            "storage.local_ssd.raid_member_count",
            "storage.local_ssd.raid_degraded_members",
            "storage.local_ssd.raid_chunk_bytes",
            "storage.local_ssd.raid_members"};
    } else if (backend == "dedicated-block") {
        backend_keys = {
            "storage.dedicated_block.device",
            "storage.dedicated_block.device_type",
            "storage.dedicated_block.device_ancestry",
            "storage.dedicated_block.protected_ancestry"};
    } else if (backend == "shared-root-filesystem") {
        backend_keys = {"storage.shared_root.directory",
                        "storage.shared_root.shares_os"};
    } else {
        throw std::runtime_error(
            "target storage provenance has an unsupported backend");
    }
    for (const std::string_view key : backend_keys) {
        if (setup.require(key) != server.require(key)) {
            throw std::runtime_error(
                "setup/server target storage provenance disagrees on " +
                std::string(key));
        }
    }
    if (server.require("storage.captured_at_utc") <
        setup.require("storage.captured_at_utc")) {
        throw std::runtime_error(
            "server-start storage provenance predates setup-start");
    }
}

bool uses_host_resource_budget(std::string_view profile) {
    return profile == "quick" || profile == "target-balancedLaned" ||
           profile == "target-mulHeavyPyramid";
}

bool is_recovered_setup(const Report &setup) {
    return setup.find("setup.mode") == "recovered-preprocessing";
}

bool validate_setup_recovery_metadata(const Report &setup) {
    const auto mode = setup.find("setup.mode");
    if (!mode || *mode == "fresh") {
        if ((mode && setup.require("timing.setup.scope") !=
                         "complete-fresh-setup") ||
            setup.find("recovery.source_run_directory") ||
            setup.find("recovery.source_run_id") ||
            setup.find("recovery.source_git_commit") ||
            setup.find("recovery.source_setup_sha256") ||
            setup.find("recovery.source_failure") ||
            setup.find("storage.recovery_source_setup_bytes") ||
            setup.find("timing.setup.key_restoration.wall_ms") ||
            setup.find("timing.setup.key_restoration.cpu_ms")) {
            throw std::runtime_error("fresh setup contains recovery metadata");
        }
        return false;
    }
    if (!is_recovered_setup(setup)) {
        throw std::runtime_error("unsupported setup.mode");
    }
    const auto canonical_hex = [](std::string_view value, std::size_t size) {
        return value.size() == size &&
            std::all_of(value.begin(), value.end(), [](char character) {
                return (character >= '0' && character <= '9') ||
                       (character >= 'a' && character <= 'f');
            });
    };
    const std::filesystem::path source{
        setup.require("recovery.source_run_directory")};
    if (setup.require("timing.setup.scope") !=
            "recovery-only-excludes-original-preprocessing" ||
        !source.is_absolute() || source == source.root_path() ||
        source.filename().empty() || source.lexically_normal() != source ||
        !canonical_hex(setup.require("recovery.source_run_id"), 64) ||
        setup.require("recovery.source_run_id") == setup.require("run.id") ||
        !canonical_hex(setup.require("recovery.source_git_commit"), 40) ||
        !canonical_hex(setup.require("recovery.source_setup_sha256"), 64) ||
        setup.require("recovery.source_failure") !=
            "setup profile exceeds its decode limit" ||
        require_integer(setup, "storage.recovery_source_setup_bytes") == 0 ||
        !setup.real("timing.setup.key_restoration.wall_ms") ||
        !setup.real("timing.setup.key_restoration.cpu_ms") ||
        setup.find("timing.setup.key_generation.wall_ms") ||
        setup.find("timing.setup.key_generation.cpu_ms")) {
        throw std::runtime_error("invalid recovered setup provenance or timing scope");
    }
    return true;
}

void validate_base_adaptive_capacity_policy(
    const Report &setup, const Report *storage_snapshot) {
    using laminate::bench::kBenchmarkFreeDiskReserveBytes;
    using laminate::bench::kBenchmarkHostRamSafetyReserveBytes;
    const std::uint64_t observed_disk = require_integer(
        setup, "storage.host_budget.observed_available_disk_bytes");
    const std::uint64_t disk_reserve = require_integer(
        setup, "storage.host_budget.free_reserve_bytes");
    const std::uint64_t gross_live = require_integer(
        setup, "storage.host_budget.max_live_disk_bytes");
    const std::uint64_t client_private = require_integer(
        setup,
        "storage.host_budget.client_private_persistence_reserve_bytes");
    const std::uint64_t server_live = require_integer(
        setup, "storage.host_budget.server_live_disk_cap_bytes");
    const std::uint64_t configured_server_live = require_integer(
        setup, "storage.configured_live_server_cap_bytes");
    const std::uint64_t min_free = require_integer(
        setup, "storage.required_free_space_reserve_bytes");
    const std::uint64_t selected_peak = require_integer(
        setup, "storage.payload_replay_plan.selected_peak_live_bytes");
    const std::uint64_t checkpoints = require_integer(
        setup, "storage.payload_replay_plan.selected_checkpoint_bytes");
    const std::uint64_t initial = require_integer(
        setup, "work.payload_replay_plan.initial_forward_units");
    const std::uint64_t repeated = require_integer(
        setup, "work.payload_replay_plan.repeated_units");
    const std::uint64_t cumulative = require_integer(
        setup, "work.payload_replay_plan.cumulative_units");
    const std::optional<double> factor =
        setup.real("work.payload_replay_plan.cumulative_factor");
    const std::uint64_t observed_ram = require_integer(
        setup, "memory.host_budget.observed_physical_ram_bytes");
    const std::uint64_t ram_reserve = require_integer(
        setup, "memory.host_budget.safety_reserve_bytes");
    const std::uint64_t gross_resident = require_integer(
        setup, "memory.host_budget.gross_resident_budget_bytes");
    const std::uint64_t client_resident = require_integer(
        setup, "memory.host_budget.client_peak_reserve_bytes");
    const std::uint64_t server_resident = require_integer(
        setup, "memory.host_budget.server_resident_cap_bytes");
    const std::uint64_t predicted_resident = require_integer(
        setup, "storage.predicted_peak_resident_server_bytes");
    const std::uint64_t selected_resident = require_integer(
        setup, "memory.payload_replay_plan.selected_peak_resident_bytes");
    const std::uint64_t alias_cache_resident = require_integer(
        setup,
        "memory.payload_replay_plan."
        "dense_multiplication_alias_cache_peak_resident_bytes");
    const std::uint64_t concurrent_resident = require_integer(
        setup, "memory.concurrent.admitted_peak_resident_bytes");
    const std::uint64_t setup_peak_resident = require_integer(
        setup, "memory.setup.peak_rss_bytes");
    const std::uint64_t predicted_live = require_integer(
        setup, "storage.predicted_peak_live_server_bytes");
    const bool target_profile = setup.require("run.profile") != "quick";
    const bool recovered = validate_setup_recovery_metadata(setup);
    const std::uint64_t setup_available = require_integer(
        setup, "storage.observed_setup_start_available_bytes");
    // Recovery retains the original canonical planning envelope. Its source
    // artifacts may still occupy disk, or unrelated files may have been freed;
    // compare the recovery requirement with its recorded capacity observations.
    const bool setup_capacity_mismatch = recovered
        ? (setup_available < require_integer(
               setup, "storage.required_setup_start_available_bytes") ||
           (storage_snapshot != nullptr &&
            require_integer(*storage_snapshot,
                            "storage.filesystem_available_bytes") < setup_available))
        : ((storage_snapshot != nullptr &&
            require_integer(*storage_snapshot,
                            "storage.filesystem_available_bytes") < observed_disk) ||
           setup_available > observed_disk);
    if (observed_disk <= kBenchmarkFreeDiskReserveBytes ||
        disk_reserve != kBenchmarkFreeDiskReserveBytes ||
        gross_live != observed_disk - disk_reserve ||
        client_private >= gross_live ||
        server_live != gross_live - client_private ||
        configured_server_live != server_live ||
        min_free != kBenchmarkFreeDiskReserveBytes ||
        setup_capacity_mismatch ||
        observed_ram <= kBenchmarkHostRamSafetyReserveBytes ||
        ram_reserve != kBenchmarkHostRamSafetyReserveBytes ||
        gross_resident != observed_ram - ram_reserve ||
        client_resident == 0 || client_resident >= gross_resident ||
        server_resident != gross_resident - client_resident ||
        alias_cache_resident > selected_resident ||
        selected_resident > predicted_resident ||
        predicted_resident > server_resident ||
        predicted_resident >
            std::numeric_limits<std::uint64_t>::max() - client_resident ||
        concurrent_resident != predicted_resident + client_resident ||
        concurrent_resident > gross_resident ||
        setup_peak_resident > gross_resident ||
        predicted_live > server_live ||
        setup.require("storage.payload_replay_plan.selection_objective") !=
            "minimum-replay-work" ||
        selected_peak > server_live || checkpoints > selected_peak ||
        (target_profile && repeated != 0) ||
        initial == 0 || repeated >
            std::numeric_limits<std::uint64_t>::max() - initial ||
        cumulative != initial + repeated || !factor || *factor > 2.5 ||
        !std::isfinite(*factor) ||
        std::abs(*factor - static_cast<double>(cumulative) /
                               static_cast<double>(initial)) > 0.000001) {
        throw std::runtime_error(
            "Base checkpoint plan does not match its host-derived "
            "disk and RAM policy");
    }
}

std::uint64_t retained_regular_file_bytes(
    const std::filesystem::path &run_directory) {
    std::uint64_t total = 0;
    std::error_code error;
    for (std::filesystem::recursive_directory_iterator iterator(
             run_directory, std::filesystem::directory_options::none, error),
         end;
         iterator != end; iterator.increment(error)) {
        if (error) {
            throw std::runtime_error(
                "cannot inspect retained run artifacts: " + error.message());
        }
        const auto status = iterator->symlink_status(error);
        if (error) {
            throw std::runtime_error(
                "cannot inspect retained run artifact: " + error.message());
        }
        if (std::filesystem::is_symlink(status)) {
            throw std::runtime_error(
                "run directory must not contain symbolic links");
        }
        if (!std::filesystem::is_regular_file(status)) {
            continue;
        }
        const std::uintmax_t size = iterator->file_size(error);
        if (error || size > std::numeric_limits<std::uint64_t>::max() - total) {
            throw std::runtime_error(
                "retained run artifact size is unavailable or overflows");
        }
        total += static_cast<std::uint64_t>(size);
    }
    if (error) {
        throw std::runtime_error(
            "cannot inspect retained run artifacts: " + error.message());
    }
    return total;
}

void require_common_identity(const SplitReports &reports,
                             std::string_view key) {
    const std::string_view setup = reports.setup.require(key);
    const std::string_view server = reports.server.require(key);
    if (reports.saved_response_provenance && !key.starts_with("run.")) {
        if (setup != server)
            throw std::runtime_error("setup and server disagree on " + std::string(key));
        return;
    }
    const std::string_view client = reports.client.require(key);
    if (setup != server || setup != client) {
        throw std::runtime_error("setup, server, and client disagree on " +
                                 std::string(key));
    }
}

void require_role_cpu_allocation(const Report &report, bool setup) {
    const auto threading = report.require("environment.threading");
    if (setup && threading == "setup-worker-pool") {
        const auto workers = require_integer(report, "environment.worker_threads");
        const auto affinity = report.require("environment.cpu_affinity");
        std::size_t begin = 0;
        std::uint64_t count = 0;
        std::optional<std::uint64_t> previous;
        while (begin < affinity.size()) {
            const auto end = affinity.find(',', begin);
            const auto part = affinity.substr(begin, end == std::string_view::npos
                ? affinity.size() - begin : end - begin);
            std::uint64_t cpu = 0;
            const auto parsed = std::from_chars(part.data(), part.data() + part.size(), cpu);
            if (part.empty() || parsed.ec != std::errc{} ||
                parsed.ptr != part.data() + part.size() ||
                part != std::to_string(cpu) || (previous && cpu <= *previous)) {
                throw std::runtime_error("setup has an invalid CPU affinity list");
            }
            previous = cpu;
            ++count;
            if (end == std::string_view::npos) break;
            begin = end + 1;
            if (begin == affinity.size()) {
                throw std::runtime_error("setup has an invalid CPU affinity list");
            }
        }
        if (workers < 2 || workers > 256 || count != workers ||
            report.find("environment.pinned_cpu")) {
            throw std::runtime_error("setup worker count and CPU affinity are inconsistent");
        }
        return;
    }
    if (threading != "single-cpu-process" ||
        (report.find("environment.worker_threads") &&
         require_integer(report, "environment.worker_threads") != 1)) {
        throw std::runtime_error("online roles and serial setup require single-CPU execution");
    }
    const auto cpu = require_integer(report, "environment.pinned_cpu");
    if (const auto affinity = report.find("environment.cpu_affinity");
        affinity && *affinity != std::to_string(cpu)) {
        throw std::runtime_error("CPU affinity disagrees with the pinned CPU");
    }
}

void validate_profile_geometry(const Report &report) {
    struct Geometry {
        std::uint64_t depth;
        std::uint64_t width;
        std::uint64_t operations;
    };
    const std::string_view profile = report.require("run.profile");
    laminate::bench::BenchmarkPayloadProfile selected;
    try {
        selected = laminate::bench::benchmark_payload_profile(profile);
    } catch (const std::invalid_argument &) {
        throw std::runtime_error(
            "run.profile must be quick, target-balancedLaned, or "
            "target-mulHeavyPyramid");
    }
    const std::string_view workload =
        report.require("parameters.payload_workload");
    std::string_view expected_workload =
        laminate::payload::workload_name(selected.workload_kind);
    const Geometry expected{selected.depth, selected.width,
                            selected.operation_count};
    const auto require_integer = [&](std::string_view key) {
        const auto value = report.integer(key);
        if (!value) {
            throw std::runtime_error(
                "profile validation requires report field: " +
                std::string(key));
        }
        return *value;
    };
    if (require_integer("parameters.slots") !=
            laminate::kDefaultPolyModulusDegree ||
        workload != expected_workload ||
        require_integer("parameters.payload_multiplicative_depth") !=
            expected.depth ||
        require_integer("parameters.payload_width") !=
            expected.width ||
        require_integer("parameters.payload_inputs") !=
            laminate::kBenchmarkDiamondInputCiphertexts ||
        require_integer("parameters.payload_outputs") !=
            laminate::kBenchmarkDiamondOutputCiphertexts ||
        require_integer("parameters.payload_operations") !=
            expected.operations ||
        require_integer("parameters.payload_add_gates") !=
            selected.add_gates ||
        require_integer("parameters.payload_add_plain_gates") !=
            selected.add_plain_gates ||
        require_integer("parameters.payload_mul_gates") !=
            selected.mul_gates ||
        require_integer("parameters.payload_mul_plain_gates") !=
            selected.mul_plain_gates ||
        require_integer("parameters.payload_rotate_gates") !=
            selected.rotate_gates) {
        throw std::runtime_error(
            "reported workload geometry disagrees with run.profile=" +
            std::string(profile));
    }
}

SplitReports read_split_reports(
    const std::filesystem::path &run_directory,
    const std::optional<std::filesystem::path> &saved_response_directory = std::nullopt) {
    std::error_code error;
    if (!std::filesystem::is_directory(run_directory, error) || error) {
        throw std::invalid_argument(
            "--run-dir must name an existing run directory");
    }
    SplitReports reports{
        .setup_path = run_directory / "shared" / "setup-result.txt",
        .server_path = run_directory / "server" / "result.txt",
        .client_path = saved_response_directory
            ? *saved_response_directory / "result.txt"
            : run_directory / "client" / "result.txt",
    };
    reports.setup = read_key_value_report(reports.setup_path);
    reports.server = read_key_value_report(reports.server_path);
    reports.client = read_key_value_report(reports.client_path);
    if (saved_response_directory)
        validate_saved_response_evidence(reports, run_directory, *saved_response_directory);
    const std::string_view client_format = reports.client.require("format");
    if (reports.setup.require("format") !=
            "laminate-benchmark-setup-v1" ||
        reports.server.require("format") !=
            "laminate-benchmark-server-v1" ||
        client_format != (saved_response_directory
            ? "laminate-base-saved-response-diagnostic-v1"
            : "laminate-benchmark-client-v2")) {
        throw std::runtime_error(
            "run directory contains an unsupported role-result format");
    }
    require_common_identity(reports, "run.variant");
    if (reports.setup.require("run.variant") != "base") {
        throw std::runtime_error("Base renderer requires run.variant=base");
    }
    require_common_identity(reports, "run.profile");
    require_common_identity(reports, "run.id");
    require_common_identity(reports, "protocol.gkr_claim_transition");
    if (reports.setup.require("protocol.gkr_claim_transition") !=
        laminate::gkr::kGkrClaimTransition) {
        throw std::runtime_error("unsupported protocol.gkr_claim_transition");
    }
    require_common_identity(reports, "protocol.gkr_multiplication");
    if (reports.setup.require("protocol.gkr_multiplication") !=
        laminate::gkr::kGkrMultiplicationReduction) {
        throw std::runtime_error("unsupported protocol.gkr_multiplication");
    }
    require_common_identity(reports, "environment.git_commit");
    require_common_identity(reports, "environment.git_dirty");
    require_common_identity(reports, "environment.build_type");
    require_common_identity(reports, "environment.seal_acceleration");
    if (reports.setup.find("environment.sha256_acceleration") ||
        reports.server.find("environment.sha256_acceleration") ||
        reports.client.find("environment.sha256_acceleration")) {
        require_common_identity(reports, "environment.sha256_acceleration");
    }
    require_role_cpu_allocation(reports.setup, true);
    require_role_cpu_allocation(reports.server, false);
    require_role_cpu_allocation(reports.client, false);
    reports.setup_storage_path =
        run_directory / "shared" /
        "storage-provenance.setup-start.txt";
    reports.server_storage_path =
        run_directory / "shared" /
        "storage-provenance.server-start.txt";
    if (reports.setup.require("run.profile") != "quick") {
        const auto require_regular_snapshot = [](const auto &path) {
            std::error_code status_error;
            const auto status =
                std::filesystem::symlink_status(path, status_error);
            if (status_error ||
                !std::filesystem::is_regular_file(status)) {
                throw std::runtime_error(
                    "target storage provenance is not a regular file: " +
                    path.string());
            }
        };
        require_regular_snapshot(reports.setup_storage_path);
        require_regular_snapshot(reports.server_storage_path);
        reports.setup_storage =
            read_key_value_report(reports.setup_storage_path);
        reports.server_storage =
            read_key_value_report(reports.server_storage_path);
        validate_target_storage_pair(*reports.setup_storage,
                                     *reports.server_storage);
    }
    if (uses_host_resource_budget(
            reports.setup.require("run.profile"))) {
        validate_base_adaptive_capacity_policy(
            reports.setup,
            reports.setup_storage ? &*reports.setup_storage : nullptr);
    }
    for (const std::string_view key : {
             "parameters.slots",
             "parameters.payload_multiplicative_depth",
             "parameters.payload_workload",
             "parameters.payload_width",
             "parameters.payload_inputs",
             "parameters.payload_outputs",
             "parameters.payload_operations",
             "parameters.payload_add_gates",
             "parameters.payload_add_plain_gates",
             "parameters.payload_mul_gates",
             "parameters.initial_ciphertext_modulus_bits",
             "parameters.initial_ciphertext_modulus_primes",
             "parameters.fresh_rns_limbs"}) {
        require_common_identity(reports, key);
    }
    for (const std::string_view key : {
             "parameters.payload_mul_plain_gates",
             "parameters.payload_rotate_gates"}) {
        if (reports.setup.find(key) || reports.server.find(key) ||
            reports.client.find(key)) {
            require_common_identity(reports, key);
        }
    }
    if (reports.setup.require("setup.result") != "PASS") {
        throw std::runtime_error("setup report does not contain setup PASS");
    }
    if (reports.server.require("server.result") != "PASS") {
        throw std::runtime_error(
            "server report does not contain server PASS");
    }
    if (reports.client.require("verification.result") != "PASS") {
        throw std::runtime_error(
            "client report does not contain verification PASS");
    }
    require_zero_process_exit(
        run_directory / "shared" / "setup-process-exit.txt", "setup");
    require_zero_process_exit(
        run_directory / "server" / "process-exit.txt", "server");
    require_zero_process_exit(
        saved_response_directory ? *saved_response_directory / "process-exit.txt"
                                 : run_directory / "client" / "process-exit.txt", "client");
    reports.combined = reports.setup;
    reports.combined.merge_equal(reports.server, "server result", true);
    reports.combined.merge_equal(reports.client, "client result", true,
                                  saved_response_directory.has_value());
    reports.combined.insert_if_missing(
        "storage.retained_run_bytes_at_summary",
        std::to_string(retained_regular_file_bytes(run_directory)));
    reports.combined.insert_if_missing(
        "process.setup.exit_status", "0");
    reports.combined.insert_if_missing(
        "process.server.exit_status", "0");
    reports.combined.insert_if_missing(
        "process.client.exit_status", "0");
    if (reports.combined.require("parameters.gate_mle_profile") !=
            "wide-local-adjoint-foldable" ||
        reports.combined.integer("parameters.gate_mle_basefold_log_rate") !=
            laminate::kGateMleBaseFoldLogRate ||
        reports.combined.integer("parameters.gate_mle_basefold_queries") !=
            laminate::basefold::foldable::kDefaultQueries) {
        throw std::runtime_error("unsupported affine gate-opening policy");
    }
    validate_profile_geometry(reports.combined);
    return reports;
}

std::string comma_integer(std::uint64_t value) {
    std::string digits = std::to_string(value);
    for (std::ptrdiff_t index =
             static_cast<std::ptrdiff_t>(digits.size()) - 3;
         index > 0; index -= 3) {
        digits.insert(static_cast<std::size_t>(index), 1, ',');
    }
    return digits;
}

std::string comma_decimal(std::string_view raw) {
    const std::size_t decimal = raw.find('.');
    const std::size_t integral_end =
        decimal == std::string_view::npos ? raw.size() : decimal;
    const bool negative = !raw.empty() && raw.front() == '-';
    const std::size_t first_digit = negative ? 1 : 0;
    std::string result(raw);
    for (std::ptrdiff_t index =
             static_cast<std::ptrdiff_t>(integral_end) - 3;
         index > static_cast<std::ptrdiff_t>(first_digit); index -= 3) {
        result.insert(static_cast<std::size_t>(index), 1, ',');
    }
    return result;
}

std::string fixed(double value, int precision) {
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << std::fixed << std::setprecision(precision) << value;
    return output.str();
}

std::string format_bytes(std::uint64_t bytes) {
    static constexpr std::array<const char *, 5> units{
        "bytes", "KiB", "MiB", "GiB", "TiB"};
    long double scaled = static_cast<long double>(bytes);
    std::size_t unit = 0;
    while (scaled >= 1024.0L && unit + 1 < units.size()) {
        scaled /= 1024.0L;
        ++unit;
    }
    if (unit == 0) {
        return comma_integer(bytes) + (bytes == 1 ? " byte" : " bytes");
    }
    return fixed(static_cast<double>(scaled), 2) + ' ' + units[unit] +
           " (" + comma_integer(bytes) + " bytes)";
}

std::string format_duration(double milliseconds, std::string_view raw) {
    std::ostringstream human;
    human.imbue(std::locale::classic());
    human << std::fixed << std::setprecision(3);
    if (milliseconds < 1000.0) {
        human << milliseconds << " ms";
    } else {
        const double seconds = milliseconds / 1000.0;
        const auto whole_seconds = static_cast<std::uint64_t>(seconds);
        const std::uint64_t hours = whole_seconds / 3600;
        const std::uint64_t minutes = (whole_seconds % 3600) / 60;
        const double remaining = seconds -
                                 static_cast<double>(hours * 3600 +
                                                     minutes * 60);
        if (hours != 0) {
            human << hours << "h ";
        }
        if (hours != 0 || minutes != 0) {
            human << minutes << "m ";
        }
        human << remaining << 's';
    }
    return human.str() + " (" + comma_decimal(raw) + " ms)";
}

std::string markdown_escape(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (const char character : value) {
        if (character == '|' || character == '\\') {
            result.push_back('\\');
        }
        result.push_back(character);
    }
    return result;
}

std::string text_or_missing(const Report &report, std::string_view key) {
    const auto value = report.find(key);
    return value ? markdown_escape(*value) : "not reported";
}

std::string bytes_or_missing(const Report &report, std::string_view key) {
    const auto value = report.integer(key);
    return value ? format_bytes(*value) : "not reported";
}

std::optional<std::string_view> first_text(
    const Report &report,
    std::initializer_list<std::string_view> keys) {
    for (const std::string_view key : keys) {
        if (const auto value = report.find(key)) {
            return value;
        }
    }
    return std::nullopt;
}

std::optional<std::uint64_t> first_integer(
    const Report &report,
    std::initializer_list<std::string_view> keys) {
    for (const std::string_view key : keys) {
        if (report.find(key)) {
            return report.integer(key);
        }
    }
    return std::nullopt;
}

std::string first_text_or_missing(
    const Report &report,
    std::initializer_list<std::string_view> keys) {
    const auto value = first_text(report, keys);
    return value ? markdown_escape(*value) : "not reported";
}

std::string first_bytes_or_missing(
    const Report &report,
    std::initializer_list<std::string_view> keys) {
    const auto value = first_integer(report, keys);
    return value ? format_bytes(*value) : "not reported";
}

struct TimingValue {
    double wall_ms = 0;
    double cpu_ms = 0;
    std::string_view wall_raw;
    std::string_view cpu_raw;
};

struct TimingAmount {
    double wall_ms = 0;
    double cpu_ms = 0;
};

std::optional<TimingValue> first_timing(
    const Report &report,
    std::initializer_list<std::string_view> prefixes) {
    for (const std::string_view prefix : prefixes) {
        for (const bool direct_prefix : {false, true}) {
            const std::string base =
                direct_prefix ? std::string(prefix)
                              : "timing." + std::string(prefix);
            const std::string wall_key = base + ".wall_ms";
            const std::string cpu_key = base + ".cpu_ms";
            const auto wall_raw = report.find(wall_key);
            const auto cpu_raw = report.find(cpu_key);
            if (!wall_raw && !cpu_raw) {
                continue;
            }
            if (!wall_raw || !cpu_raw) {
                throw std::runtime_error(
                    "timing must report both wall and CPU milliseconds: " +
                    std::string(prefix));
            }
            return TimingValue{.wall_ms = *report.real(wall_key),
                               .cpu_ms = *report.real(cpu_key),
                               .wall_raw = *wall_raw,
                               .cpu_raw = *cpu_raw};
        }
    }
    return std::nullopt;
}

using ClientComputationLedger = std::map<std::string_view, TimingValue>;

std::optional<ClientComputationLedger> client_computation_ledger(const Report &report) {
    constexpr std::array<std::string_view, 11> fields{
        "encrypt_inputs", "decrypt_output", "computation_total", "per_request_total",
        "verify.vcoed", "verify.gkr", "verify.gkr.transcript_recovery",
        "verify.gkr.plaintext", "verify.terminal_input_mle",
        "verify.transcript_packing_snark", "verify.well_formedness_noise"};
    const auto marker = report.find("timing.client.computation.schema");
    if (!marker) {
        throw std::runtime_error("client computation timing schema is missing");
    }
    if (*marker != "vcoed-client-computation-v1")
        throw std::runtime_error("unknown client computation timing schema");
    ClientComputationLedger ledger;
    for (const auto field : fields) {
        const auto timing = first_timing(report, {"client." + std::string(field)});
        if (!timing) throw std::runtime_error("missing client computation timing: " + std::string(field));
        ledger.emplace(field, *timing);
    }
    const auto check_sum = [&](std::string_view total,
                               std::initializer_list<std::string_view> children) {
        double wall = 0, cpu = 0;
        for (const auto child : children) {
            wall += ledger.at(child).wall_ms;
            cpu += ledger.at(child).cpu_ms;
        }
        const double tolerance = 0.0005 * (children.size() + 1U) + 1e-9;
        if (std::abs(ledger.at(total).wall_ms - wall) > tolerance ||
            std::abs(ledger.at(total).cpu_ms - cpu) > tolerance)
            throw std::runtime_error("client computation ledger does not reconcile " + std::string(total));
    };
    check_sum("verify.gkr", {"verify.gkr.transcript_recovery", "verify.gkr.plaintext"});
    check_sum("verify.vcoed", {"verify.gkr", "verify.terminal_input_mle",
                              "verify.transcript_packing_snark", "verify.well_formedness_noise"});
    check_sum("computation_total", {"encrypt_inputs", "decrypt_output", "verify.vcoed"});
    check_sum("per_request_total", {"computation_total"});
    for (const auto field : {"verify.transcript_packing_snark", "verify.well_formedness_noise"}) {
        if (ledger.at(field).wall_ms != 0 || ledger.at(field).cpu_ms != 0)
            throw std::runtime_error("Base client reports packed-only verification work");
    }
    if (report.require("timing.client.per_request_total.scope") !=
        "input-encryption-output-decryption-vcoed-verification;excludes-preprocessing-load-transport-peer-wait-and-output-noise-audit")
        throw std::runtime_error("unexpected client computation cost boundary");
    return ledger;
}

std::optional<std::uint64_t>
checked_sum(std::initializer_list<std::optional<std::uint64_t>> values,
            std::string_view description) {
    std::uint64_t result = 0;
    for (const auto value : values) {
        if (!value) {
            return std::nullopt;
        }
        if (*value > std::numeric_limits<std::uint64_t>::max() - result) {
            throw std::overflow_error(std::string(description) +
                                      " overflows");
        }
        result += *value;
    }
    return result;
}

void require_equal_if_present(const Report &report, std::string_view total,
                              std::initializer_list<std::string_view> parts) {
    const auto total_value = report.integer(total);
    if (!total_value) {
        return;
    }
    std::uint64_t sum = 0;
    for (const std::string_view part : parts) {
        const auto value = report.integer(part);
        if (!value) {
            return;
        }
        if (*value > std::numeric_limits<std::uint64_t>::max() - sum) {
            throw std::overflow_error("proof byte breakdown overflows");
        }
        sum += *value;
    }
    if (sum != *total_value) {
        throw std::runtime_error("inconsistent byte breakdown for field: " +
                                 std::string(total));
    }
}

void validate_breakdowns(const Report &report) {
    require_equal_if_present(
        report, "proof.response.total_bytes",
        {"proof.response.inner_transport_bytes",
         "proof.response.framing_bytes"});
    if (report.find("proof.response.output_statement_bytes")) {
        require_equal_if_present(
            report, "proof.response.framing_bytes",
            {"proof.response.envelope_header_bytes",
             "proof.response.public_bindings_bytes",
             "proof.response.output_statement_bytes",
             "proof.response.inner_length_prefix_bytes"});
    } else {
        require_equal_if_present(
            report, "proof.response.framing_bytes",
            {"proof.response.envelope_header_bytes",
             "proof.response.public_bindings_bytes",
             "proof.response.duplicated_output_claim_bytes",
             "proof.response.inner_length_prefix_bytes"});
    }
    require_equal_if_present(
        report, "proof.transport.total_bytes",
        {"proof.transport.statement_and_metadata_bytes",
         "proof.transport.round_message_bytes",
         "proof.transport.terminal_message_bytes",
         "proof.transport.partial_gate_mle_bytes",
         "proof.transport.gate_mle_opening_bytes"});
    require_equal_if_present(
        report, "proof.canonical.total_bytes",
        {"proof.canonical.statement_and_metadata_bytes",
         "proof.canonical.round_message_bytes",
         "proof.canonical.terminal_message_bytes",
         "proof.canonical.partial_gate_mle_bytes",
         "proof.canonical.gate_mle_opening_bytes"});
    const auto wire = report.integer("wire.proof_response_bytes");
    const auto response = report.integer("proof.response.total_bytes");
    if (wire && response && *wire != *response) {
        throw std::runtime_error(
            "wire and proof-response byte totals disagree");
    }
    const auto one_round_wire = report.integer("wire.response_bytes");
    if (one_round_wire && response && *one_round_wire != *response) {
        throw std::runtime_error(
            "response file and proof-response byte totals disagree");
    }
    const auto response_inner =
        report.integer("proof.response.inner_transport_bytes");
    const auto transport = report.integer("proof.transport.total_bytes");
    if (response_inner && transport && *response_inner != *transport) {
        throw std::runtime_error(
            "response and inner-transport byte totals disagree");
    }
}

using Row = std::vector<std::string>;

void table(std::ostream &output, const std::vector<std::string> &headings,
           const std::vector<Row> &rows) {
    output << '|';
    for (const std::string &heading : headings) {
        output << ' ' << heading << " |";
    }
    output << "\n|";
    for (std::size_t index = 0; index < headings.size(); ++index) {
        output << " --- |";
    }
    output << '\n';
    for (const Row &row : rows) {
        if (row.size() != headings.size()) {
            throw std::logic_error("Markdown table row has wrong width");
        }
        output << '|';
        for (const std::string &cell : row) {
            output << ' ' << cell << " |";
        }
        output << '\n';
    }
    output << '\n';
}

std::string workload(const Report &report) {
    std::vector<std::string> terms;
    if (const auto kind = report.find("parameters.payload_workload")) {
        terms.push_back("kind=" + std::string(*kind));
    }
    const auto append = [&](std::string_view name,
                            std::optional<std::uint64_t> value) {
        if (value) {
            terms.push_back(std::string(name) + '=' +
                            comma_integer(*value));
        }
    };
    const auto first_integer = [&](std::initializer_list<std::string_view>
                                       keys) -> std::optional<std::uint64_t> {
        for (const std::string_view key : keys) {
            if (report.find(key)) {
                return report.integer(key);
            }
        }
        return std::nullopt;
    };
    append("N", report.integer("parameters.slots"));
    append("D", first_integer(
                    {"parameters.payload_multiplicative_depth",
                     "diagnostic.payload_multiplicative_depth",
                     "target.payload_multiplicative_depth"}));
    append("W", first_integer({"parameters.payload_width",
                                "parameters.diamond_middle_width",
                                "diagnostic.diamond_middle_width",
                                "target.diamond_middle_width"}));
    append("I", report.integer("parameters.payload_inputs"));
    append("O", report.integer("parameters.payload_outputs"));
    append("n_FHE", report.integer("parameters.payload_operations"));
    append("Add", report.integer("parameters.payload_add_gates"));
    append("AddPlain",
           report.integer("parameters.payload_add_plain_gates"));
    append("Mul", report.integer("parameters.payload_mul_gates"));
    append("MulPlain", report.integer("parameters.payload_mul_plain_gates"));
    append("Rotate", report.integer("parameters.payload_rotate_gates"));
    if (terms.empty()) {
        return "not reported";
    }
    std::ostringstream output;
    for (std::size_t index = 0; index < terms.size(); ++index) {
        if (index != 0) {
            output << ", ";
        }
        output << terms[index];
    }
    return output.str();
}

std::string modulus_summary(const Report &report) {
    const auto bits = first_integer(
        report, {"parameters.initial_ciphertext_modulus_bits",
                 "parameters.fresh_modulus_product_bits"});
    const auto limbs = first_integer(
        report, {"parameters.initial_ciphertext_modulus_prime_count",
                 "parameters.fresh_rns_limbs"});
    if (!bits) {
        return "not reported";
    }
    std::string result = comma_integer(*bits) + " bits";
    if (limbs) {
        result += " across " + comma_integer(*limbs) + " data primes";
    }
    return result;
}

std::string key_modulus_summary(const Report &report) {
    const auto bits = report.integer("parameters.key_modulus_product_bits");
    return bits ? comma_integer(*bits) + " bits (data and special prime)"
                : "not reported";
}

std::string base_proof_schedule_summary(const Report &report) {
    const auto policy = report.find("parameters.base_proof_schedule_policy");
    const auto limbs =
        report.integer("parameters.base_proof_ingress_rns_limbs");
    if (!policy || !limbs) {
        return "not reported";
    }
    return std::string(*policy) + "; " + comma_integer(*limbs) +
           " RNS limbs at every proof source";
}

std::vector<std::uint64_t> parse_decimal_list(const Report &report,
                                              std::string_view key) {
    const std::string_view raw = report.require(key);
    std::vector<std::uint64_t> result;
    std::size_t begin = 0;
    while (begin < raw.size()) {
        const std::size_t separator = raw.find(',', begin);
        const std::size_t end = separator == std::string_view::npos
                                    ? raw.size()
                                    : separator;
        if (end == begin) {
            throw std::runtime_error("empty entry in report field: " +
                                     std::string(key));
        }
        std::uint64_t value = 0;
        const auto parsed = std::from_chars(raw.data() + begin,
                                            raw.data() + end, value);
        if (parsed.ec != std::errc{} || parsed.ptr != raw.data() + end ||
            value == 0) {
            throw std::runtime_error("invalid decimal list in report field: " +
                                     std::string(key));
        }
        result.push_back(value);
        if (separator == std::string_view::npos) {
            break;
        }
        begin = separator + 1;
    }
    if (result.empty()) {
        throw std::runtime_error("empty decimal list in report field: " +
                                 std::string(key));
    }
    return result;
}

std::string data_prime_schedule(const Report &report) {
    if (!report.find("parameters.initial_ciphertext_modulus_primes")) {
        return "not reported";
    }
    const std::vector<std::uint64_t> primes = parse_decimal_list(
        report, "parameters.initial_ciphertext_modulus_primes");
    const auto expected_count = first_integer(
        report, {"parameters.fresh_rns_limbs",
                 "parameters.initial_ciphertext_modulus_prime_count"});
    if (expected_count && *expected_count != primes.size()) {
        throw std::runtime_error(
            "data-prime schedule length disagrees with the reported limb "
            "count");
    }
    std::ostringstream output;
    for (std::size_t index = 0; index < primes.size(); ++index) {
        if (index != 0) {
            output << ", ";
        }
        output << "q" << index << '=' << primes[index] << " ("
               << std::bit_width(primes[index]) << " bits)";
    }
    output << "; bottom-to-top (q0 survives every modulus switch)";
    return output.str();
}

std::string fhe_parameter_policy(const Report &report) {
    const auto plaintext_modulus =
        report.integer("parameters.plaintext_modulus");
    const auto security = report.find("parameters.security");
    if (!plaintext_modulus && !security) {
        return "not reported";
    }
    std::string result;
    if (plaintext_modulus) {
        result = "t=" + comma_integer(*plaintext_modulus);
    }
    if (security) {
        if (!result.empty()) {
            result += "; ";
        }
        result += markdown_escape(*security);
    }
    return result;
}

std::string formatted_duration(double milliseconds) {
    return format_duration(milliseconds, fixed(milliseconds, 3));
}

struct OperationRow {
    std::string_view key;
    std::string_view label;
};

std::string operation_cell(const Report &report,
                           const std::string &prefix) {
    const auto calls = report.integer(prefix + "calls");
    const auto limbs = report.integer(prefix + "limb_operations");
    const std::string by_rns =
        text_or_missing(report, prefix + "by_rns_limb");
    const std::string call_text =
        calls ? comma_integer(*calls) + (*calls == 1 ? " call" : " calls")
              : "not reported";
    const std::string limb_text =
        limbs ? comma_integer(*limbs) +
                    (*limbs == 1 ? " limb-op" : " limb-ops")
              : "not reported";
    return call_text + "; " + limb_text + "; RNS " + by_rns;
}

std::string operation_prefix(
    const Report &report,
    std::initializer_list<std::string_view> roots,
    std::string_view operation) {
    for (const std::string_view root : roots) {
        const std::string prefix = std::string(root) +
                                   std::string(operation) + '.';
        if (report.find(prefix + "calls") ||
            report.find(prefix + "limb_operations")) {
            return prefix;
        }
    }
    return std::string(*roots.begin()) + std::string(operation) + '.';
}

void render_server_operations(std::ostream &output, const Report &report) {
    static constexpr std::array<OperationRow, 16> operations{{
        {"encrypt", "Encrypt"},
        {"decrypt", "Decrypt"},
        {"negate", "Negate"},
        {"add", "Ciphertext add"},
        {"sub", "Ciphertext subtract"},
        {"mul_no_relin", "Ciphertext multiply (before relinearization)"},
        {"relinearize", "Relinearize"},
        {"add_plain", "Add plaintext"},
        {"mul_plain_scalar", "Multiply by scalar plaintext"},
        {"mul_plain_vector", "Multiply by vector plaintext"},
        {"rotate", "Rotate"},
        {"mod_switch", "Modulus switch"},
        {"logical_ext_add", "Logical extension-field add"},
        {"logical_ext_sub", "Logical extension-field subtract"},
        {"logical_ext_mul", "Logical extension-field multiply"},
        {"logical_ext_mul_plain",
         "Logical extension-field plaintext multiply"},
    }};
    std::vector<Row> rows;
    for (const OperationRow &operation : operations) {
        const std::string evaluation_prefix =
            operation_prefix(
                report,
                {"operations.server_payload_evaluation.",
                 "operations.server_checkpoint_evaluation."},
                operation.key);
        const std::string proving_prefix =
            operation_prefix(
                report,
                {"operations.server_gkr_proving."},
                operation.key);
        const auto evaluation_calls =
            report.integer(evaluation_prefix + "calls");
        const auto evaluation_limbs =
            report.integer(evaluation_prefix + "limb_operations");
        const auto proving_calls = report.integer(proving_prefix + "calls");
        const auto proving_limbs =
            report.integer(proving_prefix + "limb_operations");
        if (evaluation_calls.value_or(0) == 0 &&
            evaluation_limbs.value_or(0) == 0 &&
            proving_calls.value_or(0) == 0 &&
            proving_limbs.value_or(0) == 0) {
            continue;
        }
        rows.push_back(
            {std::string(operation.label),
             operation_cell(report, evaluation_prefix),
             operation_cell(report, proving_prefix)});
    }
    output << "## Server FHE operation ledger\n\n";
    if (rows.empty()) {
        output << "No nonzero server operation rows were reported.\n\n";
        return;
    }
    const bool split_names = report.find(
        "operations.server_payload_evaluation.mul_no_relin.calls") ||
        report.find("run.id");
    table(output, {"Operation",
                   split_names ? "Payload evaluation"
                               : "Payload/checkpoint evaluation",
                   split_names ? "GKR proving" : "File-backed Base proof"},
          rows);
    output << "A by-RNS entry `k:c` means `c` calls executed with `k` data "
              "limbs. All-zero operations are omitted. Logical extension-"
              "field rows describe wrapper operations and are not additive "
              "to the underlying SEAL primitive rows. Operation counts show "
              "the arithmetic schedule; CPU/wall ratios and profiling are "
              "needed to attribute elapsed time.\n\n";
}

std::string variant_title(std::string_view variant) {
    if (variant == "base") {
        return "Base";
    }
    if (variant == "folded") {
        return "Folded";
    }
    if (variant == "laned") {
        return "Laned";
    }
    return markdown_escape(variant);
}

std::string profile_description(std::string_view profile) {
    if (profile == "quick") {
        return "quick: simple, short validation run";
    }
    if (profile == "target-balancedLaned") {
        return "target-balancedLaned: balanced laned evaluation";
    }
    if (profile == "target-mulHeavyPyramid") {
        return "target-mulHeavyPyramid: input-heavy multiplication pyramid";
    }
    return markdown_escape(profile);
}

std::string timing_pair_or_missing(
    const Report &report,
    std::initializer_list<std::string_view> prefixes) {
    const auto timing = first_timing(report, prefixes);
    if (!timing) {
        return "not reported";
    }
    return format_duration(timing->wall_ms, timing->wall_raw) +
           " wall; " +
           format_duration(timing->cpu_ms, timing->cpu_raw) + " CPU";
}

std::optional<TimingAmount> client_per_request_timing(
    const Report &report);

void render_client_computation(std::ostream &output, const Report &report) {
    const auto ledger = client_computation_ledger(report);
    const std::array<std::pair<std::string_view, std::string_view>, 8> components{{
        {"Per-request client computation", "computation_total"},
        {"Input encryption", "encrypt_inputs"},
        {"Output decryption", "decrypt_output"},
        {"VCoED proof verification", "verify.vcoed"},
        {"↳ GKR proof verification", "verify.gkr"},
        {"↳↳ Transcript recovery (FS, decryption, plaintext assembly)", "verify.gkr.transcript_recovery"},
        {"↳↳ Plaintext GKR and affine gate-opening checks", "verify.gkr.plaintext"},
        {"↳ Terminal input MLE", "verify.terminal_input_mle"},
    }};
    std::vector<Row> rows;
    for (const auto &[label, field] : components) {
        const auto &timing = ledger->at(field);
        rows.push_back({std::string(label),
            format_duration(timing.wall_ms, timing.wall_raw),
            format_duration(timing.cpu_ms, timing.cpu_raw)});
    }
    output << "## Client computation\n\n";
    table(output, {"Component", "Wall", "CPU"}, rows);
    output << "Client computation is input encryption + output decryption + "
              "VCoED proof verification. Preprocessing RAM loading, session "
              "binding, transport, and peer waiting are excluded. Verification "
              "rows form a hierarchy: add siblings only.\n\n";
}

struct SplitTimingRow {
    std::string label;
    std::string classification;
    std::vector<std::string_view> prefixes;
    bool client_per_request_total = false;
};


void render_split_timing_table(std::ostream &output,
                               std::string_view heading,
                               const Report &report,
                               const std::vector<SplitTimingRow> &rows) {
    output << "### " << heading << "\n\n";
    std::vector<Row> rendered;
    rendered.reserve(rows.size());
    for (const SplitTimingRow &row : rows) {
        std::optional<TimingValue> timing;
        for (const std::string_view prefix : row.prefixes) {
            timing = first_timing(report, {prefix});
            if (timing) {
                break;
            }
        }
        const auto derived = row.client_per_request_total
            ? client_per_request_timing(report)
            : std::nullopt;
        const double wall_ms = derived
            ? derived->wall_ms
            : timing ? timing->wall_ms : 0;
        const double cpu_ms = derived
            ? derived->cpu_ms
            : timing ? timing->cpu_ms : 0;
        const bool present = derived.has_value() || timing.has_value();
        rendered.push_back(
            {row.label, row.classification,
             derived
                 ? format_duration(wall_ms, fixed(wall_ms, 6))
                 : timing
                     ? format_duration(timing->wall_ms, timing->wall_raw)
                     : "not reported",
             derived
                 ? format_duration(cpu_ms, fixed(cpu_ms, 6))
                 : timing
                     ? format_duration(timing->cpu_ms, timing->cpu_raw)
                     : "not reported",
             present && wall_ms != 0
                 ? fixed(100.0 * cpu_ms / wall_ms, 2) + "%"
                 : "not reported"});
    }
    table(output,
          {"Component", "Accounting", "Wall time", "CPU time",
           "CPU/wall"},
          rendered);
}

void render_client_verifier_breakdown(std::ostream &output,
                                      const Report &report) {
    const auto layer_count =
        report.integer("timing.client.verify.layer_count");
    const auto decryption =
        first_timing(report, {"client.verify.decryption_and_unpack"});
    const auto gate_opening =
        first_timing(report, {"client.verify.gate_mle_opening"});
    if (!layer_count && !decryption && !gate_opening) {
        return;
    }
    if (!layer_count || !decryption || !gate_opening) {
        throw std::runtime_error(
            "client verifier diagnostics are incomplete");
    }
    if (*layer_count > 1024) {
        throw std::runtime_error(
            "client verifier diagnostic layer count exceeds report limit");
    }

    const auto timing_row = [](std::string phase, std::string layer,
                               std::string kind,
                               const TimingValue &timing) {
        return Row{
            std::move(phase), std::move(layer), std::move(kind),
            format_duration(timing.wall_ms, timing.wall_raw),
            format_duration(timing.cpu_ms, timing.cpu_raw),
            timing.wall_ms > 0
                ? fixed(100.0 * timing.cpu_ms / timing.wall_ms, 2) + "%"
                : "not reported"};
    };

    std::vector<Row> rows;
    rows.reserve(static_cast<std::size_t>(*layer_count) + 2U);
    rows.push_back(timing_row("Decrypt and unpack proof messages", "—",
                              "all messages", *decryption));
    for (std::uint64_t index = 0; index < *layer_count; ++index) {
        const std::string prefix =
            "client.verify.layer." + std::to_string(index);
        const auto circuit_layer =
            report.integer("timing." + prefix + ".circuit_layer");
        const auto kind = report.find("timing." + prefix + ".kind");
        const auto timing = first_timing(report, {prefix});
        if (!circuit_layer || !kind || !timing) {
            throw std::runtime_error(
                "client verifier layer diagnostic is incomplete");
        }
        rows.push_back(timing_row(
            "Verify layer reduction " + comma_integer(index + 1U),
            comma_integer(*circuit_layer), markdown_escape(*kind),
            *timing));
    }
    rows.push_back(timing_row("Finish Gate-MLE opening", "—",
                              "terminal", *gate_opening));

    output << "### Client GKR verifier detail\n\n";
    table(output,
          {"Verifier span", "Circuit layer", "Kind", "Wall time",
           "CPU time", "CPU/wall"},
          rows);
    output << "These diagnostic spans are nested inside the top-level GKR "
              "verification timer. Decryption overlaps the layer spans, so "
              "the rows are explanatory and must not be added to one "
              "another or to the per-request client total. The terminal row "
              "contains the affine gate-opening checks.\n\n";
}

struct TelemetryTiming {
    double wall_ms = 0;
    double cpu_ms = 0;
    bool present = false;
};

struct BaseLayerTelemetry {
    std::string kind = "unspecified";
    TelemetryTiming replay;
    TelemetryTiming multiplication_source_build;
    TelemetryTiming sumcheck;
    TelemetryTiming reduction;
};

void add_telemetry_timing(TelemetryTiming &destination, double wall_ms,
                          double cpu_ms) {
    destination.wall_ms += wall_ms;
    destination.cpu_ms += cpu_ms;
    destination.present = true;
}

std::string telemetry_timing(const TelemetryTiming &timing) {
    if (!timing.present) {
        return "—";
    }
    return formatted_duration(timing.wall_ms) + " wall / " +
           formatted_duration(timing.cpu_ms) + " CPU";
}

void render_base_layer_telemetry(std::ostream &output,
                                 const Report &report) {
    const auto span_count = report.integer("telemetry.completed_spans");
    if (!span_count) {
        return;
    }
    if (*span_count > (1U << 20U)) {
        throw std::runtime_error("telemetry span count exceeds report limit");
    }
    std::map<std::uint64_t, BaseLayerTelemetry, std::greater<>> layers;
    for (std::uint64_t index = 0; index < *span_count; ++index) {
        const std::string prefix =
            "telemetry.span." + std::to_string(index) + '.';
        const auto stage = report.find(prefix + "stage");
        const auto reduction_layer =
            report.integer(prefix + "reduction_layer");
        const auto wall_ms = report.real(prefix + "wall_ms");
        const auto cpu_ms = report.real(prefix + "cpu_ms");
        if (!stage || !reduction_layer || !wall_ms || !cpu_ms) {
            continue;
        }
        BaseLayerTelemetry &layer = layers[*reduction_layer];
        if (const auto kind = report.find(prefix + "layer_kind")) {
            if (*kind != "unspecified") {
                layer.kind = std::string(*kind);
            }
        }
        if (*stage == "payload.replay_segment") {
            add_telemetry_timing(layer.replay, *wall_ms, *cpu_ms);
        } else if (*stage ==
                   "base.multiplication.source_artifact_build") {
            add_telemetry_timing(
                layer.multiplication_source_build, *wall_ms, *cpu_ms);
        } else if (*stage == "base.affine.sumcheck_round" ||
                   *stage == "base.multiplication.sumcheck_round") {
            add_telemetry_timing(layer.sumcheck, *wall_ms, *cpu_ms);
        } else if (*stage == "base.reduction") {
            add_telemetry_timing(layer.reduction, *wall_ms, *cpu_ms);
        }
    }
    if (layers.empty()) {
        return;
    }
    std::vector<Row> rows;
    rows.reserve(layers.size());
    for (const auto &[layer_index, timing] : layers) {
        rows.push_back({std::to_string(layer_index), timing.kind,
                        telemetry_timing(timing.replay),
                        telemetry_timing(
                            timing.multiplication_source_build),
                        telemetry_timing(timing.sumcheck),
                        telemetry_timing(timing.reduction)});
    }
    output << "### Server layer reductions\n\n";
    table(output,
          {"Layer", "Kind", "Replay segment",
           "Multiplication source build", "Sumcheck rounds",
           "Reduction total"},
          rows);
    output << "Reduction totals and replay segments are inclusive spans. "
              "Source-build and sumcheck columns explain time within those "
              "spans; the columns are not additive.\n\n";
}

struct SumcheckRoundTelemetry {
    std::uint64_t reduction_layer = 0;
    std::optional<std::uint64_t> source_layer;
    std::uint64_t round = 0;
    std::optional<std::uint64_t> round_count;
    std::optional<std::uint64_t> work_units;
    std::string kind = "unspecified";
    std::string coordinate = "—";
    std::string side = "—";
    double wall_ms = 0;
    double cpu_ms = 0;
};

void render_sumcheck_rounds(std::ostream &output, const Report &report) {
    const auto span_count = report.integer("telemetry.completed_spans");
    if (!span_count) {
        return;
    }
    if (*span_count > (1U << 20U)) {
        throw std::runtime_error("telemetry span count exceeds report limit");
    }
    std::vector<SumcheckRoundTelemetry> rounds;
    for (std::uint64_t index = 0; index < *span_count; ++index) {
        const std::string prefix =
            "telemetry.span." + std::to_string(index) + '.';
        const auto stage = report.find(prefix + "stage");
        if (!stage ||
            (*stage != "base.affine.sumcheck_round" &&
             *stage != "base.multiplication.sumcheck_round")) {
            continue;
        }
        const auto reduction_layer =
            report.integer(prefix + "reduction_layer");
        const auto round = report.integer(prefix + "round");
        const auto wall_ms = report.real(prefix + "wall_ms");
        const auto cpu_ms = report.real(prefix + "cpu_ms");
        if (!reduction_layer || !round || !wall_ms || !cpu_ms) {
            throw std::runtime_error(
                "sumcheck telemetry span is missing layer, round, wall, or "
                "CPU time");
        }
        SumcheckRoundTelemetry entry{
            .reduction_layer = *reduction_layer,
            .source_layer = report.integer(prefix + "source_layer"),
            .round = *round,
            .round_count = report.integer(prefix + "round_count"),
            .work_units = report.integer(prefix + "work_units"),
            .wall_ms = *wall_ms,
            .cpu_ms = *cpu_ms,
        };
        if (const auto kind = report.find(prefix + "layer_kind")) {
            entry.kind = std::string(*kind);
        }
        if (const auto coordinate =
                report.find(prefix + "coordinate_domain")) {
            entry.coordinate =
                *coordinate == "ciphertext_index"
                    ? "ciphertext-index"
                    : *coordinate == "slot_index" ? "slot-index"
                                                    : std::string(*coordinate);
        }
        if (const auto side = report.find(prefix + "side")) {
            entry.side = std::string(*side);
        }
        rounds.push_back(std::move(entry));
    }
    if (rounds.empty()) {
        return;
    }
    std::stable_sort(rounds.begin(), rounds.end(),
                     [](const auto &left, const auto &right) {
                         if (left.reduction_layer != right.reduction_layer) {
                             return left.reduction_layer >
                                    right.reduction_layer;
                         }
                         return left.round < right.round;
                     });
    std::vector<Row> rows;
    rows.reserve(rounds.size());
    for (const SumcheckRoundTelemetry &entry : rounds) {
        std::string round = comma_integer(entry.round + 1);
        if (entry.round_count) {
            round += "/" + comma_integer(*entry.round_count);
        } else {
            round += " (zero-based index " + comma_integer(entry.round) + ')';
        }
        rows.push_back(
            {comma_integer(entry.reduction_layer),
             entry.source_layer ? comma_integer(*entry.source_layer) : "—",
             markdown_escape(entry.kind), markdown_escape(entry.coordinate),
             round,
             markdown_escape(entry.side),
             entry.work_units ? comma_integer(*entry.work_units) : "—",
             formatted_duration(entry.wall_ms),
             formatted_duration(entry.cpu_ms),
             entry.wall_ms > 0
                 ? fixed(100.0 * entry.cpu_ms / entry.wall_ms, 2) + "%"
                 : "not reported"});
    }
    output << "### Sumcheck rounds (individual)\n\n";
    table(output,
          {"Reduction layer", "Source layer", "Kind", "Coordinate",
           "Round", "Side", "Work units", "Wall time", "CPU time",
           "CPU/wall"},
          rows);
    output << "Round numbers are displayed one-based; the telemetry stores "
              "zero-based round indices. These rows are the individual spans "
              "summed into each layer's `Sumcheck rounds` cell above.\n\n";
}

bool has_timing(const Report &report, std::string_view prefix) {
    return first_timing(report, {prefix}).has_value();
}

std::optional<TimingAmount> client_per_request_timing(
    const Report &report) {
    const auto ledger = client_computation_ledger(report);
    const auto &total = ledger->at("computation_total");
    return TimingAmount{total.wall_ms, total.cpu_ms};
}

std::string timing_pair_or_missing(
    const std::optional<TimingAmount> &timing) {
    if (!timing) {
        return "not reported";
    }
    return format_duration(timing->wall_ms, fixed(timing->wall_ms, 6)) +
           " wall; " +
           format_duration(timing->cpu_ms, fixed(timing->cpu_ms, 6)) +
           " CPU";
}

bool has_isolated_client_response_timings(const Report &report) {
    const bool has_read =
        has_timing(report, "client.read_response_file");
    const bool has_decode =
        has_timing(report, "client.decode_response");
    if (has_read != has_decode) {
        throw std::runtime_error(
            "client response timing split is incomplete");
    }
    return has_read;
}

std::vector<std::string_view> client_active_timing_prefixes(
    const Report &) {
    return {"client.encrypt_inputs", "client.decrypt_output", "client.verify.vcoed"};
}

std::optional<double> request_to_verification_elapsed_ms(
    const Report &report) {
    const auto client_finished = first_integer(
        report, {"timing.client.finished_unix_ms"});
    if (!client_finished) {
        return std::nullopt;
    }
    const auto request_published =
        report.integer("timing.client.request_published_unix_ms");
    if (!request_published || *client_finished < *request_published) {
        return std::nullopt;
    }
    return static_cast<double>(*client_finished - *request_published);
}

std::optional<double> online_path_elapsed_ms(const Report &report) {
    const auto elapsed = first_timing(report, {"client.process_total"});
    return elapsed ? std::optional<double>(elapsed->wall_ms) : std::nullopt;
}

std::optional<double> observed_run_span_ms(const Report &report) {
    const auto setup_started =
        first_integer(report, {"timing.setup.started_unix_ms"});
    const auto client_finished =
        first_integer(report, {"timing.client.finished_unix_ms"});
    if (!setup_started || !client_finished ||
        *client_finished < *setup_started) {
        return std::nullopt;
    }
    return static_cast<double>(*client_finished - *setup_started);
}

std::string computed_duration_or_missing(std::optional<double> value) {
    return value ? formatted_duration(*value) : "not reported";
}

std::string benchmark_backend(const Report &report) {
    if (const auto backend = first_text(
            report, {"environment.fhe_backend", "run.fhe_backend"})) {
        if (*backend == "seal-bgv") {
            return "seal-bgv (Microsoft SEAL BGV concrete backend)";
        }
        return markdown_escape(*backend);
    }
    if (report.require("run.variant") == "base" &&
        report.find("environment.seal_version")) {
        return "Microsoft SEAL BGV (concrete backend)";
    }
    return "not reported";
}

std::string trace_execution(const Report &report) {
    if (const auto trace = first_text(
            report, {"environment.trace_execution", "run.trace_execution"})) {
        return markdown_escape(*trace);
    }
    if (report.require("run.variant") == "base") {
        return "file-backed payload checkpoint/replay; compact live-wire "
               "artifacts; irreversible no-retry";
    }
    return "not reported";
}

std::string pinned_cpu(const Report &report) {
    return first_text_or_missing(
        report, {"environment.pinned_cpu", "environment.pinned_logical_cpu",
                 "run.pinned_cpu"});
}

std::string setup_cpu_allocation(const Report &report) {
    if (report.require("environment.threading") == "setup-worker-pool") {
        return std::string(report.require("environment.cpu_affinity"));
    }
    return pinned_cpu(report);
}

std::string setup_worker_count(const Report &report) {
    return report.find("environment.worker_threads")
        ? std::string(report.require("environment.worker_threads")) : "1";
}

void render_split_headline(std::ostream &output, const Report &report,
                           const Report &setup_report) {
    const std::string_view variant = report.require("run.variant");
    const std::string_view profile = report.require("run.profile");
    const bool recovered = is_recovered_setup(setup_report);
    const auto setup = first_timing(report, {"setup.total",
                                             "offline_setup_total"});
    const auto online_path_elapsed = online_path_elapsed_ms(report);
    const auto request_to_verification =
        request_to_verification_elapsed_ms(report);
    const auto server_active = first_timing(
        report, {"server.online_total", "server_online_total"});
    const auto client_per_request = client_per_request_timing(report);
    const std::optional<double> online_cpu =
        server_active && client_per_request
            ? std::optional<double>(server_active->cpu_ms +
                                    client_per_request->cpu_ms)
            : std::nullopt;
    const std::optional<double> all_active_cpu =
        setup && online_cpu
            ? std::optional<double>(setup->cpu_ms + *online_cpu)
            : std::nullopt;
    const auto wire_total = checked_sum(
        {first_integer(report,
                       {"wire.request_bytes",
                        "wire.evaluation_request_bytes"}),
         first_integer(report,
                       {"wire.response_bytes",
                        "wire.proof_response_bytes"})},
        "one-round wire total");
    const auto proving_key_bytes = checked_sum(
        {report.integer("storage.setup_bytes"),
         report.integer("storage.server_preprocessing_bytes")},
        "Base proving-key bytes");
    const auto verifying_key_bytes = checked_sum(
        {report.integer("storage.setup_bytes"),
         report.integer("storage.client_preprocessing_bytes")},
        "Base verifying-key bytes");
    std::optional<double> measured_path;
    if (setup && online_path_elapsed) {
        measured_path = setup->wall_ms + *online_path_elapsed;
    }

    output << "# Laminate " << variant_title(variant)
           << " benchmark summary: " << markdown_escape(profile)
           << "\n\n";
    if (report.find("fixture.synthetic") == "true") {
        output << "> **Synthetic test fixture.** Values are invented for regression tests.\n\n";
    }
    output << "**PASS:** setup completed, the server published its single "
              "response, the client accepted the output and proof, and all "
              "three processes exited with status zero.\n\n";
    table(
        output, {"Headline metric", "Result"},
        {{"Variant", variant_title(variant)},
         {"Profile", profile_description(profile)},
         {"GKR layer transitions",
          "One claim by selector interpolation"},
         {"GKR multiplication",
          "h(0) messages and stripped terminal product"},
         {"Run ID", text_or_missing(report, "run.id")},
         {"Process exits", "setup 0; server 0; client 0"},
         {"Workload", workload(report)},
         {"FHE backend", benchmark_backend(report)},
         {"Trace execution", trace_execution(report)},
         {"Initial ciphertext modulus", modulus_summary(report)},
         {"Exact data-prime schedule", data_prime_schedule(report)},
         {"Key modulus", key_modulus_summary(report)},
         {"Galois keys",
          text_or_missing(report, "parameters.galois_keys")},
         {"FHE parameter policy", fhe_parameter_policy(report)},
         {"Base proof-ingress schedule",
          base_proof_schedule_summary(report)},
         {recovered ? "Setup recovery (active; original preprocessing excluded)"
                    : "Setup (active)",
          timing_pair_or_missing(report,
                                  {"setup.total", "offline_setup_total"})},
         {"Proving key / server preprocessing",
          proving_key_bytes ? format_bytes(*proving_key_bytes)
                            : "not reported"},
         {"Verifying key / client preprocessing",
          verifying_key_bytes ? format_bytes(*verifying_key_bytes)
                              : "not reported"},
         {"Online server (active; idle excluded)",
          timing_pair_or_missing(report,
                                 {"server.online_total",
                                  "server_online_total"})},
         {"Per-request client computation",
          timing_pair_or_missing(client_per_request)},
         {"Online active CPU (server + client)",
          computed_duration_or_missing(online_cpu) +
              "; summed CPU, not elapsed time"},
         {recovered ? "Active CPU (recovery + server + client; original preprocessing excluded)"
                    : "All active CPU (setup + server + client)",
          computed_duration_or_missing(all_active_cpu) +
              "; summed CPU, not elapsed time"},
         {"Client process elapsed (including response wait)",
          computed_duration_or_missing(online_path_elapsed)},
         {"Request-to-verification elapsed",
          computed_duration_or_missing(request_to_verification)},
         {recovered ? "Measured work path (recovery + per-request path)"
                    : "Measured work path (setup + per-request path)",
          computed_duration_or_missing(measured_path)},
         {recovered ? "Observed recovered-run span" : "Observed run span",
          computed_duration_or_missing(observed_run_span_ms(report)) +
              "; includes any operator gap between setup and online roles"},
         {"Client request file",
          first_bytes_or_missing(report,
                                 {"wire.request_bytes",
                                  "wire.evaluation_request_bytes"})},
         {"Server response file",
          first_bytes_or_missing(report,
                                 {"wire.response_bytes",
                                  "wire.proof_response_bytes"})},
         {"Total protocol traffic (one request + one response)",
          wire_total ? format_bytes(*wire_total) : "not reported"},
         {"Serialized proof inside response",
          first_bytes_or_missing(report,
                                 {"proof.transport.total_bytes",
                                  "proof.response.inner_transport_bytes"})},
         {"Setup peak RSS",
          first_bytes_or_missing(report,
                                 {"memory.setup.peak_rss_bytes"})},
         {"Server peak RSS",
          first_bytes_or_missing(
              report, {"memory.server.peak_rss_bytes",
                       "environment.server_peak_rss_bytes"})},
         {"Client peak RSS",
          first_bytes_or_missing(
              report, {"memory.client.peak_rss_bytes",
                       "environment.client_peak_rss_bytes"})},
         {"Host RAM",
          bytes_or_missing(report, "environment.ram_bytes")},
         {"Retained run artifacts",
          bytes_or_missing(report,
                           "storage.retained_run_bytes_at_summary")},
         {"Admitted peak live local storage",
          first_bytes_or_missing(
              report,
              {"capacity.admitted_peak_live_local_disk_bytes",
               "storage.predicted_peak_live_server_bytes"})},
         {"Required available disk at setup start",
          bytes_or_missing(
              report,
              "storage.required_setup_start_available_bytes")},
         {"Observed available disk at setup preflight",
          bytes_or_missing(
              report,
              "storage.observed_setup_start_available_bytes")},
         {"Setup CPU affinity", setup_cpu_allocation(setup_report)},
         {"Setup workers", setup_worker_count(setup_report)},
         {"Online threading", "single-cpu-process"},
         {"Revision",
          text_or_missing(report, "environment.git_commit") +
              " (dirty=" +
              text_or_missing(report, "environment.git_dirty") + ')'}});

    output << "Client computation covers input encryption, output decryption, "
              "and proof verification. Server active time also includes loading "
              "its preprocessing. Client process elapsed includes preprocessing "
              "loading, transport, and the response wait. Request-to-verification "
              "elapsed starts at request publication. The measured work path adds "
              "setup time and excludes operator delay before the online roles.\n\n";
    if (recovered) {
        output << "Setup and combined runtimes cover recovery only and exclude "
                  "all preprocessing work in the original failed run. Keys were "
                  "restored and validated, not generated again.\n\n";
    }
}

void render_split_runtime(std::ostream &output, const Report &report) {
    output << "## Runtime breakdown\n\n";
    const bool recovered = is_recovered_setup(report);
    std::vector<SplitTimingRow> setup_rows{
        {"Preflight", "active", {"setup.preflight", "offline_preflight"}}};
    if (recovered) {
        setup_rows.push_back({"Restore and validate SEAL context and keys", "active",
                              {"setup.key_restoration"}});
    } else {
        setup_rows.push_back({"SEAL context and key generation", "active",
                              {"setup.key_generation", "setup"}});
    }
    if (has_timing(report, "setup.client_static_preprocessing")) {
        setup_rows.push_back(
            {recovered ? "Revalidate authenticated client-static preprocessing"
                       : "Build authenticated client-static preprocessing",
             "one-time/offline",
             {"setup.client_static_preprocessing"}});
    }
    setup_rows.insert(
        setup_rows.end(),
        {{"Persist role-separated preprocessing", "active",
          {"setup.persist", "preprocessing_persist_and_reopen"}},
         {"Reopen and verify persisted preprocessing", "active",
          {"setup.verify_persisted"}},
         {recovered ? "Setup recovery total" : "Setup total", "active total",
          {"setup.total", "offline_setup_total"}}});
    render_split_timing_table(
        output, recovered ? "Setup recovery (original preprocessing excluded)" : "Setup",
        report, setup_rows);
    render_split_timing_table(
        output, "Online server", report,
        {{"Load server preprocessing", "active; included in online total",
          {"server.load_preprocessing"}},
         {"Wait for client request", "idle; excluded from active total",
          {"server.wait_for_request"}},
         {"Read and decode request", "active", {"server.read_request"}},
         {"Evaluate encrypted payload", "active",
          {"server.payload_evaluation", "server_checkpoint_evaluation"}},
         {"Produce GKR proof", "active",
          {"server.gkr_proving"}},
         {"Encode response", "active", {"server.encode_response"}},
         {"Publish response", "active", {"server.publish_response"}},
         {"Online server total", "active total; idle excluded",
          {"server.online_total", "server_online_total"}},
         {"Server process total", "active plus idle",
          {"server.process_total"}}});
    static constexpr std::array<std::pair<std::string_view,
                                          std::string_view>,
                                3>
        replay_phases{{{"Forward evaluation", "forward"},
                       {"Reverse replay", "reverse"},
                       {"GKR source", "gkr_source"}}};
    const auto replay_key = [](std::string_view phase,
                               std::string_view suffix) {
        return "work.replay." + std::string(phase) + '.' +
               std::string(suffix);
    };
    const bool has_replay_storage = std::any_of(
        replay_phases.begin(), replay_phases.end(),
        [&](const auto &phase) {
            return report.find(replay_key(
                       phase.second,
                       "storage.application_read_bytes"))
                .has_value();
        });
    if (has_replay_storage) {
        const auto require_phase_integer = [&](std::string_view phase,
                                               std::string_view suffix) {
            const std::string key = replay_key(phase, suffix);
            const auto value = report.integer(key);
            if (!value) {
                throw std::runtime_error(
                    "incomplete replay storage telemetry: " + key);
            }
            return *value;
        };
        for (const auto &[label, phase] : replay_phases) {
            (void)label;
            const std::uint64_t prefetch_bytes = require_phase_integer(
                phase, "storage.prefetch_bytes_requested");
            const std::uint64_t maximum_prefetch = require_phase_integer(
                phase, "storage.maximum_prefetch_request_bytes");
            if (maximum_prefetch > prefetch_bytes) {
                throw std::runtime_error(
                    "inconsistent replay storage telemetry for " +
                    std::string(phase));
            }
            if (phase == "gkr_source") {
                continue;
            }
            const std::uint64_t submission_attempts =
                require_phase_integer(
                    phase,
                    "storage.writeback_submission_attempts");
            const std::uint64_t submission_successes =
                require_phase_integer(
                    phase,
                    "storage.writeback_submission_successes");
            const std::uint64_t submitted_bytes = require_phase_integer(
                phase, "storage.writeback_range_bytes_submitted");
            const std::uint64_t maximum_submission =
                require_phase_integer(
                    phase,
                    "storage.maximum_writeback_submission_bytes");
            const std::uint64_t wait_attempts = require_phase_integer(
                phase, "storage.writeback_wait_attempts");
            const std::uint64_t wait_successes = require_phase_integer(
                phase, "storage.writeback_wait_successes");
            const std::uint64_t waited_bytes = require_phase_integer(
                phase, "storage.writeback_range_bytes_waited");
            const std::uint64_t submit_only_files =
                require_phase_integer(
                    phase, "storage.writeback_files_submit_only");
            if (submission_successes > submission_attempts ||
                wait_successes > wait_attempts ||
                (submission_successes != 0 &&
                 maximum_submission > submitted_bytes) ||
                waited_bytes > submitted_bytes ||
                (submit_only_files != 0 &&
                 (wait_attempts != 0 || wait_successes != 0 ||
                  waited_bytes != 0))) {
                throw std::runtime_error(
                    "inconsistent replay storage telemetry for " +
                    std::string(phase));
            }
        }
        struct ReplayTimingRow {
            std::string_view label;
            std::string_view accounting;
            std::string_view suffix;
        };
        static constexpr std::array<ReplayTimingRow, 15> timing_rows{{
            {"Complete phase work", "phase-local total", "relation"},
            {"FHE arithmetic", "active", "fhe"},
            {"Deterministic modulus switching", "active",
             "modulus_switch"},
            {"Source deserialization", "active", "deserialization"},
            {"Output serialization", "active", "serialization"},
            {"Transfer-slab record copying", "active",
             "buffer_assembly"},
            {"Artifact hashing", "active", "hashing"},
            {"Capacity admission", "boundary-only",
             "capacity_admission"},
            {"Record output submission", "inclusive parent; not additive",
             "output_submission"},
            {"Page-cache write calls", "may include dirty throttling",
             "storage_write"},
            {"Background writeback submission",
             "advisory submission; no explicit completion wait",
             "writeback_submission"},
            {"Explicit foreground writeback waits", "storage wait",
             "writeback_wait"},
            {"Page-cache prefetch advice", "advisory submission",
             "prefetch"},
            {"Source storage reads", "storage wait", "storage_read"},
            {"Drain, close, and publication", "layer boundary",
             "drain_close_publication"},
        }};
        const auto timing_cell = [&](std::string_view phase,
                                     std::string_view suffix) {
            if (phase == "gkr_source" && suffix != "prefetch" &&
                suffix != "storage_read") {
                return std::string(
                    "not reported for read-only source diagnostics");
            }
            const std::string prefix =
                replay_key(phase, "timing." + std::string(suffix));
            const auto timing = first_timing(report, {prefix});
            if (!timing) {
                return std::string("not reported");
            }
            const std::string utilization =
                timing->wall_ms == 0.0
                    ? "n/a"
                    : fixed(100.0 * timing->cpu_ms / timing->wall_ms, 2) +
                          '%';
            return format_duration(timing->wall_ms, timing->wall_raw) +
                   " wall; " +
                   format_duration(timing->cpu_ms, timing->cpu_raw) +
                   " CPU; " + utilization;
        };
        std::vector<Row> rendered_timings;
        rendered_timings.reserve(timing_rows.size());
        for (const ReplayTimingRow &timing : timing_rows) {
            Row row{std::string(timing.label),
                    std::string(timing.accounting)};
            for (const auto &[label, phase] : replay_phases) {
                (void)label;
                row.push_back(timing_cell(phase, timing.suffix));
            }
            rendered_timings.push_back(std::move(row));
        }
        output << "### Payload storage pipeline\n\n";
        table(output,
              {"Component", "Accounting", "Forward evaluation",
               "Reverse replay", "GKR source"},
              rendered_timings);

        const auto phase_integer = [&](std::string_view phase,
                                       std::string_view suffix) {
            return report.integer(replay_key(phase, suffix));
        };
        const auto phase_bytes = [&](std::string_view phase,
                                     std::string_view suffix) {
            return bytes_or_missing(report, replay_key(phase, suffix));
        };
        const auto count_pair = [&](std::string_view phase,
                                    std::string_view left,
                                    std::string_view right) {
            const auto left_value = phase_integer(phase, left);
            const auto right_value = phase_integer(phase, right);
            return left_value && right_value
                ? comma_integer(*left_value) + " / " +
                      comma_integer(*right_value)
                : std::string("not reported");
        };
        const auto count_triple = [&](std::string_view phase,
                                      std::string_view first,
                                      std::string_view second,
                                      std::string_view third) {
            const auto first_value = phase_integer(phase, first);
            const auto second_value = phase_integer(phase, second);
            const auto third_value = phase_integer(phase, third);
            return first_value && second_value && third_value
                ? comma_integer(*first_value) + " / " +
                      comma_integer(*second_value) + " / " +
                      comma_integer(*third_value)
                : std::string("not reported");
        };
        const auto transfer = [&](std::string_view phase,
                                  std::string_view byte_suffix,
                                  std::string_view timing_suffix) {
            const auto bytes = phase_integer(phase, byte_suffix);
            const std::string prefix = replay_key(phase, timing_suffix);
            const auto timing = first_timing(report, {prefix});
            if (!bytes || !timing || timing->wall_ms == 0.0) {
                return std::string("not reported");
            }
            const double mib_per_second =
                1000.0 * static_cast<double>(*bytes) /
                (1024.0 * 1024.0 * timing->wall_ms);
            return format_bytes(*bytes) + " at " +
                   fixed(mib_per_second, 1) + " MiB/s";
        };
        const auto phase_row = [&](std::string label,
                                   bool gkr_read_diagnostic,
                                   const auto &cell) {
            Row row{std::move(label)};
            for (const auto &[phase_label, phase] : replay_phases) {
                (void)phase_label;
                row.push_back(
                    phase == "gkr_source" && !gkr_read_diagnostic
                        ? "not reported for read-only source diagnostics"
                        : cell(phase));
            }
            return row;
        };
        std::vector<Row> transfer_rows;
        transfer_rows.push_back(phase_row(
            "Application bytes submitted to write calls",
            false,
            [&](std::string_view phase) {
                return transfer(phase, "storage.application_write_bytes",
                                "timing.storage_write");
            }));
        transfer_rows.push_back(phase_row(
            "Write batches / syscalls", false,
            [&](std::string_view phase) {
                return count_pair(phase, "storage.write_batches",
                                  "storage.write_syscalls");
            }));
        transfer_rows.push_back(phase_row(
            "Largest write batch", false, [&](std::string_view phase) {
                return phase_bytes(phase,
                                   "storage.maximum_write_batch_bytes");
            }));
        transfer_rows.push_back(phase_row(
            "Writeback-enabled / submit-only / fallback files",
            false,
            [&](std::string_view phase) {
                return count_triple(
                    phase, "storage.writeback_files_enabled",
                    "storage.writeback_files_submit_only",
                    "storage.writeback_files_fallback");
            }));
        transfer_rows.push_back(phase_row(
            "Writeback submission attempts / successes",
            false,
            [&](std::string_view phase) {
                return count_pair(
                    phase, "storage.writeback_submission_attempts",
                    "storage.writeback_submission_successes");
            }));
        transfer_rows.push_back(phase_row(
            "Foreground wait attempts / successes",
            false,
            [&](std::string_view phase) {
                return count_pair(phase,
                                  "storage.writeback_wait_attempts",
                                  "storage.writeback_wait_successes");
            }));
        transfer_rows.push_back(phase_row(
            "Largest successful writeback range hint",
            false,
            [&](std::string_view phase) {
                return phase_bytes(
                    phase,
                    "storage.maximum_writeback_submission_bytes");
            }));
        transfer_rows.push_back(phase_row(
            "Successful range-hint / explicitly waited range bytes",
            false,
            [&](std::string_view phase) {
                return phase_bytes(
                           phase,
                           "storage.writeback_range_bytes_submitted") +
                       " / " +
                       phase_bytes(
                           phase,
                           "storage.writeback_range_bytes_waited");
            }));
        transfer_rows.push_back(phase_row(
            "Foreground wait window / maximum application-tracked unwaited range",
            false,
            [&](std::string_view phase) {
                return phase_bytes(phase,
                                   "storage.writeback_window_bytes") +
                       " / " +
                       phase_bytes(
                           phase,
                           "storage.maximum_unwaited_writeback_range_bytes");
            }));
        transfer_rows.push_back(phase_row(
            "Foreground drains / deliberately skipped drains",
            false,
            [&](std::string_view phase) {
                return count_pair(phase, "storage.writeback_drains",
                                  "storage.writeback_drains_skipped");
            }));
        transfer_rows.push_back(phase_row(
            "Foreground-drain range / successful range-hint bytes without explicit wait",
            false,
            [&](std::string_view phase) {
                return phase_bytes(
                           phase,
                           "storage.writeback_drain_range_bytes") +
                       " / " +
                       phase_bytes(
                           phase,
                           "storage.writeback_range_bytes_without_explicit_wait");
            }));
        transfer_rows.push_back(phase_row(
            "Positional header-write calls / bytes",
            false,
            [&](std::string_view phase) {
                const auto calls = phase_integer(
                    phase, "storage.positional_write_calls");
                return calls
                    ? comma_integer(*calls) + " / " +
                          phase_bytes(
                              phase,
                              "storage.positional_write_bytes")
                    : std::string("not reported");
            }));
        transfer_rows.push_back(phase_row(
            "Application bytes returned by read calls",
            true,
            [&](std::string_view phase) {
                return transfer(phase, "storage.application_read_bytes",
                                "timing.storage_read");
            }));
        transfer_rows.push_back(phase_row(
            "Read batches / syscalls", true,
            [&](std::string_view phase) {
                return count_pair(phase, "storage.read_batches",
                                  "storage.read_syscalls");
            }));
        transfer_rows.push_back(phase_row(
            "Largest read batch", true, [&](std::string_view phase) {
                return phase_bytes(phase,
                                   "storage.maximum_read_batch_bytes");
            }));
        transfer_rows.push_back(phase_row(
            "Prefetch requests / fallbacks / seek disables",
            true,
            [&](std::string_view phase) {
                return count_triple(
                    phase, "storage.prefetch_requests",
                    "storage.prefetch_fallbacks",
                    "storage.prefetch_seek_disables");
            }));
        transfer_rows.push_back(phase_row(
            "Prefetch bytes requested", true,
            [&](std::string_view phase) {
                return phase_bytes(phase,
                                   "storage.prefetch_bytes_requested");
            }));
        transfer_rows.push_back(phase_row(
            "Prefetch logical window / largest BDI-qualified request",
            true,
            [&](std::string_view phase) {
                return phase_bytes(phase,
                                   "storage.prefetch_window_bytes") +
                       " / " +
                       phase_bytes(
                           phase,
                           "storage.maximum_prefetch_request_bytes");
            }));
        transfer_rows.push_back(phase_row(
            "Filesystem-capacity probes", false,
            [&](std::string_view phase) {
                const auto probes =
                    phase_integer(phase, "storage.capacity_probes");
                return probes
                    ? comma_integer(*probes) +
                          " (trace/layer boundaries only)"
                    : std::string("not reported");
            }));
        transfer_rows.push_back(phase_row(
            "Private scratch integrity", true,
            [&](std::string_view phase) {
                return text_or_missing(
                    report,
                    replay_key(phase, "storage.artifact_integrity"));
            }));
        transfer_rows.push_back(phase_row(
            "Authenticated / same-process-unhashed record bytes",
            false,
            [&](std::string_view phase) {
                return phase_bytes(
                           phase,
                           "storage.authenticated_record_bytes") +
                       " / " +
                       phase_bytes(
                           phase,
                           "storage.same_process_unhashed_record_bytes");
            }));
        transfer_rows.push_back(phase_row(
            "Whole-record bytes recopied into transfer slabs",
            false,
            [&](std::string_view phase) {
                return phase_bytes(phase, "storage.record_copy_bytes");
            }));
        table(output,
              {"Transfer evidence", "Forward evaluation", "Reverse replay",
               "GKR source"},
              transfer_rows);
        output << "Same-process ephemeral files use Linux submit-only "
                  "writeback: they perform no explicit foreground wait or "
                  "layer-end drain, although ordinary kernel dirty-page "
                  "throttling may still block writes. Authenticated "
                  "reopenable artifacts retain bounded foreground waits "
                  "and a layer-end drain. Linux prefetch requests are capped "
                  "by setup policy and further qualified at runtime from the "
                  "backing device's BDI read-ahead geometry; the reported "
                  "largest request is the actual submitted size. Transfer "
                  "byte counts are "
                  "application-level bytes, not "
                  "device traffic; device throughput requires host block-I/O "
                  "telemetry. Phase columns keep reverse replay and GKR "
                  "source reads distinct from forward materialization.\n\n";
        output << "Progress JSONL records current and peak RSS at every "
                  "coarse event boundary.\n\n";
    }
    if (report.integer(
            "work.replay.forward.identity_affine_alias_relations")) {
        const auto alias_count = [&](std::string_view phase,
                                     std::string_view suffix) {
            const std::string key = "work.replay." + std::string(phase) +
                                    ".identity_affine_alias_" +
                                    std::string(suffix);
            const auto value = report.integer(key);
            if (!value) {
                throw std::runtime_error(
                    "incomplete identity-affine alias telemetry: " + key);
            }
            return comma_integer(*value);
        };
        const auto alias_bytes = [&](std::string_view phase,
                                     std::string_view suffix) {
            const std::string key = "work.replay." + std::string(phase) +
                                    ".identity_affine_alias_" +
                                    std::string(suffix);
            const auto value = report.integer(key);
            if (!value) {
                throw std::runtime_error(
                    "incomplete identity-affine alias telemetry: " + key);
            }
            return format_bytes(*value);
        };
        output << "### Identity affine storage aliases\n\n"
                  "An exact singleton affine relation can publish a distinct "
                  "private namespace by hard-linking its already validated "
                  "one-layer payload file. Reused layer bytes are existing "
                  "file lengths, not newly allocated storage; unique bytes "
                  "are the new alias manifest only. Capability-only link "
                  "failures use the ordinary admitted materializer.\n\n";
        table(
            output,
            {"Phase", "Linked relations", "Capability fallbacks",
             "Records reused", "Existing layer bytes reused",
             "Unique alias bytes written"},
            {{"`forward`", alias_count("forward", "relations"),
              alias_count("forward", "fallbacks"),
              alias_count("forward", "records_reused"),
              alias_bytes("forward", "layer_bytes_reused"),
              alias_bytes("forward", "unique_bytes_written")},
             {"`reverse`", alias_count("reverse", "relations"),
              alias_count("reverse", "fallbacks"),
              alias_count("reverse", "records_reused"),
              alias_bytes("reverse", "layer_bytes_reused"),
              alias_bytes("reverse", "unique_bytes_written")}});
    }
    render_base_layer_telemetry(output, report);
    render_sumcheck_rounds(output, report);
    render_client_computation(output, report);
    std::vector<SplitTimingRow> client_rows{
        {"Load client preprocessing", "reusable RAM load; excluded from computation",
         {"client.load_preprocessing"}}};
    client_rows.insert(
        client_rows.end(),
        {{"Encrypt inputs", "per request",
          {"client.encrypt_inputs", "client_input_encryption"}},
         {"Prepare GKR input claim and bind encrypted request", "per request",
          {"client.bind_session", "client_session_binding"}},
         {"Encode request", "per request", {"client.encode_request"}},
         {"Publish request", "per request", {"client.publish_request"}},
         {"Wait for server response", "idle; excluded from active total",
          {"client.wait_for_response"}}});
    if (!has_isolated_client_response_timings(report)) {
        throw std::runtime_error("client response timing split is missing");
    }
    client_rows.push_back(
        {"Read response file", "per request", {"client.read_response_file"}});
    client_rows.push_back(
        {"Decode response", "per request", {"client.decode_response"}});
    client_rows.insert(
        client_rows.end(),
        {{"Check response binding, derive GKR challenge, decrypt output, and "
          "form output-MLE claim", "per request",
          {"client.open_response", "client.decrypt_output",
           "client_decrypt_and_claim"}},
         {"Verify GKR proof using the certified setup", "per request",
          {"client.verify", "client_verify"}},
         {"Per-request client computation",
          "encryption + decryption + VCoED verification", {}, true},
         {"Client process total", "active plus idle",
          {"client.process_total"}}});
    render_split_timing_table(output, "Per-request client", report,
                              client_rows);
    render_client_verifier_breakdown(output, report);
}

void render_split_protocol(std::ostream &output, const Report &report) {
    const auto request = first_integer(
        report, {"wire.request_bytes", "wire.evaluation_request_bytes"});
    const auto response = first_integer(
        report, {"wire.response_bytes", "wire.proof_response_bytes"});
    const auto total = checked_sum({request, response}, "total wire bytes");
    output << "## Protocol artifacts\n\n";
    table(output, {"Direction", "Artifact", "Size"},
          {{"Client → server", "`cli-to-srv-request.bin`",
            request ? format_bytes(*request) : "not reported"},
           {"Server → client", "`srv-to-cli-response.bin`",
            response ? format_bytes(*response) : "not reported"},
           {"Both directions", "One request plus one response",
            total ? format_bytes(*total) : "not reported"}});
    table(output, {"Response/proof component", "Size"},
          {{"Complete server response",
            bytes_or_missing(report, "proof.response.total_bytes")},
           {"Encrypted-output statement (metadata and ciphertext)",
            bytes_or_missing(report,
                             "proof.response.output_statement_bytes")},
           {"Response envelope header",
            bytes_or_missing(report,
                             "proof.response.envelope_header_bytes")},
           {"Public binding digests",
            bytes_or_missing(report,
                             "proof.response.public_bindings_bytes")},
           {"Proof-length prefix",
            bytes_or_missing(report,
                             "proof.response.inner_length_prefix_bytes")},
           {"Serialized proof transport",
            bytes_or_missing(report,
                             "proof.response.inner_transport_bytes")},
           {"Proof statement and metadata",
            bytes_or_missing(
                report,
                "proof.transport.statement_and_metadata_bytes")},
           {"Sumcheck round messages",
            bytes_or_missing(report,
                             "proof.transport.round_message_bytes")},
           {"Terminal proof messages",
            bytes_or_missing(report,
                             "proof.transport.terminal_message_bytes")},
           {"Partial Gate-MLE values",
            bytes_or_missing(report,
                             "proof.transport.partial_gate_mle_bytes")},
           {"Gate-MLE opening",
            bytes_or_missing(report,
                             "proof.transport.gate_mle_opening_bytes")}});
    output << "The byte counts describe canonical files on local storage; "
              "they do not include network latency or throughput. There is "
              "no second claim/proof round trip and no plaintext output "
              "claim is transmitted: the client decrypts the output and "
              "reconstructs its verification claim locally.\n\n";
}

void render_split_resources(std::ostream &output,
                            const SplitReports &reports) {
    const Report &report = reports.combined;
    const auto replay_checkpoint_count = report.integer(
        "storage.payload_replay_plan.selected_checkpoint_count");
    const auto replay_factor = report.real(
        "work.payload_replay_plan.cumulative_factor");
    output << "## Memory and storage\n\n";
    table(
        output, {"Resource", "Meaning", "Size"},
        {{"Setup peak RSS", "measured setup-process peak",
          first_bytes_or_missing(report,
                                 {"memory.setup.peak_rss_bytes"})},
         {"Server peak RSS", "measured server-process peak",
          first_bytes_or_missing(report,
                                 {"memory.server.peak_rss_bytes"})},
         {"Client peak RSS", "measured client-process peak",
          first_bytes_or_missing(report,
                                 {"memory.client.peak_rss_bytes"})},
         {"Server preprocessing", "serialized reusable server state",
          first_bytes_or_missing(
              report,
              {"storage.server.preprocessing_bytes",
               "storage.server_preprocessing_bytes",
               "storage.server_evaluation_bundle_bytes"})},
         {"Client preprocessing", "serialized client secret state",
          first_bytes_or_missing(
              report,
              {"storage.client.preprocessing_bytes",
               "storage.client_preprocessing_bytes",
               "storage.client_private_bundle_bytes"})},
         {"Shared setup record", "public setup identity and parameters",
          first_bytes_or_missing(
              report,
              {"storage.shared.setup_bytes", "storage.setup_bytes",
               "storage.preprocessing_manifest_bytes"})},
         {"Retained run artifacts", "measured before summary generation",
          bytes_or_missing(report,
                           "storage.retained_run_bytes_at_summary")},
         {"Peak payload/checkpoint artifacts",
          "measured controlled peak; excludes persistent files",
          first_bytes_or_missing(
              report,
              {"storage.payload_replay_peak_live_physical_bytes",
               "storage.payload_peak_live_physical_bytes"})},
         {"Peak GKR multiplication scratch",
          "measured controlled peak; excludes persistent files",
          bytes_or_missing(report,
                           "storage.gkr_peak_live_scratch_bytes")},
         {"Sampled server peak live local storage", "whole-role measurement",
          first_bytes_or_missing(
              report, {"storage.server.peak_live_local_bytes",
                       "storage.peak_live_local_bytes"})},
         {"Predicted/admitted peak resident RAM", "capacity-model bound",
          first_bytes_or_missing(
              report,
              {"capacity.admitted_peak_resident_ram_bytes",
               "storage.predicted_peak_resident_server_bytes"})},
         {"Operating-system RAM reserve", "fixed host headroom",
          bytes_or_missing(
              report,
              "memory.host_budget.operating_system_reserve_bytes")},
         {"Page-cache RAM reserve", "fixed sequential-I/O headroom",
          bytes_or_missing(report,
                           "memory.host_budget.page_cache_reserve_bytes")},
         {"Payload transfer-buffer reserve",
          "up to two input slabs plus one output slab",
          bytes_or_missing(
              report,
              "memory.payload_storage.transfer_buffer_reserve_bytes")},
         {"Setup-selected dense multiplication alias-cache peak",
          "relation-scoped decoded cache plus one staging value; included in "
          "the selected replay resident peak",
          bytes_or_missing(
              report,
              "memory.payload_replay_plan."
              "dense_multiplication_alias_cache_peak_resident_bytes")},
         {"Selected replay resident peak",
          "capacity-model bound including any admitted relation cache",
          bytes_or_missing(
              report,
              "memory.payload_replay_plan.selected_peak_resident_bytes")},
         {"Payload writeback window",
          "explicit foreground wait window for ephemeral payload scratch",
          bytes_or_missing(
              report,
              "memory.payload_storage.writeback_window_bytes")},
         {"Ephemeral payload writeback policy",
          "Linux submits background writeback without explicit foreground "
          "wait/drain; portable fallback uses ordinary buffered writes",
          text_or_missing(
              report,
              "storage.payload_storage.ephemeral_writeback_policy")},
         {"Configured writeback range-hint ceiling",
          "maximum range passed to one advisory submission",
          bytes_or_missing(
              report,
              "storage.payload_storage.maximum_writeback_submission_bytes")},
         {"Sequential payload readers",
          "concurrent readers charged by the payload plan",
          report.integer(
              "memory.payload_storage.sequential_reader_count")
              ? comma_integer(*report.integer(
                    "memory.payload_storage.sequential_reader_count"))
              : "not reported"},
         {"Prefetch logical window per reader",
          "bounded page-cache advice; not process-resident memory",
          bytes_or_missing(
              report,
              "memory.payload_storage.prefetch_window_bytes_each")},
         {"Payload prefetch page-cache budget",
          "reader count times logical window; inside page-cache reserve",
          bytes_or_missing(
              report,
              "memory.payload_storage.prefetch_page_cache_budget_bytes")},
         {"Configured prefetch-request ceiling",
          "Linux further qualifies requests from backing-device BDI read-ahead",
          bytes_or_missing(
              report,
              "storage.payload_storage.maximum_prefetch_request_bytes")},
         {"Multiplication-source sort buffer",
          "host-adaptive limit; allocated only as the current layer needs",
          bytes_or_missing(
              report,
              "memory.multiplication_sort_buffer_limit_bytes")},
         {"Multiplication-source sort passes",
          "initial runs / merge passes",
          report.integer("work.gkr.multiplication_sort.initial_runs") &&
                  report.integer(
                      "work.gkr.multiplication_sort.merge_passes")
              ? comma_integer(*report.integer(
                    "work.gkr.multiplication_sort.initial_runs")) +
                    " / " +
                    comma_integer(*report.integer(
                        "work.gkr.multiplication_sort.merge_passes"))
              : "not reported"},
         {"Multiplication-source peak buffered payload",
          "measured one-shot reorder arena",
          bytes_or_missing(
              report,
              "memory.gkr_multiplication_sort_peak_buffered_payload_bytes")},
         {"Multiplication-source temporary bytes retained",
          "must be zero before artifact consumption",
          bytes_or_missing(
              report,
              "storage.gkr_multiplication_sort_retained_temporary_bytes")},
         {"Predicted/admitted peak live disk", "capacity-model bound",
          first_bytes_or_missing(
              report,
              {"capacity.admitted_peak_live_local_disk_bytes",
               "storage.predicted_peak_live_server_bytes"})},
         {"Selected replay checkpoint bytes",
          "formula-derived replay plan",
          bytes_or_missing(
              report,
              "storage.payload_replay_plan.selected_checkpoint_bytes")},
         {"Selected replay peak live bytes",
          "formula-derived replay plan",
          bytes_or_missing(
              report,
              "storage.payload_replay_plan.selected_peak_live_bytes")},
         {"Selected replay checkpoints",
          "formula-derived replay plan",
          replay_checkpoint_count
              ? comma_integer(*replay_checkpoint_count)
              : "not reported"},
         {"Replay-plan objective",
          "checkpoint selection policy",
          text_or_missing(
              report,
              "storage.payload_replay_plan.selection_objective")},
         {"Cumulative payload-work factor",
          "forward evaluation plus replay / forward evaluation",
          replay_factor ? fixed(*replay_factor, 6) + "x"
                        : "not reported"},
         {"Setup-start available-disk requirement",
          "capacity-model bound including client preprocessing and reserve",
          bytes_or_missing(
              report,
              "storage.required_setup_start_available_bytes")},
         {"Configured live-server disk cap",
          "admission ceiling; not predicted allocation",
          bytes_or_missing(
              report,
              "storage.configured_live_server_cap_bytes")}});
    output << "Measured RSS rows are role-specific process peaks. Artifact "
              "peaks are separate controlled components and must not be "
              "added unless their lifetimes overlap. Capacity rows, when "
              "present, are conservative whole-server admission bounds.\n\n";
    if (reports.setup_storage && reports.server_storage) {
        const Report &setup = *reports.setup_storage;
        const Report &server = *reports.server_storage;
        std::vector<std::vector<std::string>> storage_rows{
            {"Backend", markdown_escape(setup.require("storage.backend"))},
            {"Artifact root",
             markdown_escape(setup.require("storage.artifact_root"))},
            {"Mount",
             markdown_escape(setup.require("storage.mount_source")) +
                 " on " +
                 markdown_escape(setup.require("storage.mount_target"))},
            {"Filesystem",
             markdown_escape(setup.require("storage.filesystem_type")) +
                 " (" +
                 markdown_escape(setup.require("storage.mount_options")) +
                 ")"},
            {"Filesystem capacity",
             format_bytes(require_integer(
                 setup, "storage.filesystem_total_bytes"))}};
        const std::string_view storage_backend =
            setup.require("storage.backend");
        if (storage_backend == "google-local-ssd-raid0") {
            storage_rows.push_back(
                {"Healthy Local SSD RAID0 members",
                 comma_integer(require_integer(
                     setup, "storage.local_ssd.raid_member_count")) +
                     " (" +
                     markdown_escape(setup.require(
                         "storage.local_ssd.raid_members")) +
                     ")"});
            storage_rows.push_back(
                {"RAID0 chunk",
                 format_bytes(require_integer(
                     setup, "storage.local_ssd.raid_chunk_bytes"))});
        } else if (storage_backend == "dedicated-block") {
            storage_rows.push_back(
                {"Dedicated whole block device",
                 markdown_escape(setup.require(
                     "storage.dedicated_block.device"))});
            storage_rows.push_back(
                {"Device ancestry",
                 markdown_escape(setup.require(
                     "storage.dedicated_block.device_ancestry"))});
            storage_rows.push_back(
                {"Protected root/boot ancestry",
                 markdown_escape(setup.require(
                     "storage.dedicated_block.protected_ancestry"))});
        } else if (storage_backend == "shared-root-filesystem") {
            storage_rows.push_back(
                {"Shared storage directory",
                 markdown_escape(
                     setup.require("storage.shared_root.directory"))});
            storage_rows.push_back(
                {"Shares OS filesystem and I/O",
                 "**true — benchmark artifacts and the operating system "
                 "share the root filesystem and I/O path.**"});
        } else {
            throw std::runtime_error(
                "target storage provenance has an unsupported backend");
        }
        storage_rows.push_back(
            {"Available at setup start",
             format_bytes(require_integer(
                 setup, "storage.filesystem_available_bytes")) +
                 " at " +
                 markdown_escape(setup.require("storage.captured_at_utc"))});
        storage_rows.push_back(
            {"Available at server start",
             format_bytes(require_integer(
                 server, "storage.filesystem_available_bytes")) +
                 " at " +
                 markdown_escape(server.require("storage.captured_at_utc"))});
        table(output, {"Target storage provenance", "Recorded value"},
              storage_rows);
        output << "These immutable snapshots were captured by the GCP "
                  "wrapper outside the measured setup and server timers. "
                  "They identify the filesystem used by all run artifacts; "
                  "the available-byte samples are boundary observations, "
                  "not a live-storage high-water mark.\n\n";
    }
    if (uses_host_resource_budget(report.require("run.profile"))) {
        table(
            output, {"Host-derived planner budget", "Recorded value"},
            {{"Observed available disk",
              format_bytes(require_integer(
                  report,
                  "storage.host_budget.observed_available_disk_bytes"))},
             {"Reserved free disk",
              format_bytes(require_integer(
                  report, "storage.host_budget.free_reserve_bytes"))},
             {"Gross live-artifact budget",
              format_bytes(require_integer(
                  report, "storage.host_budget.max_live_disk_bytes"))},
             {"Persistent client preprocessing reserve",
              format_bytes(require_integer(
                  report,
                  "storage.host_budget.client_private_persistence_reserve_bytes"))},
             {"Server checkpoint/replay budget",
              format_bytes(require_integer(
                  report,
                  "storage.host_budget.server_live_disk_cap_bytes"))},
             {"Observed physical RAM",
              format_bytes(require_integer(
                  report,
                  "memory.host_budget.observed_physical_ram_bytes"))},
             {"Reserved host RAM",
              format_bytes(require_integer(
                  report, "memory.host_budget.safety_reserve_bytes"))},
             {"Gross resident budget after host reserve",
              format_bytes(require_integer(
                  report,
                  "memory.host_budget.gross_resident_budget_bytes"))},
             {"Concurrent client resident reserve",
              format_bytes(require_integer(
                  report,
                  "memory.host_budget.client_peak_reserve_bytes"))},
             {"Net server resident cap",
              format_bytes(require_integer(
                  report,
                  "memory.host_budget.server_resident_cap_bytes"))}});
        output << "The payload checkpoint plan is selected from this "
                  "setup-time capacity observation. Workload and "
                  "cryptographic parameters do not change with the host.\n\n";
    }
}

struct TimingReconciliation {
    double total_wall_ms = 0;
    double component_wall_ms = 0;
    double total_cpu_ms = 0;
    double component_cpu_ms = 0;
};

std::optional<TimingReconciliation> reconcile_timing(
    const Report &report, std::string_view total_prefix,
    const std::vector<std::string_view> &component_prefixes) {
    const auto total = first_timing(report, {total_prefix});
    if (!total) {
        return std::nullopt;
    }
    TimingReconciliation result{
        .total_wall_ms = total->wall_ms,
        .total_cpu_ms = total->cpu_ms,
    };
    for (const std::string_view prefix : component_prefixes) {
        const auto component = first_timing(report, {prefix});
        if (!component) {
            return std::nullopt;
        }
        result.component_wall_ms += component->wall_ms;
        result.component_cpu_ms += component->cpu_ms;
    }
    return result;
}

std::optional<TimingReconciliation> reconcile_timing(
    const Report &report, const std::optional<TimingAmount> &total,
    const std::vector<std::string_view> &component_prefixes) {
    if (!total) {
        return std::nullopt;
    }
    TimingReconciliation result{
        .total_wall_ms = total->wall_ms,
        .total_cpu_ms = total->cpu_ms,
    };
    for (const std::string_view prefix : component_prefixes) {
        const auto component = first_timing(report, {prefix});
        if (!component) {
            return std::nullopt;
        }
        result.component_wall_ms += component->wall_ms;
        result.component_cpu_ms += component->cpu_ms;
    }
    return result;
}

std::string reconciliation_result(
    const std::optional<TimingReconciliation> &reconciliation) {
    if (!reconciliation) {
        return "not reported";
    }
    const double wall_residual = reconciliation->total_wall_ms -
                                 reconciliation->component_wall_ms;
    const double cpu_residual = reconciliation->total_cpu_ms -
                                reconciliation->component_cpu_ms;
    return "total minus listed components: " +
           fixed(wall_residual, 3) + " ms wall, " +
           fixed(cpu_residual, 3) + " ms CPU";
}

void render_evidence_and_warnings(std::ostream &output,
                                  const Report &report,
                                  const Report &online_report) {
    const bool recovered = is_recovered_setup(report);
    std::vector<std::string_view> setup_components{
        "setup.preflight", recovered ? "setup.key_restoration" : "setup.key_generation"};
    if (has_timing(report, "setup.client_static_preprocessing")) {
        setup_components.push_back("setup.client_static_preprocessing");
    }
    setup_components.push_back("setup.persist");
    if (has_timing(report, "setup.verify_persisted")) {
        setup_components.push_back("setup.verify_persisted");
    }
    const auto setup_reconciliation = reconcile_timing(
        report, "setup.total", setup_components);
    const auto server_reconciliation = reconcile_timing(
        report, "server.online_total",
        {"server.load_preprocessing", "server.read_request",
         "server.payload_evaluation", "server.gkr_proving",
         "server.encode_response", "server.publish_response"});
    const auto client_reconciliation = reconcile_timing(
        report, client_per_request_timing(report),
        client_active_timing_prefixes(report));

    output << "## Evidence and warnings\n\n";
    table(output, {"Claim", "Evidence class", "What supports it"},
          {{"Protocol accepted", "measured and checked",
            "setup PASS, server PASS, and client verification PASS from "
            "three role result files, plus zero OS exit status for every "
            "role"},
           {"One-round topology", "measured serialized artifacts",
            "exactly one canonical request file and one canonical response "
            "file; the output-MLE claim is reconstructed client-side"},
           {"Role runtimes and peak RSS", "measured",
            "per-process wall/CPU clocks and role-specific peak-RSS samples"},
           {"Proof and wire sizes", "measured",
            "canonical serialized byte counts reconciled against their "
            "component breakdowns"},
           {"Retained run storage", "derived measurement",
            "sum of regular files below the run directory immediately before "
            "summary generation"},
           {"RAM and live-disk admission", "modeled bound",
            "preflight capacity model; not a measured process or filesystem "
            "peak"},
           {"Target-profile runtime", "projected sensitivity band",
            "completed host timings scaled by executable geometry formulas "
            "and explicit fixed-chain RNS sensitivity"}});
    table(output, {"Runtime reconciliation", "Evidence"},
          {{recovered ? "Setup recovery active total" : "Setup active total",
            reconciliation_result(setup_reconciliation)},
           {"Server online active total",
            reconciliation_result(server_reconciliation)},
           {"Client per-request active total",
            reconciliation_result(client_reconciliation)}});

    std::vector<std::string> warnings;
    const auto add_reconciliation_warning =
        [&](std::string_view role,
            const std::optional<TimingReconciliation> &value) {
            if (!value) {
                warnings.push_back(std::string(role) +
                                   " timing components are incomplete; the "
                                   "active total cannot be reconciled.");
                return;
            }
            constexpr double kToleranceMs = 1.0;
            if (value->component_wall_ms >
                    value->total_wall_ms + kToleranceMs ||
                value->component_cpu_ms >
                    value->total_cpu_ms + kToleranceMs) {
                warnings.push_back(std::string(role) +
                                   " listed active components exceed the "
                                   "reported active total.");
            }
        };
    add_reconciliation_warning(recovered ? "Setup recovery" : "Setup",
                               setup_reconciliation);
    add_reconciliation_warning("Server", server_reconciliation);
    add_reconciliation_warning("Client", client_reconciliation);

    if (report.find("parameters.security") &&
        report.require("parameters.security").find("none") !=
            std::string_view::npos) {
        warnings.emplace_back(
            "SEAL uses `sec_level_type::none` for the comparison profile. "
            "Protocol PASS and integrity evidence are not an end-to-end "
            "privacy-security estimate.");
    }
    if (report.require("environment.git_dirty") != "false") {
        warnings.emplace_back(
            "The measured executable came from a dirty revision.");
    }
    if (report.require("environment.build_type") != "Release") {
        warnings.emplace_back(
            "The measured executable was not a Release build.");
    }
    if (report.require("environment.seal_acceleration") !=
        "intel-hexl-runtime-dispatch") {
        warnings.emplace_back(
            "Intel HEXL runtime dispatch was not reported as enabled.");
    }
    if (online_report.require("environment.threading") != "single-cpu-process") {
        warnings.emplace_back(
            "The report does not identify each online role as a single-CPU "
            "process.");
    }
    if (pinned_cpu(online_report) == "not reported" ||
        pinned_cpu(online_report) == "not-observed") {
        warnings.emplace_back(
            "The logical CPU ID is not recorded. Single-CPU execution is "
            "reported, but affinity cannot be audited from this summary.");
    }
    if (!first_text(report,
                    {"environment.fhe_backend", "run.fhe_backend"})) {
        warnings.emplace_back(
            "The concrete SEAL backend label is inferred from this Base "
            "benchmark executable and its SEAL version; no explicit backend "
            "field was recorded.");
    }
    if (!first_text(report, {"environment.trace_execution",
                             "run.trace_execution"})) {
        warnings.emplace_back(
            "The checkpoint/replay trace mode is inferred from this Base "
            "benchmark executable; no explicit trace-mode field was "
            "recorded.");
    }
    if (!report.find("storage.server.peak_live_local_bytes")) {
        warnings.emplace_back(
            "No sampled whole-server live-storage peak was recorded. The "
            "artifact peaks and capacity bound below are not substitutes for "
            "that measurement.");
    }
    if (const auto proving = first_timing(report, {"server.gkr_proving"});
        proving && proving->wall_ms > 0 &&
        proving->cpu_ms / proving->wall_ms < 0.95) {
        warnings.emplace_back(
            "GKR proving used less than 95% CPU/wall on its pinned process; "
            "inspect I/O and scheduling before treating it as compute-bound.");
    }

    if (warnings.empty()) {
        output << "No report-level warnings were detected.\n\n";
        return;
    }
    output << "Warnings and interpretation limits:\n\n";
    for (const std::string &warning : warnings) {
        output << "- " << warning << "\n";
    }
    output << '\n';
}

void render_split_provenance(std::ostream &output,
                             const SplitReports &reports) {
    const Report &report = reports.combined;
    const auto physical_cores =
        report.integer("environment.physical_cores");
    const auto logical_cores =
        report.integer("environment.logical_cores");
    const std::string core_topology =
        physical_cores && logical_cores
            ? comma_integer(*physical_cores) + " physical / " +
                  comma_integer(*logical_cores) + " logical"
            : "not reported";
    output << "## Provenance\n\n";
    table(output, {"Field", "Value"},
          {{"Setup result", markdown_escape(reports.setup_path.string())},
           {"Server result", markdown_escape(reports.server_path.string())},
           {"Client result", markdown_escape(reports.client_path.string())},
           {"Setup format", text_or_missing(reports.setup, "format")},
           {"Server format", text_or_missing(reports.server, "format")},
           {"Client format", text_or_missing(reports.client, "format")},
           {"Run ID", text_or_missing(report, "run.id")},
           {"Variant", text_or_missing(report, "run.variant")},
           {"Profile", text_or_missing(report, "run.profile")},
           {"FHE backend", benchmark_backend(report)},
           {"Trace execution", trace_execution(report)},
           {"Initial data modulus", modulus_summary(report)},
           {"Exact data-prime schedule", data_prime_schedule(report)},
           {"Key modulus", key_modulus_summary(report)},
           {"Git commit",
            text_or_missing(report, "environment.git_commit")},
           {"Git dirty", text_or_missing(report, "environment.git_dirty")},
           {"Build type", text_or_missing(report, "environment.build_type")},
           {"Compiler", text_or_missing(report, "environment.compiler")},
           {"SEAL version",
            text_or_missing(report, "environment.seal_version")},
           {"SEAL acceleration",
            text_or_missing(report, "environment.seal_acceleration")},
           {"SHA-256 acceleration",
            text_or_missing(report, "environment.sha256_acceleration")},
           {"Operating system", text_or_missing(report, "environment.os")},
           {"CPU", text_or_missing(report, "environment.cpu")},
           {"Core topology", core_topology},
           {"Setup CPU affinity", setup_cpu_allocation(reports.setup)},
           {"Setup workers", setup_worker_count(reports.setup)},
           {"Server pinned logical CPU", pinned_cpu(reports.server)},
           {"Client pinned logical CPU", pinned_cpu(reports.client)},
           {"Setup threading", text_or_missing(reports.setup, "environment.threading")},
           {"Online threading", "single-cpu-process"},
           {"AVX2 available",
            text_or_missing(
                report, "environment.cpu_features.avx2_available")},
           {"AVX-512F available",
            text_or_missing(
                report, "environment.cpu_features.avx512f_available")},
           {"AVX-512DQ available",
            text_or_missing(
                report, "environment.cpu_features.avx512dq_available")},
           {"AVX-512IFMA available",
            text_or_missing(
                report, "environment.cpu_features.avx512ifma_available")}});
    if (is_recovered_setup(reports.setup)) {
        output << "### Recovered preprocessing\n\n";
        table(output, {"Field", "Value"},
              {{"Setup mode", "recovered-preprocessing"},
               {"Setup timing scope", "recovery-only-excludes-original-preprocessing"},
               {"Source run directory", text_or_missing(reports.setup, "recovery.source_run_directory")},
               {"Source run identifier", text_or_missing(reports.setup, "recovery.source_run_id")},
               {"Source revision", text_or_missing(reports.setup, "recovery.source_git_commit")},
               {"Source setup SHA-256", text_or_missing(reports.setup, "recovery.source_setup_sha256")}});
    }
    const auto command_or_missing = [](const Report &role) {
        return std::string(
            role.find("environment.command").value_or("not reported"));
    };
    output << "### Exact role commands\n\n"
           << "Setup:\n\n    "
           << command_or_missing(reports.setup)
           << "\n\nServer:\n\n    "
           << command_or_missing(reports.server)
           << "\n\nClient:\n\n    "
           << command_or_missing(reports.client)
           << "\n\n";
}

std::string render_split(const SplitReports &reports) {
    const Report &report = reports.combined;
    validate_breakdowns(report);
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << kRendererMarker;
    if (reports.saved_response_provenance) output << kSavedResponseMarker;
    render_split_headline(output, report, reports.setup);
    render_split_runtime(output, report);
    render_server_operations(output, report);
    render_split_protocol(output, report);
    render_split_resources(output, reports);
    render_evidence_and_warnings(output, report, reports.server);
    render_split_provenance(output, reports);
    return output.str();
}

void write_summary(const std::optional<std::filesystem::path> &path,
                   std::string_view summary,
                   const std::vector<std::filesystem::path> &input_paths) {
    if (!path) {
        std::cout << summary;
        if (!std::cout) {
            throw std::runtime_error("failed to write summary to stdout");
        }
        return;
    }
    if (!summary.starts_with(kRendererMarker)) {
        throw std::logic_error(
            "renderer output is missing its ownership marker");
    }
    const std::filesystem::path normalized_output =
        std::filesystem::absolute(*path).lexically_normal();
    for (const std::filesystem::path &input_path : input_paths) {
        const std::filesystem::path normalized_input =
            std::filesystem::absolute(input_path).lexically_normal();
        if (normalized_input == normalized_output) {
            throw std::invalid_argument(
                "--output must not replace a canonical input report");
        }
    }
    std::error_code error;
    const std::filesystem::path parent =
        path->parent_path().empty() ? std::filesystem::path(".")
                                    : path->parent_path();
    const auto parent_status = std::filesystem::symlink_status(parent, error);
    if (error || !std::filesystem::is_directory(parent_status) ||
        std::filesystem::is_symlink(parent_status)) {
        throw std::invalid_argument(
            "--output parent must be an existing, non-symlink directory");
    }

    auto output_status = std::filesystem::symlink_status(*path, error);
    if (error == std::make_error_code(
                     std::errc::no_such_file_or_directory)) {
        error.clear();
        output_status = std::filesystem::file_status(
            std::filesystem::file_type::not_found);
    } else if (error) {
        throw std::runtime_error("cannot inspect output path: " +
                                 error.message());
    }
    if (output_status.type() != std::filesystem::file_type::not_found) {
        if (std::filesystem::is_symlink(output_status) ||
            !std::filesystem::is_regular_file(output_status)) {
            throw std::invalid_argument(
                "--output must be absent or a regular renderer-generated "
                "summary");
        }
        const std::uintmax_t existing_size =
            std::filesystem::file_size(*path, error);
        if (error || existing_size > kMaximumReportBytes) {
            throw std::invalid_argument(
                "existing --output is too large to identify safely");
        }
        std::ifstream existing(*path, std::ios::binary);
        std::string marker(kRendererMarker.size(), '\0');
        existing.read(marker.data(),
                      static_cast<std::streamsize>(marker.size()));
        if (existing.gcount() !=
                static_cast<std::streamsize>(marker.size()) ||
            marker != kRendererMarker) {
            throw std::invalid_argument(
                "refusing to replace --output: it was not generated by this "
                "summary renderer");
        }
    }

    std::filesystem::path partial;
    int descriptor = -1;
    for (unsigned attempt = 0; attempt < 32 && descriptor < 0; ++attempt) {
        partial = parent /
                  (path->filename().string() + ".partial." +
                   std::to_string(static_cast<long long>(::getpid())) + '.' +
                   std::to_string(attempt));
        descriptor = ::open(partial.c_str(),
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (descriptor < 0 && errno != EEXIST) {
            throw std::runtime_error(
                "cannot create private partial summary: " +
                std::generic_category().message(errno));
        }
    }
    if (descriptor < 0) {
        throw std::runtime_error(
            "cannot reserve a unique private partial summary path");
    }

    const auto discard_partial = [&] {
        if (descriptor >= 0) {
            static_cast<void>(::close(descriptor));
            descriptor = -1;
        }
        std::error_code ignored;
        std::filesystem::remove(partial, ignored);
    };
    try {
        std::size_t written = 0;
        while (written < summary.size()) {
            const ssize_t count = ::write(
                descriptor, summary.data() + written,
                std::min<std::size_t>(summary.size() - written,
                    static_cast<std::size_t>(
                        std::numeric_limits<ssize_t>::max())));
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw std::runtime_error(
                    "failed to write private partial summary: " +
                    std::generic_category().message(errno));
            }
            written += static_cast<std::size_t>(count);
        }
        while (::fsync(descriptor) != 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(
                "failed to flush private partial summary: " +
                std::generic_category().message(errno));
        }
        if (::close(descriptor) != 0) {
            descriptor = -1;
            throw std::runtime_error(
                "failed to close private partial summary: " +
                std::generic_category().message(errno));
        }
        descriptor = -1;
        if (::rename(partial.c_str(), path->c_str()) != 0) {
            throw std::runtime_error(
                "failed to atomically publish summary: " +
                std::generic_category().message(errno));
        }
    } catch (...) {
        discard_partial();
        throw;
    }
}

} // namespace

int main(int argc, char **argv) {
    try {
        const std::optional<Options> options = parse_options(argc, argv);
        if (!options) {
            return 0;
        }
        std::optional<laminate::bench::RunLifecycleLock> lifecycle;
        std::optional<SavedSummarySourceLock> saved_lifecycle;
        if (options->saved_response_directory) {
            saved_lifecycle.emplace(*options->run_directory);
            const auto &diagnostic = *options->saved_response_directory;
            const auto source = *options->run_directory;
            const auto contains = [](const auto &parent, const auto &child) {
                return std::mismatch(parent.begin(), parent.end(), child.begin(), child.end()).first == parent.end();
            };
            if (!diagnostic.is_absolute() || std::filesystem::canonical(diagnostic) != diagnostic ||
                contains(source, diagnostic) || contains(diagnostic, source) || !options->output ||
                std::filesystem::weakly_canonical(options->output->parent_path()) != diagnostic)
                throw std::invalid_argument("saved-response summary output must be inside its separate canonical diagnostic directory");
        } else {
            lifecycle.emplace(*options->run_directory,
                              laminate::bench::RunLifecycleLockMode::Shared);
        }
        const SplitReports reports =
            read_split_reports(*options->run_directory, options->saved_response_directory);
        if (options->variant &&
            reports.combined.require("run.variant") != *options->variant) {
            throw std::runtime_error(
                "--variant disagrees with the run reports");
        }
        if (options->profile &&
            reports.combined.require("run.profile") != *options->profile) {
            throw std::runtime_error(
                "--profile disagrees with the run reports");
        }
        std::vector<std::filesystem::path> inputs{
            reports.setup_path, reports.server_path, reports.client_path};
        if (options->saved_response_directory) {
            for (const auto *name : {"provenance.txt", "transcript.txt", "process-exit.txt"})
                inputs.push_back(*options->saved_response_directory / name);
        }
        if (reports.setup_storage && reports.server_storage) {
            inputs.push_back(reports.setup_storage_path);
            inputs.push_back(reports.server_storage_path);
        }
        write_summary(options->output, render_split(reports), inputs);
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        print_usage(std::cerr);
        return 1;
    }
}
