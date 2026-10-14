#ifndef LAMINATE_BENCHES_BENCHMARK_SUPPORT_HPP
#define LAMINATE_BENCHES_BENCHMARK_SUPPORT_HPP

/// @file benchmark_support.hpp
/// @brief Small reporting helpers shared by protocol benchmark drivers.

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <thread>
#include <utility>
#include <vector>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <sys/sysinfo.h>
#include <unistd.h>
#endif

#if defined(__linux__) && defined(__GLIBC__)
#include <malloc.h>
#endif

#ifndef LAMINATE_GIT_COMMIT
#define LAMINATE_GIT_COMMIT "unknown"
#endif
#ifndef LAMINATE_GIT_DIRTY
#define LAMINATE_GIT_DIRTY "unknown"
#endif
#ifndef LAMINATE_BUILD_TYPE
#define LAMINATE_BUILD_TYPE "unknown"
#endif
#ifndef LAMINATE_COMPILER
#define LAMINATE_COMPILER "unknown"
#endif
#ifndef LAMINATE_SEAL_VERSION
#define LAMINATE_SEAL_VERSION "unknown"
#endif
#ifndef LAMINATE_SEAL_ACCELERATION
#define LAMINATE_SEAL_ACCELERATION "unknown"
#endif
#ifndef LAMINATE_SHA256_ACCELERATION
#define LAMINATE_SHA256_ACCELERATION "unknown"
#endif

namespace laminate::bench {

/// Retain recurring ciphertext-sized allocations on the single measured core.
/// Returning those hot buffers after every ordinary layer would pay repeated
/// page-fault and zeroing costs. Phase-local bulk facilities remain responsible
/// for explicitly releasing their one-shot storage: in particular, the dense
/// multiplication sorter returns its completed reorder buffer so the immutable
/// source artifact can use page cache. This is a no-op away from glibc.
inline void configure_process_memory_runtime() {
#if defined(__linux__) && defined(__GLIBC__)
    // Disable automatic arena trimming; phase owners may still explicitly
    // release bulk storage through their own allocation facilities.
    (void)mallopt(M_TRIM_THRESHOLD, -1);
    // Serve ciphertext-sized allocations from the retained arena rather than
    // per-allocation mmap/munmap. Bulk facilities explicitly release their
    // completed one-shot arenas rather than relying on this global policy.
    (void)mallopt(M_MMAP_THRESHOLD, 64 * 1024 * 1024);
#endif
}

/// Milliseconds for one explicitly delimited phase. Wall time uses a monotonic
/// clock and includes waits/I/O inside that phase; CPU time is std::clock's
/// process CPU consumption. Timings for nested phases overlap and must not be
/// summed unless the caller defines a disjoint breakdown.
struct Timing {
    double wall_ms = 0;
    double cpu_ms = 0;
};

class Stopwatch {
  public:
    Stopwatch()
        : wall_start_(std::chrono::steady_clock::now()),
          cpu_start_(std::clock()) {}

    Timing stop() const {
        const auto wall_end = std::chrono::steady_clock::now();
        const std::clock_t cpu_end = std::clock();
        return Timing{
            std::chrono::duration<double, std::milli>(wall_end - wall_start_)
                .count(),
            1000.0 * static_cast<double>(cpu_end - cpu_start_) /
                static_cast<double>(CLOCKS_PER_SEC)};
    }

  private:
    std::chrono::steady_clock::time_point wall_start_;
    std::clock_t cpu_start_;
};

template <typename Function> auto timed(Function &&function) {
    Stopwatch timer;
    auto value = function();
    return std::pair{std::move(value), timer.stop()};
}

template <typename Function> Timing timed_void(Function &&function) {
    Stopwatch timer;
    function();
    return timer.stop();
}

inline std::size_t parse_size(std::string_view text,
                              std::string_view option) {
    std::size_t value = 0;
    const auto result =
        std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw std::invalid_argument(std::string(option) +
                                    " expects a nonnegative integer");
    }
    return value;
}

inline std::string clean(std::string value) {
    std::replace(value.begin(), value.end(), '\n', ' ');
    std::replace(value.begin(), value.end(), '\r', ' ');
    return value;
}

class Record {
  public:
    explicit Record(std::ostream *mirror = nullptr) : mirror_(mirror) {}

    void text(std::string_view key, std::string value) const {
        const std::string cleaned = clean(std::move(value));
        emit([&](std::ostream &output) {
            output << key << '=' << cleaned << '\n';
        });
    }

    template <typename Integer>
    void integer(std::string_view key, Integer value) const {
        emit([&](std::ostream &output) {
            output << key << '=' << value << '\n';
        });
    }

    void real(std::string_view key, double value) const {
        emit([&](std::ostream &output) {
            output << key << '=' << std::fixed << std::setprecision(6)
                   << value << '\n';
        });
    }

    /// Emit very small probabilities without rounding them to `0.000000`.
    void scientific(std::string_view key, long double value) const {
        emit([&](std::ostream &output) {
            output << key << '=' << std::scientific << std::setprecision(9)
                   << value << '\n';
        });
    }

  private:
    template <typename Emit> void emit(Emit &&write) const {
        write(std::cout);
        if (mirror_ != nullptr) {
            write(*mirror_);
        }
    }

    std::ostream *mirror_;
};

inline std::string exact_command(int argc, char **argv) {
    std::string result;
    for (int index = 0; index < argc; ++index) {
        if (index != 0) {
            result.push_back(' ');
        }
        const std::string_view argument(argv[index]);
        const bool safe = !argument.empty() &&
                          argument.find_first_not_of(
                              "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                              "0123456789_./:=-") == std::string_view::npos;
        if (safe) {
            result.append(argument);
            continue;
        }
        result.push_back('\'');
        for (char character : argument) {
            if (character == '\'') {
                result.append("'\\''");
            } else {
                result.push_back(character);
            }
        }
        result.push_back('\'');
    }
    return result;
}

inline std::string utc_timestamp() {
    const std::time_t now = std::time(nullptr);
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

struct SystemInfo {
    /// Features available to this process. These fields do not establish
    /// which implementation a runtime-dispatched dependency selected.
    struct CpuFeatures {
        std::string probe = "unsupported";
        bool avx2_available = false;
        bool avx512f_available = false;
        bool avx512dq_available = false;
        bool avx512ifma_available = false;
    };

    std::string os = "unknown";
    std::string cpu = "unknown";
    std::size_t physical_cores = 0;
    std::size_t logical_cores = std::thread::hardware_concurrency();
    std::uint64_t ram_bytes = 0;
    /// Process-lifetime resident-memory high-water mark from RUSAGE_SELF,
    /// normalized to bytes. This is neither a phase-local delta nor disk/page
    /// cache usage, and it excludes separate client/server processes.
    std::uint64_t peak_rss_bytes = 0;
    CpuFeatures cpu_features;
};

struct ResidentMemorySample {
    std::uint64_t current_bytes = 0;
    std::uint64_t peak_bytes = 0;
};

/// Cheap phase-boundary RSS sample. Unlike `system_info`, this does not scan
/// CPU topology and is suitable for the progress journal's coarse updates.
/// peak_bytes remains a process-lifetime high-water mark; current_bytes is a
/// point-in-time sample and may miss transient peaks between observations.
inline ResidentMemorySample resident_memory_sample() {
    ResidentMemorySample result;
#if defined(__APPLE__)
    mach_task_basic_info_data_t info{};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  reinterpret_cast<task_info_t>(&info), &count) ==
        KERN_SUCCESS) {
        result.current_bytes = static_cast<std::uint64_t>(info.resident_size);
    }
#elif defined(__linux__)
    std::ifstream statm("/proc/self/statm");
    std::uint64_t virtual_pages = 0;
    std::uint64_t resident_pages = 0;
    const long page_size = ::sysconf(_SC_PAGESIZE);
    if (page_size > 0 && statm >> virtual_pages >> resident_pages &&
        resident_pages <=
            std::numeric_limits<std::uint64_t>::max() /
                static_cast<std::uint64_t>(page_size)) {
        result.current_bytes =
            resident_pages * static_cast<std::uint64_t>(page_size);
    }
    (void)virtual_pages;
#endif
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
#if defined(__APPLE__)
        result.peak_bytes = static_cast<std::uint64_t>(usage.ru_maxrss);
#else
        result.peak_bytes =
            static_cast<std::uint64_t>(usage.ru_maxrss) * 1024U;
#endif
    }
    return result;
}

inline SystemInfo::CpuFeatures cpu_features() {
    SystemInfo::CpuFeatures result;
#if defined(__i386__) || defined(__x86_64__)
#if defined(__clang__) && defined(__has_builtin)
#if __has_builtin(__builtin_cpu_init) &&                                  \
    __has_builtin(__builtin_cpu_supports)
    result.probe = "clang-runtime";
    __builtin_cpu_init();
    result.avx2_available = __builtin_cpu_supports("avx2") != 0;
    result.avx512f_available = __builtin_cpu_supports("avx512f") != 0;
    result.avx512dq_available = __builtin_cpu_supports("avx512dq") != 0;
    result.avx512ifma_available =
        __builtin_cpu_supports("avx512ifma") != 0;
#else
    result.probe = "unsupported-x86-compiler";
#endif
#elif defined(__GNUC__)
    result.probe = "gcc-runtime";
    __builtin_cpu_init();
    result.avx2_available = __builtin_cpu_supports("avx2") != 0;
    result.avx512f_available = __builtin_cpu_supports("avx512f") != 0;
    result.avx512dq_available = __builtin_cpu_supports("avx512dq") != 0;
    result.avx512ifma_available =
        __builtin_cpu_supports("avx512ifma") != 0;
#else
    result.probe = "unsupported-x86-compiler";
#endif
#else
    result.probe = "not-applicable-non-x86";
#endif
    return result;
}

#if defined(__APPLE__)
template <typename Value> Value apple_sysctl(const char *name) {
    Value value{};
    std::size_t size = sizeof(value);
    return sysctlbyname(name, &value, &size, nullptr, 0) == 0 ? value
                                                               : Value{};
}

inline std::string apple_sysctl_string(const char *name) {
    std::size_t size = 0;
    if (sysctlbyname(name, nullptr, &size, nullptr, 0) != 0 || size == 0) {
        return "unknown";
    }
    std::string value(size, '\0');
    if (sysctlbyname(name, value.data(), &size, nullptr, 0) != 0) {
        return "unknown";
    }
    if (!value.empty() && value.back() == '\0') {
        value.pop_back();
    }
    return value;
}
#endif

#if defined(__linux__)
inline std::size_t linux_physical_core_count() {
    const std::filesystem::path cpu_root("/sys/devices/system/cpu");
    std::set<std::pair<long long, long long>> cores;
    std::error_code error;
    std::filesystem::directory_iterator iterator(
        cpu_root, std::filesystem::directory_options::skip_permission_denied,
        error);
    const std::filesystem::directory_iterator end;
    for (; !error && iterator != end; iterator.increment(error)) {
        const std::string name = iterator->path().filename().string();
        if (name.size() <= 3 || !name.starts_with("cpu") ||
            !std::all_of(name.begin() + 3, name.end(), [](char character) {
                return character >= '0' && character <= '9';
            })) {
            continue;
        }
        const std::filesystem::path topology = iterator->path() / "topology";
        std::ifstream package_input(topology / "physical_package_id");
        std::ifstream core_input(topology / "core_id");
        long long package = 0;
        long long core = 0;
        if (package_input >> package && core_input >> core) {
            cores.emplace(package, core);
        }
    }
    return cores.size();
}
#endif

inline SystemInfo system_info() {
    SystemInfo result;
    result.cpu_features = cpu_features();
    utsname name{};
    if (uname(&name) == 0) {
        result.os = std::string(name.sysname) + ' ' + name.release + ' ' +
                    name.machine;
    }
#if defined(__APPLE__)
    result.cpu = apple_sysctl_string("machdep.cpu.brand_string");
    result.physical_cores = apple_sysctl<std::uint32_t>("hw.physicalcpu");
    result.logical_cores = apple_sysctl<std::uint32_t>("hw.logicalcpu");
    result.ram_bytes = apple_sysctl<std::uint64_t>("hw.memsize");
#elif defined(__linux__)
    result.physical_cores = linux_physical_core_count();
    std::ifstream cpuinfo("/proc/cpuinfo");
    for (std::string line; std::getline(cpuinfo, line);) {
        constexpr std::string_view prefix = "model name";
        if (line.starts_with(prefix)) {
            const std::size_t colon = line.find(':');
            const std::size_t value =
                colon == std::string::npos
                    ? 0
                    : line.find_first_not_of(" \t", colon + 1);
            result.cpu = value == std::string::npos ? "unknown"
                                                     : line.substr(value);
            break;
        }
    }
    struct sysinfo info {};
    if (::sysinfo(&info) == 0) {
        result.ram_bytes = static_cast<std::uint64_t>(info.totalram) *
                           static_cast<std::uint64_t>(info.mem_unit);
    }
#endif
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
#if defined(__APPLE__)
        result.peak_rss_bytes = static_cast<std::uint64_t>(usage.ru_maxrss);
#else
        result.peak_rss_bytes =
            static_cast<std::uint64_t>(usage.ru_maxrss) * 1024;
#endif
    }
    return result;
}

inline void emit_cpu_feature_availability(const Record &record,
                                          const SystemInfo &system) {
    const bool probed = system.cpu_features.probe == "clang-runtime" ||
                        system.cpu_features.probe == "gcc-runtime";
    const bool non_x86 =
        system.cpu_features.probe == "not-applicable-non-x86";
    const auto available = [probed, non_x86](bool value) {
        return probed ? (value ? "yes" : "no")
                      : (non_x86 ? "no" : "unknown");
    };
    record.text("environment.cpu_features.probe",
                system.cpu_features.probe);
    record.text("environment.cpu_features.avx2_available",
                available(system.cpu_features.avx2_available));
    record.text("environment.cpu_features.avx512f_available",
                available(system.cpu_features.avx512f_available));
    record.text("environment.cpu_features.avx512dq_available",
                available(system.cpu_features.avx512dq_available));
    record.text("environment.cpu_features.avx512ifma_available",
                available(system.cpu_features.avx512ifma_available));
}

/// Record enough build and host context to reproduce or compare a measured
/// benchmark. Callers should emit workload-specific threading separately.
inline void emit_benchmark_provenance(const Record &record, int argc,
                                      char **argv) {
    const SystemInfo system = system_info();
    record.text("environment.git_commit", LAMINATE_GIT_COMMIT);
    record.text("environment.git_dirty", LAMINATE_GIT_DIRTY);
    record.text("environment.date_utc", utc_timestamp());
    record.text("environment.os", system.os);
    record.text("environment.cpu", system.cpu);
    emit_cpu_feature_availability(record, system);
    record.integer("environment.physical_cores", system.physical_cores);
    record.integer("environment.logical_cores", system.logical_cores);
    record.integer("environment.ram_bytes", system.ram_bytes);
    record.integer("environment.peak_rss_bytes", system.peak_rss_bytes);
    record.text("environment.compiler", LAMINATE_COMPILER);
    record.text("environment.build_type", LAMINATE_BUILD_TYPE);
    record.text("environment.seal_version", LAMINATE_SEAL_VERSION);
    record.text("environment.seal_acceleration", LAMINATE_SEAL_ACCELERATION);
    record.text("environment.sha256_acceleration",
                LAMINATE_SHA256_ACCELERATION);
    record.text("environment.command", exact_command(argc, argv));
}

template <typename Value>
std::string join(const std::vector<Value> &values) {
    std::ostringstream output;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            output << ',';
        }
        output << values[index];
    }
    return output.str();
}

template <std::size_t Size>
std::string digest_hex(
    const std::array<std::uint8_t, Size> &digest) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::uint8_t byte : digest) {
        output << std::setw(2) << static_cast<unsigned>(byte);
    }
    return output.str();
}

struct Samples {
    double minimum = 0;
    double median = 0;
    double maximum = 0;
    double mean = 0;
};

inline Samples summarize(std::vector<double> values) {
    if (values.empty()) {
        return {};
    }
    std::sort(values.begin(), values.end());
    double sum = 0;
    for (double value : values) {
        sum += value;
    }
    const std::size_t middle = values.size() / 2;
    const double median = values.size() % 2 == 0
                              ? (values[middle - 1] + values[middle]) / 2
                              : values[middle];
    return Samples{values.front(), median, values.back(),
                   sum / static_cast<double>(values.size())};
}

inline void emit_samples(const Record &record, std::string_view prefix,
                         const std::vector<double> &values) {
    const Samples samples = summarize(values);
    const std::string base(prefix);
    record.real(base + ".min", samples.minimum);
    record.real(base + ".median", samples.median);
    record.real(base + ".max", samples.maximum);
    record.real(base + ".mean", samples.mean);
}

inline void emit_timing(const Record &record, std::string_view name,
                        const Timing &timing) {
    const std::string prefix = "timing." + std::string(name);
    record.real(prefix + ".wall_ms", timing.wall_ms);
    record.real(prefix + ".cpu_ms", timing.cpu_ms);
}

inline void emit_counts(const Record &record, std::string_view stage,
                        const fhe::OperationCounts &counts) {
    const std::string prefix = "operations." + std::string(stage) + '.';
#define LAMINATE_EMIT_COUNT(field) record.integer(prefix + #field, counts.field)
    LAMINATE_EMIT_COUNT(encrypt);
    LAMINATE_EMIT_COUNT(decrypt);
    LAMINATE_EMIT_COUNT(negate);
    LAMINATE_EMIT_COUNT(add);
    LAMINATE_EMIT_COUNT(sub);
    LAMINATE_EMIT_COUNT(mul_no_relin);
    LAMINATE_EMIT_COUNT(relinearize);
    LAMINATE_EMIT_COUNT(add_plain);
    LAMINATE_EMIT_COUNT(mul_plain_scalar);
    LAMINATE_EMIT_COUNT(mul_plain_vector);
    LAMINATE_EMIT_COUNT(rotate);
    LAMINATE_EMIT_COUNT(mod_switch);
    LAMINATE_EMIT_COUNT(logical_ext_add);
    LAMINATE_EMIT_COUNT(logical_ext_sub);
    LAMINATE_EMIT_COUNT(logical_ext_mul);
    LAMINATE_EMIT_COUNT(logical_ext_mul_plain);
#undef LAMINATE_EMIT_COUNT
}

template <fhe::FheBackend Backend> struct CiphertextMeasurements {
    std::vector<double> bytes;
    std::vector<double> rns_limbs;
    std::vector<double> modulus_bits;
    std::vector<double> estimated_noise_bits;
    int minimum_noise = std::numeric_limits<int>::max();
    std::string minimum_noise_checkpoint = "none";

    void observe(const typename Backend::EvalContext &eval,
                 const typename Backend::Ciphertext &ciphertext,
                 std::string checkpoint) {
        bytes.push_back(static_cast<double>(
            Backend::serialize(ciphertext).size()));
        rns_limbs.push_back(static_cast<double>(
            Backend::rns_limb_count(eval, ciphertext)));
        modulus_bits.push_back(static_cast<double>(
            Backend::coeff_modulus_bits(eval, ciphertext)));
        const int noise = Backend::estimated_noise_bits(eval, ciphertext);
        estimated_noise_bits.push_back(static_cast<double>(noise));
        if (noise < minimum_noise) {
            minimum_noise = noise;
            minimum_noise_checkpoint = std::move(checkpoint);
        }
    }
};

template <fhe::FheBackend Backend>
void observe_extension(
    CiphertextMeasurements<Backend> &measurements,
    const typename Backend::EvalContext &eval,
    const typename Backend::ExtCiphertext &ciphertext,
    const std::string &checkpoint) {
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if (ciphertext[coefficient]) {
            measurements.observe(eval, *ciphertext[coefficient],
                                 checkpoint + "/coefficient/" +
                                     std::to_string(coefficient));
        }
    }
}

} // namespace laminate::bench

#endif // LAMINATE_BENCHES_BENCHMARK_SUPPORT_HPP
