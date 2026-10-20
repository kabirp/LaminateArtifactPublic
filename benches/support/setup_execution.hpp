#ifndef LAMINATE_BENCH_SETUP_EXECUTION_HPP
#define LAMINATE_BENCH_SETUP_EXECUTION_HPP

#include <charconv>
#include <cstddef>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <string_view>
#if defined(__linux__)
#include <sched.h>
#endif

namespace laminate::bench {

inline std::size_t parse_setup_worker_threads(std::string_view value) {
    constexpr auto error =
        "LAMINATE_SETUP_THREADS must be an integer from 1 through 256";
    if (value.empty() || value.front() == '0')
        throw std::invalid_argument(error);
    std::size_t count = 0;
    const auto parsed = std::from_chars(
        value.data(), value.data() + value.size(), count);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
        count == 0 || count > 256)
        throw std::invalid_argument(error);
    return count;
}

struct SetupExecution {
    std::size_t worker_threads = 1;
    std::string cpu_affinity;
};

// Only the Base/Folded setup actions opt in. Online roles never inspect the
// setup environment, and reconstructed prover keys keep serial defaults.
inline SetupExecution setup_execution(bool enabled) {
    SetupExecution result;
    if (!enabled) return result;
    const char *configured = std::getenv("LAMINATE_SETUP_THREADS");
    if (configured == nullptr) return result;
    result.worker_threads = parse_setup_worker_threads(configured);
    if (result.worker_threads == 1) return result;
#if defined(__linux__)
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    if (::sched_getaffinity(0, sizeof(affinity), &affinity) != 0)
        throw std::runtime_error("cannot inspect setup CPU affinity");
    std::size_t count = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET(cpu, &affinity)) continue;
        if (count++) result.cpu_affinity += ',';
        result.cpu_affinity += std::to_string(cpu);
    }
    if (count != result.worker_threads)
        throw std::invalid_argument("setup worker count must match the allowed CPU set");
#else
    // The campaign runner is Linux-only. Portable library callers select
    // their commitment workers directly, without benchmark metadata.
    throw std::invalid_argument("parallel benchmark setup requires Linux CPU affinity");
#endif
    return result;
}

} // namespace laminate::bench
#endif
