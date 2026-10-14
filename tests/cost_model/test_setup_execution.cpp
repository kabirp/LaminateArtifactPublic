#include "test_helpers.hpp"
#include "../../benches/support/setup_execution.hpp"

#include <cstdlib>
#include <optional>
#include <string>

namespace {
template <class F> bool rejects(F &&call) {
    try { call(); } catch (const std::invalid_argument &) { return true; }
    return false;
}
struct RestoreSetupEnvironment {
    std::optional<std::string> saved;
    RestoreSetupEnvironment() {
        if (const char *old = std::getenv("LAMINATE_SETUP_THREADS")) saved = old;
    }
    ~RestoreSetupEnvironment() {
        if (saved) ::setenv("LAMINATE_SETUP_THREADS", saved->c_str(), 1);
        else ::unsetenv("LAMINATE_SETUP_THREADS");
    }
};
}
int main() {
    laminate::test::Runner runner("setup execution");
    runner.run("worker budget rejects malformed or excessive values", [] {
        using laminate::bench::parse_setup_worker_threads;
        CHECK(parse_setup_worker_threads("1") == 1);
        CHECK(parse_setup_worker_threads("24") == 24);
        CHECK(parse_setup_worker_threads("256") == 256);
        for (const auto value : {"", "0", "01", "-1", "+2", "2x", " 2", "257",
                                 "184467440737095516160"}) {
            CHECK(rejects([&] { parse_setup_worker_threads(value); }));
        }
    });
    runner.run("online execution ignores setup worker environment", [] {
        RestoreSetupEnvironment restore;
        CHECK(::setenv("LAMINATE_SETUP_THREADS", "invalid", 1) == 0);
        CHECK(laminate::bench::setup_execution(false).worker_threads == 1);
        CHECK(rejects([] { laminate::bench::setup_execution(true); }));
        CHECK(::setenv("LAMINATE_SETUP_THREADS", "1", 1) == 0);
        CHECK(laminate::bench::setup_execution(true).worker_threads == 1);
        CHECK(::unsetenv("LAMINATE_SETUP_THREADS") == 0);
        CHECK(laminate::bench::setup_execution(true).worker_threads == 1);
    });
#if defined(__linux__)
    runner.run("parallel setup requires its exact allowed CPU count", [] {
        RestoreSetupEnvironment restore;
        cpu_set_t affinity;
        CPU_ZERO(&affinity);
        CHECK(::sched_getaffinity(0, sizeof(affinity), &affinity) == 0);
        const auto count = static_cast<std::size_t>(CPU_COUNT(&affinity));
        if (count >= 2 && count <= 256) {
            const auto configured = std::to_string(count);
            CHECK(::setenv("LAMINATE_SETUP_THREADS", configured.c_str(), 1) == 0);
            const auto execution = laminate::bench::setup_execution(true);
            CHECK(execution.worker_threads == count);
            CHECK(!execution.cpu_affinity.empty());
        }
        const char *mismatch = count == 2 ? "3" : "2";
        CHECK(::setenv("LAMINATE_SETUP_THREADS", mismatch, 1) == 0);
        CHECK(rejects([] { laminate::bench::setup_execution(true); }));
    });
#endif
    return runner.summary();
}
