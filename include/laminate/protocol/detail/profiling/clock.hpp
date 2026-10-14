#ifndef LAMINATE_PROTOCOL_DETAIL_PROFILING_CLOCK_HPP
#define LAMINATE_PROTOCOL_DETAIL_PROFILING_CLOCK_HPP

/// @file clock.hpp
/// @brief Wall/CPU clocks used only by opt-in protocol diagnostics.

#include <chrono>
#include <ctime>

namespace laminate::protocol::profiling_detail {

struct Elapsed {
    double wall_ms = 0;
    double cpu_ms = 0;
};

class Stopwatch {
  public:
    Elapsed stop() const {
        return Elapsed{
            std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - wall_start_)
                .count(),
            1000.0 * static_cast<double>(std::clock() - cpu_start_) /
                static_cast<double>(CLOCKS_PER_SEC)};
    }

  private:
    std::chrono::steady_clock::time_point wall_start_ =
        std::chrono::steady_clock::now();
    std::clock_t cpu_start_ = std::clock();
};

} // namespace laminate::protocol::profiling_detail

#endif // LAMINATE_PROTOCOL_DETAIL_PROFILING_CLOCK_HPP
