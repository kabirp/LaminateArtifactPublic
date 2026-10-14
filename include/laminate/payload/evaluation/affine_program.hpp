#ifndef LAMINATE_PAYLOAD_EVALUATION_AFFINE_PROGRAM_HPP
#define LAMINATE_PAYLOAD_EVALUATION_AFFINE_PROGRAM_HPP

/// @file affine_program.hpp
/// @brief Shared affine-DAG traversal and resident-workspace accounting.

#include "laminate/payload/ir/layered.hpp"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::payload {

/// Liveness for one topological affine program. Outputs are consumed in the
/// supplied physical publication order; intermediate values are computed once
/// and released after their final local or output use.
struct AffineProgramStep {
    bool output = false;
    std::size_t index = 0;
};

struct AffineProgramPlan {
    std::vector<std::size_t> remaining_uses;
    std::size_t peak_live_intermediates = 0;
    std::vector<AffineProgramStep> steps;
};

inline AffineProgramPlan affine_program_plan(
    const AffineLayer &layer, std::size_t source_size,
    std::span<const std::size_t> outputs) {
    AffineProgramPlan result;
    result.remaining_uses.resize(layer.intermediate_gates.size());
    const auto add_uses = [&](const AffineGate &gate) {
        for (const AffineTerm &term : gate.terms) {
            if (term.coefficient.is_zero() || term.source < source_size) {
                continue;
            }
            auto &count = result.remaining_uses.at(term.source - source_size);
            if (count == std::numeric_limits<std::size_t>::max()) {
                throw std::overflow_error("affine program use count overflows");
            }
            ++count;
        }
    };
    for (const std::size_t output : outputs) {
        add_uses(layer.gates.at(output));
    }
    for (std::size_t node = layer.intermediate_gates.size(); node-- > 0;) {
        if (result.remaining_uses[node] != 0) {
            add_uses(layer.intermediate_gates[node]);
        }
    }
    // Demand-driven postorder publishes early outputs without retaining the
    // entire affine layer. Each shared primitive is scheduled exactly once.
    std::vector<bool> scheduled(layer.intermediate_gates.size(), false);
    std::vector<std::pair<std::size_t, std::size_t>> stack;
    const auto schedule_node = [&](std::size_t root) {
        if (scheduled.at(root)) {
            return;
        }
        stack.emplace_back(root, 0);
        while (!stack.empty()) {
            const std::size_t node = stack.back().first;
            auto &cursor = stack.back().second;
            const auto &terms = layer.intermediate_gates[node].terms;
            bool descended = false;
            while (cursor < terms.size()) {
                const auto &term = terms[cursor++];
                if (term.coefficient.is_zero() || term.source < source_size) {
                    continue;
                }
                const std::size_t dependency = term.source - source_size;
                if (dependency >= node) {
                    throw std::invalid_argument(
                        "affine program is not topological");
                }
                if (!scheduled[dependency]) {
                    stack.emplace_back(dependency, 0);
                    descended = true;
                    break;
                }
            }
            if (!descended) {
                result.steps.push_back({false, node});
                scheduled[node] = true;
                stack.pop_back();
            }
        }
    };
    for (const std::size_t output : outputs) {
        for (const auto &term : layer.gates.at(output).terms) {
            if (!term.coefficient.is_zero() && term.source >= source_size) {
                schedule_node(term.source - source_size);
            }
        }
        result.steps.push_back({true, output});
    }
    auto remaining = result.remaining_uses;
    std::size_t live = 0;
    for (const auto &step : result.steps) {
        const auto &gate = step.output ? layer.gates[step.index]
                                      : layer.intermediate_gates[step.index];
        if (!step.output) {
            ++live;
            result.peak_live_intermediates =
                std::max(result.peak_live_intermediates, live);
        }
        for (const AffineTerm &term : gate.terms) {
            if (!term.coefficient.is_zero() && term.source >= source_size &&
                --remaining.at(term.source - source_size) == 0) {
                --live;
            }
        }
    }
    if (live != 0) {
        throw std::logic_error("affine program liveness did not retire");
    }
    return result;
}

/// Conservative per-node host storage for the liveness counts and optional
/// backend value handles. Executors statically verify their handles fit.
inline constexpr std::size_t kAffineProgramMetadataBytesPerNode = 512;

inline std::uint64_t affine_program_workspace_bytes(
    const AffineLayer &layer, std::size_t source_size,
    std::span<const std::size_t> outputs,
    std::uint64_t resident_source_bytes) {
    if (layer.intermediate_gates.empty()) {
        return 0;
    }
    const auto plan = affine_program_plan(layer, source_size, outputs);
    std::size_t maximum_fan_in = 0;
    for (const auto &step : plan.steps) {
        const auto &gate = step.output ? layer.gates[step.index]
                                      : layer.intermediate_gates[step.index];
        maximum_fan_in = std::max(maximum_fan_in, gate.terms.size());
    }
    const auto checked_sum = [](std::uint64_t a, std::uint64_t b) {
        if (b > std::numeric_limits<std::uint64_t>::max() - a) {
            throw std::overflow_error("affine program workspace overflows");
        }
        return a + b;
    };
    const std::uint64_t count = checked_sum(
        checked_sum(plan.peak_live_intermediates, maximum_fan_in), 6U);
    const std::uint64_t nodes =
        checked_sum(layer.intermediate_gates.size(), outputs.size());
    if (nodes > std::numeric_limits<std::uint64_t>::max() /
                    kAffineProgramMetadataBytesPerNode ||
        (resident_source_bytes != 0 &&
         count > std::numeric_limits<std::uint64_t>::max() /
                     resident_source_bytes)) {
        throw std::overflow_error("affine program workspace overflows");
    }
    const auto metadata = nodes * kAffineProgramMetadataBytesPerNode;
    const auto values = count * resident_source_bytes;
    if (metadata > std::numeric_limits<std::uint64_t>::max() - values) {
        throw std::overflow_error("affine program workspace overflows");
    }
    return metadata + values;
}

} // namespace laminate::payload

#endif
