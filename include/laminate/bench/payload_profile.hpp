#ifndef LAMINATE_BENCH_PAYLOAD_PROFILE_HPP
#define LAMINATE_BENCH_PAYLOAD_PROFILE_HPP

/// @file payload_profile.hpp
/// @brief Shared payload geometry for process-separated benchmark variants.

#include "laminate/params.hpp"
#include "laminate/payload/fixtures/workloads.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace laminate::bench {

enum class BenchmarkPayloadTier : std::uint8_t {
    Quick,
    TargetBalanced,
    TargetMulHeavy,
};

struct BenchmarkPayloadProfile {
    BenchmarkPayloadTier tier = BenchmarkPayloadTier::Quick;
    std::string_view name = "quick";
    payload::WorkloadKind workload_kind = payload::WorkloadKind::Diamond;
    std::size_t depth = 0;
    /// Constant balanced/Diamond width or first CT-CT pyramid width.
    std::size_t width = 0;
    std::size_t operation_count = 0;
    std::size_t inputs = kBenchmarkDiamondInputCiphertexts;
    std::size_t outputs = kBenchmarkDiamondOutputCiphertexts;
    std::size_t add_gates = 0;
    std::size_t add_plain_gates = 0;
    std::size_t mul_gates = 0;
    std::size_t mul_plain_gates = 0;
    std::size_t rotate_gates = 0;

    bool is_target() const {
        return tier != BenchmarkPayloadTier::Quick;
    }
};

inline constexpr std::string_view benchmark_payload_tier_name(
    BenchmarkPayloadTier tier) {
    switch (tier) {
    case BenchmarkPayloadTier::Quick:
        return "quick";
    case BenchmarkPayloadTier::TargetBalanced:
        return "target-balancedLaned";
    case BenchmarkPayloadTier::TargetMulHeavy:
        return "target-mulHeavyPyramid";
    }
    throw std::logic_error("unknown benchmark payload tier");
}

inline BenchmarkPayloadTier benchmark_payload_tier(
    std::string_view name) {
    if (name == "quick") {
        return BenchmarkPayloadTier::Quick;
    }
    if (name == "target-balancedLaned") {
        return BenchmarkPayloadTier::TargetBalanced;
    }
    if (name == "target-mulHeavyPyramid") {
        return BenchmarkPayloadTier::TargetMulHeavy;
    }
    throw std::invalid_argument(
        "profile must be quick, target-balancedLaned, or target-mulHeavyPyramid");
}

/// Workload/variant combinations in the benchmark campaign.
inline bool benchmark_profile_is_in_campaign(
    std::string_view variant, BenchmarkPayloadTier tier) {
    if (variant == "local" || variant == "noIntegrity") {
        return true;
    }
    if (variant == "folded" || variant == "base") return true;
    if (variant == "laned") {
        return tier == BenchmarkPayloadTier::Quick ||
               tier == BenchmarkPayloadTier::TargetBalanced;
    }
    return false;
}

inline BenchmarkPayloadProfile benchmark_payload_profile(
    BenchmarkPayloadTier tier) {
    BenchmarkPayloadProfile result;
    result.tier = tier;
    result.name = benchmark_payload_tier_name(tier);
    switch (tier) {
    case BenchmarkPayloadTier::Quick:
        result.depth = 6;
        result.width = 1'024;
        result.operation_count = benchmark_diamond_operation_count(
            result.depth, result.width, result.outputs);
        result.add_gates = result.width - result.outputs;
        result.add_plain_gates = result.depth * result.width;
        result.mul_gates = result.depth * result.width;
        break;
    case BenchmarkPayloadTier::TargetBalanced:
        result.workload_kind = payload::WorkloadKind::BalancedLaned;
        result.depth = kMaximumPayloadMultiplicativeDepth;
        result.width = kBenchmarkBalancedMiddleWidth;
        result.operation_count = kBenchmarkPayloadOperationCount;
        result.add_gates = kBenchmarkBalancedAdditionGateCount;
        result.add_plain_gates = kBenchmarkBalancedAddPlainGateCount;
        result.mul_gates = kBenchmarkBalancedMultiplicationGateCount;
        break;
    case BenchmarkPayloadTier::TargetMulHeavy:
        result.workload_kind = payload::WorkloadKind::MulHeavyPyramid;
        result.depth = kMaximumPayloadMultiplicativeDepth;
        result.width =
            kBenchmarkMulHeavyMultiplicationWidths.front();
        result.operation_count = kBenchmarkPayloadOperationCount;
        result.add_gates = kBenchmarkMulHeavyAdditionGateCount;
        result.mul_gates = kBenchmarkMulHeavyMultiplicationGateCount;
        result.mul_plain_gates = kBenchmarkMulHeavyMulPlainGateCount;
        result.rotate_gates = kBenchmarkMulHeavyRotationGateCount;
        break;
    }
    if (result.add_gates + result.add_plain_gates + result.mul_gates +
            result.mul_plain_gates + result.rotate_gates !=
        result.operation_count) {
        throw std::logic_error(
            "benchmark payload profile gate ledger is inconsistent");
    }
    return result;
}

inline BenchmarkPayloadProfile benchmark_payload_profile(
    std::string_view name) {
    return benchmark_payload_profile(benchmark_payload_tier(name));
}

inline payload::WorkloadSpec benchmark_payload_workload_spec(
    const BenchmarkPayloadProfile &profile,
    payload::PayloadShape shape, std::uint64_t seed = 1) {
    payload::WorkloadSpec result{
        .kind = profile.workload_kind,
        .shape = shape,
        .multiplicative_depth = profile.depth,
        .width = profile.width,
        .seed = seed,
    };
    result.input_count = profile.inputs;
    if (profile.workload_kind == payload::WorkloadKind::BalancedLaned) {
        result.operation_count = profile.operation_count;
        result.multiplication_widths.assign(profile.depth, profile.width);
    } else if (profile.workload_kind ==
               payload::WorkloadKind::MulHeavyPyramid) {
        result.operation_count = profile.operation_count;
        result.multiplication_widths = {
            kBenchmarkMulHeavyMultiplicationWidths.begin(),
            kBenchmarkMulHeavyMultiplicationWidths.end(),
        };
    }
    return result;
}

inline std::vector<std::size_t> benchmark_multiplication_widths(
    const BenchmarkPayloadProfile &profile) {
    if (profile.workload_kind == payload::WorkloadKind::Diamond ||
        profile.workload_kind == payload::WorkloadKind::BalancedLaned) {
        return std::vector<std::size_t>(profile.depth, profile.width);
    }
    if (profile.workload_kind ==
            payload::WorkloadKind::MulHeavyPyramid &&
        profile.depth == kMaximumPayloadMultiplicativeDepth &&
        profile.operation_count == kBenchmarkPayloadOperationCount) {
        std::vector<std::size_t> result{
            kBenchmarkMulHeavyMultiplicationWidths.begin(),
            kBenchmarkMulHeavyMultiplicationWidths.end()};
        return result;
    }
    throw std::invalid_argument(
        "benchmark profile has unsupported multiplication geometry");
}

} // namespace laminate::bench

#endif // LAMINATE_BENCH_PAYLOAD_PROFILE_HPP
