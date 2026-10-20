#ifndef LAMINATE_PAYLOAD_FIXTURES_WORKLOADS_HPP
#define LAMINATE_PAYLOAD_FIXTURES_WORKLOADS_HPP

/// @file workloads.hpp
/// @brief Deterministic synthetic payloads used by tests and benchmarks.

#include "laminate/payload/circuit.hpp"
#include "laminate/params.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace laminate::payload {

enum class WorkloadKind : std::uint8_t {
    Diamond,
    MulHeavyPyramid,
    DeepSnake,
    FanoutHeavy,
    RotationHeavy,
    BalancedLaned,
};

std::string_view workload_name(WorkloadKind kind);

struct WorkloadSpec {
    WorkloadKind kind = WorkloadKind::Diamond;
    PayloadShape shape;
    std::size_t multiplicative_depth = 1;
    /// Parallel states for Diamond/FanoutHeavy, first multiplication width for
    /// MulHeavyPyramid, or rotations per depth for RotationHeavy. Diamond uses
    /// at most the canonical benchmark input count, retains `width` states
    /// through its multiplicative layers, and reduces them to the canonical
    /// benchmark output count. DeepSnake ignores this after validating it is
    /// nonzero.
    std::size_t width = 1;
    /// Seed for reproducible synthetic workload values. This does not fix
    /// SEAL key generation, encryption randomness, or delegation nonces.
    std::uint64_t seed = 1;
    /// For Wide Diamond workloads, replace the last CT-CT level with a
    /// nonuniform affine plaintext multiplication. CT-CT multiplication
    /// depth becomes `multiplicative_depth - 1`. Laned rejects this mode.
    bool terminal_nonuniform_plaintext_multiplication = false;
    /// Number of logical inputs for Diamond, BalancedLaned, or MulHeavyPyramid.
    /// When omitted, the generator uses the benchmark-oriented
    /// `min(width, 64)` default. Budgeted workloads allow at most 64 inputs;
    /// Diamond's explicit count is constrained only by its circuit geometry.
    std::optional<std::size_t> input_count = std::nullopt;
    /// Exact pre-arithmetization gate budget for BalancedLaned or MulHeavyPyramid.
    /// BalancedLaned uses approximately 50% Mul, 45% Add, and 5% uniform AddPlain;
    /// MulHeavyPyramid uses 85% Mul, 10% Add, and 5% Rotate/nonuniform MulPlain.
    /// The latter requires Wide shape and at least two multiplication levels.
    std::optional<std::size_t> operation_count = std::nullopt;
    /// CT-CT gate quotas for successive generator stages, from inputs to
    /// outputs. In MulHeavyPyramid, masked input branches join stage two.
    /// Pairing two such branches produces a depth-one gate, so the compiler
    /// can place some products earlier than their generator stage.
    std::vector<std::size_t> multiplication_widths = {};
};

struct Workload {
    WorkloadSpec spec;
    PayloadCircuit circuit;
    std::vector<fhe::SlotVector> inputs;
};

/// Construct only the deterministic payload circuit. Setup and structural
/// reports use this path so they do not synthesize plaintext input vectors
/// that are needed only by an execution role.
PayloadCircuit make_payload_circuit(const WorkloadSpec &spec);

/// Construct only the deterministic plaintext inputs for a workload. Online
/// benchmark clients use this path so generating request values does not also
/// rebuild the static payload circuit.
std::vector<fhe::SlotVector> make_workload_inputs(const WorkloadSpec &spec);

Workload make_workload(const WorkloadSpec &spec);

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_FIXTURES_WORKLOADS_HPP
