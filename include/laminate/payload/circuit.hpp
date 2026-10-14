#ifndef LAMINATE_PAYLOAD_CIRCUIT_HPP
#define LAMINATE_PAYLOAD_CIRCUIT_HPP

/// @file circuit.hpp
/// @brief Compact payload-circuit IR for laned and wide SIMD workloads.

#include "laminate/fhe/layout/slot_grid.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace laminate::payload {

using WireId = std::size_t;
inline constexpr WireId kNoWire = std::numeric_limits<WireId>::max();

enum class PayloadKind : std::uint8_t { Laned, Wide };

/// Logical value geometry. slot_count is a power of two at least two. In
/// Laned mode lane_count is a power of two in [1, slot_count]; Wide mode uses
/// every slot and requires lane_count == 0.
struct PayloadShape {
    PayloadKind kind = PayloadKind::Laned;
    std::size_t slot_count = 0;
    /// Number of independent scalar computations in a laned payload. This is
    /// zero for a wide payload, where all slots form one computation.
    std::size_t lane_count = 0;

    static PayloadShape laned(std::size_t lanes, std::size_t slots);
    static PayloadShape wide(std::size_t slots);

    std::size_t value_width() const;
    void validate() const;

    bool operator==(const PayloadShape &other) const = default;
};

enum class GateOp : std::uint8_t {
    Add,
    AddPlain,
    Mul,
    MulPlain,
    Rotate,
};

struct Gate {
    GateOp op = GateOp::Add;
    WireId left = kNoWire;
    WireId right = kNoWire;
    /// Plaintext-table index for AddPlain/MulPlain, rotation step for Rotate,
    /// and zero for binary gates.
    std::size_t parameter = 0;
};

/// Topologically ordered payload DAG. Inputs occupy wire IDs [0, input_count)
/// and gate i produces input_count + i; operands refer only to earlier wires.
/// Plaintexts have shape.value_width() elements. Outputs are distinct valid
/// wire IDs in the caller's requested order. validate() checks these contracts
/// and the shape-specific gate restrictions.
struct PayloadCircuit {
    PayloadShape shape;
    std::size_t input_count = 0;
    std::vector<Gate> gates;
    std::vector<fhe::SlotVector> plaintexts;
    std::vector<WireId> outputs;

    std::size_t wire_count() const { return input_count + gates.size(); }
    WireId gate_output(std::size_t gate_index) const;
    void validate() const;
};

/// Programmatic authoring helper. It performs local reference checks as gates
/// are appended; finish() runs the complete circuit validator.
class PayloadBuilder {
  public:
    PayloadBuilder(PayloadShape shape, std::size_t input_count);

    std::size_t add_plaintext(fhe::SlotVector plaintext);
    std::size_t add_scalar_plaintext(const Fp &scalar);

    WireId add(WireId left, WireId right);
    WireId add_plain(WireId input, std::size_t plaintext);
    WireId mul(WireId left, WireId right);
    /// Laned payloads accept only a uniform plaintext here. Wide payloads
    /// additionally accept slot-varying plaintext vectors.
    WireId mul_plain(WireId input, std::size_t plaintext);
    /// Wide-only BGV grid action, with steps in [0, slot_count). The action
    /// uses the two-row slot layout defined in fhe/layout/slot_grid.hpp.
    WireId rotate(WireId input, std::size_t steps);

    void set_outputs(std::vector<WireId> outputs);
    PayloadCircuit finish();

  private:
    WireId append(Gate gate);
    void require_existing(WireId wire, const char *operation) const;

    PayloadCircuit circuit_;
};

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_CIRCUIT_HPP
