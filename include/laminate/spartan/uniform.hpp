#ifndef LAMINATE_SPARTAN_UNIFORM_HPP
#define LAMINATE_SPARTAN_UNIFORM_HPP

/// @file uniform.hpp
/// @brief Structured-reference evaluator for a repeated R1CS.

#include "laminate/spartan/matrix_oracle.hpp"

#include <cstddef>
#include <memory>

namespace laminate::spartan {

struct CompiledUniformR1cs {
    R1csInstance circuit;
    std::shared_ptr<const MatrixEvaluationOracle> matrix_oracle;
    /// Number of live repeated blocks.
    std::size_t cycles = 0;
    /// Power-of-two cycle domain; blocks in `[cycles,padded_cycles)` are zero.
    std::size_t padded_cycles = 0;
    /// Power-of-two public block per cycle. Zero when the local circuit has
    /// no public inputs. Slot zero of each nonzero block is reserved so the
    /// global constant remains column zero.
    std::size_t public_stride = 0;
    /// Power-of-two private block per cycle.
    std::size_t witness_stride = 0;
};

/// Repeat a local R1CS over `cycles` independent cycles. Both dimensions are
/// padded inside each cycle, yielding
///
///   M((cycle,row), (cycle,column))
///     = eq(cycle_x, cycle_y) M_local(row,column).
///
/// Constant-column entries are repeated in every cycle and handled as their
/// own factored term. Per-cycle public values occupy blocks of
/// `public_stride`, with local public column `j` at global padded column
/// `cycle * public_stride + j`. Per-cycle witnesses similarly occupy
/// `witness_stride` cells in the private half. Padding cells must be zero in
/// the assignment. The cycle domain is padded to a power of two, with no
/// constraints in dummy cycles. The returned matrix oracle evaluates A/B/C
/// from only the local template.
CompiledUniformR1cs compile_uniform_r1cs(R1csInstance local_circuit,
                                         std::size_t cycles);

} // namespace laminate::spartan

#endif // LAMINATE_SPARTAN_UNIFORM_HPP
