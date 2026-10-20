#ifndef LAMINATE_BENCHES_LOCAL_SCALAR_EVALUATOR_HPP
#define LAMINATE_BENCHES_LOCAL_SCALAR_EVALUATOR_HPP

/// @file local_scalar_evaluator.hpp
/// @brief Deliberately simple client-local scalar payload interpreter.

#include "laminate/payload/circuit.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace laminate::bench::local_payload {

struct EvaluationProgress {
    std::size_t completed_coordinates = 0;
    std::size_t total_coordinates = 0;
    /// Logical gate coordinates, including indexed permutation wires.
    std::uint64_t completed_scalar_operations = 0;
    std::uint64_t total_scalar_operations = 0;
};

using ProgressCallback = std::function<void(const EvaluationProgress &)>;

struct EvaluationResult {
    /// One complete logical Wide output vector for each payload output wire.
    std::vector<fhe::SlotVector> outputs;
    /// Logical slot permutations represented by indexed views.
    std::uint64_t scalar_permutation_wires = 0;
    /// Intermediate slot copies performed to evaluate Rotate gates. Publishing
    /// the requested output vectors is separate from evaluating those gates.
    std::uint64_t scalar_rotation_copies = 0;
};

/// Additional resident storage for indexed rotation views and arithmetic
/// ancestors of rotations. Includes indexing structures; excludes inputs,
/// outputs, scalar wires and allocator bookkeeping. Rotate gates have no
/// materialized vectors. Returns zero for circuits without rotations.
std::uint64_t cross_slot_workspace_bytes(
    const payload::PayloadCircuit &circuit);

/// Evaluate a Wide payload with one scalar wire assignment per coordinate.
/// Arithmetic ancestors of rotations are evaluated once over all slots.
/// Rotations compose indexed views into those vectors or the input vectors;
/// consumers read the corresponding coordinates without copying Rotate wires.
/// Remaining arithmetic gates run once per coordinate. No FHE backend or
/// worker pool is involved.
EvaluationResult evaluate_scalar_coordinates(
    const payload::PayloadCircuit &circuit,
    std::span<const fhe::SlotVector> inputs,
    const ProgressCallback &progress = {});

/// Stable scalar checksum for reproducibility. This is an ordinary benchmark
/// checksum, not a cryptographic commitment or integrity claim.
std::uint64_t output_checksum(
    std::span<const fhe::SlotVector> outputs);

} // namespace laminate::bench::local_payload

#endif // LAMINATE_BENCHES_LOCAL_SCALAR_EVALUATOR_HPP
