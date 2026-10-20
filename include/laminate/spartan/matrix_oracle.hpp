#ifndef LAMINATE_SPARTAN_MATRIX_ORACLE_HPP
#define LAMINATE_SPARTAN_MATRIX_ORACLE_HPP

/// @file matrix_oracle.hpp
/// @brief Succinct matrix-MLE boundary for structured Spartan circuits.

#include "laminate/spartan/r1cs.hpp"

#include <array>
#include <span>
#include <vector>

namespace laminate::spartan {

/// Public, deterministic evaluator for a structured R1CS matrix.  Spartan's
/// second sumcheck only needs the three matrix MLEs at one random point.  A
/// uniform circuit computes those values from its small local template, so it
/// should not commit to every repeated nonzero independently.
class MatrixEvaluationOracle {
  public:
    virtual ~MatrixEvaluationOracle() = default;

    /// Digest of the exact expanded R1CS relation represented by this oracle.
    virtual const Digest &circuit_digest() const = 0;

    /// Digest of the compact structured representation, bound into setup.
    virtual const Digest &oracle_digest() const = 0;

    virtual std::size_t row_variables() const = 0;
    virtual std::size_t column_variables() const = 0;

    virtual std::array<Fq2, 3> evaluate_matrices(
        std::span<const Fq2> row_point,
        std::span<const Fq2> column_point) const = 0;

    /// Sparse/structured matrix-vector product over the padded Spartan
    /// assignment.  This lets a uniform key avoid storing expanded entries.
    virtual std::vector<Fq> multiply(
        Matrix matrix, std::span<const Fq> padded_assignment) const = 0;

    /// Materialize M(r_x, y) for the ordinary second Spartan sumcheck, where
    /// M = A + gamma B + gamma^2 C.  Structured implementations do this in
    /// time linear in the assignment plus their compact local template.
    virtual std::vector<Fq2> batched_wiring_table(
        std::span<const Fq2> row_point, const Fq2 &gamma) const = 0;
};

} // namespace laminate::spartan

#endif // LAMINATE_SPARTAN_MATRIX_ORACLE_HPP
