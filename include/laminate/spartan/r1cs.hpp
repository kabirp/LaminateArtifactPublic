#ifndef LAMINATE_SPARTAN_R1CS_HPP
#define LAMINATE_SPARTAN_R1CS_HPP

/// @file r1cs.hpp
/// @brief Canonical sparse R1CS representation used by regular Spartan.

#include "laminate/field/fq.hpp"
#include "laminate/field/fq2.hpp"
#include "laminate/transcript/hash.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace laminate::spartan {

enum class Matrix : std::uint8_t { A = 0, B = 1, C = 2 };

class MatrixEvaluationOracle;

/// One conventional sparse-matrix entry. Columns address
/// `[1 | public_inputs | witness]`; setup remaps that vector into Spartan's
/// equal-size public and private halves.
struct R1csEntry {
    std::uint64_t row = 0;
    std::uint64_t column = 0;
    Fq value{};

    bool operator==(const R1csEntry &) const = default;
};

struct R1csShape {
    std::uint64_t constraints = 0;
    std::uint64_t public_inputs = 0;
    std::uint64_t witness_variables = 0;

    bool operator==(const R1csShape &) const = default;
};

struct R1csAssignment {
    std::vector<Fq> public_inputs;
    std::vector<Fq> witness;
};

/// Immutable dimensions and identity needed by a Spartan verifier.  Keeping
/// this separately from `R1csInstance` lets a computation-commitment verifier
/// authenticate matrix evaluations without retaining the sparse matrices.
class R1csMetadata {
  public:
    R1csMetadata() = default;
    R1csMetadata(R1csShape shape, std::size_t padded_constraints,
                 std::size_t assignment_half, Digest circuit_digest);

    const R1csShape &shape() const { return shape_; }
    std::size_t padded_constraints() const {
        return padded_constraints_;
    }
    std::size_t assignment_half_size() const { return assignment_half_; }
    std::size_t padded_variables() const;
    std::size_t row_variables() const;
    std::size_t column_variables() const;
    const Digest &digest() const { return digest_; }

    /// Validate dimension padding and the public/private assignment split.
    bool is_well_formed() const;

    bool operator==(const R1csMetadata &) const = default;

  private:
    R1csShape shape_{};
    std::size_t padded_constraints_ = 0;
    std::size_t assignment_half_ = 0;
    Digest digest_{};
};

/// Materialized standalone R1CS. Entries are sorted, duplicate coordinates
/// are merged modulo q, and resulting zero entries are removed.
class R1csInstance {
  public:
    R1csInstance(R1csShape shape, std::vector<R1csEntry> a,
                 std::vector<R1csEntry> b, std::vector<R1csEntry> c);

    /// Compact structured relation.  The oracle supplies matrix products and
    /// MLEs without expanding the global sparse matrices.
    R1csInstance(
        R1csShape shape,
        std::shared_ptr<const MatrixEvaluationOracle> structured_oracle,
        std::uint64_t nonzero_entries);

    const R1csShape &shape() const { return shape_; }
    std::size_t padded_constraints() const { return padded_constraints_; }
    std::size_t assignment_half_size() const { return assignment_half_; }
    std::size_t padded_variables() const { return 2 * assignment_half_; }
    std::size_t row_variables() const;
    std::size_t column_variables() const;
    const Digest &digest() const { return digest_; }
    R1csMetadata metadata() const;

    const std::vector<R1csEntry> &entries(Matrix matrix) const;
    std::uint64_t nonzero_entries() const;

    /// Map a conventional `[1|x|w]` column into `[1|x|0... | w|0...]`.
    std::size_t padded_column(std::uint64_t conventional_column) const;

    /// Build the padded assignment z and separately return the padded witness
    /// half committed by the PCS.
    std::vector<Fq> padded_assignment(const R1csAssignment &assignment) const;
    std::vector<Fq> padded_witness(const R1csAssignment &assignment) const;

    std::vector<Fq> multiply(Matrix matrix,
                             std::span<const Fq> padded_assignment) const;

    /// Dense wiring table M(r_x, y) for
    /// `M = A + gamma B + gamma^2 C`.
    std::vector<Fq2> batched_wiring_table(
        std::span<const Fq2> row_point, const Fq2 &gamma) const;

    Fq2 evaluate_matrix(Matrix matrix,
                        std::span<const Fq2> row_point,
                        std::span<const Fq2> column_point) const;

    bool is_satisfied(const R1csAssignment &assignment) const;

  private:
    R1csShape shape_;
    std::size_t padded_constraints_ = 0;
    std::size_t assignment_half_ = 0;
    std::vector<R1csEntry> a_;
    std::vector<R1csEntry> b_;
    std::vector<R1csEntry> c_;
    Digest digest_{};
    std::shared_ptr<const MatrixEvaluationOracle> structured_oracle_;
    std::uint64_t structured_nonzero_entries_ = 0;
};

} // namespace laminate::spartan

#endif // LAMINATE_SPARTAN_R1CS_HPP
