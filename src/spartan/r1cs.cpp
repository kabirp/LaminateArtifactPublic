/// @file r1cs.cpp
/// @brief Canonicalization and evaluation of sparse Spartan R1CS instances.

#include "laminate/spartan/r1cs.hpp"

#include "laminate/field/serialization.hpp"
#include "laminate/spartan/matrix_oracle.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <stdexcept>
#include <string>
#include <tuple>

namespace laminate::spartan {
namespace {

std::size_t checked_size(std::uint64_t value, const char *label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds size_t");
    }
    return static_cast<std::size_t>(value);
}

std::size_t next_power_of_two(std::size_t value, const char *label) {
    if (value == 0 || value >
                          (std::numeric_limits<std::size_t>::max() >> 1U) +
                              1U) {
        throw std::overflow_error(std::string(label) + " cannot be padded");
    }
    return std::bit_ceil(value);
}

std::size_t log2_exact(std::size_t value) {
    if (value == 0 || !std::has_single_bit(value)) {
        throw std::invalid_argument("R1CS padded dimension is not a power of two");
    }
    return std::bit_width(value) - 1U;
}

std::vector<R1csEntry> canonicalize(
    std::vector<R1csEntry> entries, const R1csShape &shape,
    const char *matrix) {
    if (shape.public_inputs >
        std::numeric_limits<std::uint64_t>::max() - 1U ||
        shape.witness_variables >
            std::numeric_limits<std::uint64_t>::max() -
                (shape.public_inputs + 1U)) {
        throw std::overflow_error("R1CS variable count overflows u64");
    }
    const std::uint64_t columns =
        1U + shape.public_inputs + shape.witness_variables;
    for (const R1csEntry &entry : entries) {
        if (entry.row >= shape.constraints || entry.column >= columns) {
            throw std::invalid_argument(std::string("R1CS ") + matrix +
                                        " entry is out of range");
        }
    }
    std::sort(entries.begin(), entries.end(),
              [](const R1csEntry &left, const R1csEntry &right) {
                  return std::tie(left.row, left.column) <
                         std::tie(right.row, right.column);
              });
    std::vector<R1csEntry> result;
    result.reserve(entries.size());
    for (const R1csEntry &entry : entries) {
        if (!result.empty() && result.back().row == entry.row &&
            result.back().column == entry.column) {
            result.back().value += entry.value;
            if (result.back().value.is_zero()) {
                result.pop_back();
            }
        } else if (!entry.value.is_zero()) {
            result.push_back(entry);
        }
    }
    return result;
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

void append_matrix(std::vector<std::uint8_t> &output, Matrix matrix,
                   const std::vector<R1csEntry> &entries) {
    output.push_back(static_cast<std::uint8_t>(matrix));
    append_u64(output, entries.size());
    for (const R1csEntry &entry : entries) {
        append_u64(output, entry.row);
        append_u64(output, entry.column);
        const SerializedFq value = serialize(entry.value);
        output.insert(output.end(), value.begin(), value.end());
    }
}

Digest circuit_digest(const R1csShape &shape, std::size_t padded_constraints,
                      std::size_t assignment_half,
                      const std::vector<R1csEntry> &a,
                      const std::vector<R1csEntry> &b,
                      const std::vector<R1csEntry> &c) {
    std::vector<std::uint8_t> bytes;
    constexpr std::string_view domain = "LaminateImpl/SpartanR1CS/v1";
    bytes.insert(bytes.end(), domain.begin(), domain.end());
    append_u64(bytes, shape.constraints);
    append_u64(bytes, shape.public_inputs);
    append_u64(bytes, shape.witness_variables);
    append_u64(bytes, padded_constraints);
    append_u64(bytes, assignment_half);
    append_matrix(bytes, Matrix::A, a);
    append_matrix(bytes, Matrix::B, b);
    append_matrix(bytes, Matrix::C, c);
    return sha256(bytes);
}

Fq2 eq_msb(std::size_t index, std::span<const Fq2> point) {
    Fq2 result = Fq2::one();
    for (std::size_t variable = 0; variable < point.size(); ++variable) {
        const bool bit =
            ((index >> (point.size() - 1 - variable)) & 1U) != 0;
        result *= bit ? point[variable] : Fq2::one() - point[variable];
    }
    return result;
}

} // namespace

R1csMetadata::R1csMetadata(R1csShape shape,
                           std::size_t padded_constraints,
                           std::size_t assignment_half,
                           Digest circuit_digest)
    : shape_(shape), padded_constraints_(padded_constraints),
      assignment_half_(assignment_half), digest_(circuit_digest) {
    if (!is_well_formed()) {
        throw std::invalid_argument("R1CS metadata is malformed");
    }
}

std::size_t R1csMetadata::padded_variables() const {
    if (assignment_half_ > std::numeric_limits<std::size_t>::max() / 2U) {
        throw std::overflow_error("R1CS metadata assignment size overflows");
    }
    return 2U * assignment_half_;
}

std::size_t R1csMetadata::row_variables() const {
    return log2_exact(padded_constraints_);
}

std::size_t R1csMetadata::column_variables() const {
    return log2_exact(padded_variables());
}

bool R1csMetadata::is_well_formed() const {
    if (shape_.constraints == 0 || shape_.witness_variables == 0 ||
        padded_constraints_ == 0 || assignment_half_ == 0 ||
        !std::has_single_bit(padded_constraints_) ||
        !std::has_single_bit(assignment_half_) ||
        assignment_half_ > std::numeric_limits<std::size_t>::max() / 2U) {
        return false;
    }
    if (shape_.constraints > padded_constraints_ ||
        shape_.public_inputs > std::numeric_limits<std::uint64_t>::max() - 1U) {
        return false;
    }
    const std::uint64_t public_side = shape_.public_inputs + 1U;
    return public_side <= assignment_half_ &&
           shape_.witness_variables <= assignment_half_;
}

R1csInstance::R1csInstance(R1csShape shape, std::vector<R1csEntry> a,
                           std::vector<R1csEntry> b,
                           std::vector<R1csEntry> c)
    : shape_(shape) {
    if (shape_.constraints == 0 || shape_.witness_variables == 0) {
        throw std::invalid_argument(
            "R1CS requires at least one constraint and witness variable");
    }
    const std::size_t constraints =
        checked_size(shape_.constraints, "R1CS constraint count");
    const std::size_t public_side =
        checked_size(shape_.public_inputs, "R1CS public input count") + 1U;
    const std::size_t witness_side = checked_size(
        shape_.witness_variables, "R1CS witness variable count");
    padded_constraints_ =
        next_power_of_two(constraints, "R1CS constraint count");
    assignment_half_ = next_power_of_two(
        std::max(public_side, witness_side), "R1CS assignment half");
    if (assignment_half_ > std::numeric_limits<std::size_t>::max() / 2U) {
        throw std::overflow_error("R1CS padded assignment overflows");
    }
    a_ = canonicalize(std::move(a), shape_, "A");
    b_ = canonicalize(std::move(b), shape_, "B");
    c_ = canonicalize(std::move(c), shape_, "C");
    digest_ = circuit_digest(shape_, padded_constraints_, assignment_half_,
                             a_, b_, c_);
}

R1csInstance::R1csInstance(
    R1csShape shape,
    std::shared_ptr<const MatrixEvaluationOracle> structured_oracle,
    std::uint64_t nonzero_entries)
    : R1csInstance(shape, {}, {}, {}) {
    if (structured_oracle == nullptr ||
        structured_oracle->row_variables() != row_variables() ||
        structured_oracle->column_variables() != column_variables()) {
        throw std::invalid_argument(
            "structured R1CS oracle has inconsistent dimensions");
    }
    structured_oracle_ = std::move(structured_oracle);
    structured_nonzero_entries_ = nonzero_entries;
    digest_ = structured_oracle_->circuit_digest();
}

std::size_t R1csInstance::row_variables() const {
    return log2_exact(padded_constraints_);
}

std::size_t R1csInstance::column_variables() const {
    return log2_exact(padded_variables());
}

R1csMetadata R1csInstance::metadata() const {
    return R1csMetadata(shape_, padded_constraints_, assignment_half_,
                        digest_);
}

const std::vector<R1csEntry> &R1csInstance::entries(Matrix matrix) const {
    if (structured_oracle_ != nullptr) {
        throw std::logic_error(
            "structured R1CS does not materialize global entries");
    }
    switch (matrix) {
    case Matrix::A:
        return a_;
    case Matrix::B:
        return b_;
    case Matrix::C:
        return c_;
    }
    throw std::invalid_argument("unknown R1CS matrix");
}

std::uint64_t R1csInstance::nonzero_entries() const {
    if (structured_oracle_ != nullptr) {
        return structured_nonzero_entries_;
    }
    if (b_.size() >
        std::numeric_limits<std::size_t>::max() - a_.size()) {
        throw std::overflow_error("R1CS nonzero count overflows");
    }
    const std::size_t ab = a_.size() + b_.size();
    if (c_.size() > std::numeric_limits<std::size_t>::max() - ab ||
        ab + c_.size() > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("R1CS nonzero count overflows");
    }
    return static_cast<std::uint64_t>(ab + c_.size());
}

std::size_t
R1csInstance::padded_column(std::uint64_t conventional_column) const {
    const std::uint64_t public_count = shape_.public_inputs + 1U;
    const std::uint64_t total = public_count + shape_.witness_variables;
    if (conventional_column >= total) {
        throw std::out_of_range("R1CS column is out of range");
    }
    if (conventional_column < public_count) {
        return checked_size(conventional_column, "R1CS public column");
    }
    return assignment_half_ + checked_size(
                                  conventional_column - public_count,
                                  "R1CS witness column");
}

std::vector<Fq>
R1csInstance::padded_witness(const R1csAssignment &assignment) const {
    if (assignment.public_inputs.size() != shape_.public_inputs ||
        assignment.witness.size() != shape_.witness_variables) {
        throw std::invalid_argument("R1CS assignment has wrong dimensions");
    }
    std::vector<Fq> result(assignment_half_, Fq::zero());
    std::copy(assignment.witness.begin(), assignment.witness.end(),
              result.begin());
    return result;
}

std::vector<Fq>
R1csInstance::padded_assignment(const R1csAssignment &assignment) const {
    if (assignment.public_inputs.size() != shape_.public_inputs ||
        assignment.witness.size() != shape_.witness_variables) {
        throw std::invalid_argument("R1CS assignment has wrong dimensions");
    }
    std::vector<Fq> result(2 * assignment_half_, Fq::zero());
    result[0] = Fq::one();
    std::copy(assignment.public_inputs.begin(),
              assignment.public_inputs.end(), result.begin() + 1);
    std::copy(assignment.witness.begin(), assignment.witness.end(),
              result.begin() + static_cast<std::ptrdiff_t>(assignment_half_));
    return result;
}

std::vector<Fq> R1csInstance::multiply(
    Matrix matrix, std::span<const Fq> padded_assignment_values) const {
    if (padded_assignment_values.size() != padded_variables()) {
        throw std::invalid_argument("R1CS matrix-vector input has wrong size");
    }
    if (structured_oracle_ != nullptr) {
        return structured_oracle_->multiply(matrix,
                                             padded_assignment_values);
    }
    std::vector<Fq> result(padded_constraints_, Fq::zero());
    for (const R1csEntry &entry : entries(matrix)) {
        result[static_cast<std::size_t>(entry.row)] +=
            entry.value *
            padded_assignment_values[padded_column(entry.column)];
    }
    return result;
}

std::vector<Fq2> R1csInstance::batched_wiring_table(
    std::span<const Fq2> row_point, const Fq2 &gamma) const {
    if (row_point.size() != row_variables()) {
        throw std::invalid_argument("R1CS row point has wrong dimension");
    }
    if (structured_oracle_ != nullptr) {
        return structured_oracle_->batched_wiring_table(row_point, gamma);
    }
    std::vector<Fq2> result(padded_variables(), Fq2::zero());
    const std::array<Fq2, 3> batching{Fq2::one(), gamma, gamma * gamma};
    for (std::size_t matrix = 0; matrix < 3; ++matrix) {
        for (const R1csEntry &entry :
             entries(static_cast<Matrix>(matrix))) {
            result[padded_column(entry.column)] +=
                batching[matrix] * entry.value *
                eq_msb(static_cast<std::size_t>(entry.row), row_point);
        }
    }
    return result;
}

Fq2 R1csInstance::evaluate_matrix(
    Matrix matrix, std::span<const Fq2> row_point,
    std::span<const Fq2> column_point) const {
    if (row_point.size() != row_variables() ||
        column_point.size() != column_variables()) {
        throw std::invalid_argument("R1CS matrix point has wrong dimension");
    }
    if (structured_oracle_ != nullptr) {
        return structured_oracle_->evaluate_matrices(row_point,
                                                      column_point)
            [static_cast<std::size_t>(matrix)];
    }
    Fq2 result = Fq2::zero();
    for (const R1csEntry &entry : entries(matrix)) {
        result += eq_msb(static_cast<std::size_t>(entry.row), row_point) *
                  entry.value *
                  eq_msb(padded_column(entry.column), column_point);
    }
    return result;
}

bool R1csInstance::is_satisfied(const R1csAssignment &assignment) const {
    const std::vector<Fq> z = padded_assignment(assignment);
    const std::vector<Fq> az = multiply(Matrix::A, z);
    const std::vector<Fq> bz = multiply(Matrix::B, z);
    const std::vector<Fq> cz = multiply(Matrix::C, z);
    for (std::size_t row = 0; row < padded_constraints_; ++row) {
        if (az[row] * bz[row] != cz[row]) {
            return false;
        }
    }
    return true;
}

} // namespace laminate::spartan
