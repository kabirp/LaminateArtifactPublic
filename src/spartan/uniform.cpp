/// @file uniform.cpp
/// @brief Compact repeated-matrix implementation for uniform Spartan.

#include "laminate/spartan/uniform.hpp"

#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::spartan {
namespace {

std::size_t checked_product(std::size_t left, std::size_t right,
                            const char *label) {
    if (left != 0 && right > std::numeric_limits<std::size_t>::max() / left) {
        throw std::overflow_error(label);
    }
    return left * right;
}

std::uint64_t as_u64(std::size_t value, const char *label) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(label);
    }
    return static_cast<std::uint64_t>(value);
}

std::size_t as_size(std::uint64_t value, const char *label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(label);
    }
    return static_cast<std::size_t>(value);
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

std::vector<Fq2> equality_table(std::span<const Fq2> point) {
    if (point.size() >= std::numeric_limits<std::size_t>::digits) {
        throw std::overflow_error("uniform equality table is too large");
    }
    std::vector<Fq2> result(std::size_t{1} << point.size(), Fq2::zero());
    result[0] = Fq2::one();
    std::size_t active = 1;
    for (const Fq2 &coordinate : point) {
        for (std::size_t index = active; index-- > 0;) {
            const Fq2 previous = result[index];
            const Fq2 high = previous * coordinate;
            result[2 * index] = previous - high;
            result[2 * index + 1] = high;
        }
        active *= 2;
    }
    return result;
}

Fq2 zero_index_evaluation(std::span<const Fq2> point) {
    Fq2 result = Fq2::one();
    for (const Fq2 &coordinate : point) {
        result *= Fq2::one() - coordinate;
    }
    return result;
}

Fq2 prefix_sum_from_bit_weights(
    std::span<const Fq2> zero_weights,
    std::span<const Fq2> one_weights,
    std::size_t exclusive_limit) {
    if (zero_weights.size() != one_weights.size() ||
        zero_weights.size() >= std::numeric_limits<std::size_t>::digits) {
        throw std::invalid_argument("invalid prefix-weight domain");
    }
    const std::size_t domain =
        std::size_t{1} << zero_weights.size();
    if (exclusive_limit > domain) {
        throw std::invalid_argument("prefix limit exceeds its domain");
    }

    // suffix[i] is the total weight of every suffix below bit i:
    //
    //   suffix[i] = product_{j >= i} (w_j(0) + w_j(1)).
    std::vector<Fq2> suffix(zero_weights.size() + 1, Fq2::one());
    for (std::size_t bit = zero_weights.size(); bit-- > 0;) {
        suffix[bit] =
            (zero_weights[bit] + one_weights[bit]) * suffix[bit + 1];
    }
    if (exclusive_limit == domain) {
        return suffix.front();
    }

    // Scan the binary prefix of `exclusive_limit`. Whenever its next bit is
    // one, add the complete branch obtained by taking zero at that bit.
    Fq2 result = Fq2::zero();
    Fq2 equal_prefix = Fq2::one();
    for (std::size_t bit = 0; bit < zero_weights.size(); ++bit) {
        const bool limit_bit =
            ((exclusive_limit >>
              (zero_weights.size() - 1 - bit)) &
             1U) != 0;
        if (limit_bit) {
            result += equal_prefix * zero_weights[bit] * suffix[bit + 1];
            equal_prefix *= one_weights[bit];
        } else {
            equal_prefix *= zero_weights[bit];
        }
    }
    return result;
}

/// Sum the multilinear equality basis over `[0, exclusive_limit)`:
///
///   sum_i eq(point, i).
Fq2 equality_prefix_sum(std::span<const Fq2> point,
                        std::size_t exclusive_limit) {
    std::vector<Fq2> zero_weights;
    std::vector<Fq2> one_weights;
    zero_weights.reserve(point.size());
    one_weights.reserve(point.size());
    for (const Fq2 &coordinate : point) {
        zero_weights.push_back(Fq2::one() - coordinate);
        one_weights.push_back(coordinate);
    }
    return prefix_sum_from_bit_weights(
        zero_weights, one_weights, exclusive_limit);
}

/// Sum two equality bases over the same live prefix:
///
///   sum_i eq(left, i) * eq(right, i).
Fq2 equality_product_prefix_sum(
    std::span<const Fq2> left, std::span<const Fq2> right,
    std::size_t exclusive_limit) {
    if (left.size() != right.size()) {
        throw std::invalid_argument(
            "equality-product points have different dimensions");
    }
    std::vector<Fq2> zero_weights;
    std::vector<Fq2> one_weights;
    zero_weights.reserve(left.size());
    one_weights.reserve(left.size());
    for (std::size_t bit = 0; bit < left.size(); ++bit) {
        zero_weights.push_back(
            (Fq2::one() - left[bit]) * (Fq2::one() - right[bit]));
        one_weights.push_back(left[bit] * right[bit]);
    }
    return prefix_sum_from_bit_weights(
        zero_weights, one_weights, exclusive_limit);
}

class UniformMatrixOracle final : public MatrixEvaluationOracle {
  public:
    UniformMatrixOracle(std::shared_ptr<const R1csInstance> local,
                        std::size_t cycles)
        : local_(std::move(local)), cycles_(cycles) {
        if (cycles_ == 0 ||
            cycles_ >
                (std::numeric_limits<std::size_t>::max() >> 1U) + 1U) {
            throw std::overflow_error(
                "uniform cycle count cannot be padded");
        }
        padded_cycles_ = std::bit_ceil(cycles_);
        const std::size_t cycle_variables =
            std::countr_zero(padded_cycles_);
        const std::size_t local_public_inputs = as_size(
            local_->shape().public_inputs,
            "uniform local public inputs exceed size_t");
        public_stride_ =
            local_public_inputs == 0
                ? 0
                : std::bit_ceil(local_public_inputs + 1U);
        witness_stride_ = local_->assignment_half_size();
        if (public_stride_ > witness_stride_) {
            throw std::logic_error(
                "uniform public stride exceeds its assignment half");
        }
        row_variables_ = cycle_variables + local_->row_variables();
        column_variables_ =
            1U + cycle_variables +
            std::countr_zero(witness_stride_);

        std::vector<std::uint8_t> encoding;
        constexpr std::string_view circuit_domain =
            "LaminateImpl/Spartan/UniformR1CS/v1";
        encoding.insert(encoding.end(), circuit_domain.begin(),
                        circuit_domain.end());
        encoding.insert(encoding.end(), local_->digest().begin(),
                        local_->digest().end());
        append_u64(encoding, cycles_);
        append_u64(encoding, padded_cycles_);
        append_u64(encoding, local_->padded_constraints());
        append_u64(encoding, public_stride_);
        append_u64(encoding, witness_stride_);
        circuit_digest_ = sha256(encoding);
        constexpr std::string_view oracle_domain =
            "LaminateImpl/Spartan/UniformMatrixOracle/v1";
        encoding.assign(oracle_domain.begin(), oracle_domain.end());
        encoding.insert(encoding.end(), circuit_digest_.begin(),
                        circuit_digest_.end());
        oracle_digest_ = sha256(encoding);
    }

    const Digest &circuit_digest() const override {
        return circuit_digest_;
    }
    const Digest &oracle_digest() const override { return oracle_digest_; }
    std::size_t row_variables() const override { return row_variables_; }
    std::size_t column_variables() const override {
        return column_variables_;
    }
    std::size_t public_stride() const { return public_stride_; }
    std::size_t witness_stride() const { return witness_stride_; }
    std::size_t padded_cycles() const { return padded_cycles_; }

    std::array<Fq2, 3> evaluate_matrices(
        std::span<const Fq2> row_point,
        std::span<const Fq2> column_point) const override {
        validate_points(row_point, column_point);
        const std::size_t cycle_variables =
            std::countr_zero(padded_cycles_);
        const std::size_t local_public_inputs = as_size(
            local_->shape().public_inputs,
            "uniform local public inputs exceed size_t");
        const auto row_cycle = row_point.first(cycle_variables);
        const auto row_local = row_point.subspan(cycle_variables);
        const Fq2 witness_selector = column_point.front();
        const auto witness_cycle =
            column_point.subspan(1, cycle_variables);
        const auto witness_local =
            column_point.subspan(1 + cycle_variables);
        const std::vector<Fq2> row_eq = equality_table(row_local);
        const std::vector<Fq2> witness_eq = equality_table(witness_local);
        const Fq2 row_cycle_sum =
            equality_prefix_sum(row_cycle, cycles_);
        const Fq2 witness_cycle_eq = equality_product_prefix_sum(
            row_cycle, witness_cycle, cycles_);
        const Fq2 constant_weight = zero_index_evaluation(column_point);

        Fq2 public_prefix_weight = Fq2::zero();
        Fq2 public_cycle_eq = Fq2::zero();
        std::vector<Fq2> public_eq;
        if (public_stride_ != 0) {
            const std::size_t public_variables =
                std::countr_zero(public_stride_);
            const std::size_t prefix_variables =
                std::countr_zero(witness_stride_) - public_variables;
            const auto column_tail = column_point.subspan(1);
            public_prefix_weight = zero_index_evaluation(
                column_tail.first(prefix_variables));
            const auto public_cycle = column_tail.subspan(
                prefix_variables, cycle_variables);
            public_cycle_eq = equality_product_prefix_sum(
                row_cycle, public_cycle, cycles_);
            public_eq = equality_table(
                column_tail.subspan(prefix_variables + cycle_variables));
        }

        std::array<Fq2, 3> result{};
        for (std::size_t matrix_index = 0; matrix_index < 3;
             ++matrix_index) {
            Fq2 local_witness = Fq2::zero();
            Fq2 local_public = Fq2::zero();
            Fq2 local_constant = Fq2::zero();
            for (const R1csEntry &entry : local_->entries(
                     static_cast<Matrix>(matrix_index))) {
                const Fq2 row_weight =
                    row_eq[static_cast<std::size_t>(entry.row)];
                if (entry.column == 0) {
                    local_constant += row_weight * entry.value;
                } else if (entry.column <= local_public_inputs) {
                    local_public +=
                        row_weight * entry.value *
                        public_eq[static_cast<std::size_t>(entry.column)];
                } else {
                    const std::size_t local_column =
                        static_cast<std::size_t>(
                            entry.column - local_public_inputs - 1U);
                    local_witness += row_weight * entry.value *
                                     witness_eq[local_column];
                }
            }
            result[matrix_index] =
                constant_weight * row_cycle_sum * local_constant +
                (Fq2::one() - witness_selector) *
                    public_prefix_weight * public_cycle_eq * local_public +
                witness_selector * witness_cycle_eq * local_witness;
        }
        return result;
    }

    std::vector<Fq> multiply(
        Matrix matrix,
        std::span<const Fq> padded_assignment) const override {
        const std::size_t half = checked_product(
            padded_cycles_, witness_stride_,
            "uniform assignment half overflows size_t");
        if (padded_assignment.size() != 2 * half) {
            throw std::invalid_argument(
                "uniform matrix-vector input has the wrong dimension");
        }
        const std::size_t rows_per_cycle = local_->padded_constraints();
        std::vector<Fq> result(
            checked_product(padded_cycles_, rows_per_cycle,
                            "uniform row domain overflows size_t"),
            Fq::zero());
        const auto &entries = local_->entries(matrix);
        const std::size_t local_public_inputs = as_size(
            local_->shape().public_inputs,
            "uniform local public inputs exceed size_t");
        for (std::size_t cycle = 0; cycle < cycles_; ++cycle) {
            const std::size_t row_base = cycle * rows_per_cycle;
            const std::size_t public_base = cycle * public_stride_;
            const std::size_t witness_base =
                half + cycle * witness_stride_;
            for (const R1csEntry &entry : entries) {
                const Fq *value = nullptr;
                if (entry.column == 0) {
                    value = &padded_assignment[0];
                } else if (entry.column <= local_public_inputs) {
                    value = &padded_assignment[
                        public_base +
                        static_cast<std::size_t>(entry.column)];
                } else {
                    value = &padded_assignment[
                        witness_base + static_cast<std::size_t>(
                                           entry.column -
                                           local_public_inputs - 1U)];
                }
                result[row_base + static_cast<std::size_t>(entry.row)] +=
                    entry.value * *value;
            }
        }
        return result;
    }

    std::vector<Fq2> batched_wiring_table(
        std::span<const Fq2> row_point,
        const Fq2 &gamma) const override {
        if (row_point.size() != row_variables_) {
            throw std::invalid_argument(
                "uniform row point has the wrong dimension");
        }
        const std::size_t cycle_variables =
            std::countr_zero(padded_cycles_);
        const auto row_cycle = row_point.first(cycle_variables);
        const auto row_local = row_point.subspan(cycle_variables);
        const std::vector<Fq2> cycle_eq = equality_table(row_cycle);
        const std::vector<Fq2> row_eq = equality_table(row_local);
        const std::array<Fq2, 3> batching{
            Fq2::one(), gamma, gamma * gamma};
        const std::size_t local_public_inputs = as_size(
            local_->shape().public_inputs,
            "uniform local public inputs exceed size_t");
        std::vector<Fq2> local_public(public_stride_, Fq2::zero());
        std::vector<Fq2> local_witness(witness_stride_, Fq2::zero());
        Fq2 constant = Fq2::zero();
        for (std::size_t matrix_index = 0; matrix_index < 3;
             ++matrix_index) {
            for (const R1csEntry &entry : local_->entries(
                     static_cast<Matrix>(matrix_index))) {
                const Fq2 weighted = batching[matrix_index] * entry.value *
                                     row_eq[static_cast<std::size_t>(entry.row)];
                if (entry.column == 0) {
                    constant += weighted;
                } else if (entry.column <= local_public_inputs) {
                    local_public[static_cast<std::size_t>(entry.column)] +=
                        weighted;
                } else {
                    local_witness[static_cast<std::size_t>(
                        entry.column - local_public_inputs - 1U)] += weighted;
                }
            }
        }

        const std::size_t half = checked_product(
            padded_cycles_, witness_stride_,
            "uniform assignment half overflows size_t");
        std::vector<Fq2> result(2 * half, Fq2::zero());
        Fq2 constant_cycle_weight = Fq2::zero();
        for (std::size_t cycle = 0; cycle < cycles_; ++cycle) {
            constant_cycle_weight += cycle_eq[cycle];
        }
        result[0] = constant_cycle_weight * constant;
        for (std::size_t cycle = 0; cycle < cycles_; ++cycle) {
            const std::size_t public_begin = cycle * public_stride_;
            for (std::size_t column = 1; column < public_stride_; ++column) {
                result[public_begin + column] =
                    cycle_eq[cycle] * local_public[column];
            }
            const std::size_t witness_begin =
                half + cycle * witness_stride_;
            for (std::size_t column = 0; column < witness_stride_; ++column) {
                result[witness_begin + column] =
                    cycle_eq[cycle] * local_witness[column];
            }
        }
        return result;
    }

  private:
    void validate_points(std::span<const Fq2> row_point,
                         std::span<const Fq2> column_point) const {
        if (row_point.size() != row_variables_ ||
            column_point.size() != column_variables_) {
            throw std::invalid_argument(
                "uniform matrix point has the wrong dimension");
        }
    }

    std::shared_ptr<const R1csInstance> local_;
    std::size_t cycles_ = 0;
    std::size_t padded_cycles_ = 0;
    std::size_t public_stride_ = 0;
    std::size_t witness_stride_ = 0;
    std::size_t row_variables_ = 0;
    std::size_t column_variables_ = 0;
    Digest circuit_digest_{};
    Digest oracle_digest_{};
};

} // namespace

CompiledUniformR1cs compile_uniform_r1cs(R1csInstance local_circuit,
                                         std::size_t cycles) {
    if (cycles == 0) {
        throw std::invalid_argument(
            "uniform R1CS needs a nonzero cycle count");
    }
    const std::size_t constraints = checked_product(
        cycles, local_circuit.padded_constraints(),
        "uniform constraint count overflows size_t");
    const std::uint64_t local_nonzeros = local_circuit.nonzero_entries();
    if (local_nonzeros != 0 &&
        cycles > std::numeric_limits<std::uint64_t>::max() /
                     local_nonzeros) {
        throw std::overflow_error("uniform nonzero count exceeds u64");
    }
    auto local =
        std::make_shared<const R1csInstance>(std::move(local_circuit));
    auto oracle = std::make_shared<const UniformMatrixOracle>(
        local, cycles);
    const std::size_t public_cells = checked_product(
        oracle->padded_cycles(), oracle->public_stride(),
        "uniform public input count overflows size_t");
    const std::size_t public_inputs =
        public_cells == 0 ? 0 : public_cells - 1U;
    const std::size_t witnesses = checked_product(
        oracle->padded_cycles(), oracle->witness_stride(),
        "uniform witness count overflows size_t");
    R1csInstance circuit(
        R1csShape{.constraints = as_u64(constraints,
                                        "uniform constraints exceed u64"),
                  .public_inputs = as_u64(
                      public_inputs, "uniform public inputs exceed u64"),
                  .witness_variables =
                      as_u64(witnesses, "uniform witnesses exceed u64")},
        oracle, local_nonzeros * cycles);
    const std::size_t padded_cycles = oracle->padded_cycles();
    const std::size_t public_stride = oracle->public_stride();
    const std::size_t witness_stride = oracle->witness_stride();
    return CompiledUniformR1cs{
        std::move(circuit), std::move(oracle), cycles, padded_cycles,
        public_stride, witness_stride};
}

} // namespace laminate::spartan
