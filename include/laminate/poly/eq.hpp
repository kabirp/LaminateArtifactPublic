#ifndef LAMINATE_POLY_EQ_HPP
#define LAMINATE_POLY_EQ_HPP

/// @file eq.hpp
/// @brief Equality MLEs and the exact BGV-grid rotation predicate.

#include "laminate/fhe/layout/slot_grid.hpp"
#include "laminate/poly/multilinear.hpp"

#include <cstddef>
#include <limits>
#include <stdexcept>
#include <vector>

namespace laminate::poly {

/// Return [eq(point, vertex)] in MSB-first Boolean-hypercube order.
template <Field Value>
std::vector<Value> eq_evaluations(const std::vector<Value> &point) {
    (void)hypercube_size(point.size());
    std::vector<Value> result{Value::one()};
    for (const Value &coordinate : point) {
        std::vector<Value> next(result.size() * 2, Value::zero());
        for (std::size_t index = 0; index < result.size(); ++index) {
            const Value high = result[index] * coordinate;
            next[2 * index] = result[index] - high;
            next[2 * index + 1] = high;
        }
        result = std::move(next);
    }
    return result;
}

template <Field Value>
Multilinear<Value> eq_table(const std::vector<Value> &point) {
    return Multilinear<Value>(point.size(), eq_evaluations(point));
}

template <Field Value>
Value eq_eval(const std::vector<Value> &left,
              const std::vector<Value> &right) {
    if (left.size() != right.size()) {
        throw std::invalid_argument("eq_eval: point sizes differ");
    }
    Value result = Value::one();
    for (std::size_t index = 0; index < left.size(); ++index) {
        result *= left[index] * right[index] +
                  (Value::one() - left[index]) *
                      (Value::one() - right[index]);
    }
    return result;
}

/// Evaluate the MLE of `out[u] = in[(u + shift) mod 2^m]` in O(m).
/// A two-state carry DP is used from the least significant bit upward, while
/// coordinates themselves remain stored MSB-first.
template <Field Value>
Value cyclic_shift_eval(const std::vector<Value> &input_point,
                        const std::vector<Value> &output_point,
                        std::size_t shift) {
    if (input_point.size() != output_point.size()) {
        throw std::invalid_argument(
            "cyclic_shift_eval: point sizes differ");
    }
    const std::size_t num_vars = input_point.size();
    if (num_vars >=
        static_cast<std::size_t>(std::numeric_limits<std::size_t>::digits)) {
        throw std::invalid_argument(
            "cyclic_shift_eval: number of variables overflows size_t");
    }

    const std::size_t modulus = hypercube_size(num_vars);
    const std::size_t normalized = shift % modulus;
    Value carry_zero = Value::one();
    Value carry_one = Value::zero();
    for (std::size_t bit = 0; bit < num_vars; ++bit) {
        const Value &input = input_point[num_vars - 1 - bit];
        const Value &output = output_point[num_vars - 1 - bit];
        const std::size_t shift_bit = (normalized >> bit) & 1U;
        Value next_zero = Value::zero();
        Value next_one = Value::zero();
        for (std::size_t carry = 0; carry < 2; ++carry) {
            const Value &prefix = carry == 0 ? carry_zero : carry_one;
            for (std::size_t input_bit = 0; input_bit < 2; ++input_bit) {
                const std::size_t sum = input_bit + shift_bit + carry;
                const Value input_weight =
                    input_bit == 0 ? Value::one() - input : input;
                const Value output_weight =
                    (sum & 1U) == 0 ? Value::one() - output : output;
                Value &destination =
                    (sum >> 1U) == 0 ? next_zero : next_one;
                destination += prefix * input_weight * output_weight;
            }
        }
        carry_zero = next_zero;
        carry_one = next_one;
    }
    return carry_zero + carry_one;
}

/// Evaluate the MLE of the shared BGV action with a field-valued action
/// offset. All three points use MSB-first coordinates
///
///   [row-swap bit | within-row rotation bits].
///
/// On Boolean points the predicate is
///
///   source = grid_source(N, offset, destination).
///
/// The row-swap relation is evaluated directly. The within-row modular sum
/// is evaluated from least to most significant bit with a two-state carry DP.
template <Field Value>
Value grid_action_eval(const std::vector<Value> &destination_point,
                       const std::vector<Value> &source_point,
                       const std::vector<Value> &offset_point) {
    if (destination_point.size() != source_point.size() ||
        destination_point.size() != offset_point.size()) {
        throw std::invalid_argument(
            "grid_action_eval: point sizes differ");
    }
    if (destination_point.empty()) {
        throw std::invalid_argument(
            "grid_action_eval: a slot index needs at least one bit");
    }

    const auto bit_weight = [](const Value &coordinate,
                               std::size_t bit) {
        return bit == 0 ? Value::one() - coordinate : coordinate;
    };

    // source_row = destination_row XOR offset_row.
    Value row = Value::zero();
    for (std::size_t destination_bit = 0; destination_bit < 2;
         ++destination_bit) {
        for (std::size_t offset_bit = 0; offset_bit < 2; ++offset_bit) {
            const std::size_t source_bit =
                destination_bit ^ offset_bit;
            row += bit_weight(destination_point.front(), destination_bit) *
                   bit_weight(source_point.front(), source_bit) *
                   bit_weight(offset_point.front(), offset_bit);
        }
    }

    // source_column = destination_column + offset_column mod N/2.
    // The carry beyond the most-significant within-row bit is discarded.
    Value carry_zero = Value::one();
    Value carry_one = Value::zero();
    for (std::size_t bit = 0; bit + 1 < destination_point.size(); ++bit) {
        const std::size_t variable = destination_point.size() - 1U - bit;
        Value next_zero = Value::zero();
        Value next_one = Value::zero();
        for (std::size_t carry = 0; carry < 2; ++carry) {
            const Value &prefix = carry == 0 ? carry_zero : carry_one;
            for (std::size_t destination_bit = 0; destination_bit < 2;
                 ++destination_bit) {
                for (std::size_t offset_bit = 0; offset_bit < 2;
                     ++offset_bit) {
                    const std::size_t sum =
                        destination_bit + offset_bit + carry;
                    const std::size_t source_bit = sum & 1U;
                    Value &next =
                        (sum >> 1U) == 0 ? next_zero : next_one;
                    next += prefix *
                            bit_weight(destination_point[variable],
                                       destination_bit) *
                            bit_weight(source_point[variable], source_bit) *
                            bit_weight(offset_point[variable], offset_bit);
                }
            }
        }
        carry_zero = next_zero;
        carry_one = next_one;
    }
    return row * (carry_zero + carry_one);
}

/// Evaluate the MLE of the shared BGV 2 x (N/2) grid permutation:
///
///   sum_l eq(row_point, l)
///             * eq(column_point, grid_source(N, step, l)).
///
/// This is the matrix convention for `out[l] = in[grid_source(..., l)]`.
template <Field Value>
Value grid_rotation_eval(const std::vector<Value> &row_point,
                         const std::vector<Value> &column_point,
                         std::size_t step) {
    if (row_point.size() != column_point.size()) {
        throw std::invalid_argument(
            "grid_rotation_eval: point sizes differ");
    }
    if (row_point.empty()) {
        throw std::invalid_argument(
            "grid_rotation_eval: a slot index needs at least one bit");
    }
    const std::size_t slot_count = hypercube_size(row_point.size());
    const std::size_t half = slot_count / 2;
    const std::size_t normalized = step % slot_count;
    const bool swap_rows = normalized >= half;

    const Value same_row = row_point.front() * column_point.front() +
                           (Value::one() - row_point.front()) *
                               (Value::one() - column_point.front());
    const Value different_row =
        row_point.front() * (Value::one() - column_point.front()) +
        (Value::one() - row_point.front()) * column_point.front();
    const std::vector<Value> row_column(row_point.begin() + 1,
                                        row_point.end());
    const std::vector<Value> source_column(column_point.begin() + 1,
                                           column_point.end());
    return (swap_rows ? different_row : same_row) *
           cyclic_shift_eval(row_column, source_column, normalized % half);
}

} // namespace laminate::poly

#endif // LAMINATE_POLY_EQ_HPP
