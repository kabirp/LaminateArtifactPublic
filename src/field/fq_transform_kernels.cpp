/// @file fq_transform_kernels.cpp
/// @brief Exact transpose and twiddle tile arithmetic over native Fq.

#include "laminate/field/fq_transform_kernels.hpp"

#include <stdexcept>

namespace laminate {

void apply_fq_twiddle_tile(std::span<Fq> tile, std::size_t rows,
                           std::size_t columns, std::size_t row_begin,
                           std::size_t column_begin, const Fq &root) {
    if (rows == 0 || columns == 0 || rows > tile.size() / columns ||
        rows * columns != tile.size()) {
        throw std::invalid_argument("invalid Fq twiddle tile shape");
    }
    Fq row_step = root.pow(row_begin);
    for (std::size_t row = 0; row < rows; ++row) {
        Fq twiddle = row_step.pow(column_begin);
        for (std::size_t column = 0; column < columns; ++column) {
            tile[row * columns + column] *= twiddle;
            twiddle *= row_step;
        }
        row_step *= root;
    }
}

void transpose_fq_tile(std::span<const Fq> input, std::span<Fq> output,
                       std::size_t rows, std::size_t columns) {
    if (rows == 0 || columns == 0 || rows > input.size() / columns ||
        rows * columns != input.size() || output.size() != input.size()) {
        throw std::invalid_argument("invalid Fq transpose tile shape");
    }
    for (std::size_t row = 0; row < rows; ++row) {
        for (std::size_t column = 0; column < columns; ++column) {
            output[column * rows + row] = input[row * columns + column];
        }
    }
}

} // namespace laminate
