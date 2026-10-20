#ifndef LAMINATE_FIELD_FQ_TRANSFORM_KERNELS_HPP
#define LAMINATE_FIELD_FQ_TRANSFORM_KERNELS_HPP

/// @file fq_transform_kernels.hpp
/// @brief Exact tile arithmetic used by external native-Fq transforms.

#include "laminate/field/fq.hpp"

#include <cstddef>
#include <span>

namespace laminate {

/// Multiply tile entry `(row,column)` by
/// `root^((row_begin + row) * (column_begin + column))`.
void apply_fq_twiddle_tile(std::span<Fq> tile, std::size_t rows,
                           std::size_t columns, std::size_t row_begin,
                           std::size_t column_begin, const Fq &root);

/// Transpose one dense row-major tile into a dense row-major output tile.
/// The input and output spans must not overlap.
void transpose_fq_tile(std::span<const Fq> input, std::span<Fq> output,
                       std::size_t rows, std::size_t columns);

} // namespace laminate

#endif // LAMINATE_FIELD_FQ_TRANSFORM_KERNELS_HPP
