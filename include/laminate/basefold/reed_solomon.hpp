#ifndef LAMINATE_BASEFOLD_REED_SOLOMON_HPP
#define LAMINATE_BASEFOLD_REED_SOLOMON_HPP

/// @file reed_solomon.hpp
/// @brief The NTT and multilinear coefficient transform used by BaseFold.
///
/// A message is supplied as hypercube evaluations in LSB-first order. The
/// Mobius transform produces multilinear coefficients; reading those
/// coefficients as a univariate polynomial and evaluating it on a
/// multiplicative subgroup gives the BaseFold Reed--Solomon codeword.

#include "laminate/field/fp.hpp"
#include "laminate/field/fpk.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace laminate::basefold {

void ntt_in_place(std::vector<Fp> &values, const Fp &generator);
void ntt_in_place(std::vector<Fpk> &values, const Fp &generator);

std::vector<Fp> evaluations_to_coefficients(std::span<const Fp> values);
std::vector<Fpk> evaluations_to_coefficients(std::span<const Fpk> values);
std::vector<Fp> coefficients_to_evaluations(std::span<const Fp> values);

std::vector<Fp> reed_solomon_encode(std::span<const Fp> coefficients,
                                    std::size_t log_rate);
std::vector<Fpk> reed_solomon_encode(std::span<const Fpk> coefficients,
                                     std::size_t log_rate);

} // namespace laminate::basefold

#endif // LAMINATE_BASEFOLD_REED_SOLOMON_HPP
