#ifndef LAMINATE_TESTS_GKR_REFERENCE_HELPERS_HPP
#define LAMINATE_TESTS_GKR_REFERENCE_HELPERS_HPP

/// @file gkr_reference_helpers.hpp
/// @brief Slow, explicit MLE helpers used only by correctness tests.

#include "laminate/field/fpk.hpp"
#include "laminate/poly/eq.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::test {

inline std::vector<Fpk> hypercube_vertex(std::size_t index,
                                         std::size_t variables) {
    std::vector<Fpk> result;
    result.reserve(variables);
    for (std::size_t variable = 0; variable < variables; ++variable) {
        const bool bit =
            ((index >> (variables - 1U - variable)) & 1U) != 0;
        result.push_back(bit ? Fpk::one() : Fpk::zero());
    }
    return result;
}

inline Fpk evaluate_mle_reference(std::span<const Fpk> evaluations,
                                  std::span<const Fpk> point) {
    if (evaluations.size() != poly::hypercube_size(point.size())) {
        throw std::invalid_argument(
            "reference MLE table and point dimensions differ");
    }
    const std::vector<Fpk> owned_point(point.begin(), point.end());
    const std::vector<Fpk> weights = poly::eq_evaluations(owned_point);
    Fpk result = Fpk::zero();
    for (std::size_t index = 0; index < evaluations.size(); ++index) {
        result += weights[index] * evaluations[index];
    }
    return result;
}

} // namespace laminate::test

#endif // LAMINATE_TESTS_GKR_REFERENCE_HELPERS_HPP
