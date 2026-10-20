#ifndef LAMINATE_GKR_DETAIL_BASE_CLAIMS_EVALUATION_HPP
#define LAMINATE_GKR_DETAIL_BASE_CLAIMS_EVALUATION_HPP

/// @file evaluation.hpp
/// @brief Claim composition and affine GateMLE evaluation for Base.

#include "laminate/gates/gate_mle.hpp"
#include "laminate/gkr/claims.hpp"

#include <cstddef>
#include <span>
#include <variant>
#include <vector>

namespace laminate::gkr::base_detail {

inline std::vector<Fpk> concatenate(std::span<const Fpk> first,
                                    std::span<const Fpk> second) {
    std::vector<Fpk> result;
    result.reserve(first.size() + second.size());
    result.insert(result.end(), first.begin(), first.end());
    result.insert(result.end(), second.begin(), second.end());
    return result;
}

inline Fpk claim_value(const LayerClaim &claim) {
    return std::visit([](const auto &typed) { return typed.value; }, claim);
}

template <typename Provider>
Fpk affine_gate_at(Provider &provider, std::size_t layer,
                   const LayerClaim &claim,
                   std::span<const Fpk> source_point) {
    if (const auto *single = std::get_if<SingleClaim>(&claim)) {
        return provider.evaluate(gates::GateMleQuery{gates::AffineQuery{
            layer, single->point, source_point}});
    }
    const BatchedClaim &batched = std::get<BatchedClaim>(claim);
    if constexpr (requires {
                      provider.evaluate_affine_pair(
                          layer, batched.first.point,
                          batched.second.point, source_point,
                          batched.challenge);
                  }) {
        return provider.evaluate_affine_pair(
            layer, batched.first.point, batched.second.point,
            source_point, batched.challenge);
    } else {
        const Fpk first = provider.evaluate(
            gates::GateMleQuery{gates::AffineQuery{
                layer, batched.first.point, source_point}});
        const Fpk second = provider.evaluate(
            gates::GateMleQuery{gates::AffineQuery{
                layer, batched.second.point, source_point}});
        return first + batched.challenge * second;
    }
}

template <typename Provider>
Fpk affine_constant_at(Provider &provider, std::size_t layer,
                       const LayerClaim &claim) {
    if (const auto *single = std::get_if<SingleClaim>(&claim)) {
        return provider.evaluate_affine_constant(layer, single->point);
    }
    const BatchedClaim &batched = std::get<BatchedClaim>(claim);
    if constexpr (requires {
                      provider.evaluate_affine_constant_pair(
                          layer, batched.first.point,
                          batched.second.point, batched.challenge);
                  }) {
        return provider.evaluate_affine_constant_pair(
            layer, batched.first.point, batched.second.point,
            batched.challenge);
    } else {
        const Fpk first = provider.evaluate_affine_constant(
            layer, batched.first.point);
        const Fpk second = provider.evaluate_affine_constant(
            layer, batched.second.point);
        return first + batched.challenge * second;
    }
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_CLAIMS_EVALUATION_HPP
