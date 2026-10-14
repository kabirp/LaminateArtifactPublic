#ifndef LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_GATE_MLE_HPP
#define LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_GATE_MLE_HPP

/// @file gate_mle.hpp
/// @brief Prepared public GateMLE state for Base affine reductions.

#include "laminate/gkr/detail/base/claims/evaluation.hpp"

#include <cstddef>
#include <limits>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::base_detail {

/// Direct affine GateMLEs prepared once for the current output claim.
/// Runtime GKR reductions carry one claim. The generic batched-claim form
/// remains available for isolated affine callers and combines its public
/// tables in the same order as `affine_gate_at`.
struct PreparedAffineGateMle {
    struct Basis {
        std::size_t component = 0;
        std::size_t rotation = 0;
        std::span<const Fpk> slots;
    };

    struct Component {
        gates::PreparedDirectAffineMle prepared;
        Fpk weight = Fpk::zero();
    };

    struct Bound {
        struct SparseBasisCoefficient {
            std::size_t basis = 0;
            Fpk coefficient = Fpk::zero();
        };

        std::vector<gates::BoundDirectAffineMle> components;
        std::vector<Fpk> weights;
        std::size_t suffix_count = 0;

        /// Visit the nonzero sparse rotation coefficients for one Boolean
        /// suffix without constructing a temporary coefficient vector. The
        /// prepared stream contains only structurally present matrix terms.
        /// A bound-only backend may additionally retain a term whose value
        /// became zero after multiplying by the public-claim weight; that
        /// zero depends on the modeled claim and is not structural support.
        template <typename Visit>
        void for_each_sparse_basis_coefficient(
            std::size_t suffix, bool retain_zero_weighted_terms,
            Visit &&visit) const {
            if (components.empty() || components.size() != weights.size() ||
                suffix >= suffix_count) {
                throw std::logic_error(
                    "LaminateBase prepared affine binding is invalid");
            }
            std::size_t basis_offset = 0;
            for (std::size_t component = 0;
                 component < components.size(); ++component) {
                for (const auto &entry :
                     components[component]
                         .sparse_rotation_coefficients(suffix)) {
                    const Fpk coefficient =
                        weights[component] * entry.coefficient;
                    if (entry.fixed_point_support &&
                        (retain_zero_weighted_terms ||
                         !coefficient.is_zero())) {
                        visit(SparseBasisCoefficient{
                            basis_offset + entry.rotation_index,
                            coefficient});
                    }
                }
                basis_offset +=
                    components[component].rotation_basis_count();
            }
        }
    };

    struct RollingBinding {
        std::vector<gates::RollingDirectAffineMle> components;
        std::vector<Fpk> weights;

        Bound evaluate_next(const Fpk &round_value) const {
            if (components.empty() || components.size() != weights.size()) {
                throw std::logic_error(
                    "LaminateBase rolling affine binding is invalid");
            }
            Bound result;
            result.components.reserve(components.size());
            result.weights = weights;
            for (const auto &component : components) {
                result.components.push_back(
                    component.evaluate_next(round_value));
                const std::size_t suffixes =
                    result.components.back().boolean_suffix_count();
                if (result.suffix_count == 0) {
                    result.suffix_count = suffixes;
                } else if (result.suffix_count != suffixes) {
                    throw std::logic_error(
                        "LaminateBase rolling affine suffix count drifted");
                }
            }
            return result;
        }

        void bind(const Fpk &challenge) {
            for (auto &component : components) {
                component.bind(challenge);
            }
        }

        std::size_t bound_variables() const {
            if (components.empty()) {
                throw std::logic_error(
                    "LaminateBase rolling affine binding is empty");
            }
            const std::size_t result = components.front().bound_variables();
            for (const auto &component : components) {
                if (component.bound_variables() != result) {
                    throw std::logic_error(
                        "LaminateBase rolling affine binding drifted");
                }
            }
            return result;
        }
    };

    static PreparedAffineGateMle create(
        const gates::DirectGateMle &provider, std::size_t layer,
        const LayerClaim &claim) {
        PreparedAffineGateMle result;
        if (const auto *single = std::get_if<SingleClaim>(&claim)) {
            result.components.push_back(Component{
                provider.prepare_affine(layer, single->point), Fpk::one()});
            return result;
        }
        const BatchedClaim &batched = std::get<BatchedClaim>(claim);
        result.components.push_back(Component{
            provider.prepare_affine(layer, batched.first.point),
            Fpk::one()});
        result.components.push_back(Component{
            provider.prepare_affine(layer, batched.second.point),
            batched.challenge});
        return result;
    }

    RollingBinding rolling_source_wire_binding() const {
        RollingBinding result;
        result.components.reserve(components.size());
        result.weights.reserve(components.size());
        for (const Component &component : components) {
            result.components.push_back(
                component.prepared.rolling_source_wire_binding());
            result.weights.push_back(component.weight);
        }
        if (result.components.empty()) {
            throw std::logic_error(
                "LaminateBase prepared affine claim is empty");
        }
        return result;
    }

    std::size_t weighted_term_count() const {
        std::size_t result = 0;
        for (const Component &component : components) {
            if (component.prepared.weighted_term_count() >
                std::numeric_limits<std::size_t>::max() - result) {
                throw std::overflow_error(
                    "LaminateBase affine term count overflows");
            }
            result += component.prepared.weighted_term_count();
        }
        return result;
    }

    std::vector<Basis> bases() const {
        std::vector<Basis> result;
        for (std::size_t component = 0;
             component < components.size(); ++component) {
            for (std::size_t rotation = 0;
                 rotation <
                 components[component].prepared.rotation_basis_count();
                 ++rotation) {
                result.push_back(Basis{
                    component, rotation,
                    components[component]
                        .prepared.rotation_slot_basis(rotation)});
            }
        }
        return result;
    }
    std::vector<Component> components;
};

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_GATE_MLE_HPP
