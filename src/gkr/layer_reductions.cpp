/// @file layer_reductions.cpp
/// @brief Plaintext GKR layer-reduction oracle.

#include "laminate/gkr/layer_reductions.hpp"

#include "laminate/gkr/detail/shared/dense_multiplication/geometry.hpp"
#include "laminate/poly/eq.hpp"
#include "laminate/poly/multilinear.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace laminate::gkr {
namespace {

std::size_t layer_num_vars(const payload::LayeredCircuit &circuit,
                           std::size_t layer_index) {
    if (layer_index >= circuit.layers.size()) {
        throw std::invalid_argument("layer reduction: layer index is invalid");
    }
    const std::size_t wires =
        payload::layer_dimensions(circuit.layers[layer_index]).padded_size;
    const std::size_t width = circuit.shape.value_width();
    return (std::bit_width(wires) - 1U) +
           (std::bit_width(width) - 1U);
}

poly::Multilinear<Fpk>
layer_table(const payload::LayeredCircuit &circuit,
            const payload::PlainTrace &trace, std::size_t layer_index) {
    if (!(trace.shape == circuit.shape) ||
        trace.layers.size() != circuit.layers.size() ||
        layer_index >= trace.layers.size()) {
        throw std::invalid_argument(
            "layer reduction: trace and circuit dimensions differ");
    }
    const std::size_t expected_wires =
        payload::layer_dimensions(circuit.layers[layer_index]).padded_size;
    const std::size_t width = circuit.shape.value_width();
    if (trace.layers[layer_index].size() != expected_wires) {
        throw std::invalid_argument(
            "layer reduction: trace layer has the wrong wire count");
    }
    std::vector<Fpk> evaluations;
    if (expected_wires > std::numeric_limits<std::size_t>::max() / width) {
        throw std::invalid_argument(
            "layer reduction: flattened layer size overflows");
    }
    evaluations.reserve(expected_wires * width);
    for (const fhe::SlotVector &wire : trace.layers[layer_index]) {
        if (wire.size() != width) {
            throw std::invalid_argument(
                "layer reduction: trace wire has the wrong width");
        }
        for (const Fp &value : wire) {
            evaluations.push_back(Fpk::from_base(value));
        }
    }
    return poly::Multilinear<Fpk>(layer_num_vars(circuit, layer_index),
                                  std::move(evaluations));
}

std::vector<Fpk> boolean_point(std::size_t index, std::size_t num_vars) {
    std::vector<Fpk> point;
    point.reserve(num_vars);
    for (std::size_t variable = 0; variable < num_vars; ++variable) {
        const bool bit =
            ((index >> (num_vars - 1 - variable)) & 1U) != 0;
        point.push_back(bit ? Fpk::one() : Fpk::zero());
    }
    return point;
}

bool valid_claim(const LayerClaim &claim, std::size_t expected_vars) {
    if (const auto *single = std::get_if<SingleClaim>(&claim)) {
        return single->point.size() == expected_vars;
    }
    const BatchedClaim &batched = std::get<BatchedClaim>(claim);
    return batched.first.point.size() == expected_vars &&
           batched.second.point.size() == expected_vars &&
           batched.value == batched.first.value +
                                batched.challenge * batched.second.value;
}

Fpk sum_products_on_hypercube(const poly::Multilinear<Fpk> &left,
                              const poly::Multilinear<Fpk> &right) {
    if (left.num_vars() != right.num_vars()) {
        throw std::invalid_argument(
            "affine layer reduction: table dimensions differ");
    }
    Fpk result = Fpk::zero();
    for (std::size_t index = 0; index < left.evaluations().size(); ++index) {
        result += left.on_hypercube(index) * right.on_hypercube(index);
    }
    return result;
}

Fpk sum_relation_on_hypercube(
    std::size_t num_vars,
    const MultiplicationLayerReductionSumcheck::Oracle &relation) {
    const std::size_t size = poly::hypercube_size(num_vars);
    Fpk result = Fpk::zero();
    std::vector<Fpk> point(num_vars, Fpk::zero());
    for (std::size_t vertex = 0; vertex < size; ++vertex) {
        for (std::size_t variable = 0; variable < num_vars; ++variable) {
            const bool bit =
                ((vertex >> (num_vars - 1 - variable)) & 1U) != 0;
            point[variable] = bit ? Fpk::one() : Fpk::zero();
        }
        result += relation(point);
    }
    return result;
}

Fpk claim_value(const LayerClaim &claim) {
    return std::visit([](const auto &typed) { return typed.value; }, claim);
}

Fpk affine_linear_at(const gates::DirectGateMle &provider,
                     std::size_t layer_index, const LayerClaim &claim,
                     const std::vector<Fpk> &source_point) {
    if (const auto *single = std::get_if<SingleClaim>(&claim)) {
        return provider.evaluate(gates::GateMleQuery{gates::AffineQuery{
            layer_index, single->point, source_point}});
    }
    const BatchedClaim &batched = std::get<BatchedClaim>(claim);
    const Fpk first = provider.evaluate(gates::GateMleQuery{
        gates::AffineQuery{layer_index, batched.first.point, source_point}});
    const Fpk second = provider.evaluate(gates::GateMleQuery{
        gates::AffineQuery{layer_index, batched.second.point, source_point}});
    return first + batched.challenge * second;
}

Fpk affine_constant_at(const gates::DirectGateMle &provider,
                       std::size_t layer_index, const LayerClaim &claim) {
    if (const auto *single = std::get_if<SingleClaim>(&claim)) {
        return provider.evaluate_affine_constant(layer_index, single->point);
    }
    const BatchedClaim &batched = std::get<BatchedClaim>(claim);
    return provider.evaluate_affine_constant(layer_index,
                                             batched.first.point) +
           batched.challenge * provider.evaluate_affine_constant(
                                   layer_index, batched.second.point);
}

struct MultiplicationOracles {
    MultiplicationLayerReductionSumcheck::Oracle full;
    MultiplicationLayerReductionSumcheck::Oracle stripped;
};

MultiplicationOracles multiplication_oracles(
    const SingleClaim &current_claim,
    const poly::Multilinear<Fpk> &source_table) {
    const std::size_t shared_variables = current_claim.point.size();
    MultiplicationLayerReductionSumcheck::Oracle stripped =
        [&, shared_variables](std::span<const Fpk> point) {
            if (point.size() != shared_variables) {
                throw std::invalid_argument(
                    "multiplication oracle: point has the wrong dimension");
            }
            std::vector<Fpk> left;
            left.reserve(shared_variables + 1U);
            left.push_back(Fpk::zero());
            left.insert(left.end(), point.begin(), point.end());
            std::vector<Fpk> right;
            right.reserve(shared_variables + 1U);
            right.push_back(Fpk::one());
            right.insert(right.end(), point.begin(), point.end());
            const Fpk left_value = source_table.evaluate(left);
            const Fpk right_value = source_table.evaluate(right);
            return left_value * right_value;
        };
    MultiplicationLayerReductionSumcheck::Oracle full =
        [stripped, output_point = current_claim.point,
         shared_variables](std::span<const Fpk> point) {
            if (point.size() != shared_variables) {
                throw std::invalid_argument(
                    "multiplication oracle: point has the wrong dimension");
            }
            return detail::dense_multiplication_equality(output_point,
                                                          point) *
                   stripped(point);
        };
    return MultiplicationOracles{std::move(full), std::move(stripped)};
}

struct MultiplicationTerminalPoints {
    std::vector<Fpk> left;
    std::vector<Fpk> right;
};

MultiplicationTerminalPoints terminal_points(
    std::span<const Fpk> challenges) {
    MultiplicationTerminalPoints result;
    result.left.reserve(challenges.size() + 1U);
    result.left.push_back(Fpk::zero());
    result.left.insert(result.left.end(), challenges.begin(),
                       challenges.end());
    result.right.reserve(challenges.size() + 1U);
    result.right.push_back(Fpk::one());
    result.right.insert(result.right.end(), challenges.begin(),
                        challenges.end());
    return result;
}

Fpk multiplication_terminal(const SingleClaim &left,
                           const SingleClaim &right) {
    return left.value * right.value;
}

SingleClaim observe_and_reduce_multiplication_source(
    std::span<const Fpk> shared_point, const SingleClaim &left,
    const SingleClaim &right, Transcript &transcript) {
    // Both endpoint values are fixed before the fresh selector challenge.
    // The source MLE is linear in this coordinate, so one evaluation suffices
    // for the next layer instead of a random sum of two separate claims.
    transcript.observe("laminate/gkr/multiplication-selector/v1",
                       std::uint64_t{1});
    observe_claim(left, transcript);
    observe_claim(right, transcript);
    const Fpk selector_challenge = transcript.challenge_fpk();
    return detail::make_dense_multiplication_source_claim(
        shared_point, left.value, right.value, selector_challenge);
}

void require_layer_kind(const payload::LayeredCircuit &circuit,
                        std::size_t layer_index, payload::LayerKind expected) {
    if (layer_index + 1 >= circuit.layers.size() ||
        payload::layer_kind(circuit.layers[layer_index]) != expected) {
        throw std::invalid_argument(
            "layer reduction: reduction kind does not match layer");
    }
}

} // namespace

ProvedAffineLayerReduction prove_affine_layer_reduction(
    const payload::LayeredCircuit &circuit, const payload::PlainTrace &trace,
    std::size_t layer_index, const LayerClaim &current_claim,
    const gates::DirectGateMle &gate_mles, Transcript &transcript) {
    require_layer_kind(circuit, layer_index, payload::LayerKind::Affine);
    if (!valid_claim(current_claim, layer_num_vars(circuit, layer_index))) {
        throw std::invalid_argument(
            "prove_affine_layer_reduction: malformed current claim");
    }
    const std::size_t source_vars = layer_num_vars(circuit, layer_index + 1);
    const auto source = layer_table(circuit, trace, layer_index + 1);
    std::vector<Fpk> linear_evaluations;
    linear_evaluations.reserve(poly::hypercube_size(source_vars));
    for (std::size_t vertex = 0; vertex < poly::hypercube_size(source_vars);
         ++vertex) {
        linear_evaluations.push_back(affine_linear_at(
            gate_mles, layer_index, current_claim,
            boolean_point(vertex, source_vars)));
    }
    const poly::Multilinear<Fpk> linear(source_vars,
                                        std::move(linear_evaluations));
    const Fpk claimed_linear =
        claim_value(current_claim) -
        affine_constant_at(gate_mles, layer_index, current_claim);
    if (sum_products_on_hypercube(linear, source) != claimed_linear) {
        throw std::invalid_argument(
            "prove_affine_layer_reduction: trace does not satisfy the layer claim");
    }

    ProvedLayerReductionSumcheck sumcheck =
        AffineLayerReductionSumcheck::prove(linear, source, transcript);
    SingleClaim next{sumcheck.challenges,
                     source.evaluate(sumcheck.challenges)};
    const Fpk terminal = affine_linear_at(
        gate_mles, layer_index, current_claim, next.point);
    if (terminal * next.value !=
        linear.evaluate(next.point) * source.evaluate(next.point)) {
        throw std::logic_error(
            "prove_affine_layer_reduction: inconsistent terminal oracle");
    }
    observe_claim(next, transcript);
    return ProvedAffineLayerReduction{
        AffineLayerReductionProof{std::move(sumcheck.proof), next.value},
        std::move(next)};
}

std::optional<SingleClaim> verify_affine_layer_reduction(
    const payload::LayeredCircuit &circuit, std::size_t layer_index,
    const LayerClaim &current_claim, const AffineLayerReductionProof &proof,
    const gates::DirectGateMle &gate_mles, Transcript &transcript) {
    try {
        require_layer_kind(circuit, layer_index, payload::LayerKind::Affine);
        if (!valid_claim(current_claim,
                         layer_num_vars(circuit, layer_index))) {
            return std::nullopt;
        }
        const Fpk claimed_linear =
            claim_value(current_claim) -
            affine_constant_at(gate_mles, layer_index, current_claim);
        const std::size_t source_vars =
            layer_num_vars(circuit, layer_index + 1);
        const VerifiedLayerReductionSumcheck sumcheck =
            AffineLayerReductionSumcheck::verify(
                proof.sumcheck, claimed_linear, source_vars, transcript);
        if (!sumcheck.structurally_valid) {
            return std::nullopt;
        }
        SingleClaim next{sumcheck.challenges, proof.source_value};
        observe_claim(next, transcript);
        const Fpk gate = affine_linear_at(
            gate_mles, layer_index, current_claim, next.point);
        if (!sumcheck.accepts(gate * next.value)) {
            return std::nullopt;
        }
        return next;
    } catch (const std::invalid_argument &) {
        return std::nullopt;
    }
}

ProvedMultiplicationLayerReduction prove_multiplication_layer_reduction(
    const payload::LayeredCircuit &circuit, const payload::PlainTrace &trace,
    std::size_t layer_index, const SingleClaim &current_claim,
    Transcript &transcript) {
    require_layer_kind(circuit, layer_index,
                       payload::LayerKind::Multiplication);
    if (current_claim.point.size() != layer_num_vars(circuit, layer_index)) {
        throw std::invalid_argument(
            "prove_multiplication_layer_reduction: malformed current claim");
    }
    const auto source = layer_table(circuit, trace, layer_index + 1);
    const MultiplicationOracles oracles = multiplication_oracles(
        current_claim, source);
    const std::size_t sumcheck_vars = current_claim.point.size();
    if (sum_relation_on_hypercube(sumcheck_vars, oracles.full) !=
        current_claim.value) {
        throw std::invalid_argument(
            "prove_multiplication_layer_reduction: trace does not satisfy the layer "
            "claim");
    }
    ProvedLayerReductionSumcheck sumcheck =
        MultiplicationLayerReductionSumcheck::prove(
            0, current_claim.point, oracles.full, oracles.stripped,
            transcript);
    MultiplicationTerminalPoints points =
        terminal_points(sumcheck.challenges);
    const Fpk left_value = source.evaluate(points.left);
    const Fpk right_value = source.evaluate(points.right);
    const SingleClaim left{std::move(points.left), left_value};
    const SingleClaim right{std::move(points.right), right_value};
    const Fpk terminal = multiplication_terminal(left, right);
    SingleClaim next = observe_and_reduce_multiplication_source(
        sumcheck.challenges, left, right, transcript);
    const Fpk expected_final = oracles.stripped(sumcheck.challenges);
    if (terminal != expected_final) {
        throw std::logic_error(
            "prove_multiplication_layer_reduction: inconsistent terminal oracle");
    }
    return ProvedMultiplicationLayerReduction{
        MultiplicationLayerReductionProof{std::move(sumcheck.proof), left.value,
                                     right.value},
        std::move(next)};
}

std::optional<SingleClaim> verify_multiplication_layer_reduction(
    const payload::LayeredCircuit &circuit, std::size_t layer_index,
    const SingleClaim &current_claim,
    const MultiplicationLayerReductionProof &proof, Transcript &transcript) {
    try {
        require_layer_kind(circuit, layer_index,
                           payload::LayerKind::Multiplication);
        if (current_claim.point.size() !=
            layer_num_vars(circuit, layer_index)) {
            return std::nullopt;
        }
        const VerifiedLayerReductionSumcheck sumcheck =
            MultiplicationLayerReductionSumcheck::verify(
                proof.sumcheck, current_claim.value, 0,
                current_claim.point, transcript);
        if (!sumcheck.structurally_valid) {
            return std::nullopt;
        }
        MultiplicationTerminalPoints points =
            terminal_points(sumcheck.challenges);
        SingleClaim left{std::move(points.left), proof.left_value};
        SingleClaim right{std::move(points.right), proof.right_value};
        SingleClaim next = observe_and_reduce_multiplication_source(
            sumcheck.challenges, left, right, transcript);
        const Fpk terminal = multiplication_terminal(left, right);
        if (!sumcheck.accepts(terminal)) {
            return std::nullopt;
        }
        return next;
    } catch (const std::invalid_argument &) {
        return std::nullopt;
    }
}

} // namespace laminate::gkr
