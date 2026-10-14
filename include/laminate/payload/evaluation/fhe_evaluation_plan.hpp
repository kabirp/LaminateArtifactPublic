#ifndef LAMINATE_PAYLOAD_EVALUATION_FHE_EVALUATION_PLAN_HPP
#define LAMINATE_PAYLOAD_EVALUATION_FHE_EVALUATION_PLAN_HPP

/// @file fhe_evaluation_plan.hpp
/// @brief Public modulus-switch and proof-ingress schedule for payload FHE.

#include "laminate/payload/trace/encrypted_trace.hpp"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::payload {

/// Public schedule for homomorphic payload evaluation and proof ingress.
///
/// `modulus_switches_after_layer[i]` is applied after evaluating layer `i`
/// and before using it as the source of layer `i-1`. The input-layer entry is
/// unused and must be zero. `trace` records the natural level at which payload
/// evaluation produces each layer. `proof_ingress_mult_depth_by_layer`
/// records the level of the independent copy consumed by the proof. Layer 0
/// is the payload output returned for client decryption, not a reverse-GKR
/// source, and therefore remains at its natural level. Source layers 1..L-1
/// may enter the proof at a lower level, but never a higher one. Preparing a
/// proof copy never changes ciphertexts used to continue payload evaluation.
struct FheEvaluationPlan {
    TraceEncryptionPlan trace;
    std::vector<std::size_t> proof_ingress_mult_depth_by_layer;
    std::vector<std::size_t> modulus_switches_after_layer;

    bool operator==(const FheEvaluationPlan &other) const = default;

    static FheEvaluationPlan without_payload_switches(
        const LayeredCircuit &circuit, std::size_t required_proof_depth) {
        TraceEncryptionPlan trace =
            TraceEncryptionPlan::uniform(circuit, required_proof_depth);
        return FheEvaluationPlan{
            trace,
            trace.required_mult_depth_by_layer,
            std::vector<std::size_t>(circuit.layers.size(), 0)};
    }

    static FheEvaluationPlan switch_after_multiplication_layers(
        const LayeredCircuit &circuit, std::size_t required_proof_depth,
        std::size_t switches_per_layer = 1) {
        FheEvaluationPlan result =
            without_payload_switches(circuit, required_proof_depth);
        for (std::size_t layer = 0; layer + 1 < circuit.layers.size();
             ++layer) {
            if (requires_ciphertext_multiplication(circuit.layers[layer])) {
                result.modulus_switches_after_layer[layer] =
                    switches_per_layer;
            }
        }
        return result;
    }

    /// Switch after every multiplication layer and retain each proof snapshot
    /// at the level where payload evaluation produced it. This avoids extra
    /// compaction and is the appropriate plan for an ordered per-level chain.
    /// `fresh_chain_index` must be the actual chain index of every encrypted
    /// input supplied to the evaluator.
    static FheEvaluationPlan at_evaluation_levels(
        const LayeredCircuit &circuit, std::size_t fresh_chain_index,
        std::size_t switches_per_layer = 1,
        std::size_t maximum_switched_layers =
            std::numeric_limits<std::size_t>::max()) {
        circuit.validate();
        FheEvaluationPlan result{
            TraceEncryptionPlan{std::vector<std::size_t>(
                circuit.layers.size(), 0)},
            std::vector<std::size_t>(circuit.layers.size(), 0),
            std::vector<std::size_t>(circuit.layers.size(), 0)};
        std::size_t current_level = fresh_chain_index;
        std::size_t switched_layers = 0;
        result.trace.required_mult_depth_by_layer.back() = current_level;
        for (std::size_t source_layer = circuit.layers.size() - 1;
             source_layer > 0; --source_layer) {
            const std::size_t output_layer = source_layer - 1;
            if (requires_ciphertext_multiplication(
                    circuit.layers[output_layer]) &&
                switched_layers < maximum_switched_layers) {
                if (current_level < switches_per_layer) {
                    throw std::invalid_argument(
                        "FheEvaluationPlan: multiplication schedule exceeds "
                        "the fresh chain");
                }
                result.modulus_switches_after_layer[output_layer] =
                    switches_per_layer;
                current_level -= switches_per_layer;
                ++switched_layers;
            }
            result.trace.required_mult_depth_by_layer[output_layer] =
                current_level;
        }
        result.proof_ingress_mult_depth_by_layer =
            result.trace.required_mult_depth_by_layer;
        return result;
    }

    /// Use the smallest natural level that preserves every packed-proof
    /// source floor and leaves one prompt drop for every later CT-CT layer.
    /// Surplus heads are removed at the earliest CT-CT boundary; the client
    /// output is normalized all the way to the bottom prime. This keeps later
    /// multiplications small while preserving the exact source snapshots
    /// selected by setup. `fresh_chain_index` is the natural level of the
    /// encrypted inputs. Entries 1..L-1 of
    /// `proof_ingress_mult_depth_by_layer` are source-layer floors and are
    /// retained exactly. Entry 0 is ignored because the payload output is
    /// returned to the client rather than consumed by reverse GKR; the output
    /// is recorded at level zero.
    static FheEvaluationPlan
    packed_payload_with_prompt_switches(
        const LayeredCircuit &circuit, std::size_t fresh_chain_index,
        std::span<const std::size_t>
            proof_ingress_mult_depth_by_layer) {
        circuit.validate();
        const std::size_t layer_count = circuit.layers.size();
        if (proof_ingress_mult_depth_by_layer.size() != layer_count) {
            throw std::invalid_argument(
                "FheEvaluationPlan: expected one proof-ingress floor per "
                "layer");
        }
        if (fresh_chain_index ==
            std::numeric_limits<std::size_t>::max()) {
            throw std::invalid_argument(
                "FheEvaluationPlan: fresh chain index overflows its RNS "
                "limb count");
        }

        // `minimum_natural_level[layer]` is the least source level that both
        // meets this layer's proof floor and leaves one droppable head for
        // each CT-CT relation below it.
        std::vector<std::size_t> minimum_natural_level(layer_count, 0);
        for (std::size_t layer = 1; layer < layer_count; ++layer) {
            if (proof_ingress_mult_depth_by_layer[layer] >
                fresh_chain_index) {
                throw std::invalid_argument(
                    "FheEvaluationPlan: proof-ingress floor exceeds the "
                    "fresh chain level");
            }
            const std::size_t drop_after_relation =
                requires_ciphertext_multiplication(
                    circuit.layers[layer - 1])
                    ? 1U
                    : 0U;
            if (minimum_natural_level[layer - 1] >
                std::numeric_limits<std::size_t>::max() -
                    drop_after_relation) {
                throw std::invalid_argument(
                    "FheEvaluationPlan: packed payload level schedule "
                    "overflows");
            }
            minimum_natural_level[layer] = std::max(
                proof_ingress_mult_depth_by_layer[layer],
                minimum_natural_level[layer - 1] +
                    drop_after_relation);
        }
        if (minimum_natural_level.back() > fresh_chain_index) {
            throw std::invalid_argument(
                "FheEvaluationPlan: fresh chain cannot preserve proof "
                "floors and one drop per CT-CT layer");
        }

        FheEvaluationPlan result{
            TraceEncryptionPlan{std::vector<std::size_t>(layer_count, 0)},
            std::vector<std::size_t>(
                proof_ingress_mult_depth_by_layer.begin(),
                proof_ingress_mult_depth_by_layer.end()),
            std::vector<std::size_t>(layer_count, 0)};
        std::size_t current_level = fresh_chain_index;
        result.trace.required_mult_depth_by_layer.back() = current_level;
        for (std::size_t source_layer = layer_count - 1; source_layer > 0;
             --source_layer) {
            const std::size_t output_layer = source_layer - 1;
            if (requires_ciphertext_multiplication(
                    circuit.layers[output_layer])) {
                const std::size_t target_level =
                    minimum_natural_level[output_layer];
                if (current_level < target_level) {
                    throw std::logic_error(
                        "FheEvaluationPlan: packed payload schedule lost "
                        "required RNS headroom");
                }
                result.modulus_switches_after_layer[output_layer] =
                    current_level - target_level;
                current_level = target_level;
            }
            result.trace.required_mult_depth_by_layer[output_layer] =
                current_level;
        }

        // Layer zero is not a reverse-GKR source. Normalize the returned
        // ciphertext even when the final circuit relation is affine.
        result.modulus_switches_after_layer.front() += current_level;
        result.trace.required_mult_depth_by_layer.front() = 0;
        result.proof_ingress_mult_depth_by_layer.front() = 0;
        result.validate(circuit);
        return result;
    }

  private:
    static bool requires_ciphertext_multiplication(const Layer &layer) {
        const auto *multiplication =
            std::get_if<MultiplicationLayer>(&layer);
        if (multiplication == nullptr) {
            return false;
        }
        return std::any_of(
            multiplication->gates.begin(), multiplication->gates.end(),
            [](const MultiplicationGate &gate) {
                return gate.origin == GateOrigin::Payload;
            });
    }

  public:
    void validate(const LayeredCircuit &circuit) const {
        trace.validate(circuit);
        if (proof_ingress_mult_depth_by_layer.size() !=
            circuit.layers.size()) {
            throw std::invalid_argument(
                "FheEvaluationPlan: expected one proof-ingress level per "
                "layer");
        }
        if (modulus_switches_after_layer.size() !=
            circuit.layers.size()) {
            throw std::invalid_argument(
                "FheEvaluationPlan: expected one switch count per layer");
        }
        if (!modulus_switches_after_layer.empty() &&
            modulus_switches_after_layer.back() != 0) {
            throw std::invalid_argument(
                "FheEvaluationPlan: input layer cannot have an after-layer "
                "switch");
        }
        if (!proof_ingress_mult_depth_by_layer.empty() &&
            proof_ingress_mult_depth_by_layer.front() !=
                trace.required_mult_depth_by_layer.front()) {
            throw std::invalid_argument(
                "FheEvaluationPlan: output layer must remain at its "
                "natural level");
        }
        for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
            if (proof_ingress_mult_depth_by_layer[layer] >
                trace.required_mult_depth_by_layer[layer]) {
                throw std::invalid_argument(
                    "FheEvaluationPlan: proof ingress exceeds the natural "
                    "trace level");
            }
        }
    }
};

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_EVALUATION_FHE_EVALUATION_PLAN_HPP
