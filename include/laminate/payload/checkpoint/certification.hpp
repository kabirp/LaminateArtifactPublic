#ifndef LAMINATE_PAYLOAD_CHECKPOINT_CERTIFICATION_HPP
#define LAMINATE_PAYLOAD_CHECKPOINT_CERTIFICATION_HPP

/// @file certification.hpp
/// @brief Immutable replay geometry certification and capacity validation.

#include "laminate/payload/checkpoint/artifact_io.hpp"
#include "laminate/payload/evaluation/fhe_evaluation_plan.hpp"
#include "laminate/payload/trace/fhe_trace_id.hpp"

#include <cstddef>
#include <filesystem>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::payload {

inline void validate_payload_checkpoint_relation_chunk_capacity(
    const CertifiedCanonicalTraceLayout &trace_layout,
    std::size_t chunk_ciphertexts);

/// Immutable checkpoint/replay geometry certified before a recurring server
/// request begins. It owns the canonical circuit/layout token and exact
/// evaluation, resource, and replay plans, so the online publisher need only
/// validate request ciphertexts and mutable filesystem resources.
class CertifiedPayloadCheckpointReplayStatic {
  public:
    CertifiedPayloadCheckpointReplayStatic(
        const CertifiedPayloadCheckpointReplayStatic &) = default;
    CertifiedPayloadCheckpointReplayStatic &operator=(
        const CertifiedPayloadCheckpointReplayStatic &) = default;
    CertifiedPayloadCheckpointReplayStatic(
        CertifiedPayloadCheckpointReplayStatic &&) noexcept = default;
    CertifiedPayloadCheckpointReplayStatic &operator=(
        CertifiedPayloadCheckpointReplayStatic &&) noexcept = default;

    const CertifiedCanonicalTraceLayout &trace_layout() const {
        return state_->trace_layout;
    }
    const LayeredCircuit &circuit() const {
        return state_->trace_layout.circuit();
    }
    const FheEvaluationPlan &evaluation() const { return state_->evaluation; }
    const PayloadCheckpointReplayProblem &problem() const {
        return state_->problem;
    }
    const PayloadCheckpointReplayBudgets &budgets() const {
        return state_->budgets;
    }
    const PayloadCheckpointReplayPlan &plan() const { return state_->plan; }
    const Digest &combined_circuit_id() const {
        return state_->combined_circuit_id;
    }
    const Digest &layered_circuit_id() const {
        return state_->layered_circuit_id;
    }
    const EncryptedTraceDescriptor &natural_trace_template() const {
        return state_->natural_trace_template;
    }
    const EncryptedTraceDescriptor &proof_trace_template() const {
        return state_->proof_trace_template;
    }
    const PayloadShape &shape() const { return state_->shape; }
    std::size_t input_count() const { return state_->input_count; }

  private:
    struct State {
        State(
        PayloadShape shape, std::size_t input_count,
        CertifiedCanonicalTraceLayout trace_layout,
        FheEvaluationPlan evaluation,
        PayloadCheckpointReplayProblem problem,
        PayloadCheckpointReplayBudgets budgets,
        PayloadCheckpointReplayPlan plan,
        Digest combined_circuit_id, Digest layered_circuit_id,
        EncryptedTraceDescriptor natural_trace_template,
        EncryptedTraceDescriptor proof_trace_template)
            : shape(shape), input_count(input_count),
              trace_layout(std::move(trace_layout)),
              evaluation(std::move(evaluation)),
              problem(std::move(problem)), budgets(std::move(budgets)),
              plan(std::move(plan)),
              combined_circuit_id(combined_circuit_id),
              layered_circuit_id(layered_circuit_id),
              natural_trace_template(std::move(natural_trace_template)),
              proof_trace_template(std::move(proof_trace_template)) {}

        PayloadShape shape;
        std::size_t input_count = 0;
        CertifiedCanonicalTraceLayout trace_layout;
        FheEvaluationPlan evaluation;
        PayloadCheckpointReplayProblem problem;
        PayloadCheckpointReplayBudgets budgets;
        PayloadCheckpointReplayPlan plan;
        Digest combined_circuit_id{};
        Digest layered_circuit_id{};
        EncryptedTraceDescriptor natural_trace_template;
        EncryptedTraceDescriptor proof_trace_template;
    };

    explicit CertifiedPayloadCheckpointReplayStatic(
        std::shared_ptr<const State> state)
        : state_(std::move(state)) {
        if (!state_) {
            throw std::invalid_argument(
                "checkpoint replay certificate state is null");
        }
    }

    std::shared_ptr<const State> state_;

    friend CertifiedPayloadCheckpointReplayStatic
    certify_payload_checkpoint_replay_static(
        const PayloadCircuit &, CertifiedCanonicalTraceLayout,
        FheEvaluationPlan, PayloadCheckpointReplayProblem,
        PayloadCheckpointReplayBudgets, PayloadCheckpointReplayPlan);
};

/// Perform every payload/circuit/layout/plan check once and return the only
/// token accepted by the no-rescan online checkpoint publisher.
inline CertifiedPayloadCheckpointReplayStatic
certify_payload_checkpoint_replay_static(
    const PayloadCircuit &payload,
    CertifiedCanonicalTraceLayout trace_layout,
    FheEvaluationPlan evaluation,
    PayloadCheckpointReplayProblem problem,
    PayloadCheckpointReplayBudgets budgets,
    PayloadCheckpointReplayPlan plan) {
    const LayeredCircuit &circuit = trace_layout.circuit();
    validate_compilation_pair(payload, circuit);
    checkpoint_replay_execution_detail::validate_execution_geometry(
        circuit, evaluation, problem, trace_layout.layout());
    checkpoint_replay_execution_detail::require_admitted_plan(
        problem, budgets, plan);
    validate_payload_checkpoint_relation_chunk_capacity(
        trace_layout, plan.selected.chunk_ciphertexts);
    const Digest combined_circuit_id = combined_digest(payload, circuit);
    const Digest layered_circuit_id = digest(circuit);
    EncryptedTraceDescriptor natural_trace_template{
        payload.shape, TraceProvenance::FheEvaluated,
        combined_circuit_id, Digest{}, {}};
    EncryptedTraceDescriptor proof_trace_template = natural_trace_template;
    const TraceLayerLayout layer_layout =
        circuit.shape.kind == PayloadKind::Wide
            ? TraceLayerLayout::Wide
            : TraceLayerLayout::BPeriodic;
    natural_trace_template.layers.reserve(circuit.layers.size());
    proof_trace_template.layers.reserve(circuit.layers.size());
    const auto &storage = trace_layout.layout().storage;
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        const LayerDimensions dimensions =
            layer_dimensions(circuit.layers[layer]);
        natural_trace_template.layers.push_back(
            EncryptedTraceLayerDescriptor{
                layer_layout, dimensions,
                evaluation.trace.required_mult_depth_by_layer[layer],
                storage[layer].stored_wire_count});
        proof_trace_template.layers.push_back(
            EncryptedTraceLayerDescriptor{
                layer_layout, dimensions,
                layer == 0
                    ? evaluation.trace
                          .required_mult_depth_by_layer[layer]
                    : evaluation
                          .proof_ingress_mult_depth_by_layer[layer],
                storage[layer].stored_wire_count});
    }
    return CertifiedPayloadCheckpointReplayStatic(
        std::make_shared<const CertifiedPayloadCheckpointReplayStatic::State>(
            payload.shape, payload.input_count, std::move(trace_layout),
            std::move(evaluation), std::move(problem), std::move(budgets),
            std::move(plan), combined_circuit_id, layered_circuit_id,
            std::move(natural_trace_template),
            std::move(proof_trace_template)));
}

/// Return the smallest ciphertext chunk which can evaluate every payload
/// relation. Affine gates do not contribute their total fan-in: checkpoint
/// replay streams a high-fan-in affine sum one live source at a time. A
/// multiplication gate still needs all of its live ciphertext operands at
/// once. Structural padding is the public plaintext-zero polynomial and is
/// excluded from this count.
inline std::size_t minimum_payload_checkpoint_relation_chunk_ciphertexts(
    const LayeredCircuit &circuit) {
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(circuit);
    return checkpoint_replay_execution_detail::
        minimum_relation_chunk_ciphertexts(circuit, storage);
}

/// Cached-layout form of
/// `minimum_payload_checkpoint_relation_chunk_ciphertexts`. The layout must
/// already bind the exact immutable alias map to its originating circuit.
inline std::size_t minimum_payload_checkpoint_relation_chunk_ciphertexts(
    const CertifiedCanonicalTraceLayout &trace_layout) {
    return checkpoint_replay_execution_detail::
        minimum_relation_chunk_ciphertexts(
            trace_layout.circuit(), trace_layout.layout().storage);
}

/// Reject a chunk which cannot hold the simultaneous live operands of one
/// payload relation. This check is pure and must run before paths are created
/// or server FHE work begins.
inline void validate_payload_checkpoint_relation_chunk_capacity(
    const LayeredCircuit &circuit, std::size_t chunk_ciphertexts) {
    if (chunk_ciphertexts == 0) {
        throw std::invalid_argument(
            "checkpoint replay execution chunk is zero");
    }
    const std::size_t minimum =
        minimum_payload_checkpoint_relation_chunk_ciphertexts(circuit);
    if (chunk_ciphertexts < minimum) {
        throw std::invalid_argument(
            "checkpoint replay source ciphertext chunk is below the "
            "circuit-derived simultaneous-operand minimum");
    }
}

/// Cached-layout form of
/// `validate_payload_checkpoint_relation_chunk_capacity`.
inline void validate_payload_checkpoint_relation_chunk_capacity(
    const CertifiedCanonicalTraceLayout &trace_layout,
    std::size_t chunk_ciphertexts) {
    if (chunk_ciphertexts == 0) {
        throw std::invalid_argument(
            "checkpoint replay execution chunk is zero");
    }
    const std::size_t minimum =
        minimum_payload_checkpoint_relation_chunk_ciphertexts(
            trace_layout);
    if (chunk_ciphertexts < minimum) {
        throw std::invalid_argument(
            "checkpoint replay source ciphertext chunk is below the "
            "circuit-derived simultaneous-operand minimum");
    }
}

/// Validate a caller-owned replay root without creating files and return its
/// stable absolute canonical name. Publication repeats this check before it
/// creates per-layer directories.
inline std::filesystem::path
preflight_and_normalize_payload_checkpoint_replay_root(
    const std::filesystem::path &directory) {
    return checkpoint_replay_execution_detail::validate_empty_root(
        directory);
}

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_CHECKPOINT_CERTIFICATION_HPP
