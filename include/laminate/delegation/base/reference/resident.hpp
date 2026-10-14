#ifndef LAMINATE_DELEGATION_BASE_REFERENCE_RESIDENT_HPP
#define LAMINATE_DELEGATION_BASE_REFERENCE_RESIDENT_HPP

/// @file reference/resident.hpp
/// @brief Small resident Base delegation parity path for tests.

#include "laminate/delegation/base/reference/client.hpp"
#include "laminate/delegation/base/server.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/gkr/detail/base/reference/prover.hpp"
#include "laminate/payload/trace/trace_sink.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"

#include <span>
#include <utility>
#include <vector>

namespace laminate::delegation::reference {

namespace detail {
template <fhe::FheBackend Backend> struct ServerStateAccess;
}

/// Move-only server state for the bounded in-memory lifecycle/parity path.
/// Production Base delegation stores authenticated checkpoints instead.
template <fhe::FheBackend Backend> class BaseServerEvaluated {
  public:
    BaseServerEvaluated(
        Digest setup, Digest session, Digest circuit, Digest trace,
        Digest request_commitment, Digest statement_digest,
        payload::EncryptedTrace<Backend> encrypted_trace)
        : setup_id_(setup), session_id_(session), circuit_id_(circuit),
          trace_id_(trace), request_commitment_(request_commitment),
          statement_digest_(statement_digest),
          trace_(std::move(encrypted_trace)) {}
    BaseServerEvaluated(const BaseServerEvaluated &) = delete;
    BaseServerEvaluated &operator=(const BaseServerEvaluated &) = delete;
    BaseServerEvaluated(BaseServerEvaluated &&other) noexcept
        : setup_id_(std::exchange(other.setup_id_, Digest{})),
          session_id_(std::exchange(other.session_id_, Digest{})),
          circuit_id_(std::exchange(other.circuit_id_, Digest{})),
          trace_id_(std::exchange(other.trace_id_, Digest{})),
          request_commitment_(
              std::exchange(other.request_commitment_, Digest{})),
          statement_digest_(
              std::exchange(other.statement_digest_, Digest{})),
          trace_(std::move(other.trace_)) {}
    BaseServerEvaluated &operator=(BaseServerEvaluated &&other) noexcept {
        setup_id_ = std::exchange(other.setup_id_, Digest{});
        session_id_ = std::exchange(other.session_id_, Digest{});
        circuit_id_ = std::exchange(other.circuit_id_, Digest{});
        trace_id_ = std::exchange(other.trace_id_, Digest{});
        request_commitment_ =
            std::exchange(other.request_commitment_, Digest{});
        statement_digest_ =
            std::exchange(other.statement_digest_, Digest{});
        trace_ = std::move(other.trace_);
        return *this;
    }

    const payload::EncryptedTrace<Backend> &trace() const { return trace_; }

  private:
    Digest setup_id_{};
    Digest session_id_{};
    Digest circuit_id_{};
    Digest trace_id_{};
    Digest request_commitment_{};
    Digest statement_digest_{};
    payload::EncryptedTrace<Backend> trace_;

    friend struct detail::ServerStateAccess<Backend>;
};

template <fhe::FheBackend Backend> struct BaseServerEvaluationResult {
    BaseFheOutput<Backend> output;
    BaseServerEvaluated<Backend> state;
};

namespace detail {

template <fhe::FheBackend Backend> struct ServerStateAccess {
    static const Digest &setup_id(const BaseServerEvaluated<Backend> &state) {
        return state.setup_id_;
    }
    static const Digest &session_id(
        const BaseServerEvaluated<Backend> &state) {
        return state.session_id_;
    }
    static const Digest &circuit_id(
        const BaseServerEvaluated<Backend> &state) {
        return state.circuit_id_;
    }
    static const Digest &trace_id(const BaseServerEvaluated<Backend> &state) {
        return state.trace_id_;
    }
    static const payload::EncryptedTrace<Backend> &
    trace(const BaseServerEvaluated<Backend> &state) {
        return state.trace_;
    }
    static const Digest &request_commitment(
        const BaseServerEvaluated<Backend> &state) {
        return state.request_commitment_;
    }
    static const Digest &statement_digest(
        const BaseServerEvaluated<Backend> &state) {
        return state.statement_digest_;
    }
};

template <fhe::FheBackend Backend>
void validate_compact_trace(
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace) {
    if (!(trace.shape == circuit.shape) ||
        trace.shape.kind != payload::PayloadKind::Wide ||
        trace.provenance != payload::TraceProvenance::FheEvaluated ||
        trace.layers.size() != circuit.layers.size()) {
        throw std::logic_error(
            "Base reference evaluator returned a mismatched trace");
    }
    const std::vector<payload::LayerStorageLayout> storage =
        payload::canonical_trace_storage_layout(circuit);
    for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
        if (trace.layers[layer].layout != payload::TraceLayerLayout::Wide ||
            trace.layers[layer].dimensions !=
                payload::layer_dimensions(circuit.layers[layer]) ||
            trace.layers[layer].wires.size() !=
                storage[layer].stored_wire_count) {
            throw std::logic_error(
                "Base reference evaluator returned a malformed canonical "
                "stored layer");
        }
    }
}

template <fhe::FheBackend Backend>
void require_resident_prover_layout(
    const payload::EncryptedTrace<Backend> &trace) {
    for (const payload::EncryptedTraceLayer<Backend> &layer : trace.layers) {
        if (layer.wires.size() != layer.dimensions.padded_size) {
            throw std::logic_error(
                "Base reference prover cannot consume compact padded layers; "
                "production callers must use checkpoint replay");
        }
    }
}

} // namespace detail

/// Evaluate a small Wide request entirely in memory for correctness tests.
template <fhe::FheBackend Backend>
BaseServerEvaluationResult<Backend> evaluate_base_request(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const BaseRequest<Backend> &request,
    const payload::FheEvaluationPlan &plan) {
    server.public_setup.validate(payload, circuit);
    base_server_detail::validate_evaluation_request_binding(
        payload, circuit, server, request);
    if (server.public_setup.honest_payload_noise_schedule_digest) {
        throw std::invalid_argument(
            "Base reference evaluation cannot execute a setup-bound honest "
            "schedule through an unbound FheEvaluationPlan");
    }
    payload::EncryptedTrace<Backend> trace =
        payload::evaluate_wide_fhe_trace_into<Backend>(
            server.context, payload, circuit, request.encrypted_inputs, plan,
            payload::InMemoryTraceSink<Backend>{server.context});
    detail::validate_compact_trace(circuit, trace);
    if (trace.circuit_id != request.circuit_id ||
        trace.trace_id != request.trace_id) {
        throw std::logic_error(
            "Base reference evaluator returned a binding mismatch");
    }

    BaseFheOutput<Backend> output{
        trace.layers.front().dimensions, trace.layers.front().wires};
    const Digest request_commitment =
        base_request_commitment<Backend>(request);
    const Digest statement_digest =
        base_encrypted_statement_digest<Backend>(
            request_commitment, request.setup_id, request.session_id,
            request.circuit_id, request.trace_id, output);
    return BaseServerEvaluationResult<Backend>{
        std::move(output),
        BaseServerEvaluated<Backend>{
            request.setup_id, request.session_id, request.circuit_id,
            request.trace_id, request_commitment, statement_digest,
            std::move(trace)}};
}

/// Prove the result of `evaluate_base_request` with the resident test path.
template <fhe::FheBackend Backend>
BaseResponse<Backend> prove_base_request(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    BaseServerEvaluationResult<Backend> evaluated,
    Transcript &transcript) {
    server.public_setup.validate(payload, circuit);
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = payload::combined_digest(payload, circuit);
    auto &state = evaluated.state;
    const auto &trace = detail::ServerStateAccess<Backend>::trace(state);
    if (detail::ServerStateAccess<Backend>::setup_id(state) != setup_id ||
        detail::ServerStateAccess<Backend>::session_id(state) == Digest{} ||
        detail::ServerStateAccess<Backend>::circuit_id(state) != circuit_id ||
        detail::ServerStateAccess<Backend>::trace_id(state) != trace.trace_id ||
        trace.circuit_id != circuit_id ||
        trace.provenance != payload::TraceProvenance::FheEvaluated ||
        evaluated.output.dimensions !=
            payload::layer_dimensions(circuit.layers.front()) ||
        evaluated.output.values.size() !=
            payload::canonical_layer_wire_support(circuit, 0)
                .live_wire_count) {
        throw std::invalid_argument(
            "Base reference prover: retained-state binding mismatch");
    }
    detail::validate_compact_trace(circuit, trace);
    detail::require_resident_prover_layout(trace);

    const Digest statement_digest =
        base_encrypted_statement_digest<Backend>(
            detail::ServerStateAccess<Backend>::request_commitment(state),
            setup_id, detail::ServerStateAccess<Backend>::session_id(state),
            circuit_id, trace.trace_id, evaluated.output);
    if (statement_digest !=
        detail::ServerStateAccess<Backend>::statement_digest(state)) {
        throw std::invalid_argument(
            "Base reference prover: encrypted output changed after "
            "evaluation");
    }
    transcript.observe("delegation-setup-id",
                       std::span<const std::uint8_t>(setup_id));
    transcript.observe(
        "delegation-session-id",
        std::span<const std::uint8_t>(
            detail::ServerStateAccess<Backend>::session_id(state)));
    const std::vector<Fpk> output_point = derive_base_output_point(
        transcript, statement_digest,
        gkr::base_detail::layer_vars(circuit, 0));
    protocol::LaminateBaseProof<Backend> proof =
        gkr::base_detail::prove_resident_test_reference<Backend>(
            payload, circuit, trace, server, output_point, transcript);
    return BaseResponse<Backend>{
        setup_id, detail::ServerStateAccess<Backend>::session_id(state),
        circuit_id, trace.trace_id, std::move(evaluated.output),
        std::move(proof)};
}

} // namespace laminate::delegation::reference

#endif // LAMINATE_DELEGATION_BASE_REFERENCE_RESIDENT_HPP
