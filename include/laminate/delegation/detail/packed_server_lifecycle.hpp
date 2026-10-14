#ifndef LAMINATE_DELEGATION_DETAIL_PACKED_SERVER_LIFECYCLE_HPP
#define LAMINATE_DELEGATION_DETAIL_PACKED_SERVER_LIFECYCLE_HPP

/// @file packed_server_lifecycle.hpp
/// @brief Shared request and encrypted-statement binding for packed servers.

#include "laminate/delegation/packed/statement.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace/fhe_trace_id.hpp"
#include "laminate/setup.hpp"

#include <stdexcept>
#include <string>

namespace laminate::delegation::packed_server_detail {

template <fhe::FheBackend Backend, typename Request>
void validate_request(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server, const Request &request,
    payload::PayloadKind expected_kind, const char *operation) {
    server.public_setup.validate(payload, circuit);
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = server.public_setup.circuit_digest;
    if (payload.shape.kind != expected_kind ||
        circuit.shape.kind != expected_kind ||
        request.setup_id != setup_id || request.session_id == Digest{} ||
        request.circuit_id != circuit_id ||
        request.trace_id !=
            payload::prevalidated_trace_identity::
                validated_fhe_evaluated_trace_id<Backend>(
                    circuit_id, payload.input_count,
                    request.encrypted_inputs)) {
        throw std::invalid_argument(
            std::string(operation) + ": request binding mismatch");
    }
}

template <fhe::FheBackend Backend, typename Request>
Digest request_commitment(
    PackedProtocolVariant variant, const Request &request) {
    return packed_request_commitment<Backend>(
        variant, request.setup_id, request.session_id, request.circuit_id,
        request.trace_id);
}

template <fhe::FheBackend Backend, typename Output>
Digest statement_digest(
    PackedProtocolVariant variant, const Digest &request_commitment,
    const Digest &setup_id, const Digest &session_id,
    const Digest &circuit_id, const Digest &trace_id,
    const Output &output) {
    return packed_encrypted_statement_digest<Backend>(
        variant, request_commitment, setup_id, session_id, circuit_id,
        trace_id, output.dimensions, output.values);
}

} // namespace laminate::delegation::packed_server_detail

#endif // LAMINATE_DELEGATION_DETAIL_PACKED_SERVER_LIFECYCLE_HPP
