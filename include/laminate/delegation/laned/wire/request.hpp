#ifndef LAMINATE_DELEGATION_LANED_WIRE_REQUEST_HPP
#define LAMINATE_DELEGATION_LANED_WIRE_REQUEST_HPP

/// @file wire/request.hpp
/// @brief Canonical Laned evaluation-request encoding and decoding.

#include "laminate/delegation/laned/wire/detail/envelope.hpp"

namespace laminate::delegation {

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
std::vector<std::uint8_t> encode_laned_evaluation_request(
    const StorageContext &context,
    const LanedEvaluationRequest<Backend> &request,
    std::size_t max_request_bytes = 0) {
    constexpr const char *operation = "encode_laned_evaluation_request";
    wire_detail::validate_message_bindings(request, operation);
    wire_detail::Bytes output;
    const std::size_t payload_start = wire_detail::begin_laned_envelope(
        output, LanedWireMessageType::EvaluationRequest,
        max_request_bytes, operation);
    wire_detail::append_bindings(output, request);
    wire_detail::append_ciphertexts<Backend>(
        output, context, request.encrypted_inputs, operation);
    wire_detail::finish_laned_envelope(output, payload_start, operation);
    if (max_request_bytes != 0 && output.size() > max_request_bytes) {
        wire_detail::reject(operation,
                            "request exceeds configured byte limit");
    }
    return output;
}

template <fhe::PersistableFheBackend Backend>
LanedEvaluationRequest<Backend> decode_laned_evaluation_request(
    const typename Backend::EvalContext &eval,
    std::span<const std::uint8_t> encoded,
    const LanedWireDecodeLimits &limits) {
    constexpr const char *operation = "decode_laned_evaluation_request";
    auto reader = wire_detail::open_laned_envelope(
        encoded, LanedWireMessageType::EvaluationRequest, limits, operation);
    const wire_detail::Bindings bindings = wire_detail::read_bindings(reader);
    wire_detail::validate_bindings(bindings, operation);
    auto ciphertexts = wire_detail::read_ciphertexts<Backend>(
        reader, eval, limits, operation);
    reader.require_end();
    return LanedEvaluationRequest<Backend>{
        bindings.setup_id, bindings.session_id, bindings.circuit_id,
        bindings.trace_id, std::move(ciphertexts)};
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_LANED_WIRE_REQUEST_HPP
