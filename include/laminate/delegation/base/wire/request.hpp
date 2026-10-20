#ifndef LAMINATE_DELEGATION_BASE_WIRE_REQUEST_HPP
#define LAMINATE_DELEGATION_BASE_WIRE_REQUEST_HPP

/// @file request.hpp
/// @brief Canonical Base client-to-server request codec.

#include "laminate/delegation/base/wire/detail/envelope.hpp"

#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace laminate::delegation {

/// Encode a request with any role context that supports canonical ciphertext
/// persistence. This includes the SEAL client and evaluation contexts.
template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
std::vector<std::uint8_t> encode_base_request(
    const StorageContext &context, const BaseRequest<Backend> &request) {
    constexpr const char *operation = "encode_base_request";
    base_wire_detail::validate_message_bindings(request, operation);
    base_wire_detail::Bytes payload;
    wire_detail::append_bindings(payload, request);
    wire_detail::append_ciphertexts<Backend>(
        payload, context, request.encrypted_inputs, operation);
    return base_wire_detail::envelope(
        BaseWireMessageType::Request, payload, operation);
}

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
BaseRequest<Backend> decode_base_request(
    const StorageContext &context, std::span<const std::uint8_t> encoded,
    const BaseWireDecodeLimits &limits) {
    constexpr const char *operation = "decode_base_request";
    auto reader = base_wire_detail::open_envelope(
        encoded, BaseWireMessageType::Request, limits, operation);
    const wire_detail::Bindings bindings = wire_detail::read_bindings(reader);
    base_wire_detail::validate_bindings(bindings, operation);
    auto ciphertexts = wire_detail::read_ciphertexts<Backend>(
        reader, context, base_wire_detail::common_limits(limits), operation);
    reader.require_end();
    return BaseRequest<Backend>{
        bindings.setup_id, bindings.session_id, bindings.circuit_id,
        bindings.trace_id, std::move(ciphertexts)};
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_WIRE_REQUEST_HPP
