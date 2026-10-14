#ifndef LAMINATE_DELEGATION_LANED_WIRE_RESPONSE_HPP
#define LAMINATE_DELEGATION_LANED_WIRE_RESPONSE_HPP

/// @file wire/response.hpp
/// @brief Canonical Laned response framing and bounded opaque decoding.

#include "laminate/delegation/laned/wire/detail/envelope.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"

namespace laminate::delegation {

struct EncodedLanedResponse {
    std::vector<std::uint8_t> bytes;
    protocol::LanedProofSizeBreakdown proof_size;
};

template <fhe::PersistableFheBackend Backend>
EncodedLanedResponse encode_laned_response_with_size(
    const typename Backend::EvalContext &eval,
    const LanedResponse<Backend> &response,
    std::size_t max_response_bytes = 0) {
    constexpr const char *operation = "encode_laned_response_with_size";
    wire_detail::validate_message_bindings(response, operation);
    wire_detail::validate_output_dimensions(
        response.output.dimensions, response.output.values.size(), operation);
    wire_detail::Bytes output;
    const std::size_t payload_start = wire_detail::begin_laned_envelope(
        output, LanedWireMessageType::Response, max_response_bytes, operation);
    wire_detail::append_bindings(output, response);
    wire_detail::append_dimensions(output, response.output.dimensions,
                                   operation);
    wire_detail::append_fhe_values<Backend>(
        output, eval, response.output.values, operation);
    const std::size_t proof_size_offset = output.size();
    wire_detail::append_size(output, 0, operation);
    const std::size_t proof_start = output.size();
    protocol::LanedProofSizeBreakdown proof_size =
        protocol::append_canonical_with_size<Backend>(response.proof, output);
    if (proof_size.total_bytes != output.size() - proof_start) {
        wire_detail::reject(operation, "proof byte accounting mismatch");
    }
    wire_detail::patch_size(output, proof_size_offset,
                            proof_size.total_bytes, operation);
    wire_detail::validate_opaque_laned_proof_prefix(
        std::span<const std::uint8_t>(output).subspan(
            proof_start, proof_size.total_bytes),
        operation);
    wire_detail::finish_laned_envelope(output, payload_start, operation);
    if (max_response_bytes != 0 && output.size() > max_response_bytes) {
        wire_detail::reject(operation,
                            "response exceeds configured byte limit");
    }
    return EncodedLanedResponse{
        .bytes = std::move(output), .proof_size = std::move(proof_size)};
}

template <fhe::PersistableFheBackend Backend>
std::vector<std::uint8_t> encode_laned_response(
    const typename Backend::EvalContext &eval,
    const LanedResponse<Backend> &response) {
    return encode_laned_response_with_size<Backend>(eval, response).bytes;
}

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
BorrowedLanedResponseEnvelope<Backend>
decode_borrowed_laned_response_envelope(
    const StorageContext &context, std::span<const std::uint8_t> encoded,
    const LanedWireDecodeLimits &limits) {
    constexpr const char *operation =
        "decode_opaque_laned_response_envelope";
    auto reader = wire_detail::open_laned_envelope(
        encoded, LanedWireMessageType::Response, limits, operation);
    const wire_detail::Bindings bindings = wire_detail::read_bindings(reader);
    wire_detail::validate_bindings(bindings, operation);
    const payload::LayerDimensions dimensions =
        wire_detail::read_dimensions(reader);
    wire_detail::validate_output_dimensions(
        dimensions, dimensions.logical_size, operation);
    if (dimensions.logical_size > limits.max_ciphertexts) {
        wire_detail::reject(
            operation, "output width exceeds configured value limit");
    }
    auto values = wire_detail::read_fhe_values<Backend>(
        reader, context, limits, operation);
    wire_detail::validate_output_dimensions(
        dimensions, values.size(), operation);
    const std::size_t proof_bytes = reader.read_size();
    if (proof_bytes > limits.max_proof_bytes) {
        wire_detail::reject(operation,
                            "proof exceeds configured byte limit");
    }
    const auto proof_span = reader.read_bytes(proof_bytes);
    wire_detail::validate_opaque_laned_proof_prefix(proof_span, operation);
    reader.require_end();
    return BorrowedLanedResponseEnvelope<Backend>{
        bindings.setup_id, bindings.session_id, bindings.circuit_id,
        bindings.trace_id,
        LanedFheOutput<Backend>{dimensions, std::move(values)}, proof_span};
}

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
OpaqueLanedResponseEnvelope<Backend>
decode_opaque_laned_response_envelope(
    const StorageContext &context, std::span<const std::uint8_t> encoded,
    const LanedWireDecodeLimits &limits) {
    auto borrowed = decode_borrowed_laned_response_envelope<Backend>(
        context, encoded, limits);
    return OpaqueLanedResponseEnvelope<Backend>{
        borrowed.setup_id, borrowed.session_id, borrowed.circuit_id,
        borrowed.trace_id, std::move(borrowed.output),
        std::vector<std::uint8_t>(borrowed.opaque_proof_bytes.begin(),
                                  borrowed.opaque_proof_bytes.end())};
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_LANED_WIRE_RESPONSE_HPP
