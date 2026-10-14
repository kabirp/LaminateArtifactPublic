#ifndef LAMINATE_DELEGATION_FOLDED_WIRE_RESPONSE_HPP
#define LAMINATE_DELEGATION_FOLDED_WIRE_RESPONSE_HPP

/// @file wire/response.hpp
/// @brief Canonical Folded response framing and bounded opaque decoding.

#include "laminate/delegation/folded/wire/detail/envelope.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"

namespace laminate::delegation {

struct EncodedFoldedResponse {
    std::vector<std::uint8_t> bytes;
    protocol::FoldedProofSizeBreakdown proof_size;
};

template <fhe::PersistableFheBackend Backend>
EncodedFoldedResponse encode_folded_response_with_size(
    const typename Backend::EvalContext &eval,
    const FoldedResponse<Backend> &response,
    std::size_t max_response_bytes = 0) {
    constexpr const char *operation = "encode_folded_response_with_size";
    wire_detail::validate_message_bindings(response, operation);
    folded_wire_detail::validate_compact_output_count(
        response.output.dimensions, response.output.values.size(), operation);
    wire_detail::Bytes output;
    const std::size_t payload_start = folded_wire_detail::begin_envelope(
        output, FoldedWireMessageType::Response, max_response_bytes, operation);
    wire_detail::append_bindings(output, response);
    wire_detail::append_dimensions(output, response.output.dimensions,
                                   operation);
    wire_detail::append_fhe_values<Backend>(
        output, eval, response.output.values, operation);
    const std::size_t proof_size_offset = output.size();
    wire_detail::append_size(output, 0, operation);
    const std::size_t proof_start = output.size();
    protocol::FoldedProofSizeBreakdown proof_size =
        protocol::append_canonical_with_size<Backend>(response.proof, output);
    if (proof_size.total_bytes != output.size() - proof_start) {
        wire_detail::reject(operation, "proof byte accounting mismatch");
    }
    wire_detail::patch_size(output, proof_size_offset,
                            proof_size.total_bytes, operation);
    folded_wire_detail::validate_proof_prefix(
        std::span<const std::uint8_t>(output).subspan(
            proof_start, proof_size.total_bytes),
        operation);
    folded_wire_detail::finish_envelope(output, payload_start, operation);
    if (max_response_bytes != 0 && output.size() > max_response_bytes) {
        wire_detail::reject(operation,
                            "response exceeds configured byte limit");
    }
    return EncodedFoldedResponse{
        .bytes = std::move(output), .proof_size = std::move(proof_size)};
}

template <fhe::PersistableFheBackend Backend>
std::vector<std::uint8_t> encode_folded_response(
    const typename Backend::EvalContext &eval,
    const FoldedResponse<Backend> &response) {
    return encode_folded_response_with_size<Backend>(eval, response).bytes;
}

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
BorrowedFoldedResponseEnvelope<Backend>
decode_borrowed_folded_response_envelope(
    const StorageContext &context, std::span<const std::uint8_t> encoded,
    const FoldedWireDecodeLimits &limits) {
    constexpr const char *operation =
        "decode_opaque_folded_response_envelope";
    auto reader = folded_wire_detail::open_envelope(
        encoded, FoldedWireMessageType::Response, limits, operation);
    const wire_detail::Bindings bindings = wire_detail::read_bindings(reader);
    wire_detail::validate_bindings(bindings, operation);
    const payload::LayerDimensions dimensions =
        wire_detail::read_dimensions(reader);
    folded_wire_detail::validate_dimensions(dimensions, operation);
    auto values = wire_detail::read_fhe_values<Backend>(
        reader, context, limits, operation);
    folded_wire_detail::validate_compact_output_count(
        dimensions, values.size(), operation);
    const std::size_t proof_bytes = reader.read_size();
    if (proof_bytes > limits.max_proof_bytes) {
        wire_detail::reject(operation,
                            "proof exceeds configured byte limit");
    }
    const auto proof_span = reader.read_bytes(proof_bytes);
    folded_wire_detail::validate_proof_prefix(proof_span, operation);
    reader.require_end();
    return BorrowedFoldedResponseEnvelope<Backend>{
        bindings.setup_id, bindings.session_id, bindings.circuit_id,
        bindings.trace_id,
        FoldedFheOutput<Backend>{dimensions, std::move(values)}, proof_span};
}

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
OpaqueFoldedResponseEnvelope<Backend>
decode_opaque_folded_response_envelope(
    const StorageContext &context, std::span<const std::uint8_t> encoded,
    const FoldedWireDecodeLimits &limits) {
    auto borrowed = decode_borrowed_folded_response_envelope<Backend>(
        context, encoded, limits);
    return OpaqueFoldedResponseEnvelope<Backend>{
        borrowed.setup_id, borrowed.session_id, borrowed.circuit_id,
        borrowed.trace_id, std::move(borrowed.output),
        std::vector<std::uint8_t>(borrowed.opaque_proof_bytes.begin(),
                                  borrowed.opaque_proof_bytes.end())};
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_FOLDED_WIRE_RESPONSE_HPP
