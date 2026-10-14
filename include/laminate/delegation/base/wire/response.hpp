#ifndef LAMINATE_DELEGATION_BASE_WIRE_RESPONSE_HPP
#define LAMINATE_DELEGATION_BASE_WIRE_RESPONSE_HPP

/// @file response.hpp
/// @brief Canonical Base output-and-proof response codec.

#include "laminate/delegation/base/wire/detail/proof_transport.hpp"
#include "laminate/gkr/detail/base/validation/request.hpp"
#include "laminate/protocol/setup/base_client.hpp"

#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace laminate::delegation {

/// Encode the sole Base response. Its output prefix fixes the encrypted public
/// statement and therefore the initial Fiat--Shamir point; the proof follows
/// in the same immutable envelope.
template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
std::vector<std::uint8_t> encode_base_response(
    const StorageContext &context, const BaseResponse<Backend> &response,
    base_wire_detail::ProofTransportSizeBreakdown *proof_breakdown =
        nullptr) {
    constexpr const char *operation = "encode_base_response";
    base_wire_detail::validate_message_bindings(response, operation);
    wire_detail::validate_output_dimensions(
        response.output.dimensions, response.output.values.size(), operation);
    base_wire_detail::Bytes payload;
    wire_detail::append_bindings(payload, response);
    wire_detail::append_dimensions(payload, response.output.dimensions,
                                   operation);
    wire_detail::append_fhe_values<Backend>(
        payload, context, response.output.values, operation);
    const base_wire_detail::Bytes proof =
        base_wire_detail::encode_proof_transport<Backend>(
            context, response.proof, proof_breakdown);
    wire_detail::append_size(payload, proof.size(), operation);
    payload.insert(payload.end(), proof.begin(), proof.end());
    return base_wire_detail::envelope(
        BaseWireMessageType::Response, payload, operation);
}

namespace base_wire_detail {

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
BaseResponse<Backend> decode_base_response_with_static_binding(
    const StorageContext &context, std::span<const std::uint8_t> encoded,
    const BaseWireDecodeLimits &limits,
    const payload::LayeredCircuit &circuit, const PublicSetup &setup,
    const Digest &expected_setup_id, const Digest &expected_circuit_id,
    payload::TraceProvenance expected_provenance,
    const char *operation) {
    auto reader = open_envelope(
        encoded, BaseWireMessageType::Response, limits, operation);
    const wire_detail::Bindings bindings = wire_detail::read_bindings(reader);
    base_wire_detail::validate_bindings(bindings, operation);
    const payload::LayerDimensions dimensions =
        wire_detail::read_dimensions(reader);
    wire_detail::validate_output_dimensions(
        dimensions, dimensions.logical_size, operation);
    if (dimensions.logical_size > limits.max_ciphertexts) {
        wire_detail::reject(
            operation, "output width exceeds configured value limit");
    }

    DecodeBudget budget(limits, operation);
    auto values = read_response_output_values<Backend>(
        reader, context, budget, limits, operation);
    wire_detail::validate_output_dimensions(dimensions, values.size(),
                                            operation);
    const std::size_t proof_bytes = reader.read_size();
    if (proof_bytes > limits.max_proof_bytes) {
        wire_detail::reject(operation,
                            "proof exceeds configured byte limit");
    }
    Reader proof_reader(reader.read_bytes(proof_bytes), operation);
    protocol::LaminateBaseProof<Backend> proof =
        decode_proof_transport<Backend>(
            context, proof_reader, circuit, setup, budget, limits,
            operation);
    proof_reader.require_end();
    reader.require_end();

    if (bindings.setup_id != expected_setup_id ||
        bindings.circuit_id != expected_circuit_id ||
        bindings.trace_id != proof.header.trace_id ||
        proof.header.setup_id != bindings.setup_id ||
        proof.header.circuit_id != bindings.circuit_id ||
        proof.header.provenance != expected_provenance ||
        !gkr::base_detail::validate_structure<Backend>(
            proof, expected_provenance, bindings.trace_id, setup, circuit)) {
        wire_detail::reject(operation,
                            "proof structure or public bindings mismatch");
    }
    return BaseResponse<Backend>{
        bindings.setup_id, bindings.session_id, bindings.circuit_id,
        bindings.trace_id,
        BaseFheOutput<Backend>{dimensions, std::move(values)},
        std::move(proof)};
}

} // namespace base_wire_detail

/// Decode and structurally validate a complete Base proof against the expected
/// payload, circuit, setup, provenance, and envelope bindings. Cryptographic
/// verification is the caller's next state transition.
template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
BaseResponse<Backend> decode_base_response(
    const StorageContext &context, std::span<const std::uint8_t> encoded,
    const BaseWireDecodeLimits &limits,
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit, const PublicSetup &setup,
    payload::TraceProvenance expected_provenance) {
    constexpr const char *operation = "decode_base_response";
    setup.validate(payload, circuit);
    return base_wire_detail::decode_base_response_with_static_binding<Backend>(
        context, encoded, limits, circuit, setup, setup_digest(setup),
        setup.circuit_digest, expected_provenance, operation);
}

/// Decode against an immutable client setup whose circuit and public binding
/// were certified offline. Untrusted bytes, bounds, structure, provenance,
/// and public envelope bindings are still checked here.
template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
BaseResponse<Backend> decode_base_response(
    const StorageContext &context,
    const protocol::CertifiedBaseClientSetup<Backend> &setup,
    std::span<const std::uint8_t> encoded,
    const BaseWireDecodeLimits &limits,
    payload::TraceProvenance expected_provenance) {
    constexpr const char *operation = "decode_base_response";
    return base_wire_detail::decode_base_response_with_static_binding<Backend>(
        context, encoded, limits, setup.circuit(), setup.public_setup(),
        setup.setup_id(), setup.circuit_id(), expected_provenance, operation);
}

template <fhe::PersistableFheBackend Backend>
    requires fhe::CiphertextStorageContext<
        Backend, typename Backend::ClientContext>
BaseResponse<Backend> decode_base_response(
    const protocol::CertifiedBaseClientSetup<Backend> &setup,
    std::span<const std::uint8_t> encoded,
    const BaseWireDecodeLimits &limits,
    payload::TraceProvenance expected_provenance) {
    return decode_base_response<Backend>(
        setup.context(), setup, encoded, limits, expected_provenance);
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_WIRE_RESPONSE_HPP
