#ifndef LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_PACKING_REVEALS_HPP
#define LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_PACKING_REVEALS_HPP

/// @file packing_reveals.hpp
/// @brief Canonical public-zero and ciphertext reveal decoding.

#include "laminate/protocol/packed/wire/detail/canonical_framing.hpp"

#include <optional>

namespace laminate::protocol::detail::packed_proof_decode_detail {

template <packing::CoefficientWellFormednessBackend Backend,
          typename Context>
    requires PackedProofDecodeContext<Backend, Context>
std::optional<typename Backend::Ciphertext> read_reveal(
    Reader &reader, const Context &context, DecodeBudget &budget,
    const PackedProofDecodeLimits &limits, const char *operation) {
    const std::size_t bytes = reader.read_size();
    if (bytes == 0 || bytes > limits.max_proof_bytes) {
        reject(operation, "invalid packed reveal length");
    }
    Reader value(reader.read_bytes(bytes), operation);
    const auto tag = static_cast<fhe::FheValueRecordTag>(value.read_u8());
    if (tag == fhe::FheValueRecordTag::PublicScalar) {
        if (value.read_u64() != 0) {
            reject(operation, "packed reveal public value is not zero");
        }
        value.require_end();
        return std::nullopt;
    }
    if (tag != fhe::FheValueRecordTag::Ciphertext) {
        reject(operation, "packed reveal has a noncanonical value tag");
    }

    // Charge both ciphertext count and bytes before deserialization. The
    // backend then performs the sole canonical parse of this bounded frame.
    const auto ciphertext_bytes = value.remaining_bytes();
    budget.add_ciphertext(ciphertext_bytes.size());
    if (ciphertext_bytes.size() > limits.max_ciphertext_bytes) {
        reject(operation, "packed reveal ciphertext exceeds byte limit");
    }
    typename Backend::Ciphertext ciphertext =
        Backend::deserialize_protocol(context, ciphertext_bytes);
    (void)value.read_bytes(ciphertext_bytes.size());
    value.require_end();
    if (!Backend::is_normalized_for_coefficient_commitment(ciphertext)) {
        reject(operation, "packed reveal ciphertext is not normalized");
    }
    return ciphertext;
}

} // namespace laminate::protocol::detail::packed_proof_decode_detail

#endif // LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_PACKING_REVEALS_HPP
