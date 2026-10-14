#ifndef LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_CANONICAL_FRAMING_HPP
#define LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_CANONICAL_FRAMING_HPP

/// @file canonical_framing.hpp
/// @brief Strict tags, counts, and allocation budgets for packed proof frames.

#include "laminate/delegation/base/wire/codec.hpp"
#include "laminate/protocol/packed/wire/detail/decode_policy.hpp"

#include <algorithm>
#include <limits>
#include <string>
#include <string_view>

namespace laminate::protocol::detail::packed_proof_decode_detail {

using Reader = delegation::wire_detail::Reader;
using DecodeBudget = delegation::base_wire_detail::DecodeBudget;

inline constexpr std::string_view kPackedPrefix = "LM/PACKED/";
inline constexpr std::string_view kCommittedPrefix = "LM/COMMITTED/";

[[noreturn]] inline void reject(const char *operation,
                                std::string_view reason) {
    delegation::wire_detail::reject(operation, reason);
}

inline delegation::BaseWireDecodeLimits base_limits(
    const PackedProofDecodeLimits &limits) {
    return delegation::BaseWireDecodeLimits{
        .max_message_bytes = limits.max_proof_bytes,
        .max_ciphertexts = limits.max_ciphertexts,
        .max_ciphertext_bytes = limits.max_ciphertext_bytes,
        .max_total_ciphertext_bytes = limits.max_total_ciphertext_bytes,
        .max_claim_coordinates = limits.max_collection_elements,
        .max_proof_bytes = limits.max_proof_bytes,
        .max_reductions = limits.max_collection_elements,
        .max_rounds_per_reduction = limits.max_collection_elements,
        .max_gate_proof_rounds = limits.max_collection_elements,
        .max_partial_gate_values = limits.max_collection_elements,
        .max_gate_claims = limits.max_collection_elements,
        .max_gate_target_values = limits.max_collection_elements,
        .max_basefold_queries = limits.max_collection_elements,
        .max_merkle_path_digests = limits.max_total_digests,
        .max_total_field_elements = limits.max_total_field_elements,
        .max_total_digests = limits.max_total_digests,
    };
}

inline void require_raw(Reader &reader, std::string_view expected,
                        const char *operation) {
    const auto actual = reader.read_bytes(expected.size());
    if (!std::equal(actual.begin(), actual.end(), expected.begin())) {
        reject(operation, "wrong canonical encoding tag");
    }
}

inline void require_versioned_tag(Reader &reader, std::string_view prefix,
                                  char variant, char version,
                                  const char *operation) {
    require_raw(reader, prefix, operation);
    if (reader.read_u8() != static_cast<std::uint8_t>(variant) ||
        reader.read_u8() != '/' || reader.read_u8() != 'v' ||
        reader.read_u8() != static_cast<std::uint8_t>(version)) {
        reject(operation, "wrong canonical protocol tag");
    }
}

inline void require_count(std::size_t encoded, std::size_t expected,
                          const PackedProofDecodeLimits &limits,
                          const char *operation,
                          std::string_view description) {
    // Check the trusted shape against the caller's allocation ceiling before
    // comparing it with untrusted wire data. No reserve() follows unless both
    // tests succeed.
    if (expected > limits.max_collection_elements || encoded != expected) {
        reject(operation,
               std::string("unexpected ") + std::string(description));
    }
}

inline std::size_t checked_size(std::uint64_t value,
                                const char *operation) {
    if constexpr (sizeof(std::size_t) < sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::size_t>::max()) {
            reject(operation, "trusted proof shape does not fit size_t");
        }
    }
    return static_cast<std::size_t>(value);
}

inline Fq2 read_fq2(Reader &reader, DecodeBudget &budget) {
    budget.add_fields(1);
    return deserialize_fq2(reader.read_bytes(kSerializedFq2Bytes));
}

} // namespace laminate::protocol::detail::packed_proof_decode_detail

#endif // LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_CANONICAL_FRAMING_HPP
