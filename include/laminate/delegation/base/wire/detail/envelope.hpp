#ifndef LAMINATE_DELEGATION_BASE_WIRE_DETAIL_ENVELOPE_HPP
#define LAMINATE_DELEGATION_BASE_WIRE_DETAIL_ENVELOPE_HPP

/// @file envelope.hpp
/// @brief Base message framing, public-binding checks, and decode budgets.

#include "laminate/delegation/base/transport/messages.hpp"
#include "laminate/delegation/base/wire/format.hpp"
#include "laminate/delegation/base/wire/types.hpp"
#include "laminate/delegation/laned/wire/format.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace laminate::delegation {

namespace base_wire_detail {

using Bytes = wire_detail::Bytes;
using Reader = wire_detail::Reader;

/// Base has one request and one combined response. The response budget is the
/// sum of its encrypted output prefix and proof, not the larger component.
inline BaseWireCiphertextBudget derive_ciphertext_budget(
    CiphertextFootprint request, CiphertextFootprint response_output,
    CiphertextFootprint response_proof) {
    constexpr const char *operation = "derive Base wire ciphertext budget";
    const CiphertextFootprint response{
        .count = wire_detail::checked_add(
            response_output.count, response_proof.count, operation),
        .bytes = wire_detail::checked_add(
            response_output.bytes, response_proof.bytes, operation),
    };
    return BaseWireCiphertextBudget{
        .max_count_per_message = std::max(request.count, response.count),
        .max_bytes_per_message = std::max(request.bytes, response.bytes),
    };
}

inline LanedWireDecodeLimits
common_limits(const BaseWireDecodeLimits &limits) {
    return LanedWireDecodeLimits{
        .max_message_bytes = limits.max_message_bytes,
        .max_ciphertexts = limits.max_ciphertexts,
        .max_ciphertext_bytes = limits.max_ciphertext_bytes,
        .max_total_ciphertext_bytes = limits.max_total_ciphertext_bytes,
        .max_proof_bytes = limits.max_proof_bytes,
    };
}

inline Bytes envelope(BaseWireMessageType type,
                      std::span<const std::uint8_t> payload,
                      const char *operation) {
    const std::size_t total = wire_detail::checked_add(
        kBaseDelegationWireHeaderBytes, payload.size(), operation);
    Bytes output;
    output.reserve(total);
    output.insert(output.end(), kBaseDelegationWireDomain.begin(),
                  kBaseDelegationWireDomain.end());
    output.push_back(kBaseDelegationWireVersion);
    output.push_back(static_cast<std::uint8_t>(type));
    wire_detail::append_u16(output, 0);
    wire_detail::append_size(output, payload.size(), operation);
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

inline Reader open_envelope(std::span<const std::uint8_t> encoded,
                            BaseWireMessageType expected,
                            const BaseWireDecodeLimits &limits,
                            const char *operation) {
    if (encoded.size() > limits.max_message_bytes) {
        wire_detail::reject(operation,
                            "message exceeds configured byte limit");
    }
    Reader reader(encoded, operation);
    const auto domain = reader.read_bytes(kBaseDelegationWireDomain.size());
    if (!std::equal(domain.begin(), domain.end(),
                    kBaseDelegationWireDomain.begin())) {
        wire_detail::reject(operation, "wrong wire domain");
    }
    if (reader.read_u8() != kBaseDelegationWireVersion) {
        wire_detail::reject(operation, "unsupported wire version");
    }
    if (reader.read_u8() != static_cast<std::uint8_t>(expected)) {
        wire_detail::reject(operation, "wrong message type");
    }
    if (reader.read_u16() != 0) {
        wire_detail::reject(operation, "unsupported wire flags");
    }
    if (reader.read_size() != reader.remaining()) {
        wire_detail::reject(operation,
                            "truncated or trailing envelope data");
    }
    return reader;
}

inline bool all_zero(const Digest &digest) {
    return std::all_of(digest.begin(), digest.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

inline void validate_bindings(const wire_detail::Bindings &bindings,
                              const char *operation) {
    if (all_zero(bindings.setup_id) || all_zero(bindings.session_id) ||
        all_zero(bindings.circuit_id) || all_zero(bindings.trace_id)) {
        wire_detail::reject(operation, "zero public binding");
    }
}

template <typename Message>
void validate_message_bindings(const Message &message,
                               const char *operation) {
    base_wire_detail::validate_bindings(
        wire_detail::Bindings{message.setup_id, message.session_id,
                              message.circuit_id, message.trace_id},
        operation);
}

/// Tracks aggregate resources while nested proof objects are decoded.
class DecodeBudget {
  public:
    DecodeBudget(const BaseWireDecodeLimits &limits, const char *operation)
        : limits_(limits), operation_(operation) {}

    void add_ciphertext(std::size_t bytes) {
        if (ciphertexts_ == limits_.max_ciphertexts) {
            wire_detail::reject(operation_,
                                "ciphertext count exceeds configured limit");
        }
        ++ciphertexts_;
        ciphertext_bytes_ = wire_detail::checked_add(
            ciphertext_bytes_, bytes, operation_);
        if (bytes > limits_.max_ciphertext_bytes ||
            ciphertext_bytes_ > limits_.max_total_ciphertext_bytes) {
            wire_detail::reject(
                operation_, "ciphertext bytes exceed configured limit");
        }
    }

    void add_fields(std::size_t count) {
        field_elements_ = wire_detail::checked_add(field_elements_, count,
                                                   operation_);
        if (field_elements_ > limits_.max_total_field_elements) {
            wire_detail::reject(
                operation_, "field elements exceed configured limit");
        }
    }

    void add_digests(std::size_t count) {
        digests_ = wire_detail::checked_add(digests_, count, operation_);
        if (digests_ > limits_.max_total_digests) {
            wire_detail::reject(operation_,
                                "digests exceed configured limit");
        }
    }

  private:
    const BaseWireDecodeLimits &limits_;
    const char *operation_;
    std::size_t ciphertexts_ = 0;
    std::size_t ciphertext_bytes_ = 0;
    std::size_t field_elements_ = 0;
    std::size_t digests_ = 0;
};

} // namespace base_wire_detail
} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_WIRE_DETAIL_ENVELOPE_HPP
