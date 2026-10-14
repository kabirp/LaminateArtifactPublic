#ifndef LAMINATE_DELEGATION_BASE_CLIENT_STATE_ACCESS_HPP
#define LAMINATE_DELEGATION_BASE_CLIENT_STATE_ACCESS_HPP

/// @file client/state_access.hpp
/// @brief One-shot Base client state access and session derivation.

#include "laminate/delegation/base/session/state.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::delegation {
namespace base_client_detail {

inline bool all_zero(const Digest &value) {
    return std::all_of(value.begin(), value.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

inline Digest derive_session_id(const Digest &nonce, const Digest &setup_id,
                                const Digest &circuit_id,
                                const Digest &trace_id) {
    static constexpr std::string_view kDomain =
        "LaminateImpl/BaseDelegationSession/v1";
    std::vector<std::uint8_t> encoded(kDomain.begin(), kDomain.end());
    encoded.insert(encoded.end(), nonce.begin(), nonce.end());
    encoded.insert(encoded.end(), setup_id.begin(), setup_id.end());
    encoded.insert(encoded.end(), circuit_id.begin(), circuit_id.end());
    encoded.insert(encoded.end(), trace_id.begin(), trace_id.end());
    return sha256(encoded);
}

/// Centralizes privileged access to the move-only state types. Lifecycle
/// routines exchange rather than copy retained bindings and plaintexts.
struct ClientStateAccess {
    static Digest consume_nonce(BaseClientNonce &nonce) {
        return std::exchange(nonce.bytes_, Digest{});
    }

    static const Digest &setup_id(const BaseClientAwaitingResponse &state) {
        return state.setup_id_;
    }
    static const Digest &session_id(const BaseClientAwaitingResponse &state) {
        return state.session_id_;
    }
    static const Digest &circuit_id(const BaseClientAwaitingResponse &state) {
        return state.circuit_id_;
    }
    static const Digest &trace_id(const BaseClientAwaitingResponse &state) {
        return state.trace_id_;
    }
    static const Digest &request_commitment(
        const BaseClientAwaitingResponse &state) {
        return state.request_commitment_;
    }
    static const std::vector<fhe::SlotVector> &
    inputs(const BaseClientAwaitingResponse &state) {
        return state.input_layer_;
    }

    static BaseClientOpenedResponse open(
        BaseClientAwaitingResponse state, Digest statement_digest,
        std::vector<fhe::SlotVector> output_layer,
        gkr::SingleClaim output_claim) {
        return BaseClientOpenedResponse{
            std::exchange(state.setup_id_, Digest{}),
            std::exchange(state.session_id_, Digest{}),
            std::exchange(state.circuit_id_, Digest{}),
            std::exchange(state.trace_id_, Digest{}),
            std::exchange(state.request_commitment_, Digest{}),
            statement_digest, std::move(state.input_layer_),
            std::move(output_layer), std::move(output_claim)};
    }

    static const Digest &setup_id(const BaseClientOpenedResponse &state) {
        return state.setup_id_;
    }
    static const Digest &session_id(const BaseClientOpenedResponse &state) {
        return state.session_id_;
    }
    static const Digest &circuit_id(const BaseClientOpenedResponse &state) {
        return state.circuit_id_;
    }
    static const Digest &trace_id(const BaseClientOpenedResponse &state) {
        return state.trace_id_;
    }
    static const Digest &request_commitment(
        const BaseClientOpenedResponse &state) {
        return state.request_commitment_;
    }
    static const Digest &statement_digest(
        const BaseClientOpenedResponse &state) {
        return state.statement_digest_;
    }
    static const std::vector<fhe::SlotVector> &
    inputs(const BaseClientOpenedResponse &state) {
        return state.input_layer_;
    }
    static const gkr::SingleClaim &
    output_claim(const BaseClientOpenedResponse &state) {
        return state.output_claim_;
    }
    static std::size_t output_count(const BaseClientOpenedResponse &state) {
        return state.output_layer_.size();
    }
    static std::vector<fhe::SlotVector>
    take_outputs(BaseClientOpenedResponse &state) {
        return std::move(state.output_layer_);
    }
};

} // namespace base_client_detail

inline BaseClientNonce
make_base_client_nonce(std::span<const std::uint8_t> random_bytes) {
    if (random_bytes.size() < 32) {
        throw std::invalid_argument(
            "make_base_client_nonce: expected at least 32 random bytes");
    }
    static constexpr std::string_view kDomain =
        "LaminateImpl/BaseDelegationClientNonce/v1";
    std::vector<std::uint8_t> encoded(kDomain.begin(), kDomain.end());
    encoded.insert(encoded.end(), random_bytes.begin(), random_bytes.end());
    return BaseClientNonce(sha256(encoded));
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_CLIENT_STATE_ACCESS_HPP
