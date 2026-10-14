#ifndef LAMINATE_DELEGATION_FOLDED_CLIENT_STATE_ACCESS_HPP
#define LAMINATE_DELEGATION_FOLDED_CLIENT_STATE_ACCESS_HPP

/// @file client/state_access.hpp
/// @brief One-shot Folded client state access and session derivation.

#include "laminate/delegation/detail/packed_client_lifecycle.hpp"
#include "laminate/delegation/folded/session/state.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::delegation {
namespace folded_client_detail {

inline Digest derive_session_id(const Digest &nonce, const Digest &setup_id,
                                const Digest &circuit_id,
                                const Digest &trace_id) {
    static constexpr std::string_view kDomain =
        "LaminateImpl/FoldedDelegationSession/v1";
    return packed_client_detail::derive_session_id(
        kDomain, nonce, setup_id, circuit_id, trace_id);
}

inline bool all_zero(const Digest &value) {
    return packed_client_detail::is_zero_digest(value);
}

/// Centralizes privileged access to move-only request state. Client lifecycle
/// code consumes every binding once and never exposes tentative plaintext.
struct ClientStateAccess {
    static Digest consume_nonce(FoldedClientNonce &nonce) {
        return std::exchange(nonce.bytes_, Digest{});
    }
    static const Digest &setup_id(
        const FoldedClientAwaitingResponse &state) {
        return state.setup_id_;
    }
    static const Digest &session_id(
        const FoldedClientAwaitingResponse &state) {
        return state.session_id_;
    }
    static const Digest &circuit_id(
        const FoldedClientAwaitingResponse &state) {
        return state.circuit_id_;
    }
    static const Digest &trace_id(
        const FoldedClientAwaitingResponse &state) {
        return state.trace_id_;
    }
    static const Digest &request_commitment(
        const FoldedClientAwaitingResponse &state) {
        return state.request_commitment_;
    }

    static FoldedClientOpenedResponse open(
        FoldedClientAwaitingResponse state, Digest statement_digest,
        std::vector<fhe::SlotVector> output_layer,
        gkr::SingleClaim output_claim) {
        return FoldedClientOpenedResponse{
            std::exchange(state.setup_id_, Digest{}),
            std::exchange(state.session_id_, Digest{}),
            std::exchange(state.circuit_id_, Digest{}),
            std::exchange(state.trace_id_, Digest{}),
            std::exchange(state.request_commitment_, Digest{}),
            statement_digest, std::move(state.input_layer_),
            std::move(output_layer), std::move(output_claim)};
    }

    static const Digest &setup_id(
        const FoldedClientOpenedResponse &state) {
        return state.setup_id_;
    }
    static const Digest &session_id(
        const FoldedClientOpenedResponse &state) {
        return state.session_id_;
    }
    static const Digest &circuit_id(
        const FoldedClientOpenedResponse &state) {
        return state.circuit_id_;
    }
    static const Digest &trace_id(
        const FoldedClientOpenedResponse &state) {
        return state.trace_id_;
    }
    static const Digest &request_commitment(
        const FoldedClientOpenedResponse &state) {
        return state.request_commitment_;
    }
    static const Digest &statement_digest(
        const FoldedClientOpenedResponse &state) {
        return state.statement_digest_;
    }
    static const std::vector<fhe::SlotVector> &inputs(
        const FoldedClientOpenedResponse &state) {
        return state.input_layer_;
    }
    static const gkr::SingleClaim &output_claim(
        const FoldedClientOpenedResponse &state) {
        return state.output_claim_;
    }
    static std::size_t output_count(
        const FoldedClientOpenedResponse &state) {
        return state.output_layer_.size();
    }
    static std::vector<fhe::SlotVector> take_outputs(
        FoldedClientOpenedResponse &state) {
        return std::move(state.output_layer_);
    }
};

} // namespace folded_client_detail

inline FoldedClientNonce
make_folded_client_nonce(std::span<const std::uint8_t> random_bytes) {
    if (random_bytes.size() < 32) {
        throw std::invalid_argument(
            "make_folded_client_nonce: expected at least 32 random bytes");
    }
    static constexpr std::string_view kDomain =
        "LaminateImpl/FoldedDelegationClientNonce/v1";
    std::vector<std::uint8_t> encoded(kDomain.begin(), kDomain.end());
    encoded.insert(encoded.end(), random_bytes.begin(), random_bytes.end());
    return FoldedClientNonce(sha256(encoded));
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_FOLDED_CLIENT_STATE_ACCESS_HPP
