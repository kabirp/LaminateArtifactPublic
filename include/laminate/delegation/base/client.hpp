#ifndef LAMINATE_DELEGATION_BASE_CLIENT_HPP
#define LAMINATE_DELEGATION_BASE_CLIENT_HPP

/// @file client.hpp
/// @brief Declaration-first Base client lifecycle.
///
/// Read this file in order: create one-use entropy, encrypt one request, open
/// the sole response without releasing plaintext, then verify and release.
/// The open and verify transitions consume their move-only state even on
/// rejection. Continue with the same transcript after a successful open;
/// failed attempts must not reuse that session or its partially used transcript.

#include "laminate/delegation/base/session/state.hpp"
#include "laminate/protocol/setup/base_client.hpp"
#include "laminate/transcript/transcript.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace laminate::delegation {

/// Condense at least 256 bits of client CSPRNG output into one-use session
/// entropy. Starting a request consumes this value.
inline BaseClientNonce
make_base_client_nonce(std::span<const std::uint8_t> random_bytes);

// ---- Request: encrypt inputs using workload metadata authenticated offline.

template <fhe::FheBackend Backend>
BaseClientRequestStart<Backend> begin_base_request(
    const protocol::CertifiedBaseClientSetup<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    BaseClientNonce nonce);

// ---- Open: bind and decrypt the response, but expose no plaintext yet.

template <fhe::FheBackend Backend>
std::optional<BaseClientOpenedResponse> open_base_response(
    const protocol::CertifiedBaseClientSetup<Backend> &client,
    BaseClientAwaitingResponse state,
    const BaseResponse<Backend> &response, Transcript &transcript);

// ---- Verify: check GKR and release only the accepted payload outputs.

template <fhe::FheBackend Backend>
std::optional<std::vector<fhe::SlotVector>> verify_opened_base_response(
    const protocol::CertifiedBaseClientSetup<Backend> &client,
    BaseClientOpenedResponse state,
    const BaseResponse<Backend> &response, Transcript &transcript);

/// Convenience composition of `open_base_response` and
/// `verify_opened_base_response`; output decryption still occurs exactly once.
template <fhe::FheBackend Backend>
std::optional<std::vector<fhe::SlotVector>> verify_base_response(
    const protocol::CertifiedBaseClientSetup<Backend> &client,
    BaseClientAwaitingResponse state,
    const BaseResponse<Backend> &response, Transcript &transcript);

} // namespace laminate::delegation

#include "laminate/delegation/base/client/api_impl.hpp"

#endif // LAMINATE_DELEGATION_BASE_CLIENT_HPP
