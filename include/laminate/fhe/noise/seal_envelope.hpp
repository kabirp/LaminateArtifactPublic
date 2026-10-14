#ifndef LAMINATE_FHE_NOISE_SEAL_ENVELOPE_HPP
#define LAMINATE_FHE_NOISE_SEAL_ENVELOPE_HPP

/// @file seal_envelope.hpp
/// @brief Exact public-parameter bridge from SEAL to the bound-only backend.

#include "laminate/fhe/noise/envelope_backend.hpp"
#include "laminate/fhe/seal_backend.hpp"

namespace laminate::fhe {

/// Copy the live SEAL modulus inventory into a challenge-independent noise
/// backend configuration.
///
/// Preconditions:
/// - `eval` was produced by `SealBackend::create`;
/// - its data chain is nonempty.
///
/// Postcondition: the returned data-prime order is `[q_0,...,q_L]`, exactly
/// matching fresh SEAL ciphertexts, and the key-switching prime is separate.
/// No secret-key material or sampled ciphertext diagnostic is consulted.
NoiseEnvelopeParameters make_noise_envelope_parameters(
    const SealBackend::EvalContext &eval);

} // namespace laminate::fhe

#endif // LAMINATE_FHE_NOISE_SEAL_ENVELOPE_HPP
