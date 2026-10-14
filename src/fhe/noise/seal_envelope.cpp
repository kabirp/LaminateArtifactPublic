/// @file seal_envelope.cpp
/// @brief Public SEAL modulus-chain conversion for offline noise proofs.

#include "laminate/fhe/noise/seal_envelope.hpp"

#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::fhe {

NoiseEnvelopeParameters make_noise_envelope_parameters(
    const SealBackend::EvalContext &eval) {
    std::vector<std::uint64_t> moduli =
        SealBackend::coefficient_moduli(eval);
    if (moduli.size() < 2) {
        throw std::logic_error(
            "SEAL noise envelope: expected data and special primes");
    }

    const std::uint64_t special_modulus = moduli.back();
    moduli.pop_back();
    NoiseEnvelopeParameters result{
        .policy = DeterministicNoisePolicy{
            .ring_degree = eval.parameters.poly_modulus_degree,
            .plaintext_modulus = kBaseFieldOrder,
            .secret_hamming_weight_upper = static_cast<std::uint64_t>(
                eval.parameters.poly_modulus_degree),
            .sampled_error_coefficient_bound = 21,
        },
        .data_moduli = std::move(moduli),
        .special_modulus = special_modulus,
    };
    result.validate();
    return result;
}

} // namespace laminate::fhe
