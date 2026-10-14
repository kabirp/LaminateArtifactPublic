#ifndef LAMINATE_PAYLOAD_EVALUATION_PROOF_CIPHERTEXT_NORMALIZATION_HPP
#define LAMINATE_PAYLOAD_EVALUATION_PROOF_CIPHERTEXT_NORMALIZATION_HPP

/// @file proof_ciphertext_normalization.hpp
/// @brief Lower payload ciphertexts to the RNS level consumed by GKR.

#include "laminate/fhe/backend.hpp"

#include <cstddef>
#include <limits>
#include <stdexcept>

namespace laminate::payload {

/// Drop an evaluated payload ciphertext to exactly the RNS limb count needed
/// by its proof relation. This operates on the proof snapshot; it does not
/// change the copy used to continue payload evaluation.
template <fhe::FheBackend Backend>
void normalize_ciphertext_for_proof(
    const typename Backend::EvalContext &eval,
    typename Backend::Ciphertext &ciphertext,
    std::size_t proof_mult_depth) {
    if (proof_mult_depth == std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(
            "proof multiplication depth overflows its RNS limb count");
    }
    fhe::mod_switch_to_rns_limb_count<Backend>(
        eval, ciphertext, proof_mult_depth + 1U);
}

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_EVALUATION_PROOF_CIPHERTEXT_NORMALIZATION_HPP
