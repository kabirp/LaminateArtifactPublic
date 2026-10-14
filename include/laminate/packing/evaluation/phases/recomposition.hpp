#ifndef LAMINATE_PACKING_EVALUATION_PHASES_RECOMPOSITION_HPP
#define LAMINATE_PACKING_EVALUATION_PHASES_RECOMPOSITION_HPP

/// @file recomposition.hpp
/// @brief Client decryption and signed-radix recomposition.

namespace laminate::packing {

template <PublicCoefficientEncodingBackend Backend>
std::vector<fhe::SlotVector> decrypt_and_recompose_signed_digit_packing(
    const typename Backend::ClientContext &client,
    std::span<const MixedPackingValue<Backend>> packed_digit_values,
    std::size_t logical_packed_outputs,
    const BalancedRadix &packing_radix) {
    packing_radix.validate();
    const std::size_t digits = packing_radix.digit_count;
    if (logical_packed_outputs == 0 ||
        packed_digit_values.size() != logical_packed_outputs * digits) {
        throw std::invalid_argument(
            "signed-digit packing: malformed ciphertext dimensions");
    }

    std::vector<fhe::SlotVector> result(
        logical_packed_outputs,
        fhe::SlotVector(Backend::slot_count(client), Fp::zero()));
    Fp place = Fp::one();
    for (std::size_t digit = 0; digit < digits; ++digit) {
        for (std::size_t output = 0; output < logical_packed_outputs;
             ++output) {
            const MixedPackingValue<Backend> &value =
                packed_digit_values[output * digits + digit];
            fhe::SlotVector plaintext = value.public_offset.materialize(
                Backend::slot_count(client));
            if (value.encrypted_contribution) {
                const fhe::SlotVector encrypted = Backend::decrypt(
                    client, *value.encrypted_contribution);
                if (encrypted.size() != plaintext.size()) {
                    throw std::logic_error(
                        "signed-digit packing: backend returned wrong slot "
                        "count");
                }
                for (std::size_t slot = 0; slot < plaintext.size(); ++slot) {
                    plaintext[slot] += encrypted[slot];
                }
            }
            if (plaintext.size() != result[output].size()) {
                throw std::logic_error(
                    "signed-digit packing: backend returned wrong slot count");
            }
            for (std::size_t slot = 0; slot < plaintext.size(); ++slot) {
                result[output][slot] += place * plaintext[slot];
            }
        }
        place *= Fp(packing_radix.base);
    }
    return result;
}

} // namespace laminate::packing

#endif // LAMINATE_PACKING_EVALUATION_PHASES_RECOMPOSITION_HPP
