#ifndef LAMINATE_SRC_FHE_SEAL_ARITHMETIC_INTERNAL_HPP
#define LAMINATE_SRC_FHE_SEAL_ARITHMETIC_INTERNAL_HPP

/// @file arithmetic_internal.hpp
/// @brief Private primitives shared by raw and prepared SEAL arithmetic.

#include "state.hpp"

#include <array>
#include <optional>
#include <span>
#include <stdexcept>

namespace laminate::fhe::seal_detail {

using Ciphertext = SealBackend::Ciphertext;
using EvalContext = SealBackend::EvalContext;
using OperationKind = SealBackend::OperationKind;

std::size_t saturated_add(std::size_t left, std::size_t right);
std::size_t scalar_noise_bits();
std::size_t full_multiplication_noise_bits(std::size_t slots);
int signed_remaining_bits(std::size_t bits, std::size_t loss);

template <typename Context>
DeterministicNoisePolicy deterministic_noise_policy(
    const Context &context) {
    return DeterministicNoisePolicy{
        .ring_degree = context.parameters.poly_modulus_degree,
        .plaintext_modulus = kBaseFieldOrder,
        .secret_hamming_weight_upper = static_cast<std::uint64_t>(
            context.parameters.poly_modulus_degree),
        .sampled_error_coefficient_bound = 21,
    };
}

template <typename Context>
std::vector<std::uint64_t> data_moduli(
    const Context &context, const Ciphertext &ciphertext) {
    const auto data =
        context.context->get_context_data(ciphertext.raw.parms_id());
    if (!data) {
        throw std::invalid_argument(
            "SealBackend: ciphertext parameters are not in the context");
    }
    std::vector<std::uint64_t> result;
    result.reserve(data->parms().coeff_modulus().size());
    for (const seal::Modulus &modulus :
         data->parms().coeff_modulus()) {
        result.push_back(modulus.value());
    }
    return result;
}

template <typename Context>
std::uint64_t special_modulus(const Context &context) {
    const auto key_data = context.context->key_context_data();
    if (!key_data || key_data->parms().coeff_modulus().empty()) {
        throw std::logic_error(
            "SealBackend: key context has no special modulus");
    }
    return key_data->parms().coeff_modulus().back().value();
}

template <typename Context>
const DeterministicNoiseBound *tracked_bound(
    const Context &context, const Ciphertext &ciphertext) {
    if (!context.parameters.track_deterministic_noise_bounds) {
        return nullptr;
    }
    if (!ciphertext.deterministic_noise_bound) {
        throw std::logic_error(
            "SealBackend: deterministic noise metadata is missing");
    }
    return &*ciphertext.deterministic_noise_bound;
}

template <typename Context>
void set_fresh_bound(const Context &context, Ciphertext &ciphertext,
                     std::uint64_t message_coefficient_bound) {
    if (!context.parameters.track_deterministic_noise_bounds) {
        ciphertext.deterministic_noise_bound.reset();
        return;
    }
    ciphertext.deterministic_noise_bound =
        bound_fresh_asymmetric_encryption(
            deterministic_noise_policy(context),
            message_coefficient_bound, data_moduli(context, ciphertext));
}
std::optional<DeterministicNoiseBound> additive_bound(
    const EvalContext &context, const Ciphertext &left,
    const Ciphertext &right, DeterministicNoiseOperation operation);
std::uint64_t plaintext_radius();
std::uint64_t plaintext_l1_bound(const EvalContext &context, bool scalar);

void record(const std::shared_ptr<SealBackend::CounterState> &state,
            OperationKind kind, std::size_t limbs);
void record(const EvalContext &context, OperationKind kind,
            const Ciphertext &ciphertext);
std::size_t chain_index(const EvalContext &context,
                        const Ciphertext &ciphertext);
bool same_raw_ciphertext(const Ciphertext &left,
                         const Ciphertext &right);
[[noreturn]] void rethrow(const char *operation,
                          const std::exception &error);
[[noreturn]] void reject_transparent_result(const char *operation);

seal::Plaintext encode_slots(
    const std::shared_ptr<seal::BatchEncoder> &encoder,
    const SlotVector &slots, const char *operation);
bool is_scalar_plaintext(const SlotVector &plaintext, std::size_t width);
bool is_zero_plaintext(const SlotVector &plaintext);
SlotVector canonical_plaintext(const SlotVector &plaintext,
                               std::size_t width,
                               const char *operation);
std::uint64_t plaintext_cache_hash(std::span<const Fp> plaintext);
std::shared_ptr<const SealBackend::PreparedPlaintextCache::Entry>
find_preprocessed_plaintext(const EvalContext &context,
                            std::span<const Fp> plaintext);
const seal::Plaintext &preprocessed_at_ciphertext_level(
    const SealBackend::PreparedPlaintextCache::Entry &entry,
    const Ciphertext &ciphertext);
Ciphertext multiply_plain_encoded(
    const EvalContext &context, const Ciphertext &ciphertext,
    const seal::Plaintext &encoded, bool scalar);
Ciphertext multiply_plain_scalar_direct(
    const EvalContext &context, const Ciphertext &ciphertext,
    const Fp &scalar);
seal::Plaintext encode_plaintext_at_ciphertext_level(
    const EvalContext &context, const SlotVector &plaintext,
    const Ciphertext &ciphertext);

const Ciphertext *validate_extension_level(
    const EvalContext &context,
    const SealBackend::ExtCiphertext &ciphertext,
    const char *operation);
const Ciphertext *validate_extension_pair(
    const EvalContext &context,
    const SealBackend::ExtCiphertext &left,
    const SealBackend::ExtCiphertext &right,
    const char *operation);
void accumulate_ciphertext_coordinate(
    const EvalContext &context,
    std::optional<Ciphertext> &destination,
    Ciphertext term, const char *operation);

template <std::size_t Size>
void reduce_extension_polynomial(
    const EvalContext &context,
    std::array<std::optional<Ciphertext>, Size> &coefficients) {
    static_assert(Size >= 2 * kExtensionDegree - 1);
    for (std::size_t degree = Size; degree-- > kExtensionDegree;) {
        if (!coefficients[degree]) {
            continue;
        }
        const Ciphertext negative =
            SealBackend::negate(context, *coefficients[degree]);
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            const std::uint64_t modulus_coefficient =
                kExtensionModulusPoly[coefficient];
            if (modulus_coefficient == 0) {
                continue;
            }
            Ciphertext term =
                modulus_coefficient == 1
                    ? negative
                    : SealBackend::mul_plain(
                          context, negative,
                          SlotVector(SealBackend::slot_count(context),
                                     Fp(modulus_coefficient)));
            auto &destination =
                coefficients[degree - kExtensionDegree + coefficient];
            accumulate_ciphertext_coordinate(
                context, destination, std::move(term),
                "SealBackend::reduce_extension_polynomial");
        }
    }
}

} // namespace laminate::fhe::seal_detail

#endif // LAMINATE_SRC_FHE_SEAL_ARITHMETIC_INTERNAL_HPP
