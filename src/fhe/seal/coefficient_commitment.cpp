/// @file coefficient_commitment.cpp
/// @brief Coefficient encoding, commitments, and partial decryption checks.
///
/// This unit is the transcript-packing bridge: it normalizes a one-prime BGV
/// ciphertext, exposes its public NTT coordinates, and evaluates the
/// client-secret partial-decryption predicate.

#include "arithmetic_internal.hpp"

#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace laminate::fhe {

using seal_detail::encode_slots;
using seal_detail::rethrow;

// Convert between SIMD slot values and the centered coefficient convention
// used by the transcript-packing relation.
std::uint64_t SealBackend::plaintext_modulus(const EvalContext &context) {
    const auto data = context.context->first_context_data();
    if (!data) {
        throw std::logic_error("SealBackend: missing first context data");
    }
    return data->parms().plain_modulus().value();
}

std::vector<std::int64_t>
SealBackend::encode_centered_plaintext_coefficients(
    const EvalContext &context, const SlotVector &slots) {
    const seal::Plaintext encoded = encode_slots(
        context.encoder, slots,
        "SealBackend::encode_centered_plaintext_coefficients");
    const std::uint64_t modulus = context.context->first_context_data()
                                      ->parms()
                                      .plain_modulus()
                                      .value();
    if (encoded.is_ntt_form() || encoded.coeff_count() != slot_count(context) ||
        modulus > static_cast<std::uint64_t>(
                      std::numeric_limits<std::int64_t>::max())) {
        throw std::logic_error(
            "SealBackend: unexpected plaintext encoding representation");
    }

    std::vector<std::int64_t> result(encoded.coeff_count());
    for (std::size_t coefficient = 0; coefficient < encoded.coeff_count();
         ++coefficient) {
        const std::uint64_t residue = encoded[coefficient];
        if (residue >= modulus) {
            throw std::logic_error(
                "SealBackend: encoded plaintext coefficient exceeds t");
        }
        result[coefficient] =
            residue <= modulus / 2
                ? static_cast<std::int64_t>(residue)
                : -static_cast<std::int64_t>(modulus - residue);
    }
    return result;
}

std::vector<std::int64_t>
SealBackend::encode_centered_plaintext_coefficients(
    const PublicVerifierContext &context, const SlotVector &slots) {
    const seal::Plaintext encoded = encode_slots(
        context.encoder, slots,
        "SealBackend::encode_centered_plaintext_coefficients(verifier)");
    const auto first = context.context->first_context_data();
    if (!first) {
        throw std::logic_error(
            "SealBackend: verifier context has no first context data");
    }
    const std::uint64_t modulus = first->parms().plain_modulus().value();
    if (encoded.is_ntt_form() ||
        encoded.coeff_count() != slot_count(context) ||
        modulus > static_cast<std::uint64_t>(
                      std::numeric_limits<std::int64_t>::max())) {
        throw std::logic_error(
            "SealBackend: unexpected verifier plaintext encoding "
            "representation");
    }

    std::vector<std::int64_t> result(encoded.coeff_count());
    for (std::size_t coefficient = 0; coefficient < encoded.coeff_count();
         ++coefficient) {
        const std::uint64_t residue = encoded[coefficient];
        if (residue >= modulus) {
            throw std::logic_error(
                "SealBackend: encoded verifier plaintext coefficient "
                "exceeds t");
        }
        result[coefficient] =
            residue <= modulus / 2
                ? static_cast<std::int64_t>(residue)
                : -static_cast<std::int64_t>(modulus - residue);
    }
    return result;
}

SlotVector SealBackend::decode_centered_plaintext_coefficients(
    const EvalContext &context,
    std::span<const std::int64_t> centered_coefficients) {
    const std::size_t degree = slot_count(context);
    const std::uint64_t modulus = context.context->first_context_data()
                                      ->parms()
                                      .plain_modulus()
                                      .value();
    if (centered_coefficients.size() != degree ||
        modulus > static_cast<std::uint64_t>(
                      std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument(
            "SealBackend::decode_centered_plaintext_coefficients: wrong "
            "degree or unsupported plaintext modulus");
    }

    seal::Plaintext encoded;
    encoded.resize(degree);
    const std::int64_t radius = static_cast<std::int64_t>((modulus - 1) / 2);
    for (std::size_t coefficient = 0; coefficient < degree; ++coefficient) {
        const std::int64_t value = centered_coefficients[coefficient];
        if (value < -radius || value > radius) {
            throw std::invalid_argument(
                "SealBackend::decode_centered_plaintext_coefficients: "
                "coefficient is outside the centered interval");
        }
        encoded[coefficient] =
            value >= 0
                ? static_cast<std::uint64_t>(value)
                : modulus - (std::uint64_t{0} -
                             static_cast<std::uint64_t>(value));
    }

    std::vector<std::uint64_t> decoded;
    try {
        context.encoder->decode(encoded, decoded);
    } catch (const std::exception &error) {
        rethrow("SealBackend::decode_centered_plaintext_coefficients", error);
    }
    if (decoded.size() != degree) {
        throw std::logic_error(
            "SealBackend: BatchEncoder decoded the wrong slot count");
    }
    SlotVector result;
    result.reserve(degree);
    for (const std::uint64_t value : decoded) {
        if (value >= modulus) {
            throw std::logic_error(
                "SealBackend: decoded plaintext slot exceeds t");
        }
        result.emplace_back(value);
    }
    return result;
}

SlotVector SealBackend::decode_centered_plaintext_coefficients(
    const PublicVerifierContext &context,
    std::span<const std::int64_t> centered_coefficients) {
    const std::size_t degree = slot_count(context);
    const auto first = context.context->first_context_data();
    if (!first) {
        throw std::logic_error(
            "SealBackend: verifier context has no first context data");
    }
    const std::uint64_t modulus = first->parms().plain_modulus().value();
    if (centered_coefficients.size() != degree ||
        modulus > static_cast<std::uint64_t>(
                      std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument(
            "SealBackend::decode_centered_plaintext_coefficients(verifier): "
            "wrong degree or unsupported plaintext modulus");
    }

    seal::Plaintext encoded;
    encoded.resize(degree);
    const std::int64_t radius =
        static_cast<std::int64_t>((modulus - 1) / 2);
    for (std::size_t coefficient = 0; coefficient < degree; ++coefficient) {
        const std::int64_t value = centered_coefficients[coefficient];
        if (value < -radius || value > radius) {
            throw std::invalid_argument(
                "SealBackend::decode_centered_plaintext_coefficients"
                "(verifier): coefficient is outside the centered interval");
        }
        encoded[coefficient] =
            value >= 0
                ? static_cast<std::uint64_t>(value)
                : modulus - (std::uint64_t{0} -
                             static_cast<std::uint64_t>(value));
    }

    std::vector<std::uint64_t> decoded;
    try {
        context.encoder->decode(encoded, decoded);
    } catch (const std::exception &error) {
        rethrow(
            "SealBackend::decode_centered_plaintext_coefficients(verifier)",
            error);
    }
    if (decoded.size() != degree) {
        throw std::logic_error(
            "SealBackend: verifier BatchEncoder decoded the wrong slot "
            "count");
    }
    SlotVector result;
    result.reserve(degree);
    for (const std::uint64_t value : decoded) {
        if (value >= modulus) {
            throw std::logic_error(
                "SealBackend: decoded verifier plaintext slot exceeds t");
        }
        result.emplace_back(value);
    }
    return result;
}

std::uint64_t SealBackend::lowest_coefficient_modulus(
    const EvalContext &context) {
    const auto data = context.context->last_context_data();
    if (!data || data->parms().coeff_modulus().size() != 1) {
        throw std::logic_error(
            "SealBackend: bottom data chain is not one limb");
    }
    return data->parms().coeff_modulus().front().value();
}

// The caller has already reduced the ciphertext to one data prime. Set its
// correction factor to one before committing to its public NTT coordinates.
void SealBackend::normalize_for_coefficient_commitment(
    const EvalContext &context, Ciphertext &ciphertext) {
    if (ciphertext.raw.size() != 2 ||
        ciphertext.raw.coeff_modulus_size() != 1 ||
        !ciphertext.raw.is_ntt_form()) {
        throw std::invalid_argument(
            "SealBackend::normalize_for_coefficient_commitment: expected a "
            "size-two, one-prime, NTT-form ciphertext");
    }
    const std::uint64_t correction = ciphertext.raw.correction_factor();
    if (correction == 1) {
        return;
    }
    if (correction == 0 || correction >= kBaseFieldOrder) {
        throw std::invalid_argument(
            "SealBackend::normalize_for_coefficient_commitment: invalid BGV "
            "correction factor");
    }

    // BGV decryption returns correction^{-1} * (c0 + c1*s) modulo t.
    // Multiplying both public ciphertext polynomials by correction^{-1} and
    // setting the metadata to one therefore chooses a canonical coefficient
    // representation without changing the encrypted plaintext.
    const Fp inverse = Fp(correction).inverse();
    ciphertext = mul_plain(
        context, ciphertext, SlotVector(slot_count(context), inverse));
    ciphertext.raw.correction_factor() = 1;
}

bool SealBackend::correction_factor_is_one(
    const Ciphertext &ciphertext) {
    return ciphertext.raw.correction_factor() == 1;
}

bool SealBackend::is_normalized_for_coefficient_commitment(
    const Ciphertext &ciphertext) {
    return ciphertext.raw.size() == 2 &&
           ciphertext.raw.coeff_modulus_size() == 1 &&
           ciphertext.raw.is_ntt_form() &&
           correction_factor_is_one(ciphertext);
}

std::vector<std::uint64_t>
SealBackend::coefficient_commitment_ntt_coordinates(
    const Ciphertext &ciphertext) {
    const std::span<const std::uint64_t> coordinates =
        coefficient_commitment_ntt_coordinate_view(ciphertext);
    return std::vector<std::uint64_t>(
        coordinates.begin(), coordinates.end());
}

std::span<const std::uint64_t>
SealBackend::coefficient_commitment_ntt_coordinate_view(
    const Ciphertext &ciphertext) {
    if (!is_normalized_for_coefficient_commitment(ciphertext)) {
        throw std::invalid_argument(
            "SealBackend::coefficient_commitment_ntt_coordinate_view: "
            "ciphertext is not canonical");
    }
    const std::size_t coordinate_count =
        ciphertext.raw.size() * ciphertext.raw.poly_modulus_degree();
    return std::span<const std::uint64_t>(
        ciphertext.raw.data(), coordinate_count);
}

// Public plaintext offsets use the same final-prime NTT representation as the
// ciphertext coordinates, allowing the verifier to combine them directly.
std::vector<std::uint64_t>
SealBackend::encode_lowest_plaintext_ntt_coordinates(
    const EvalContext &context,
    std::span<const std::int64_t> centered_coefficients) {
    const auto bottom = context.context->last_context_data();
    if (!bottom || bottom->parms().coeff_modulus().size() != 1 ||
        centered_coefficients.size() != bottom->parms().poly_modulus_degree()) {
        throw std::invalid_argument(
            "SealBackend::encode_lowest_plaintext_ntt_coordinates: "
            "wrong polynomial degree or bottom-chain shape");
    }

    const SlotVector slots = decode_centered_plaintext_coefficients(
        context, centered_coefficients);
    seal::Plaintext plaintext = encode_slots(
        context.encoder, slots,
        "SealBackend::encode_lowest_plaintext_ntt_coordinates");
    try {
        context.evaluator->transform_to_ntt_inplace(
            plaintext, bottom->parms_id());
    } catch (const std::exception &error) {
        rethrow("SealBackend::encode_lowest_plaintext_ntt_coordinates",
                error);
    }
    if (!plaintext.is_ntt_form() ||
        plaintext.coeff_count() != bottom->parms().poly_modulus_degree()) {
        throw std::logic_error(
            "SealBackend: plaintext NTT lift returned the wrong shape");
    }
    return std::vector<std::uint64_t>(
        plaintext.data(), plaintext.data() + plaintext.coeff_count());
}

std::vector<std::uint64_t>
SealBackend::encode_lowest_plaintext_ntt_coordinates(
    const PublicVerifierContext &context,
    std::span<const std::int64_t> centered_coefficients) {
    const auto bottom = context.context->last_context_data();
    if (!bottom || bottom->parms().coeff_modulus().size() != 1 ||
        centered_coefficients.size() !=
            bottom->parms().poly_modulus_degree()) {
        throw std::invalid_argument(
            "SealBackend::encode_lowest_plaintext_ntt_coordinates"
            "(verifier): wrong polynomial degree or bottom-chain shape");
    }

    const SlotVector slots = decode_centered_plaintext_coefficients(
        context, centered_coefficients);
    seal::Plaintext plaintext = encode_slots(
        context.encoder, slots,
        "SealBackend::encode_lowest_plaintext_ntt_coordinates(verifier)");
    try {
        // Transforming one public plaintext needs encryption parameters but
        // no evaluation key. Keep this short-lived object inside the backend
        // so the typed verifier context itself exposes no server evaluator.
        seal::Evaluator evaluator(*context.context);
        evaluator.transform_to_ntt_inplace(plaintext,
                                           bottom->parms_id());
    } catch (const std::exception &error) {
        rethrow(
            "SealBackend::encode_lowest_plaintext_ntt_coordinates(verifier)",
            error);
    }
    if (!plaintext.is_ntt_form() ||
        plaintext.coeff_count() !=
            bottom->parms().poly_modulus_degree()) {
        throw std::logic_error(
            "SealBackend: verifier plaintext NTT lift returned the wrong "
            "shape");
    }
    return std::vector<std::uint64_t>(
        plaintext.data(), plaintext.data() + plaintext.coeff_count());
}

// Client-secret partial decryption supplies the centered coefficients used
// by the verifier's well-formedness check.
std::vector<std::int64_t>
SealBackend::partial_decryption_centered_coefficients(
    const ClientContext &context, const Ciphertext &ciphertext) {
    const auto data =
        context.context->get_context_data(ciphertext.raw.parms_id());
    if (!data) {
        throw std::invalid_argument(
            "SealBackend::partial_decryption_centered_coefficients: ciphertext "
            "parameters are not in the client context");
    }
    const auto &moduli = data->parms().coeff_modulus();
    if (moduli.size() != 1) {
        throw std::invalid_argument(
            "SealBackend::partial_decryption_centered_coefficients: expected the "
            "single-prime bottom level");
    }
    if (ciphertext.raw.size() != 2 || !ciphertext.raw.is_ntt_form()) {
        throw std::invalid_argument(
            "SealBackend::partial_decryption_centered_coefficients: expected a "
            "size-two NTT-form ciphertext");
    }
    if (!is_normalized_for_coefficient_commitment(ciphertext)) {
        throw std::invalid_argument(
            "SealBackend::partial_decryption_centered_coefficients: ciphertext is "
            "not correction-factor normalized");
    }
    if (!context.secret_key) {
        throw std::invalid_argument(
            "SealBackend::partial_decryption_centered_coefficients: client has no "
            "secret key");
    }

    const seal::Modulus &modulus = moduli.front();
    const auto &key_moduli = context.context->key_context_data()
                                 ->parms()
                                 .coeff_modulus();
    if (key_moduli.empty() || key_moduli.front().value() != modulus.value()) {
        throw std::logic_error(
            "SealBackend::partial_decryption_centered_coefficients: bottom modulus "
            "is not the first secret-key RNS component");
    }

    const std::size_t degree = ciphertext.raw.poly_modulus_degree();
    const std::uint64_t *c0 = ciphertext.raw.data(0);
    const std::uint64_t *c1 = ciphertext.raw.data(1);
    const std::uint64_t *secret = context.secret_key->data().data();
    std::vector<std::uint64_t> partial_decryption(degree);
    for (std::size_t coefficient = 0; coefficient < degree; ++coefficient) {
        const std::uint64_t product = seal::util::multiply_uint_mod(
            c1[coefficient], secret[coefficient], modulus);
        partial_decryption[coefficient] = seal::util::add_uint_mod(
            c0[coefficient], product, modulus);
    }
    seal::util::inverse_ntt_negacyclic_harvey(
        partial_decryption.data(), data->small_ntt_tables()[0]);

    const std::uint64_t modulus_value = modulus.value();
    const std::uint64_t half = modulus_value >> 1U;
    std::vector<std::int64_t> result;
    result.reserve(degree);
    for (const std::uint64_t residue : partial_decryption) {
        result.push_back(
            residue > half
                ? -static_cast<std::int64_t>(modulus_value - residue)
                : static_cast<std::int64_t>(residue));
    }
    return result;
}

// The following norm routines evaluate the exact bounded-noise predicate used
// by transcript packing; they do not estimate SEAL's heuristic noise budget.
std::uint64_t SealBackend::partial_decryption_infinity_norm(
    const ClientContext &context, const Ciphertext &ciphertext) {
    const auto coefficients = partial_decryption_centered_coefficients(
        context, ciphertext);
    std::uint64_t maximum = 0;
    for (const std::int64_t coefficient : coefficients) {
        const std::uint64_t magnitude =
            coefficient >= 0
                ? static_cast<std::uint64_t>(coefficient)
                : std::uint64_t{0} -
                      static_cast<std::uint64_t>(coefficient);
        maximum = std::max(maximum, magnitude);
    }
    return maximum;
}

std::uint64_t SealBackend::canonical_error_infinity_norm(
    const EvalContext &eval, const ClientContext &client,
    const Ciphertext &ciphertext) {
    const std::vector<std::int64_t> phase =
        partial_decryption_centered_coefficients(client, ciphertext);
    const SlotVector message = decrypt(client, ciphertext);
    const std::vector<std::int64_t> plaintext =
        encode_centered_plaintext_coefficients(eval, message);
    if (phase.size() != plaintext.size()) {
        throw std::logic_error(
            "SealBackend::canonical_error_infinity_norm: plaintext and "
            "phase degrees differ");
    }

    std::uint64_t maximum = 0;
    for (std::size_t coefficient = 0; coefficient < phase.size();
         ++coefficient) {
        const std::int64_t numerator =
            phase[coefficient] - plaintext[coefficient];
        if (numerator % static_cast<std::int64_t>(kBaseFieldOrder) != 0) {
            throw std::logic_error(
                "SealBackend::canonical_error_infinity_norm: phase minus "
                "plaintext is not divisible by t");
        }
        const std::int64_t error =
            numerator / static_cast<std::int64_t>(kBaseFieldOrder);
        const std::uint64_t magnitude =
            error < 0
                ? std::uint64_t{0} - static_cast<std::uint64_t>(error)
                : static_cast<std::uint64_t>(error);
        maximum = std::max(maximum, magnitude);
    }
    return maximum;
}

std::uint64_t SealBackend::canonical_error_infinity_norm(
    const PublicVerifierContext &verifier, const ClientContext &client,
    const Ciphertext &ciphertext) {
    const std::vector<std::int64_t> phase =
        partial_decryption_centered_coefficients(client, ciphertext);
    const SlotVector message = decrypt(client, ciphertext);
    const std::vector<std::int64_t> plaintext =
        encode_centered_plaintext_coefficients(verifier, message);
    if (phase.size() != plaintext.size()) {
        throw std::logic_error(
            "SealBackend::canonical_error_infinity_norm: plaintext and "
            "phase degrees differ");
    }

    std::uint64_t maximum = 0;
    for (std::size_t coefficient = 0; coefficient < phase.size();
         ++coefficient) {
        const std::int64_t numerator =
            phase[coefficient] - plaintext[coefficient];
        if (numerator % static_cast<std::int64_t>(kBaseFieldOrder) != 0) {
            throw std::logic_error(
                "SealBackend::canonical_error_infinity_norm: phase minus "
                "plaintext is not divisible by t");
        }
        const std::int64_t error =
            numerator / static_cast<std::int64_t>(kBaseFieldOrder);
        const std::uint64_t magnitude =
            error < 0
                ? std::uint64_t{0} - static_cast<std::uint64_t>(error)
                : static_cast<std::uint64_t>(error);
        maximum = std::max(maximum, magnitude);
    }
    return maximum;
}

std::uint64_t
SealBackend::partial_decryption_with_public_ntt_offset_infinity_norm(
    const ClientContext &context, const Ciphertext *ciphertext,
    std::span<const std::uint64_t> public_c0_coordinates) {
    const auto data = ciphertext != nullptr
                          ? context.context->get_context_data(
                                ciphertext->raw.parms_id())
                          : context.context->last_context_data();
    if (!data || data->parms().coeff_modulus().size() != 1) {
        throw std::invalid_argument(
            "SealBackend mixed partial-decryption norm requires the "
            "single-prime bottom level");
    }
    const std::size_t degree = data->parms().poly_modulus_degree();
    if (!public_c0_coordinates.empty() &&
        public_c0_coordinates.size() != degree) {
        throw std::invalid_argument(
            "SealBackend mixed partial-decryption norm has the wrong "
            "public coordinate count");
    }
    const seal::Modulus &modulus = data->parms().coeff_modulus().front();
    std::vector<std::uint64_t> partial_decryption(degree, 0);
    for (std::size_t coefficient = 0;
         coefficient < public_c0_coordinates.size(); ++coefficient) {
        if (public_c0_coordinates[coefficient] >= modulus.value()) {
            throw std::invalid_argument(
                "SealBackend mixed public coordinate exceeds the bottom "
                "modulus");
        }
        partial_decryption[coefficient] =
            public_c0_coordinates[coefficient];
    }

    if (ciphertext != nullptr) {
        if (!is_normalized_for_coefficient_commitment(*ciphertext) ||
            !context.secret_key) {
            throw std::invalid_argument(
                "SealBackend mixed partial-decryption ciphertext is not "
                "normalized or the client secret key is missing");
        }
        const auto &key_moduli = context.context->key_context_data()
                                     ->parms()
                                     .coeff_modulus();
        if (key_moduli.empty() ||
            key_moduli.front().value() != modulus.value()) {
            throw std::logic_error(
                "SealBackend mixed partial-decryption bottom modulus does "
                "not match the secret-key basis");
        }
        const std::uint64_t *c0 = ciphertext->raw.data(0);
        const std::uint64_t *c1 = ciphertext->raw.data(1);
        const std::uint64_t *secret = context.secret_key->data().data();
        for (std::size_t coefficient = 0; coefficient < degree;
             ++coefficient) {
            const std::uint64_t secret_term =
                seal::util::multiply_uint_mod(
                    c1[coefficient], secret[coefficient], modulus);
            partial_decryption[coefficient] = seal::util::add_uint_mod(
                partial_decryption[coefficient],
                seal::util::add_uint_mod(c0[coefficient], secret_term,
                                         modulus),
                modulus);
        }
    }

    seal::util::inverse_ntt_negacyclic_harvey(
        partial_decryption.data(), data->small_ntt_tables()[0]);
    const std::uint64_t half = modulus.value() >> 1U;
    std::uint64_t maximum = 0;
    for (const std::uint64_t residue : partial_decryption) {
        maximum = std::max(
            maximum, residue > half ? modulus.value() - residue : residue);
    }
    return maximum;
}

bool SealBackend::partial_decryption_within_bound(
    const ClientContext &context, const Ciphertext &ciphertext,
    std::uint64_t threshold) {
    return partial_decryption_infinity_norm(context, ciphertext) <= threshold;
}

} // namespace laminate::fhe
