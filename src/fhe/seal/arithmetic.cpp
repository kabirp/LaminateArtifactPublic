/// @file arithmetic.cpp
/// @brief Raw BGV ciphertext and extension-field arithmetic.
///
/// This is the concrete backend boundary for Laminate's FHE work. Base
/// ciphertext add, multiply, relinearize, rotate, and modulus-switch calls are
/// implemented here; prepared plaintext multiplication lives in
/// `plaintext_basis.cpp`.

#include "arithmetic_internal.hpp"

#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace laminate::fhe::seal_detail {

constexpr std::size_t kRelinearizationNoiseBits = 2;
constexpr std::size_t kRotationNoiseBits = 1;

std::size_t saturated_add(std::size_t left, std::size_t right) {
    return right > std::numeric_limits<std::size_t>::max() - left
               ? std::numeric_limits<std::size_t>::max()
               : left + right;
}

std::size_t scalar_noise_bits() {
    return std::bit_width(kBaseFieldOrder - 1U);
}

std::size_t full_multiplication_noise_bits(std::size_t slots) {
    return scalar_noise_bits() + std::bit_width(slots - 1U);
}

int signed_remaining_bits(std::size_t bits, std::size_t loss) {
    if (loss <= bits) {
        const std::size_t remaining = bits - loss;
        return remaining >
                       static_cast<std::size_t>(std::numeric_limits<int>::max())
                   ? std::numeric_limits<int>::max()
                   : static_cast<int>(remaining);
    }
    const std::size_t deficit = loss - bits;
    return deficit >
                   static_cast<std::size_t>(std::numeric_limits<int>::max())
               ? std::numeric_limits<int>::min()
               : -static_cast<int>(deficit);
}
std::optional<DeterministicNoiseBound> additive_bound(
    const EvalContext &context, const Ciphertext &left,
    const Ciphertext &right, DeterministicNoiseOperation operation) {
    const auto *left_bound = tracked_bound(context, left);
    const auto *right_bound = tracked_bound(context, right);
    if (left_bound == nullptr) {
        return std::nullopt;
    }
    return bound_addition(*left_bound, *right_bound,
                          data_moduli(context, left), operation);
}

std::uint64_t plaintext_radius() {
    return (kBaseFieldOrder - 1) / 2;
}

std::uint64_t plaintext_l1_bound(const EvalContext &context,
                                 bool scalar) {
    const std::uint64_t coefficients =
        scalar ? 1
               : static_cast<std::uint64_t>(
                     SealBackend::slot_count(context));
    if (coefficients >
        std::numeric_limits<std::uint64_t>::max() / plaintext_radius()) {
        throw std::overflow_error(
            "SealBackend: plaintext l1 bound overflows uint64");
    }
    return coefficients * plaintext_radius();
}

void record(const std::shared_ptr<SealBackend::CounterState> &state,
            OperationKind kind, std::size_t rns_limbs) {
    if (state && state->enabled) {
        ++state->counts.by_kind.at(static_cast<std::size_t>(kind))[rns_limbs];
    }
}

void record(const EvalContext &context, OperationKind kind,
            const Ciphertext &ciphertext) {
    record(context.counters, kind, ciphertext.raw.coeff_modulus_size());
}

std::size_t chain_index(const EvalContext &context,
                        const Ciphertext &ciphertext) {
    const auto data =
        context.context->get_context_data(ciphertext.raw.parms_id());
    if (!data) {
        throw std::invalid_argument(
            "SealBackend: ciphertext parameters are not in the context");
    }
    return data->chain_index();
}

[[noreturn]] void rethrow(const char *operation,
                          const std::exception &error) {
    throw std::logic_error(std::string(operation) + ": " + error.what());
}

bool same_raw_ciphertext(const Ciphertext &left,
                         const Ciphertext &right) {
    const seal::Ciphertext &a = left.raw;
    const seal::Ciphertext &b = right.raw;
    if (a.parms_id() != b.parms_id() || a.size() != b.size() ||
        a.is_ntt_form() != b.is_ntt_form() ||
        a.poly_modulus_degree() != b.poly_modulus_degree() ||
        a.coeff_modulus_size() != b.coeff_modulus_size() ||
        a.scale() != b.scale() ||
        a.correction_factor() != b.correction_factor()) {
        return false;
    }
    const std::size_t words =
        a.size() * a.poly_modulus_degree() * a.coeff_modulus_size();
    if (words == 0) {
        return false;
    }
    return std::equal(a.data(), a.data() + words, b.data());
}

[[noreturn]] void reject_transparent_result(const char *operation) {
    throw std::logic_error(
        std::string(operation) +
        ": raw ciphertext arithmetic produced a publicly known zero; "
        "represent it as fhe::FheValue public plaintext instead");
}

SlotVector decode_transparent_bgv_plaintext(
    const EvalContext &context, const Ciphertext &ciphertext) {
    if (!ciphertext.raw.is_transparent()) {
        throw std::logic_error(
            "SealBackend: attempted to decode a nontransparent ciphertext");
    }
    const auto context_data =
        context.context->get_context_data(ciphertext.raw.parms_id());
    if (!context_data || !ciphertext.raw.is_ntt_form()) {
        throw std::logic_error(
            "SealBackend: transparent BGV ciphertext has invalid metadata");
    }

    const auto &parameters = context_data->parms();
    const auto &plain_modulus = parameters.plain_modulus();
    const std::size_t degree = parameters.poly_modulus_degree();
    const std::size_t modulus_count =
        parameters.coeff_modulus().size();
    if (ciphertext.raw.poly_modulus_degree() != degree ||
        ciphertext.raw.coeff_modulus_size() != modulus_count ||
        ciphertext.raw.size() < 2) {
        throw std::logic_error(
            "SealBackend: transparent BGV ciphertext has invalid shape");
    }

    std::vector<std::uint64_t> phase(degree * modulus_count);
    std::copy_n(ciphertext.raw.data(0), phase.size(), phase.data());
    seal::util::inverse_ntt_negacyclic_harvey(
        seal::util::RNSIter(phase.data(), degree), modulus_count,
        seal::util::iter(context_data->small_ntt_tables()));

    std::vector<std::uint64_t> coefficients(degree);
    context_data->rns_tool()->decrypt_modt(
        seal::util::RNSIter(phase.data(), degree),
        seal::util::CoeffIter(coefficients.data()),
        seal::MemoryManager::GetPool());

    const std::uint64_t correction =
        ciphertext.raw.correction_factor();
    if (correction != 1) {
        std::uint64_t inverse = 1;
        if (!seal::util::try_invert_uint_mod(
                correction, plain_modulus, inverse)) {
            throw std::logic_error(
                "SealBackend: transparent BGV ciphertext has invalid "
                "correction factor");
        }
        for (std::uint64_t &coefficient : coefficients) {
            coefficient = seal::util::multiply_uint_mod(
                coefficient, inverse, plain_modulus);
        }
    }

    seal::Plaintext plaintext;
    plaintext.resize(degree);
    std::copy(coefficients.begin(), coefficients.end(), plaintext.data());
    std::vector<std::uint64_t> decoded;
    context.encoder->decode(plaintext, decoded);
    if (decoded.size() != degree) {
        throw std::logic_error(
            "SealBackend: transparent BGV plaintext has the wrong slot "
            "count");
    }
    SlotVector result;
    result.reserve(decoded.size());
    for (const std::uint64_t value : decoded) {
        result.emplace_back(value);
    }
    return result;
}

void align_levels(const EvalContext &context, Ciphertext &left,
                  Ciphertext &right) {
    std::size_t left_level = chain_index(context, left);
    std::size_t right_level = chain_index(context, right);
    while (left_level > right_level) {
        SealBackend::mod_switch_to_next(context, left);
        --left_level;
    }
    while (right_level > left_level) {
        SealBackend::mod_switch_to_next(context, right);
        --right_level;
    }
}

std::optional<SlotVector> add_at_same_level_inplace_or_public(
    const EvalContext &context, Ciphertext &accumulator,
    const Ciphertext &term) {
    if (accumulator.raw.parms_id() != term.raw.parms_id()) {
        throw std::logic_error(
            "SealBackend::add: internal level alignment failed");
    }

    const std::size_t noise_loss_bits =
        std::max(accumulator.noise_loss_bits, term.noise_loss_bits);
    std::optional<DeterministicNoiseBound> output_bound = additive_bound(
        context, accumulator, term,
        DeterministicNoiseOperation::Addition);
    try {
        record(context, OperationKind::Add, accumulator);
        context.evaluator->add_inplace(accumulator.raw, term.raw);
    } catch (const std::logic_error &error) {
        if (accumulator.raw.is_transparent()) {
            return decode_transparent_bgv_plaintext(context, accumulator);
        }
        rethrow("SealBackend::add", error);
    }
    if (accumulator.raw.is_transparent()) {
        return decode_transparent_bgv_plaintext(context, accumulator);
    }
    accumulator.deterministic_noise_bound = std::move(output_bound);
    accumulator.noise_loss_bits = noise_loss_bits;
    return std::nullopt;
}

std::optional<SlotVector> subtract_at_same_level_inplace_or_public(
    const EvalContext &context, Ciphertext &accumulator,
    const Ciphertext &term) {
    if (accumulator.raw.parms_id() != term.raw.parms_id()) {
        throw std::logic_error(
            "SealBackend::sub: internal level alignment failed");
    }
    if (same_raw_ciphertext(accumulator, term)) {
        return SlotVector(context.encoder->slot_count(), Fp::zero());
    }

    const std::size_t noise_loss_bits =
        std::max(accumulator.noise_loss_bits, term.noise_loss_bits);
    std::optional<DeterministicNoiseBound> output_bound = additive_bound(
        context, accumulator, term,
        DeterministicNoiseOperation::Subtraction);
    try {
        record(context, OperationKind::Sub, accumulator);
        context.evaluator->sub_inplace(accumulator.raw, term.raw);
    } catch (const std::logic_error &error) {
        if (accumulator.raw.is_transparent()) {
            return decode_transparent_bgv_plaintext(context, accumulator);
        }
        rethrow("SealBackend::sub", error);
    }
    if (accumulator.raw.is_transparent()) {
        return decode_transparent_bgv_plaintext(context, accumulator);
    }
    accumulator.deterministic_noise_bound = std::move(output_bound);
    accumulator.noise_loss_bits = noise_loss_bits;
    return std::nullopt;
}

Ciphertext subtract_at_same_level(const EvalContext &context,
                                  const Ciphertext &left,
                                  const Ciphertext &right) {
    Ciphertext result = left;
    if (subtract_at_same_level_inplace_or_public(context, result, right)) {
        reject_transparent_result("SealBackend::sub");
    }
    return result;
}

Ciphertext multiply_at_same_level_without_relinearizing(
    const EvalContext &context, const Ciphertext &left,
    const Ciphertext &right) {
    if (left.raw.parms_id() != right.raw.parms_id()) {
        throw std::logic_error(
            "SealBackend::mul_no_relin: internal level alignment failed");
    }

    Ciphertext result;
    try {
        record(context, OperationKind::MulNoRelin, left);
        context.evaluator->multiply(left.raw, right.raw, result.raw);
    } catch (const std::logic_error &error) {
        if (result.raw.is_transparent()) {
            reject_transparent_result("SealBackend::mul_no_relin");
        }
        rethrow("SealBackend::mul_no_relin", error);
    }
    if (result.raw.is_transparent()) {
        reject_transparent_result("SealBackend::mul_no_relin");
    }
    if (const auto *left_bound = tracked_bound(context, left)) {
        const auto *right_bound = tracked_bound(context, right);
        result.deterministic_noise_bound = bound_ciphertext_multiplication(
            deterministic_noise_policy(context), *left_bound,
            *right_bound, data_moduli(context, result));
    }
    result.noise_loss_bits = saturated_add(
        std::max(left.noise_loss_bits, right.noise_loss_bits),
        full_multiplication_noise_bits(SealBackend::slot_count(context)));
    return result;
}

const Ciphertext *validate_extension_level(
    const EvalContext &context,
    const SealBackend::ExtCiphertext &ciphertext,
    const char *operation) {
    const Ciphertext *anchor = nullptr;
    for (const auto &coefficient : ciphertext) {
        if (!coefficient) {
            continue;
        }
        if (!context.context->get_context_data(
                coefficient->raw.parms_id())) {
            throw std::invalid_argument(
                std::string(operation) +
                ": extension coefficient has unknown parameters");
        }
        if (anchor != nullptr &&
            anchor->raw.parms_id() != coefficient->raw.parms_id()) {
            throw std::invalid_argument(
                std::string(operation) +
                ": extension coefficients have different RNS levels");
        }
        anchor = anchor == nullptr ? &*coefficient : anchor;
    }
    return anchor;
}

const Ciphertext *validate_extension_pair(
    const EvalContext &context,
    const SealBackend::ExtCiphertext &left,
    const SealBackend::ExtCiphertext &right,
    const char *operation) {
    const Ciphertext *left_anchor =
        validate_extension_level(context, left, operation);
    const Ciphertext *right_anchor =
        validate_extension_level(context, right, operation);
    if (left_anchor != nullptr && right_anchor != nullptr &&
        left_anchor->raw.parms_id() != right_anchor->raw.parms_id()) {
        throw std::invalid_argument(
            std::string(operation) +
            ": extension operands have different RNS levels");
    }
    return left_anchor != nullptr ? left_anchor : right_anchor;
}

void accumulate_ciphertext_coordinate(
    const EvalContext &context, std::optional<Ciphertext> &destination,
    Ciphertext term, const char *operation) {
    if (!destination) {
        destination.emplace(std::move(term));
        return;
    }
    const auto public_result = SealBackend::add_assign_or_public(
        context, *destination, term);
    if (!public_result) {
        return;
    }
    if (!is_zero_plaintext(*public_result)) {
        throw std::logic_error(
            std::string(operation) +
            ": encrypted terms resolved to a public nonzero plaintext");
    }
    destination.reset();
}

} // namespace laminate::fhe::seal_detail

namespace laminate::fhe {

using namespace seal_detail;

// --------------------------------------------------------------------------
// Client boundary: encrypt inputs and decrypt verified outputs.
// --------------------------------------------------------------------------

SealBackend::Ciphertext
SealBackend::encrypt(const ClientContext &context, const SlotVector &slots) {
    const seal::Plaintext plaintext =
        encode_slots(context.encoder, slots, "SealBackend::encrypt");
    Ciphertext result;
    context.encryptor->encrypt(plaintext, result.raw);
    if (result.raw.is_transparent()) {
        throw std::logic_error(
            "SealBackend::encrypt: ordinary public-key encryption returned "
            "a transparent ciphertext");
    }
    set_fresh_bound(context, result, plaintext_radius());
    record(context.counters, OperationKind::Encrypt,
           result.raw.coeff_modulus_size());
    return result;
}

SlotVector SealBackend::decrypt(const ClientContext &context,
                                const Ciphertext &ciphertext) {
    record(context.counters, OperationKind::Decrypt,
           ciphertext.raw.coeff_modulus_size());
    seal::Plaintext plaintext;
    context.decryptor->decrypt(ciphertext.raw, plaintext);
    std::vector<std::uint64_t> values;
    context.encoder->decode(plaintext, values);
    SlotVector result;
    result.reserve(values.size());
    for (std::uint64_t value : values) {
        result.emplace_back(value);
    }
    return result;
}

// --------------------------------------------------------------------------
// Base-ciphertext linear arithmetic.
//
// Addition and subtraction first align both operands to the lower RNS level.
// The `*_or_public` forms are the internal escape hatch for cancellation:
// known-zero results return as plaintext instead of becoming encrypted zeros.
// --------------------------------------------------------------------------

SealBackend::Ciphertext
SealBackend::negate(const EvalContext &context,
                    const Ciphertext &ciphertext) {
    Ciphertext result = ciphertext;
    if (const auto *bound = tracked_bound(context, ciphertext)) {
        result.deterministic_noise_bound = bound_negation(*bound);
    }
    try {
        record(context, OperationKind::Negate, result);
        context.evaluator->negate_inplace(result.raw);
    } catch (const std::logic_error &error) {
        if (result.raw.is_transparent()) {
            reject_transparent_result("SealBackend::negate");
        }
        rethrow("SealBackend::negate", error);
    }
    if (result.raw.is_transparent()) {
        reject_transparent_result("SealBackend::negate");
    }
    return result;
}

SealBackend::Ciphertext SealBackend::add(const EvalContext &context,
                                         const Ciphertext &left,
                                         const Ciphertext &right) {
    Ciphertext result = left;
    add_assign(context, result, right);
    return result;
}

void SealBackend::add_assign(const EvalContext &context,
                             Ciphertext &accumulator,
                             const Ciphertext &term) {
    if (add_assign_or_public(context, accumulator, term)) {
        reject_transparent_result("SealBackend::add");
    }
}

std::optional<SlotVector> SealBackend::add_assign_or_public(
    const EvalContext &context, Ciphertext &accumulator,
    const Ciphertext &term) {
    // SEAL's low-level aliasing contract is intentionally not exposed here.
    // Doubling is uncommon in accumulation loops, so preserve it safely with
    // one copy while keeping the ordinary same-level path allocation-free.
    if (std::addressof(accumulator) == std::addressof(term)) {
        const Ciphertext term_copy = term;
        return add_at_same_level_inplace_or_public(
            context, accumulator, term_copy);
    }

    std::size_t accumulator_level = chain_index(context, accumulator);
    const std::size_t term_level = chain_index(context, term);
    while (accumulator_level > term_level) {
        mod_switch_to_next(context, accumulator);
        --accumulator_level;
    }
    if (term_level > accumulator_level) {
        Ciphertext aligned_term = term;
        std::size_t aligned_term_level = term_level;
        while (aligned_term_level > accumulator_level) {
            mod_switch_to_next(context, aligned_term);
            --aligned_term_level;
        }
        return add_at_same_level_inplace_or_public(
            context, accumulator, aligned_term);
    }
    return add_at_same_level_inplace_or_public(
        context, accumulator, term);
}

bool SealBackend::same_ciphertext(const EvalContext &context,
                                  const Ciphertext &left,
                                  const Ciphertext &right) {
    (void)chain_index(context, left);
    (void)chain_index(context, right);
    return same_raw_ciphertext(left, right);
}

std::optional<SlotVector> SealBackend::sub_assign_or_public(
    const EvalContext &context, Ciphertext &accumulator,
    const Ciphertext &term) {
    if (std::addressof(accumulator) == std::addressof(term)) {
        return SlotVector(context.encoder->slot_count(), Fp::zero());
    }
    std::size_t accumulator_level = chain_index(context, accumulator);
    const std::size_t term_level = chain_index(context, term);
    while (accumulator_level > term_level) {
        mod_switch_to_next(context, accumulator);
        --accumulator_level;
    }
    if (term_level > accumulator_level) {
        Ciphertext aligned_term = term;
        std::size_t aligned_term_level = term_level;
        while (aligned_term_level > accumulator_level) {
            mod_switch_to_next(context, aligned_term);
            --aligned_term_level;
        }
        return subtract_at_same_level_inplace_or_public(
            context, accumulator, aligned_term);
    }
    return subtract_at_same_level_inplace_or_public(
        context, accumulator, term);
}

SealBackend::Ciphertext SealBackend::sub(const EvalContext &context,
                                         const Ciphertext &left,
                                         const Ciphertext &right) {
    if (left.raw.parms_id() == right.raw.parms_id()) {
        return subtract_at_same_level(context, left, right);
    }

    Ciphertext aligned_left = left;
    Ciphertext aligned_right = right;
    align_levels(context, aligned_left, aligned_right);
    return subtract_at_same_level(context, aligned_left, aligned_right);
}

// --------------------------------------------------------------------------
// Base-ciphertext multiplication and key switching.
//
// `mul_no_relin` is exposed because extension multiplication accumulates the
// degree-two products before paying for relinearization once per coordinate.
// The ordinary `mul` operation performs both steps.
// --------------------------------------------------------------------------

SealBackend::Ciphertext SealBackend::mul_no_relin(
    const EvalContext &context, const Ciphertext &left,
    const Ciphertext &right) {
    if (left.raw.size() != 2 || right.raw.size() != 2) {
        throw std::invalid_argument(
            "SealBackend::mul_no_relin: inputs must be relinearized");
    }
    if (left.raw.parms_id() == right.raw.parms_id()) {
        return multiply_at_same_level_without_relinearizing(
            context, left, right);
    }

    Ciphertext aligned_left = left;
    Ciphertext aligned_right = right;
    align_levels(context, aligned_left, aligned_right);
    return multiply_at_same_level_without_relinearizing(
        context, aligned_left, aligned_right);
}

void SealBackend::relinearize(const EvalContext &context,
                              Ciphertext &ciphertext) {
    if (ciphertext.raw.size() <= 2) {
        throw std::invalid_argument(
            "SealBackend::relinearize: ciphertext is already relinearized");
    }
    std::optional<DeterministicNoiseBound> output_bound;
    if (const auto *bound = tracked_bound(context, ciphertext)) {
        output_bound = bound_key_switch(
            deterministic_noise_policy(context), *bound,
            data_moduli(context, ciphertext), special_modulus(context),
            DeterministicNoiseOperation::Relinearization);
    }
    try {
        record(context, OperationKind::Relinearize, ciphertext);
        context.evaluator->relinearize_inplace(ciphertext.raw,
                                               *context.relin_keys);
    } catch (const std::logic_error &error) {
        rethrow("SealBackend::relinearize", error);
    }
    ciphertext.deterministic_noise_bound = std::move(output_bound);
    ciphertext.noise_loss_bits = saturated_add(
        ciphertext.noise_loss_bits, kRelinearizationNoiseBits);
}

SealBackend::Ciphertext SealBackend::mul(const EvalContext &context,
                                         const Ciphertext &left,
                                         const Ciphertext &right) {
    Ciphertext result = mul_no_relin(context, left, right);
    relinearize(context, result);
    return result;
}

// --------------------------------------------------------------------------
// Slot movement. A logical rotation may require a row rotation, a row swap,
// or both. `fold` sums all rotations and is used to collapse SIMD slots.
// --------------------------------------------------------------------------

SealBackend::Ciphertext
SealBackend::rotate(const EvalContext &context,
                    const Ciphertext &ciphertext, std::size_t steps) {
    const std::size_t width = slot_count(context);
    const std::size_t reduced = steps % width;
    const std::size_t half = width / 2;
    Ciphertext result = ciphertext;
    std::size_t primitive_rotations = 0;
    if (reduced % half != 0) {
        if (const auto *bound = tracked_bound(context, result)) {
            result.deterministic_noise_bound = bound_key_switch(
                deterministic_noise_policy(context), *bound,
                data_moduli(context, result), special_modulus(context),
                DeterministicNoiseOperation::Rotation);
        }
        try {
            record(context, OperationKind::Rotate, result);
            context.evaluator->rotate_rows_inplace(
                result.raw, static_cast<int>(reduced % half),
                *context.galois_keys);
            ++primitive_rotations;
        } catch (const std::logic_error &error) {
            rethrow("SealBackend::rotate_rows", error);
        }
    }
    if (reduced >= half) {
        if (const auto *bound = tracked_bound(context, result)) {
            result.deterministic_noise_bound = bound_key_switch(
                deterministic_noise_policy(context), *bound,
                data_moduli(context, result), special_modulus(context),
                DeterministicNoiseOperation::Rotation);
        }
        try {
            record(context, OperationKind::Rotate, result);
            context.evaluator->rotate_columns_inplace(result.raw,
                                                      *context.galois_keys);
            ++primitive_rotations;
        } catch (const std::logic_error &error) {
            rethrow("SealBackend::rotate_columns", error);
        }
    }
    result.noise_loss_bits = saturated_add(
        result.noise_loss_bits,
        primitive_rotations * kRotationNoiseBits);
    return result;
}

SealBackend::Ciphertext
SealBackend::fold(const EvalContext &context,
                  const Ciphertext &ciphertext) {
    Ciphertext result = ciphertext;
    for (std::size_t shift = 1; shift < slot_count(context); shift *= 2) {
        Ciphertext rotated = rotate(context, result, shift);
        add_assign(context, result, rotated);
    }
    return result;
}

// --------------------------------------------------------------------------
// Degree-eight extension arithmetic.
//
// Each optional coordinate is either an encrypted base-field coefficient or
// a known public zero. Multiplication convolves the coordinates and reduces
// modulo x^8 + x^3 + 1. The caller then relinearizes the result.
// --------------------------------------------------------------------------

SealBackend::ExtCiphertext
SealBackend::ext_add(const EvalContext &context, const ExtCiphertext &left,
                     const ExtCiphertext &right) {
    ExtCiphertext result = left;
    ext_add_assign(context, result, right);
    return result;
}

void SealBackend::ext_add_assign(const EvalContext &context,
                                 ExtCiphertext &accumulator,
                                 const ExtCiphertext &term) {
    const Ciphertext *anchor = validate_extension_pair(
        context, accumulator, term, "SealBackend::ext_add_assign");
    if (anchor != nullptr) {
        record(context, OperationKind::LogicalExtAdd, *anchor);
    }
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if (!term[coefficient]) {
            continue;
        }
        if (accumulator[coefficient]) {
            if (auto public_result = add_assign_or_public(
                    context, *accumulator[coefficient],
                    *term[coefficient])) {
                if (!is_zero_plaintext(*public_result)) {
                    throw std::logic_error(
                        "SealBackend::ext_add_assign: encrypted terms "
                        "resolved to a public nonzero plaintext");
                }
                accumulator[coefficient].reset();
            }
        } else {
            accumulator[coefficient] = *term[coefficient];
        }
    }
}

void SealBackend::record_logical_extension_add(
    const EvalContext &context, const Ciphertext &encrypted_anchor) {
    (void)chain_index(context, encrypted_anchor);
    record(context, OperationKind::LogicalExtAdd, encrypted_anchor);
}

SealBackend::ExtCiphertext
SealBackend::ext_sub(const EvalContext &context, const ExtCiphertext &left,
                     const ExtCiphertext &right) {
    const Ciphertext *anchor = validate_extension_pair(
        context, left, right, "SealBackend::ext_sub");
    if (anchor != nullptr) {
        record(context, OperationKind::LogicalExtSub, *anchor);
    }
    ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if (left[coefficient] && right[coefficient]) {
            if (same_raw_ciphertext(*left[coefficient],
                                    *right[coefficient])) {
                continue;
            }
            result[coefficient] = sub(
                context, *left[coefficient], *right[coefficient]);
        } else if (left[coefficient]) {
            result[coefficient] = *left[coefficient];
        } else if (right[coefficient]) {
            result[coefficient] = negate(context, *right[coefficient]);
        }
    }
    return result;
}

void SealBackend::record_logical_extension_sub(
    const EvalContext &context, const Ciphertext &encrypted_anchor) {
    (void)chain_index(context, encrypted_anchor);
    record(context, OperationKind::LogicalExtSub, encrypted_anchor);
}

void SealBackend::record_logical_extension_mul_plain(
    const EvalContext &context, const Ciphertext &encrypted_anchor) {
    (void)chain_index(context, encrypted_anchor);
    record(context, OperationKind::LogicalExtMulPlain, encrypted_anchor);
}

SealBackend::ExtCiphertext SealBackend::ext_mul_no_relin(
    const EvalContext &context, const ExtCiphertext &left,
    const ExtCiphertext &right) {
    const Ciphertext *anchor = validate_extension_pair(
        context, left, right, "SealBackend::ext_mul_no_relin");
    if (anchor != nullptr) {
        record(context, OperationKind::LogicalExtMul, *anchor);
    }
    std::array<std::optional<Ciphertext>, 2 * kExtensionDegree - 1>
        coefficients{};
    for (std::size_t left_degree = 0;
         left_degree < kExtensionDegree; ++left_degree) {
        if (!left[left_degree]) {
            continue;
        }
        for (std::size_t right_degree = 0;
             right_degree < kExtensionDegree; ++right_degree) {
            if (!right[right_degree]) {
                continue;
            }
            Ciphertext term = mul_no_relin(
                context, *left[left_degree], *right[right_degree]);
            auto &destination =
                coefficients[left_degree + right_degree];
            accumulate_ciphertext_coordinate(
                context, destination, std::move(term),
                "SealBackend::ext_mul_no_relin");
        }
    }
    reduce_extension_polynomial(context, coefficients);

    ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        result[coefficient] = std::move(coefficients[coefficient]);
    }
    return result;
}

void SealBackend::ext_relinearize(const EvalContext &context,
                                  ExtCiphertext &ciphertext) {
    validate_extension_level(
        context, ciphertext, "SealBackend::ext_relinearize");
    for (auto &coefficient : ciphertext) {
        if (coefficient && coefficient->raw.size() > 2) {
            relinearize(context, *coefficient);
        }
    }
}

SealBackend::ExtCiphertext
SealBackend::ext_mul(const EvalContext &context, const ExtCiphertext &left,
                     const ExtCiphertext &right) {
    ExtCiphertext result = ext_mul_no_relin(context, left, right);
    ext_relinearize(context, result);
    return result;
}

// --------------------------------------------------------------------------
// RNS-chain movement. These are the only raw SEAL modulus-switch calls.
// --------------------------------------------------------------------------

void SealBackend::mod_switch_to_next(const EvalContext &context,
                                     Ciphertext &ciphertext) {
    if (chain_index(context, ciphertext) == 0) {
        throw std::invalid_argument(
            "SealBackend::mod_switch_to_next: already at the lowest level");
    }
    record(context, OperationKind::ModSwitch, ciphertext);
    std::optional<DeterministicNoiseBound> output_bound;
    if (const auto *bound = tracked_bound(context, ciphertext)) {
        output_bound = bound_modulus_switch(
            deterministic_noise_policy(context), *bound,
            ciphertext.raw.size(),
            data_moduli(context, ciphertext));
    }
    try {
        context.evaluator->mod_switch_to_next_inplace(ciphertext.raw);
        ciphertext.deterministic_noise_bound = std::move(output_bound);
    } catch (const std::logic_error &error) {
        if (ciphertext.raw.is_transparent()) {
            reject_transparent_result("SealBackend::mod_switch_to_next");
        }
        rethrow("SealBackend::mod_switch_to_next", error);
    }
    if (ciphertext.raw.is_transparent()) {
        reject_transparent_result("SealBackend::mod_switch_to_next");
    }
}

void SealBackend::mod_switch_to_lowest(const EvalContext &context,
                                       Ciphertext &ciphertext) {
    while (chain_index(context, ciphertext) != 0) {
        mod_switch_to_next(context, ciphertext);
    }
}

} // namespace laminate::fhe
