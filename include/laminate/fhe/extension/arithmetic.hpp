#ifndef LAMINATE_FHE_EXTENSION_ARITHMETIC_HPP
#define LAMINATE_FHE_EXTENSION_ARITHMETIC_HPP

/// @file arithmetic.hpp
/// @brief Arithmetic for sparse ciphertext and mixed extension values.

#include "laminate/fhe/extension/prepared_basis.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>

namespace laminate::fhe {

template <FheBackend Backend>
ExtensionValue<Backend> public_extension_part(
    const ExtensionValue<Backend> &value) {
    ExtensionValue<Backend> result;
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        if (value[coefficient].is_public()) {
            result[coefficient] = value[coefficient];
        }
    }
    return result;
}

/// Mixed extension multiplication with the established backend fast path for
/// the encrypted-by-encrypted component. This keeps Base's all-private target
/// operation topology unchanged while adding public cross terms analytically.
template <FheBackend Backend>
ExtensionValue<Backend> mixed_extension_mul_no_relin(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &left,
    const ExtensionValue<Backend> &right) {
    const typename Backend::ExtCiphertext left_encrypted =
        left.encrypted_projection();
    const typename Backend::ExtCiphertext right_encrypted =
        right.encrypted_projection();
    ExtensionValue<Backend> result;
    const bool has_left_encrypted = left.ciphertext_count() != 0;
    const bool has_right_encrypted = right.ciphertext_count() != 0;
    if (has_left_encrypted && has_right_encrypted) {
        result = ExtensionValue<Backend>(Backend::ext_mul_no_relin(
            eval, left_encrypted, right_encrypted));
    }

    const ExtensionValue<Backend> left_public =
        public_extension_part<Backend>(left);
    const ExtensionValue<Backend> right_public =
        public_extension_part<Backend>(right);
    if (!left_public.is_public_zero()) {
        extension_add_assign<Backend>(
            eval, result,
            extension_mul_no_relin<Backend>(eval, left_public, right));
    }
    if (has_left_encrypted && !right_public.is_public_zero()) {
        extension_add_assign<Backend>(
            eval, result,
            extension_mul_no_relin<Backend>(
                eval, ExtensionValue<Backend>(left_encrypted),
                right_public));
    }
    return result;
}

template <FheBackend Backend>
ExtensionValue<Backend> mixed_extension_mul_base_no_relin(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &extension,
    const FheValue<Backend> &base) {
    if (!extension.has_public_nonzero() && base.is_encrypted()) {
        typename Backend::ExtCiphertext product{};
        const typename Backend::ExtCiphertext encrypted =
            extension.encrypted_projection();
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            if (encrypted[coefficient]) {
                product[coefficient] = Backend::mul_no_relin(
                    eval, *encrypted[coefficient], base.ciphertext());
            }
        }
        return ExtensionValue<Backend>(std::move(product));
    }
    ExtensionValue<Backend> promoted;
    promoted[0] = base;
    return mixed_extension_mul_no_relin<Backend>(eval, extension,
                                                  promoted);
}

template <FheBackend Backend>
typename Backend::ExtCiphertext
rotate_extension(const typename Backend::EvalContext &eval,
                 const typename Backend::ExtCiphertext &ciphertext,
                 std::size_t steps) {
    typename Backend::ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if (ciphertext[coefficient]) {
            result[coefficient] = Backend::rotate(
                eval, *ciphertext[coefficient], steps);
        }
    }
    return result;
}

/// Return `2 * at_one - at_zero`, coefficientwise. Slot-round callers first
/// rotate the one-branch so sibling slots are aligned with the zero-branch.
template <FheBackend Backend>
typename Backend::ExtCiphertext extrapolate_extension_at_two(
    const typename Backend::EvalContext &eval,
    const typename Backend::ExtCiphertext &at_zero,
    const typename Backend::ExtCiphertext &at_one) {
    return Backend::ext_sub(eval,
                            Backend::ext_add(eval, at_one, at_one),
                            at_zero);
}

/// Embed a base ciphertext as a constant extension polynomial without moving
/// it back to the top of the modulus chain.
template <FheBackend Backend>
typename Backend::ExtCiphertext
promote_base(const typename Backend::EvalContext &eval,
             const typename Backend::Ciphertext &ciphertext) {
    (void)eval;
    typename Backend::ExtCiphertext result{};
    result[0] = ciphertext;
    return result;
}

/// Promotion by a slot-varying extension plaintext. Limb `i` encrypts
/// `base[slot] * weights[slot][i]`.
template <FheBackend Backend>
typename Backend::ExtCiphertext promote_scale(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &ciphertext,
    std::span<const Fpk> weights) {
    if (weights.size() != Backend::slot_count(eval)) {
        throw std::invalid_argument(
            "promote_scale: expected one extension weight per slot");
    }
    const PlainExtension plaintext = encode_extension_plain(weights);
    const bool retain_zero_terms =
        forces_challenge_independent_topology<Backend>(eval);
    typename Backend::ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if (detail::all_zero(plaintext[coefficient]) &&
            !retain_zero_terms) {
            continue;
        }
        const SlotVector owned_plaintext =
            retain_zero_terms && detail::all_zero(plaintext[coefficient])
                ? detail::nonzero_vector_envelope(
                      plaintext[coefficient], Backend::slot_count(eval))
                : plaintext[coefficient];
        result[coefficient] =
            Backend::mul_plain(eval, ciphertext, owned_plaintext);
    }
    return result;
}

template <FheBackend Backend>
typename Backend::ExtCiphertext promote_scale(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &ciphertext, const Fpk &weight) {
    const bool retain_zero_terms =
        forces_challenge_independent_topology<Backend>(eval);
    typename Backend::ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        const Fp scalar = weight.coefficients()[coefficient];
        if (scalar.is_zero() && !retain_zero_terms) {
            continue;
        }
        result[coefficient] = Backend::mul_plain_scalar(
            eval, ciphertext,
            scalar.is_zero() && retain_zero_terms ? Fp::one() : scalar);
    }
    return result;
}

template <FheBackend Backend>
typename Backend::ExtCiphertext scale_extension(
    const typename Backend::EvalContext &eval,
    const typename Backend::ExtCiphertext &ciphertext,
    std::span<const Fpk> weights) {
    if (weights.size() != Backend::slot_count(eval)) {
        throw std::invalid_argument(
            "scale_extension: expected one extension weight per slot");
    }
    PlainExtension plaintext = encode_extension_plain(weights);
    if (forces_challenge_independent_topology<Backend>(eval)) {
        plaintext = detail::retain_vector_plaintext_topology(
            std::move(plaintext), Backend::slot_count(eval));
    }
    return Backend::ext_mul_plain(eval, ciphertext, plaintext);
}

template <FheBackend Backend>
typename Backend::ExtCiphertext scale_extension(
    const typename Backend::EvalContext &eval,
    const typename Backend::ExtCiphertext &ciphertext, const Fpk &weight) {
    PlainExtensionScalar plaintext = weight.coefficients();
    if (forces_challenge_independent_topology<Backend>(eval)) {
        plaintext = detail::retain_scalar_plaintext_topology(
            std::move(plaintext));
    }
    return Backend::ext_mul_plain_scalar(eval, ciphertext, plaintext);
}

template <FheBackend Backend>
ExtensionValue<Backend> mixed_scale_extension(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &value, const Fpk &weight) {
    ExtensionValue<Backend> result;
    if (value.ciphertext_count() != 0) {
        result = ExtensionValue<Backend>(scale_extension<Backend>(
            eval, value.encrypted_projection(), weight));
    }
    const ExtensionValue<Backend> public_part =
        public_extension_part<Backend>(value);
    if (!public_part.is_public_zero()) {
        extension_add_assign<Backend>(
            eval, result,
            scale_extension_value<Backend>(eval, public_part, weight));
    }
    return result;
}

template <FheBackend Backend>
ExtensionValue<Backend> rotate_extension_value(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &value, std::size_t steps) {
    ExtensionValue<Backend> result;
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        result[coefficient] = value_rotate<Backend>(
            eval, value[coefficient], steps);
    }
    return result;
}

template <FheBackend Backend>
void ext_add_assign(const typename Backend::EvalContext &eval,
                    ExtensionValue<Backend> &accumulator,
                    const ExtensionValue<Backend> &term) {
    extension_add_assign<Backend>(eval, accumulator, term);
}

template <FheBackend Backend>
ExtensionValue<Backend> rotate_extension(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &value, std::size_t steps) {
    return rotate_extension_value<Backend>(eval, value, steps);
}

template <FheBackend Backend>
ExtensionValue<Backend> extrapolate_extension_at_two(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &at_zero,
    const ExtensionValue<Backend> &at_one) {
    return extension_sub<Backend>(
        eval, extension_add<Backend>(eval, at_one, at_one), at_zero);
}

template <FheBackend Backend>
ExtensionValue<Backend> scale_extension(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &value, const Fpk &weight) {
    return scale_extension_value<Backend>(eval, value, weight);
}

template <FheBackend Backend>
ExtensionValue<Backend> scale_extension(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &value,
    std::span<const Fpk> weights) {
    return scale_extension_value<Backend>(eval, value, weights);
}

/// Multiply an extension ciphertext by an encrypted base-field batch. No
/// extension reduction is needed because the base operand has degree zero.
template <FheBackend Backend>
typename Backend::ExtCiphertext ext_mul_base_no_relin(
    const typename Backend::EvalContext &eval,
    const typename Backend::ExtCiphertext &extension,
    const typename Backend::Ciphertext &base) {
    typename Backend::ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if (extension[coefficient]) {
            result[coefficient] = Backend::mul_no_relin(
                eval, *extension[coefficient], base);
        }
    }
    return result;
}

template <FheBackend Backend>
ExtensionValue<Backend> extension_mul_base_no_relin(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &extension,
    const FheValue<Backend> &base) {
    ExtensionValue<Backend> result;
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        result[coefficient] = value_mul_no_relin<Backend>(
            eval, extension[coefficient], base);
    }
    return result;
}

} // namespace laminate::fhe

#endif // LAMINATE_FHE_EXTENSION_ARITHMETIC_HPP
