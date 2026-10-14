#ifndef LAMINATE_FHE_EXTENSION_VALUE_HPP
#define LAMINATE_FHE_EXTENSION_VALUE_HPP

/// @file extension_value.hpp
/// @brief Public-or-encrypted SIMD values over the GKR extension field.

#include "laminate/fhe/value.hpp"
#include "laminate/field/fpk.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::fhe {

/// One SIMD extension-field value in coefficient-transposed form.
///
/// Every coefficient is independently either canonical public plaintext or
/// ciphertext. This is deliberately distinct from `Backend::ExtCiphertext`:
/// an absent backend coefficient means public zero only, whereas proof
/// messages may also carry nonzero circuit-public values without encrypting
/// them.
template <FheBackend Backend> class ExtensionValue {
  public:
    using Coefficients = std::array<FheValue<Backend>, kExtensionDegree>;

    ExtensionValue() = default;

    explicit ExtensionValue(const typename Backend::ExtCiphertext &value) {
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            if (value[coefficient]) {
                coefficients_[coefficient] =
                    FheValue<Backend>::from_ciphertext(
                        *value[coefficient]);
            }
        }
    }

    explicit ExtensionValue(typename Backend::ExtCiphertext &&value) {
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            if (value[coefficient]) {
                coefficients_[coefficient] =
                    FheValue<Backend>::from_ciphertext(
                        std::move(*value[coefficient]));
            }
        }
    }

    static ExtensionValue public_scalar(const Fpk &value) {
        ExtensionValue result;
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            result[coefficient] = FheValue<Backend>::public_scalar(
                value.coefficients()[coefficient]);
        }
        return result;
    }

    static ExtensionValue public_slots(std::span<const Fpk> values) {
        if (values.empty()) {
            throw std::invalid_argument(
                "ExtensionValue::public_slots: values must not be empty");
        }
        ExtensionValue result;
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            SlotVector slots;
            slots.reserve(values.size());
            for (const Fpk &value : values) {
                slots.push_back(value.coefficients()[coefficient]);
            }
            result[coefficient] = FheValue<Backend>::public_slots(
                std::move(slots));
        }
        return result;
    }

    FheValue<Backend> &operator[](std::size_t coefficient) {
        return coefficients_.at(coefficient);
    }
    const FheValue<Backend> &operator[](std::size_t coefficient) const {
        return coefficients_.at(coefficient);
    }

    auto begin() noexcept { return coefficients_.begin(); }
    auto end() noexcept { return coefficients_.end(); }
    auto begin() const noexcept { return coefficients_.begin(); }
    auto end() const noexcept { return coefficients_.end(); }

    bool is_public() const {
        return std::all_of(
            coefficients_.begin(), coefficients_.end(),
            [](const auto &coefficient) { return coefficient.is_public(); });
    }

    bool is_public_zero() const {
        return std::all_of(coefficients_.begin(), coefficients_.end(),
                           [](const auto &coefficient) {
                               return coefficient.is_public_zero();
                           });
    }

    bool has_public_nonzero() const {
        return std::any_of(coefficients_.begin(), coefficients_.end(),
                           [](const auto &coefficient) {
                               return coefficient.is_public() &&
                                      !coefficient.is_public_zero();
                           });
    }

    std::size_t ciphertext_count() const {
        return static_cast<std::size_t>(std::count_if(
            coefficients_.begin(), coefficients_.end(),
            [](const auto &coefficient) {
                return coefficient.is_encrypted();
            }));
    }

    /// Project onto the encrypted coordinates. This is for mixed algorithms
    /// that separately preserve and process `public_extension_part`; callers
    /// must not treat the result as the complete semantic value.
    typename Backend::ExtCiphertext encrypted_projection() const {
        typename Backend::ExtCiphertext result{};
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            if (coefficients_[coefficient].is_encrypted()) {
                result[coefficient] =
                    coefficients_[coefficient].ciphertext();
            }
        }
        return result;
    }

    /// Project a ciphertext/public-zero value to the backend's sparse
    /// ciphertext form. Rejecting public nonzeros prevents an apparently total
    /// conversion from silently changing the semantic value.
    typename Backend::ExtCiphertext encrypted_part() const {
        if (has_public_nonzero()) {
            throw std::invalid_argument(
                "ExtensionValue::encrypted_part cannot discard nonzero "
                "public coordinates");
        }
        return encrypted_projection();
    }

    Coefficients &coefficients() noexcept { return coefficients_; }
    const Coefficients &coefficients() const noexcept {
        return coefficients_;
    }

  private:
    Coefficients coefficients_{};
};

namespace extension_value_detail {

template <FheBackend Backend>
const typename Backend::Ciphertext *first_encrypted_coordinate(
    const ExtensionValue<Backend> &value) {
    for (const FheValue<Backend> &coefficient : value) {
        if (coefficient.is_encrypted()) {
            return &coefficient.ciphertext();
        }
    }
    return nullptr;
}

template <FheBackend Backend>
const typename Backend::Ciphertext *first_encrypted_coordinate(
    const ExtensionValue<Backend> &left,
    const ExtensionValue<Backend> &right) {
    if (const auto *anchor =
            first_encrypted_coordinate<Backend>(left)) {
        return anchor;
    }
    return first_encrypted_coordinate<Backend>(right);
}

template <FheBackend Backend>
void record_add(const typename Backend::EvalContext &eval,
                const ExtensionValue<Backend> &left,
                const ExtensionValue<Backend> &right) {
    if (const auto *anchor =
            first_encrypted_coordinate<Backend>(left, right)) {
        record_logical_extension_add<Backend>(eval, *anchor);
    }
}

template <FheBackend Backend>
void record_sub(const typename Backend::EvalContext &eval,
                const ExtensionValue<Backend> &left,
                const ExtensionValue<Backend> &right) {
    if (const auto *anchor =
            first_encrypted_coordinate<Backend>(left, right)) {
        record_logical_extension_sub<Backend>(eval, *anchor);
    }
}

} // namespace extension_value_detail

template <FheBackend Backend>
ExtensionValue<Backend> extension_add(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &left,
    const ExtensionValue<Backend> &right) {
    if (left.is_public_zero()) {
        return right;
    }
    if (right.is_public_zero()) {
        return left;
    }
    extension_value_detail::record_add<Backend>(eval, left, right);
    ExtensionValue<Backend> result;
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        result[coefficient] = value_add<Backend>(
            eval, left[coefficient], right[coefficient]);
    }
    return result;
}

template <FheBackend Backend>
void extension_add_assign(const typename Backend::EvalContext &eval,
                          ExtensionValue<Backend> &accumulator,
                          const ExtensionValue<Backend> &term) {
    if (term.is_public_zero()) {
        return;
    }
    if (accumulator.is_public_zero()) {
        accumulator = term;
        return;
    }
    extension_value_detail::record_add<Backend>(eval, accumulator, term);
    // Work coefficientwise even when both operands currently look fully
    // encrypted. Related ciphertexts can cancel to a public nonzero value;
    // the backend's sparse ciphertext-only extension cannot represent that
    // transition, while FheValue can.
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        value_add_assign<Backend>(eval, accumulator[coefficient],
                                  term[coefficient]);
    }
}

/// Rvalue counterpart of `extension_add_assign`. A newly computed first term
/// becomes the accumulator by ownership transfer instead of copying as many
/// as `kExtensionDegree` ciphertexts.
template <FheBackend Backend>
void extension_add_assign(const typename Backend::EvalContext &eval,
                          ExtensionValue<Backend> &accumulator,
                          ExtensionValue<Backend> &&term) {
    if (&accumulator == &term || !accumulator.is_public_zero()) {
        extension_add_assign<Backend>(
            eval, accumulator,
            static_cast<const ExtensionValue<Backend> &>(term));
        return;
    }
    accumulator = std::move(term);
}

template <FheBackend Backend>
ExtensionValue<Backend> extension_sub(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &left,
    const ExtensionValue<Backend> &right) {
    if (right.is_public_zero()) {
        return left;
    }
    extension_value_detail::record_sub<Backend>(eval, left, right);
    ExtensionValue<Backend> result;
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        result[coefficient] = value_sub<Backend>(
            eval, left[coefficient], right[coefficient]);
    }
    return result;
}

namespace extension_value_detail {

template <FheBackend Backend>
FheValue<Backend> multiply_without_relinearization(
    const typename Backend::EvalContext &eval,
    const FheValue<Backend> &left, const FheValue<Backend> &right) {
    return value_mul_no_relin<Backend>(eval, left, right);
}

template <FheBackend Backend>
FheValue<Backend> multiply_by_public_scalar(
    const typename Backend::EvalContext &eval,
    const FheValue<Backend> &value, const Fp &scalar) {
    if (scalar.is_zero() || value.is_public_zero()) {
        return FheValue<Backend>::public_zero();
    }
    if (scalar == Fp::one()) {
        return value;
    }
    return value_mul<Backend>(
        eval, value, FheValue<Backend>::public_scalar(scalar));
}

template <FheBackend Backend>
ExtensionValue<Backend> public_part(
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

inline bool all_zero(std::span<const Fpk> values) {
    return std::all_of(values.begin(), values.end(),
                       [](const Fpk &value) {
                           return value.is_zero();
                       });
}

inline bool all_zero(std::span<const Fp> values) {
    return std::all_of(values.begin(), values.end(),
                       [](const Fp &value) {
                           return value.is_zero();
                       });
}

inline bool is_base_field_scalar(const Fpk &value) {
    return std::all_of(
        std::next(value.coefficients().begin()),
        value.coefficients().end(),
        [](const Fp &coefficient) { return coefficient.is_zero(); });
}

inline bool is_base_field_vector(std::span<const Fpk> values) {
    return std::all_of(
        values.begin(), values.end(),
        [](const Fpk &value) { return is_base_field_scalar(value); });
}

/// Raw sparse extension multiplication cannot represent a public nonzero
/// created when related encrypted terms cancel. Even one encrypted input
/// coordinate can reach a reduced output coordinate along two paths. The raw
/// path is therefore safe only for base-field multipliers, which never mix
/// extension coordinates, and for symbolic bound-only evaluation.
template <FheBackend Backend>
bool raw_public_multiplication_is_safe(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &value, bool base_field_multiplier) {
    (void)value;
    return forces_challenge_independent_topology<Backend>(eval) ||
           base_field_multiplier;
}

template <FheBackend Backend>
void record_public_multiplication(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &value) {
    if (const auto *anchor = first_encrypted_coordinate<Backend>(value)) {
        record_logical_extension_mul_plain<Backend>(eval, *anchor);
    }
}

} // namespace extension_value_detail

/// Multiply two extension values, leaving CT--CT products unrelinearized.
/// The caller can combine several such terms and relinearize once at the end.
template <FheBackend Backend>
ExtensionValue<Backend> extension_mul_no_relin(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &left,
    const ExtensionValue<Backend> &right) {
    std::array<FheValue<Backend>, 2 * kExtensionDegree - 1>
        coefficients{};
    for (std::size_t left_coefficient = 0;
         left_coefficient < kExtensionDegree; ++left_coefficient) {
        if (left[left_coefficient].is_public_zero()) {
            continue;
        }
        for (std::size_t right_coefficient = 0;
             right_coefficient < kExtensionDegree; ++right_coefficient) {
            if (right[right_coefficient].is_public_zero()) {
                continue;
            }
            value_add_assign<Backend>(
                eval, coefficients[left_coefficient + right_coefficient],
                extension_value_detail::multiply_without_relinearization<
                    Backend>(eval, left[left_coefficient],
                             right[right_coefficient]));
        }
    }

    // Reduce the convolution modulo x^R + x^3 + 1. Accumulating each high
    // coefficient before reducing it is important: it matches the backend
    // extension kernels and avoids one negation per individual product.
    for (std::size_t degree = coefficients.size();
         degree-- > kExtensionDegree;) {
        if (coefficients[degree].is_public_zero()) {
            continue;
        }
        const FheValue<Backend> negative =
            value_negate<Backend>(eval, coefficients[degree]);
        value_add_assign<Backend>(
            eval, coefficients[degree - kExtensionDegree],
            negative);
        value_add_assign<Backend>(
            eval, coefficients[degree - kExtensionDegree + 3],
            negative);
    }

    ExtensionValue<Backend> result;
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        result[coefficient] = std::move(coefficients[coefficient]);
    }
    return result;
}

template <FheBackend Backend>
void relinearize_extension_value(
    const typename Backend::EvalContext &eval,
    ExtensionValue<Backend> &value) {
    typename Backend::ExtCiphertext encrypted =
        value.encrypted_projection();
    Backend::ext_relinearize(eval, encrypted);
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        if (encrypted[coefficient]) {
            value[coefficient] = FheValue<Backend>::from_ciphertext(
                std::move(*encrypted[coefficient]));
        }
    }
}

/// Multiply a base value by one public extension-field scalar.
template <FheBackend Backend>
ExtensionValue<Backend> promote_extension_value(
    const typename Backend::EvalContext &eval,
    const FheValue<Backend> &base, const Fpk &weight) {
    ExtensionValue<Backend> result;
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        result[coefficient] =
            extension_value_detail::multiply_by_public_scalar<Backend>(
                eval, base, weight.coefficients()[coefficient]);
    }
    return result;
}

/// Multiply an extension value by one public extension scalar.
template <FheBackend Backend>
ExtensionValue<Backend> scale_extension_value(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &value, const Fpk &weight) {
    const bool retain_zero_terms =
        forces_challenge_independent_topology<Backend>(eval);
    if (weight.is_zero() && !retain_zero_terms) {
        return {};
    }
    if (value.ciphertext_count() != 0 &&
        !extension_value_detail::raw_public_multiplication_is_safe<Backend>(
            eval, value,
            extension_value_detail::is_base_field_scalar(weight))) {
        extension_value_detail::record_public_multiplication<Backend>(
            eval, value);
        return extension_mul_no_relin<Backend>(
            eval, value, ExtensionValue<Backend>::public_scalar(weight));
    }
    ExtensionValue<Backend> result;
    if (value.ciphertext_count() != 0) {
        PlainExtensionScalar plaintext = weight.coefficients();
        if (retain_zero_terms) {
            for (Fp &coefficient : plaintext) {
                if (coefficient.is_zero()) {
                    coefficient = Fp::one();
                }
            }
        }
        result = ExtensionValue<Backend>(Backend::ext_mul_plain_scalar(
            eval, value.encrypted_projection(), plaintext));
    }
    const ExtensionValue<Backend> public_value =
        extension_value_detail::public_part<Backend>(value);
    if (!public_value.is_public_zero()) {
        extension_add_assign<Backend>(
            eval, result,
            extension_mul_no_relin<Backend>(
                eval, public_value,
                ExtensionValue<Backend>::public_scalar(weight)));
    }
    return result;
}

/// Multiply an extension value by one public extension value per SIMD slot.
template <FheBackend Backend>
ExtensionValue<Backend> scale_extension_value(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &value,
    std::span<const Fpk> weights) {
    if (weights.size() != Backend::slot_count(eval)) {
        throw std::invalid_argument(
            "scale_extension_value: wrong slot count");
    }
    const bool retain_zero_terms =
        forces_challenge_independent_topology<Backend>(eval);
    if (extension_value_detail::all_zero(weights) && !retain_zero_terms) {
        return {};
    }
    if (value.ciphertext_count() != 0 &&
        !extension_value_detail::raw_public_multiplication_is_safe<Backend>(
            eval, value,
            extension_value_detail::is_base_field_vector(weights))) {
        extension_value_detail::record_public_multiplication<Backend>(
            eval, value);
        return extension_mul_no_relin<Backend>(
            eval, value, ExtensionValue<Backend>::public_slots(weights));
    }
    ExtensionValue<Backend> result;
    if (value.ciphertext_count() != 0) {
        PlainExtension plaintext{};
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            plaintext[coefficient].reserve(weights.size());
            for (const Fpk &weight : weights) {
                plaintext[coefficient].push_back(
                    weight.coefficients()[coefficient]);
            }
            if (retain_zero_terms &&
                extension_value_detail::all_zero(
                    std::span<const Fp>(plaintext[coefficient]))) {
                plaintext[coefficient].front() = Fp::one();
            }
        }
        result = ExtensionValue<Backend>(Backend::ext_mul_plain(
            eval, value.encrypted_projection(), plaintext));
    }
    const ExtensionValue<Backend> public_value =
        extension_value_detail::public_part<Backend>(value);
    if (!public_value.is_public_zero()) {
        extension_add_assign<Backend>(
            eval, result,
            extension_mul_no_relin<Backend>(
                eval, public_value,
                ExtensionValue<Backend>::public_slots(weights)));
    }
    return result;
}

/// Multiply a base value by one public extension-field value per SIMD slot.
template <FheBackend Backend>
ExtensionValue<Backend> promote_extension_value(
    const typename Backend::EvalContext &eval,
    const FheValue<Backend> &base, std::span<const Fpk> weights) {
    if (weights.size() != Backend::slot_count(eval)) {
        throw std::invalid_argument(
            "promote_extension_value: wrong slot count");
    }
    ExtensionValue<Backend> result;
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        SlotVector scalar_slots;
        scalar_slots.reserve(weights.size());
        for (const Fpk &weight : weights) {
            scalar_slots.push_back(weight.coefficients()[coefficient]);
        }
        result[coefficient] = value_mul<Backend>(
            eval, base,
            FheValue<Backend>::public_slots(std::move(scalar_slots)));
    }
    return result;
}

template <FheBackend Backend>
std::vector<Fpk> read_extension_value(
    const typename Backend::ClientContext &client,
    const ExtensionValue<Backend> &value) {
    const std::size_t slots = Backend::slot_count(client);
    std::array<SlotVector, kExtensionDegree> coefficients;
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        if (value[coefficient].is_public()) {
            coefficients[coefficient] =
                value[coefficient].plaintext().materialize(slots);
        } else {
            coefficients[coefficient] = Backend::decrypt(
                client, value[coefficient].ciphertext());
            if (coefficients[coefficient].size() != slots) {
                throw std::invalid_argument(
                    "read_extension_value: backend returned wrong slot "
                    "count");
            }
        }
    }
    std::vector<Fpk> result(slots);
    for (std::size_t slot = 0; slot < slots; ++slot) {
        Fpk::Coefficients scalar{};
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            scalar[coefficient] = coefficients[coefficient][slot];
        }
        result[slot] = Fpk(scalar);
    }
    return result;
}

} // namespace laminate::fhe

#endif // LAMINATE_FHE_EXTENSION_VALUE_HPP
