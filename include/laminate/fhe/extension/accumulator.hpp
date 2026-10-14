#ifndef LAMINATE_FHE_EXTENSION_ACCUMULATOR_HPP
#define LAMINATE_FHE_EXTENSION_ACCUMULATOR_HPP

/// @file accumulator.hpp
/// @brief Sparse and mixed public/ciphertext extension accumulators.

#include "laminate/fhe/extension/prepared_basis.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>

namespace laminate::fhe {

/// Move the first term into an optional extension accumulator, then add later
/// terms in place when the backend supports it. Keeping this backend-generic
/// avoids coupling Base, Folded, and Laned round kernels to one another.
template <FheBackend Backend>
void accumulate_extension(
    const typename Backend::EvalContext &eval,
    std::optional<typename Backend::ExtCiphertext> &accumulator,
    typename Backend::ExtCiphertext term) {
    if (accumulator) {
        ext_add_assign<Backend>(eval, *accumulator, term);
    } else {
        accumulator.emplace(std::move(term));
    }
}

namespace detail {

template <FheBackend Backend>
void add_extension_coordinates_unrecorded(
    const typename Backend::EvalContext &eval,
    ExtensionValue<Backend> &accumulator,
    const ExtensionValue<Backend> &term) {
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        value_add_assign<Backend>(eval, accumulator[coefficient],
                                  term[coefficient]);
    }
}

/// Multiply an extension value by x^shift modulo x^R + x^3 + 1. The
/// coefficientwise representation is essential here: a reduction can cancel
/// related ciphertexts to a public value that raw ExtCiphertext cannot carry.
template <FheBackend Backend>
ExtensionValue<Backend> multiply_by_extension_monomial(
    const typename Backend::EvalContext &eval,
    ExtensionValue<Backend> value, std::size_t shift) {
    if (shift >= kExtensionDegree) {
        throw std::invalid_argument(
            "multiply_by_extension_monomial: shift is outside the field");
    }
    if (shift == 0) {
        return value;
    }

    std::array<FheValue<Backend>, 2 * kExtensionDegree - 1>
        coefficients{};
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        coefficients[coefficient + shift] =
            std::move(value[coefficient]);
    }
    for (std::size_t degree = coefficients.size();
         degree-- > kExtensionDegree;) {
        if (coefficients[degree].is_public_zero()) {
            continue;
        }
        const FheValue<Backend> negative =
            value_negate<Backend>(eval, coefficients[degree]);
        value_add_assign<Backend>(
            eval, coefficients[degree - kExtensionDegree], negative);
        value_add_assign<Backend>(
            eval, coefficients[degree - kExtensionDegree + 3], negative);
    }

    ExtensionValue<Backend> result;
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        result[coefficient] = std::move(coefficients[coefficient]);
    }
    return result;
}

/// Prepared public multiplication with typed cross-coordinate accumulation.
/// Each encrypted input coordinate still uses the backend's immutable
/// prepared basis; only the extension convolution and reduction move to
/// FheValue so transparent public results remain representable.
template <FheBackend Backend>
ExtensionValue<Backend> scale_extension_prepared_public_aware(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &value,
    const PreparedFpkSlotBasis<Backend> &basis,
    std::span<const Fpk> public_basis) {
    if (basis.slot_count != Backend::slot_count(eval) ||
        public_basis.size() != Backend::slot_count(eval)) {
        throw std::invalid_argument(
            "scale_extension_prepared_public_aware: basis has the wrong "
            "slot count");
    }
    extension_value_detail::record_public_multiplication<Backend>(eval,
                                                                  value);

    ExtensionValue<Backend> result;
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        if (!value[coefficient].is_encrypted()) {
            continue;
        }
        typename Backend::ExtCiphertext raw_contribution =
            promote_plain_prepared_internal<Backend>(
                eval, value[coefficient].ciphertext(),
                basis.backend_basis);
        for (std::size_t basis_coefficient = 0;
             basis_coefficient < kExtensionDegree;
             ++basis_coefficient) {
            if ((basis.public_coordinate_support &
                 static_cast<std::uint8_t>(
                     std::uint8_t{1} << basis_coefficient)) == 0) {
                raw_contribution[basis_coefficient].reset();
            }
        }
        ExtensionValue<Backend> contribution(
            std::move(raw_contribution));
        contribution = multiply_by_extension_monomial<Backend>(
            eval, std::move(contribution), coefficient);
        add_extension_coordinates_unrecorded<Backend>(
            eval, result, contribution);
    }

    const ExtensionValue<Backend> public_value =
        extension_value_detail::public_part<Backend>(value);
    if (!public_value.is_public_zero()) {
        const ExtensionValue<Backend> public_product =
            extension_mul_no_relin<Backend>(
                eval, public_value,
                ExtensionValue<Backend>::public_slots(public_basis));
        add_extension_coordinates_unrecorded<Backend>(
            eval, result, public_product);
    }
    return result;
}

} // namespace detail

/// Coordinate-sparse extension value used while accumulating linear terms.
///
/// `Backend::ExtCiphertext` uses the same public-known-zero representation.
/// This mutable helper owns each coordinate's first term and applies later
/// additions in place.
template <FheBackend Backend> class SparseExtensionAccumulator {
  public:
    using Ciphertext = typename Backend::Ciphertext;
    using ExtCiphertext = typename Backend::ExtCiphertext;

    bool empty() const noexcept {
        return std::none_of(
            coefficients_.begin(), coefficients_.end(),
            [](const auto &coefficient) { return coefficient.has_value(); });
    }

    std::size_t active_coefficient_count() const noexcept {
        return static_cast<std::size_t>(std::count_if(
            coefficients_.begin(), coefficients_.end(),
            [](const auto &coefficient) { return coefficient.has_value(); }));
    }

    bool has_only_coefficient_zero() const noexcept {
        if (!coefficients_.front()) {
            return false;
        }
        return std::none_of(
            std::next(coefficients_.begin()), coefficients_.end(),
            [](const auto &coefficient) { return coefficient.has_value(); });
    }

    /// Add `source * scalar` without constructing encrypted zeros for absent
    /// extension coefficients. Bound-only backends retain their deliberately
    /// dense challenge-independent topology.
    void accumulate_scaled_base(
        const typename Backend::EvalContext &eval,
        const Ciphertext &source, const Fpk &scalar) {
        const bool retain_zero_terms =
            forces_challenge_independent_topology<Backend>(eval);
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            Fp weight = scalar.coefficients()[coefficient];
            if (weight.is_zero()) {
                if (!retain_zero_terms) {
                    continue;
                }
                weight = Fp::one();
            }
            if (weight == Fp::one() && !retain_zero_terms) {
                accumulate_coordinate(eval, coefficient, source);
                continue;
            }
            accumulate_owned_coordinate(
                eval, coefficient,
                Backend::mul_plain_scalar(eval, source, weight));
        }
    }

    /// Add `source * scalar` when every zero coefficient of `scalar` is fixed
    /// by public circuit geometry rather than by a transcript challenge.
    /// Such coordinates remain symbolic zeros even for bound-only backends.
    void accumulate_scaled_base_with_public_support(
        const typename Backend::EvalContext &eval,
        const Ciphertext &source, const Fpk &scalar) {
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            const Fp weight = scalar.coefficients()[coefficient];
            if (weight.is_zero()) {
                continue;
            }
            if (weight == Fp::one()) {
                accumulate_coordinate(eval, coefficient, source);
            } else {
                accumulate_owned_coordinate(
                    eval, coefficient,
                    Backend::mul_plain_scalar(eval, source, weight));
            }
        }
    }

    /// Add a base ciphertext multiplied by one extension value per SIMD slot.
    /// Only one base-field coefficient vector is live at a time, and an
    /// all-zero coefficient creates no ciphertext in ordinary execution.
    void accumulate_scaled_slots(
        const typename Backend::EvalContext &eval,
        const Ciphertext &source, std::span<const Fpk> weights) {
        const std::size_t slots = Backend::slot_count(eval);
        if (weights.size() != slots) {
            throw std::invalid_argument(
                "SparseExtensionAccumulator::accumulate_scaled_slots: "
                "expected one extension weight per slot");
        }
        const bool retain_zero_terms =
            forces_challenge_independent_topology<Backend>(eval);
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            SlotVector plaintext;
            plaintext.reserve(slots);
            for (const Fpk &weight : weights) {
                plaintext.push_back(weight.coefficients()[coefficient]);
            }
            if (detail::all_zero(plaintext)) {
                if (!retain_zero_terms) {
                    continue;
                }
                plaintext = detail::nonzero_vector_envelope(
                    plaintext, slots);
            }
            accumulate_owned_coordinate(
                eval, coefficient,
                Backend::mul_plain(eval, source, plaintext));
        }
    }

    /// Add an already represented extension term without changing the
    /// accumulator's sparse representation. Absent input coordinates remain
    /// public algebraic zeros.
    void accumulate_extension(
        const typename Backend::EvalContext &eval,
        ExtCiphertext term) {
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            if (term[coefficient]) {
                accumulate_owned_coordinate(
                    eval, coefficient,
                    std::move(*term[coefficient]));
            }
        }
    }

    /// Consume the accumulator. Missing coordinates remain symbolic zeros,
    /// and an empty accumulator is the canonical public-zero extension value.
    ExtCiphertext finish() && {
        return std::move(coefficients_);
    }

    /// Apply a prepared slot basis to the sparse value. A value supported
    /// only in extension coefficient zero is a base ciphertext, so the
    /// backend can promote it directly. Other known-zero coordinates remain
    /// absent, and an empty value stays empty.
    ExtCiphertext apply_prepared_basis(
        const typename Backend::EvalContext &eval,
        const PreparedFpkSlotBasis<Backend> &basis) && {
        if (has_only_coefficient_zero()) {
            return promote_scale_prepared<Backend>(
                eval, *coefficients_.front(), basis);
        }
        return scale_extension_prepared<Backend>(
            eval, std::move(coefficients_), basis);
    }

  private:
    void accumulate_coordinate(
        const typename Backend::EvalContext &eval,
        std::size_t coefficient, const Ciphertext &term) {
        auto &destination = coefficients_.at(coefficient);
        if (destination) {
            if (auto public_result = add_assign_or_public<Backend>(
                    eval, *destination, term)) {
                if (!detail::all_zero(*public_result)) {
                    throw std::logic_error(
                        "SparseExtensionAccumulator: encrypted terms "
                        "resolved to a public nonzero plaintext");
                }
                destination.reset();
            }
        } else {
            destination.emplace(term);
        }
    }

    void accumulate_owned_coordinate(
        const typename Backend::EvalContext &eval,
        std::size_t coefficient, Ciphertext term) {
        auto &destination = coefficients_.at(coefficient);
        if (destination) {
            if (auto public_result = add_assign_or_public<Backend>(
                    eval, *destination, term)) {
                if (!detail::all_zero(*public_result)) {
                    throw std::logic_error(
                        "SparseExtensionAccumulator: encrypted terms "
                        "resolved to a public nonzero plaintext");
                }
                destination.reset();
            }
        } else {
            destination.emplace(std::move(term));
        }
    }

    std::array<std::optional<Ciphertext>, kExtensionDegree> coefficients_{};
};

/// Streaming accumulator for extension values whose source may be public or
/// encrypted. The encrypted path delegates to the existing sparse backend
/// accumulator unchanged; public terms are combined with host-field
/// arithmetic and never acquire a ciphertext level anchor.
template <FheBackend Backend> class MixedExtensionAccumulator {
  public:
    bool empty() const noexcept { return value_.is_public_zero(); }

    bool has_encrypted() const noexcept {
        return value_.ciphertext_count() != 0;
    }

    bool has_only_coefficient_zero() const noexcept {
        if (value_[0].is_public_zero()) {
            return false;
        }
        return std::all_of(
            std::next(value_.begin()), value_.end(),
            [](const auto &coefficient) {
                return coefficient.is_public_zero();
            });
    }

    void accumulate_scaled_base(
        const typename Backend::EvalContext &eval,
        const FheValue<Backend> &source, const Fpk &scalar) {
        if (source.is_public()) {
            accumulate_extension_value(
                eval,
                promote_extension_value<Backend>(eval, source, scalar));
            return;
        }
        const bool retain_zero_terms =
            forces_challenge_independent_topology<Backend>(eval);
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            Fp weight = scalar.coefficients()[coefficient];
            if (weight.is_zero()) {
                if (!retain_zero_terms) {
                    continue;
                }
                // Bound-only backends use a nonzero symbolic operation to
                // upper-bound a challenge coefficient that happened to be
                // zero. Ordinary backends never enter this branch.
                weight = Fp::one();
            }
            if (weight == Fp::one() && !retain_zero_terms) {
                accumulate_coordinate(eval, coefficient, source);
            } else {
                accumulate_coordinate(
                    eval, coefficient,
                    FheValue<Backend>::from_ciphertext(
                        Backend::mul_plain_scalar(
                            eval, source.ciphertext(), weight)));
            }
        }
    }

    void accumulate_scaled_base(
        const typename Backend::EvalContext &eval,
        const typename Backend::Ciphertext &source,
        const Fpk &scalar) {
        accumulate_scaled_base(
            eval, FheValue<Backend>::from_ciphertext(source), scalar);
    }

    void accumulate_scaled_base_with_public_support(
        const typename Backend::EvalContext &eval,
        const FheValue<Backend> &source, const Fpk &scalar) {
        if (source.is_public()) {
            accumulate_extension_value(
                eval,
                promote_extension_value<Backend>(eval, source, scalar));
            return;
        }
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            const Fp weight = scalar.coefficients()[coefficient];
            if (weight.is_zero()) {
                continue;
            }
            if (weight == Fp::one()) {
                accumulate_coordinate(eval, coefficient, source);
            } else {
                accumulate_coordinate(
                    eval, coefficient,
                    FheValue<Backend>::from_ciphertext(
                        Backend::mul_plain_scalar(
                            eval, source.ciphertext(), weight)));
            }
        }
    }

    void accumulate_scaled_base_with_public_support(
        const typename Backend::EvalContext &eval,
        const typename Backend::Ciphertext &source,
        const Fpk &scalar) {
        accumulate_scaled_base_with_public_support(
            eval, FheValue<Backend>::from_ciphertext(source), scalar);
    }

    void accumulate_scaled_slots(
        const typename Backend::EvalContext &eval,
        const FheValue<Backend> &source,
        std::span<const Fpk> weights) {
        if (weights.size() != Backend::slot_count(eval)) {
            throw std::invalid_argument(
                "MixedExtensionAccumulator::accumulate_scaled_slots: "
                "expected one extension weight per slot");
        }
        if (source.is_public()) {
            accumulate_extension_value(
                eval,
                promote_extension_value<Backend>(eval, source, weights));
            return;
        }
        const std::size_t slots = Backend::slot_count(eval);
        const bool retain_zero_terms =
            forces_challenge_independent_topology<Backend>(eval);
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            SlotVector plaintext;
            plaintext.reserve(slots);
            for (const Fpk &weight : weights) {
                plaintext.push_back(weight.coefficients()[coefficient]);
            }
            if (detail::all_zero(plaintext)) {
                if (!retain_zero_terms) {
                    continue;
                }
                plaintext = detail::nonzero_vector_envelope(
                    plaintext, slots);
            }
            accumulate_coordinate(
                eval, coefficient,
                FheValue<Backend>::from_ciphertext(
                    Backend::mul_plain(eval, source.ciphertext(),
                                       plaintext)));
        }
    }

    void accumulate_extension(
        const typename Backend::EvalContext &eval,
        ExtensionValue<Backend> term) {
        accumulate_extension_value(eval, std::move(term));
    }

    /// Finish while applying a public extension-valued slot basis. The
    /// encrypted portion keeps the backend's prepared fast path; the public
    /// portion is multiplied analytically.
    ExtensionValue<Backend> apply_prepared_basis(
        const typename Backend::EvalContext &eval,
        const PreparedFpkSlotBasis<Backend> &basis,
        std::span<const Fpk> public_basis) && {
        if (value_.ciphertext_count() != 0U &&
            !extension_value_detail::is_base_field_vector(public_basis) &&
            !forces_challenge_independent_topology<Backend>(eval)) {
            return detail::scale_extension_prepared_public_aware<Backend>(
                eval, value_, basis, public_basis);
        }
        ExtensionValue<Backend> result;
        typename Backend::ExtCiphertext encrypted =
            value_.encrypted_projection();
        const bool only_encrypted_coefficient_zero =
            encrypted[0].has_value() &&
            std::none_of(std::next(encrypted.begin()), encrypted.end(),
                         [](const auto &coefficient) {
                             return coefficient.has_value();
                         });
        if (only_encrypted_coefficient_zero) {
            result = ExtensionValue<Backend>(
                promote_scale_prepared<Backend>(
                    eval, *encrypted[0], basis));
        } else if (value_.ciphertext_count() != 0) {
            result = ExtensionValue<Backend>(
                scale_extension_prepared<Backend>(
                    eval, encrypted, basis));
        }
        ExtensionValue<Backend> public_value;
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            if (value_[coefficient].is_public()) {
                public_value[coefficient] = value_[coefficient];
            }
        }
        if (!public_value.is_public_zero()) {
            extension_add_assign<Backend>(
                eval, result,
                scale_extension_value<Backend>(
                    eval, public_value, public_basis));
        }
        return result;
    }

    ExtensionValue<Backend> finish(
        const typename Backend::EvalContext &eval) && {
        (void)eval;
        return std::move(value_);
    }

  private:
    void accumulate_coordinate(
        const typename Backend::EvalContext &eval,
        std::size_t coefficient, FheValue<Backend> term) {
        FheValue<Backend> &destination = value_[coefficient];
        if (term.is_public_zero()) {
            return;
        }
        if (destination.is_public_zero()) {
            destination = std::move(term);
            return;
        }
        value_add_assign<Backend>(eval, destination, term);
    }

    void accumulate_extension_value(
        const typename Backend::EvalContext &eval,
        ExtensionValue<Backend> term) {
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            accumulate_coordinate(
                eval, coefficient, std::move(term[coefficient]));
        }
    }

    // FheValue is necessary here even when every input term begins encrypted:
    // related ciphertexts can cancel to a known public nonzero value.
    ExtensionValue<Backend> value_;
};

} // namespace laminate::fhe

#endif // LAMINATE_FHE_EXTENSION_ACCUMULATOR_HPP
