#ifndef LAMINATE_FHE_EXTENSION_PREPARED_BASIS_HPP
#define LAMINATE_FHE_EXTENSION_PREPARED_BASIS_HPP

/// @file prepared_basis.hpp
/// @brief Encoding and immutable prepared bases for extension-field SIMD work.

#include "laminate/fhe/backend.hpp"
#include "laminate/fhe/extension_value.hpp"
#include "laminate/field/fpk.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <utility>

namespace laminate::fhe {
namespace detail {

inline bool all_zero(std::span<const Fp> values) {
    for (const Fp &value : values) {
        if (!value.is_zero()) {
            return false;
        }
    }
    return true;
}

/// Replace a challenge-created zero by a nonzero plaintext of the same
/// structural kind for value-free bound execution.
inline SlotVector nonzero_vector_envelope(std::span<const Fp> values,
                                          std::size_t slot_count) {
    SlotVector result(slot_count, Fp::zero());
    std::copy(values.begin(), values.end(), result.begin());
    result.front() = Fp::one();
    return result;
}

inline SlotVector nonzero_scalar_envelope(std::size_t slot_count) {
    return SlotVector(slot_count, Fp::one());
}

inline PlainExtension retain_vector_plaintext_topology(
    PlainExtension plaintext, std::size_t slot_count) {
    for (SlotVector &coefficient : plaintext) {
        if (all_zero(coefficient)) {
            coefficient = nonzero_vector_envelope(coefficient, slot_count);
        }
    }
    return plaintext;
}

inline PlainExtensionScalar retain_scalar_plaintext_topology(
    PlainExtensionScalar plaintext) {
    for (Fp &coefficient : plaintext) {
        if (coefficient.is_zero()) {
            coefficient = Fp::one();
        }
    }
    return plaintext;
}

} // namespace detail

inline PlainExtension
encode_extension_plain(std::span<const Fpk> values) {
    PlainExtension result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        result[coefficient].reserve(values.size());
        for (const Fpk &value : values) {
            result[coefficient].push_back(
                value.coefficients()[coefficient]);
        }
    }
    return result;
}

inline PlainExtension encode_extension_scalar(const Fpk &value,
                                               std::size_t slot_count) {
    PlainExtension result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        result[coefficient].assign(slot_count,
                                   value.coefficients()[coefficient]);
    }
    return result;
}

/// Immutable extension-valued SIMD basis prepared once outside online
/// ciphertext-record scans. The backend owns any level-specific encoded/NTT
/// representations; this wrapper prevents an online caller from falling back
/// to an N-entry host-vector construction or cache lookup.
template <FheBackend Backend> struct PreparedFpkSlotBasis {
    typename Backend::PreparedExtensionSlotBasis backend_basis;
    std::size_t slot_count = 0;
    PreparedBasisStorageStats storage;
    /// Coordinates whose nonzero support is fixed by public data. A dense
    /// mask is used for challenge-derived bases, whose observed zeros must
    /// not change the protocol topology.
    std::uint8_t public_coordinate_support =
        static_cast<std::uint8_t>((std::uint16_t{1}
                                   << kExtensionDegree) - 1U);
};

template <FheBackend Backend>
PreparedFpkSlotBasis<Backend> prepare_fpk_slot_basis(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &level_reference,
    std::span<const Fpk> basis) {
    if (basis.size() != Backend::slot_count(eval)) {
        throw std::invalid_argument(
            "prepare_fpk_slot_basis: basis must fill all slots");
    }
    auto backend_basis = Backend::prepare_extension_slot_basis(
        eval, level_reference, encode_extension_plain(basis));
    const PreparedBasisStorageStats storage =
        Backend::prepared_extension_slot_basis_storage(backend_basis);
    return PreparedFpkSlotBasis<Backend>{std::move(backend_basis),
                                         basis.size(), storage};
}

/// Prepare a basis whose coordinate support is fixed by the public circuit.
/// This lets callers omit algebraically zero extension coordinates without
/// treating challenge-dependent accidental zeros as structural.
template <FheBackend Backend>
PreparedFpkSlotBasis<Backend> prepare_public_fpk_slot_basis(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &level_reference,
    std::span<const Fpk> basis) {
    PreparedFpkSlotBasis<Backend> result =
        prepare_fpk_slot_basis<Backend>(eval, level_reference, basis);
    result.public_coordinate_support = 0;
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        const bool present = std::any_of(
            basis.begin(), basis.end(), [&](const Fpk &value) {
                return !value.coefficients()[coefficient].is_zero();
            });
        if (present) {
            result.public_coordinate_support |=
                static_cast<std::uint8_t>(std::uint8_t{1} << coefficient);
        }
    }
    return result;
}

/// Apply one prepared Fpk slot basis to an already scalar-aggregated
/// extension ciphertext. This is one slot-varying plaintext-multiplication
/// level and performs no online Fpk vector construction.
template <FheBackend Backend>
typename Backend::ExtCiphertext scale_extension_prepared(
    const typename Backend::EvalContext &eval,
    const typename Backend::ExtCiphertext &ciphertext,
    const PreparedFpkSlotBasis<Backend> &basis) {
    if (basis.slot_count != Backend::slot_count(eval)) {
        throw std::invalid_argument(
            "scale_extension_prepared: basis has the wrong slot count");
    }
    return Backend::ext_mul_plain_prepared(
        eval, ciphertext, basis.backend_basis);
}

/// Multiply one base ciphertext by a prepared extension-valued slot basis.
/// This uses at most k prepared base CT-PT products, not k^2, and stays at one
/// slot-varying plaintext-multiplication level.
template <FheBackend Backend>
typename Backend::ExtCiphertext promote_scale_prepared(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &ciphertext,
    const PreparedFpkSlotBasis<Backend> &basis) {
    if (basis.slot_count != Backend::slot_count(eval)) {
        throw std::invalid_argument(
            "promote_scale_prepared: basis has the wrong slot count");
    }
    typename Backend::ExtCiphertext result = Backend::promote_plain_prepared(
        eval, ciphertext, basis.backend_basis);
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if ((basis.public_coordinate_support &
             static_cast<std::uint8_t>(std::uint8_t{1} << coefficient)) ==
            0) {
            result[coefficient].reset();
        }
    }
    return result;
}

} // namespace laminate::fhe

#endif // LAMINATE_FHE_EXTENSION_PREPARED_BASIS_HPP
