#ifndef LAMINATE_GKR_DETAIL_SHARED_PACKED_PREPARED_BASIS_HPP
#define LAMINATE_GKR_DETAIL_SHARED_PACKED_PREPARED_BASIS_HPP

/// @file prepared_basis.hpp
/// @brief Public-or-encrypted application of immutable SIMD bases.

#include "laminate/fhe/extension.hpp"

#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::detail {

/// One immutable extension-valued slot basis in both forms needed by mixed
/// proof arithmetic. `public_values` is always present. `encrypted` is built
/// only when the source contains ciphertexts and therefore has a modulus
/// level at which the backend can prepare the basis.
template <fhe::FheBackend Backend> struct MixedPreparedFpkSlotBasis {
    std::vector<Fpk> public_values;
    std::optional<fhe::PreparedFpkSlotBasis<Backend>> encrypted;

    std::size_t slot_count() const noexcept {
        return public_values.size();
    }
};

template <fhe::FheBackend Backend>
MixedPreparedFpkSlotBasis<Backend> prepare_mixed_fpk_slot_basis(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext *level_reference,
    std::span<const Fpk> values) {
    if (values.size() != Backend::slot_count(eval)) {
        throw std::invalid_argument(
            "prepare_mixed_fpk_slot_basis: basis has the wrong slot count");
    }
    MixedPreparedFpkSlotBasis<Backend> result;
    result.public_values.assign(values.begin(), values.end());
    if (level_reference != nullptr) {
        result.encrypted.emplace(fhe::prepare_fpk_slot_basis<Backend>(
            eval, *level_reference, values));
    }
    return result;
}

/// Apply a mixed prepared basis. The public-only case deliberately avoids a
/// backend level anchor; the encrypted case requires the basis prepared at
/// that level and keeps the optimized backend path.
template <fhe::FheBackend Backend>
fhe::ExtensionValue<Backend> apply_mixed_prepared_basis(
    const typename Backend::EvalContext &eval,
    fhe::MixedExtensionAccumulator<Backend> accumulator,
    const MixedPreparedFpkSlotBasis<Backend> &basis) {
    if (accumulator.has_encrypted()) {
        if (!basis.encrypted) {
            throw std::invalid_argument(
                "apply_mixed_prepared_basis: encrypted value has no "
                "prepared basis");
        }
        return std::move(accumulator).apply_prepared_basis(
            eval, *basis.encrypted, basis.public_values);
    }
    return fhe::scale_extension_value<Backend>(
        eval, std::move(accumulator).finish(eval), basis.public_values);
}

template <fhe::FheBackend Backend>
fhe::ExtensionValue<Backend> apply_mixed_prepared_basis(
    const typename Backend::EvalContext &eval,
    fhe::ExtensionValue<Backend> value,
    const MixedPreparedFpkSlotBasis<Backend> &basis) {
    fhe::MixedExtensionAccumulator<Backend> accumulator;
    accumulator.accumulate_extension(eval, std::move(value));
    return apply_mixed_prepared_basis<Backend>(
        eval, std::move(accumulator), basis);
}

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_PACKED_PREPARED_BASIS_HPP
