#ifndef LAMINATE_PACKING_ALIGNMENT_PLACEMENT_HPP
#define LAMINATE_PACKING_ALIGNMENT_PLACEMENT_HPP

/// @file placement.hpp
/// @brief Shared grid placement primitives for transcript-packing profiles.

#include "laminate/packing/alignment/layout.hpp"

namespace laminate::packing::placement_detail {

inline bool destination_mask_is_identity(
    const PackingLayout &layout, const PackingPlacement &placement) {
    return placement.destination_begin == 0 &&
           placement.length == layout.slot_count;
}

/// Rotate a common-layout BhIP-round ciphertext so that its source interval
/// begins at the destination interval. No position mask is applied here; this
/// is the pre-mask boundary analyzed by the implemented well-formedness test.
template <fhe::FheBackend Backend>
typename Backend::Ciphertext rotate_to_destination(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &message,
    const PackingPlacement &placement) {
    return placement.rotation_steps == 0
               ? message
               : Backend::rotate(eval, message, placement.rotation_steps);
}

/// Apply the exact destination mask used by the final packing operator.
template <fhe::FheBackend Backend>
typename Backend::Ciphertext apply_destination_mask(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &aligned,
    const PackingLayout &layout, const PackingPlacement &placement) {
    if (destination_mask_is_identity(layout, placement)) {
        return aligned;
    }
    return Backend::mul_plain(
        eval, aligned, make_packing_destination_mask(layout, placement));
}

template <fhe::FheBackend Backend>
typename Backend::Ciphertext make_positioned_contribution(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &message,
    const PackingLayout &layout, const PackingPlacement &placement) {
    return apply_destination_mask<Backend>(
        eval, rotate_to_destination<Backend>(eval, message, placement),
        layout, placement);
}

} // namespace laminate::packing::placement_detail

#endif // LAMINATE_PACKING_ALIGNMENT_PLACEMENT_HPP
