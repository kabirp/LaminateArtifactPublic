#ifndef LAMINATE_GKR_DETAIL_FOLDED_TRANSPORT_MESSAGE_PACKING_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_TRANSPORT_MESSAGE_PACKING_HPP

/// @file message_packing.hpp
/// @brief Pack Folded sumcheck values into one transport ciphertext.

#include "laminate/fhe/extension/packing.hpp"

#include <cstddef>
#include <span>

namespace laminate::gkr::folded_detail {

/// Put one or two replicated extension values in the fixed Folded message
/// cells, then discard RNS limbs not needed by the remaining transport.
template <fhe::FheBackend Backend>
fhe::FheValue<Backend> pack_reduction_message(
    const typename Backend::EvalContext &eval,
    std::span<const fhe::ExtensionValue<Backend>> values,
    std::size_t reserved_mult_depth = 0) {
    fhe::FheValue<Backend> packed =
        fhe::pack_replicated_extension_values<Backend>(eval, values);
    fhe::value_compact_for_transport<Backend>(
        eval, packed, reserved_mult_depth);
    return packed;
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_TRANSPORT_MESSAGE_PACKING_HPP
