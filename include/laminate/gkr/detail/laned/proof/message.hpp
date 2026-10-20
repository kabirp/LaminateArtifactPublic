#ifndef LAMINATE_GKR_DETAIL_LANED_PROOF_MESSAGE_HPP
#define LAMINATE_GKR_DETAIL_LANED_PROOF_MESSAGE_HPP

/// @file message.hpp
/// @brief Pack fixed-size Laned proof values into one transport message.

#include "laminate/fhe/extension.hpp"
#include "laminate/fhe/value.hpp"

#include <cstddef>
#include <span>

namespace laminate::gkr::laned_detail {

/// Place replicated extension values in one FHE message and drop transport-
/// safe RNS limbs. This is a proof-transport boundary, not sumcheck
/// arithmetic: `values` have already been computed by the reduction kernel.
template <fhe::FheBackend Backend>
fhe::FheValue<Backend> pack_laned_proof_message(
    const typename Backend::EvalContext &eval,
    std::span<const fhe::ExtensionValue<Backend>> values,
    std::size_t reserved_mult_depth = 0) {
    fhe::FheValue<Backend> packed =
        fhe::pack_replicated_extension_values<Backend>(eval, values);
    fhe::value_compact_for_transport<Backend>(
        eval, packed, reserved_mult_depth);
    return packed;
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_PROOF_MESSAGE_HPP
