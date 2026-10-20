#ifndef LAMINATE_GKR_DETAIL_BASE_FHE_MESSAGE_NORMALIZATION_HPP
#define LAMINATE_GKR_DETAIL_BASE_FHE_MESSAGE_NORMALIZATION_HPP

/// @file message_normalization.hpp
/// @brief Move one Base proof message to its canonical lowest RNS level.

#include "laminate/fhe/extension.hpp"

namespace laminate::gkr::base_detail {

template <fhe::FheBackend Backend>
void switch_message_to_lowest(
    const typename Backend::EvalContext &eval,
    fhe::ExtensionValue<Backend> &value) {
    if constexpr (requires(
                      const typename Backend::EvalContext &context,
                      const typename Backend::ExtCiphertext &before,
                      const typename Backend::ExtCiphertext &after) {
                      Backend::observe_base_message_normalization(
                          context, before, after);
                  }) {
        const typename Backend::ExtCiphertext before =
            value.encrypted_projection();
        fhe::mod_switch_extension_value_to_lowest<Backend>(eval, value);
        Backend::observe_base_message_normalization(
            eval, before, value.encrypted_projection());
    } else {
        fhe::mod_switch_extension_value_to_lowest<Backend>(eval, value);
    }
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_FHE_MESSAGE_NORMALIZATION_HPP
