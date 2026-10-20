#ifndef LAMINATE_DELEGATION_FOLDED_SERVER_ADMISSION_OPTIONS_HPP
#define LAMINATE_DELEGATION_FOLDED_SERVER_ADMISSION_OPTIONS_HPP

/// @file server/admission/options.hpp
/// @brief Mutable storage policy admitted for one Folded server proof.

#include "laminate/gkr/detail/folded/prover.hpp"

namespace laminate::delegation {

using FoldedServerProofOptions =
    gkr::folded_detail::IrreversibleFileFoldedGkrOptions;

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_FOLDED_SERVER_ADMISSION_OPTIONS_HPP
