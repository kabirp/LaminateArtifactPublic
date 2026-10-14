#ifndef LAMINATE_DELEGATION_LANED_SERVER_ADMISSION_OPTIONS_HPP
#define LAMINATE_DELEGATION_LANED_SERVER_ADMISSION_OPTIONS_HPP

/// @file server/admission/options.hpp
/// @brief Mutable storage policy admitted for one Laned server proof.

#include "laminate/gkr/detail/laned/prover.hpp"

namespace laminate::delegation {

using LanedServerProofOptions =
    gkr::laned_detail::IrreversibleFileLanedGkrOptions;

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_LANED_SERVER_ADMISSION_OPTIONS_HPP
