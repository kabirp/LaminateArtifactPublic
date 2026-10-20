#ifndef LAMINATE_PROTOCOL_PACKED_SETUP_HPP
#define LAMINATE_PROTOCOL_PACKED_SETUP_HPP

/// @file setup.hpp
/// @brief Public setup API for Folded/Laned transcript packing.
///
/// Reading map:
/// - `proof_ingress.hpp` selects the RNS levels exposed to packed GKR.
/// - `transcript_packing.hpp` defines the shared Spartan preprocessing state.
/// - `variants.hpp` binds that state to Folded and Laned payload evaluation.
/// - `builders.hpp` declares the production constructors; their template
///   bodies are kept under `setup/detail/`.
///
/// Most callers want `setup_folded_conservative` or
/// `setup_laned_conservative`. Honest-candidate and certified builders are
/// explicit calibration paths in `builders.hpp`.
/// Uniform-ingress test fixtures live in
/// `tests/support/packed_setup_fixture.hpp`.

#include "laminate/protocol/packed/setup/proof_ingress.hpp"
#include "laminate/protocol/packed/setup/transcript_packing.hpp"
#include "laminate/protocol/packed/setup/variants.hpp"
#include "laminate/protocol/packed/setup/builders.hpp"

#endif // LAMINATE_PROTOCOL_PACKED_SETUP_HPP
