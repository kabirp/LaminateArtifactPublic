#ifndef LAMINATE_PROTOCOL_PACKED_REFERENCE_MATERIALIZED_EXTERNAL_SETUP_HPP
#define LAMINATE_PROTOCOL_PACKED_REFERENCE_MATERIALIZED_EXTERNAL_SETUP_HPP

/// @file materialized_external_setup.hpp
/// @brief Test-only bridge from resident packing setup to external setup.
///
/// Target preprocessing constructs compact structured metadata directly. This
/// adapter materializes the complete R1CS and exists only for small reference
/// equivalence and malformed-input tests.

#include "laminate/protocol/packed/external/transcript_packing.hpp"

namespace laminate::protocol::reference {

TranscriptPackingExternalProverSetup
make_materialized_reference_external_prover_setup(
    const TranscriptPackingSpartanSetup &resident_setup,
    std::shared_ptr<const spartan::BaseFoldPcs> basefold_pcs,
    spartan::ExternalProverKey spartan_key);

} // namespace laminate::protocol::reference

#endif // LAMINATE_PROTOCOL_PACKED_REFERENCE_MATERIALIZED_EXTERNAL_SETUP_HPP
