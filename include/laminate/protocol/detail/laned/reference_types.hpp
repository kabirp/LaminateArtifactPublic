#ifndef LAMINATE_PROTOCOL_DETAIL_LANED_REFERENCE_TYPES_HPP
#define LAMINATE_PROTOCOL_DETAIL_LANED_REFERENCE_TYPES_HPP

/// @file reference_types.hpp
/// @brief Types used only by Laned file and checkpoint reference paths.

#include "laminate/gkr/detail/laned/prover.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/protocol/packed/proof.hpp"

namespace laminate::protocol::reference {

using IrreversibleLanedFileProofOptions =
    gkr::laned_detail::IrreversibleFileLanedGkrOptions;

template <packing::CoefficientWellFormednessBackend Backend>
struct LanedFileProofResult {
    LaminateLanedProof<Backend> proof;
    gkr::laned_detail::FileLanedGkrReport gkr_report;
};

template <packing::CoefficientWellFormednessBackend Backend>
    requires fhe::PersistableFheBackend<Backend>
struct LanedCheckpointReplayProofResult {
    LaminateLanedProof<Backend> proof;
    gkr::laned_detail::FileLanedGkrReport gkr_report;
    payload::PayloadCheckpointReplayExecutionReport payload_replay_report;
};

} // namespace laminate::protocol::reference

#endif // LAMINATE_PROTOCOL_DETAIL_LANED_REFERENCE_TYPES_HPP
