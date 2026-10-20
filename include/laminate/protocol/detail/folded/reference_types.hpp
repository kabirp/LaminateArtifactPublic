#ifndef LAMINATE_PROTOCOL_DETAIL_FOLDED_REFERENCE_TYPES_HPP
#define LAMINATE_PROTOCOL_DETAIL_FOLDED_REFERENCE_TYPES_HPP

/// @file reference_types.hpp
/// @brief Types used only by Folded file and checkpoint reference paths.

#include "laminate/gkr/detail/folded/prover.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/protocol/packed/proof.hpp"

namespace laminate::protocol::reference {

using RetryableFoldedFileProofOptions =
    gkr::folded_detail::FileFoldedGkrOptions;
using IrreversibleFoldedFileProofOptions =
    gkr::folded_detail::IrreversibleFileFoldedGkrOptions;

template <packing::CoefficientWellFormednessBackend Backend>
struct FoldedFileProofResult {
    LaminateFoldedProof<Backend> proof;
    gkr::folded_detail::FileFoldedGkrReport gkr_report;
};

template <packing::CoefficientWellFormednessBackend Backend>
    requires fhe::PersistableFheBackend<Backend>
struct FoldedCheckpointReplayProofResult {
    LaminateFoldedProof<Backend> proof;
    gkr::folded_detail::FileFoldedGkrReport gkr_report;
    payload::PayloadCheckpointReplayExecutionReport payload_replay_report;
};

} // namespace laminate::protocol::reference

#endif // LAMINATE_PROTOCOL_DETAIL_FOLDED_REFERENCE_TYPES_HPP
