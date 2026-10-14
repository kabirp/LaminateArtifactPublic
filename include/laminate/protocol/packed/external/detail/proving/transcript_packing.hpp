#ifndef LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_PROVING_TRANSCRIPT_PACKING_HPP
#define LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_PROVING_TRANSCRIPT_PACKING_HPP

/// @file transcript_packing.hpp
/// @brief Assignment construction and Spartan proof of transcript packing.

#include "laminate/protocol/detail/packing/committed_gkr_encoding.hpp"
#include "laminate/protocol/detail/packing/aligned_commitments.hpp"

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace laminate::protocol::packed_external_detail {

inline void require_packing_report_matches_admission(
    const TranscriptPackingExternalProverReport &actual,
    const TranscriptPackingExternalPreflightReport &admitted,
    std::string_view variant) {
    if (actual.prefix_storage != admitted.prefix_storage ||
        actual.storage != admitted.spartan_storage) {
        throw std::logic_error(
            "external " + std::string(variant) +
            " packing execution drifted from preflight");
    }
}

/// Bind the committed GKR proof, build the transcript-packing assignment, and
/// prove that assignment with Spartan. This is the complete Laminate suffix:
/// no packing challenge is sampled before the committed GKR encoding enters
/// the continuing protocol transcript.
template <ProofOfPackingBackend Backend, typename CommittedGkrProof>
TranscriptPackingExternalProverResult<Backend>
run_assignment_and_spartan_suffix(
    const typename Backend::EvalContext &evaluation,
    const TranscriptPackingExternalProverSetup &setup,
    TranscriptPackingExternalAdmission admission,
    detail::CollectedAlignedCommitments<Backend> packing_sources,
    const CommittedGkrProof &committed_gkr,
    Transcript &protocol_transcript,
    const RuntimeProgressCallback &progress,
    const TranscriptPackingExternalPreflightReport &preflight,
    std::string_view variant) {
    detail::bind_committed_gkr_for_packing(
        committed_gkr, protocol_transcript);

    TranscriptPackingExternalProverInput<Backend> input(
        std::move(packing_sources));
    auto packed = prove_transcript_packing_external_admitted<Backend>(
        evaluation, setup, std::move(admission), std::move(input),
        protocol_transcript, progress);
    require_packing_report_matches_admission(
        packed.report, preflight, variant);

    return packed;
}

} // namespace laminate::protocol::packed_external_detail

#endif // LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_PROVING_TRANSCRIPT_PACKING_HPP
