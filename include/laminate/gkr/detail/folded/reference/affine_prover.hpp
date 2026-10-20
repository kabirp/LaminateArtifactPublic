#ifndef LAMINATE_GKR_DETAIL_FOLDED_REFERENCE_AFFINE_PROVER_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_REFERENCE_AFFINE_PROVER_HPP

/// @file affine_prover.hpp
/// @brief Resident Folded affine adapter for tests and analysis.

#include "laminate/gkr/detail/base/reference/trace_source.hpp"
#include "laminate/gkr/detail/folded/affine/prover.hpp"

#include <cstddef>
#include <utility>

namespace laminate::gkr::folded_detail {

/// Adapt a resident trace to the same explicit source-backed affine
/// recurrence used by the file-backed prover. This is an input-storage
/// adapter, not a second or reference sumcheck implementation. Both paths
/// prove
///
///   claim - affine_constant = sum_u GateMLE(output_point, u) Source(u).
template <fhe::FheBackend Backend>
FoldedAffineReductionResult<Backend> prove_affine_resident(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace, std::size_t layer,
    const LayerClaim &claim, Transcript &transcript,
    std::size_t reserved_transport_depth = 0,
    detail::ProverGateClaims *gate_claims = nullptr,
    PackedMessageCommitmentFunction<Backend> commitment_function = {},
    FoldedAffineStatistics *statistics = nullptr,
    RuntimeProgressCallback progress = {}) {
    // Step 1: Expose the resident trace through the same compact active-wire
    // contract used by the production affine recurrence. Omitted padded wires
    // remain public/null zero and never become ciphertexts.
    const base_detail::ResidentBaseTraceSource<Backend> resident_source(
        eval, circuit, trace);

    // Step 2: Run the canonical Folded affine recurrence unchanged.
    return prove_affine<Backend>(
        eval, circuit, resident_source,
        resident_source.layer_support(layer + 1U), layer, claim, transcript,
        reserved_transport_depth, gate_claims,
        std::move(commitment_function), statistics, std::move(progress));
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_REFERENCE_AFFINE_PROVER_HPP
