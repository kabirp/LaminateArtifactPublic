#ifndef LAMINATE_GKR_DETAIL_BASE_REFERENCE_AFFINE_PROVER_HPP
#define LAMINATE_GKR_DETAIL_BASE_REFERENCE_AFFINE_PROVER_HPP

/// @file affine_prover.hpp
/// @brief Bounded resident adapter for the Base affine reduction kernel.

#include "laminate/gkr/detail/base/affine/prover.hpp"
#include "laminate/gkr/detail/base/reference/trace_source.hpp"

namespace laminate::gkr::base_detail {

/// Run the production affine recurrence over an in-memory trace adapter.
/// This reference path changes storage only: it reaches the same
/// `evaluate_base_affine_ciphertext_index_round` FHE kernel as file-backed Base.
template <fhe::FheBackend Backend>
ProvedAffine<Backend> prove_affine_resident(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace, std::size_t layer,
    const LayerClaim &claim, const gates::DirectGateMle &provider,
    Transcript &transcript,
    detail::ProverGateClaims *gate_claims = nullptr,
    BaseAffineStatistics *statistics = nullptr) {
    // Step 1: expose the resident trace through the compact active-wire
    // source interface. Omitted padding remains known plaintext zero.
    const ResidentBaseTraceSource<Backend> source(eval, circuit, trace);

    // Step 2: run the same affine recurrence and FHE kernel as file-backed
    // Base; only the source reader differs.
    return prove_affine_reduction<Backend>(
        eval, circuit, source, source.layer_support(layer + 1U), layer,
        claim, provider, transcript,
        gate_claims, statistics);
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_REFERENCE_AFFINE_PROVER_HPP
