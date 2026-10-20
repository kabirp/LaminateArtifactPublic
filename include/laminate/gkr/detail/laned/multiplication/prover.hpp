#ifndef LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_PROVER_HPP
#define LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_PROVER_HPP

/// @file prover.hpp
/// @brief Canonical file-backed multiplication reduction for LaminateLaned.

#include "laminate/gkr/detail/laned/multiplication/types.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/prover.hpp"
#include "laminate/runtime_progress.hpp"

#include <cstddef>
#include <stdexcept>
#include <utility>

namespace laminate::gkr::laned_detail {

/// Laned geometry, admission, and telemetry labels consumed by the shared
/// file-backed multiplication recurrence. This contains no protocol loop.
struct LanedMultiplicationProtocol {
    static constexpr ProtocolVariant variant =
        ProtocolVariant::LaminateLaned;
    static constexpr RuntimeProgressStage checkpoint_stage =
        RuntimeProgressStage::LanedMultiplicationSlotCheckpoint;
    static constexpr RuntimeProgressStage sumcheck_stage =
        RuntimeProgressStage::LanedMultiplicationSumcheckRound;
    template <fhe::FheBackend Backend>
    using Result = LanedMultiplicationLayerReductionResult<Backend>;

    using Geometry = LanedMultiplicationLayerReductionGeometry;

    static Geometry make_geometry(const payload::LayeredCircuit &circuit,
                                  std::size_t layer,
                                  const SingleClaim &claim) {
        return Geometry::create(circuit, layer, claim);
    }

    template <fhe::PersistableFheBackend Backend>
    static void validate_source(
        const typename Backend::EvalContext &eval,
        const payload::LayeredCircuit &circuit,
        const ::laminate::gkr::detail::FileDenseMultiplicationSource<Backend>
            &source,
        std::size_t layer,
        const Geometry &geometry) {
        const auto &descriptor = source.descriptor();
        // Opening this source already checked its full descriptor against
        // the setup-preprocessed plan. In particular, its layered-circuit
        // digest is authenticated there; recomputing that digest in every
        // online reduction would rescan the whole circuit.
        const bool mismatch =
            descriptor.backend_context_id !=
                Backend::storage_context_id(eval) ||
            descriptor.shape != circuit.shape ||
            descriptor.reduction_layer != layer ||
            descriptor.output_layout != geometry.output ||
            descriptor.source_layout != geometry.source ||
            descriptor.pair_count != geometry.pair_count ||
            Backend::slot_count(eval) != circuit.shape.slot_count;
        if (mismatch) {
            throw std::invalid_argument(
                "LaminateLaned multiplication source mismatch");
        }
    }
};

/// Prove `Out(x,s)=Left(x,s)*Right(x,s)` from the bit-reversed file artifact.
/// The explicit recurrence is in
/// `detail/shared/dense_multiplication/prover.hpp`; each ciphertext-index
/// round reaches the complete source pass and FHE products in
/// `arithmetic/ciphertext_index_rounds.hpp`. Slot checkpoints and rounds are
/// linear.
template <fhe::PersistableFheBackend Backend>
LanedMultiplicationLayerReductionResult<Backend>
prove_multiplication(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit,
    const ::laminate::gkr::detail::FileDenseMultiplicationSource<Backend>
        &source,
    std::size_t layer, const SingleClaim &claim,
    Transcript &transcript, std::size_t reserved_transport_depth = 0,
    PackedMessageCommitmentFunction<Backend> commitment_function = {},
    ::laminate::gkr::detail::FileBackedMultiplicationStatistics *statistics =
        nullptr,
    RuntimeProgressCallback progress = {}) {
    using MultiplicationSumcheck = ::laminate::gkr::detail::
        PackedDenseMultiplicationProver<Backend,
                                        LanedMultiplicationProtocol>;

    // For every round,
    //   claim_j=(1-tau_j)S_j(0)+tau_j*S_j(1).
    // The shared recurrence evaluates the nonsingular Boolean endpoint and
    // S_j(2) under FHE, binds that message, samples r_j, and carries
    // claim_{j+1}=S_j(r_j). Source scans are sequential; known public-zero
    // operands stay null and avoid backend work.
    return MultiplicationSumcheck(
               eval, circuit, source, layer, claim, transcript,
               reserved_transport_depth, std::move(commitment_function),
               statistics, std::move(progress))
        .run();
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_PROVER_HPP
