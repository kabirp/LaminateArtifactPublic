#ifndef LAMINATE_GKR_DETAIL_FOLDED_MULTIPLICATION_PROVER_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_MULTIPLICATION_PROVER_HPP

/// @file prover.hpp
/// @brief Canonical file-backed Folded multiplication reduction.

#include "laminate/gkr/detail/folded/multiplication/types.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/prover.hpp"

#include <cstddef>
#include <stdexcept>
#include <utility>

namespace laminate::gkr::folded_detail {

using FoldedMultiplicationStatistics =
    ::laminate::gkr::detail::FileBackedMultiplicationStatistics;

/// Folded validation and progress labels for the shared file-backed prover.
/// The visible sumcheck recurrence is in
/// `detail/shared/dense_multiplication/prover.hpp`; its ciphertext-index
/// rounds call the complete source-pass and product FHE kernel in
/// `ciphertext_index_rounds.hpp`.
struct FoldedMultiplicationPolicy {
    static constexpr ProtocolVariant variant =
        ProtocolVariant::LaminateFolded;
    static constexpr RuntimeProgressStage checkpoint_stage =
        RuntimeProgressStage::FoldedMultiplicationSlotCheckpoint;
    static constexpr RuntimeProgressStage sumcheck_stage =
        RuntimeProgressStage::FoldedMultiplicationSumcheckRound;
    template <fhe::FheBackend Backend>
    using Result = FoldedMultiplicationReductionResult<Backend>;
    using Geometry = FoldedMultiplicationReductionGeometry;

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
        // `FileDenseMultiplicationSource::open` already authenticated the
        // complete descriptor against the setup-preprocessed source plan,
        // including `layered_circuit_id`. Rehashing the whole circuit here
        // would turn every online multiplication reduction into a static
        // setup scan.
        const bool mismatch =
            descriptor.backend_context_id !=
                Backend::storage_context_id(eval) ||
            descriptor.shape != circuit.shape ||
            descriptor.reduction_layer != layer ||
            descriptor.output_layout !=
                ::laminate::gkr::detail::
                    dense_multiplication_storage_layout(circuit, layer) ||
            descriptor.source_layout !=
                ::laminate::gkr::detail::
                    dense_multiplication_storage_layout(circuit, layer + 1U) ||
            descriptor.pair_count != geometry.pair_count ||
            descriptor.chunks_per_packed_ciphertext != 1U ||
            Backend::slot_count(eval) != circuit.shape.slot_count;
        if (mismatch) {
            throw std::invalid_argument(
                "LaminateFolded multiplication source mismatch");
        }
    }
};

template <fhe::PersistableFheBackend Backend>
using FoldedMultiplicationProver =
    ::laminate::gkr::detail::PackedDenseMultiplicationProver<
        Backend, FoldedMultiplicationPolicy>;

template <fhe::PersistableFheBackend Backend>
FoldedMultiplicationReductionResult<Backend>
prove_multiplication(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit,
    const ::laminate::gkr::detail::FileDenseMultiplicationSource<Backend>
        &source,
    std::size_t layer, const SingleClaim &claim,
    Transcript &transcript, std::size_t reserved_transport_depth = 0,
    PackedMessageCommitmentFunction<Backend> commitment_function = {},
    FoldedMultiplicationStatistics *statistics = nullptr,
    RuntimeProgressCallback progress = {}) {
    // Step 1: Execute Folded's equality-stripped file-backed recurrence.
    // Ciphertext-index passes scan the compact L/R artifact; slot-index
    // passes fold its two encrypted checkpoints. Omitted trace padding is
    // public zero and triggers no ciphertext operation.
    return FoldedMultiplicationProver<Backend>(
               eval, circuit, source, layer, claim, transcript,
               reserved_transport_depth, std::move(commitment_function),
               statistics, std::move(progress))
        .run();
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_MULTIPLICATION_PROVER_HPP
