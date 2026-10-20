#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_EVALUATOR_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_EVALUATOR_HPP

/// @file evaluator.hpp
/// @brief File-backed FHE evaluator for dense multiplication sumcheck rounds.
///
/// This is the boundary between the visible multiplication protocol and its
/// external-memory implementation. The prover asks for one mathematical
/// operation at a time; this object owns reader rewinds, sequential scans,
/// prepared public bases, and I/O accounting. It never publishes a message or
/// samples a Fiat--Shamir challenge.

#include "laminate/gkr/detail/shared/dense_multiplication/rounds.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/arithmetic/ciphertext_index_rounds.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <utility>

namespace laminate::gkr::detail {

/// Evaluates the dense relation
///
///   S_j(X) = sum_u eq(gamma_suffix,u)
///                    L(r_prefix,X,u) R(r_prefix,X,u)
///
/// from a compact file-backed left/right source. Each ciphertext-index round
/// is one sequential pass. After all ciphertext-index variables are fixed,
/// one final pass produces two encrypted slot checkpoints; subsequent
/// slot-index rounds use only those checkpoints and no longer read the source.
template <fhe::PersistableFheBackend Backend, typename Geometry,
          typename Reader>
class DenseMultiplicationRoundEvaluator {
  public:
    using RoundEvaluations =
        TransmittedLayerReductionRound<fhe::ExtensionValue<Backend>>;
    using SlotCheckpoints = MultiplicationSlotCheckpoints<Backend>;
    using SourceValues =
        DenseMultiplicationSourceValues<fhe::ExtensionValue<Backend>>;

    DenseMultiplicationRoundEvaluator(
        const typename Backend::EvalContext &eval,
        const Geometry &geometry, Reader reader,
        std::size_t live_pair_count,
        FileBackedMultiplicationStatistics &statistics)
        : eval_(eval), geometry_(geometry), reader_(std::move(reader)),
          live_pair_count_(live_pair_count), statistics_(statistics) {}

    /// Evaluate S(endpoint) and S(2) for one ciphertext-index variable. One
    /// semantic jump reaches the complete source pass and concrete FHE
    /// multiplication in `arithmetic/ciphertext_index_rounds.hpp`.
    RoundEvaluations evaluate_ciphertext_index_round(
        std::span<const Fpk> output_point,
        std::span<const Fpk> challenge_prefix,
        const LayerReductionRoundPoints &points) {
        return evaluate_packed_multiplication_ciphertext_round<Backend>(
            eval_, reader_, output_point, geometry_.ciphertext_index_variables,
            challenge_prefix, points, geometry_.output_slot_weights,
            prepared_output_slots_, statistics_);
    }

    /// Bind the complete ciphertext-index point into L and R. This final
    /// source scan uses scalar-weighted additions and no ciphertext product.
    SlotCheckpoints evaluate_slot_checkpoints(
        std::span<const Fpk> ciphertext_index_point) {
        return evaluate_multiplication_slot_checkpoints<Backend>(
            eval_, reader_, ciphertext_index_point, statistics_);
    }

    /// Evaluate the next SIMD slot-index round from the retained L/R
    /// checkpoints. The source file is no longer involved.
    RoundEvaluations evaluate_slot_index_round(
        const SlotCheckpoints &checkpoints,
        std::span<const Fpk> output_slot,
        std::span<const Fpk> challenge_prefix,
        const Fpk &transmitted_endpoint) {
        file_dense_multiplication_source_detail::checked_accumulate(
            statistics_.slot_checkpoint_prefix_pairs_bound, 1,
            "multiplication slot checkpoint prefix pair");
        file_dense_multiplication_source_detail::checked_accumulate(
            statistics_.slot_public_mask_pairs_constructed, 1,
            "multiplication slot public mask pair");
        return evaluate_multiplication_slot_round<Backend>(
            eval_, checkpoints.left, checkpoints.right, output_slot,
            challenge_prefix, transmitted_endpoint);
    }

    /// Finish L and R at the complete random point for the terminal proof
    /// message and next-layer GKR claim.
    SourceValues evaluate_terminal_source(
        const SlotCheckpoints &checkpoints,
        std::span<const Fpk> slot_point) const {
        return {
            .left = fhe::partial_evaluate_slot_index_point<Backend>(
                eval_, checkpoints.left, slot_point),
            .right = fhe::partial_evaluate_slot_index_point<Backend>(
                eval_, checkpoints.right, slot_point),
        };
    }

    std::size_t live_pair_count() const { return live_pair_count_; }

  private:
    const typename Backend::EvalContext &eval_; ///< FHE operation context.
    const Geometry &geometry_;                  ///< Fixed reduction geometry.
    Reader reader_;                            ///< Sequential source reader.
    std::size_t live_pair_count_;               ///< Nonzero logical pairs.
    FileBackedMultiplicationStatistics &statistics_; ///< I/O/FHE diagnostics.

    /// Cached public slot-equality basis, built lazily by the first
    /// ciphertext-index round and reused for every later round.
    std::optional<MixedPreparedFpkSlotBasis<Backend>>
        prepared_output_slots_;
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_EVALUATOR_HPP
