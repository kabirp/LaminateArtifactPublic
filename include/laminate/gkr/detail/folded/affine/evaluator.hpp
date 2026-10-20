#ifndef LAMINATE_GKR_DETAIL_FOLDED_AFFINE_EVALUATOR_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_AFFINE_EVALUATOR_HPP

/// @file evaluator.hpp
/// @brief File-backed FHE evaluator for one LaminateFolded affine reduction.

#include "laminate/gkr/detail/folded/affine/arithmetic/slot_round.hpp"
#include "laminate/gkr/detail/folded/affine/internal/basis.hpp"
#include "laminate/gkr/detail/folded/affine/internal/ciphertext_index_equalities.hpp"
#include "laminate/gkr/detail/folded/affine/internal/gate_schedule.hpp"
#include "laminate/gkr/detail/folded/affine/source/prepared_bases.hpp"
#include "laminate/gkr/detail/folded/affine/source/scan.hpp"
#include "laminate/gkr/detail/folded/affine/types.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::folded_detail {

template <fhe::FheBackend Backend, typename Reader>
FoldedAffineRoundEvaluations<Backend>
evaluate_affine_ciphertext_index_round(
    const typename Backend::EvalContext &eval, Reader &reader,
    const payload::LayerWireSupport &support,
    const AffineSparseSchedule &schedule,
    std::span<const detail::MixedPreparedFpkSlotBasis<Backend>>
        cached_prepared_bases,
    PreparedCiphertextIndexEqualities &ciphertext_index_equalities,
    const FoldedAffineRoundEvaluationPoints &evaluation_points,
    FoldedAffineStatistics &statistics);

template <fhe::FheBackend Backend, typename Reader>
fhe::ExtensionValue<Backend> evaluate_affine_slot_checkpoint(
    const typename Backend::EvalContext &eval, Reader &reader,
    const payload::LayerWireSupport &support,
    PreparedCiphertextIndexEqualities &ciphertext_index_equalities,
    FoldedAffineStatistics &statistics);

/// Owns source access and concrete FHE arithmetic for one affine reduction.
///
/// The protocol prover owns Fiat--Shamir, proof publication, and challenge
/// order. This evaluator owns the compact source reader, every rewind/scan,
/// source-level public-basis preparation, and the encrypted checkpoint passed
/// from ciphertext-index rounds to slot-index rounds. It never observes the
/// transcript and therefore cannot reorder a protocol message or challenge.
template <fhe::FheBackend Backend, typename TraceSource>
class FoldedAffineEvaluator {
  public:
    FoldedAffineEvaluator(
        const typename Backend::EvalContext &eval,
        const payload::LayeredCircuit &circuit, const TraceSource &trace,
        std::size_t layer,
        payload::LayerWireSupport source_support,
        AffineSparseSchedule schedule,
        std::size_t ciphertext_index_variables,
        FoldedAffineStatistics *statistics)
        : eval_(eval), trace_(trace), source_layer_(layer + 1U),
          source_support_(std::move(source_support)),
          schedule_(std::move(schedule)),
          ciphertext_index_equalities_(
              PreparedCiphertextIndexEqualities::create(
                  ciphertext_index_variables)),
          statistics_(statistics != nullptr ? statistics
                                            : &owned_statistics_) {
        validate_source(circuit);
    }

    /// Open the source and prepare immutable slot bases at its RNS level.
    ///
    /// This is deliberately an explicit operation rather than constructor
    /// work: the visible prover performs source admission first and shows this
    /// storage/FHE preparation before the first transcript message.
    void prepare_source_level_bases() {
        if (source_reader_) {
            throw std::logic_error(
                "LaminateFolded affine source was prepared twice");
        }
        *statistics_ = FoldedAffineStatistics{};
        statistics_->prepared_basis_count = schedule_.bases.size();
        statistics_->retained_public_claim_table_entries =
            schedule_.claim_boolean_values.size() *
            affine_slot_count(schedule_);
        statistics_->peak_transient_public_basis_entries =
            schedule_.bases.empty() ? 0 : affine_slot_count(schedule_);

        source_reader_.emplace(trace_.active_layer_reader(source_layer_));
        prepared_bases_ =
            folded_affine_detail::prepare_source_level_affine_bases<Backend>(
                eval_, reader(), schedule_, *statistics_);
    }

    /// Evaluate and slot-fold `R_j(1), R_j(2)` in one source-scan request.
    FoldedAffineRoundEvaluations<Backend> evaluate_ciphertext_index_round(
        const FoldedAffineRoundEvaluationPoints &evaluation_points) {
        FoldedAffineRoundEvaluations<Backend> evaluations =
            evaluate_affine_ciphertext_index_round<Backend>(
                eval_, reader(), source_support_, schedule_,
                prepared_bases_, ciphertext_index_equalities_,
                evaluation_points, *statistics_);
        evaluations.at_one =
            fhe::ext_fold<Backend>(eval_, evaluations.at_one);
        evaluations.at_two =
            fhe::ext_fold<Backend>(eval_, evaluations.at_two);
        return evaluations;
    }

    /// Fix the sampled ciphertext coordinate for the next source scan.
    void fix_ciphertext_index(const Fpk &challenge) {
        ciphertext_index_equalities_.bind(challenge);
        statistics_->ciphertext_index_equalities =
            ciphertext_index_equalities_.statistics();
    }

    /// Make the sole encrypted checkpoint consumed by all slot-index rounds.
    fhe::ExtensionValue<Backend> build_slot_checkpoint() {
        return evaluate_affine_slot_checkpoint<Backend>(
            eval_, reader(), source_support_, ciphertext_index_equalities_,
            *statistics_);
    }

    /// Restrict the public affine GateMLE after all ciphertext indices bind.
    PreparedAffineSlotWeights prepare_slot_index_gate_weights(
        std::span<const Fpk> ciphertext_index_point,
        std::size_t ciphertext_index_variables) {
        const std::vector<Fpk> basis_weights = affine_basis_weights(
            schedule_, ciphertext_index_point, ciphertext_index_variables,
            &ciphertext_index_equalities_);
        return PreparedAffineSlotWeights::create(schedule_, basis_weights);
    }

    /// Evaluate one slot-index round from the retained checkpoint only.
    FoldedAffineRoundEvaluations<Backend> evaluate_slot_index_round(
        const fhe::ExtensionValue<Backend> &checkpoint,
        const PreparedAffineSlotWeights &public_weights,
        std::span<const Fpk> slot_index_prefix,
        std::size_t slot_index_variables) {
        return affine_sparse_slot_round<Backend>(
            eval_, checkpoint, public_weights.round_weights(),
            slot_index_prefix, slot_index_variables,
            &statistics_->slot_rounds);
    }

    /// Evaluate the checkpoint at the final slot-index point.
    fhe::ExtensionValue<Backend> evaluate_terminal_source(
        const fhe::ExtensionValue<Backend> &checkpoint,
        std::span<const Fpk> slot_index_point) const {
        return fhe::partial_evaluate_slot_index_point<Backend>(
            eval_, checkpoint, slot_index_point);
    }

  private:
    using SourceReader = decltype(
        std::declval<const TraceSource &>().active_layer_reader(
            std::size_t{}));

    SourceReader &reader() {
        if (!source_reader_) {
            throw std::logic_error(
                "LaminateFolded affine source is not prepared");
        }
        return *source_reader_;
    }

    void validate_source(const payload::LayeredCircuit &circuit) const {
        const auto &descriptor = trace_.descriptor();
        if (circuit.shape.kind != payload::PayloadKind::Wide ||
            !(descriptor.shape == circuit.shape) ||
            !trace_.matches_backend_context(eval_) ||
            source_layer_ >= descriptor.layers.size() ||
            Backend::slot_count(eval_) != circuit.shape.slot_count ||
            source_support_.live_wire_count == 0) {
            throw std::invalid_argument(
                "LaminateFolded affine source identity mismatch");
        }
        const auto &source = descriptor.layers[source_layer_];
        if (source.layout != payload::TraceLayerLayout::Wide ||
            source.dimensions.padded_size !=
                source_support_.padded_wire_count ||
            source.record_count != source_support_.live_wire_count) {
            throw std::invalid_argument(
                "LaminateFolded affine source metadata mismatch");
        }
    }

    const typename Backend::EvalContext &eval_; ///< Concrete FHE context.
    const TraceSource &trace_; ///< Compact source owner, opened on `prepare`.
    std::size_t source_layer_; ///< Layer read by this affine reduction.
    payload::LayerWireSupport source_support_; ///< Live/padded source map.
    AffineSparseSchedule schedule_; ///< Public affine GateMLE decomposition.
    /// Rolling public equality table used by every source scan.
    PreparedCiphertextIndexEqualities ciphertext_index_equalities_;
    FoldedAffineStatistics owned_statistics_;
    FoldedAffineStatistics *statistics_; ///< Non-transcript diagnostics.
    /// Opened only by `prepare_source_level_bases`, before the first round.
    std::optional<SourceReader> source_reader_;
    /// Public slot bases cached at the source ciphertext's exact RNS level.
    std::vector<detail::MixedPreparedFpkSlotBasis<Backend>> prepared_bases_;
};

namespace folded_affine_ciphertext_round_detail {

using PreparedTerm = folded_affine_detail::PreparedTerm;
using TermsBySuffix = std::vector<std::vector<PreparedTerm>>;

/// Sparse public GateMLE terms restricted at X=1 and X=2.
using PublicGateTerms =
    ::laminate::gkr::detail::AffineRoundPair<TermsBySuffix>;

/// Encrypted SourceMLE contributions, separated by evaluation point and
/// public slot basis, for one bounded basis batch.
template <fhe::FheBackend Backend> struct CompactSourceProducts {
    explicit CompactSourceProducts(std::size_t basis_count)
        : by_round_point{
              .at_one = std::vector<
                  fhe::MixedExtensionAccumulator<Backend>>(basis_count),
              .at_two = std::vector<
                  fhe::MixedExtensionAccumulator<Backend>>(basis_count)} {}

    /// Partial sums for R_j(1) and R_j(2), indexed by the current slot basis.
    ::laminate::gkr::detail::AffineRoundPair<
        std::vector<fhe::MixedExtensionAccumulator<Backend>>>
        by_round_point;
    /// First encrypted source at this modulus level, used only to prepare a
    /// compatible public basis. Empty for an entirely public source.
    std::optional<typename Backend::Ciphertext> level_reference;
};

PublicGateTerms prepare_public_gate_mle_terms(
    const payload::LayerWireSupport &support,
    const AffineSparseSchedule &schedule,
    PreparedCiphertextIndexEqualities &ciphertext_index_equalities,
    const FoldedAffineRoundEvaluationPoints &evaluation_points,
    std::size_t suffix_count, std::size_t batch_begin,
    std::size_t batch_end, bool retain_zero_terms,
    FoldedAffineStatistics &statistics);

template <fhe::FheBackend Backend, typename Reader>
CompactSourceProducts<Backend> accumulate_compact_source(
    const typename Backend::EvalContext &eval, Reader &reader,
    const payload::LayerWireSupport &support,
    PreparedCiphertextIndexEqualities &ciphertext_index_equalities,
    const FoldedAffineRoundEvaluationPoints &evaluation_points,
    const PublicGateTerms &public_gate_terms, std::size_t suffix_count,
    std::size_t basis_count, bool retain_zero_terms,
    const FoldedAffineRoundEvaluations<Backend> &prior_results,
    FoldedAffineStatistics &statistics);

template <fhe::FheBackend Backend>
void apply_prepared_slot_bases(
    const typename Backend::EvalContext &eval,
    const AffineSparseSchedule &schedule,
    std::span<const detail::MixedPreparedFpkSlotBasis<Backend>>
        cached_prepared_bases,
    std::size_t batch_begin, std::size_t batch_end,
    CompactSourceProducts<Backend> &source_products,
    FoldedAffineRoundEvaluations<Backend> &results,
    FoldedAffineStatistics &statistics);

} // namespace folded_affine_ciphertext_round_detail

/// Evaluate one Folded affine ciphertext-index round under FHE.
///
/// Evaluate x=1 and x=2 at the current challenge prefix. Each bounded
/// slot-basis batch:
///
///  1. groups public gate weights by `(source-index suffix, slot basis)`;
///  2. scans the compact source once and performs the scalar-times-ciphertext
///     accumulations that form the SourceMLE products; and
///  3. applies the prepared slot bases and adds them into R_j(1), R_j(2).
///
/// The first phase is host-field work. The latter two contain the FHE
/// operations, whose exact boundaries are documented in their named helpers
/// below. Padded source positions are public zero, have no trace record, and
/// therefore cause no backend operation.
template <fhe::FheBackend Backend, typename Reader>
FoldedAffineRoundEvaluations<Backend>
evaluate_affine_ciphertext_index_round(
    const typename Backend::EvalContext &eval, Reader &reader,
    const payload::LayerWireSupport &support,
    const AffineSparseSchedule &schedule,
    std::span<const detail::MixedPreparedFpkSlotBasis<Backend>>
        cached_prepared_bases,
    PreparedCiphertextIndexEqualities &ciphertext_index_equalities,
    const FoldedAffineRoundEvaluationPoints &evaluation_points,
    FoldedAffineStatistics &statistics) {
    const std::size_t ciphertext_index_variables =
        ciphertext_index_equalities.variables();
    if (support.padded_wire_count !=
            poly::hypercube_size(ciphertext_index_variables) ||
        ciphertext_index_equalities.bound_variables() >=
            ciphertext_index_variables ||
        schedule.bases.empty() ||
        (!cached_prepared_bases.empty() &&
         (cached_prepared_bases.size() != schedule.bases.size() ||
          cached_prepared_bases.size() >
              kFoldedAffineCachedBasisLimit))) {
        throw std::invalid_argument(
            "LaminateFolded affine round shape mismatch");
    }
    const std::size_t suffix_count = poly::hypercube_size(
        ciphertext_index_variables -
        ciphertext_index_equalities.bound_variables() - 1U);
    const bool retain_zero_terms =
        fhe::forces_challenge_independent_topology<Backend>(eval);
    FoldedAffineRoundEvaluations<Backend> results;
    for (std::size_t batch_begin = 0;
         batch_begin < schedule.bases.size();
         batch_begin += kFoldedAffineCachedBasisLimit) {
        const std::size_t batch_end = std::min(
            schedule.bases.size(),
            batch_begin + kFoldedAffineCachedBasisLimit);
        const std::size_t batch_size = batch_end - batch_begin;
        // Step 1: GateMLE is public. Evaluate and combine its sparse terms before
        // reading any ciphertext.
        const auto public_gate_terms =
            folded_affine_ciphertext_round_detail::
                prepare_public_gate_mle_terms(
                support, schedule, ciphertext_index_equalities,
                evaluation_points,
                suffix_count, batch_begin, batch_end, retain_zero_terms,
                statistics);

        // Step 2: SourceMLE comes from the compact encrypted trace. This sequential
        // scan forms the encrypted GateMLE * SourceMLE contributions.
        auto source_products =
            folded_affine_ciphertext_round_detail::
                accumulate_compact_source<Backend>(
                eval, reader, support, ciphertext_index_equalities,
                         evaluation_points, public_gate_terms, suffix_count,
                         batch_size, retain_zero_terms, results, statistics);
        folded_affine_detail::checked_accumulate(
            statistics.ciphertext_index_round_basis_batches, 1,
            "Folded affine ciphertext-index round basis batches");

        // Step 3: Reconstruct the public slot-basis coordinate and add this batch to
        // the two transmitted round evaluations R_j(1), R_j(2).
        folded_affine_ciphertext_round_detail::
            apply_prepared_slot_bases<Backend>(
            eval, schedule, cached_prepared_bases, batch_begin, batch_end,
            source_products, results, statistics);
    }
    return results;
}

namespace folded_affine_ciphertext_round_detail {

inline PublicGateTerms prepare_public_gate_mle_terms(
    const payload::LayerWireSupport &support,
    const AffineSparseSchedule &schedule,
    PreparedCiphertextIndexEqualities &ciphertext_index_equalities,
    const FoldedAffineRoundEvaluationPoints &evaluation_points,
    std::size_t suffix_count, std::size_t batch_begin,
    std::size_t batch_end, bool retain_zero_terms,
    FoldedAffineStatistics &statistics) {
    PublicGateTerms by_suffix{
        .at_one = TermsBySuffix(suffix_count),
        .at_two = TermsBySuffix(suffix_count)};
    for (const AffineSparseTerm &term : schedule.terms) {
        if (term.source >= support.padded_wire_count ||
            term.basis >= schedule.bases.size()) {
            throw std::logic_error(
                "LaminateFolded affine public schedule is invalid");
        }
        if (term.basis < batch_begin || term.basis >= batch_end) {
            continue;
        }
        const auto restrict_term_at =
            [&](const Fpk &point, TermsBySuffix &restricted_terms) {
            const Fpk gate_weight =
                term.coefficient * ciphertext_index_equalities.evaluate(
                                       term.source, point);
            folded_affine_detail::checked_accumulate(
                statistics.public_term_visits, 1,
                "Folded affine public term visits");
            if (retain_zero_terms || !gate_weight.is_zero()) {
                restricted_terms[term.source & (suffix_count - 1U)]
                    .push_back(PreparedTerm{
                        term.basis - batch_begin, gate_weight});
            }
        };
        restrict_term_at(evaluation_points.at_one, by_suffix.at_one);
        restrict_term_at(evaluation_points.at_two, by_suffix.at_two);
    }
    const auto reduce_terms = [](TermsBySuffix &terms) {
        for (auto &suffix : terms) {
            folded_affine_detail::reduce_prepared_terms(suffix);
        }
    };
    reduce_terms(by_suffix.at_one);
    reduce_terms(by_suffix.at_two);
    return by_suffix;
}

template <fhe::FheBackend Backend, typename Reader>
CompactSourceProducts<Backend> accumulate_compact_source(
    const typename Backend::EvalContext &eval, Reader &reader,
    const payload::LayerWireSupport &support,
    PreparedCiphertextIndexEqualities &ciphertext_index_equalities,
    const FoldedAffineRoundEvaluationPoints &evaluation_points,
    const PublicGateTerms &public_gate_terms, std::size_t suffix_count,
    std::size_t basis_count, bool retain_zero_terms,
    const FoldedAffineRoundEvaluations<Backend> &prior_results,
    FoldedAffineStatistics &statistics) {
    // There are two accumulators per basis: one for R_j(1), one for R_j(2).
    // Only the current bounded basis batch remains resident.
    CompactSourceProducts<Backend> products(basis_count);
    folded_affine_detail::scan_active_source(
        reader, support, statistics,
        [&](std::size_t padded_index, const auto &source) {
            if (!products.level_reference) {
                if (const auto *encrypted =
                        folded_affine_detail::
                            encrypted_ciphertext_ptr<Backend>(source)) {
                    products.level_reference = *encrypted;
                }
            }
            const std::size_t suffix =
                padded_index & (suffix_count - 1U);
            const auto accumulate_at_point =
                [&](const Fpk &point,
                    const TermsBySuffix &gate_terms,
                    std::vector<fhe::MixedExtensionAccumulator<Backend>>
                        &basis_products) {
                if (gate_terms[suffix].empty()) {
                    return;
                }
                const Fpk source_weight =
                    ciphertext_index_equalities.evaluate(
                        padded_index, point);
                if (source_weight.is_zero() && !retain_zero_terms) {
                    return;
                }
                for (const PreparedTerm &term : gate_terms[suffix]) {
                    folded_affine_detail::checked_accumulate(
                        statistics.source_basis_visits, 1,
                        "Folded affine source-basis visits");
                    const Fpk term_weight =
                        source_weight * term.coefficient;
                    if (!retain_zero_terms && term_weight.is_zero()) {
                        continue;
                    }
                    // FHE boundary: multiply the source ciphertext by its
                    // public extension-field weight, then add it to this
                    // slot basis's SourceMLE product.
                    basis_products[term.basis]
                        .accumulate_scaled_base(eval, source, term_weight);
                    folded_affine_detail::checked_accumulate(
                        statistics.scalar_source_promotions, 1,
                        "Folded affine scalar source promotions");
                }
            };
            accumulate_at_point(
                evaluation_points.at_one, public_gate_terms.at_one,
                products.by_round_point.at_one);
            accumulate_at_point(
                evaluation_points.at_two, public_gate_terms.at_two,
                products.by_round_point.at_two);

            std::size_t retained =
                static_cast<std::size_t>(
                    !prior_results.at_one.is_public_zero()) +
                static_cast<std::size_t>(
                    !prior_results.at_two.is_public_zero());
            const auto nonempty_products = [](const auto &values) {
                return static_cast<std::size_t>(std::count_if(
                    values.begin(), values.end(),
                    [](const auto &value) { return !value.empty(); }));
            };
            retained += nonempty_products(products.by_round_point.at_one);
            retained += nonempty_products(products.by_round_point.at_two);
            statistics.peak_retained_extension_accumulators = std::max(
                statistics.peak_retained_extension_accumulators, retained);
        });
    return products;
}

template <fhe::FheBackend Backend>
void apply_prepared_slot_bases(
    const typename Backend::EvalContext &eval,
    const AffineSparseSchedule &schedule,
    std::span<const detail::MixedPreparedFpkSlotBasis<Backend>>
        cached_prepared_bases,
    std::size_t batch_begin, std::size_t batch_end,
    CompactSourceProducts<Backend> &source_products,
    FoldedAffineRoundEvaluations<Backend> &results,
    FoldedAffineStatistics &statistics) {
    const std::size_t batch_size = batch_end - batch_begin;
    std::vector<detail::MixedPreparedFpkSlotBasis<Backend>> local_prepared;
    std::span<const detail::MixedPreparedFpkSlotBasis<Backend>> prepared;
    if (!cached_prepared_bases.empty()) {
        prepared = cached_prepared_bases.subspan(batch_begin, batch_size);
    } else {
        local_prepared.reserve(batch_size);
        for (std::size_t basis = batch_begin; basis < batch_end; ++basis) {
            const std::vector<Fpk> values =
                affine_slot_basis_values(schedule, basis);
            local_prepared.push_back(
                detail::prepare_mixed_fpk_slot_basis<Backend>(
                    eval,
                    source_products.level_reference
                        ? &*source_products.level_reference
                        : nullptr,
                    values));
            record_prepared_affine_basis<Backend>(
                local_prepared.back(), statistics);
        }
        prepared = local_prepared;
    }
    statistics.peak_retained_prepared_bases = std::max(
        statistics.peak_retained_prepared_bases, prepared.size());

    const auto apply_at_point =
        [&](std::vector<fhe::MixedExtensionAccumulator<Backend>>
                &basis_products,
            fhe::ExtensionValue<Backend> &round_evaluation) {
        for (std::size_t basis = 0; basis < batch_size; ++basis) {
            auto &product = basis_products[basis];
            if (product.empty()) {
                continue;
            }
            // FHE boundary: apply the immutable packed-slot basis to this
            // aggregate, then add it to the round message R_j(x).
            fhe::extension_add_assign<Backend>(
                eval, round_evaluation,
                detail::apply_mixed_prepared_basis<Backend>(
                    eval, std::move(product), prepared[basis]));
            folded_affine_detail::checked_accumulate(
                statistics.prepared_basis_applications, 1,
                "Folded affine prepared-basis applications");
            folded_affine_detail::checked_accumulate(
                statistics.avoided_online_slot_vector_elements,
                folded_affine_detail::checked_u64(
                    Backend::slot_count(eval),
                    "Folded affine avoided online vector elements"),
                "Folded affine avoided online vector elements");
        }
    };
    apply_at_point(source_products.by_round_point.at_one, results.at_one);
    apply_at_point(source_products.by_round_point.at_two, results.at_two);
}

} // namespace folded_affine_ciphertext_round_detail

/// Bind every ciphertext-index variable and retain the packed-slot checkpoint.
///
/// For the complete ciphertext-index point `r_ct`, this compact scan computes
///
///   checkpoint(slots) = sum_u eq(r_ct, u) * Source(u, slots).
///
/// The checkpoint is the sole encrypted source value used by the later slot
/// rounds and terminal evaluation. Each live source contributes one public
/// scalar-times-ciphertext accumulation; omitted padding contributes zero
/// without allocating or encrypting a placeholder.
template <fhe::FheBackend Backend, typename Reader>
fhe::ExtensionValue<Backend> evaluate_affine_slot_checkpoint(
    const typename Backend::EvalContext &eval, Reader &reader,
    const payload::LayerWireSupport &support,
    PreparedCiphertextIndexEqualities &ciphertext_index_equalities,
    FoldedAffineStatistics &statistics) {
    if (ciphertext_index_equalities.domain_size() !=
            support.padded_wire_count ||
        ciphertext_index_equalities.bound_variables() !=
            ciphertext_index_equalities.variables()) {
        throw std::invalid_argument(
            "LaminateFolded affine checkpoint point is incomplete");
    }
    fhe::MixedExtensionAccumulator<Backend> accumulator;
    folded_affine_detail::scan_active_source(
        reader, support, statistics,
        [&](std::size_t padded_index, const auto &source) {
            // FHE kernel: one weighted source accumulation at r_ct.
            accumulator.accumulate_scaled_base(
                eval, source,
                ciphertext_index_equalities.fixed(padded_index));
            statistics.peak_retained_extension_accumulators = std::max(
                statistics.peak_retained_extension_accumulators,
                std::size_t{1});
        });
    return std::move(accumulator).finish(eval);
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_AFFINE_EVALUATOR_HPP
