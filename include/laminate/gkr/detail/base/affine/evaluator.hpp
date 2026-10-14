#ifndef LAMINATE_GKR_DETAIL_BASE_AFFINE_EVALUATOR_HPP
#define LAMINATE_GKR_DETAIL_BASE_AFFINE_EVALUATOR_HPP

/// @file evaluator.hpp
/// @brief FHE round evaluation for production Base affine reductions.

#include "laminate/gkr/detail/base/affine/types.hpp"
#include "laminate/gkr/detail/base/affine/internal/basis_batches.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::base_detail {

/// File-backed FHE evaluator for one LaminateBase affine reduction.
///
/// The protocol prover asks this object only for the mathematical values it
/// needs: the two evaluations in the next ciphertext-index round, and the
/// terminal source MLE after every ciphertext index has been fixed. This
/// object owns the rewindable source reader, public GateMLE restriction,
/// equality-prefix weights, and prepared slot-basis cache needed to compute
/// those values. Reader cursors, decoding, batching, and cache lifetime never
/// enter the proof/transcript control flow.
///
/// After challenges `r_0, ..., r_{j-1}` have been bound, the evaluator's
/// invariant is that both `rolling_gate_` and `source_prefix_` represent that
/// exact prefix. `bind_ciphertext_index_challenge` advances both together.
template <fhe::FheBackend Backend, typename TraceSource>
class BaseAffineEvaluator {
  public:
    BaseAffineEvaluator(
        const typename Backend::EvalContext &eval,
        const payload::LayeredCircuit &circuit, const TraceSource &trace,
        const BaseAffineSourceAdmission &source_admission,
        const payload::LayerWireSupport &source_support,
        std::size_t layer, const LayerClaim &claim,
        const gates::DirectGateMle &provider,
        const AffineGeometry &geometry,
        BaseAffineStatistics *statistics = nullptr);

    /// Compute R_j(1) and R_j(2) for the next ciphertext-index round.
    EncryptedAffineRoundEvaluations<Backend>
    evaluate_ciphertext_index_round();

    /// Fix the next verifier challenge in every public evaluation factor.
    void bind_ciphertext_index_challenge(const Fpk &challenge);

    /// Compute W(r_ct; slot) after all ciphertext indices are fixed.
    fhe::ExtensionValue<Backend> evaluate_terminal_source();

  private:
    using SourceReader = decltype(
        std::declval<const TraceSource &>().active_layer_reader(
            std::size_t{}));

    void validate_source(
        const payload::LayeredCircuit &circuit, const TraceSource &trace,
        std::size_t layer) const;

    const typename Backend::EvalContext &eval_;
    /// Compact live-wire support; omitted padded entries are plaintext zero.
    payload::LayerWireSupport support_;
    /// Public sparse GateMLE representation restricted after each challenge.
    PreparedAffineGateMle prepared_gate_;
    std::vector<PreparedAffineGateMle::Basis> rotation_bases_;
    PreparedAffineGateMle::RollingBinding rolling_gate_;
    /// Equality weights eq(r_ct, source_index) for compact active records.
    base_affine_detail::SparseSourcePrefixWeights source_prefix_;
    /// The only raw file-reader state in the production affine reduction.
    SourceReader source_reader_;
    /// Public bases prepared lazily at the source ciphertext's exact level.
    std::vector<fhe::PreparedFpkSlotBasis<Backend>> prepared_bases_;
    std::size_t ciphertext_index_variables_ = 0;
    std::size_t slot_index_variables_ = 0;
    BaseAffineStatistics *statistics_ = nullptr;
};

/// Evaluate the two encrypted messages sent in one Base affine sumcheck round.
///
/// The kernel evaluates x=1 and x=2 at the current challenge prefix:
///
/// 1. restrict the public GateMLE and equality prefix at x=1 and x=2;
/// 2. rewind and scan the compact encrypted source `W`;
/// 3. accumulate public-scalar times ciphertext terms by rotation basis;
/// 4. multiply those aggregates by prepared public slot polynomials and add
///    the basis results into `R_j(1)` and `R_j(2)`.
///
/// Each source pass handles a bounded rotation-basis batch. A record's padded
/// index supplies its Boolean suffix and branch. Omitted positions are the
/// public zero polynomial and cause no backend call. There is no
/// ciphertext-ciphertext multiplication in an affine reduction.
template <fhe::FheBackend Backend, typename Reader>
EncryptedAffineRoundEvaluations<Backend>
evaluate_base_affine_ciphertext_index_round(
    const typename Backend::EvalContext &eval, Reader &reader,
    const payload::LayerWireSupport &support,
    const PreparedAffineGateMle &prepared_gate,
    std::span<const PreparedAffineGateMle::Basis> rotation_bases,
    const PreparedAffineGateMle::RollingBinding &rolling_gate,
    const base_affine_detail::SparseSourcePrefixWeights &
        source_prefix,
    const AffineRoundEvaluationPoints &evaluation_points,
    std::size_t ciphertext_index_variables,
    std::size_t slot_index_variables,
    BaseAffineStatistics *statistics = nullptr,
    std::vector<fhe::PreparedFpkSlotBasis<Backend>>
        *reduction_prepared_bases = nullptr) {
    using namespace base_affine_detail;

    // Step 1: restrict the two public factors at X=1 and X=2. This performs
    // field arithmetic only; no ciphertext has been read yet.
    const AffineRoundRestriction round = restrict_affine_round(
        support, prepared_gate, rotation_bases, rolling_gate, source_prefix,
        evaluation_points, ciphertext_index_variables, statistics);
    if (round.rotation_bases.empty()) {
        // Public duplicate cancellation can make the complete affine matrix
        // zero. Both evaluations are then symbolic plaintext zero.
        return {};
    }

    // Step 2: choose the bounded public-basis cache policy for this reduction.
    AffineRoundSums<Backend> round_sums;
    const bool retain_challenge_zero_terms =
        fhe::forces_challenge_independent_topology<Backend>(eval);
    const bool cache_complete_reduction =
        round.rotation_bases.size() <=
            kResidentAffineRotationBasisLimit &&
        reduction_prepared_bases != nullptr;
    if (cache_complete_reduction &&
        !reduction_prepared_bases->empty() &&
        reduction_prepared_bases->size() !=
            round.rotation_bases.size()) {
        throw std::logic_error(
            "LaminateBase affine prepared basis count drifted");
    }

    // Step 3: process one bounded rotation-basis batch at a time. The helpers
    // below are the three concrete FHE phases: scan and accumulate
    // public-scalar*ciphertext terms, prepare public slot polynomials, then
    // apply those plaintext polynomials to the encrypted accumulators.
    for (std::size_t batch_begin = 0;
         batch_begin < round.rotation_bases.size();
         batch_begin += kResidentAffineRotationBasisLimit) {
        const std::size_t batch_end = std::min(
            round.rotation_bases.size(),
            batch_begin + kResidentAffineRotationBasisLimit);

        // 3a. One sequential pass over compact live source ciphertexts.
        auto batch = scan_rotation_basis_batch<Backend>(
            eval, reader, support, round, source_prefix, evaluation_points,
            batch_begin, batch_end, retain_challenge_zero_terms,
            round_sums, statistics);

        // 3b. Prepare the public slot polynomials at the source's level.
        std::vector<fhe::PreparedFpkSlotBasis<Backend>> local_prepared;
        const auto prepared = prepare_rotation_basis_batch<Backend>(
            eval, round, batch, batch_begin, batch_end,
            slot_index_variables,
            cache_complete_reduction, reduction_prepared_bases,
            local_prepared, statistics);

        // 3c. Plaintext-multiply and add into R_j(1), R_j(2).
        apply_rotation_basis_batch<Backend>(
            eval, round, std::move(batch), batch_begin, prepared,
            round_sums, statistics);
    }

    // Step 4: finalize the two sparse extension accumulators. Known public
    // zeros remain symbolic and never invoke `encrypt_zero`.
    return finish_affine_round<Backend>(eval, std::move(round_sums));
}

/// Evaluate the source MLE at the complete Fiat--Shamir ciphertext-index
/// point with one final compact scan:
///
///   W(r_ct; s) = sum_i eq(r_ct, i) W_i(s).
///
/// SIMD slot variables remain packed in the result. This pass is linear and
/// performs no ciphertext-ciphertext multiplication.
template <fhe::FheBackend Backend, typename Reader>
fhe::ExtensionValue<Backend> evaluate_base_affine_terminal_source(
    const typename Backend::EvalContext &eval, Reader &reader,
    const payload::LayerWireSupport &support,
    const base_affine_detail::SparseSourcePrefixWeights &
        source_prefix,
    BaseAffineStatistics *statistics = nullptr) {
    if (support.padded_wire_count !=
            poly::hypercube_size(source_prefix.variables()) ||
        source_prefix.bound_variables() != source_prefix.variables()) {
        throw std::invalid_argument(
            "LaminateBase affine terminal point has wrong domain");
    }
    if (source_prefix.variables() == 0) {
        // Step 1a: a one-point ciphertext-index domain needs one live value.
        std::optional<fhe::FheValue<Backend>> source_value;
        base_affine_detail::scan_active_source<Backend>(
            reader, support, statistics,
            [&](std::size_t, std::size_t,
                const fhe::FheValue<Backend> &value) {
                if (source_value) {
                    throw std::logic_error(
                        "LaminateBase zero-variable affine source has "
                        "multiple live values");
                }
                source_value = value;
            });
        if (!source_value) {
            return {};
        }
        return fhe::promote_extension_value<Backend>(
            eval, *source_value, Fpk::one());
    }

    fhe::SparseExtensionAccumulator<Backend> encrypted_sum;
    fhe::ExtensionValue<Backend> public_sum;

    // Step 1b: otherwise accumulate each compact live value with its public
    // eq(r_ct,i) coefficient. Omitted padded wires are never visited.
    base_affine_detail::scan_active_source<Backend>(
        reader, support, statistics,
        [&](std::size_t live_ordinal, std::size_t padded_index,
            const fhe::FheValue<Backend> &source_value) {
            const Fpk weight = source_prefix.complete_at(
                live_ordinal, padded_index);
            if (source_value.is_public()) {
                fhe::extension_add_assign<Backend>(
                    eval, public_sum,
                    fhe::promote_extension_value<Backend>(
                        eval, source_value, weight));
            } else {
                encrypted_sum.accumulate_scaled_base(
                    eval, source_value.ciphertext(), weight);
            }
            if (statistics != nullptr && source_value.is_encrypted()) {
                statistics->peak_retained_extension_accumulators =
                    std::max(
                        statistics->peak_retained_extension_accumulators,
                        std::size_t{1});
            }
        });

    // Step 2: combine encrypted and known-public contributions. A wholly
    // public zero result stays symbolic.
    fhe::ExtensionValue<Backend> result(
        std::move(encrypted_sum).finish());
    fhe::extension_add_assign<Backend>(eval, result,
                                       std::move(public_sum));
    return result;
}

template <fhe::FheBackend Backend, typename TraceSource>
BaseAffineEvaluator<Backend, TraceSource>::BaseAffineEvaluator(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit, const TraceSource &trace,
    const BaseAffineSourceAdmission &source_admission,
    const payload::LayerWireSupport &source_support, std::size_t layer,
    const LayerClaim &claim, const gates::DirectGateMle &provider,
    const AffineGeometry &geometry, BaseAffineStatistics *statistics)
    : eval_(eval), support_(source_support),
      prepared_gate_(PreparedAffineGateMle::create(provider, layer, claim)),
      rotation_bases_(prepared_gate_.bases()),
      rolling_gate_(prepared_gate_.rolling_source_wire_binding()),
      source_prefix_(support_),
      source_reader_(trace.active_layer_reader(layer + 1U)),
      ciphertext_index_variables_(geometry.ciphertext_index_variables),
      slot_index_variables_(geometry.slot_index_variables),
      statistics_(statistics) {
    source_admission.require_matches(circuit, trace);
    validate_source(circuit, trace, layer);
    if (statistics_ != nullptr) {
        *statistics_ = BaseAffineStatistics{};
    }
}

template <fhe::FheBackend Backend, typename TraceSource>
EncryptedAffineRoundEvaluations<Backend>
BaseAffineEvaluator<Backend, TraceSource>::
    evaluate_ciphertext_index_round() {
    const AffineRoundEvaluationPoints points;
    return evaluate_base_affine_ciphertext_index_round<Backend>(
        eval_, source_reader_, support_, prepared_gate_, rotation_bases_,
        rolling_gate_, source_prefix_, points,
        ciphertext_index_variables_, slot_index_variables_, statistics_,
        &prepared_bases_);
}

template <fhe::FheBackend Backend, typename TraceSource>
void BaseAffineEvaluator<Backend, TraceSource>::
    bind_ciphertext_index_challenge(const Fpk &challenge) {
    rolling_gate_.bind(challenge);
    source_prefix_.bind(challenge, statistics_);
    if (statistics_ != nullptr) {
        base_affine_detail::checked_accumulate(
            statistics_->public_gate_term_weight_updates,
            base_affine_detail::checked_u64(
                prepared_gate_.weighted_term_count(),
                "Base affine gate term weight updates"),
            "Base affine gate term weight updates");
    }
}

template <fhe::FheBackend Backend, typename TraceSource>
fhe::ExtensionValue<Backend>
BaseAffineEvaluator<Backend, TraceSource>::evaluate_terminal_source() {
    return evaluate_base_affine_terminal_source<Backend>(
        eval_, source_reader_, support_, source_prefix_, statistics_);
}

template <fhe::FheBackend Backend, typename TraceSource>
void BaseAffineEvaluator<Backend, TraceSource>::validate_source(
    const payload::LayeredCircuit &circuit, const TraceSource &trace,
    std::size_t layer) const {
    const auto &descriptor = trace.descriptor();
    if (circuit.shape.kind != payload::PayloadKind::Wide ||
        !(descriptor.shape == circuit.shape) ||
        !trace.matches_backend_context(eval_) ||
        layer + 1U >= descriptor.layers.size() ||
        Backend::slot_count(eval_) != descriptor.shape.slot_count) {
        throw std::invalid_argument(
            "LaminateBase affine trace shape mismatch");
    }
    const auto &source = descriptor.layers[layer + 1U];
    if (source.layout != decltype(source.layout)::Wide ||
        !(source.dimensions ==
          payload::layer_dimensions(circuit.layers[layer + 1U])) ||
        source.dimensions.padded_size != support_.padded_wire_count ||
        source.record_count != support_.live_wire_count ||
        support_.live_wire_count == 0) {
        throw std::invalid_argument(
            "LaminateBase affine source metadata mismatch");
    }
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_AFFINE_EVALUATOR_HPP
