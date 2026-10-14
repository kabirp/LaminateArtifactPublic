#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_EVALUATOR_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_EVALUATOR_HPP

/// @file evaluator.hpp
/// @brief File-backed FHE evaluator for one LaminateLaned affine reduction.

#include "laminate/gkr/detail/laned/affine/source/prefix_weights.hpp"
#include "laminate/gkr/detail/laned/affine/source/prepared_bases.hpp"
#include "laminate/gkr/detail/laned/affine/source/chunk_batches.hpp"
#include "laminate/gkr/detail/laned/affine/source/materialized_packing.hpp"
#include "laminate/gkr/detail/laned/affine/source/scan.hpp"
#include "laminate/gkr/detail/laned/affine/types.hpp"
#include "laminate/gkr/detail/laned/validation/request.hpp"
#include "laminate/gkr/laned.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::laned_detail {

/// Owns file access and concrete FHE arithmetic for one affine reduction.
///
/// The protocol prover decides which polynomial to evaluate, binds messages,
/// and samples challenges. This evaluator implements those requests with
/// sequential source scans and retains only prepared public bases plus the
/// reader. It never observes or advances Fiat--Shamir.
template <fhe::PersistableFheBackend Backend, typename TraceSource>
class LanedAffineEvaluator {
    using SourceReader = decltype(
        std::declval<const TraceSource &>().active_layer_reader(
            std::size_t{}));

    static bool has_eager_packed_source(
        const TraceSource &trace) {
        if constexpr (requires {
                          trace.uses_eager_laned_witness_packing();
                      }) {
            return trace.uses_eager_laned_witness_packing();
        }
        return false;
    }

    static std::optional<SourceReader> open_unpacked_source(
        const TraceSource &trace, std::size_t source_layer) {
        if (has_eager_packed_source(trace)) {
            return std::nullopt;
        }
        return trace.active_layer_reader(source_layer);
    }

  public:
    LanedAffineEvaluator(
        const typename Backend::EvalContext &eval,
        const TraceSource &trace, std::size_t layer,
        const LanedAffineLayerReductionGeometry &geometry,
        std::size_t expected_rns_limbs,
        LanedAffineStatistics *statistics)
        : eval_(eval), trace_(trace), source_layer_(layer + 1U),
          source_layout_(geometry.source),
          source_support_(geometry.source_support),
          lane_weights_(geometry.lane_weights),
          source_reader_(open_unpacked_source(trace, layer + 1U)),
          expected_rns_limbs_(expected_rns_limbs),
          statistics_(statistics) {
        validate_source(trace, layer);
    }

    bool uses_materialized_packed_source() const {
        return affine_detail::use_materialized_packed_source(
            source_layout_);
    }

    bool source_is_eagerly_packed() const {
        return has_eager_packed_source(trace_);
    }

    std::size_t source_preparation_work_units() const {
        return source_is_eagerly_packed()
                   ? source_layout_.logical_ciphertext_count
                   : source_support_.live_wire_count;
    }

    std::size_t ciphertext_index_work_units() const {
        return uses_materialized_packed_source()
                   ? source_layout_.logical_ciphertext_count
                   : source_support_.live_wire_count;
    }

    /// Build the challenge-independent S/N packed source selected for small
    /// packed domains. The streaming fallback deliberately does nothing.
    template <typename Progress>
    void prepare_source(Progress &&progress) {
        if (!uses_materialized_packed_source()) {
            return;
        }
        if (materialized_source_.built()) {
            return;
        }
        if (has_eager_packed_source(trace_)) {
            if constexpr (requires {
                              trace_.laned_packed_layer_reader(
                                  source_layer_);
                              trace_.laned_packed_layer_layout(
                                  source_layer_);
                              trace_.laned_packed_layer_rns_limbs(
                                  source_layer_);
                          }) {
                if (!(trace_.laned_packed_layer_layout(source_layer_) ==
                      source_layout_) ||
                    trace_.laned_packed_layer_rns_limbs(source_layer_) !=
                        expected_rns_limbs_) {
                    throw std::invalid_argument(
                        "Laned affine eager packed source metadata "
                        "mismatch");
                }
                auto reader =
                    trace_.laned_packed_layer_reader(source_layer_);
                materialized_source_.load_packed(
                    reader, source_layout_,
                    [&](const fhe::FheValue<Backend> &source) {
                        validate_encrypted_source_level(source);
                    },
                    statistics_);
                progress(source_layout_.logical_ciphertext_count,
                         source_layout_.logical_ciphertext_count);
                return;
            }
        }
        if (!source_reader_) {
            throw std::logic_error(
                "Laned affine unpacked source reader is unavailable");
        }
        materialized_source_.build(
            eval_, *source_reader_, source_layout_, source_support_,
            [&](const fhe::FheValue<Backend> &source) {
                validate_encrypted_source_level(source);
            },
            std::forward<Progress>(progress), statistics_);
    }

    void prepare_source() {
        prepare_source([](std::size_t, std::size_t) {});
    }

    /// Evaluate `R_j(1)` and `R_j(2)` for one ciphertext-index round.
    ///
    /// For `a` in `{1, 2}`, the scan computes
    ///
    ///   R_j(a) = FoldSlots(sum_w eq(prefix || a, packed(w))
    ///                            * gate_a[suffix(w)] * PlaceLanes(W[w])).
    ///
    /// Both points share one scan. Affine evaluation uses public-scalar times
    /// ciphertext operations, additions, prepared public lane placement,
    /// rotations, and a final slot fold; it has no ciphertext multiplication.
    LanedAffineRoundEvaluations<Backend>
    evaluate_ciphertext_index_round(
        const LanedAffineGateRestrictions &gate_values,
        std::span<const Fpk> prefix,
        const LanedAffineRoundEvaluationPoints &round_points) {
        const std::size_t ciphertext_index_variables = log2_exact(
            source_layout_.padded_ciphertext_count,
            "LaminateLaned affine ciphertext variables");

        // FHE Step 1: Build the public equality weights for R_j(1) and
        // R_j(2). The public gate table has already been restricted by the
        // protocol prover to the matching suffix.
        using PublicVectors =
            ::laminate::gkr::detail::AffineRoundPair<std::vector<Fpk>>;
        PublicVectors bounds;
        PublicVectors witness_prefix_weights;
        const auto prepare_endpoint =
            [&](const Fpk &point, const std::vector<Fpk> &gate_suffix,
                std::vector<Fpk> &bound,
                std::vector<Fpk> &prefix_weights) {
            bound.assign(prefix.begin(), prefix.end());
            bound.push_back(point);
            if (bound.size() > ciphertext_index_variables) {
                throw std::invalid_argument(
                    "LaminateLaned affine ciphertext prefix is too long");
            }
            if (gate_suffix.empty() ||
                (gate_suffix.size() & (gate_suffix.size() - 1U)) != 0U) {
                throw std::invalid_argument(
                    "LaminateLaned affine gate suffix is malformed");
            }
            prefix_weights =
                affine_detail::cached_prefix_weights(bound, statistics_);
        };
        prepare_endpoint(
            round_points.at_one, gate_values.at_one, bounds.at_one,
            witness_prefix_weights.at_one);
        prepare_endpoint(
            round_points.at_two, gate_values.at_two, bounds.at_two,
            witness_prefix_weights.at_two);
        validate_round_shape();

        if (uses_materialized_packed_source()) {
            prepare_source();
            return materialized_source_.evaluate_ciphertext_round(
                eval_, source_layout_, lane_weights_, gate_values,
                witness_prefix_weights.at_one,
                witness_prefix_weights.at_two,
                ciphertext_index_variables, statistics_);
        }

        // FHE Step 2: Visit every live source wire once through bounded,
        // indexed chunk batches. For each evaluation point, multiply W[w]
        // by its public Fpk coefficient and add it to that chunk's extension
        // accumulator. Only 64 chunks are resident at once, including when
        // B=1 and the full layer contains N chunks.
        const std::size_t chunks = source_layout_.chunks_per_ciphertext();
        const std::size_t chunks_per_batch =
            affine_detail::laned_affine_chunks_per_batch(chunks);
        const bool retain_zero_terms =
            fhe::forces_challenge_independent_topology<Backend>(eval_);
        using MixedExtension = fhe::MixedExtensionAccumulator<Backend>;
        LanedAffineRoundEvaluations<Backend> placed_results;
        affine_detail::ensure_prepared_lane_bases<Backend>(
            eval_, nullptr, source_layout_, lane_weights_,
            prepared_lane_bases_, statistics_);
        auto scan = affine_detail::begin_batched_source_scan(
            *source_reader_, source_support_.live_wire_count, statistics_);
        for (std::size_t batch_begin = 0; batch_begin < chunks;
             batch_begin += chunks_per_batch) {
            const std::size_t batch_end =
                std::min(chunks, batch_begin + chunks_per_batch);
            const std::size_t batch_size = batch_end - batch_begin;
            ::laminate::gkr::detail::AffineRoundPair<
                std::vector<MixedExtension>>
                chunk_aggregates{
                    .at_one = std::vector<MixedExtension>(batch_size),
                    .at_two = std::vector<MixedExtension>(batch_size)};
            ::laminate::gkr::detail::AffineRoundPair<std::size_t>
                present_chunk_aggregates{};
            note_chunk_batch(batch_size);

            scan_chunk_batch(
                batch_begin, batch_end, scan,
                [&](std::size_t wire,
                    const fhe::FheValue<Backend> &source) {
                    prepare_encrypted_source_level(source);
                    const std::size_t packed = wire / chunks;
                    const std::size_t local_chunk =
                        wire % chunks - batch_begin;
                    const auto accumulate_at_endpoint =
                        [&](const std::vector<Fpk> &prefix_weights,
                            const std::vector<Fpk> &gate_suffix,
                            std::vector<MixedExtension> &aggregates,
                            std::size_t &present_aggregates) {
                        const Fpk witness_interpolation =
                            affine_detail::cached_prefix_weight(
                                prefix_weights, packed,
                                ciphertext_index_variables, statistics_);
                        const Fpk gate = gate_suffix[
                            wire & (gate_suffix.size() - 1U)];
                        const Fpk coefficient =
                            witness_interpolation * gate;
                        if (coefficient.is_zero() && !retain_zero_terms) {
                            return;
                        }
                        auto &aggregate = aggregates[local_chunk];
                        const bool introduced_accumulator =
                            aggregate.empty();
                        accumulate_laned_scalar_source<Backend>(
                            eval_, aggregate, source, coefficient);
                        affine_detail::note_scalar_promotion_and_peak(
                            introduced_accumulator, present_aggregates,
                            statistics_);
                    };
                    accumulate_at_endpoint(
                        witness_prefix_weights.at_one, gate_values.at_one,
                        chunk_aggregates.at_one,
                        present_chunk_aggregates.at_one);
                    accumulate_at_endpoint(
                        witness_prefix_weights.at_two, gate_values.at_two,
                        chunk_aggregates.at_two,
                        present_chunk_aggregates.at_two);
                    note_combined_accumulator_peak(
                        present_chunk_aggregates);
                });

            // Each chunk is placed exactly once. Combining batch results
            // before the final slot fold preserves the unbatched equation and
            // its FHE operation count.
            accumulate_placed_batch(
                placed_results.at_one, chunk_aggregates.at_one,
                batch_begin, chunks);
            accumulate_placed_batch(
                placed_results.at_two, chunk_aggregates.at_two,
                batch_begin, chunks);
        }
        affine_detail::finish_batched_source_scan(
            *source_reader_, source_support_.live_wire_count, scan,
            statistics_);

        // FHE Step 3: Apply the prepared public lane mask, rotate each chunk
        // into position as each batch finishes, then fold the two complete
        // placed slot tables once.
        return {
            .at_one = fhe::ext_fold<Backend>(eval_, placed_results.at_one),
            .at_two = fhe::ext_fold<Backend>(eval_, placed_results.at_two),
        };
    }

    /// Build the extension checkpoint reused by every slot-index round.
    ///
    /// After fixing the ciphertext-index point `r_ct`, this computes
    ///
    ///   C = sum_w eq(r_ct, packed(w)) * PlaceLanes(W[w]).
    ///
    /// This is the final source scan. Slot-index rounds restrict `C` in memory
    /// and never read the trace again.
    fhe::ExtensionValue<Backend> build_slot_checkpoint(
        std::span<const Fpk> ciphertext_point) {
        const std::size_t ciphertext_index_variables = log2_exact(
            source_layout_.padded_ciphertext_count,
            "LaminateLaned affine checkpoint variables");
        if (ciphertext_point.size() != ciphertext_index_variables) {
            throw std::invalid_argument(
                "LaminateLaned affine checkpoint shape mismatch");
        }

        // FHE Step 1: Prepare public equality weights for the fixed
        // ciphertext-index point.
        const std::vector<Fpk> owned_point(
            ciphertext_point.begin(), ciphertext_point.end());
        const std::vector<Fpk> ciphertext_weights =
            poly::eq_evaluations(owned_point);
        if (uses_materialized_packed_source()) {
            prepare_source();
            return materialized_source_.build_slot_checkpoint(
                eval_, source_layout_, lane_weights_, ciphertext_weights,
                statistics_);
        }
        const std::size_t chunks = source_layout_.chunks_per_ciphertext();
        const std::size_t chunks_per_batch =
            affine_detail::laned_affine_chunks_per_batch(chunks);
        const bool retain_zero_terms =
            fhe::forces_challenge_independent_topology<Backend>(eval_);
        fhe::ExtensionValue<Backend> checkpoint;
        affine_detail::ensure_prepared_lane_bases<Backend>(
            eval_, nullptr, source_layout_, lane_weights_,
            prepared_lane_bases_, statistics_);

        // FHE Step 2: Make one indexed source pass, retaining only one chunk
        // batch. Each source is multiplied by its equality weight exactly
        // once, then accumulated into the checkpoint after lane placement.
        auto scan = affine_detail::begin_batched_source_scan(
            *source_reader_, source_support_.live_wire_count, statistics_);
        for (std::size_t batch_begin = 0; batch_begin < chunks;
             batch_begin += chunks_per_batch) {
            const std::size_t batch_end =
                std::min(chunks, batch_begin + chunks_per_batch);
            const std::size_t batch_size = batch_end - batch_begin;
            std::vector<fhe::MixedExtensionAccumulator<Backend>>
                chunk_aggregates(batch_size);
            std::size_t present_chunk_aggregates = 0;
            note_chunk_batch(batch_size);
            scan_chunk_batch(
                batch_begin, batch_end, scan,
                [&](std::size_t wire,
                    const fhe::FheValue<Backend> &source) {
                    prepare_encrypted_source_level(source);
                    const std::size_t packed = wire / chunks;
                    const Fpk packed_weight = ciphertext_weights[packed];
                    if (packed_weight.is_zero() && !retain_zero_terms) {
                        return;
                    }
                    auto &aggregate =
                        chunk_aggregates[wire % chunks - batch_begin];
                    const bool introduced_accumulator = aggregate.empty();
                    accumulate_laned_scalar_source<Backend>(
                        eval_, aggregate, source, packed_weight);
                    affine_detail::note_scalar_promotion_and_peak(
                        introduced_accumulator, present_chunk_aggregates,
                        statistics_);
                });
            accumulate_placed_batch(
                checkpoint, chunk_aggregates, batch_begin, chunks);
        }
        affine_detail::finish_batched_source_scan(
            *source_reader_, source_support_.live_wire_count, scan,
            statistics_);

        // FHE Step 3: Place the chunk accumulators in their SIMD lanes. This
        // extension value is the complete handoff from file-backed source
        // access to the in-memory slot-index rounds.
        if (statistics_ != nullptr) {
            statistics_->peak_retained_extension_checkpoints = std::max(
                statistics_->peak_retained_extension_checkpoints,
                std::size_t{1});
        }
        return checkpoint;
    }

  private:
    template <typename Visit>
    void scan_chunk_batch(
        std::size_t batch_begin, std::size_t batch_end,
        affine_detail::BatchedSourceScanAccounting &accounting,
        Visit &&visit) {
        const std::size_t chunks = source_layout_.chunks_per_ciphertext();
        if (batch_begin >= batch_end || batch_end > chunks) {
            throw std::invalid_argument(
                "LaminateLaned affine chunk batch is invalid");
        }
        for (std::size_t packed = 0;
             packed < source_layout_.logical_ciphertext_count; ++packed) {
            const std::size_t wire_begin = packed * chunks + batch_begin;
            if (wire_begin >= source_layout_.original_wire_count) {
                break;
            }
            const std::size_t wire_end = std::min(
                source_layout_.original_wire_count,
                packed * chunks + batch_end);
            const std::size_t stored_begin =
                payload::trace_storage::live_wire_rank(
                    source_support_, wire_begin);
            const std::size_t stored_end =
                payload::trace_storage::live_wire_rank(
                    source_support_, wire_end);
            if (stored_begin == stored_end) {
                continue;
            }
            affine_detail::scan_batched_source_range<Backend>(
                *source_reader_, source_layout_.original_wire_count,
                stored_begin, stored_end, accounting, statistics_,
                [&](std::size_t wire,
                    const fhe::FheValue<Backend> &source) {
                    const std::size_t chunk = wire % chunks;
                    if (wire < wire_begin || wire >= wire_end ||
                        chunk < batch_begin || chunk >= batch_end) {
                        throw std::logic_error(
                            "LaminateLaned affine indexed range drifted");
                    }
                    visit(wire, source);
                });
        }
    }

    void note_chunk_batch(std::size_t batch_size) {
        if (statistics_ == nullptr) {
            return;
        }
        affine_detail::checked_accumulate(
            statistics_->chunk_batches, 1,
            "file-backed affine chunk batch count");
        statistics_->peak_chunk_batch_size = std::max(
            statistics_->peak_chunk_batch_size, batch_size);
    }

    void note_combined_accumulator_peak(
        const ::laminate::gkr::detail::AffineRoundPair<std::size_t>
            &present) {
        if (statistics_ == nullptr) {
            return;
        }
        statistics_->peak_retained_extension_accumulators = std::max(
            statistics_->peak_retained_extension_accumulators,
            present.at_one + present.at_two);
    }

    void accumulate_placed_batch(
        fhe::ExtensionValue<Backend> &destination,
        std::span<fhe::MixedExtensionAccumulator<Backend>> aggregates,
        std::size_t batch_begin, std::size_t total_chunks) {
        fhe::ExtensionValue<Backend> placed =
            affine_detail::apply_prepared_lane_bases<Backend>(
                eval_, aggregates, prepared_lane_bases_, statistics_,
                batch_begin, total_chunks);
        fhe::extension_add_assign<Backend>(eval_, destination,
                                           std::move(placed));
    }

    void validate_round_shape() const {
        if (source_support_.padded_wire_count !=
                source_layout_.original_wire_count ||
            lane_weights_.size() != source_layout_.lane_count) {
            throw std::invalid_argument(
                "LaminateLaned affine ciphertext round shape mismatch");
        }
    }

    void prepare_encrypted_source_level(
        const fhe::FheValue<Backend> &source) {
        validate_encrypted_source_level(source);
        if (!source.is_encrypted()) {
            return;
        }
        affine_detail::ensure_prepared_lane_bases<Backend>(
            eval_, &source.ciphertext(), source_layout_, lane_weights_,
            prepared_lane_bases_, statistics_);
    }

    void validate_encrypted_source_level(
        const fhe::FheValue<Backend> &source) const {
        if (!source.is_encrypted()) {
            return;
        }
        validate_exact_proof_ingress_ciphertext<Backend>(
            eval_, source.ciphertext(), expected_rns_limbs_,
            "LaminateLaned affine source");
    }

    void validate_source(const TraceSource &trace,
                         std::size_t layer) const {
        const payload::EncryptedTraceDescriptor &descriptor =
            trace.descriptor();
        if (descriptor.shape.kind != payload::PayloadKind::Laned ||
            descriptor.shape.slot_count != source_layout_.slot_count ||
            descriptor.shape.lane_count != source_layout_.lane_count ||
            Backend::storage_context_id(eval_) !=
                trace.backend_context_id() ||
            layer + 1U >= descriptor.layers.size() ||
            Backend::slot_count(eval_) != descriptor.shape.slot_count) {
            throw std::invalid_argument(
                "LaminateLaned affine trace shape mismatch");
        }
        const payload::EncryptedTraceLayerDescriptor &source =
            descriptor.layers[layer + 1U];
        const payload::LayerStorageLayout &storage =
            trace.layer_storage_layout(layer + 1U);
        if (source.layout != payload::TraceLayerLayout::BPeriodic ||
            source.dimensions.padded_size !=
                source_layout_.original_wire_count ||
            source.record_count !=
                source_support_.live_wire_count ||
            source_support_.padded_wire_count !=
                source_layout_.original_wire_count) {
            throw std::invalid_argument(
                "LaminateLaned affine source metadata mismatch");
        }
        // Affine sources are multiplication outputs or the input layer, so
        // their canonical storage is identity-ordered. Indexed chunk batches
        // rely on this property to translate padded ranges to stored ranges.
        if (storage.stored_wire_count != source_support_.live_wire_count) {
            throw std::invalid_argument(
                "LaminateLaned affine source unexpectedly contains aliases");
        }
        for (std::size_t stored = 0;
             stored < storage.stored_wire_count; ++stored) {
            if (storage.representative_padded_index_of(stored) !=
                source_support_.padded_index_of(stored)) {
                throw std::invalid_argument(
                    "LaminateLaned affine source order is not canonical");
            }
        }
    }

    const typename Backend::EvalContext &eval_; ///< Concrete FHE context.
    const TraceSource &trace_; ///< Owns either packed or unpacked source.
    std::size_t source_layer_; ///< Trace layer consumed by this reduction.
    packing::LanedPackingLayout source_layout_; ///< Packed source geometry.
    payload::LayerWireSupport source_support_; ///< Live versus padded wires.
    std::vector<Fpk> lane_weights_; ///< Fixed public lane equality weights.
    std::optional<SourceReader>
        source_reader_; ///< Rewindable compact source when packing is lazy.
    std::size_t expected_rns_limbs_; ///< Admitted source ciphertext level.
    LanedAffineStatistics *statistics_; ///< Non-transcript diagnostics.
    /// Prepared public lane bases reused by every source scan.
    std::vector<detail::MixedPreparedFpkSlotBasis<Backend>>
        prepared_lane_bases_;
    /// Low-width backend: one challenge-independent base-field packed source.
    affine_detail::MaterializedAffinePackedSource<Backend>
        materialized_source_;
};

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_EVALUATOR_HPP
