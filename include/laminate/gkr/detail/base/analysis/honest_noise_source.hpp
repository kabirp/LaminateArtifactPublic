#ifndef LAMINATE_GKR_DETAIL_BASE_ANALYSIS_HONEST_NOISE_SOURCE_HPP
#define LAMINATE_GKR_DETAIL_BASE_ANALYSIS_HONEST_NOISE_SOURCE_HPP

/// @file honest_noise_source.hpp
/// @brief Live-only virtual Base source for the honest noise backend.

#include "laminate/fhe/noise/honest_envelope_backend.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace laminate::gkr::base_detail {

/// Cumulative evidence that a virtual source returned only live protocol
/// records. Skipped structural positions are public plaintext zeroes; they
/// are counted separately and never become backend ciphertext objects.
struct HonestBaseVirtualSourceAuditCounters {
    std::uint64_t source_objects_returned = 0;
    std::uint64_t source_ciphertext_objects_returned = 0;
    std::uint64_t contribution_objects_returned = 0;
    std::uint64_t structural_padding_positions_skipped = 0;
    std::uint64_t padding_objects_returned = 0;

    void assert_no_padding_objects() const {
        if (padding_objects_returned != 0) {
            throw std::logic_error(
                "honest Base virtual source returned a padding object");
        }
    }

    bool operator==(
        const HonestBaseVirtualSourceAuditCounters &) const = default;
};

/// Reader-local counts for canonical public-or-encrypted values. Virtual
/// records have no serialized payload bytes; `ciphertexts_read` counts only
/// modeled ciphertext objects, while `values_read` includes public values.
struct HonestBaseVirtualReaderStatistics {
    std::uint64_t passes_started = 1;
    std::uint64_t rewinds = 0;
    std::uint64_t values_read = 0;
    std::uint64_t ciphertexts_read = 0;
    std::uint64_t logical_ciphertext_bytes_read = 0;

    bool operator==(
        const HonestBaseVirtualReaderStatistics &) const = default;
};

/// Combined metadata surface accepted by production Base reductions. The
/// affine fields describe compact stored public-or-encrypted trace records.
/// Dense multiplication uses the same public layout and alias geometry as
/// the file artifact.
struct HonestBaseVirtualSourceDescriptor {
    payload::PayloadShape shape;
    std::vector<payload::EncryptedTraceLayerDescriptor> layers;
    Digest layered_circuit_id{};
    std::size_t reduction_layer = 0;
    payload::LayerDimensions output_dimensions;
    payload::EncryptedTraceLayerDescriptor source_layer;
    payload::LayerWireSupport source_support;
    packing::LanedPackingLayout output_layout;
    packing::LanedPackingLayout source_layout;
    std::size_t pair_count = 0;
    std::size_t live_pair_count = 0;
    std::size_t stored_value_count = 0;

    bool operator==(
        const HonestBaseVirtualSourceDescriptor &) const = default;
};

struct HonestBaseVirtualSourceWire {
    std::size_t padded_index = 0;
    fhe::FheValue<fhe::HonestNoiseEnvelopeBackend> value;
};

struct HonestBaseVirtualDensePair {
    std::size_t packed_index = 0;
    fhe::FheValue<fhe::HonestNoiseEnvelopeBackend> left_value;
    fhe::FheValue<fhe::HonestNoiseEnvelopeBackend> right_value;

    const fhe::FheValue<fhe::HonestNoiseEnvelopeBackend> &left() const {
        return left_value;
    }

    const fhe::FheValue<fhe::HonestNoiseEnvelopeBackend> &right() const {
        return right_value;
    }
};

namespace honest_base_virtual_source_detail {

struct SharedAuditState {
    HonestBaseVirtualSourceAuditCounters counters;
};

inline void checked_increment(std::uint64_t &value,
                              const char *description) {
    if (value == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(std::string(description) +
                                  " overflows u64");
    }
    ++value;
}

inline void checked_add_size(std::uint64_t &value, std::size_t added,
                             const char *description) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (added > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(description) +
                                      " does not fit u64");
        }
    }
    const std::uint64_t converted = static_cast<std::uint64_t>(added);
    if (converted > std::numeric_limits<std::uint64_t>::max() - value) {
        throw std::overflow_error(std::string(description) +
                                  " overflows u64");
    }
    value += converted;
}

inline bool matches_source_parameters(
    const payload::LayeredCircuit &circuit,
    const payload::HonestPayloadNoiseSchedule &schedule,
    const fhe::HonestNoiseEnvelopeParameters &parameters) {
    // Base proof arithmetic may use distinct setup-bound operation debits.
    // Only the fields that define imported payload states and their RNS
    // normalization are shared with the payload schedule.
    return parameters.ring_degree == circuit.shape.slot_count &&
           parameters.plaintext_modulus == kBaseFieldOrder &&
           parameters.fresh_canonical_error_bound == fhe::NaturalMagnitude(
               schedule.calibration.fresh_canonical_error_bound) &&
           parameters.switch_rounding_error_bound == fhe::NaturalMagnitude(
               schedule.calibration.switch_rounding_error_bound) &&
           parameters.data_moduli == schedule.data_moduli_low_to_high;
}

struct SourceEnvelope {
    fhe::NaturalMagnitude canonical_error_bound;
    std::size_t rns_limb_count = 0;
};

struct ProofIngressEnvelope {
    SourceEnvelope output;
    bool input_phase_fits = false;
    std::vector<payload::HonestBaseProofNoiseNormalizationStep> steps;
    std::optional<std::size_t> first_failed_step;
    bool all_phases_fit = false;
};

inline bool phase_fits(
    const fhe::HonestNoiseEnvelopeParameters &parameters,
    const fhe::NaturalMagnitude &canonical_error_bound,
    std::size_t limbs) {
    return fhe::honest_noise_fits_active_modulus(
        parameters.plaintext_modulus, canonical_error_bound,
        std::span<const std::uint64_t>(parameters.data_moduli).first(limbs));
}

inline ProofIngressEnvelope switch_to_proof_ingress(
    const fhe::HonestNoiseEnvelopeParameters &parameters,
    SourceEnvelope natural, std::size_t proof_ingress_limbs) {
    if (natural.rns_limb_count == 0 || proof_ingress_limbs == 0 ||
        proof_ingress_limbs > natural.rns_limb_count ||
        natural.rns_limb_count > parameters.data_moduli.size()) {
        throw std::logic_error(
            "honest Base virtual source proof-ingress level is invalid");
    }
    ProofIngressEnvelope result;
    result.input_phase_fits = phase_fits(
        parameters, natural.canonical_error_bound, natural.rns_limb_count);
    result.all_phases_fit = result.input_phase_fits;
    result.steps.reserve(natural.rns_limb_count - proof_ingress_limbs);
    while (natural.rns_limb_count > proof_ingress_limbs) {
        const std::size_t input_limbs = natural.rns_limb_count;
        const std::uint64_t dropped =
            parameters.data_moduli[input_limbs - 1U];
        const fhe::NaturalMagnitude input = natural.canonical_error_bound;
        const fhe::NaturalMagnitude output = fhe::NaturalMagnitude::add(
            fhe::NaturalMagnitude::divide_ceil(
                input, dropped),
            parameters.switch_rounding_error_bound);
        const fhe::NaturalMagnitude input_phase =
            fhe::honest_noise_phase_bound(
                parameters.plaintext_modulus, input);
        const fhe::NaturalMagnitude output_phase =
            fhe::honest_noise_phase_bound(
                parameters.plaintext_modulus, output);
        const bool input_fits =
            phase_fits(parameters, input, input_limbs);
        const bool output_fits =
            phase_fits(parameters, output, input_limbs - 1U);
        result.steps.push_back(
            payload::HonestBaseProofNoiseNormalizationStep{
                .input_rns_limb_count = input_limbs,
                .output_rns_limb_count = input_limbs - 1U,
                .dropped_modulus = dropped,
                .input_canonical_error_bound = input,
                .output_canonical_error_bound = output,
                .input_phase_bound = input_phase,
                .output_phase_bound = output_phase,
                .input_phase_fits = input_fits,
                .output_phase_fits = output_fits,
            });
        if ((!input_fits || !output_fits) &&
            !result.first_failed_step) {
            result.first_failed_step = result.steps.size() - 1U;
        }
        result.all_phases_fit =
            result.all_phases_fit && input_fits && output_fits;
        natural.canonical_error_bound = output;
        --natural.rns_limb_count;
    }
    result.output = std::move(natural);
    return result;
}

inline SourceEnvelope source_envelope(
    const payload::LayeredCircuit &circuit,
    const payload::HonestPayloadNoiseSchedule &schedule,
    std::size_t source_layer) {
    const std::size_t expected_limbs =
        schedule.evaluation_plan.trace.required_mult_depth_by_layer.at(
            source_layer) +
        1U;
    if (source_layer + 1U == circuit.layers.size()) {
        if (expected_limbs != schedule.data_moduli_low_to_high.size()) {
            throw std::logic_error(
                "honest Base virtual input level differs from schedule");
        }
        return SourceEnvelope{
            fhe::NaturalMagnitude(
                schedule.calibration.fresh_canonical_error_bound),
            expected_limbs,
        };
    }

    const payload::HonestPayloadLayerSchedule *matched = nullptr;
    for (const payload::HonestPayloadLayerSchedule &layer :
         schedule.layers_in_evaluation_order) {
        if (layer.layer != source_layer) {
            continue;
        }
        if (matched != nullptr) {
            throw std::logic_error(
                "honest Base virtual source schedule layer is duplicated");
        }
        matched = &layer;
    }
    if (matched == nullptr ||
        matched->output_rns_limb_count != expected_limbs) {
        throw std::logic_error(
            "honest Base virtual source layer is absent or stale");
    }
    return SourceEnvelope{
        matched->output_canonical_error_bound,
        matched->output_rns_limb_count,
    };
}

/// Project canonical per-stored-value classifications onto the distinct Wide
/// operands named by a dense alias plan. This is an ordinal lookup only; all
/// public-vs-encrypted inference remains in trace-wire-support analysis.
inline std::vector<payload::ClassifiedTraceValue>
dense_operand_classifications(
    const detail::DenseMultiplicationAliasPlan &aliases,
    std::span<const payload::ClassifiedTraceValue>
        source_classifications) {
    std::vector<payload::ClassifiedTraceValue> result;
    result.reserve(aliases.operands.size());
    for (const auto &operand : aliases.operands) {
        if (operand.stored_ordinals.size() != 1U ||
            !operand.stored_ordinals.front()) {
            throw std::logic_error(
                "honest Base dense operand lacks one stored wide value");
        }
        const std::size_t stored = *operand.stored_ordinals.front();
        if (stored >= source_classifications.size()) {
            throw std::logic_error(
                "honest Base dense operand classification is stale");
        }
        result.push_back(source_classifications[stored]);
    }
    return result;
}

} // namespace honest_base_virtual_source_detail

/// Lazy live-wire reader for the file-backed affine reduction. Every successful
/// `next()` returns the canonical public value or imports a fresh ciphertext
/// at the source layer's exact schedule state.
class HonestBaseVirtualWireReader {
  public:
    std::optional<HonestBaseVirtualSourceWire> next() {
        if (position_ == support_.live_wire_count) {
            account_exhausted_padding();
            return std::nullopt;
        }

        const std::size_t padded_index =
            support_.padded_index_of(position_);

        if (!support_.is_live(padded_index)) {
            honest_base_virtual_source_detail::checked_increment(
                audit_->counters.padding_objects_returned,
                "honest Base padding object count");
            throw std::logic_error(
                "honest Base virtual source attempted to import padding");
        }
        const std::optional<std::size_t> stored =
            storage_.stored_ordinal_of(padded_index);
        if (!stored) {
            throw std::logic_error(
                "honest Base virtual source live wire is not stored");
        }
        const payload::ClassifiedTraceValue &classification =
            classifications_.at(*stored);
        fhe::FheValue<fhe::HonestNoiseEnvelopeBackend> value;
        if (classification) {
            value = fhe::FheValue<fhe::HonestNoiseEnvelopeBackend>::
                public_plaintext(*classification);
        } else {
            value = fhe::FheValue<fhe::HonestNoiseEnvelopeBackend>::
                from_ciphertext(
                    fhe::HonestNoiseEnvelopeBackend::source_ciphertext(
                        *eval_, canonical_error_bound_, rns_limb_count_));
            honest_base_virtual_source_detail::checked_increment(
                statistics_.ciphertexts_read,
                "honest Base virtual source ciphertext read count");
            honest_base_virtual_source_detail::checked_increment(
                audit_->counters.source_ciphertext_objects_returned,
                "honest Base returned source ciphertext count");
        }
        ++position_;
        honest_base_virtual_source_detail::checked_increment(
            statistics_.values_read,
            "honest Base virtual source value read count");
        honest_base_virtual_source_detail::checked_increment(
            audit_->counters.source_objects_returned,
            "honest Base returned source count");
        return HonestBaseVirtualSourceWire{
            padded_index, std::move(value)};
    }

    void rewind() {
        position_ = 0;
        padding_positions_skipped_this_pass_ = 0;
        exhausted_padding_accounted_ = false;
        honest_base_virtual_source_detail::checked_increment(
            statistics_.rewinds,
            "honest Base virtual source rewind count");
        honest_base_virtual_source_detail::checked_increment(
            statistics_.passes_started,
            "honest Base virtual source pass count");
    }

    std::size_t begin() const { return 0; }
    std::size_t end() const { return support_.live_wire_count; }
    std::size_t size() const { return support_.live_wire_count; }
    std::size_t position() const { return position_; }
    std::size_t resident_ciphertexts_held() const { return 0; }
    const HonestBaseVirtualReaderStatistics &statistics() const {
        return statistics_;
    }

  private:
    void account_exhausted_padding() {
        if (exhausted_padding_accounted_) {
            return;
        }
        const std::size_t total_padding =
            support_.padded_wire_count - support_.live_wire_count;
        if (padding_positions_skipped_this_pass_ > total_padding) {
            throw std::logic_error(
                "honest Base virtual source padding ledger drifted");
        }
        honest_base_virtual_source_detail::checked_add_size(
            audit_->counters.structural_padding_positions_skipped,
            total_padding - padding_positions_skipped_this_pass_,
            "honest Base skipped padding count");
        padding_positions_skipped_this_pass_ = total_padding;
        exhausted_padding_accounted_ = true;
    }

    HonestBaseVirtualWireReader(
        const fhe::HonestNoiseEnvelopeBackend::EvalContext &eval,
        payload::LayerWireSupport support,
        payload::LayerStorageLayout storage,
        std::vector<payload::ClassifiedTraceValue> classifications,
        fhe::NaturalMagnitude canonical_error_bound,
        std::size_t rns_limb_count,
        std::shared_ptr<honest_base_virtual_source_detail::SharedAuditState>
            audit)
        : eval_(&eval), support_(std::move(support)),
          storage_(std::move(storage)),
          classifications_(std::move(classifications)),
          canonical_error_bound_(std::move(canonical_error_bound)),
          rns_limb_count_(rns_limb_count), audit_(std::move(audit)) {
        payload::validate_layer_storage_layout(storage_);
        if (storage_.padded_wire_count != support_.padded_wire_count ||
            classifications_.size() != storage_.stored_wire_count) {
            throw std::logic_error(
                "honest Base virtual source classification is stale");
        }
    }

    const fhe::HonestNoiseEnvelopeBackend::EvalContext *eval_;
    payload::LayerWireSupport support_;
    payload::LayerStorageLayout storage_;
    std::vector<payload::ClassifiedTraceValue> classifications_;
    fhe::NaturalMagnitude canonical_error_bound_;
    std::size_t rns_limb_count_ = 0;
    std::shared_ptr<honest_base_virtual_source_detail::SharedAuditState>
        audit_;
    std::size_t position_ = 0;
    std::size_t padding_positions_skipped_this_pass_ = 0;
    bool exhausted_padding_accounted_ = false;
    HonestBaseVirtualReaderStatistics statistics_;

    friend class HonestBaseVirtualSource;
};

/// Lazy alias-aware reader for the canonical dense multiplication halves.
/// Each distinct operand is modeled once per scan. Unlike the bounded disk
/// reader, these lightweight symbolic values need no eviction or rereads.
/// Only private operands are
/// imported as modeled ciphertexts; circuit-fixed operands stay plaintext.
class HonestBaseVirtualDenseReader {
  public:
    using Pair = HonestBaseVirtualDensePair;

    std::optional<Pair> next() {
        if (position_ == aliases_.live_pair_count) {
            account_exhausted_padding();
            return std::nullopt;
        }
        const std::size_t packed = aliases_.physical_pair_order[position_++];
        auto left = read_operand(aliases_.left_operand.at(packed));
        auto right = read_operand(aliases_.right_operand.at(packed));
        honest_base_virtual_source_detail::checked_increment(
            statistics_.pairs_read,
            "honest Base virtual dense pair count");
        statistics_.peak_live_decoded_values = std::max(
            statistics_.peak_live_decoded_values, cached_values_ + 2U);
        if (position_ == aliases_.live_pair_count) {
            account_exhausted_padding();
        }
        return Pair{packed, std::move(left), std::move(right)};
    }

    void rewind() {
        position_ = 0;
        cached_values_ = 0;
        exhausted_padding_accounted_ = false;
        std::fill(seen_.begin(), seen_.end(), false);
        for (auto &value : cache_) {
            value.reset();
        }
        honest_base_virtual_source_detail::checked_increment(
            statistics_.rewinds,
            "honest Base virtual dense rewind count");
        honest_base_virtual_source_detail::checked_increment(
            statistics_.passes_started,
            "honest Base virtual dense pass count");
    }

    std::size_t size() const { return aliases_.live_pair_count; }
    std::size_t domain_size() const { return aliases_.pair_count; }
    std::size_t position() const { return position_; }
    std::uint64_t stored_value_count() const {
        return static_cast<std::uint64_t>(aliases_.operands.size());
    }
    const detail::FileDenseMultiplicationSourceReadStatistics &statistics()
        const {
        return statistics_;
    }

  private:
    HonestBaseVirtualDenseReader(
        const fhe::HonestNoiseEnvelopeBackend::EvalContext &eval,
        detail::DenseMultiplicationAliasPlan aliases,
        std::vector<payload::ClassifiedTraceValue>
            operand_classifications,
        fhe::NaturalMagnitude canonical_error_bound,
        std::size_t rns_limb_count,
        std::shared_ptr<honest_base_virtual_source_detail::SharedAuditState>
            audit)
        : eval_(&eval), aliases_(std::move(aliases)),
          operand_classifications_(std::move(operand_classifications)),
          canonical_error_bound_(std::move(canonical_error_bound)),
          rns_limb_count_(rns_limb_count), audit_(std::move(audit)),
          seen_(aliases_.operands.size(), false),
          cache_(aliases_.operands.size()) {
        if (operand_classifications_.size() != aliases_.operands.size()) {
            throw std::logic_error(
                "honest Base dense public-operand metadata is stale");
        }
    }

    fhe::FheValue<fhe::HonestNoiseEnvelopeBackend>
    read_operand(std::size_t operand) {
        if (operand >= aliases_.operands.size()) {
            throw std::logic_error(
                "honest Base virtual dense operand is out of range");
        }
        if (seen_[operand]) {
            if (!cache_[operand]) {
                throw std::logic_error(
                    "honest Base virtual dense alias was not cached");
            }
            return *cache_[operand];
        }
        seen_[operand] = true;
        honest_base_virtual_source_detail::checked_increment(
            statistics_.values_read,
            "honest Base virtual dense value count");
        honest_base_virtual_source_detail::checked_increment(
            statistics_.distinct_values_read,
            "honest Base virtual dense distinct value count");
        honest_base_virtual_source_detail::checked_increment(
            audit_->counters.source_objects_returned,
            "honest Base returned dense value count");
        fhe::FheValue<fhe::HonestNoiseEnvelopeBackend> value;
        if (operand_classifications_[operand]) {
            value = fhe::FheValue<fhe::HonestNoiseEnvelopeBackend>::
                public_plaintext(
                    *operand_classifications_[operand]);
        } else {
            honest_base_virtual_source_detail::checked_increment(
                audit_->counters.source_ciphertext_objects_returned,
                "honest Base returned dense ciphertext count");
            value = fhe::FheValue<fhe::HonestNoiseEnvelopeBackend>::
                from_ciphertext(
                    fhe::HonestNoiseEnvelopeBackend::source_ciphertext(
                        *eval_, canonical_error_bound_, rns_limb_count_));
        }
        if (aliases_.operand_occurrences.at(operand) > 1U) {
            cache_[operand] = value;
            ++cached_values_;
        }
        return value;
    }

    void account_exhausted_padding() {
        if (exhausted_padding_accounted_) {
            return;
        }
        honest_base_virtual_source_detail::checked_add_size(
            audit_->counters.structural_padding_positions_skipped,
            aliases_.pair_count - aliases_.live_pair_count,
            "honest Base skipped dense pair count");
        exhausted_padding_accounted_ = true;
    }

    const fhe::HonestNoiseEnvelopeBackend::EvalContext *eval_;
    detail::DenseMultiplicationAliasPlan aliases_;
    std::vector<payload::ClassifiedTraceValue>
        operand_classifications_;
    fhe::NaturalMagnitude canonical_error_bound_;
    std::size_t rns_limb_count_ = 0;
    std::shared_ptr<honest_base_virtual_source_detail::SharedAuditState>
        audit_;
    std::vector<bool> seen_;
    std::vector<std::optional<
        fhe::FheValue<fhe::HonestNoiseEnvelopeBackend>>> cache_;
    std::size_t cached_values_ = 0;
    std::size_t position_ = 0;
    bool exhausted_padding_accounted_ = false;
    detail::FileDenseMultiplicationSourceReadStatistics statistics_;

    friend class HonestBaseVirtualSource;
};

/// One reduction-scoped source for operational Base proof noise assessment.
/// It owns no trace values or padding table. Its dense reader keeps
/// circuit-fixed operands plaintext and models only private operands as
/// ciphertexts.
class HonestBaseVirtualSource {
  public:
    HonestBaseVirtualSource(
        const payload::LayeredCircuit &circuit,
        const payload::HonestPayloadNoiseSchedule &schedule,
        std::size_t reduction_layer,
        const fhe::HonestNoiseEnvelopeBackend::EvalContext &eval)
        : eval_(&eval), context_token_(eval.sequences),
          context_parameters_(eval.parameters),
          audit_(std::make_shared<
                 honest_base_virtual_source_detail::SharedAuditState>()) {
        payload::validate_honest_payload_noise_schedule_core(
            circuit, schedule);
        if (circuit.shape.kind != payload::PayloadKind::Wide ||
            reduction_layer >= circuit.layers.size() - 1U ||
            !honest_base_virtual_source_detail::matches_source_parameters(
                circuit, schedule, eval.parameters) ||
            eval.sequences == nullptr) {
            throw std::invalid_argument(
                "honest Base virtual source circuit, layer, or context "
                "mismatch");
        }
        source_layer_ = reduction_layer + 1U;

        const auto envelope =
            honest_base_virtual_source_detail::source_envelope(
                circuit, schedule, source_layer_);
        natural_canonical_error_bound_ = envelope.canonical_error_bound;
        natural_rns_limb_count_ = envelope.rns_limb_count;
        const auto ingress =
            honest_base_virtual_source_detail::switch_to_proof_ingress(
                eval.parameters, envelope,
                schedule.evaluation_plan
                        .proof_ingress_mult_depth_by_layer.at(source_layer_) +
                    1U);
        canonical_error_bound_ = ingress.output.canonical_error_bound;
        rns_limb_count_ = ingress.output.rns_limb_count;
        ingress_input_phase_fits_ = ingress.input_phase_fits;
        ingress_normalization_steps_ = ingress.steps;
        first_failed_ingress_step_ = ingress.first_failed_step;
        all_ingress_phases_fit_ = ingress.all_phases_fit;

        descriptor_.shape = circuit.shape;
        descriptor_.layered_circuit_id = payload::digest(circuit);
        descriptor_.reduction_layer = reduction_layer;
        descriptor_.output_dimensions =
            payload::layer_dimensions(circuit.layers[reduction_layer]);
        const payload::CanonicalTraceLayout trace =
            payload::canonical_trace_layout(circuit);
        descriptor_.source_support = trace.wire_support.at(source_layer_);
        source_storage_ = trace.storage.at(source_layer_);
        source_classifications_ =
            trace.stored_value_classifications.at(source_layer_);
        for (std::size_t live = 0;
             live < descriptor_.source_support.live_wire_count; ++live) {
            const std::size_t padded =
                descriptor_.source_support.padded_index_of(live);
            const std::optional<std::size_t> stored =
                source_storage_.stored_ordinal_of(padded);
            if (!stored) {
                throw std::logic_error(
                    "honest Base virtual source live wire is not stored");
            }
            source_ciphertext_objects_per_scan_ +=
                static_cast<std::size_t>(
                    !source_classifications_.at(*stored).has_value());
        }
        descriptor_.layers.reserve(circuit.layers.size());
        for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
            descriptor_.layers.push_back(
                payload::EncryptedTraceLayerDescriptor{
                    .layout = payload::TraceLayerLayout::Wide,
                    .dimensions =
                        payload::layer_dimensions(circuit.layers[layer]),
                    .required_mult_depth =
                        schedule.evaluation_plan
                            .proof_ingress_mult_depth_by_layer.at(layer),
                    .record_count =
                        trace.value_counts[layer].stored_values,
                });
        }
        descriptor_.source_layer = descriptor_.layers[source_layer_];
        if (payload::layer_kind(circuit.layers[reduction_layer]) ==
            payload::LayerKind::Multiplication) {
            aliases_ = detail::make_dense_multiplication_alias_plan(
                circuit, reduction_layer,
                trace.wire_support.at(source_layer_),
                trace.storage.at(source_layer_));
            dense_operand_classifications_ =
                honest_base_virtual_source_detail::
                    dense_operand_classifications(
                        *aliases_, trace.stored_value_classifications.at(
                                       source_layer_));
            source_ciphertext_objects_per_scan_ =
                static_cast<std::size_t>(std::count(
                    dense_operand_classifications_.begin(),
                    dense_operand_classifications_.end(), std::nullopt));
            descriptor_.output_layout =
                detail::dense_multiplication_storage_layout(
                    circuit, reduction_layer);
            descriptor_.source_layout =
                detail::dense_multiplication_storage_layout(
                    circuit, source_layer_);
            descriptor_.pair_count = aliases_->pair_count;
            descriptor_.live_pair_count = aliases_->live_pair_count;
            descriptor_.stored_value_count = aliases_->operands.size();
        }

        if (descriptor_.source_support.live_wire_count == 0 ||
            descriptor_.source_layer.record_count !=
                trace.value_counts[source_layer_].stored_values ||
            descriptor_.source_layer.required_mult_depth + 1U !=
                rns_limb_count_) {
            throw std::logic_error(
                "honest Base virtual source metadata is inconsistent");
        }
    }

    const HonestBaseVirtualSourceDescriptor &descriptor() const {
        return descriptor_;
    }

    bool matches_backend_context(
        const fhe::HonestNoiseEnvelopeBackend::EvalContext &eval) const {
        return eval.sequences == context_token_ &&
               eval.parameters == context_parameters_;
    }

    const Digest &layered_circuit_id() const {
        return descriptor_.layered_circuit_id;
    }

    const payload::LayerWireSupport &layer_support(
        std::size_t layer) const {
        if (layer != source_layer_) {
            throw std::out_of_range(
                "honest Base virtual source exposes only its source layer");
        }
        return descriptor_.source_support;
    }

    HonestBaseVirtualWireReader active_layer_reader(
        std::size_t layer) const {
        (void)layer_support(layer);
        return HonestBaseVirtualWireReader(
            *eval_, descriptor_.source_support, source_storage_,
            source_classifications_, canonical_error_bound_,
            rns_limb_count_, audit_);
    }

    /// Open the dense-pair view admitted when this one-reduction diagnostic
    /// source was constructed. Production and analysis sources deliberately
    /// expose the same zero-argument reader boundary; neither asks a round
    /// prover to rediscover circuit geometry.
    HonestBaseVirtualDenseReader reader() const {
        if (!aliases_) {
            throw std::invalid_argument(
                "honest Base virtual source is not multiplication");
        }
        return HonestBaseVirtualDenseReader(
            *eval_, *aliases_, dense_operand_classifications_,
            canonical_error_bound_, rns_limb_count_, audit_);
    }

    fhe::NaturalMagnitude source_canonical_error_bound() const {
        return canonical_error_bound_;
    }

    fhe::NaturalMagnitude natural_source_canonical_error_bound() const {
        return natural_canonical_error_bound_;
    }

    std::size_t source_rns_limb_count() const {
        return rns_limb_count_;
    }

    std::size_t natural_source_rns_limb_count() const {
        return natural_rns_limb_count_;
    }

    std::size_t source_ciphertext_objects_per_scan() const {
        return source_ciphertext_objects_per_scan_;
    }

    bool ingress_input_phase_fits() const {
        return ingress_input_phase_fits_;
    }

    const std::vector<payload::HonestBaseProofNoiseNormalizationStep> &
    ingress_normalization_steps() const {
        return ingress_normalization_steps_;
    }

    std::optional<std::size_t> first_failed_ingress_step() const {
        return first_failed_ingress_step_;
    }

    bool all_ingress_phases_fit() const {
        return all_ingress_phases_fit_;
    }

    HonestBaseVirtualSourceAuditCounters audit_counters() const {
        return audit_->counters;
    }

    void assert_no_padding_objects() const {
        audit_->counters.assert_no_padding_objects();
    }

  private:
    const fhe::HonestNoiseEnvelopeBackend::EvalContext *eval_;
    std::shared_ptr<fhe::HonestNoiseEnvelopeBackend::SequenceState>
        context_token_;
    fhe::HonestNoiseEnvelopeParameters context_parameters_;
    std::size_t source_layer_ = 0;
    HonestBaseVirtualSourceDescriptor descriptor_;
    payload::LayerStorageLayout source_storage_;
    std::vector<payload::ClassifiedTraceValue> source_classifications_;
    std::optional<detail::DenseMultiplicationAliasPlan> aliases_;
    std::vector<payload::ClassifiedTraceValue>
        dense_operand_classifications_;
    fhe::NaturalMagnitude natural_canonical_error_bound_;
    fhe::NaturalMagnitude canonical_error_bound_;
    std::size_t natural_rns_limb_count_ = 0;
    std::size_t rns_limb_count_ = 0;
    std::size_t source_ciphertext_objects_per_scan_ = 0;
    bool ingress_input_phase_fits_ = false;
    std::vector<payload::HonestBaseProofNoiseNormalizationStep>
        ingress_normalization_steps_;
    std::optional<std::size_t> first_failed_ingress_step_;
    bool all_ingress_phases_fit_ = false;
    std::shared_ptr<honest_base_virtual_source_detail::SharedAuditState>
        audit_;
};

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_ANALYSIS_HONEST_NOISE_SOURCE_HPP
