#ifndef LAMINATE_PAYLOAD_NOISE_HONEST_BASE_PROOF_NOISE_HPP
#define LAMINATE_PAYLOAD_NOISE_HONEST_BASE_PROOF_NOISE_HPP

/// @file honest_base_proof_noise.hpp
/// @brief Operational assessment of Base proof-message noise bounds.

#include "laminate/fhe/noise/honest_envelope_backend.hpp"
#include "laminate/gkr/detail/base/analysis/honest_noise_source.hpp"
#include "laminate/gkr/detail/base/affine/evaluator.hpp"
#include "laminate/gkr/detail/base/affine/diagnostics/statistics.hpp"
#include "laminate/gkr/detail/base/multiplication/prover.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"
#include "laminate/transcript/transcript.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace laminate::payload {

/// Setup input for operations whose proof-message envelope can differ from
/// the payload-evaluation calibration. Shared source and normalization inputs
/// are always derived from the validated payload schedule instead.
struct HonestBaseProofNoiseCalibration {
    std::size_t ctct_relinearized_debit_bits = 0;
    std::size_t plaintext_multiplication_debit_bits = 0;
    std::size_t rotation_debit_bits = 0;

    void validate() const;

    bool operator==(
        const HonestBaseProofNoiseCalibration &other) const = default;
};

/// Construct the exact Base proof-noise backend parameters. The circuit and
/// payload-core schedule determine N, t, the fresh error bound, the switch
/// rounding allowance, and the ordered data-prime chain. Only the three
/// operation debits above come from `calibration`.
fhe::HonestNoiseEnvelopeParameters
derive_honest_base_proof_noise_parameters(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &payload_core_schedule,
    const HonestBaseProofNoiseCalibration &calibration);

/// Check and summarize the canonical normalization records for one Base GKR
/// reduction.
///
/// Records follow the file-backed prover's transcript order: each round's
/// primary endpoint (normally one, or zero when tau=1), then its evaluation at
/// two, followed by the terminal messages. The function executes no proof or backend operation. It derives
/// one top-to-bottom modulus-switch chain from each nonempty family's maximum
/// pre-normalization bound and admits the result only when every observed
/// coefficient is contained by the planned support envelope and has the
/// planned level and component shape, the same exact recurrence, consistent
/// sticky-failure metadata, and the expected final state. A family may be
/// wholly public and therefore have no coefficient chain.
///
/// Malformed public parameters throw. A plan/record mismatch instead returns a
/// fail-closed assessment with `topology_complete == false` and
/// `all_messages_fit == false`.
HonestBaseProofReductionNoiseAssessment
aggregate_honest_base_proof_normalization_records(
    const HonestBaseProofNormalizationLayerPlan &normalization_plan,
    const fhe::HonestNoiseEnvelopeParameters &parameters, LayerKind kind,
    std::span<const fhe::HonestBaseNormalizationRecord> records);

/// Exact live-record and file-backed-prover accounting for one operational
/// reduction assessment. Exactly one reduction-statistics alternative is
/// populated according to `kind`.
struct HonestBaseProofReductionNoiseExecutionAudit {
    LayerKind kind = LayerKind::Affine;
    /// Exact coordinate-presence masks observed at the normalization boundary
    /// in transcript order. This is audit evidence, not a second source of
    /// topology truth.
    std::vector<HonestBaseProofCoordinateMask>
        observed_message_coordinate_masks;
    /// Backend operations executed after the source is constructed and before
    /// the production reduction returns, including lazy live imports and
    /// message normalization.
    std::uint64_t backend_operation_count = 0;
    gkr::base_detail::HonestBaseVirtualSourceAuditCounters virtual_source;
    std::optional<gkr::base_detail::BaseAffineStatistics>
        affine;
    std::optional<gkr::detail::FileBackedMultiplicationStatistics>
        multiplication;

    bool operator==(
        const HonestBaseProofReductionNoiseExecutionAudit &) const = default;
};

/// Run one production file-backed Base reduction over a lazy, live-only honest
/// noise source and aggregate every canonical normalization observation.
///
/// `transcript` is caller-owned so tests can establish challenge-history
/// independence. The internal claim is the deterministic all-zero point with
/// the exact reduction-layer dimension. Structural padding remains absent:
/// any virtual padding object or mismatch between generated live objects and
/// file-reader counts rejects the assessment.
HonestBaseProofReductionNoiseAssessment
assess_honest_base_proof_reduction_noise(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    std::size_t reduction_layer,
    fhe::HonestNoiseEnvelopeParameters parameters,
    Transcript &transcript,
    HonestBaseProofReductionNoiseExecutionAudit *execution_audit = nullptr);

/// Canonical totals from one complete Base proof-noise assessment. Reduction
/// entries retain their kind-specific execution statistics; the scalar and
/// virtual-source counters are their checked sums across all reductions.
struct HonestBaseProofNoiseExecutionAudit {
    std::uint64_t normalization_records_observed = 0;
    std::uint64_t backend_operation_count = 0;
    gkr::base_detail::HonestBaseVirtualSourceAuditCounters virtual_source;
    std::vector<HonestBaseProofReductionNoiseExecutionAudit> reductions;

    bool operator==(
        const HonestBaseProofNoiseExecutionAudit &) const = default;
};

/// Assess every canonical Base reduction twice under distinct fixed
/// transcript histories and compose the challenge-independent result.
///
/// Any history-dependent assessment or execution audit, normalization-plan
/// topology-envelope violation, or checked-counter overflow rejects the
/// operation. The aggregate records exact observed switch work while the
/// schedule retains its safe modeled upper bound. Noise-fit failures remain
/// data in the returned assessment; the first one is selected by canonical
/// reduction order.
HonestBaseProofNoiseAssessment assess_honest_base_proof_noise(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    fhe::HonestNoiseEnvelopeParameters parameters,
    HonestBaseProofNoiseExecutionAudit *execution_audit = nullptr);

/// Validate the report's canonical ordering, counts, aggregate flags, source
/// schedule binding, and proof-parameter digest without replaying the
/// operational topology.
void validate_honest_base_proof_noise_assessment_binding(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule);

/// Re-run the complete operational assessment and require exact equality
/// with the schedule attachment. This is an offline construction/admission
/// boundary, not a per-message execution check.
void validate_honest_base_proof_noise_assessment(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    fhe::HonestNoiseEnvelopeParameters parameters);

/// Exact admission predicate. It first replays and validates the complete
/// assessment against `parameters`; malformed, stale, or injected reports
/// throw instead of being interpreted as an accepting boolean.
bool honest_base_end_to_end_model_accepts(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    fhe::HonestNoiseEnvelopeParameters parameters);

/// Return whether an exactly validated, accepting schedule uses the canonical
/// component-wise proof ingress vector. The selector first finds the smallest
/// natural suffix reserve that makes every source independently viable, then
/// chooses the smallest exact accepting limb count for each reduction and
/// validates the resulting mixed vector as a whole. Malformed selected inputs
/// still throw.
bool honest_base_proof_ingress_is_minimal(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    fhe::HonestNoiseEnvelopeParameters parameters);

enum class HonestBaseProofIngressSelectionStage : std::uint8_t {
    ReserveCandidate,
    LimbProbe,
    FinalAssessment,
};

/// One observable boundary in the exhaustive ingress search. Fields that do
/// not apply to the current stage are zero. Indices are zero-based; counts are
/// included so a caller can render stable human-readable progress.
struct HonestBaseProofIngressSelectionProgress {
    HonestBaseProofIngressSelectionStage stage =
        HonestBaseProofIngressSelectionStage::ReserveCandidate;
    std::size_t reserve = 0;
    std::size_t reserve_count = 0;
    std::size_t reduction = 0;
    std::size_t reduction_count = 0;
    std::size_t candidate_limbs = 0;
    std::size_t maximum_limbs = 0;
};

using HonestBaseProofIngressSelectionProgressCallback =
    std::function<void(
        const HonestBaseProofIngressSelectionProgress &progress)>;

/// Progress is diagnostic only and cannot change setup selection. This
/// mirrors `notify_runtime_progress`: a logging callback failure is ignored.
inline void notify_honest_base_proof_ingress_selection_progress(
    const HonestBaseProofIngressSelectionProgressCallback &callback,
    const HonestBaseProofIngressSelectionProgress &progress) noexcept {
    if (!callback) {
        return;
    }
    try {
        callback(progress);
    } catch (...) {
    }
}

/// A canonical minimal-ingress schedule and exact Base proof-noise assessment
/// produced together by the exhaustive selector below. Construction is
/// private so setup code can distinguish this freshly derived result from an
/// arbitrary caller-supplied schedule that still requires exact replay.
class CertifiedHonestBaseProofIngressSelection {
  public:
    const HonestPayloadNoiseSchedule &schedule() const noexcept {
        return schedule_;
    }

    HonestPayloadNoiseSchedule release_schedule() && {
        return std::move(schedule_);
    }

  private:
    friend CertifiedHonestBaseProofIngressSelection
    select_certified_honest_base_proof_ingress(
        const LayeredCircuit &circuit,
        std::span<const std::uint64_t> data_moduli_low_to_high,
        HonestPayloadNoiseCalibration payload_calibration,
        const HonestBaseProofNoiseCalibration &proof_calibration,
        HonestBaseProofNoiseExecutionAudit *execution_audit,
        HonestBaseProofIngressSelectionProgressCallback progress_callback);

    CertifiedHonestBaseProofIngressSelection() = default;
    HonestPayloadNoiseSchedule schedule_;
};

/// Derive the same canonical component-wise minimal schedule as
/// `select_minimal_honest_base_proof_ingress`, while retaining a construction
/// certificate that setup can bind without rerunning the complete search and
/// operational assessment. An optional callback reports each reserve,
/// reduction/limb probe, and final all-reduction assessment before it begins.
CertifiedHonestBaseProofIngressSelection
select_certified_honest_base_proof_ingress(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    HonestPayloadNoiseCalibration payload_calibration,
    const HonestBaseProofNoiseCalibration &proof_calibration,
    HonestBaseProofNoiseExecutionAudit *execution_audit = nullptr,
    HonestBaseProofIngressSelectionProgressCallback progress_callback = {});

/// Derive and attach the canonical component-wise proof ingress vector.
/// `payload_calibration` supplies every calibration field except the scalar
/// natural-availability floor, which the selector searches from zero upward.
/// Within each viable floor it probes each source from q_0-only ingress upward
/// and admits the first exact accepting limb count before assessing the final
/// mixed vector. Throws if no supported reserve admits both the payload and
/// exact Base proof-noise models.
HonestPayloadNoiseSchedule select_minimal_honest_base_proof_ingress(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    HonestPayloadNoiseCalibration payload_calibration,
    const HonestBaseProofNoiseCalibration &proof_calibration,
    HonestBaseProofNoiseExecutionAudit *execution_audit = nullptr);

/// Attach a freshly re-derived assessment to a payload-core schedule.
HonestPayloadNoiseSchedule attach_honest_base_proof_noise_assessment(
    const LayeredCircuit &circuit, HonestPayloadNoiseSchedule schedule,
    fhe::HonestNoiseEnvelopeParameters parameters,
    HonestBaseProofNoiseExecutionAudit *execution_audit = nullptr);

/// Exact canonical encoding and digest of the complete derived report. These
/// bind every arbitrary-precision bound and normalization step; callers must
/// still validate or re-derive the assessment before first admission.
std::vector<std::uint8_t> encode_canonical(
    const HonestBaseProofNoiseAssessment &assessment);

/// Decode one complete canonical assessment report without replaying the
/// offline assessor. Callers must subsequently validate the report against
/// its circuit and schedule with
/// `validate_honest_base_proof_noise_assessment_binding`.
HonestBaseProofNoiseAssessment
decode_canonical_honest_base_proof_noise_assessment(
    std::span<const std::uint8_t> encoded,
    std::size_t max_bytes = 64U << 20U);

Digest honest_base_proof_noise_assessment_digest(
    const HonestBaseProofNoiseAssessment &assessment);

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_NOISE_HONEST_BASE_PROOF_NOISE_HPP
