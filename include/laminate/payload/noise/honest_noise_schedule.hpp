#ifndef LAMINATE_PAYLOAD_NOISE_HONEST_NOISE_SCHEDULE_HPP
#define LAMINATE_PAYLOAD_NOISE_HONEST_NOISE_SCHEDULE_HPP

/// @file honest_noise_schedule.hpp
/// @brief Setup-fixed payload schedule for honest-input BGV calibration.

#include "laminate/fhe/noise/deterministic.hpp"
#include "laminate/payload/evaluation/fhe_evaluation_plan.hpp"
#include "laminate/transcript/hash.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::payload {

/// Stable name for the current operational honest-input calibration policy.
///
/// This is an engineering model for SEAL's deterministic mod-t-and-divide
/// operation on honestly generated ciphertexts. It is not the deterministic
/// worst-case theorem implemented by `fhe/noise/deterministic.*`, and it does
/// not certify privacy or end-to-end completeness.
inline constexpr std::string_view kHonestDeterministicSwitchPolicyV3 =
    "Laminate/HonestDeterministicSwitch/RandomizedTailHeuristic/V3";

/// Payload error propagation follows each wire's actual dependencies. This
/// identity is separate from the modulus-switch rounding heuristic.
inline constexpr std::string_view kDependencyAwareHonestPayloadNoiseModelV1 =
    "LaminateImpl/DependencyAwareHonestPayloadNoise/v1";

/// Setup-bound calibration used by the public payload scheduler.
///
/// All error bounds are canonical BGV error units. Fixed operation debits are
/// powers of two applied to the actual operand envelopes. They are deliberately
/// inputs rather than library defaults: the selected values must come from a
/// reproducible honest-ciphertext calibration with an explicit margin.
struct HonestPayloadNoiseCalibration {
    std::uint64_t fresh_canonical_error_bound = 0;
    std::size_t ctct_relinearized_debit_bits = 0;
    std::size_t plaintext_multiplication_debit_bits = 0;
    std::size_t rotation_debit_bits = 0;

    /// The optional-switch test is q_l P' <= 2^tau P. Equality switches.
    std::size_t maximum_switch_tax_bits = 0;
    /// Setup-bound rounding allowance R_ms. For deterministic SEAL switching,
    /// its randomized-tail interpretation is the honest-ciphertext heuristic
    /// named by `kHonestDeterministicSwitchPolicyV3`.
    std::uint64_t switch_rounding_error_bound = 0;
    /// Audit metadata for the offline derivation of R_ms. The online
    /// scheduler consumes the exact bound above and performs no sampling.
    std::uint64_t modeled_switch_events_upper_bound = 0;
    std::size_t switch_model_failure_budget_bits = 0;

    /// Global natural-level availability floor retained during payload
    /// evaluation. A reserve of two leaves q_0 plus two droppable limbs. The
    /// setup-selected proof-ingress level may be lower and is recorded per
    /// source layer in `FheEvaluationPlan`.
    std::size_t proof_suffix_level_reserve = 0;

    void validate(const LayeredCircuit &circuit) const;

    bool operator==(
        const HonestPayloadNoiseCalibration &other) const = default;
};

/// Conservative integer evaluation of the randomized BGV modulus-switch
/// rounding allowance,
///
///   ceil(1 + sqrt((h+1)/2 * ln(2 r N / delta))).
///
/// Here `h=N`, `r=modeled_switch_events_upper_bound`, and
/// `delta=2^-switch_model_failure_budget_bits`. Production still executes
/// SEAL's deterministic switch. Reusing this randomized-rounding tail bound
/// for honestly generated ciphertexts is therefore an explicit engineering
/// heuristic, not a theorem about adversarial deterministic-switch inputs.
/// The result slightly upper-bounds the real-valued expression using integer
/// arithmetic so setup validation is platform independent.
std::uint64_t randomized_mod_switch_rounding_heuristic_bound(
    std::size_t ring_degree,
    std::uint64_t modeled_switch_events_upper_bound,
    std::size_t switch_model_failure_budget_bits);

enum class HonestPayloadSwitchDecision : std::uint8_t {
    IneligibleLayer,
    RetainForThreshold,
    RetainForProofSuffix,
    SwitchNow,
};

/// Presence bits for the eight base-field coordinates of one extension-field
/// ciphertext. Bit `i` is set exactly when coordinate `i` is encrypted.
using HonestBaseProofCoordinateMask = std::uint8_t;

/// Public envelope and level decision for one layer in evaluation order.
struct HonestPayloadLayerSchedule {
    std::size_t layer = 0;
    LayerKind kind = LayerKind::Affine;
    /// Diagnostic growth for uniformly bounded encrypted inputs. Actual
    /// propagation follows each dependency, so evaluated error need not equal
    /// this factor times the maximum input error.
    fhe::NaturalMagnitude layer_error_growth_factor;
    fhe::NaturalMagnitude input_canonical_error_bound;
    /// Maximum over evaluated outputs and affine temporaries, including an
    /// operation whose result is subsequently annihilated by a public zero.
    fhe::NaturalMagnitude evaluated_canonical_error_bound;
    /// Maximum over output wires only, after any selected modulus switch.
    fhe::NaturalMagnitude output_canonical_error_bound;
    fhe::NaturalMagnitude evaluated_phase_bound;
    fhe::NaturalMagnitude output_phase_bound;
    std::size_t input_rns_limb_count = 0;
    std::size_t output_rns_limb_count = 0;
    bool completed_relinearized_payload_multiplication = false;
    bool evaluated_phase_fits = false;
    bool output_phase_fits = false;
    HonestPayloadSwitchDecision decision =
        HonestPayloadSwitchDecision::IneligibleLayer;
    std::optional<std::uint64_t> dropped_modulus;
    std::optional<fhe::NaturalMagnitude> threshold_left;
    std::optional<fhe::NaturalMagnitude> threshold_right;

    bool switched() const {
        return decision == HonestPayloadSwitchDecision::SwitchNow;
    }

    bool operator==(
        const HonestPayloadLayerSchedule &other) const = default;
};

/// One exact switch point, ordered as the payload executes from input to
/// output. There is at most one entry per multiplication layer.
struct HonestPayloadSwitchPoint {
    std::size_t after_layer = 0;
    std::uint64_t dropped_modulus = 0;
    std::size_t switched_ciphertext_count = 0;
    std::size_t input_rns_limb_count = 0;
    std::size_t output_rns_limb_count = 0;
    fhe::NaturalMagnitude input_canonical_error_bound;
    fhe::NaturalMagnitude output_canonical_error_bound;

    bool operator==(
        const HonestPayloadSwitchPoint &other) const = default;
};

/// Exact public Base proof-ingress requirement and conservative
/// message-normalization envelope for one GKR reduction. Each encrypted
/// stored source value is switched once from its natural payload level to the
/// proof-ingress level. Base sends two extension values per sumcheck round and
/// one (affine) or two (multiplication) terminal values. Setup derives a safe
/// coordinate-support upper bound from compact circuit geometry; public-value
/// annihilation during challenge-dependent execution may realize a strict
/// subset. Planned proof-message event fields upper-bound calls to
/// `mod_switch_to_next`, not logical extension values.
///
/// `wire_variables` describes the virtual power-of-two sumcheck domain. For
/// dense multiplication this is log M for M output pairs, not log(2M) for the
/// source layer. It
/// does not materialize, encrypt, read, or otherwise assign backend state to
/// structural padding.
struct HonestBaseProofNormalizationLayerPlan {
    std::size_t reduction_layer = 0;
    LayerKind kind = LayerKind::Affine;
    std::size_t natural_source_rns_limb_count = 0;
    std::size_t proof_ingress_rns_limb_count = 0;
    std::size_t live_source_ciphertext_count = 0;
    std::size_t wire_variables = 0;
    std::size_t round_extension_ciphertext_count = 0;
    std::size_t terminal_extension_ciphertext_count = 0;
    std::size_t public_zero_extension_message_count = 0;
    /// One bit mask per extension message in transcript order. Bit `i` says
    /// coordinate `i` may be encrypted; observed masks must be subsets.
    std::vector<HonestBaseProofCoordinateMask> message_coordinate_masks;
    /// Upper bound on encrypted base-field coordinates across all extension
    /// messages in this reduction.
    std::size_t base_ciphertext_count = 0;
    std::uint64_t ingress_switch_events = 0;
    std::uint64_t proof_message_switch_events = 0;
    std::uint64_t switch_events = 0;

    bool operator==(
        const HonestBaseProofNormalizationLayerPlan &other) const = default;
};

/// Complete normalization envelope derived from the circuit and executable
/// payload level plan. Proof-message counts are safe upper bounds. It has no
/// entry, ciphertext, or event for a structural-padding position.
struct HonestBaseProofNormalizationPlan {
    std::vector<HonestBaseProofNormalizationLayerPlan> reductions;
    std::uint64_t ingress_switch_events = 0;
    std::uint64_t proof_message_switch_events = 0;
    std::uint64_t switch_events = 0;

    bool operator==(
        const HonestBaseProofNormalizationPlan &other) const = default;
};

enum class HonestBaseProofMessageFamily : std::uint8_t {
    AffineRoundAtOne,
    AffineRoundAtTwo,
    AffineTerminal,
    MultiplicationRoundPrimary,
    MultiplicationRoundAtTwo,
    MultiplicationLeftTerminal,
    MultiplicationRightTerminal,
};

const char *honest_base_proof_message_family_name(
    HonestBaseProofMessageFamily family);

/// Conservative message support for one transcript family. Support is stored
/// per occurrence because sparse circuit coordinates can make non-prefix
/// fixed-point evaluations public zero. `base_ciphertext_count` upper-bounds
/// encrypted coordinates; an execution may observe a strict subset.
struct HonestBaseProofMessageFamilyTopology {
    HonestBaseProofMessageFamily family =
        HonestBaseProofMessageFamily::AffineRoundAtOne;
    std::size_t extension_message_count = 0;
    std::size_t public_zero_extension_message_count = 0;
    std::vector<HonestBaseProofCoordinateMask> message_coordinate_masks;
    std::size_t base_ciphertext_count = 0;

    bool operator==(
        const HonestBaseProofMessageFamilyTopology &other) const = default;
};

/// Canonical Base transcript-message upper-bound topology for one reduction.
struct HonestBaseProofMessageTopology {
    std::vector<HonestBaseProofMessageFamilyTopology> families;
    std::size_t round_extension_message_count = 0;
    std::size_t terminal_extension_message_count = 0;
    std::size_t public_zero_extension_message_count = 0;
    /// Coordinate upper bounds in exact transcript order.
    std::vector<HonestBaseProofCoordinateMask> message_coordinate_masks;
    std::size_t base_ciphertext_count = 0;

    bool operator==(
        const HonestBaseProofMessageTopology &other) const = default;
};

/// Circuit-derived overload used by standalone callers. It binds source
/// width, output width and compact live-source support before deriving a safe
/// envelope. Complete normalization-plan derivation reuses one canonical
/// trace layout across all reductions.
HonestBaseProofMessageTopology derive_honest_base_proof_message_topology(
    const LayeredCircuit &circuit, std::size_t reduction_layer);

/// Reconstruct the exact family grouping from a setup-bound layer plan.
HonestBaseProofMessageTopology derive_honest_base_proof_message_topology(
    const HonestBaseProofNormalizationLayerPlan &plan);

/// One deterministic normalization transition for an encrypted Base proof
/// coefficient. The reduction-level assessor derives one such chain for the
/// maximum pre-normalization bound in each message family.
struct HonestBaseProofNoiseNormalizationStep {
    std::size_t input_rns_limb_count = 0;
    std::size_t output_rns_limb_count = 0;
    std::uint64_t dropped_modulus = 0;
    fhe::NaturalMagnitude input_canonical_error_bound;
    fhe::NaturalMagnitude output_canonical_error_bound;
    fhe::NaturalMagnitude input_phase_bound;
    fhe::NaturalMagnitude output_phase_bound;
    bool input_phase_fits = false;
    bool output_phase_fits = false;

    bool operator==(
        const HonestBaseProofNoiseNormalizationStep &other) const = default;
};

/// Honest-input envelope result for one proof-message family in one
/// reduction. Observed counts are checked against normalization-plan upper
/// bounds before an assessment can be admitted.
struct HonestBaseProofMessageFamilyAssessment {
    HonestBaseProofMessageFamily family =
        HonestBaseProofMessageFamily::AffineRoundAtOne;
    std::size_t extension_message_count = 0;
    std::size_t base_ciphertext_count = 0;
    std::size_t source_rns_limb_count = 0;
    fhe::NaturalMagnitude maximum_pre_normalization_canonical_error_bound;
    fhe::NaturalMagnitude maximum_pre_normalization_phase_bound;
    bool all_pre_normalization_phases_fit = false;
    std::vector<HonestBaseProofNoiseNormalizationStep>
        normalization_steps;
    fhe::NaturalMagnitude maximum_post_normalization_canonical_error_bound;
    fhe::NaturalMagnitude maximum_post_normalization_phase_bound;
    bool all_post_normalization_phases_fit = false;

    bool operator==(
        const HonestBaseProofMessageFamilyAssessment &other) const = default;
};

enum class HonestBaseProofNoiseFailureStage : std::uint8_t {
    PreNormalization,
    NormalizationStep,
    PostNormalization,
};

struct HonestBaseProofNoiseFailure {
    std::size_t reduction_layer = 0;
    HonestBaseProofMessageFamily family =
        HonestBaseProofMessageFamily::AffineRoundAtOne;
    /// Zero-based occurrence within `family`, in transcript order.
    std::size_t message_occurrence = 0;
    std::size_t coefficient_index = 0;
    HonestBaseProofNoiseFailureStage stage =
        HonestBaseProofNoiseFailureStage::PreNormalization;
    /// Present only when `stage == NormalizationStep`.
    std::optional<std::size_t> normalization_step;

    bool operator==(
        const HonestBaseProofNoiseFailure &other) const = default;
};

struct HonestBaseProofReductionNoiseAssessment {
    std::size_t reduction_layer = 0;
    LayerKind kind = LayerKind::Affine;
    std::size_t natural_source_rns_limb_count = 0;
    std::size_t proof_ingress_rns_limb_count = 0;
    std::size_t live_source_ciphertext_count = 0;
    fhe::NaturalMagnitude natural_source_canonical_error_bound;
    fhe::NaturalMagnitude proof_ingress_canonical_error_bound;
    bool ingress_input_phase_fits = false;
    std::vector<HonestBaseProofNoiseNormalizationStep>
        ingress_normalization_steps;
    std::optional<std::size_t> first_failed_ingress_step;
    bool all_ingress_phases_fit = false;
    /// Compatibility view of the level at which proof arithmetic begins.
    std::size_t source_rns_limb_count = 0;
    std::size_t wire_variables = 0;
    std::vector<HonestBaseProofMessageFamilyAssessment> families;
    std::size_t expected_extension_message_count = 0;
    std::size_t observed_extension_message_count = 0;
    std::uint64_t ingress_switch_events = 0;
    /// Planned upper bound followed by exact observed normalization work.
    std::uint64_t expected_proof_message_switch_events = 0;
    std::uint64_t observed_proof_message_switch_events = 0;
    /// Ingress plus the planned bound, followed by ingress plus observed work.
    std::uint64_t expected_switch_events = 0;
    std::uint64_t observed_switch_events = 0;
    std::optional<HonestBaseProofNoiseFailure> first_failure;
    bool topology_complete = false;
    bool all_messages_fit = false;

    bool operator==(
        const HonestBaseProofReductionNoiseAssessment &other) const = default;
};

/// Stable policy for the operational Base proof-noise assessment. The
/// assessor first applies the exact natural-to-ingress switch recurrence,
/// then executes the production file-backed topology twice under distinct
/// transcript histories and accepts only a challenge-independent result.
inline constexpr std::string_view kHonestBaseProofNoiseAssessmentPolicyV6 =
    "LaminateImpl/HonestBaseProofNoiseAssessment/v6";

/// Challenge-independent honest-input assessment of the complete Base proof
/// suffix. The payload schedule digest and exact proof-parameter digest bind
/// the two independent input domains; `reductions` is the re-derived report.
struct HonestBaseProofNoiseAssessment {
    std::string_view policy;
    Digest source_payload_schedule_digest{};
    Digest proof_noise_parameters_digest{};
    std::vector<HonestBaseProofReductionNoiseAssessment> reductions;
    /// Exact observed ingress-plus-normalization work, bounded by the
    /// setup-derived modeled switch-event envelope.
    std::uint64_t observed_switch_events = 0;
    std::optional<HonestBaseProofNoiseFailure> first_failure;
    bool topology_complete = false;
    bool all_messages_fit = false;

    /// Boolean summary of this report only. Admission must use the exact
    /// validating Base predicate, which re-derives the report first.
    bool report_accepts() const {
        return topology_complete && all_messages_fit &&
               !first_failure.has_value();
    }

    bool operator==(
        const HonestBaseProofNoiseAssessment &other) const = default;
};

/// Complete setup-derived schedule for one exact ordered modulus chain.
///
/// `data_moduli_low_to_high` is never sorted or otherwise rewritten. Its last
/// active entry is the next prime dropped by SEAL. `evaluation_plan` is the
/// exact executable level plan; callers should validate parity after decoding
/// either object from setup.
struct HonestPayloadNoiseSchedule {
    std::string_view policy = kHonestDeterministicSwitchPolicyV3;
    std::string_view payload_noise_model =
        kDependencyAwareHonestPayloadNoiseModelV1;
    /// Optional construction policy for the Base proof-ingress vector. Empty
    /// means the vector is caller-selected or accompanied by an exact offline
    /// assessment. The uniform fixed policy is validated from the schedule's
    /// reserve and every source level; it is not a free-form assertion.
    std::string_view base_proof_ingress_policy;
    HonestPayloadNoiseCalibration calibration;
    std::vector<std::uint64_t> data_moduli_low_to_high;
    std::size_t fresh_modulus_product_bits = 0;
    bool fresh_phase_fits = false;
    bool all_modeled_phases_fit = false;
    bool proof_suffix_reserve_preserved = false;
    /// Deterministic modulus-switch calls made by the initial payload
    /// evaluation. Structural padding contributes no ciphertext and no event.
    std::uint64_t modeled_payload_switch_events = 0;
    /// One-time deterministic switches of live payload artifacts from their
    /// natural evaluation levels to their setup-selected proof ingress.
    std::uint64_t modeled_base_proof_ingress_switch_events = 0;
    /// Safe upper bound on deterministic switches while Base normalizes proof
    /// messages from proof ingress to q_0.
    std::uint64_t modeled_base_proof_message_switch_events = 0;
    /// Exact Base proof-ingress switches plus the proof-message upper bound.
    std::uint64_t modeled_base_proof_switch_events = 0;
    /// End-to-end initial-payload plus Base-proof event requirement checked
    /// against `calibration.modeled_switch_events_upper_bound`.
    std::uint64_t modeled_switch_events = 0;
    std::vector<HonestPayloadLayerSchedule> layers_in_evaluation_order;
    std::vector<HonestPayloadSwitchPoint> switch_points;
    HonestBaseProofNormalizationPlan base_proof_normalization_plan;
    /// Null until the challenge-independent operational Base proof assessor
    /// has traversed every proof-message family and checked each observed
    /// encrypted coordinate.
    std::optional<HonestBaseProofNoiseAssessment>
        base_proof_noise_assessment;
    FheEvaluationPlan evaluation_plan;

    /// Payload-only operational model acceptance. This says nothing about
    /// noise accumulated while producing Base proof messages.
    bool payload_model_accepts() const {
        return fresh_phase_fits && all_modeled_phases_fit &&
               proof_suffix_reserve_preserved;
    }

    bool operator==(
        const HonestPayloadNoiseSchedule &other) const = default;
};

/// Immutable proof that one owned schedule has passed its exact semantic
/// validation, together with the canonical digest bound into public setup.
/// Keeping the schedule inside the certificate prevents a caller from
/// mutating it after validation and lets downstream protocol boundaries check
/// only the digest and their local execution preconditions.
class CertifiedHonestPayloadSchedule {
  public:
    CertifiedHonestPayloadSchedule(
        const CertifiedHonestPayloadSchedule &) = default;
    CertifiedHonestPayloadSchedule &operator=(
        const CertifiedHonestPayloadSchedule &) = default;
    CertifiedHonestPayloadSchedule(
        CertifiedHonestPayloadSchedule &&) noexcept = default;
    CertifiedHonestPayloadSchedule &operator=(
        CertifiedHonestPayloadSchedule &&) noexcept = default;

    const HonestPayloadNoiseSchedule &schedule() const {
        return state().schedule;
    }
    const Digest &circuit_digest() const { return state().circuit_digest; }
    const Digest &digest() const { return state().digest; }
    const std::optional<Digest> &proof_assessment_digest() const {
        return state().proof_assessment_digest;
    }

    /// Require the caller's independently authenticated circuit identity
    /// before exposing this certificate across a protocol boundary.
    void validate_circuit_digest(const Digest &expected) const;

    bool operator==(
        const CertifiedHonestPayloadSchedule &other) const {
        if (!state_ || !other.state_) {
            return state_ == other.state_;
        }
        return state_->schedule == other.state_->schedule &&
               state_->circuit_digest == other.state_->circuit_digest &&
               state_->digest == other.state_->digest &&
               state_->proof_assessment_digest ==
                   other.state_->proof_assessment_digest;
    }

  private:
    struct State {
        HonestPayloadNoiseSchedule schedule;
        Digest circuit_digest{};
        Digest digest{};
        std::optional<Digest> proof_assessment_digest;
    };

    CertifiedHonestPayloadSchedule(
        HonestPayloadNoiseSchedule schedule, Digest circuit_digest,
        Digest digest,
        std::optional<Digest> proof_assessment_digest)
        : state_(std::make_shared<const State>(State{
              std::move(schedule), circuit_digest, digest,
              std::move(proof_assessment_digest)})) {}

    const State &state() const;

    std::shared_ptr<const State> state_;

    friend CertifiedHonestPayloadSchedule
    certify_honest_payload_noise_schedule(
        const LayeredCircuit &, HonestPayloadNoiseSchedule);
    friend CertifiedHonestPayloadSchedule
    derive_certified_uniform_honest_base_proof_schedule(
        const LayeredCircuit &, std::span<const std::uint64_t>,
        HonestPayloadNoiseCalibration, std::size_t);
};

/// Validate an arbitrary owned schedule exactly once and seal it against
/// subsequent mutation.
CertifiedHonestPayloadSchedule certify_honest_payload_noise_schedule(
    const LayeredCircuit &circuit, HonestPayloadNoiseSchedule schedule);

/// Stable identity of the attached complete Base proof-noise assessment.
/// Declared at the schedule boundary so execution artifacts can authenticate
/// an assessed schedule without depending on the Base prover implementation.
Digest honest_base_proof_noise_assessment_digest(
    const HonestBaseProofNoiseAssessment &assessment);

/// Exact threshold predicate used by the setup scheduler. Equality returns
/// true; this is the fixed tie break for a boundary candidate.
bool honest_switch_within_tax_threshold(
    const fhe::NaturalMagnitude &input_phase_bound,
    const fhe::NaturalMagnitude &switched_phase_bound,
    std::uint64_t dropped_modulus,
    std::size_t maximum_switch_tax_bits);

/// Derive and validate exact ingress plus a safe Base proof-message
/// normalization upper-bound topology.
HonestBaseProofNormalizationPlan
derive_honest_base_proof_normalization_plan(
    const LayeredCircuit &circuit, const FheEvaluationPlan &plan);

void validate_honest_base_proof_normalization_plan(
    const LayeredCircuit &circuit, const FheEvaluationPlan &plan,
    const HonestBaseProofNormalizationPlan &normalization_plan);

/// Derive the public schedule for one exact ordered chain.
///
/// The function accepts no ciphertext, client context, secret key, or measured
/// invariant noise. It allows a drop only after a layer containing an actual
/// payload CT-CT multiplication, whose evaluator has completed the product and
/// relinearization before applying `FheEvaluationPlan`'s after-layer switch.
HonestPayloadNoiseSchedule derive_honest_payload_noise_schedule(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    const HonestPayloadNoiseCalibration &calibration);

/// Stable policy name for a fixed, uniform Base proof ingress. Setup retains
/// the requested number of RNS limbs at the payload boundary and uses that
/// same level for every proof source. The policy performs no operational proof
/// replay and makes neither a minimality nor a fresh completeness claim.
inline constexpr std::string_view kUniformBaseProofIngressPolicyV1 =
    "LaminateImpl/UniformBaseProofIngress/v1";

/// Derive a payload schedule with one setup-fixed Base proof level. This is the
/// inexpensive production alternative to the offline exhaustive selector: it
/// fixes `proof_suffix_level_reserve = proof_ingress_rns_limbs - 1` and applies
/// that ingress to every proof source. Layer zero is not a proof source and
/// remains at its natural level.
HonestPayloadNoiseSchedule derive_uniform_honest_base_proof_schedule(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    HonestPayloadNoiseCalibration calibration,
    std::size_t proof_ingress_rns_limbs);

/// Construct and certify the fixed uniform schedule without re-deriving the
/// schedule merely to hash the result returned by the trusted derivation.
CertifiedHonestPayloadSchedule
derive_certified_uniform_honest_base_proof_schedule(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    HonestPayloadNoiseCalibration calibration,
    std::size_t proof_ingress_rns_limbs);

/// Replace only the setup-public proof-ingress vector of an already derived
/// payload schedule. Natural trace levels, payload switch points, and payload
/// noise envelopes remain fixed; Base normalization topology and all event
/// totals are re-derived exactly. Layer zero must remain at its natural level.
HonestPayloadNoiseSchedule apply_honest_base_proof_ingress_depths(
    const LayeredCircuit &circuit, HonestPayloadNoiseSchedule schedule,
    std::span<const std::size_t> proof_ingress_mult_depth_by_layer);

/// Maximum switch-event domain needed to search every natural availability
/// reserve and every per-source ingress choice. For each natural schedule it
/// uses the exact payload events plus the larger endpoint of each reduction's
/// affine ingress/message event function, then takes the maximum across
/// reserves.
std::uint64_t honest_base_proof_ingress_search_event_upper_bound(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    HonestPayloadNoiseCalibration calibration);

/// Re-derive and validate the payload schedule while deliberately excluding
/// the optional Base proof-noise attachment. This nonrecursive boundary is
/// used by the Base assessor and by the stable payload-only setup digest.
void validate_honest_payload_noise_schedule_core(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule);

/// Re-derive `schedule` from its circuit, exact ordered chain, and
/// calibration, then validate the canonical shape and input bindings of an
/// optional Base proof-noise attachment. Exact operational re-execution is a
/// separate assessor validation step so ordinary execution does not repeat
/// the complete file-backed proof topology.
void validate_honest_payload_noise_schedule(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule);

/// Canonical schedule encoding for setup binding.
///
/// The encoding contains the compiled-circuit digest and the irreducible
/// derivation inputs. Validation first re-derives and compares every
/// redundant report and executable-plan field, so those fields cannot be
/// changed without rejection and need not be encoded twice.
std::vector<std::uint8_t> encode_canonical(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule);

Digest honest_payload_noise_schedule_digest(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule);

/// Reject any executable plan that differs from the setup-derived schedule.
void validate_honest_payload_plan_parity(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    const FheEvaluationPlan &plan);

/// Assessment of one exact prefix of a caller-supplied ordered maximum chain.
struct HonestPayloadChainPrefixAssessment {
    std::size_t fresh_rns_limb_count = 0;
    std::size_t fresh_modulus_product_bits = 0;
    HonestPayloadNoiseSchedule schedule;

    bool payload_model_accepts() const {
        return schedule.payload_model_accepts();
    }
};

/// Offline exact-prefix search. The deterministic selection rule is the first
/// model-accepted prefix, i.e. the fewest limbs from the supplied order. No
/// prime is reordered and no online observation can alter this choice.
struct HonestPayloadChainPrefixSearch {
    std::vector<HonestPayloadChainPrefixAssessment> assessments;
    std::optional<std::size_t> selected_assessment;

    const HonestPayloadChainPrefixAssessment *selected() const;
};

HonestPayloadChainPrefixSearch assess_honest_payload_chain_prefixes(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> maximum_data_moduli_low_to_high,
    const HonestPayloadNoiseCalibration &calibration);

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_NOISE_HONEST_NOISE_SCHEDULE_HPP
