#ifndef LAMINATE_PROTOCOL_PACKED_EXTERNAL_PROVER_HPP
#define LAMINATE_PROTOCOL_PACKED_EXTERNAL_PROVER_HPP

/// @file prover.hpp
/// @brief Destructive checkpoint-replay GKR with external transcript packing.

#include "laminate/gkr/detail/folded/prover.hpp"
#include "laminate/gkr/detail/laned/prover.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/protocol/folded.hpp"
#include "laminate/protocol/laned.hpp"
#include "laminate/protocol/packed/external/transcript_packing.hpp"

#include <cstddef>
#include <filesystem>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace laminate::protocol {

using FoldedExternalGkrProofOptions =
    gkr::folded_detail::IrreversibleFileFoldedGkrOptions;
using LanedExternalGkrProofOptions =
    gkr::laned_detail::IrreversibleFileLanedGkrOptions;

namespace detail {
struct PackedExternalProverSetupFactory;
struct PackedExternalAdmissionAccess;
}

/// Immutable binding between one GKR variant/circuit, its exact proof-ingress
/// limb schedule, and the artifact-backed transcript-packing certificate.
/// Construct this during preprocessing, before publishing a replay trace.
class PackedExternalProverSetup {
  public:
    PackingGkrVariant variant() const noexcept { return variant_; }
    std::size_t bhip_round_count() const noexcept {
        return bhip_round_count_;
    }
    const Digest &layered_circuit_digest() const noexcept {
        return layered_circuit_digest_;
    }
    const Digest &identity() const noexcept { return identity_; }
    std::span<const std::size_t>
    proof_ingress_rns_limbs_by_layer() const noexcept {
        return proof_ingress_schedule_.rns_limbs_by_layer();
    }
    const ConservativePackedProofIngressSchedule &
    proof_ingress_schedule() const noexcept {
        return proof_ingress_schedule_;
    }
    const TranscriptPackingExternalProverSetup &transcript_packing() const {
        return transcript_packing_;
    }

  private:
    PackedExternalProverSetup(
        PackingGkrVariant variant, std::size_t bhip_round_count,
        Digest layered_circuit_digest, Digest identity,
        ConservativePackedProofIngressSchedule proof_ingress_schedule,
        TranscriptPackingExternalProverSetup transcript_packing)
        : variant_(variant), bhip_round_count_(bhip_round_count),
          layered_circuit_digest_(layered_circuit_digest),
          identity_(identity),
          proof_ingress_schedule_(std::move(proof_ingress_schedule)),
          transcript_packing_(std::move(transcript_packing)) {}

    friend PackedExternalProverSetup
    make_folded_packed_external_prover_setup(
        const payload::PayloadCircuit &,
        const payload::LayeredCircuit &, const PublicSetup &,
        const ConservativePackedProofIngressSchedule &,
        TranscriptPackingExternalProverSetup);
    friend struct detail::PackedExternalProverSetupFactory;
    friend PackedExternalProverSetup
    make_laned_packed_external_prover_setup(
        const payload::PayloadCircuit &,
        const payload::LayeredCircuit &, const PublicSetup &,
        const ConservativePackedProofIngressSchedule &,
        TranscriptPackingExternalProverSetup);

    PackingGkrVariant variant_ = PackingGkrVariant::Folded;
    std::size_t bhip_round_count_ = 0;
    Digest layered_circuit_digest_{};
    Digest identity_{};
    ConservativePackedProofIngressSchedule proof_ingress_schedule_;
    TranscriptPackingExternalProverSetup transcript_packing_;
};

template <packing::SignedDigitPackingBackend Backend>
class CertifiedPackedExternalGkrStatic;

namespace packed_external_detail {
template <packing::SignedDigitPackingBackend Backend>
CertifiedPackedExternalGkrStatic<Backend> certify_static_gkr(
    PackingGkrVariant, const payload::PayloadCircuit &,
    const payload::LayeredCircuit &, const EvaluationSetup<Backend> &,
    const PackedExternalProverSetup &,
    payload::EncryptedTraceDescriptor);
}

template <packing::SignedDigitPackingBackend Backend>
CertifiedPackedExternalGkrStatic<Backend>
certify_packed_external_gkr_static(
    PackingGkrVariant expected_variant,
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &evaluation,
    const PackedExternalProverSetup &setup,
    payload::EncryptedTraceDescriptor proof_trace_template);

/// Opaque result of complete setup/circuit/claim-flow preprocessing for the
/// recurring packed GKR server. Reduced online validation accepts this token,
/// never an unauthenticated collection of raw pointers.
template <packing::SignedDigitPackingBackend Backend>
class CertifiedPackedExternalGkrStatic {
  public:
    PackingGkrVariant variant() const noexcept { return state_->variant; }
    std::span<const gkr::detail::DenseMultiplicationSourcePlan>
    multiplication_source_plans() const noexcept {
        return state_->multiplication_source_plans;
    }
    bool matches(
        PackingGkrVariant variant,
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit,
        const EvaluationSetup<Backend> &evaluation,
        const PackedExternalProverSetup &setup) const noexcept {
        return state_->variant == variant && state_->payload == &payload &&
               state_->circuit == &circuit &&
               state_->evaluation == &evaluation && state_->setup == &setup;
    }

  private:
    struct State {
        PackingGkrVariant variant = PackingGkrVariant::Folded;
        const payload::PayloadCircuit *payload = nullptr;
        const payload::LayeredCircuit *circuit = nullptr;
        const EvaluationSetup<Backend> *evaluation = nullptr;
        const PackedExternalProverSetup *setup = nullptr;
        std::vector<gkr::detail::DenseMultiplicationSourcePlan>
            multiplication_source_plans;
    };

    explicit CertifiedPackedExternalGkrStatic(
        std::shared_ptr<const State> state)
        : state_(std::move(state)) {}

    friend CertifiedPackedExternalGkrStatic<Backend>
    certify_packed_external_gkr_static<Backend>(
        PackingGkrVariant, const payload::PayloadCircuit &,
        const payload::LayeredCircuit &,
        const EvaluationSetup<Backend> &,
        const PackedExternalProverSetup &,
        payload::EncryptedTraceDescriptor);
    friend CertifiedPackedExternalGkrStatic<Backend>
    packed_external_detail::certify_static_gkr<Backend>(
        PackingGkrVariant, const payload::PayloadCircuit &,
        const payload::LayeredCircuit &,
        const EvaluationSetup<Backend> &,
        const PackedExternalProverSetup &,
        payload::EncryptedTraceDescriptor);

    std::shared_ptr<const State> state_;
};

PackedExternalProverSetup make_folded_packed_external_prover_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const ConservativePackedProofIngressSchedule &proof_ingress_schedule,
    TranscriptPackingExternalProverSetup transcript_packing);

PackedExternalProverSetup make_laned_packed_external_prover_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const ConservativePackedProofIngressSchedule &proof_ingress_schedule,
    TranscriptPackingExternalProverSetup transcript_packing);

/// Validate the complete compact external setup against the live circuit and
/// evaluation context without scanning preprocessing artifacts or writing
/// proof state. Servers call this before payload evaluation; the later
/// one-shot admission still authenticates and admits the external artifacts.
template <packing::SignedDigitPackingBackend Backend>
void preflight_packed_external_prover_setup(
    PackingGkrVariant expected_variant,
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &evaluation,
    const PackedExternalProverSetup &setup);

/// Reject any ancestry overlap between the replay/GKR namespaces and every
/// mutable external-packing namespace. Call this before moving the packing
/// options into their one-shot admission.
void preflight_folded_packed_external_resource_roots(
    const std::filesystem::path &replay_root,
    const FoldedExternalGkrProofOptions &gkr_options,
    const TranscriptPackingExternalAdmission &packing_admission);

void preflight_laned_packed_external_resource_roots(
    const std::filesystem::path &replay_root,
    const LanedExternalGkrProofOptions &gkr_options,
    const TranscriptPackingExternalAdmission &packing_admission);

struct FoldedCheckpointReplayExternalOptions {
    FoldedExternalGkrProofOptions gkr;
    TranscriptPackingExternalProverOptions transcript_packing;
};

struct LanedCheckpointReplayExternalOptions {
    LanedExternalGkrProofOptions gkr;
    TranscriptPackingExternalProverOptions transcript_packing;
};

/// Wall and process-CPU time for the two online proof suffixes. Laned witness
/// packing is measured by the payload trace because it is deliberately
/// executed beside forward evaluation rather than inside this suffix.
struct PackedExternalProverPhaseTimings {
    double gkr_wall_ms = 0.0;
    double gkr_cpu_ms = 0.0;
    double transcript_packing_wall_ms = 0.0;
    double transcript_packing_cpu_ms = 0.0;

    bool operator==(const PackedExternalProverPhaseTimings &) const =
        default;
};

/// Move-only complete Folded admission. It binds the live trace and every
/// immutable input/resource before the trace's no-retry boundary, and owns
/// the single external-packing preprocessing scan until proving consumes it.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
class FoldedCheckpointReplayExternalAdmission {
  public:
    FoldedCheckpointReplayExternalAdmission(
        FoldedCheckpointReplayExternalAdmission &&) noexcept = default;
    FoldedCheckpointReplayExternalAdmission &operator=(
        FoldedCheckpointReplayExternalAdmission &&) noexcept = default;
    FoldedCheckpointReplayExternalAdmission(
        const FoldedCheckpointReplayExternalAdmission &) = delete;
    FoldedCheckpointReplayExternalAdmission &operator=(
        const FoldedCheckpointReplayExternalAdmission &) = delete;

    TranscriptPackingExternalPreflightReport packing_report() const {
        return packing_.report();
    }

  private:
    FoldedCheckpointReplayExternalAdmission(
        const payload::PayloadCircuit *payload,
        const payload::LayeredCircuit *circuit,
        payload::PayloadCheckpointReplayTrace<Backend> *trace,
        const EvaluationSetup<Backend> *evaluation,
        const PackedExternalProverSetup *setup,
        std::vector<Fpk> output_point,
        FoldedExternalGkrProofOptions gkr_options,
        TranscriptPackingExternalAdmission packing,
        const CertifiedPackedExternalGkrStatic<Backend> *gkr_static)
        : payload_(payload), circuit_(circuit), trace_(trace),
          evaluation_(evaluation), setup_(setup),
          output_point_(std::move(output_point)),
          gkr_options_(std::move(gkr_options)),
          packing_(std::move(packing)), gkr_static_(gkr_static) {}

    friend struct detail::PackedExternalAdmissionAccess;

    const payload::PayloadCircuit *payload_ = nullptr;
    const payload::LayeredCircuit *circuit_ = nullptr;
    payload::PayloadCheckpointReplayTrace<Backend> *trace_ = nullptr;
    const EvaluationSetup<Backend> *evaluation_ = nullptr;
    const PackedExternalProverSetup *setup_ = nullptr;
    std::vector<Fpk> output_point_;
    FoldedExternalGkrProofOptions gkr_options_;
    TranscriptPackingExternalAdmission packing_;
    const CertifiedPackedExternalGkrStatic<Backend> *gkr_static_ = nullptr;
};

/// Laned counterpart of the complete Folded admission.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
class LanedCheckpointReplayExternalAdmission {
  public:
    LanedCheckpointReplayExternalAdmission(
        LanedCheckpointReplayExternalAdmission &&) noexcept = default;
    LanedCheckpointReplayExternalAdmission &operator=(
        LanedCheckpointReplayExternalAdmission &&) noexcept = default;
    LanedCheckpointReplayExternalAdmission(
        const LanedCheckpointReplayExternalAdmission &) = delete;
    LanedCheckpointReplayExternalAdmission &operator=(
        const LanedCheckpointReplayExternalAdmission &) = delete;

    TranscriptPackingExternalPreflightReport packing_report() const {
        return packing_.report();
    }

  private:
    LanedCheckpointReplayExternalAdmission(
        const payload::PayloadCircuit *payload,
        const payload::LayeredCircuit *circuit,
        payload::PayloadCheckpointReplayTrace<Backend> *trace,
        const EvaluationSetup<Backend> *evaluation,
        const PackedExternalProverSetup *setup,
        std::vector<Fpk> output_point,
        LanedExternalGkrProofOptions gkr_options,
        TranscriptPackingExternalAdmission packing,
        const CertifiedPackedExternalGkrStatic<Backend> *gkr_static)
        : payload_(payload), circuit_(circuit), trace_(trace),
          evaluation_(evaluation), setup_(setup),
          output_point_(std::move(output_point)),
          gkr_options_(std::move(gkr_options)),
          packing_(std::move(packing)), gkr_static_(gkr_static) {}

    friend struct detail::PackedExternalAdmissionAccess;

    const payload::PayloadCircuit *payload_ = nullptr;
    const payload::LayeredCircuit *circuit_ = nullptr;
    payload::PayloadCheckpointReplayTrace<Backend> *trace_ = nullptr;
    const EvaluationSetup<Backend> *evaluation_ = nullptr;
    const PackedExternalProverSetup *setup_ = nullptr;
    std::vector<Fpk> output_point_;
    LanedExternalGkrProofOptions gkr_options_;
    TranscriptPackingExternalAdmission packing_;
    const CertifiedPackedExternalGkrStatic<Backend> *gkr_static_ = nullptr;
};

template <packing::CoefficientWellFormednessBackend Backend>
    requires fhe::PersistableFheBackend<Backend>
struct FoldedCheckpointReplayExternalResult {
    LaminateFoldedProof<Backend> proof;
    gkr::folded_detail::FileFoldedGkrReport gkr_report;
    payload::PayloadCheckpointReplayExecutionReport payload_replay_report;
    TranscriptPackingExternalProverReport transcript_packing_report;
    PackedExternalProverPhaseTimings phase_timings;
};

template <packing::CoefficientWellFormednessBackend Backend>
    requires fhe::PersistableFheBackend<Backend>
struct LanedCheckpointReplayExternalResult {
    LaminateLanedProof<Backend> proof;
    gkr::laned_detail::FileLanedGkrReport gkr_report;
    payload::PayloadCheckpointReplayExecutionReport payload_replay_report;
    TranscriptPackingExternalProverReport transcript_packing_report;
    PackedExternalProverPhaseTimings phase_timings;
};

/// Complete no-write admission before Folded crosses the checkpoint trace's
/// no-retry boundary. The returned report is the exact packing admission.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
FoldedCheckpointReplayExternalAdmission<Backend>
admit_folded_checkpoint_replay_external_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const PackedExternalProverSetup &prover_setup,
    std::span<const Fpk> output_point,
    const FoldedCheckpointReplayExternalOptions &options);

/// Compose a trace with an external packing admission that was obtained and
/// retained before payload evaluation. This path performs no second scan.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
FoldedCheckpointReplayExternalAdmission<Backend>
admit_folded_checkpoint_replay_with_packing_admission_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const PackedExternalProverSetup &prover_setup,
    std::span<const Fpk> output_point,
    FoldedExternalGkrProofOptions gkr_options,
    TranscriptPackingExternalAdmission packing_admission);

/// Destructive Folded checkpoint/replay proof with a one-shot external
/// packing suffix. Any failure after preflight is terminal for `trace`; the
/// caller must publish a fresh replay session and must not retry this one.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
FoldedCheckpointReplayExternalResult<Backend>
prove_folded_checkpoint_replay_external_irreversible(
    FoldedCheckpointReplayExternalAdmission<Backend> admission,
    Transcript &transcript,
    gkr::ProofTransportPolicy transport = {});

/// Laned counterpart of the complete no-write Folded admission.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
LanedCheckpointReplayExternalAdmission<Backend>
admit_laned_checkpoint_replay_external_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const PackedExternalProverSetup &prover_setup,
    std::span<const Fpk> output_point,
    const LanedCheckpointReplayExternalOptions &options);

/// Laned counterpart that consumes a packing admission retained since before
/// payload evaluation and therefore performs no second immutable-state scan.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
LanedCheckpointReplayExternalAdmission<Backend>
admit_laned_checkpoint_replay_with_packing_admission_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const PackedExternalProverSetup &prover_setup,
    std::span<const Fpk> output_point,
    LanedExternalGkrProofOptions gkr_options,
    TranscriptPackingExternalAdmission packing_admission);

/// Destructive Laned checkpoint/replay proof with a one-shot external
/// packing suffix. Any failure after preflight is terminal for `trace`.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
LanedCheckpointReplayExternalResult<Backend>
prove_laned_checkpoint_replay_external_irreversible(
    LanedCheckpointReplayExternalAdmission<Backend> admission,
    Transcript &transcript,
    gkr::ProofTransportPolicy transport = {});

} // namespace laminate::protocol

#include "laminate/protocol/packed/external/detail/prover_impl.hpp"

#endif // LAMINATE_PROTOCOL_PACKED_EXTERNAL_PROVER_HPP
