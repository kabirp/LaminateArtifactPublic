#ifndef LAMINATE_GKR_DETAIL_LANED_VERIFIER_HPP
#define LAMINATE_GKR_DETAIL_LANED_VERIFIER_HPP

/// @file verifier.hpp
/// @brief Reader-parametric GKR verifier used by LaminateLaned.

#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/laned/affine/verifier.hpp"
#include "laminate/gkr/detail/laned/geometry/layers.hpp"
#include "laminate/gkr/detail/laned/multiplication/verifier.hpp"
#include "laminate/gkr/detail/laned/validation/request.hpp"
#include "laminate/gkr/detail/shared/packed/message_reader.hpp"
#include "laminate/gkr/detail/shared/packed/validated_structure.hpp"
#include "laminate/gkr/detail/shared/reduction/gate_claims.hpp"
#include "laminate/protocol/packed/preprocessing/workload.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace laminate::gkr::laned_detail {

/// Mutable output-to-input claim state of one Laned GKR verification.
/// `current_claim` is the claim on `next_layer`; each accepted reduction
/// replaces it with a claim on the following source layer.
struct LanedGkrVerificationState {
    /// Claim consumed by the next affine or multiplication verifier.
    LayerClaim current_claim;
    /// Index of the reduction replayed next.
    std::size_t next_layer = 0;
};

/// Verifies GKR independently of the physical fixed-message transport.
template <fhe::FheBackend Backend, typename Reader, typename Message>
class LanedGkrVerifier {
  public:
    using VerificationState = LanedGkrVerificationState;

    /// Replay the proof from the claimed output to the public input layer.
    /// The loop is deliberately here—not in a generic scheduler—so the
    /// verifier's protocol order is visible from this navigation surface.
    bool run() {
        // Step 1: Admit the proof structure, then bind its header, GateMLE
        // setup, and claimed output point in prover order.
        std::optional<VerificationState> state = begin();
        if (!state) {
            return false;
        }

        // Step 2: Replay each affine or multiplication reduction from the
        // claimed output toward the public input layer.
        while (has_next_layer(*state)) {
            if (!verify_next_layer(*state)) {
                return false;
            }
        }

        // Step 3: Check the final public-input claim, transport exhaustion,
        // and the accumulated GateMLE opening without short-circuiting.
        return finish(*state);
    }

    std::optional<VerificationState> begin() {
        // Step 1: Validate setup and the complete proof geometry without
        // changing Fiat--Shamir.
        if (authenticated_setup_id_ == nullptr) {
            public_setup_.validate(payload_, circuit_);
        }
        const bool structure_is_valid = proof_structure_validated_ ||
            (authenticated_setup_id_ != nullptr
                 ? validate_structure_against_setup_id(
                       proof_, expected_provenance_, expected_trace_id_,
                       public_setup_, circuit_, *authenticated_setup_id_)
                 : validate_structure(
                       proof_, expected_provenance_, expected_trace_id_,
                       public_setup_, circuit_));
        if (!structure_is_valid ||
            expected_output_claim_.point.size() !=
                laned_layer_variables(circuit_, 0)) {
            return std::nullopt;
        }

        // Step 2: Bind the proof identity, public GateMLE setup, and claimed
        // output point in the same order used by the prover.
        observe_proof_header(proof_.header, transcript_);
        gates::observe_gate_mle_setup(public_setup_, transcript_);
        base_detail::observe_output_point(expected_output_claim_.point,
                                          transcript_);
        // Step 3: Initialize the reverse layer walk at the output claim.
        return VerificationState{LayerClaim{expected_output_claim_}};
    }

    bool has_next_layer(const VerificationState &state) const {
        return state.next_layer < proof_.reductions.size();
    }

    payload::LayerKind next_layer_kind(
        const VerificationState &state) const {
        if (!has_next_layer(state)) {
            throw std::logic_error("LaminateLaned: no layer remains");
        }
        return payload::layer_kind(circuit_.layers[state.next_layer]);
    }

    bool verify_next_layer(VerificationState &state) {
        // Step 1: Select the circuit relation matching this proof reduction.
        const std::size_t layer = state.next_layer;

        // Step 2: Replay that relation's complete sumcheck. A successful
        // reduction returns precisely the source claim for the next layer.
        const std::optional<LayerClaim> next =
            next_layer_kind(state) == payload::LayerKind::Affine
                ? replay_affine_reduction(layer, state.current_claim)
                : replay_multiplication_reduction(
                      layer, state.current_claim);
        if (!next) {
            return false;
        }

        // Step 3: Advance only after the next claim is established.
        state.current_claim = *next;
        ++state.next_layer;
        return true;
    }

    bool terminal_claim_is_valid(
        const VerificationState &state) const {
        return state.next_layer >= proof_.reductions.size() &&
               terminal_input_claim_is_valid(state.current_claim) &&
               all_messages_consumed();
    }

    bool verify_gate_opening() { return gate_claims_.finish(); }

    bool finish(const VerificationState &state) {
        // Always verify the gate opening, even when the terminal claim is
        // false. This preserves the verifier's fail-closed final ordering.
        const bool terminal = terminal_claim_is_valid(state);
        const bool gate_opening = verify_gate_opening();
        return terminal && gate_opening;
    }

  private:
    std::optional<LayerClaim> replay_affine_reduction(
        std::size_t layer, const LayerClaim &current) {
        const LanedAffineLayerReduction<Message> &reduction =
            std::get<LanedAffineLayerReduction<Message>>(
                proof_.reductions[layer]);
        std::optional<SingleClaim> next =
            verify_affine_reduction<Backend>(
                reader_, circuit_, layer, current, reduction,
                gate_claims_, transcript_);
        if (!next) {
            return std::nullopt;
        }
        return LayerClaim{std::move(*next)};
    }

    std::optional<LayerClaim> replay_multiplication_reduction(
        std::size_t layer, const LayerClaim &current) {
        const SingleClaim *single = std::get_if<SingleClaim>(&current);
        if (single == nullptr) {
            return std::nullopt;
        }
        const LanedMultiplicationLayerReduction<Message> &reduction =
            std::get<LanedMultiplicationLayerReduction<Message>>(
                proof_.reductions[layer]);
        std::optional<SingleClaim> next =
            verify_multiplication_reduction<Backend>(
                reader_, circuit_, layer, *single, reduction, transcript_);
        if (!next) {
            return std::nullopt;
        }
        return LayerClaim{std::move(*next)};
    }

    bool all_messages_consumed() const {
        if constexpr (requires { reader_.all_messages_consumed(); }) {
            return reader_.all_messages_consumed();
        }
        return true;
    }

    bool terminal_input_claim_is_valid(const LayerClaim &current) const {
        const SingleClaim *terminal = std::get_if<SingleClaim>(&current);
        if (terminal == nullptr) {
            return false;
        }
        const packing::LanedPackingLayout input_layout =
            laned_layout(circuit_, circuit_.layers.size() - 1);
        if (input_layout.original_wire_count == 1 &&
            input_layer_.size() == 1 &&
            input_layer_.front().size() == input_layout.lane_count) {
            return evaluate_prefix_input_mle(
                       input_layer_.front(), terminal->point) ==
                   terminal->value;
        }
        return evaluate_packed_laned_layer(
                   input_layer_, input_layout, terminal->point) ==
               terminal->value;
    }

  public:

    /// Opaque evidence returned only after this verifier validates the
    /// complete proof structure. The shared token remains bound to this exact
    /// verifier specialization and proof snapshot.
    using ValidatedStructure =
        ::laminate::gkr::detail::ValidatedPackedGkrStructure<
            LanedGkrProof<Message>,
            LanedGkrVerifier<Backend, Reader, Message>>;

    static std::optional<ValidatedStructure> validate_structure_once(
        const LanedGkrProof<Message> &proof,
        payload::TraceProvenance provenance, const Digest &trace_id,
        const PublicSetup &setup,
        const payload::LayeredCircuit &circuit) {
        if (!validate_structure(proof, provenance, trace_id, setup,
                                circuit)) {
            return std::nullopt;
        }
        return ValidatedStructure(proof, provenance, trace_id, setup,
                                  circuit);
    }

    static std::optional<ValidatedStructure> validate_structure_once(
        const protocol::CertifiedPackedWorkloadStatic &workload,
        const LanedGkrProof<Message> &proof,
        payload::TraceProvenance provenance, const Digest &trace_id) {
        if (!validate_structure_against_setup_id(
                proof, provenance, trace_id, workload.public_setup(),
                workload.circuit(), workload.setup_digest())) {
            return std::nullopt;
        }
        return ValidatedStructure(
            proof, provenance, trace_id, workload.public_setup(),
            workload.circuit());
    }

    LanedGkrVerifier(
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit,
        std::span<const fhe::SlotVector> input_layer,
        const ClientSetup<Backend> &setup,
        payload::TraceProvenance expected_provenance,
        const Digest &expected_trace_id,
        const SingleClaim &expected_output_claim,
        const LanedGkrProof<Message> &proof, Reader &reader,
        Transcript &transcript)
        : payload_(payload), circuit_(circuit), input_layer_(input_layer),
          public_setup_(setup.public_setup),
          expected_provenance_(expected_provenance),
          expected_trace_id_(expected_trace_id),
          expected_output_claim_(expected_output_claim), proof_(proof),
          transcript_(transcript),
          gate_claims_(circuit, setup.public_setup,
                       proof.gate_mle_opening, transcript),
          reader_(reader) {}

    LanedGkrVerifier(
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit,
        std::span<const fhe::SlotVector> input_layer,
        const ClientSetup<Backend> &setup,
        payload::TraceProvenance expected_provenance,
        const Digest &expected_trace_id,
        const SingleClaim &expected_output_claim,
        const LanedGkrProof<Message> &proof, Reader &reader,
        Transcript &transcript,
        const ValidatedStructure &validated_structure)
        : LanedGkrVerifier(payload, circuit, input_layer, setup,
                           expected_provenance, expected_trace_id,
                           expected_output_claim, proof, reader,
                           transcript) {
        proof_structure_validated_ = validated_structure.matches(
            proof, expected_provenance, expected_trace_id,
            setup.public_setup, circuit);
    }

    LanedGkrVerifier(
        const protocol::CertifiedPackedWorkloadStatic &workload,
        std::span<const fhe::SlotVector> input_layer,
        payload::TraceProvenance expected_provenance,
        const Digest &expected_trace_id,
        const SingleClaim &expected_output_claim,
        const LanedGkrProof<Message> &proof, Reader &reader,
        Transcript &transcript)
        : payload_(workload.payload()), circuit_(workload.circuit()),
          input_layer_(input_layer), public_setup_(workload.public_setup()),
          expected_provenance_(expected_provenance),
          expected_trace_id_(expected_trace_id),
          expected_output_claim_(expected_output_claim), proof_(proof),
          transcript_(transcript),
          gate_claims_(circuit_, public_setup_, proof.gate_mle_opening,
                       transcript),
          reader_(reader),
          authenticated_setup_id_(&workload.setup_digest()) {}

    LanedGkrVerifier(
        const protocol::CertifiedPackedWorkloadStatic &workload,
        std::span<const fhe::SlotVector> input_layer,
        payload::TraceProvenance expected_provenance,
        const Digest &expected_trace_id,
        const SingleClaim &expected_output_claim,
        const LanedGkrProof<Message> &proof, Reader &reader,
        Transcript &transcript,
        const ValidatedStructure &validated_structure)
        : LanedGkrVerifier(workload, input_layer, expected_provenance,
                           expected_trace_id, expected_output_claim, proof,
                           reader, transcript) {
        proof_structure_validated_ = validated_structure.matches(
            proof, expected_provenance, expected_trace_id,
            workload.public_setup(), workload.circuit());
    }

  private:
    /// Public payload semantics authenticated by setup.
    const payload::PayloadCircuit &payload_;
    /// Layered arithmetization whose reductions are replayed.
    const payload::LayeredCircuit &circuit_;
    /// Plaintext input slots used only for the terminal MLE check.
    std::span<const fhe::SlotVector> input_layer_;
    /// Public preprocessing data, including the committed GateMLE tables.
    const PublicSetup &public_setup_;
    /// Trace provenance required by the proof header.
    payload::TraceProvenance expected_provenance_;
    /// Trace digest required by the proof header.
    const Digest &expected_trace_id_;
    /// Output claim that initializes reverse GKR.
    const SingleClaim &expected_output_claim_;
    /// Ordered Laned reduction messages supplied by the prover.
    const LanedGkrProof<Message> &proof_;
    /// Fiat--Shamir transcript replayed in prover order.
    Transcript &transcript_;
    /// Accumulates affine GateMLE claims for the final opening check.
    ::laminate::gkr::detail::VerifierGateClaims gate_claims_;
    /// Decodes each fixed-size proof message exactly once.
    Reader &reader_;
    /// True only when a matching one-shot structural-admission token was used.
    bool proof_structure_validated_ = false;
    /// Authenticated setup identifier for the certified-workload path.
    const Digest *authenticated_setup_id_ = nullptr;
};

/// Diagnostic verifier for a common-layout, unpacked encrypted GKR transcript.
template <fhe::FheBackend Backend>
bool verify_encrypted_gkr(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> input_layer,
    const ClientSetup<Backend> &setup,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const SingleClaim &expected_output_claim,
    const EncryptedLanedProof<Backend> &proof, Transcript &transcript) {
    try {
        detail::FixedMessageReader<Backend> reader(setup.context);
        return LanedGkrVerifier<Backend, decltype(reader),
                                fhe::FheValue<Backend>>(
                   payload, circuit, input_layer, setup,
                   expected_provenance, expected_trace_id,
                   expected_output_claim, proof, reader, transcript)
            .run();
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    } catch (const std::overflow_error &) {
        return false;
    } catch (const std::runtime_error &) {
        return false;
    }
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_VERIFIER_HPP
