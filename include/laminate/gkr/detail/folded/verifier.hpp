#ifndef LAMINATE_GKR_DETAIL_FOLDED_VERIFIER_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_VERIFIER_HPP

/// @file verifier.hpp
/// @brief LaminateFolded GKR verification over decrypted packed messages.

#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/folded/affine/verifier.hpp"
#include "laminate/gkr/detail/folded/multiplication/verifier.hpp"
#include "laminate/gkr/detail/folded/validation/request.hpp"
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

namespace laminate::gkr::folded_detail {

/// Verifies GKR independently of how fixed messages are transported.
///
/// `Message` is either a tagged public-or-encrypted packed value (diagnostic
/// raw-GKR verification) or a `CommittedPackedMessage` (the selected
/// protocol). `Reader` supplies the corresponding plaintext values.
template <fhe::FheBackend Backend, typename Reader, typename Message>
class FoldedGkrVerifier {
  public:
    /// Mutable output-to-input claim state for Folded GKR verification.
    /// Profiling may advance it one layer at a time; `run()` owns the same
    /// canonical verifier order for ordinary callers.
    struct FoldedGkrVerificationState {
        /// Claim on `next_layer`, established by the preceding reduction.
        LayerClaim current_claim;
        /// Circuit/proof reduction that must be verified next.
        std::size_t next_layer = 0;
    };

    /// Replay the proof from the claimed output to the public input layer.
    /// The loop is deliberately here—not in a generic scheduler—so the
    /// verifier's protocol order is visible from this navigation surface.
    bool run() {
        // Step 1: Admit the complete proof shape, then bind its header and
        // expected output claim to Fiat--Shamir.
        std::optional<FoldedGkrVerificationState> state = begin();
        if (!state) {
            return false;
        }

        // Step 2: Replay each affine or multiplication layer reduction from
        // the claimed output back to the public input layer.
        while (has_next_layer(*state)) {
            if (!verify_next_layer(*state)) {
                return false;
            }
        }

        // Step 3: Check the final input-layer claim and the batched GateMLE
        // opening. Both checks run even if the terminal claim is false.
        return finish(*state);
    }

    std::optional<FoldedGkrVerificationState> begin() {
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
                base_detail::layer_vars(circuit_, 0)) {
            return std::nullopt;
        }

        // Step 2: Bind the proof identity, public GateMLE setup, and claimed
        // output point in the same order used by the prover.
        observe_proof_header(proof_.header, transcript_);
        gates::observe_gate_mle_setup(public_setup_, transcript_);
        base_detail::observe_output_point(expected_output_claim_.point,
                                          transcript_);
        // Step 3: Initialize the reverse layer walk at the output claim.
        return FoldedGkrVerificationState{
            LayerClaim{expected_output_claim_}};
    }

    bool has_next_layer(const FoldedGkrVerificationState &state) const {
        return state.next_layer < proof_.reductions.size();
    }

    payload::LayerKind next_layer_kind(
        const FoldedGkrVerificationState &state) const {
        if (!has_next_layer(state)) {
            throw std::logic_error("LaminateFolded: no layer remains");
        }
        return payload::layer_kind(circuit_.layers[state.next_layer]);
    }

    bool verify_next_layer(FoldedGkrVerificationState &state) {
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
        const FoldedGkrVerificationState &state) const {
        if (state.next_layer < proof_.reductions.size() ||
            !all_messages_consumed()) {
            return false;
        }
        if (circuit_.payload_input_count == 1 && input_layer_.size() == 1 &&
            input_layer_.front().size() == circuit_.shape.value_width()) {
            return verify_prefix_input_claim(input_layer_.front(),
                                             state.current_claim);
        }
        return verify_terminal_claim(input_layer_, state.current_claim);
    }

    bool verify_gate_opening() { return gate_claims_.finish(); }

    bool finish(const FoldedGkrVerificationState &state) {
        // Always verify the gate opening, even when the terminal claim is
        // false. This preserves the verifier's fail-closed final ordering.
        const bool terminal = terminal_claim_is_valid(state);
        const bool gate_opening = verify_gate_opening();
        return terminal && gate_opening;
    }

  private:
    std::optional<LayerClaim> replay_affine_reduction(
        std::size_t layer, const LayerClaim &current) {
        const FoldedAffineLayerReduction<Message> &reduction =
            std::get<FoldedAffineLayerReduction<Message>>(
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
        const FoldedMultiplicationLayerReduction<Message> &reduction =
            std::get<FoldedMultiplicationLayerReduction<Message>>(
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

  public:

    /// Opaque evidence returned only after this verifier validates the
    /// complete proof structure. The shared token remains bound to this exact
    /// verifier specialization and proof snapshot.
    using ValidatedStructure =
        ::laminate::gkr::detail::ValidatedPackedGkrStructure<
            FoldedGkrProof<Message>,
            FoldedGkrVerifier<Backend, Reader, Message>>;

    /// Validate an ordinary caller-supplied setup once. The returned token
    /// lets the verifier avoid repeating the same proof walk after packing.
    static std::optional<ValidatedStructure> validate_structure_once(
        const FoldedGkrProof<Message> &proof,
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

    /// Certified counterpart: reuse the setup digest authenticated with the
    /// immutable workload instead of canonically encoding and hashing setup
    /// again on every request.
    static std::optional<ValidatedStructure> validate_structure_once(
        const protocol::CertifiedPackedWorkloadStatic &workload,
        const FoldedGkrProof<Message> &proof,
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

    FoldedGkrVerifier(
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit,
        std::span<const fhe::SlotVector> input_layer,
        const ClientSetup<Backend> &setup,
        payload::TraceProvenance expected_provenance,
        const Digest &expected_trace_id,
        const SingleClaim &expected_output_claim,
        const FoldedGkrProof<Message> &proof, Reader &reader,
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

    FoldedGkrVerifier(
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit,
        std::span<const fhe::SlotVector> input_layer,
        const ClientSetup<Backend> &setup,
        payload::TraceProvenance expected_provenance,
        const Digest &expected_trace_id,
        const SingleClaim &expected_output_claim,
        const FoldedGkrProof<Message> &proof, Reader &reader,
        Transcript &transcript,
        const ValidatedStructure &validated_structure)
        : FoldedGkrVerifier(payload, circuit, input_layer, setup,
                            expected_provenance, expected_trace_id,
                            expected_output_claim, proof, reader,
                            transcript) {
        proof_structure_validated_ = validated_structure.matches(
            proof, expected_provenance, expected_trace_id,
            setup.public_setup, circuit);
    }

    FoldedGkrVerifier(
        const protocol::CertifiedPackedWorkloadStatic &workload,
        std::span<const fhe::SlotVector> input_layer,
        payload::TraceProvenance expected_provenance,
        const Digest &expected_trace_id,
        const SingleClaim &expected_output_claim,
        const FoldedGkrProof<Message> &proof, Reader &reader,
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

    FoldedGkrVerifier(
        const protocol::CertifiedPackedWorkloadStatic &workload,
        std::span<const fhe::SlotVector> input_layer,
        payload::TraceProvenance expected_provenance,
        const Digest &expected_trace_id,
        const SingleClaim &expected_output_claim,
        const FoldedGkrProof<Message> &proof, Reader &reader,
        Transcript &transcript,
        const ValidatedStructure &validated_structure)
        : FoldedGkrVerifier(workload, input_layer, expected_provenance,
                            expected_trace_id, expected_output_claim,
                            proof, reader, transcript) {
        proof_structure_validated_ = validated_structure.matches(
            proof, expected_provenance, expected_trace_id,
            workload.public_setup(), workload.circuit());
    }

  private:
    /// Public payload and canonical layered arithmetization being verified.
    const payload::PayloadCircuit &payload_;
    const payload::LayeredCircuit &circuit_;
    /// Client-known plaintext input vectors used for the terminal claim.
    std::span<const fhe::SlotVector> input_layer_;
    /// Public setup containing the authenticated GateMLE commitment.
    const PublicSetup &public_setup_;
    /// Trace identity that the proof header must authenticate.
    payload::TraceProvenance expected_provenance_;
    const Digest &expected_trace_id_;
    /// Initial claim at circuit layer zero.
    const SingleClaim &expected_output_claim_;
    /// Immutable proof whose reductions are replayed in circuit order.
    const FoldedGkrProof<Message> &proof_;
    /// Fiat--Shamir state shared with message decoding and GateMLE openings.
    Transcript &transcript_;
    /// Verifier accumulator for all outsourced public-gate evaluations.
    ::laminate::gkr::detail::VerifierGateClaims gate_claims_;
    /// Converts packed proof messages into their logical plaintext values.
    Reader &reader_;
    /// True when an immutable validation token matches this proof snapshot.
    bool proof_structure_validated_ = false;
    /// Preauthenticated setup digest, present only for certified workloads.
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
    const EncryptedFoldedProof<Backend> &proof, Transcript &transcript) {
    try {
        detail::FixedMessageReader<Backend> reader(setup.context);
        return FoldedGkrVerifier<Backend, decltype(reader),
                                 fhe::FheValue<Backend>>(
                   payload, circuit, input_layer, setup,
                   expected_provenance, expected_trace_id,
                   expected_output_claim, proof, reader, transcript)
            .run();
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    } catch (const std::runtime_error &) {
        return false;
    }
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_VERIFIER_HPP
