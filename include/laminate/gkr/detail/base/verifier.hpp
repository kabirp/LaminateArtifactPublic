#ifndef LAMINATE_GKR_DETAIL_BASE_VERIFIER_HPP
#define LAMINATE_GKR_DETAIL_BASE_VERIFIER_HPP

/// @file verifier.hpp
/// @brief Layer-by-layer LaminateBase client verifier.

#include "laminate/gkr/detail/base/affine/verifier.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/gkr/detail/base/multiplication/verifier.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/base/validation/request.hpp"
#include "laminate/gkr/detail/base/verification/diagnostic.hpp"
#include "laminate/gkr/detail/base/verification/proof_reader.hpp"
#include "laminate/protocol/setup/base_client.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <variant>

namespace laminate::gkr::base_detail {

/// Mutable output-to-input claim state of one Base GKR verification.
/// `current_claim` is attached to `next_layer`; an accepted reduction replaces
/// it with the claim on the following source layer.
struct BaseGkrVerificationState {
    LayerClaim current_claim;
    std::size_t next_layer = 0;
};

template <fhe::FheBackend Backend, typename Reader>
class BaseGkrVerifier {
  public:
    using VerificationState = BaseGkrVerificationState;

    /// Replay the proof from the claimed output to the public input layer.
    /// The complete layer order is visible here rather than delegated to a
    /// generic callback or state-machine framework.
    bool run() {
        base_verifier_diagnostic().reset();
        // Step 1: validate proof geometry and bind the public statement,
        // setup, output claim, and proof header to Fiat--Shamir.
        std::optional<VerificationState> state = begin();
        if (!state) {
            return false;
        }

        // Step 2: replay each affine or multiplication reduction in circuit
        // order, carrying its typed source claim into the next layer.
        while (has_next_layer(*state)) {
            if (!verify_next_layer(*state)) {
                return false;
            }
        }

        // Step 3: check the final public-input claim and the accumulated
        // preprocessed GateMLE opening. Neither check short-circuits the other.
        return finish(*state);
    }

    std::optional<VerificationState> begin() {
        base_verifier_diagnostic().enter("header-and-geometry");
        // Step 1: Validate setup and the complete proof geometry without
        // changing Fiat--Shamir.
        if (certified_layout_ == nullptr) {
            public_setup_.validate(payload_, circuit_);
        }
        if (!validate_structure(
                proof_, expected_provenance_, expected_trace_id_,
                public_setup_, circuit_)) {
            base_verifier_diagnostic().detail =
                "proof structure, provenance, or trace-id validation failed";
            return std::nullopt;
        }
        if (expected_output_claim_.point.size() != layer_vars(circuit_, 0)) {
            base_verifier_diagnostic().detail =
                "output claim point arity does not match the circuit";
            return std::nullopt;
        }

        // Step 2: Bind the proof identity, public GateMLE setup, and claimed
        // output point in the same order used by the prover.
        observe_proof_header(proof_.header, transcript_);
        gates::observe_gate_mle_setup(public_setup_, transcript_);
        observe_output_point(expected_output_claim_.point, transcript_);

        // Step 3: Initialize the reverse layer walk at the output claim.
        return VerificationState{LayerClaim{expected_output_claim_}};
    }

    bool has_next_layer(const VerificationState &state) const {
        return state.next_layer < proof_.reductions.size();
    }

    payload::LayerKind next_layer_kind(
        const VerificationState &state) const {
        if (!has_next_layer(state)) {
            throw std::logic_error("LaminateBase: no layer remains");
        }
        return payload::layer_kind(circuit_.layers[state.next_layer]);
    }

    bool verify_next_layer(VerificationState &state) {
        // Step 1: Select the circuit relation matching this proof reduction.
        const std::size_t layer = state.next_layer;
        const bool affine =
            next_layer_kind(state) == payload::LayerKind::Affine;
        base_verifier_diagnostic().enter(
            affine ? "affine-reduction" : "multiplication-reduction", layer);

        // Step 2: Replay that relation's complete sumcheck. A successful
        // reduction returns precisely the source claim for the next layer.
        const std::optional<LayerClaim> next =
            affine ? replay_affine_reduction(layer, state.current_claim)
                   : replay_multiplication_reduction(layer,
                                                     state.current_claim);
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
        if (state.next_layer < proof_.reductions.size()) {
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

    bool finish(const VerificationState &state) {
        // The gate opening is checked even when the terminal input claim is
        // false. Keep these calls separate so a bad terminal claim cannot
        // short-circuit the final proof check.
        const bool terminal = terminal_claim_is_valid(state);
        const bool gate_opening = verify_gate_opening();
        if (!terminal) {
            base_verifier_diagnostic().enter("terminal-input-claim");
            base_verifier_diagnostic().detail =
                "reduced input claim does not match the public inputs";
        } else if (!gate_opening) {
            base_verifier_diagnostic().enter("gate-mle-opening");
            base_verifier_diagnostic().detail =
                "accumulated preprocessed GateMLE opening does not verify";
        }
        return terminal && gate_opening;
    }

  private:
    std::optional<LayerClaim> replay_affine_reduction(
        std::size_t layer, const LayerClaim &current) {
        const EncryptedBaseAffineLayerReduction<Backend> &reduction =
            std::get<EncryptedBaseAffineLayerReduction<Backend>>(
                proof_.reductions[layer]);
        std::optional<SingleClaim> next =
            ::laminate::gkr::base_detail::verify_affine_reduction<Backend>(
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
            base_verifier_diagnostic().detail =
                "incoming claim is not a single claim as this layer requires";
            return std::nullopt;
        }
        const EncryptedBaseMultiplicationLayerReduction<Backend> &reduction =
            std::get<EncryptedBaseMultiplicationLayerReduction<Backend>>(
                proof_.reductions[layer]);
        std::optional<SingleClaim> next;
        if (certified_layout_ == nullptr) {
            next = ::laminate::gkr::base_detail::
                verify_multiplication_reduction<Backend>(
                    reader_, circuit_, layer, *single, reduction,
                    transcript_);
        } else {
            next = ::laminate::gkr::base_detail::
                verify_multiplication_reduction_with_storage<Backend>(
                    reader_, circuit_,
                    certified_layout_->storage.at(layer + 1U), layer,
                    *single, reduction, transcript_);
        }
        if (!next) {
            return std::nullopt;
        }
        return LayerClaim{std::move(*next)};
    }

  public:
    /// Construct the bounded raw-setup verifier used by reference tests and
    /// profiling. `run()` still performs setup and proof admission.
    BaseGkrVerifier(
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit,
        std::span<const fhe::SlotVector> input_layer,
        const ClientSetup<Backend> &setup,
        payload::TraceProvenance expected_provenance,
        const Digest &expected_trace_id,
        const SingleClaim &expected_output_claim,
        const EncryptedBaseProof<Backend> &proof, Reader &reader,
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

    /// Construct the production verifier from authenticated static setup.
    BaseGkrVerifier(
        const protocol::CertifiedBaseClientSetup<Backend> &setup,
        std::span<const fhe::SlotVector> input_layer,
        payload::TraceProvenance expected_provenance,
        const Digest &expected_trace_id,
        const SingleClaim &expected_output_claim,
        const EncryptedBaseProof<Backend> &proof, Reader &reader,
        Transcript &transcript)
        : payload_(setup.payload()), circuit_(setup.circuit()),
          input_layer_(input_layer), public_setup_(setup.public_setup()),
          expected_provenance_(expected_provenance),
          expected_trace_id_(expected_trace_id),
          expected_output_claim_(expected_output_claim), proof_(proof),
          transcript_(transcript),
          gate_claims_(circuit_, public_setup_, proof.gate_mle_opening,
                       transcript),
          reader_(reader), certified_layout_(&setup.layout()) {}

  private:

    const payload::PayloadCircuit &payload_; ///< Authenticated payload program.
    const payload::LayeredCircuit &circuit_; ///< Layered GKR arithmetization.
    std::span<const fhe::SlotVector> input_layer_; ///< Public input values.
    const PublicSetup &public_setup_; ///< Authenticated GateMLE preprocessing.
    payload::TraceProvenance expected_provenance_; ///< Required trace origin.
    const Digest &expected_trace_id_; ///< Required trace digest.
    const SingleClaim &expected_output_claim_; ///< Initial output claim.
    const EncryptedBaseProof<Backend> &proof_; ///< Ordered layer messages.
    Transcript &transcript_; ///< Fiat--Shamir state replayed in prover order.
    ::laminate::gkr::detail::VerifierGateClaims gate_claims_;
    Reader &reader_; ///< Decrypts each fixed-size Base proof message.
    const payload::CanonicalTraceLayout *certified_layout_ = nullptr;
};

/// Bounded raw-setup reference entry point. It reuses the production verifier
/// arithmetic; production clients use `verify_base_gkr` with certified setup.
template <fhe::FheBackend Backend>
bool verify_base_gkr_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> input_layer,
    const ClientSetup<Backend> &setup,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const SingleClaim &expected_output_claim,
    const EncryptedBaseProof<Backend> &proof, Transcript &transcript) {
    try {
        ProofReader<Backend> reader(setup.context);
        return BaseGkrVerifier<Backend, decltype(reader)>(
                   payload, circuit, input_layer, setup,
                   expected_provenance, expected_trace_id,
                   expected_output_claim, proof, reader, transcript)
            .run();
    } catch (const std::invalid_argument &error) {
        return record_base_verifier_exception(error);
    } catch (const std::out_of_range &error) {
        return record_base_verifier_exception(error);
    } catch (const std::runtime_error &error) {
        return record_base_verifier_exception(error);
    }
}

template <fhe::FheBackend Backend>
bool verify_base_gkr(
    const protocol::CertifiedBaseClientSetup<Backend> &setup,
    std::span<const fhe::SlotVector> input_layer,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const SingleClaim &expected_output_claim,
    const EncryptedBaseProof<Backend> &proof, Transcript &transcript) {
    try {
        ProofReader<Backend> reader(setup.context());
        return BaseGkrVerifier<Backend, decltype(reader)>(
                   setup, input_layer, expected_provenance,
                   expected_trace_id, expected_output_claim, proof, reader,
                   transcript)
            .run();
    } catch (const std::invalid_argument &error) {
        return record_base_verifier_exception(error);
    } catch (const std::out_of_range &error) {
        return record_base_verifier_exception(error);
    } catch (const std::runtime_error &error) {
        return record_base_verifier_exception(error);
    }
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_VERIFIER_HPP
