#ifndef LAMINATE_PROTOCOL_DETAIL_PACKING_GKR_TRANSCRIPT_REPLAY_HPP
#define LAMINATE_PROTOCOL_DETAIL_PACKING_GKR_TRANSCRIPT_REPLAY_HPP

/// @file gkr_transcript_replay.hpp
/// @brief One public challenge walk, followed by deferred GKR arithmetic.
///
/// Packed GKR fixes ciphertext commitments before their plaintexts are
/// available. Those commitments, public gate claims, and circuit geometry
/// determine every challenge. Public replay authenticates gate openings and
/// continues the transcript into Spartan before proof-message decryption.
/// The resulting plan retains the challenges and gate values needed to check
/// the recovered plaintext messages later, without hashing or opening gates
/// a second time.

#include "laminate/gkr/detail/base/claims/evaluation.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/folded/affine/types.hpp"
#include "laminate/gkr/detail/folded/multiplication/types.hpp"
#include "laminate/gkr/detail/laned/affine/internal/gate_claim.hpp"
#include "laminate/gkr/detail/laned/affine/internal/hadamard.hpp"
#include "laminate/gkr/detail/laned/geometry/layers.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/geometry.hpp"
#include "laminate/gkr/detail/shared/packed/transcript.hpp"
#include "laminate/gkr/detail/shared/reduction/gate_claims.hpp"
#include "laminate/gkr/detail/shared/reduction/sumcheck.hpp"
#include "laminate/protocol/detail/packing/committed_gkr_encoding.hpp"
#include "laminate/protocol/detail/profiling/clock.hpp"
#include "laminate/protocol/fiat_shamir.hpp"
#include "laminate/protocol/metrics/types.hpp"
#include "laminate/verification_profile.hpp"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace laminate::protocol::detail {

template <gkr::ProtocolVariant Variant>
class PackedGkrReplayPlan;

template <gkr::ProtocolVariant Variant, typename Backend>
std::optional<PackedGkrReplayPlan<Variant>> replay_packed_gkr_transcript(
    const payload::LayeredCircuit &circuit, const PublicSetup &setup,
    const gkr::detail::PackedGkrProof<gkr::CommittedPackedMessage, Variant>
        &proof,
    std::span<const Fpk> output_point, Transcript &transcript,
    BaseVerifierTimings *timings = nullptr);

/// Authenticated public data for deferred GKR verification. Only the public
/// replay routine can construct a plan, and callers cannot alter its data.
/// The borrowed proof must remain alive and immutable until verification ends.
/// A digest check at the deferred boundary detects accidental or adversarial
/// mutation between the two phases; it is not another Fiat--Shamir replay.
template <gkr::ProtocolVariant Variant>
class PackedGkrReplayPlan final {
    static_assert(gkr::detail::kIsPackedProofVariant<Variant>);
    using Proof = gkr::detail::PackedGkrProof<
        gkr::CommittedPackedMessage, Variant>;
    using AffineProof = gkr::detail::PackedAffineReduction<
        gkr::CommittedPackedMessage, Variant>;
    using MultiplicationProof = gkr::detail::PackedMultiplicationReduction<
        gkr::CommittedPackedMessage, Variant>;

    struct Layer {
        payload::LayerKind kind = payload::LayerKind::Affine;
        std::vector<Fpk> challenges;
        Fpk affine_constant = Fpk::zero();
        Fpk affine_gate = Fpk::zero();
        Fpk inverse_hadamard_factor = Fpk::one();
        std::vector<Fpk> affine_source_point;
        std::vector<Fpk> multiplication_output_point;
        Fpk selector_challenge = Fpk::zero();
    };

    struct Data {
        const Proof *proof = nullptr;
        Digest proof_digest{};
        std::vector<Fpk> output_point;
        std::vector<Layer> layers;
        std::size_t input_count = 0;
        std::size_t input_width = 0;
        std::optional<packing::LanedPackingLayout> input_layout;
    };

  public:
    template <typename Reader>
    class PlaintextVerifier final {
      public:
        struct VerificationState {
            gkr::LayerClaim current_claim;
            std::size_t next_layer = 0;
        };

        std::optional<VerificationState> begin() {
            const verification_profile::ScopedVerificationPhase recovery(
                verification_profile::Category::Recovery);
            // Reusing an already-consumed reader is never an accepted proof.
            if (begun_ || data_->proof != &proof_ ||
                expected_output_claim_.point != data_->output_point ||
                committed_gkr_encoding_digest(proof_) != data_->proof_digest) {
                return std::nullopt;
            }
            begun_ = true;
            return VerificationState{gkr::LayerClaim{expected_output_claim_}};
        }

        bool has_next_layer(const VerificationState &state) const {
            return state.next_layer < data_->layers.size();
        }

        payload::LayerKind next_layer_kind(
            const VerificationState &state) const {
            return data_->layers.at(state.next_layer).kind;
        }

        bool verify_next_layer(VerificationState &state) {
            if (!begun_ || failed_ || !has_next_layer(state)) {
                return false;
            }
            const Layer &layer = data_->layers[state.next_layer];
            const bool accepted = layer.kind == payload::LayerKind::Affine
                ? verify_affine(state, layer)
                : verify_multiplication(state, layer);
            if (!accepted) {
                failed_ = true;
                return false;
            }
            ++state.next_layer;
            return true;
        }

        bool terminal_claim_is_valid(const VerificationState &state) const {
            if (!begun_ || failed_ ||
                state.next_layer != data_->layers.size()) {
                return false;
            }
            if constexpr (requires { reader_.all_messages_consumed(); }) {
                if (!reader_.all_messages_consumed()) {
                    return false;
                }
            }
            if constexpr (Variant == gkr::ProtocolVariant::LaminateFolded) {
                if (data_->input_count == 1 && input_layer_.size() == 1 &&
                    input_layer_.front().size() == data_->input_width) {
                    return gkr::verify_prefix_input_claim(
                        input_layer_.front(), state.current_claim);
                }
                return gkr::verify_terminal_claim(input_layer_,
                                                  state.current_claim);
            } else {
                const auto *terminal =
                    std::get_if<gkr::SingleClaim>(&state.current_claim);
                if (terminal == nullptr) {
                    return false;
                }
                const auto &layout = *data_->input_layout;
                if (layout.original_wire_count == 1 &&
                    input_layer_.size() == 1 &&
                    input_layer_.front().size() == layout.lane_count) {
                    return gkr::evaluate_prefix_input_mle(
                               input_layer_.front(), terminal->point) ==
                           terminal->value;
                }
                return gkr::evaluate_packed_laned_layer(
                           input_layer_, layout, terminal->point) ==
                       terminal->value;
            }
        }

        /// The private plan constructor certifies that the public replay has
        /// already checked this exact proof's gate opening.
        bool verify_gate_opening() const { return begun_ && !failed_; }

        bool finish(const VerificationState &state) const {
            return terminal_claim_is_valid(state) && verify_gate_opening();
        }

        bool run() {
            auto state = begin();
            if (!state) {
                return false;
            }
            while (has_next_layer(*state)) {
                if (!verify_next_layer(*state)) {
                    return false;
                }
            }
            return finish(*state);
        }

      private:
        PlaintextVerifier(std::shared_ptr<const Data> data,
                          std::span<const fhe::SlotVector> input_layer,
                          const gkr::SingleClaim &expected_output_claim,
                          const Proof &proof, Reader &reader)
            : data_(std::move(data)), input_layer_(input_layer),
              expected_output_claim_(expected_output_claim), proof_(proof),
              reader_(reader) {}

        bool verify_affine(VerificationState &state, const Layer &layer) {
            const auto &proof = std::get<AffineProof>(
                proof_.reductions[state.next_layer]);
            Fpk running = gkr::base_detail::claim_value(state.current_claim) -
                          layer.affine_constant;
            for (std::size_t round = 0; round < layer.challenges.size();
                 ++round) {
                const auto decoded = reader_.read(
                    proof.rounds[round].packed_evaluations, 2);
                if (decoded.size() != 2) {
                    return false;
                }
                const gkr::detail::LayerReductionRoundEvaluations polynomial{
                    running - decoded[0], decoded[0], decoded[1]};
                running = polynomial.interpolate_at(layer.challenges[round]);
            }
            const auto decoded = reader_.read(proof.packed_terminal_value, 1);
            if (decoded.size() != 1 || layer.affine_gate * decoded[0] != running) {
                return false;
            }
            state.current_claim = gkr::SingleClaim{
                layer.affine_source_point,
                decoded[0] * layer.inverse_hadamard_factor};
            return true;
        }

        bool verify_multiplication(VerificationState &state,
                                   const Layer &layer) {
            const auto *single =
                std::get_if<gkr::SingleClaim>(&state.current_claim);
            if (single == nullptr ||
                single->point != layer.multiplication_output_point) {
                return false;
            }
            const auto &proof = std::get<MultiplicationProof>(
                proof_.reductions[state.next_layer]);
            Fpk running = single->value;
            for (std::size_t round = 0; round < layer.challenges.size();
                 ++round) {
                const auto decoded = reader_.read(
                    proof.rounds[round].packed_evaluations, 2);
                if (decoded.size() != 2) {
                    return false;
                }
                const Fpk &tau = layer.multiplication_output_point[round];
                const auto endpoints = gkr::detail::
                    recover_dense_multiplication_endpoints(
                        running, tau, decoded[0]);
                const gkr::detail::LayerReductionRoundEvaluations polynomial{
                    endpoints.zero, endpoints.one, decoded[1]};
                running = polynomial.interpolate_at(layer.challenges[round]);
            }
            const auto decoded = reader_.read(proof.packed_source_values, 2);
            if (decoded.size() != 2 ||
                !gkr::detail::dense_multiplication_terminal_is_valid(
                    decoded[0], decoded[1], running)) {
                return false;
            }
            state.current_claim = gkr::detail::
                make_dense_multiplication_source_claim(
                    layer.challenges, decoded[0], decoded[1],
                    layer.selector_challenge);
            return true;
        }

        std::shared_ptr<const Data> data_;
        std::span<const fhe::SlotVector> input_layer_;
        gkr::SingleClaim expected_output_claim_;
        const Proof &proof_;
        Reader &reader_;
        bool begun_ = false;
        bool failed_ = false;
        friend class PackedGkrReplayPlan;
    };

    template <typename Reader>
    PlaintextVerifier<Reader> make_plaintext_verifier(
        std::span<const fhe::SlotVector> input_layer,
        const gkr::SingleClaim &expected_output_claim,
        const Proof &proof, Reader &reader) const {
        return PlaintextVerifier<Reader>(
            data_, input_layer, expected_output_claim, proof, reader);
    }

  private:
    explicit PackedGkrReplayPlan(std::shared_ptr<const Data> data)
        : data_(std::move(data)) {}

    std::shared_ptr<const Data> data_;
    template <gkr::ProtocolVariant V, typename Backend>
    friend std::optional<PackedGkrReplayPlan<V>>
    replay_packed_gkr_transcript(
        const payload::LayeredCircuit &, const PublicSetup &,
        const gkr::detail::PackedGkrProof<gkr::CommittedPackedMessage, V> &,
        std::span<const Fpk>, Transcript &, BaseVerifierTimings *);
};

/// Replay the public part of an admitted packed GKR proof. The caller has
/// already authenticated the setup, statement identities and complete proof
/// shape. This routine additionally checks the geometry it consumes. Values
/// in `point_claim` are unused zero placeholders: only the points enter
/// the public gate queries and challenge walk.
/// No sumcheck is accepted until the resulting plan checks its plaintexts.
template <gkr::ProtocolVariant Variant, typename Backend>
std::optional<PackedGkrReplayPlan<Variant>> replay_packed_gkr_transcript(
    const payload::LayeredCircuit &circuit, const PublicSetup &setup,
    const gkr::detail::PackedGkrProof<gkr::CommittedPackedMessage, Variant>
        &proof,
    std::span<const Fpk> output_point, Transcript &transcript,
    BaseVerifierTimings *timings) {
    static_assert(fhe::FheBackend<Backend>);
    using Plan = PackedGkrReplayPlan<Variant>;
    using AffineProof = typename Plan::AffineProof;
    using MultiplicationProof = typename Plan::MultiplicationProof;
    try {
        const verification_profile::ScopedVerificationPhase recovery(
            verification_profile::Category::Recovery);
        constexpr bool folded =
            Variant == gkr::ProtocolVariant::LaminateFolded;
        if (circuit.layers.empty() ||
            proof.reductions.size() != circuit.layers.size() - 1U ||
            proof.header.profile.variant != Variant ||
            proof.header.profile.gate_mle != setup.gate_mle_profile ||
            proof.header.version !=
                gkr::detail::PackedProofTraits<Variant>::proof_version ||
            circuit.shape.kind != (folded ? payload::PayloadKind::Wide
                                          : payload::PayloadKind::Laned)) {
            return std::nullopt;
        }
        const std::size_t output_variables = folded
            ? gkr::base_detail::layer_vars(circuit, 0)
            : gkr::laned_layer_variables(circuit, 0);
        if (output_point.size() != output_variables) {
            return std::nullopt;
        }
        auto data = std::make_shared<typename Plan::Data>();
        data->proof = &proof;
        data->proof_digest = committed_gkr_encoding_digest(proof);
        data->output_point.assign(output_point.begin(), output_point.end());
        data->input_count = circuit.payload_input_count;
        data->input_width = circuit.shape.value_width();
        if constexpr (!folded) {
            data->input_layout = gkr::laned_layout(
                circuit, circuit.layers.size() - 1U);
        }
        data->layers.reserve(proof.reductions.size());

        gkr::detail::VerifierGateClaims gate_claims(
            circuit, setup, proof.gate_mle_opening, transcript);
        observe_packed_fiat_shamir_schedule(transcript);
        gkr::observe_proof_header(proof.header, transcript);
        gates::observe_gate_mle_setup(setup, transcript);
        gkr::base_detail::observe_output_point(output_point, transcript);
        gkr::LayerClaim point_claim = gkr::SingleClaim{
            data->output_point, Fpk::zero()};

        for (std::size_t index = 0; index < proof.reductions.size(); ++index) {
            std::optional<profiling_detail::Stopwatch> layer_timer;
            if (timings != nullptr) {
                layer_timer.emplace();
            }
            typename Plan::Layer layer;
            layer.kind = payload::layer_kind(circuit.layers[index]);
            if (layer.kind == payload::LayerKind::Affine) {
                const auto *affine =
                    std::get_if<AffineProof>(&proof.reductions[index]);
                const std::size_t rounds = folded
                    ? gkr::base_detail::layer_vars(circuit, index + 1U)
                    : gkr::laned_layer_variables(circuit, index + 1U);
                if (affine == nullptr || affine->rounds.size() != rounds) {
                    return std::nullopt;
                }
                std::vector<Fpk> lane_point;
                if constexpr (folded) {
                    layer.affine_constant = gkr::base_detail::
                        affine_constant_at(gate_claims, index, point_claim);
                } else {
                    const auto output_layout = gkr::laned_layout(circuit, index);
                    lane_point = gkr::laned_detail::common_lane_point(
                        output_layout, point_claim);
                    layer.affine_constant = gkr::laned_detail::
                        affine_constant_at(gate_claims, index, output_layout,
                                           point_claim);
                }
                if (lane_point.size() > rounds) {
                    return std::nullopt;
                }
                gkr::detail::observe_packed_reduction_begin<Variant>(
                    index, payload::LayerKind::Affine, rounds, transcript);
                layer.challenges.reserve(rounds);
                const std::size_t lane_begin = rounds - lane_point.size();
                for (std::size_t round = 0; round < rounds; ++round) {
                    gkr::detail::observe_packed_round<Variant>(
                        index, round, affine->rounds[round], transcript);
                    layer.challenges.push_back(round < lane_begin
                        ? transcript.challenge_fpk()
                        : gkr::laned_detail::challenge_hadamard_safe(
                              transcript, lane_point[round - lane_begin]));
                }
                gkr::detail::observe_packed_terminal<Variant>(
                    index, affine->packed_terminal_value, transcript);
                layer.affine_source_point = layer.challenges;
                if constexpr (folded) {
                    layer.affine_gate = gkr::base_detail::affine_gate_at(
                        gate_claims, index, point_claim, layer.challenges);
                } else {
                    layer.affine_gate = gkr::laned_detail::affine_wire_at(
                        gate_claims, index, gkr::laned_layout(circuit, index),
                        gkr::laned_layout(circuit, index + 1U), point_claim,
                        layer.challenges);
                    const auto transform = gkr::laned_detail::hadamard_transform(
                        lane_point, std::span<const Fpk>(layer.challenges)
                                        .subspan(lane_begin));
                    std::copy(transform.point.begin(), transform.point.end(),
                              layer.affine_source_point.begin() +
                                  static_cast<std::ptrdiff_t>(lane_begin));
                    layer.inverse_hadamard_factor = transform.factor.inverse();
                }
                point_claim = gkr::SingleClaim{
                    layer.affine_source_point, Fpk::zero()};
            } else if (layer.kind == payload::LayerKind::Multiplication) {
                const auto *multiplication =
                    std::get_if<MultiplicationProof>(&proof.reductions[index]);
                const auto *single = std::get_if<gkr::SingleClaim>(&point_claim);
                if (multiplication == nullptr || single == nullptr) {
                    return std::nullopt;
                }
                std::size_t rounds = 0;
                if constexpr (folded) {
                    rounds = gkr::detail::DenseMultiplicationDimensions::create(
                        payload::layer_dimensions(circuit.layers[index]).padded_size,
                        payload::layer_dimensions(circuit.layers[index + 1U]).padded_size,
                        circuit.shape.value_width()).round_count();
                } else {
                    const auto output = gkr::laned_layout(circuit, index);
                    const auto source = gkr::laned_layout(circuit, index + 1U);
                    rounds = gkr::detail::DenseMultiplicationDimensions::create(
                        output.padded_ciphertext_count,
                        source.padded_ciphertext_count, output.slot_count)
                                 .round_count();
                }
                if (multiplication->rounds.size() != rounds ||
                    single->point.size() != rounds) {
                    return std::nullopt;
                }
                layer.multiplication_output_point = single->point;
                gkr::detail::observe_packed_reduction_begin<Variant>(
                    index, payload::LayerKind::Multiplication, rounds, transcript);
                layer.challenges.reserve(rounds);
                for (std::size_t round = 0; round < rounds; ++round) {
                    gkr::detail::observe_packed_round<Variant>(
                        index, round, multiplication->rounds[round], transcript);
                    layer.challenges.push_back(transcript.challenge_fpk());
                }
                gkr::detail::observe_packed_terminal<Variant>(
                    index, multiplication->packed_source_values, transcript);
                layer.selector_challenge = transcript.challenge_fpk();
                point_claim = gkr::detail::make_dense_multiplication_source_claim(
                    layer.challenges, Fpk::zero(), Fpk::zero(),
                    layer.selector_challenge);
            } else {
                return std::nullopt;
            }
            if (timings != nullptr) {
                const auto elapsed = layer_timer->stop();
                timings->layers.push_back(BaseLayerTiming{
                    index, layer.kind, elapsed.wall_ms, elapsed.cpu_ms});
            }
            data->layers.push_back(std::move(layer));
        }
        {
            std::optional<profiling_detail::Stopwatch> gate_timer;
            if (timings != nullptr) {
                gate_timer.emplace();
            }
            const verification_profile::ScopedVerificationPhase gate_phase(
                verification_profile::Category::GkrPlaintext, false);
            const bool accepted = gate_claims.finish();
            if (timings != nullptr) {
                const auto elapsed = gate_timer->stop();
                timings->gate_mle_opening_wall_ms = elapsed.wall_ms;
                timings->gate_mle_opening_cpu_ms = elapsed.cpu_ms;
            }
            if (!accepted) {
                return std::nullopt;
            }
        }
        return Plan(std::move(data));
    } catch (const std::invalid_argument &) {
        return std::nullopt;
    } catch (const std::out_of_range &) {
        return std::nullopt;
    } catch (const std::runtime_error &) {
        return std::nullopt;
    }
}

} // namespace laminate::protocol::detail

#endif // LAMINATE_PROTOCOL_DETAIL_PACKING_GKR_TRANSCRIPT_REPLAY_HPP
