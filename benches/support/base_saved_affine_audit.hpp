#ifndef LAMINATE_BENCH_BASE_SAVED_AFFINE_AUDIT_HPP
#define LAMINATE_BENCH_BASE_SAVED_AFFINE_AUDIT_HPP

#include "benchmark_support.hpp"
#include "laminate/delegation/base/transport/messages.hpp"
#include "laminate/gkr/detail/base/affine/internal/partial_gate_mle.hpp"
#include "laminate/gkr/detail/base/affine/types.hpp"
#include "laminate/gkr/detail/base/arithmetic/reduction.hpp"
#include "laminate/gkr/detail/base/claims/evaluation.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/base/verification/proof_reader.hpp"
#include "laminate/gkr/detail/shared/reduction/gate_claims.hpp"
#include "laminate/gkr/layer_reduction_sumcheck.hpp"
#include "laminate/protocol/setup/base_client.hpp"

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <variant>
#include <vector>

namespace laminate::bench {

/// Inspect the first affine reduction of an already opened saved response.
/// The transcript must be a copy taken immediately after open_base_response.
/// This replays the proof's original public claims, then independently derives
/// its affine coefficients from the authenticated circuit. It reports counts
/// and equality outcomes only; plaintext values are never written. No outcome
/// substitutes for ordinary verification or authenticates the remaining proof.
template <fhe::FheBackend Backend>
void audit_saved_first_affine(
    const protocol::CertifiedBaseClientSetup<Backend> &client,
    const delegation::BaseResponse<Backend> &response,
    const gkr::SingleClaim &output_claim, Transcript transcript_after_open,
    const Record &record) {
    using namespace gkr::base_detail;
    constexpr std::size_t layer = 0;
    record.integer("audit.affine.layer", layer);
    const auto &circuit = client.circuit();
    if (circuit.layers.size() < 2 || response.proof.reductions.empty() ||
        payload::layer_kind(circuit.layers.front()) != payload::LayerKind::Affine ||
        !std::holds_alternative<gkr::EncryptedBaseAffineLayerReduction<Backend>>(
            response.proof.reductions.front())) {
        record.text("audit.affine.status", "first-reduction-is-not-affine");
        return;
    }
    const auto &proof = std::get<gkr::EncryptedBaseAffineLayerReduction<Backend>>(
        response.proof.reductions.front());
    const auto geometry = AffineGeometry::create(circuit, layer);
    if (proof.rounds.size() != geometry.ciphertext_index_variables ||
        output_claim.point.size() != layer_vars(circuit, layer)) {
        throw std::invalid_argument("saved affine audit: first-layer geometry mismatch");
    }
    record.integer("audit.affine.round_count", proof.rounds.size());

    gkr::detail::VerifierGateClaims gate_claims(
        circuit, client.public_setup(), response.proof.gate_mle_opening,
        transcript_after_open);
    gkr::observe_proof_header(response.proof.header, transcript_after_open);
    gates::observe_gate_mle_setup(client.public_setup(), transcript_after_open);
    observe_output_point(output_claim.point, transcript_after_open);
    const gkr::LayerClaim claim{output_claim};
    const auto saved_constant = affine_constant_at(gate_claims, layer, claim);
    gates::DirectGateMle direct(circuit);
    const auto direct_constant = affine_constant_at(direct, layer, claim);
    record.text("audit.affine.constant_matches_direct",
                saved_constant == direct_constant ? "yes" : "no");
    auto saved_reduced_claim = output_claim.value - saved_constant;
    auto direct_reduced_claim = output_claim.value - direct_constant;

    observe_begin(layer, payload::LayerKind::Affine,
                  geometry.ciphertext_index_variables, transcript_after_open);
    std::vector<Fpk> challenges;
    challenges.reserve(geometry.ciphertext_index_variables);
    ProofReader<Backend> reader(client.context());
    for (std::size_t round = 0; round < proof.rounds.size(); ++round) {
        const auto &message = proof.rounds[round];
        observe_round<Backend>(layer, round, message, transcript_after_open);
        const auto at_one = sum_slots(reader.read(message.evaluations.front()));
        const auto at_two = sum_slots(reader.read(message.evaluations.back()));
        const auto challenge = transcript_after_open.challenge_fpk();
        saved_reduced_claim = gkr::detail::LayerReductionRoundEvaluations{
            saved_reduced_claim - at_one, at_one, at_two}.interpolate_at(challenge);
        direct_reduced_claim = gkr::detail::LayerReductionRoundEvaluations{
            direct_reduced_claim - at_one, at_one, at_two}.interpolate_at(challenge);
        challenges.push_back(challenge);
    }

    const auto expected = make_affine_partial_gate_mle(circuit, layer, claim, challenges);
    const auto &saved = proof.partial_gate_mle.evaluations;
    const auto common = std::min(saved.size(), expected.evaluations.size());
    std::size_t mismatched_values = std::max(saved.size(), expected.evaluations.size()) - common;
    for (std::size_t slot = 0; slot < common; ++slot)
        mismatched_values += saved[slot] != expected.evaluations[slot] ? 1U : 0U;
    record.integer("audit.affine.partial_gate_mle.saved_count", saved.size());
    record.integer("audit.affine.partial_gate_mle.expected_count", expected.evaluations.size());
    record.integer("audit.affine.partial_gate_mle.mismatched_values", mismatched_values);
    record.text("audit.affine.partial_gate_mle.matches_direct", mismatched_values == 0 ? "yes" : "no");

    // These are diagnostic equalities at the original proof's challenges.
    // In particular, the direct-constant comparison does not replace the
    // constant's transcript binding or repair any proof message.
    const auto source = reader.read(proof.source_vector);
    record.text("audit.affine.terminal_identity_saved_public",
        source.size() == saved.size() && inner_product(saved, source) == saved_reduced_claim
            ? "pass" : "fail");
    record.text("audit.affine.terminal_identity_direct_public",
        source.size() == expected.evaluations.size() &&
                inner_product(expected.evaluations, source) == direct_reduced_claim
            ? "pass" : "fail");
    record.text("audit.affine.status", "complete");
}

} // namespace laminate::bench

#endif
