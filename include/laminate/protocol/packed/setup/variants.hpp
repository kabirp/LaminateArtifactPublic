#ifndef LAMINATE_PROTOCOL_PACKED_SETUP_VARIANTS_HPP
#define LAMINATE_PROTOCOL_PACKED_SETUP_VARIANTS_HPP

/// @file variants.hpp
/// @brief Folded/Laned setup state and its payload-evaluation binding.

#include "laminate/payload/evaluation/fhe_evaluation_plan.hpp"
#include "laminate/protocol/packed/setup/proof_ingress.hpp"
#include "laminate/protocol/packed/setup/transcript_packing.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <ranges>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::protocol {

/// Prover setup for Folded GKR and its transcript-packing proof.
struct FoldedSetup {
    FoldedSetup() = default;
    FoldedSetup(
        TranscriptPackingSpartanSetup transcript_packing_value,
        std::vector<std::size_t> proof_ingress_rns_limbs_by_layer_value,
        std::optional<ConservativePackedProofIngressSchedule>
            conservative_schedule = std::nullopt)
        : transcript_packing(std::move(transcript_packing_value)),
          proof_ingress_rns_limbs_by_layer(
              std::move(proof_ingress_rns_limbs_by_layer_value)),
          conservative_proof_ingress_schedule(
              std::move(conservative_schedule)) {}

    TranscriptPackingSpartanSetup transcript_packing;
    /// Exact actual RNS limb count for each circuit layer. Entry `i > 0`
    /// binds the source ciphertext level used when reducing layer `i-1`.
    /// Entry 0 is retained for a uniform layer-indexed schema but is not a
    /// proof-ingress authority: layer 0 is the payload output returned for
    /// client decryption and is never read by reverse GKR.
    std::vector<std::size_t> proof_ingress_rns_limbs_by_layer;
    /// Present for the inexpensive routine setup path. Exact exhaustive
    /// offline selections and raw test candidates deliberately leave it empty.
    std::optional<ConservativePackedProofIngressSchedule>
        conservative_proof_ingress_schedule;
};

/// Prover setup for Laned GKR and its transcript-packing proof.
struct LanedSetup {
    LanedSetup() = default;
    LanedSetup(
        TranscriptPackingSpartanSetup transcript_packing_value,
        std::vector<std::size_t> proof_ingress_rns_limbs_by_layer_value,
        std::optional<ConservativePackedProofIngressSchedule>
            conservative_schedule = std::nullopt)
        : transcript_packing(std::move(transcript_packing_value)),
          proof_ingress_rns_limbs_by_layer(
              std::move(proof_ingress_rns_limbs_by_layer_value)),
          conservative_proof_ingress_schedule(
              std::move(conservative_schedule)) {}

    TranscriptPackingSpartanSetup transcript_packing;
    /// Same source-layer convention as `FoldedSetup`; entry 0 is not a
    /// reverse-GKR source and therefore never forces an output modulus drop.
    std::vector<std::size_t> proof_ingress_rns_limbs_by_layer;
    std::optional<ConservativePackedProofIngressSchedule>
        conservative_proof_ingress_schedule;
};

namespace detail {

inline payload::FheEvaluationPlan apply_packed_proof_ingress_schedule(
    const payload::LayeredCircuit &circuit,
    payload::FheEvaluationPlan plan,
    std::span<const std::size_t> exact_rns_limbs_by_layer) {
    plan.validate(circuit);
    if (exact_rns_limbs_by_layer.size() != circuit.layers.size()) {
        throw std::invalid_argument(
            "packed proof-ingress schedule has the wrong layer count");
    }

    // Layer 0 is an output for decryption, not a source scanned by GKR. Keep
    // its natural payload-evaluation level. Every actual proof source is
    // copied once and switched directly to the setup-selected exact level by
    // the evaluator's snapshot boundary.
    plan.proof_ingress_mult_depth_by_layer[0] =
        plan.trace.required_mult_depth_by_layer[0];
    for (std::size_t layer = 1; layer < circuit.layers.size(); ++layer) {
        const std::size_t limbs = exact_rns_limbs_by_layer[layer];
        if (limbs == 0) {
            throw std::invalid_argument(
                "packed proof-ingress schedule selected zero source "
                "limbs");
        }
        const std::size_t depth = limbs - 1U;
        if (depth > plan.trace.required_mult_depth_by_layer[layer]) {
            throw std::invalid_argument(
                "packed proof-ingress schedule exceeds a source layer's "
                "natural RNS level");
        }
        plan.proof_ingress_mult_depth_by_layer[layer] = depth;
    }
    plan.validate(circuit);
    return plan;
}

} // namespace detail

/// Bind the Folded setup's exact source levels into payload evaluation.
/// Evaluation then performs every required modulus drop once while publishing
/// its compact proof snapshots; the prover only validates and scans them.
inline payload::FheEvaluationPlan apply_packed_proof_ingress_schedule(
    const payload::LayeredCircuit &circuit,
    payload::FheEvaluationPlan plan, const FoldedSetup &setup) {
    if (setup.transcript_packing.variant != PackingGkrVariant::Folded) {
        throw std::invalid_argument(
            "Folded proof-ingress schedule has the wrong variant");
    }
    if (setup.conservative_proof_ingress_schedule &&
        (setup.conservative_proof_ingress_schedule->variant() !=
             PackingGkrVariant::Folded ||
         !std::ranges::equal(
             setup.conservative_proof_ingress_schedule
                 ->rns_limbs_by_layer(),
             setup.proof_ingress_rns_limbs_by_layer))) {
        throw std::invalid_argument(
            "Folded conservative proof-ingress binding disagrees with the "
            "executable vector");
    }
    return detail::apply_packed_proof_ingress_schedule(
        circuit, std::move(plan),
        setup.proof_ingress_rns_limbs_by_layer);
}

/// Laned counterpart of the Folded evaluation-plan binding.
inline payload::FheEvaluationPlan apply_packed_proof_ingress_schedule(
    const payload::LayeredCircuit &circuit,
    payload::FheEvaluationPlan plan, const LanedSetup &setup) {
    if (setup.transcript_packing.variant != PackingGkrVariant::Laned) {
        throw std::invalid_argument(
            "Laned proof-ingress schedule has the wrong variant");
    }
    if (setup.conservative_proof_ingress_schedule &&
        (setup.conservative_proof_ingress_schedule->variant() !=
             PackingGkrVariant::Laned ||
         !std::ranges::equal(
             setup.conservative_proof_ingress_schedule
                 ->rns_limbs_by_layer(),
             setup.proof_ingress_rns_limbs_by_layer))) {
        throw std::invalid_argument(
            "Laned conservative proof-ingress binding disagrees with the "
            "executable vector");
    }
    return detail::apply_packed_proof_ingress_schedule(
        circuit, std::move(plan),
        setup.proof_ingress_rns_limbs_by_layer);
}

struct FoldedVerifierSetup {
    TranscriptPackingSpartanVerifierSetup transcript_packing;
};

struct LanedVerifierSetup {
    TranscriptPackingSpartanVerifierSetup transcript_packing;
};

FoldedVerifierSetup verifier_setup(const FoldedSetup &setup);
LanedVerifierSetup verifier_setup(const LanedSetup &setup);

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_SETUP_VARIANTS_HPP
