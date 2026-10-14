#ifndef LAMINATE_PROTOCOL_PACKED_SETUP_DETAIL_BUILDERS_IMPL_HPP
#define LAMINATE_PROTOCOL_PACKED_SETUP_DETAIL_BUILDERS_IMPL_HPP

/// @file builders_impl.hpp
/// @brief Template definitions for packed protocol setup builders.

#include "laminate/protocol/packed/setup/variants.hpp"

#include <cstddef>
#include <ranges>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::protocol {

namespace detail {

/// Build transcript-packing preprocessing without choosing a proof-ingress
/// policy. The public builders below supply and bind that policy separately.
template <ProofOfPackingBackend Backend>
TranscriptPackingSpartanSetup build_folded_transcript_packing_setup(
    const payload::LayeredCircuit &circuit,
    const typename Backend::EvalContext &eval,
    packing::LazyTernaryParameters packing_parameters,
    spartan::BaseFoldPcsParameters basefold_parameters,
    spartan::Options options,
    TranscriptPackingPreprocessingOptions preprocessing_options) {
    const std::size_t ring_degree = Backend::slot_count(eval);
    if (ring_degree != circuit.shape.slot_count ||
        Backend::lowest_coefficient_modulus(eval) != kOuterFieldOrder) {
        throw std::invalid_argument(
            "Folded transcript-packing setup: backend does not use the "
            "circuit's native field");
    }
    return make_transcript_packing_spartan_setup(
        PackingGkrVariant::Folded, ring_degree,
        folded_bhip_round_count(circuit),
        {.centered_coefficients =
             [&eval](const fhe::SlotVector &slots) {
                 return Backend::encode_centered_plaintext_coefficients(
                     eval, slots);
             },
         .native_ntt =
             [&eval](std::span<const std::int64_t> coefficients) {
                 return Backend::encode_lowest_plaintext_ntt_coordinates(
                     eval, coefficients);
             }},
        std::move(packing_parameters), basefold_parameters, options,
        preprocessing_options);
}

template <ProofOfPackingBackend Backend>
TranscriptPackingSpartanSetup build_laned_transcript_packing_setup(
    const payload::LayeredCircuit &circuit,
    const typename Backend::EvalContext &eval,
    packing::LazyTernaryParameters packing_parameters,
    spartan::BaseFoldPcsParameters basefold_parameters,
    spartan::Options options,
    TranscriptPackingPreprocessingOptions preprocessing_options) {
    const std::size_t ring_degree = Backend::slot_count(eval);
    if (ring_degree != circuit.shape.slot_count ||
        Backend::lowest_coefficient_modulus(eval) != kOuterFieldOrder) {
        throw std::invalid_argument(
            "Laned transcript-packing setup: backend does not use the "
            "circuit's native field");
    }
    return make_transcript_packing_spartan_setup(
        PackingGkrVariant::Laned, ring_degree,
        laned_bhip_round_count(circuit),
        {.centered_coefficients =
             [&eval](const fhe::SlotVector &slots) {
                 return Backend::encode_centered_plaintext_coefficients(
                     eval, slots);
             },
         .native_ntt =
             [&eval](std::span<const std::int64_t> coefficients) {
                 return Backend::encode_lowest_plaintext_ntt_coordinates(
                     eval, coefficients);
             }},
        std::move(packing_parameters), basefold_parameters, options,
        preprocessing_options);
}

} // namespace detail

/// Build a Folded setup for an empirical honest-run parameter candidate.
/// This binds the exact per-source RNS levels used by the live prover but
/// makes no theorem-level noise-completeness claim. Candidate admission must
/// instead require correct payload decryption, the configured bottom-modulus
/// error target, and successful end-to-end proof verification.
template <ProofOfPackingBackend Backend>
FoldedSetup setup_folded_honest_candidate(
    const payload::LayeredCircuit &circuit,
    const typename Backend::EvalContext &eval,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    packing::LazyTernaryParameters packing_parameters,
    spartan::BaseFoldPcsParameters basefold_parameters,
    spartan::Options options,
    TranscriptPackingPreprocessingOptions preprocessing_options) {
    if (proof_ingress_rns_limbs_by_layer.size() !=
            circuit.layers.size() ||
        std::ranges::any_of(
            proof_ingress_rns_limbs_by_layer,
            [](std::size_t limbs) { return limbs == 0; })) {
        throw std::invalid_argument(
            "Folded honest candidate requires one nonzero ingress level "
            "per layer");
    }
    return FoldedSetup{
        detail::build_folded_transcript_packing_setup<Backend>(
            circuit, eval, std::move(packing_parameters),
            basefold_parameters, options,
            std::move(preprocessing_options)),
        std::vector<std::size_t>(
            proof_ingress_rns_limbs_by_layer.begin(),
            proof_ingress_rns_limbs_by_layer.end())};
}

/// Selected-parameter convenience overload. Callers that override the
/// repetition count must use the overload above and classify the result as a
/// nonselected diagnostic with no selected-profile security claim.
template <ProofOfPackingBackend Backend>
FoldedSetup setup_folded_honest_candidate(
    const payload::LayeredCircuit &circuit,
    const typename Backend::EvalContext &eval,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    spartan::BaseFoldPcsParameters basefold_parameters,
    spartan::Options options,
    TranscriptPackingPreprocessingOptions preprocessing_options) {
    return setup_folded_honest_candidate<Backend>(
        circuit, eval, proof_ingress_rns_limbs_by_layer,
        packing::selected_lazy_ternary_parameters(), basefold_parameters,
        options, std::move(preprocessing_options));
}

/// Laned counterpart of `setup_folded_honest_candidate`.
template <ProofOfPackingBackend Backend>
LanedSetup setup_laned_honest_candidate(
    const payload::LayeredCircuit &circuit,
    const typename Backend::EvalContext &eval,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    packing::LazyTernaryParameters packing_parameters,
    spartan::BaseFoldPcsParameters basefold_parameters,
    spartan::Options options,
    TranscriptPackingPreprocessingOptions preprocessing_options) {
    if (proof_ingress_rns_limbs_by_layer.size() !=
            circuit.layers.size() ||
        std::ranges::any_of(
            proof_ingress_rns_limbs_by_layer,
            [](std::size_t limbs) { return limbs == 0; })) {
        throw std::invalid_argument(
            "Laned honest candidate requires one nonzero ingress level per "
            "layer");
    }
    return LanedSetup{
        detail::build_laned_transcript_packing_setup<Backend>(
            circuit, eval, std::move(packing_parameters),
            basefold_parameters, options,
            std::move(preprocessing_options)),
        std::vector<std::size_t>(
            proof_ingress_rns_limbs_by_layer.begin(),
            proof_ingress_rns_limbs_by_layer.end())};
}

/// Selected-parameter convenience overload; see the Folded counterpart.
template <ProofOfPackingBackend Backend>
LanedSetup setup_laned_honest_candidate(
    const payload::LayeredCircuit &circuit,
    const typename Backend::EvalContext &eval,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    spartan::BaseFoldPcsParameters basefold_parameters,
    spartan::Options options,
    TranscriptPackingPreprocessingOptions preprocessing_options) {
    return setup_laned_honest_candidate<Backend>(
        circuit, eval, proof_ingress_rns_limbs_by_layer,
        packing::selected_lazy_ternary_parameters(), basefold_parameters,
        options, std::move(preprocessing_options));
}

/// Routine Folded setup with the versioned conservative ingress policy. The
/// caller may derive and persist `schedule` before expensive transcript-packing
/// preprocessing. Validation re-binds it to the exact variant, circuit, public
/// setup, and full vector; it performs no FHE execution or proof replay.
template <ProofOfPackingBackend Backend>
FoldedSetup setup_folded_conservative(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const typename Backend::EvalContext &eval,
    const ConservativePackedProofIngressSchedule &schedule,
    packing::LazyTernaryParameters packing_parameters,
    spartan::BaseFoldPcsParameters basefold_parameters,
    spartan::Options options,
    TranscriptPackingPreprocessingOptions preprocessing_options) {
    validate_conservative_packed_proof_ingress_schedule(
        payload, circuit, public_setup, schedule);
    if (schedule.variant() != PackingGkrVariant::Folded) {
        throw std::invalid_argument(
            "setup_folded_conservative: schedule has the wrong variant");
    }
    return FoldedSetup{
        detail::build_folded_transcript_packing_setup<Backend>(
            circuit, eval, std::move(packing_parameters),
            basefold_parameters, options,
            std::move(preprocessing_options)),
        std::vector<std::size_t>(schedule.rns_limbs_by_layer().begin(),
                                 schedule.rns_limbs_by_layer().end()),
        schedule};
}

/// Convenience overload that derives the inexpensive Folded policy inside
/// setup. Use the explicit-schedule overload when persistence needs its digest
/// before transcript-packing preprocessing begins.
template <ProofOfPackingBackend Backend>
FoldedSetup setup_folded_conservative(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const typename Backend::EvalContext &eval,
    packing::LazyTernaryParameters packing_parameters,
    spartan::BaseFoldPcsParameters basefold_parameters,
    spartan::Options options,
    TranscriptPackingPreprocessingOptions preprocessing_options) {
    const ConservativePackedProofIngressSchedule schedule =
        derive_conservative_packed_proof_ingress_schedule(
            PackingGkrVariant::Folded, payload, circuit, public_setup);
    return setup_folded_conservative<Backend>(
        payload, circuit, public_setup, eval, schedule,
        std::move(packing_parameters), basefold_parameters, options,
        std::move(preprocessing_options));
}

/// Routine Laned counterpart of `setup_folded_conservative`.
template <ProofOfPackingBackend Backend>
LanedSetup setup_laned_conservative(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const typename Backend::EvalContext &eval,
    const ConservativePackedProofIngressSchedule &schedule,
    packing::LazyTernaryParameters packing_parameters,
    spartan::BaseFoldPcsParameters basefold_parameters,
    spartan::Options options,
    TranscriptPackingPreprocessingOptions preprocessing_options) {
    validate_conservative_packed_proof_ingress_schedule(
        payload, circuit, public_setup, schedule);
    if (schedule.variant() != PackingGkrVariant::Laned) {
        throw std::invalid_argument(
            "setup_laned_conservative: schedule has the wrong variant");
    }
    return LanedSetup{
        detail::build_laned_transcript_packing_setup<Backend>(
            circuit, eval, std::move(packing_parameters),
            basefold_parameters, options,
            std::move(preprocessing_options)),
        std::vector<std::size_t>(schedule.rns_limbs_by_layer().begin(),
                                 schedule.rns_limbs_by_layer().end()),
        schedule};
}

/// Convenience overload deriving the inexpensive Laned policy inside setup.
template <ProofOfPackingBackend Backend>
LanedSetup setup_laned_conservative(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const typename Backend::EvalContext &eval,
    packing::LazyTernaryParameters packing_parameters,
    spartan::BaseFoldPcsParameters basefold_parameters,
    spartan::Options options,
    TranscriptPackingPreprocessingOptions preprocessing_options) {
    const ConservativePackedProofIngressSchedule schedule =
        derive_conservative_packed_proof_ingress_schedule(
            PackingGkrVariant::Laned, payload, circuit, public_setup);
    return setup_laned_conservative<Backend>(
        payload, circuit, public_setup, eval, schedule,
        std::move(packing_parameters), basefold_parameters, options,
        std::move(preprocessing_options));
}

/// Certificate-bound Folded setup. The payload and public GKR setup are
/// explicit here because the completeness analysis binds both; accepting only
/// the layered circuit would permit replaying a level choice for a different
/// statement.
template <ProofOfPackingBackend Backend>
FoldedSetup setup_folded_certified(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const typename Backend::EvalContext &eval,
    const CertifiedProofIngressRnsSelection &selection,
    spartan::BaseFoldPcsParameters basefold_parameters,
    spartan::Options options,
    TranscriptPackingPreprocessingOptions preprocessing_options) {
    if (selection.variant() != PackingGkrVariant::Folded ||
        selection.exact_rns_limbs_by_layer().size() !=
            circuit.layers.size() ||
        std::ranges::any_of(
            selection.exact_rns_limbs_by_layer(),
            [](std::size_t limbs) { return limbs == 0; }) ||
        selection.circuit_id() !=
            payload::combined_digest(payload, circuit) ||
        selection.setup_id() != setup_digest(public_setup)) {
        throw std::invalid_argument(
            "setup_folded_certified: completeness selection does not "
            "match the statement");
    }
    return FoldedSetup{
        detail::build_folded_transcript_packing_setup<Backend>(
            circuit, eval, packing::selected_lazy_ternary_parameters(),
            basefold_parameters, options,
            std::move(preprocessing_options)),
        std::vector<std::size_t>(
            selection.exact_rns_limbs_by_layer().begin(),
            selection.exact_rns_limbs_by_layer().end())};
}

/// Certificate-bound Laned counterpart of `setup_folded_certified`.
template <ProofOfPackingBackend Backend>
LanedSetup setup_laned_certified(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const typename Backend::EvalContext &eval,
    const CertifiedProofIngressRnsSelection &selection,
    spartan::BaseFoldPcsParameters basefold_parameters,
    spartan::Options options,
    TranscriptPackingPreprocessingOptions preprocessing_options) {
    if (selection.variant() != PackingGkrVariant::Laned ||
        selection.exact_rns_limbs_by_layer().size() !=
            circuit.layers.size() ||
        std::ranges::any_of(
            selection.exact_rns_limbs_by_layer(),
            [](std::size_t limbs) { return limbs == 0; }) ||
        selection.circuit_id() !=
            payload::combined_digest(payload, circuit) ||
        selection.setup_id() != setup_digest(public_setup)) {
        throw std::invalid_argument(
            "setup_laned_certified: completeness selection does not "
            "match the statement");
    }
    return LanedSetup{
        detail::build_laned_transcript_packing_setup<Backend>(
            circuit, eval, packing::selected_lazy_ternary_parameters(),
            basefold_parameters, options,
            std::move(preprocessing_options)),
        std::vector<std::size_t>(
            selection.exact_rns_limbs_by_layer().begin(),
            selection.exact_rns_limbs_by_layer().end())};
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_SETUP_DETAIL_BUILDERS_IMPL_HPP
