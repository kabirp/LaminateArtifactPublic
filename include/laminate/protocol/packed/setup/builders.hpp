#ifndef LAMINATE_PROTOCOL_PACKED_SETUP_BUILDERS_HPP
#define LAMINATE_PROTOCOL_PACKED_SETUP_BUILDERS_HPP

/// @file builders.hpp
/// @brief Declaration-first API for Folded and Laned packed setup.

#include "laminate/protocol/packed/setup/variants.hpp"

#include <span>

namespace laminate::protocol {

// Routine setup derives a versioned, topology-only proof-ingress policy.
template <ProofOfPackingBackend Backend>
FoldedSetup setup_folded_conservative(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const typename Backend::EvalContext &eval,
    packing::LazyTernaryParameters packing_parameters =
        packing::selected_lazy_ternary_parameters(),
    spartan::BaseFoldPcsParameters basefold_parameters = {},
    spartan::Options options = spartan::Options{
        .matrix_evaluation =
            spartan::MatrixEvaluationMode::CommittedFactored},
    TranscriptPackingPreprocessingOptions preprocessing_options = {});

template <ProofOfPackingBackend Backend>
LanedSetup setup_laned_conservative(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const typename Backend::EvalContext &eval,
    packing::LazyTernaryParameters packing_parameters =
        packing::selected_lazy_ternary_parameters(),
    spartan::BaseFoldPcsParameters basefold_parameters = {},
    spartan::Options options = spartan::Options{
        .matrix_evaluation =
            spartan::MatrixEvaluationMode::CommittedFactored},
    TranscriptPackingPreprocessingOptions preprocessing_options = {});

// Explicit-schedule overloads let callers persist the policy digest before
// expensive transcript-packing preprocessing begins.
template <ProofOfPackingBackend Backend>
FoldedSetup setup_folded_conservative(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const typename Backend::EvalContext &eval,
    const ConservativePackedProofIngressSchedule &schedule,
    packing::LazyTernaryParameters packing_parameters =
        packing::selected_lazy_ternary_parameters(),
    spartan::BaseFoldPcsParameters basefold_parameters = {},
    spartan::Options options = spartan::Options{
        .matrix_evaluation =
            spartan::MatrixEvaluationMode::CommittedFactored},
    TranscriptPackingPreprocessingOptions preprocessing_options = {});

template <ProofOfPackingBackend Backend>
LanedSetup setup_laned_conservative(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const typename Backend::EvalContext &eval,
    const ConservativePackedProofIngressSchedule &schedule,
    packing::LazyTernaryParameters packing_parameters =
        packing::selected_lazy_ternary_parameters(),
    spartan::BaseFoldPcsParameters basefold_parameters = {},
    spartan::Options options = spartan::Options{
        .matrix_evaluation =
            spartan::MatrixEvaluationMode::CommittedFactored},
    TranscriptPackingPreprocessingOptions preprocessing_options = {});

// Honest-candidate setup admits an empirical per-layer ingress vector without
// claiming theorem-level completeness.
template <ProofOfPackingBackend Backend>
FoldedSetup setup_folded_honest_candidate(
    const payload::LayeredCircuit &circuit,
    const typename Backend::EvalContext &eval,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    packing::LazyTernaryParameters packing_parameters,
    spartan::BaseFoldPcsParameters basefold_parameters = {},
    spartan::Options options = spartan::Options{
        .matrix_evaluation =
            spartan::MatrixEvaluationMode::CommittedFactored},
    TranscriptPackingPreprocessingOptions preprocessing_options = {});

template <ProofOfPackingBackend Backend>
FoldedSetup setup_folded_honest_candidate(
    const payload::LayeredCircuit &circuit,
    const typename Backend::EvalContext &eval,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    spartan::BaseFoldPcsParameters basefold_parameters = {},
    spartan::Options options = spartan::Options{
        .matrix_evaluation =
            spartan::MatrixEvaluationMode::CommittedFactored},
    TranscriptPackingPreprocessingOptions preprocessing_options = {});

template <ProofOfPackingBackend Backend>
LanedSetup setup_laned_honest_candidate(
    const payload::LayeredCircuit &circuit,
    const typename Backend::EvalContext &eval,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    packing::LazyTernaryParameters packing_parameters,
    spartan::BaseFoldPcsParameters basefold_parameters = {},
    spartan::Options options = spartan::Options{
        .matrix_evaluation =
            spartan::MatrixEvaluationMode::CommittedFactored},
    TranscriptPackingPreprocessingOptions preprocessing_options = {});

template <ProofOfPackingBackend Backend>
LanedSetup setup_laned_honest_candidate(
    const payload::LayeredCircuit &circuit,
    const typename Backend::EvalContext &eval,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    spartan::BaseFoldPcsParameters basefold_parameters = {},
    spartan::Options options = spartan::Options{
        .matrix_evaluation =
            spartan::MatrixEvaluationMode::CommittedFactored},
    TranscriptPackingPreprocessingOptions preprocessing_options = {});

// Certified setup accepts only an exact selection projected from a successful
// exhaustive completeness analysis.
template <ProofOfPackingBackend Backend>
FoldedSetup setup_folded_certified(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const typename Backend::EvalContext &eval,
    const CertifiedProofIngressRnsSelection &selection,
    spartan::BaseFoldPcsParameters basefold_parameters = {},
    spartan::Options options = spartan::Options{
        .matrix_evaluation =
            spartan::MatrixEvaluationMode::CommittedFactored},
    TranscriptPackingPreprocessingOptions preprocessing_options = {});

template <ProofOfPackingBackend Backend>
LanedSetup setup_laned_certified(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const typename Backend::EvalContext &eval,
    const CertifiedProofIngressRnsSelection &selection,
    spartan::BaseFoldPcsParameters basefold_parameters = {},
    spartan::Options options = spartan::Options{
        .matrix_evaluation =
            spartan::MatrixEvaluationMode::CommittedFactored},
    TranscriptPackingPreprocessingOptions preprocessing_options = {});

} // namespace laminate::protocol

#include "laminate/protocol/packed/setup/detail/builders_impl.hpp"

#endif // LAMINATE_PROTOCOL_PACKED_SETUP_BUILDERS_HPP
