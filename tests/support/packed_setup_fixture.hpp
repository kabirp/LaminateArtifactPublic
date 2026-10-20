#ifndef LAMINATE_TESTS_SUPPORT_PACKED_SETUP_FIXTURE_HPP
#define LAMINATE_TESTS_SUPPORT_PACKED_SETUP_FIXTURE_HPP

/// @file packed_setup_fixture.hpp
/// @brief Small uniform-ingress Folded and Laned setup fixtures.

#include "laminate/params.hpp"
#include "laminate/protocol/packed/setup/builders.hpp"

#include <cstddef>
#include <utility>
#include <vector>

namespace laminate::protocol {

inline constexpr std::size_t kFoldedFixtureProofIngressRnsLimbs =
    kPackingReservedMultDepth + 2U;
inline constexpr std::size_t kLanedFixtureProofIngressRnsLimbs =
    kPackingReservedMultDepth + 3U;

template <ProofOfPackingBackend Backend>
FoldedSetup make_folded_setup_fixture(
    const payload::LayeredCircuit &circuit,
    const typename Backend::EvalContext &eval,
    spartan::BaseFoldPcsParameters basefold_parameters = {},
    spartan::Options options = spartan::Options{
        .matrix_evaluation =
            spartan::MatrixEvaluationMode::CommittedFactored},
    TranscriptPackingPreprocessingOptions preprocessing_options = {}) {
    return setup_folded_honest_candidate<Backend>(
        circuit, eval,
        std::vector<std::size_t>(
            circuit.layers.size(), kFoldedFixtureProofIngressRnsLimbs),
        basefold_parameters, options, std::move(preprocessing_options));
}

template <ProofOfPackingBackend Backend>
LanedSetup make_laned_setup_fixture(
    const payload::LayeredCircuit &circuit,
    const typename Backend::EvalContext &eval,
    spartan::BaseFoldPcsParameters basefold_parameters = {},
    spartan::Options options = spartan::Options{
        .matrix_evaluation =
            spartan::MatrixEvaluationMode::CommittedFactored},
    TranscriptPackingPreprocessingOptions preprocessing_options = {}) {
    return setup_laned_honest_candidate<Backend>(
        circuit, eval,
        std::vector<std::size_t>(
            circuit.layers.size(), kLanedFixtureProofIngressRnsLimbs),
        basefold_parameters, options, std::move(preprocessing_options));
}

} // namespace laminate::protocol

#endif // LAMINATE_TESTS_SUPPORT_PACKED_SETUP_FIXTURE_HPP
