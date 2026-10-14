#ifndef LAMINATE_PROTOCOL_METRICS_PROFILING_HPP
#define LAMINATE_PROTOCOL_METRICS_PROFILING_HPP

/// @file profiling.hpp
/// @brief Optional protocol timing adapters for tests and benchmarks.
///
/// The primary `base.hpp`, `folded.hpp`, and `laned.hpp` APIs intentionally do
/// not mention timing records or transport experiments. Tools that need those
/// diagnostics opt in through this header.

#include "laminate/protocol/base.hpp"
#include "laminate/protocol/detail/profiling/base.hpp"
#include "laminate/protocol/detail/profiling/folded.hpp"
#include "laminate/protocol/detail/profiling/laned.hpp"
#include "laminate/protocol/metrics/types.hpp"
#include "laminate/protocol/folded.hpp"
#include "laminate/protocol/laned.hpp"
#include "laminate/runtime_progress.hpp"

#include <functional>
#include <utility>

namespace laminate::protocol {

template <fhe::FheBackend Backend>
LaminateBaseProof<Backend> prove_base_reference_profiled(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point,
    Transcript &transcript, BaseProverTimings &timings) {
    return profiling_detail::prove_base_reference<Backend>(
        payload, circuit, trace, setup, output_point, transcript, timings);
}

template <fhe::FheBackend Backend>
bool verify_base_reference_profiled(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> input_layer,
    const ClientSetup<Backend> &setup,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const LaminateBaseProof<Backend> &proof, Transcript &transcript,
    BaseVerifierTimings &timings) {
    return profiling_detail::verify_base_reference<Backend>(
        payload, circuit, input_layer, setup, expected_provenance,
        expected_trace_id, expected_output_claim, proof, transcript,
        timings);
}

template <fhe::FheBackend Backend>
bool verify_base_profiled(
    const CertifiedBaseClientSetup<Backend> &setup,
    std::span<const fhe::SlotVector> input_layer,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const LaminateBaseProof<Backend> &proof, Transcript &transcript,
    BaseVerifierTimings &timings) {
    return profiling_detail::verify_base<Backend>(
        setup, input_layer, expected_provenance, expected_trace_id,
        expected_output_claim, proof, transcript, timings);
}

template <packing::SignedDigitPackingBackend Backend>
LaminateFoldedProof<Backend> prove_folded_reference_profiled(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point,
    Transcript &transcript, FoldedProverTimings &timings,
    gkr::ProofTransportPolicy transport = {},
    std::function<void()> gkr_complete = {},
    RuntimeProgressCallback progress = {}) {
    return profiling_detail::prove_folded_reference<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        transcript, timings, transport, std::move(gkr_complete),
        std::move(progress));
}

template <packing::SignedDigitPackingBackend Backend,
          typename VerifierContext>
    requires packing::PublicCoefficientVerifierContext<
        Backend, VerifierContext>
bool verify_folded_profiled(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> input_layer,
    const VerifierContext &verifier,
    const FoldedVerifierSetup &packing_setup,
    const ClientSetup<Backend> &setup,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const LaminateFoldedProof<Backend> &proof, Transcript &transcript,
    FoldedVerifierTimings &timings,
    RuntimeProgressCallback progress = {}) {
    return profiling_detail::verify_folded<Backend>(
        payload, circuit, input_layer, verifier, packing_setup, setup,
        expected_provenance, expected_trace_id, expected_output_claim,
        proof, transcript, timings, progress);
}

template <packing::SignedDigitPackingBackend Backend>
LaminateLanedProof<Backend> prove_laned_reference_profiled(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup,
    std::span<const Fpk> output_point,
    Transcript &transcript, LanedProverTimings &timings,
    gkr::ProofTransportPolicy transport = {},
    std::function<void()> gkr_complete = {},
    RuntimeProgressCallback progress = {}) {
    return profiling_detail::prove_laned_reference<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        transcript, timings, transport, std::move(gkr_complete),
        std::move(progress));
}

template <packing::SignedDigitPackingBackend Backend,
          typename VerifierContext>
    requires packing::PublicCoefficientVerifierContext<
        Backend, VerifierContext>
bool verify_laned_profiled(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> input_layer,
    const VerifierContext &verifier,
    const LanedVerifierSetup &packing_setup,
    const ClientSetup<Backend> &setup,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const LaminateLanedProof<Backend> &proof, Transcript &transcript,
    LanedVerifierTimings &timings,
    RuntimeProgressCallback progress = {}) {
    return profiling_detail::verify_laned<Backend>(
        payload, circuit, input_layer, verifier, packing_setup, setup,
        expected_provenance, expected_trace_id, expected_output_claim,
        proof, transcript, timings, progress);
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_METRICS_PROFILING_HPP
