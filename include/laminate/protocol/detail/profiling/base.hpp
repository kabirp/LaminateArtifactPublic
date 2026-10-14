#ifndef LAMINATE_PROTOCOL_DETAIL_PROFILING_BASE_HPP
#define LAMINATE_PROTOCOL_DETAIL_PROFILING_BASE_HPP

/// @file base.hpp
/// @brief Opt-in timing driver for LaminateBase.

#include "laminate/gkr/detail/base/reference/prover.hpp"
#include "laminate/gkr/detail/base/verifier.hpp"
#include "laminate/protocol/detail/profiling/readers.hpp"
#include "laminate/protocol/detail/profiling/runner.hpp"

namespace laminate::protocol::profiling_detail {

template <fhe::FheBackend Backend>
gkr::EncryptedBaseProof<Backend> prove_base_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point,
    Transcript &transcript, BaseProverTimings &timings) {
    timings = {};
    gkr::base_detail::ResidentBaseReferenceProver<Backend> prover(
        payload, circuit, trace, setup, output_point, transcript);
    return run_prover(prover, timings);
}

template <fhe::FheBackend Backend>
bool verify_base_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> input_layer,
    const ClientSetup<Backend> &setup,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const gkr::EncryptedBaseProof<Backend> &proof, Transcript &transcript,
    BaseVerifierTimings &timings) {
    timings = {};
    try {
        BaseMessageReader<Backend> reader(setup.context, timings);
        gkr::base_detail::BaseGkrVerifier<Backend, decltype(reader)> verifier(
            payload, circuit, input_layer, setup, expected_provenance,
            expected_trace_id, expected_output_claim, proof, reader,
            transcript);
        return run_verifier(verifier, timings);
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    } catch (const std::runtime_error &) {
        return false;
    }
}

template <fhe::FheBackend Backend>
bool verify_base(
    const CertifiedBaseClientSetup<Backend> &setup,
    std::span<const fhe::SlotVector> input_layer,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const gkr::EncryptedBaseProof<Backend> &proof, Transcript &transcript,
    BaseVerifierTimings &timings) {
    timings = {};
    try {
        BaseMessageReader<Backend> reader(setup.context(), timings);
        gkr::base_detail::BaseGkrVerifier<Backend, decltype(reader)> verifier(
            setup, input_layer, expected_provenance, expected_trace_id,
            expected_output_claim, proof, reader, transcript);
        return run_verifier(verifier, timings);
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    } catch (const std::runtime_error &) {
        return false;
    }
}

} // namespace laminate::protocol::profiling_detail

#endif // LAMINATE_PROTOCOL_DETAIL_PROFILING_BASE_HPP
