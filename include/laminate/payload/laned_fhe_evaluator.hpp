#ifndef LAMINATE_PAYLOAD_LANED_FHE_EVALUATOR_HPP
#define LAMINATE_PAYLOAD_LANED_FHE_EVALUATOR_HPP

/// @file laned_fhe_evaluator.hpp
/// @brief Server-side homomorphic evaluation of Laned payload traces.

#include "laminate/payload/evaluation/detail/fhe_evaluation_core.hpp"

namespace laminate::payload {

/// Evaluate the canonical alternating Laned circuit from encrypted inputs.
/// The server receives no client context and cannot decrypt. Only canonical
/// live trace values enter `sink`; structural padding remains the public zero
/// polynomial and consumes no ciphertext or trace record.
template <fhe::FheBackend Backend, typename Sink>
auto evaluate_laned_fhe_trace_into(
    const typename Backend::EvalContext &eval,
    const PayloadCircuit &payload, const LayeredCircuit &circuit,
    std::span<const typename Backend::Ciphertext> encrypted_inputs,
    const FheEvaluationPlan &plan, Sink sink)
    -> decltype(std::move(sink).finish()) {
    return fhe_evaluation_detail::evaluate_trace_into<
        Backend, fhe_evaluation_detail::LanedLayout>(
        eval, payload, circuit, encrypted_inputs, plan, std::move(sink));
}

/// Resident convenience wrapper for small instances and correctness tests.
/// Production execution normally supplies a file-backed compact sink.
template <fhe::FheBackend Backend>
EncryptedTrace<Backend> evaluate_laned_fhe_trace(
    const typename Backend::EvalContext &eval,
    const PayloadCircuit &payload, const LayeredCircuit &circuit,
    std::span<const typename Backend::Ciphertext> encrypted_inputs,
    const FheEvaluationPlan &plan) {
    return evaluate_laned_fhe_trace_into<Backend>(
        eval, payload, circuit, encrypted_inputs, plan,
        InMemoryTraceSink<Backend>{eval});
}

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_LANED_FHE_EVALUATOR_HPP
