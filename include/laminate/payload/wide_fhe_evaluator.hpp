#ifndef LAMINATE_PAYLOAD_WIDE_FHE_EVALUATOR_HPP
#define LAMINATE_PAYLOAD_WIDE_FHE_EVALUATOR_HPP

/// @file wide_fhe_evaluator.hpp
/// @brief Server-side homomorphic evaluation of Wide payload traces.

#include "laminate/payload/evaluation/detail/fhe_evaluation_core.hpp"

namespace laminate::payload {

/// Evaluate a canonical Wide circuit and emit live trace values directly to
/// a compact sink. The server receives no client context and cannot decrypt.
/// Power-of-two padding remains a public protocol-domain convention rather
/// than an evaluated or serialized ciphertext value.
template <fhe::FheBackend Backend, typename Sink>
auto evaluate_wide_fhe_trace_into(
    const typename Backend::EvalContext &eval,
    const PayloadCircuit &payload, const LayeredCircuit &circuit,
    std::span<const typename Backend::Ciphertext> encrypted_inputs,
    const FheEvaluationPlan &plan, Sink sink)
    -> decltype(std::move(sink).finish()) {
    return fhe_evaluation_detail::evaluate_trace_into<
        Backend, fhe_evaluation_detail::WideLayout>(
        eval, payload, circuit, encrypted_inputs, plan, std::move(sink));
}

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_WIDE_FHE_EVALUATOR_HPP
