#ifndef LAMINATE_GKR_DETAIL_BASE_TESTING_FILE_TRACE_PROVER_HPP
#define LAMINATE_GKR_DETAIL_BASE_TESTING_FILE_TRACE_PROVER_HPP

/// @file file_trace_prover.hpp
/// @brief Retryable file-store adapter for bounded GKR kernel tests.
///
/// Production Base proving uses checkpoint replay and the explicit no-retry
/// entry point. This adapter deliberately keeps its source files so tests can
/// compare repeated proofs and failure behavior.

#include "laminate/gkr/detail/base/prover.hpp"

#include <span>
#include <utility>

namespace laminate::gkr::base_detail {

template <fhe::PersistableFheBackend Backend>
FileBaseGkrResult<Backend> prove_base_gkr_for_testing(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    FileEncryptedBaseGkrOptions options) {
    return BaseProver<
               Backend, const payload::FileEncryptedTraceStore<Backend>>(
               payload, circuit, trace, setup, output_point, transcript,
               std::move(options))
        .run();
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_TESTING_FILE_TRACE_PROVER_HPP
