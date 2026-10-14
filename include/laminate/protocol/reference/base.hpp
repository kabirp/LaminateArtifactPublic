#ifndef LAMINATE_PROTOCOL_REFERENCE_BASE_HPP
#define LAMINATE_PROTOCOL_REFERENCE_BASE_HPP

/// @file base.hpp
/// @brief Bounded resident parity paths for LaminateBase tests and analysis.

#include "laminate/protocol/base.hpp"

namespace laminate::protocol::reference {

/// Prove from an already encrypted synthetic trace. This path intentionally
/// rejects FHE-evaluated provenance because it has no authenticated,
/// setup-bound proof-ingress schedule.
template <fhe::FheBackend Backend>
LaminateBaseProof<Backend> prove_base(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point, Transcript &transcript);

/// Verify against raw payload, circuit, and client setup objects. Production
/// clients use `protocol::verify_base` with `CertifiedBaseClientSetup`.
template <fhe::FheBackend Backend>
bool verify_base(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> input_layer,
    const ClientSetup<Backend> &setup,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const LaminateBaseProof<Backend> &proof, Transcript &transcript);

} // namespace laminate::protocol::reference

#include "laminate/protocol/detail/base/reference_impl.hpp"

#endif // LAMINATE_PROTOCOL_REFERENCE_BASE_HPP
