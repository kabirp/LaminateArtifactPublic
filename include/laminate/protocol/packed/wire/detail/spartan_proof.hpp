#ifndef LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_SPARTAN_PROOF_HPP
#define LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_SPARTAN_PROOF_HPP

/// @file spartan_proof.hpp
/// @brief Setup-shaped decoding of the transcript-packing Spartan proof.

#include "laminate/protocol/packed/wire/detail/matrix_evaluation_proofs.hpp"

#include <bit>

namespace laminate::protocol::detail::packed_proof_decode_detail {

inline spartan::Proof read_spartan_proof(
    Reader &reader, const spartan::VerifierKey &key,
    spartan::BaseFoldPcsParameters parameters, DecodeBudget &budget,
    const PackedProofDecodeLimits &limits, const char *operation) {
    if (!key.circuit_metadata.is_well_formed() ||
        key.pcs_scheme != spartan::BaseFoldPcs::kSchemeIdentifier) {
        reject(operation, "invalid trusted Spartan verifier key");
    }
    spartan::Proof result;
    result.witness_commitment =
        read_pcs_commitment(reader, budget, key, parameters, operation);

    const std::size_t constraint_rounds =
        key.circuit_metadata.row_variables();
    const std::size_t wiring_rounds =
        key.circuit_metadata.column_variables();
    if (constraint_rounds > limits.max_collection_elements ||
        wiring_rounds > limits.max_collection_elements) {
        reject(operation, "Spartan round count exceeds configured limit");
    }
    result.constraint_sumcheck.rounds.reserve(constraint_rounds);
    for (std::size_t round = 0; round < constraint_rounds; ++round) {
        result.constraint_sumcheck.rounds.push_back(
            spartan::ConstraintSumcheckRound{
                read_fq2(reader, budget), read_fq2(reader, budget)});
    }
    result.az_evaluation = read_fq2(reader, budget);
    result.bz_evaluation = read_fq2(reader, budget);
    result.cz_evaluation = read_fq2(reader, budget);
    result.wiring_sumcheck.rounds.reserve(wiring_rounds);
    for (std::size_t round = 0; round < wiring_rounds; ++round) {
        result.wiring_sumcheck.rounds.push_back(
            spartan::WiringSumcheckRound{
                read_fq2(reader, budget), read_fq2(reader, budget)});
    }
    result.matrix_evaluation = read_fq2(reader, budget);
    result.assignment_evaluation = read_fq2(reader, budget);

    // The matrix-evaluation subproof is length-delimited so it cannot consume
    // bytes belonging to the witness opening that follows it.
    const std::size_t factored_bytes = reader.read_size();
    if (key.options.matrix_evaluation ==
        spartan::MatrixEvaluationMode::CommittedFactored) {
        if (!key.factored_computation || factored_bytes == 0 ||
            factored_bytes > limits.max_proof_bytes) {
            reject(operation, "missing or oversized factored proof");
        }
        Reader factored(reader.read_bytes(factored_bytes), operation);
        result.factored_evaluation = read_factored_proof(
            factored, *key.factored_computation, parameters, budget, limits,
            operation);
        factored.require_end();
    } else if (factored_bytes != 0) {
        reject(operation, "unexpected factored proof");
    }

    if (key.circuit_metadata.assignment_half_size() == 0 ||
        !std::has_single_bit(
            key.circuit_metadata.assignment_half_size())) {
        reject(operation, "invalid Spartan witness shape");
    }
    const std::size_t witness_log =
        std::bit_width(key.circuit_metadata.assignment_half_size()) - 1U;
    const std::size_t opening_bytes = reader.read_size();
    result.witness_opening = read_basefold_opening(
        reader, opening_bytes, witness_log, 1U, parameters, limits,
        operation, "Spartan witness BaseFold opening");
    return result;
}

} // namespace laminate::protocol::detail::packed_proof_decode_detail

#endif // LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_SPARTAN_PROOF_HPP
