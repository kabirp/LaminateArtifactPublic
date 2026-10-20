#ifndef LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_MATRIX_EVALUATION_PROOFS_HPP
#define LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_MATRIX_EVALUATION_PROOFS_HPP

/// @file matrix_evaluation_proofs.hpp
/// @brief Canonical factored-matrix subproof decoding.

#include "laminate/protocol/packed/wire/detail/basefold_frames.hpp"

#include <bit>
#include <string_view>
#include <utility>

namespace laminate::protocol::detail::packed_proof_decode_detail {

inline constexpr std::string_view kFactoredProofDomain =
    "LaminateImpl/FactoredMatrixEvaluationProof/v1";

inline spartan::FactoredMatrixEvaluationProof read_factored_proof(
    Reader &reader, const spartan::FactoredMatrixVerifierKey &key,
    spartan::BaseFoldPcsParameters parameters, DecodeBudget &budget,
    const PackedProofDecodeLimits &limits, const char *operation) {
    require_raw(reader, kFactoredProofDomain, operation);
    const auto &committed = key.commitment.tensors;
    require_count(reader.read_size(), committed.size(), limits, operation,
                  "factored tensor count");
    spartan::FactoredMatrixEvaluationProof result;
    result.tensors.reserve(committed.size());
    for (const auto &expected : committed) {
        if (expected.shape.evaluation_count == 0 ||
            !std::has_single_bit(expected.shape.evaluation_count) ||
            expected.shape.column_count == 0) {
            reject(operation, "invalid trusted factored tensor shape");
        }
        const std::size_t rounds =
            std::bit_width(expected.shape.evaluation_count) - 1U;
        spartan::FactoredTensorEvaluationProof tensor;
        tensor.claim = read_fq2(reader, budget);
        require_count(reader.read_size(), rounds, limits, operation,
                      "factored sumcheck round count");
        tensor.rounds.reserve(rounds);
        for (std::size_t round = 0; round < rounds; ++round) {
            spartan::FactoredSumcheckRound message;
            message.evaluations[0] = read_fq2(reader, budget);
            message.evaluations[1] = read_fq2(reader, budget);
            tensor.rounds.push_back(std::move(message));
        }
        tensor.terminal_tensor_value = read_fq2(reader, budget);
        const std::size_t opening_bytes = reader.read_size();
        const std::size_t columns =
            checked_size(expected.shape.column_count, operation);
        tensor.opening = read_basefold_opening(
            reader, opening_bytes, rounds, columns, parameters, limits,
            operation, "factored BaseFold opening");
        result.tensors.push_back(std::move(tensor));
    }
    return result;
}

} // namespace laminate::protocol::detail::packed_proof_decode_detail

#endif // LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_MATRIX_EVALUATION_PROOFS_HPP
