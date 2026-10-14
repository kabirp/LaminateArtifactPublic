#ifndef LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_BASEFOLD_FRAMES_HPP
#define LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_BASEFOLD_FRAMES_HPP

/// @file basefold_frames.hpp
/// @brief Setup-shaped commitment and opaque BaseFold-opening frames.

#include "laminate/protocol/packed/wire/detail/canonical_framing.hpp"

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

namespace laminate::protocol::detail::packed_proof_decode_detail {

inline spartan::PcsCommitment read_pcs_commitment(
    Reader &reader, DecodeBudget &budget,
    const spartan::VerifierKey &key,
    spartan::BaseFoldPcsParameters parameters,
    const char *operation) {
    spartan::PcsCommitment result;
    result.scheme = reader.read_u64();
    const auto root = reader.read_bytes(result.root.size());
    std::copy(root.begin(), root.end(), result.root.begin());
    budget.add_digests(1);
    result.evaluation_count = reader.read_u64();
    result.width = reader.read_u64();
    const std::uint64_t log_rate = reader.read_u64();
    const std::uint64_t query_count = reader.read_u64();
    const auto &metadata = key.circuit_metadata;
    if (parameters.log_rate > std::numeric_limits<std::uint32_t>::max() ||
        parameters.query_count >
            std::numeric_limits<std::uint32_t>::max() ||
        result.scheme != key.pcs_scheme ||
        result.evaluation_count != metadata.assignment_half_size() ||
        result.width != 1U || log_rate != parameters.log_rate ||
        query_count != parameters.query_count) {
        reject(operation, "Spartan witness commitment metadata mismatch");
    }
    result.log_rate = static_cast<std::uint32_t>(log_rate);
    result.query_count = static_cast<std::uint32_t>(query_count);
    return result;
}

inline spartan::PcsOpeningProof read_basefold_opening(
    Reader &reader, std::size_t encoded_bytes, std::size_t message_log,
    std::size_t width, spartan::BaseFoldPcsParameters parameters,
    const PackedProofDecodeLimits &limits, const char *operation,
    std::string_view description) {
    if (message_log > limits.max_collection_elements || width == 0 ||
        width > limits.max_collection_elements ||
        parameters.query_count == 0 ||
        parameters.query_count > limits.max_collection_elements) {
        reject(operation,
               std::string(description) +
                   " shape exceeds configured limits");
    }
    const std::size_t maximum_bytes =
        spartan::basefold_opening_proof_max_size_bytes(
            message_log, width, parameters);
    if (encoded_bytes == 0 || encoded_bytes > maximum_bytes ||
        encoded_bytes > limits.max_proof_bytes) {
        reject(operation,
               std::string("unexpected ") + std::string(description) +
                   " length");
    }

    // BaseFold owns canonical parsing. This boundary only enforces the exact
    // setup-derived upper bound and copies the already-bounded opaque frame.
    const std::span<const std::uint8_t> encoded =
        reader.read_bytes(encoded_bytes);
    return spartan::PcsOpeningProof{
        std::vector<std::uint8_t>(encoded.begin(), encoded.end())};
}

} // namespace laminate::protocol::detail::packed_proof_decode_detail

#endif // LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_BASEFOLD_FRAMES_HPP
