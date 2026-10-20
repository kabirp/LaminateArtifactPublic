#ifndef LAMINATE_PROTOCOL_DETAIL_PROOF_SIZE_PACKED_HPP
#define LAMINATE_PROTOCOL_DETAIL_PROOF_SIZE_PACKED_HPP

/// @file packed.hpp
/// @brief Canonical wire encoding and accounting for selected packed proofs.

#include "laminate/protocol/detail/packing/committed_gkr_encoding.hpp"
#include "laminate/protocol/detail/packing/messages.hpp"
#include "laminate/fhe/storage/value_codec.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace laminate::protocol::detail::packed_proof_io_detail {

inline void append_u64(std::vector<std::uint8_t> &output,
                       std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

inline void append_size(std::vector<std::uint8_t> &output,
                        std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("packed proof: size does not fit u64");
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

inline void patch_size(std::vector<std::uint8_t> &output,
                       std::size_t offset, std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max() ||
        offset > output.size() || output.size() - offset < 8U) {
        throw std::overflow_error("packed proof: invalid size patch");
    }
    const std::uint64_t encoded = static_cast<std::uint64_t>(value);
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output[offset + byte] = static_cast<std::uint8_t>(
            (encoded >> (8U * byte)) & std::uint64_t{0xff});
    }
}

template <fhe::FheBackend Backend>
std::size_t append_reveal_value(
    std::vector<std::uint8_t> &output,
    const std::optional<typename Backend::Ciphertext> &value) {
    if (!value) {
        constexpr std::size_t record_bytes =
            1U + sizeof(std::uint64_t);
        append_size(output, record_bytes);
        output.push_back(static_cast<std::uint8_t>(
            fhe::FheValueRecordTag::PublicScalar));
        append_u64(output, 0);
        return sizeof(std::uint64_t) + record_bytes;
    }

    const std::vector<std::uint8_t> ciphertext =
        Backend::serialize(*value);
    if (ciphertext.empty() ||
        ciphertext.size() == std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(
            "packed proof: backend produced an invalid ciphertext encoding");
    }
    const std::size_t record_bytes = 1U + ciphertext.size();
    append_size(output, record_bytes);
    output.push_back(static_cast<std::uint8_t>(
        fhe::FheValueRecordTag::Ciphertext));
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());
    return sizeof(std::uint64_t) + record_bytes;
}

struct ComponentBytes {
    std::size_t committed_gkr = 0;
    std::size_t gkr_commitments = 0;
    std::size_t gate_mle_opening = 0;
    std::size_t well_formedness = 0;
    std::size_t packed_digits = 0;
    std::size_t spartan = 0;
};

template <packing::CoefficientWellFormednessBackend Backend,
          typename CommittedProof>
ComponentBytes append(
    char protocol_tag, const CommittedProof &gkr,
    const TranscriptPackingProof<Backend> &packing,
    std::vector<std::uint8_t> &output) {
    const std::array<std::uint8_t, 14> prefix{
        'L', 'M', '/', 'P', 'A', 'C', 'K', 'E', 'D', '/',
        static_cast<std::uint8_t>(protocol_tag), '/', 'v', '7'};
    output.insert(output.end(), prefix.begin(), prefix.end());
    ComponentBytes components;
    const std::size_t committed_size_offset = output.size();
    append_size(output, 0);
    const CommittedGkrEncodingStats committed =
        append_committed_gkr(output, gkr);
    patch_size(output, committed_size_offset, committed.total_bytes);
    components.committed_gkr = committed.total_bytes;
    components.gkr_commitments = committed.commitment_digest_bytes;
    components.gate_mle_opening = committed.gate_mle_opening_bytes;

    append_size(output, packing.well_formedness_reveals.size());
    for (const auto &reveal : packing.well_formedness_reveals) {
        components.well_formedness +=
            append_reveal_value<Backend>(output, reveal);
    }

    append_size(output,
                packing.digit_decomposed_packed_values.size());
    for (const auto &digit :
         packing.digit_decomposed_packed_values) {
        components.packed_digits +=
            append_reveal_value<Backend>(output, digit);
    }

    const std::size_t spartan_size_offset = output.size();
    append_size(output, 0);
    const std::size_t spartan_start = output.size();
    spartan::append_encoded_proof(packing.proof_of_packing, output);
    components.spartan = output.size() - spartan_start;
    patch_size(output, spartan_size_offset, components.spartan);
    return components;
}

template <typename CommittedProof>
std::size_t round_commitment_count(const CommittedProof &proof) {
    std::size_t result = 0;
    for (const auto &reduction : proof.reductions) {
        std::visit([&](const auto &typed) { result += typed.rounds.size(); },
                   reduction);
    }
    return result;
}

template <typename Size, typename Proof>
void fill_common(Size &result, const Proof &proof,
                 const ComponentBytes &components) {
    result.committed_gkr_bytes = components.committed_gkr;
    result.gkr_commitment_bytes = components.gkr_commitments;
    result.gate_mle_opening_bytes = components.gate_mle_opening;
    result.well_formedness_reveal_bytes = components.well_formedness;
    result.digit_packing_ciphertext_bytes = components.packed_digits;
    result.spartan_packing_proof_bytes = components.spartan;
    result.transcript_packing_bytes =
        components.well_formedness + components.packed_digits +
        components.spartan;
    result.logical_round_messages = round_commitment_count(proof.gkr);
    result.base_ciphertexts =
        static_cast<std::size_t>(std::count_if(
            proof.transcript_packing.digit_decomposed_packed_values.begin(),
            proof.transcript_packing.digit_decomposed_packed_values.end(),
            [](const auto &value) { return value.has_value(); }));
    for (const auto &reveal :
         proof.transcript_packing.well_formedness_reveals) {
        result.base_ciphertexts += reveal ? 1U : 0U;
    }
    const std::size_t classified =
        result.committed_gkr_bytes + result.well_formedness_reveal_bytes +
        result.digit_packing_ciphertext_bytes +
        result.spartan_packing_proof_bytes;
    if (classified > result.total_bytes) {
        throw std::logic_error(
            "packed proof: component sizes exceed canonical encoding");
    }
    result.statement_and_metadata_bytes = result.total_bytes - classified;
}

} // namespace laminate::protocol::detail::packed_proof_io_detail

namespace laminate::protocol {

template <packing::CoefficientWellFormednessBackend Backend>
FoldedProofSizeBreakdown append_canonical_with_size(
    const LaminateFoldedProof<Backend> &proof,
    std::vector<std::uint8_t> &output) {
    const std::size_t start = output.size();
    const auto components =
        detail::packed_proof_io_detail::append<Backend>(
            'F', proof.gkr, proof.transcript_packing, output);
    FoldedProofSizeBreakdown breakdown;
    breakdown.total_bytes = output.size() - start;
    detail::packed_proof_io_detail::fill_common(
        breakdown, proof, components);
    return breakdown;
}

template <packing::CoefficientWellFormednessBackend Backend>
CanonicalProofEncoding<FoldedProofSizeBreakdown>
encode_canonical_with_size(const LaminateFoldedProof<Backend> &proof) {
    CanonicalProofEncoding<FoldedProofSizeBreakdown> result;
    result.breakdown = append_canonical_with_size<Backend>(
        proof, result.bytes);
    return CanonicalProofEncoding<FoldedProofSizeBreakdown>{
        .bytes = std::move(result.bytes),
        .breakdown = std::move(result.breakdown),
    };
}

template <packing::CoefficientWellFormednessBackend Backend>
std::vector<std::uint8_t>
encode_canonical(const LaminateFoldedProof<Backend> &proof) {
    return encode_canonical_with_size<Backend>(proof).bytes;
}

template <packing::CoefficientWellFormednessBackend Backend>
FoldedProofSizeBreakdown
measure_proof_size(const LaminateFoldedProof<Backend> &proof) {
    return encode_canonical_with_size<Backend>(proof).breakdown;
}

template <packing::CoefficientWellFormednessBackend Backend>
LanedProofSizeBreakdown append_canonical_with_size(
    const LaminateLanedProof<Backend> &proof,
    std::vector<std::uint8_t> &output) {
    const std::size_t start = output.size();
    const auto components =
        detail::packed_proof_io_detail::append<Backend>(
            'L', proof.gkr, proof.transcript_packing, output);
    LanedProofSizeBreakdown breakdown;
    breakdown.total_bytes = output.size() - start;
    detail::packed_proof_io_detail::fill_common(
        breakdown, proof, components);
    return breakdown;
}

template <packing::CoefficientWellFormednessBackend Backend>
CanonicalProofEncoding<LanedProofSizeBreakdown>
encode_canonical_with_size(const LaminateLanedProof<Backend> &proof) {
    CanonicalProofEncoding<LanedProofSizeBreakdown> result;
    result.breakdown = append_canonical_with_size<Backend>(
        proof, result.bytes);
    return CanonicalProofEncoding<LanedProofSizeBreakdown>{
        .bytes = std::move(result.bytes),
        .breakdown = std::move(result.breakdown),
    };
}

template <packing::CoefficientWellFormednessBackend Backend>
std::vector<std::uint8_t>
encode_canonical(const LaminateLanedProof<Backend> &proof) {
    return encode_canonical_with_size<Backend>(proof).bytes;
}

template <packing::CoefficientWellFormednessBackend Backend>
LanedProofSizeBreakdown
measure_proof_size(const LaminateLanedProof<Backend> &proof) {
    return encode_canonical_with_size<Backend>(proof).breakdown;
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_DETAIL_PROOF_SIZE_PACKED_HPP
