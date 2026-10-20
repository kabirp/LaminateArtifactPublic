#ifndef LAMINATE_PROTOCOL_METRICS_PROOF_SIZE_HPP
#define LAMINATE_PROTOCOL_METRICS_PROOF_SIZE_HPP

/// @file proof_size.hpp
/// @brief Canonical encodings and size accounting for benchmarks/tools.
///
/// This header is deliberately separate from the protocol entry points. A
/// reader following `prove_*` and `verify_*` never needs these diagnostics.
/// Sizes describe the selected canonical proof encoding, excluding delegation
/// request/response framing, encrypted payload outputs, preprocessing, and
/// transport overhead. Raw EncryptedFoldedProof/EncryptedLanedProof overloads
/// measure encrypted GKR before cross-round transcript packing; the
/// LaminateFoldedProof/LaminateLanedProof overloads measure the complete packed
/// protocol proof.

#include "laminate/gkr/base.hpp"
#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/laned.hpp"
#include "laminate/protocol/metrics/types.hpp"
#include "laminate/protocol/packed/proof.hpp"

namespace laminate::protocol {

/// One canonical proof serialization together with byte accounting collected
/// during that same pass. Process-boundary encoders use this form to avoid
/// traversing and serializing a large packed proof twice for diagnostics.
template <typename Breakdown> struct CanonicalProofEncoding {
    std::vector<std::uint8_t> bytes;
    Breakdown breakdown;
};

template <fhe::FheBackend Backend>
std::vector<std::uint8_t>
encode_canonical(const gkr::EncryptedBaseProof<Backend> &proof);

template <fhe::FheBackend Backend>
BaseProofSizeBreakdown
measure_proof_size(const gkr::EncryptedBaseProof<Backend> &proof);

template <fhe::FheBackend Backend>
std::vector<std::uint8_t>
encode_canonical(const gkr::EncryptedFoldedProof<Backend> &proof);

template <fhe::FheBackend Backend>
FoldedProofSizeBreakdown
measure_proof_size(const gkr::EncryptedFoldedProof<Backend> &proof);

template <fhe::FheBackend Backend>
std::vector<std::uint8_t>
encode_canonical(const gkr::EncryptedLanedProof<Backend> &proof);

template <fhe::FheBackend Backend>
LanedProofSizeBreakdown
measure_proof_size(const gkr::EncryptedLanedProof<Backend> &proof);

template <packing::CoefficientWellFormednessBackend Backend>
std::vector<std::uint8_t>
encode_canonical(const LaminateFoldedProof<Backend> &proof);

template <packing::CoefficientWellFormednessBackend Backend>
CanonicalProofEncoding<FoldedProofSizeBreakdown>
encode_canonical_with_size(const LaminateFoldedProof<Backend> &proof);

template <packing::CoefficientWellFormednessBackend Backend>
FoldedProofSizeBreakdown append_canonical_with_size(
    const LaminateFoldedProof<Backend> &proof,
    std::vector<std::uint8_t> &output);

template <packing::CoefficientWellFormednessBackend Backend>
FoldedProofSizeBreakdown
measure_proof_size(const LaminateFoldedProof<Backend> &proof);

template <packing::CoefficientWellFormednessBackend Backend>
std::vector<std::uint8_t>
encode_canonical(const LaminateLanedProof<Backend> &proof);

template <packing::CoefficientWellFormednessBackend Backend>
CanonicalProofEncoding<LanedProofSizeBreakdown>
encode_canonical_with_size(const LaminateLanedProof<Backend> &proof);

template <packing::CoefficientWellFormednessBackend Backend>
LanedProofSizeBreakdown append_canonical_with_size(
    const LaminateLanedProof<Backend> &proof,
    std::vector<std::uint8_t> &output);

template <packing::CoefficientWellFormednessBackend Backend>
LanedProofSizeBreakdown
measure_proof_size(const LaminateLanedProof<Backend> &proof);

} // namespace laminate::protocol

#include "laminate/protocol/detail/proof_size/base.hpp"
#include "laminate/protocol/detail/proof_size/folded.hpp"
#include "laminate/protocol/detail/proof_size/laned.hpp"
#include "laminate/protocol/detail/proof_size/packed.hpp"

#endif // LAMINATE_PROTOCOL_METRICS_PROOF_SIZE_HPP
