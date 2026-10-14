#ifndef LAMINATE_PROTOCOL_PACKED_PROOF_HPP
#define LAMINATE_PROTOCOL_PACKED_PROOF_HPP

/// @file proof.hpp
/// @brief Data-only proof types shared by LaminateFolded and LaminateLaned.

#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/laned.hpp"
#include "laminate/packing/evaluation/lazy_ternary.hpp"
#include "laminate/spartan/spartan.hpp"

#include <optional>
#include <vector>

namespace laminate::protocol {

/// Transcript-packing suffix carried by both packed Laminate variants.
///
/// Only encrypted contributions are transported. Public offsets and their
/// bottom-q coordinate sidecars are derived locally from tagged GKR messages
/// and Fiat--Shamir challenges. Spartan authenticates the resulting packing
/// relation against the committed aligned ciphertexts.
template <packing::CoefficientWellFormednessBackend Backend>
struct TranscriptPackingProof {
    std::vector<std::optional<typename Backend::Ciphertext>>
        well_formedness_reveals;
    std::vector<std::optional<typename Backend::Ciphertext>>
        digit_decomposed_packed_values;
    spartan::Proof proof_of_packing;
};

template <packing::CoefficientWellFormednessBackend Backend>
struct LaminateFoldedProof {
    gkr::CommittedFoldedGkrProof gkr;
    TranscriptPackingProof<Backend> transcript_packing;
};

template <packing::CoefficientWellFormednessBackend Backend>
struct LaminateLanedProof {
    gkr::CommittedLanedGkrProof gkr;
    TranscriptPackingProof<Backend> transcript_packing;
};

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_PROOF_HPP
