#ifndef LAMINATE_PROTOCOL_METRICS_TYPES_HPP
#define LAMINATE_PROTOCOL_METRICS_TYPES_HPP

/// @file types.hpp
/// @brief Optional timing and proof-size records kept outside protocol APIs.

#include "laminate/payload/circuit.hpp"
#include "laminate/payload/ir/layered.hpp"
#include "laminate/packing/evaluation/lazy_ternary.hpp"

#include <cstddef>
#include <vector>

namespace laminate::protocol {

struct BaseProofSizeBreakdown {
    std::size_t total_bytes = 0;
    std::size_t statement_and_metadata_bytes = 0;
    std::size_t round_message_bytes = 0;
    std::size_t terminal_message_bytes = 0;
    std::size_t partial_gate_mle_bytes = 0;
    std::size_t gate_mle_opening_bytes = 0;
    std::size_t transcript_packing_bytes = 0;
    std::size_t logical_round_messages = 0;
    std::size_t extension_ciphertexts = 0;
    std::size_t base_ciphertexts = 0;
    /// Public coefficient records emitted by mixed extension messages.
    std::size_t public_plaintext_coefficients = 0;
    /// Base-field elements carried by those public coefficient records.
    std::size_t public_plaintext_field_elements = 0;

    bool operator==(const BaseProofSizeBreakdown &) const = default;
};

struct FoldedProofSizeBreakdown : BaseProofSizeBreakdown {
    std::size_t committed_gkr_bytes = 0;
    std::size_t gkr_commitment_bytes = 0;
    std::size_t well_formedness_reveal_bytes = 0;
    std::size_t digit_packing_ciphertext_bytes = 0;
    std::size_t spartan_packing_proof_bytes = 0;

    bool operator==(const FoldedProofSizeBreakdown &) const = default;
};

struct LanedProofSizeBreakdown : BaseProofSizeBreakdown {
    std::size_t committed_gkr_bytes = 0;
    std::size_t gkr_commitment_bytes = 0;
    std::size_t well_formedness_reveal_bytes = 0;
    std::size_t digit_packing_ciphertext_bytes = 0;
    std::size_t spartan_packing_proof_bytes = 0;

    bool operator==(const LanedProofSizeBreakdown &) const = default;
};

struct BaseLayerTiming {
    std::size_t layer = 0;
    payload::LayerKind kind = payload::LayerKind::Input;
    double wall_ms = 0;
    double cpu_ms = 0;
};

struct BaseProverTimings {
    std::vector<BaseLayerTiming> layers;
    double gate_mle_opening_wall_ms = 0;
    double gate_mle_opening_cpu_ms = 0;
};

struct BaseVerifierTimings {
    std::vector<BaseLayerTiming> layers;
    // Direct message recovery for Base; complete transcript-packing proof
    // verification and message recovery for Folded/Laned.
    double packed_message_verification_wall_ms = 0;
    double packed_message_verification_cpu_ms = 0;
    double gate_mle_opening_wall_ms = 0;
    double gate_mle_opening_cpu_ms = 0;
};

using FoldedLayerTiming = BaseLayerTiming;
struct FoldedProverTimings : BaseProverTimings {
    double transcript_packing_wall_ms = 0;
    double transcript_packing_cpu_ms = 0;
};
struct FoldedVerifierTimings : BaseVerifierTimings {
    packing::LazyTernaryThresholdAssessment transcript_packing_threshold;
};

using LanedLayerTiming = BaseLayerTiming;
struct LanedProverTimings : BaseProverTimings {
    double transcript_packing_wall_ms = 0;
    double transcript_packing_cpu_ms = 0;
};
struct LanedVerifierTimings : BaseVerifierTimings {
    packing::LazyTernaryThresholdAssessment transcript_packing_threshold;
};

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_METRICS_TYPES_HPP
