#ifndef LAMINATE_PROTOCOL_ANALYSIS_PACKING_COMPLETENESS_HPP
#define LAMINATE_PROTOCOL_ANALYSIS_PACKING_COMPLETENESS_HPP

/// @file packing_completeness.hpp
/// @brief Circuit-wide deterministic-noise execution for Folded and Laned.

#include "laminate/fhe/noise/envelope_backend.hpp"
#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/laned.hpp"
#include "laminate/packing/analysis/deterministic_completeness.hpp"
#include "laminate/payload/trace.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace laminate::protocol {

/// Backend-independent statement and witness data needed to replay the prover
/// with bounds in place of ciphertext values. References must outlive the
/// synchronous certification call.
struct ProtocolNoiseEnvelopeStatement {
    const payload::PayloadCircuit &payload;
    const payload::LayeredCircuit &circuit;
    const payload::PlainTrace &trace;
    const PublicSetup &public_setup;
    const gkr::SingleClaim &output_claim;
    std::shared_ptr<const gates::GateTableProverKey> gate_mle_prover_key;
};

/// Shared statement type used by Folded/Laned packing analysis.
using PackingNoiseEnvelopeStatement = ProtocolNoiseEnvelopeStatement;

/// Public modulus and level schedule certified before a measured run.
struct PackingNoiseEnvelopeSchedule {
    fhe::NoiseEnvelopeParameters fhe_parameters;
    /// Uniform ingress depth used when the exact vector below is empty.
    /// Every proof-source layer then enters with `depth + 1` limbs.
    std::size_t required_proof_mult_depth = 0;
    /// Exact actual RNS limb count for every circuit layer. Entry zero is a
    /// non-authoritative output-layer placeholder; entries 1..L-1 are the
    /// levels consumed by reverse GKR. A nonempty vector takes precedence over
    /// `required_proof_mult_depth`.
    std::vector<std::size_t> proof_ingress_rns_limbs_by_layer;
    gkr::ProofTransportPolicy transport{
        .reserved_mult_depth = kPackingReservedMultDepth};
    std::uint64_t selected_final_error_cap =
        kSelectedPackingHonestErrorBound;

    void validate() const;
};

/// Complete result for one fixed circuit and protocol variant.
struct PackingNoiseEnvelopeResult {
    packing::DeterministicPackingCompletenessCertificate certificate;
    std::size_t ring_degree = 0;
    std::uint64_t plaintext_modulus = 0;
    std::uint64_t packing_modulus = 0;
    std::size_t bhip_round_count = 0;
    std::size_t logical_packed_output_count = 0;

    bool passes() const { return certificate.passes(); }
};

/// Replay every structurally possible Folded prover term, align each BhIP
/// round ciphertext, and certify the selected one-prime honest-error cap.
PackingNoiseEnvelopeResult certify_folded_packing_completeness(
    const PackingNoiseEnvelopeStatement &statement,
    const PackingNoiseEnvelopeSchedule &schedule);

/// Replay every structurally possible Laned prover term, align each BhIP
/// round ciphertext, and certify the selected one-prime honest-error cap.
PackingNoiseEnvelopeResult certify_laned_packing_completeness(
    const PackingNoiseEnvelopeStatement &statement,
    const PackingNoiseEnvelopeSchedule &schedule);

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_ANALYSIS_PACKING_COMPLETENESS_HPP
