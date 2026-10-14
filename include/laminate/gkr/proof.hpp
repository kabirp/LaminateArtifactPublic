#ifndef LAMINATE_GKR_PROOF_HPP
#define LAMINATE_GKR_PROOF_HPP

/// @file proof.hpp
/// @brief Profile-tagged logical GKR proof and plaintext oracle driver.

#include "laminate/gkr/layer_reductions.hpp"
#include "laminate/setup.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

namespace laminate::gkr {

enum class ProtocolVariant : std::uint8_t {
    LaminateBase,
    LaminateFolded,
    LaminateLaned,
};

/// Generic cross-round transcript packing. Fixed packing of the two values in
/// one Folded/Laned round is part of that round's encrypted encoding, not this
/// profile. Cross-round packing is assembled outside the logical GKR proof.
enum class CrossRoundPacking : std::uint8_t {
    None,
};

struct ProtocolProfile {
    ProtocolVariant variant = ProtocolVariant::LaminateBase;
    GateMleProfile gate_mle = GateMleProfile::Direct;
    CrossRoundPacking cross_round_packing = CrossRoundPacking::None;

    bool operator==(const ProtocolProfile &) const = default;
};

/// Transport compaction normally keeps only enough noise for client
/// decryption. An outer packer can explicitly reserve depth before messages
/// are compacted. The underlying layer relation is unchanged, but the actual
/// normalized ciphertext encoding is transcript-bound, so changing this
/// policy can change proof bytes and Fiat--Shamir challenges.
struct ProofTransportPolicy {
    std::size_t reserved_mult_depth = 0;
};

/// Version 5 uses h(0),h(2) multiplication messages (h(1),h(2) at gamma=0)
/// and checks the equality-stripped terminal product before selector interpolation.
inline constexpr std::uint64_t kLogicalProofVersion = 5;

struct ProofHeader {
    std::uint64_t version = kLogicalProofVersion;
    ProtocolProfile profile;
    payload::TraceProvenance provenance =
        payload::TraceProvenance::SyntheticTrace;
    Digest circuit_id{};
    Digest setup_id{};
    Digest trace_id{};
    std::size_t layer_count = 0;

    bool operator==(const ProofHeader &) const = default;
};

using DecryptedLayerReductionProof =
    std::variant<AffineLayerReductionProof, MultiplicationLayerReductionProof>;

/// Logical messages after decryption. Fiat-Shamir challenges and intermediate claim
/// state are derived during replay and therefore are not proof bytes.
struct DecryptedGkrProof {
    ProofHeader header;
    SingleClaim output_claim;
    std::vector<DecryptedLayerReductionProof> reductions;

    bool operator==(const DecryptedGkrProof &) const = default;
};

void validate_profile(const ProtocolProfile &profile,
                      const PublicSetup &setup,
                      const payload::LayeredCircuit &circuit);

std::vector<std::uint8_t> encode_canonical(const ProofHeader &header);
std::vector<std::uint8_t> encode_canonical(const DecryptedGkrProof &proof);
void observe_proof_header(const ProofHeader &header, Transcript &transcript);

/// Validate IDs, profile, layer kinds, output dimension, and every expected
/// round count without consuming transcript state.
bool validate_proof_structure(const DecryptedGkrProof &proof,
                              const ProtocolProfile &expected_profile,
                              payload::TraceProvenance expected_provenance,
                              const Digest &expected_trace_id,
                              const PublicSetup &setup,
                              const payload::LayeredCircuit &circuit);

/// Construct every logical proof message from a validated plaintext trace.
/// This is a correctness oracle, not the benchmarked encrypted prover.
DecryptedGkrProof prove_plaintext_gkr(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::PlainTrace &trace, const PublicSetup &setup,
    const ProtocolProfile &profile, std::vector<Fpk> output_point,
    Transcript &transcript);

/// Replay a logical proof against the expected public IDs/output and the
/// terminal input table. Returns false for every malformed or failed proof.
bool verify_plaintext_gkr(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> input_layer, const PublicSetup &setup,
    const ProtocolProfile &expected_profile,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id, const SingleClaim &expected_output_claim,
    const DecryptedGkrProof &proof, Transcript &transcript);

} // namespace laminate::gkr

#endif // LAMINATE_GKR_PROOF_HPP
