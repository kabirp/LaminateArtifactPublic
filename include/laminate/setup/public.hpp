#ifndef LAMINATE_SETUP_PUBLIC_HPP
#define LAMINATE_SETUP_PUBLIC_HPP

/// @file setup/public.hpp
/// @brief Public circuit identity and GateMLE setup profiles.

#include "laminate/gates/canonical_tables.hpp"
#include "laminate/payload/setup/encoding.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace laminate {

namespace payload {
class CertifiedHonestPayloadSchedule;
}

enum class GateMleProfile : std::uint8_t {
    Direct,
    /// Diagnostic transcript binding with direct Gate MLE evaluation;
    /// these digests are not polynomial commitments.
    DummyCommittedDirect,
    /// Committed gate-MLE openings. Wide uses bounded sparse composition
    /// with a local-adjoint fallback, authenticated by generic foldable codes.
    /// Laned uses sparse gate polynomials and sharded Reed-Solomon commitments.
    OutsourcedBaseFold,
};

struct DummyGateMleCommitment {
    std::size_t layer_index = 0;
    Digest value{};

    bool operator==(const DummyGateMleCommitment &other) const = default;
};

struct PublicSetup {
    GateMleProfile gate_mle_profile = GateMleProfile::Direct;
    payload::PayloadShape shape;
    std::size_t layer_count = 0;
    std::uint64_t plaintext_modulus = kBaseFieldOrder;
    std::size_t extension_degree = kExtensionDegree;
    std::size_t target_security_bits = kTargetSecurityBits;
    Digest payload_digest{};
    Digest layered_digest{};
    Digest circuit_digest{};
    /// Digest of one accepted, exactly re-derived honest-input payload
    /// schedule. Absence denotes a setup that has not selected an operational
    /// payload schedule.
    std::optional<Digest> honest_payload_noise_schedule_digest;
    /// Digest of the separately validated complete Base proof-noise report.
    /// Presence requires the payload-core schedule binding above.
    std::optional<Digest> honest_base_proof_noise_assessment_digest;
    std::vector<DummyGateMleCommitment> dummy_gate_commitments;
    std::optional<gates::GateTableVerifierKey> outsourced_gate_mle;

    void validate(const payload::PayloadCircuit &payload,
                  const payload::LayeredCircuit &layered) const;

    /// Check a schedule that already passed exact semantic validation.
    void validate_certified_payload_schedule(
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &layered,
        const payload::CertifiedHonestPayloadSchedule &schedule) const;
};

PublicSetup make_direct_setup(const payload::PayloadCircuit &payload,
                              const payload::LayeredCircuit &layered);
PublicSetup make_dummy_committed_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered);
PublicSetup make_outsourced_gate_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    gates::GateTableVerifierKey verifier_key);

/// Canonical public setup encoding used by proof IDs and transcript binding.
std::vector<std::uint8_t> encode_canonical(const PublicSetup &setup);
Digest setup_digest(const PublicSetup &setup);

} // namespace laminate

#endif // LAMINATE_SETUP_PUBLIC_HPP
