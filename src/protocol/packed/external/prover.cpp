/// @file prover.cpp
/// @brief Immutable Folded/Laned bindings for external transcript packing.

#include "laminate/protocol/packed/external/prover.hpp"

#include "laminate/payload/setup/encoding.hpp"

#include <algorithm>
#include <limits>
#include <ranges>
#include <stdexcept>
#include <utility>

namespace laminate::protocol {
namespace {

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

Digest external_setup_identity(
    PackingGkrVariant variant, std::size_t round_count,
    const Digest &layered_circuit_digest,
    const ConservativePackedProofIngressSchedule &schedule,
    const TranscriptPackingExternalProverSetup &transcript_packing) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (round_count > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                "packed external setup round count does not fit u64");
        }
    }
    static constexpr std::string_view kDomain =
        "LaminateImpl/PackedExternalProverSetupIdentity/v1";
    std::vector<std::uint8_t> encoded(kDomain.begin(), kDomain.end());
    append_u64(encoded, static_cast<std::uint64_t>(variant));
    append_u64(encoded, static_cast<std::uint64_t>(round_count));
    encoded.insert(encoded.end(), layered_circuit_digest.begin(),
                   layered_circuit_digest.end());
    encoded.insert(encoded.end(), schedule.digest().begin(),
                   schedule.digest().end());
    const Digest &spartan =
        transcript_packing.spartan_key().setup_digest;
    encoded.insert(encoded.end(), spartan.begin(), spartan.end());
    return sha256(encoded);
}

} // namespace

struct detail::PackedExternalProverSetupFactory {
    static PackedExternalProverSetup make(
        PackingGkrVariant variant,
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit,
        const PublicSetup &public_setup,
        const ConservativePackedProofIngressSchedule &
            proof_ingress_schedule,
        TranscriptPackingExternalProverSetup transcript_packing) {
    validate_conservative_packed_proof_ingress_schedule(
        payload, circuit, public_setup, proof_ingress_schedule);
    const std::size_t round_count =
        variant == PackingGkrVariant::Folded
            ? folded_bhip_round_count(circuit)
            : laned_bhip_round_count(circuit);
    const auto &relation = transcript_packing.relation();
    const std::size_t slot_count = relation.alignment_layout.slot_count;
    if (round_count == 0 ||
        proof_ingress_schedule.variant() != variant ||
        transcript_packing.variant() != variant ||
        transcript_packing.bhip_round_count() != round_count ||
        slot_count != circuit.shape.slot_count ||
        slot_count < fhe::kFixedMessageCellCount ||
        slot_count % fhe::kFixedMessageCellCount != 0 ||
        relation.alignment_layout !=
            packing::make_fixed_message_coset_packing_layout(
                slot_count, round_count,
                slot_count / fhe::kFixedMessageCellCount) ||
        relation.relation_plan.shape.native_modulus != kOuterFieldOrder ||
        relation.relation_plan.shape.ring_degree != slot_count) {
        throw std::invalid_argument(
            "packed external setup does not match its variant, circuit, "
            "ingress schedule, and canonical packing geometry");
    }
    const Digest layered_circuit_digest = payload::digest(circuit);
    const Digest identity = external_setup_identity(
        variant, round_count, layered_circuit_digest,
        proof_ingress_schedule, transcript_packing);
    return PackedExternalProverSetup(
        variant, round_count, layered_circuit_digest, identity,
        proof_ingress_schedule, std::move(transcript_packing));
    }
};

PackedExternalProverSetup make_folded_packed_external_prover_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const ConservativePackedProofIngressSchedule &
        proof_ingress_schedule,
    TranscriptPackingExternalProverSetup transcript_packing) {
    return detail::PackedExternalProverSetupFactory::make(
        PackingGkrVariant::Folded, payload, circuit, public_setup,
        proof_ingress_schedule,
        std::move(transcript_packing));
}

PackedExternalProverSetup make_laned_packed_external_prover_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const ConservativePackedProofIngressSchedule &
        proof_ingress_schedule,
    TranscriptPackingExternalProverSetup transcript_packing) {
    return detail::PackedExternalProverSetupFactory::make(
        PackingGkrVariant::Laned, payload, circuit, public_setup,
        proof_ingress_schedule,
        std::move(transcript_packing));
}

} // namespace laminate::protocol
