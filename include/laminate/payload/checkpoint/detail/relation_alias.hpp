#ifndef LAMINATE_PAYLOAD_CHECKPOINT_DETAIL_RELATION_ALIAS_HPP
#define LAMINATE_PAYLOAD_CHECKPOINT_DETAIL_RELATION_ALIAS_HPP

/// @file relation_alias.hpp
/// @brief Exact eligibility predicate for file-backed identity aliases.

#include "laminate/payload/checkpoint/execution_types.hpp"

#include <cstddef>
#include <optional>
#include <variant>
#include <vector>

namespace laminate::payload::checkpoint_replay_execution_detail {

/// Immutable view of the setup-certified facts needed to decide whether an
/// affine relation can publish its source records under a new manifest.
struct StoredIdentityAffineAliasCandidate {
    const Layer &relation;
    const EncryptedTraceLayerDescriptor &source_descriptor;
    const EncryptedTraceLayerDescriptor &output_descriptor;
    const PayloadReplayLayer &source_resources;
    const PayloadReplayLayer &output_resources;
    const LayerStorageLayout &source_storage;
    const LayerStorageLayout &output_storage;
    const std::vector<ClassifiedTraceValue> &source_classifications;
    const std::vector<ClassifiedTraceValue> &output_classifications;
};

/// True exactly when the stored output sequence is byte-for-byte identical to
/// the stored source sequence at the same FHE level. Padded protocol domains
/// may differ because padding is virtual and never enters either sequence.
inline bool qualifies_stored_identity_affine_alias(
    const StoredIdentityAffineAliasCandidate &candidate) {
    const auto *affine = std::get_if<AffineLayer>(&candidate.relation);
    if (affine == nullptr || !affine->intermediate_gates.empty() ||
        candidate.source_descriptor.layout !=
            candidate.output_descriptor.layout ||
        candidate.source_descriptor.dimensions.logical_size !=
            candidate.output_descriptor.dimensions.logical_size ||
        candidate.source_descriptor.required_mult_depth !=
            candidate.output_descriptor.required_mult_depth ||
        candidate.source_descriptor.record_count !=
            candidate.output_descriptor.record_count ||
        candidate.source_resources.rns_limb_count !=
            candidate.output_resources.rns_limb_count ||
        candidate.source_resources.serialized_ciphertext_bytes !=
            candidate.output_resources.serialized_ciphertext_bytes ||
        candidate.output_resources.modulus_switches_after_layer != 0 ||
        candidate.source_storage.stored_wire_count == 0 ||
        candidate.source_storage.stored_wire_count !=
            candidate.output_storage.stored_wire_count ||
        candidate.source_classifications !=
            candidate.output_classifications) {
        return false;
    }

    for (std::size_t stored = 0;
         stored < candidate.output_storage.stored_wire_count; ++stored) {
        const std::size_t gate_index =
            candidate.output_storage.representative_padded_index_of(stored);
        const AffineGate &gate = affine->gates.at(gate_index);
        const auto *constant = std::get_if<Fp>(&gate.constant);
        if (gate.origin == GateOrigin::Padding || gate.terms.size() != 1U ||
            constant == nullptr || !constant->is_zero()) {
            return false;
        }
        const AffineTerm &term = gate.terms.front();
        const std::optional<std::size_t> source_ordinal =
            candidate.source_storage.stored_ordinal_of(term.source);
        if (!source_ordinal || *source_ordinal != stored ||
            term.rotation != 0 || term.plaintext_index ||
            !(term.coefficient == Fp::one())) {
            return false;
        }
    }
    return true;
}

} // namespace laminate::payload::checkpoint_replay_execution_detail

#endif // LAMINATE_PAYLOAD_CHECKPOINT_DETAIL_RELATION_ALIAS_HPP
