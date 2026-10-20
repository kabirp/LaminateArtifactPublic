#ifndef LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_COMMITTED_GKR_HPP
#define LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_COMMITTED_GKR_HPP

/// @file committed_gkr.hpp
/// @brief Canonical committed Folded/Laned GKR proof decoding.

#include "laminate/gkr/detail/folded/validation/request.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/gkr/detail/laned/validation/request.hpp"
#include "laminate/protocol/packed/wire/detail/canonical_framing.hpp"

#include <type_traits>
#include <utility>

namespace laminate::protocol::detail::packed_proof_decode_detail {

template <packing::CoefficientWellFormednessBackend Backend,
          typename Context>
    requires PackedProofDecodeContext<Backend, Context>
gkr::CommittedPackedMessage read_committed_message(
    Reader &reader, const Context &context, DecodeBudget &budget,
    const PackedProofDecodeLimits &limits, const char *operation) {
    const std::uint8_t kind = reader.read_u8();
    if (kind == 1U) {
        gkr::PackedMessageCommitment commitment;
        const auto digest = reader.read_bytes(commitment.digest.size());
        std::copy(digest.begin(), digest.end(), commitment.digest.begin());
        budget.add_digests(1);
        return gkr::CommittedPackedMessage::encrypted_message(commitment);
    }
    if (kind != 0U) {
        reject(operation, "unknown committed-message tag");
    }

    const std::uint8_t plaintext_kind = reader.read_u8();
    if (plaintext_kind == 0U) {
        const std::uint64_t value = reader.read_u64();
        if (value >= kBaseFieldOrder) {
            reject(operation, "public scalar is outside Fp");
        }
        budget.add_fields(1);
        return gkr::CommittedPackedMessage::public_message(
            fhe::PublicPlaintext::from_scalar(Fp(value)));
    }
    if (plaintext_kind != 1U && plaintext_kind != 2U) {
        reject(operation, "unknown public-message tag");
    }

    const std::size_t slots = reader.read_size();
    if (slots != Backend::slot_count(context) ||
        slots > limits.max_collection_elements) {
        reject(operation, "public message has the wrong slot count");
    }
    // Charge the reconstructed allocation, not only the sparse wire entries.
    budget.add_fields(slots);
    fhe::SlotVector values(slots, Fp::zero());
    std::size_t nonzero = 0;
    if (plaintext_kind == 2U) {
        nonzero = reader.read_size();
        if (nonzero == 0 ||
            !gkr::committed_public_uses_sparse(slots, nonzero)) {
            reject(operation, "noncanonical public sparse count");
        }
        std::size_t previous = 0;
        for (std::size_t entry = 0; entry < nonzero; ++entry) {
            const std::size_t index = reader.read_size();
            const std::uint64_t value = reader.read_u64();
            if (index >= slots || (entry != 0 && index <= previous)) {
                reject(operation, "public sparse indices are not increasing");
            }
            if (value == 0 || value >= kBaseFieldOrder) {
                reject(operation, "public sparse value is not nonzero Fp");
            }
            values[index] = Fp(value);
            previous = index;
        }
    } else {
        for (std::size_t slot = 0; slot < slots; ++slot) {
            const std::uint64_t value = reader.read_u64();
            if (value >= kBaseFieldOrder) {
                reject(operation, "public slot is outside Fp");
            }
            values[slot] = Fp(value);
            nonzero += value != 0;
        }
        if (gkr::committed_public_uses_sparse(slots, nonzero)) {
            reject(operation, "sparse public message uses dense encoding");
        }
    }
    fhe::PublicPlaintext plaintext =
        fhe::PublicPlaintext::from_slots(std::move(values));
    if (!plaintext.is_slots()) {
        reject(operation, "uniform public-slot message is noncanonical");
    }
    return gkr::CommittedPackedMessage::public_message(
        std::move(plaintext));
}

template <packing::CoefficientWellFormednessBackend Backend,
          typename Context, typename CommittedProof>
    requires PackedProofDecodeContext<Backend, Context>
CommittedProof read_committed_gkr(
    Reader &reader, char variant, const Context &context,
    const payload::LayeredCircuit &circuit, const PublicSetup &setup,
    const Digest &expected_setup_id, DecodeBudget &budget,
    const PackedProofDecodeLimits &limits, const char *operation) {
    require_versioned_tag(reader, kCommittedPrefix, variant, '3', operation);
    CommittedProof proof;
    proof.header =
        delegation::base_wire_detail::read_header(reader, operation);
    const gkr::ProtocolVariant expected_variant =
        variant == 'F' ? gkr::ProtocolVariant::LaminateFolded
                       : gkr::ProtocolVariant::LaminateLaned;
    const std::uint64_t expected_version =
        variant == 'F' ? gkr::kEncryptedFoldedProofVersion
                       : gkr::kEncryptedLanedProofVersion;
    const gkr::ProtocolProfile expected_profile{
        expected_variant, setup.gate_mle_profile,
        gkr::CrossRoundPacking::None};
    if (proof.header.version != expected_version ||
        proof.header.profile != expected_profile ||
        proof.header.circuit_id != setup.circuit_digest ||
        proof.header.setup_id != expected_setup_id ||
        proof.header.layer_count != circuit.layers.size()) {
        reject(operation, "committed GKR header disagrees with setup");
    }

    const std::size_t reductions = circuit.layers.size() - 1U;
    require_count(reader.read_size(), reductions, limits, operation,
                  "committed GKR reduction count");
    proof.reductions.reserve(reductions);
    for (std::size_t layer = 0; layer < reductions; ++layer) {
        const payload::LayerKind layer_kind =
            payload::layer_kind(circuit.layers[layer]);
        const std::uint8_t encoded_kind = reader.read_u8();
        const std::size_t expected_rounds = [&] {
            if (variant == 'F') {
                const std::size_t wire_variables =
                    gkr::base_detail::ciphertext_index_variables(
                        circuit, layer + 1U);
                const std::size_t slot_variables =
                    gkr::base_detail::slot_index_variables(circuit);
                return layer_kind == payload::LayerKind::Affine
                           ? delegation::wire_detail::checked_add(
                                 wire_variables, slot_variables, operation)
                           : delegation::wire_detail::checked_add(
                                 wire_variables - 1U, slot_variables,
                                 operation);
            }
            if (layer_kind == payload::LayerKind::Affine) {
                return gkr::laned_layer_variables(circuit, layer + 1U);
            }
            return gkr::laned_detail::layout_variables(
                gkr::laned_layout(circuit, layer));
        }();
        require_count(reader.read_size(), expected_rounds, limits,
                      operation, "committed GKR round count");

        if (layer_kind == payload::LayerKind::Affine) {
            if (encoded_kind != 0U) {
                reject(operation, "wrong committed GKR reduction kind");
            }
            if constexpr (std::is_same_v<
                              CommittedProof,
                              gkr::CommittedFoldedGkrProof>) {
                gkr::CommittedFoldedAffineLayerReduction reduction;
                reduction.rounds.reserve(expected_rounds);
                for (std::size_t round = 0; round < expected_rounds;
                     ++round) {
                    reduction.rounds.push_back(
                        gkr::CommittedFoldedLayerReductionSumcheckRound{
                            read_committed_message<Backend>(
                                reader, context, budget, limits,
                                operation)});
                }
                reduction.packed_terminal_value =
                    read_committed_message<Backend>(
                        reader, context, budget, limits, operation);
                proof.reductions.emplace_back(std::move(reduction));
            } else {
                gkr::CommittedLanedAffineLayerReduction reduction;
                reduction.rounds.reserve(expected_rounds);
                for (std::size_t round = 0; round < expected_rounds;
                     ++round) {
                    reduction.rounds.push_back(
                        gkr::CommittedLanedLayerReductionSumcheckRound{
                            read_committed_message<Backend>(
                                reader, context, budget, limits,
                                operation)});
                }
                reduction.packed_terminal_value =
                    read_committed_message<Backend>(
                        reader, context, budget, limits, operation);
                proof.reductions.emplace_back(std::move(reduction));
            }
            continue;
        }

        if (encoded_kind != 1U) {
            reject(operation, "wrong committed GKR reduction kind");
        }
        if constexpr (std::is_same_v<CommittedProof,
                                     gkr::CommittedFoldedGkrProof>) {
            gkr::CommittedFoldedMultiplicationLayerReduction reduction;
            reduction.rounds.reserve(expected_rounds);
            for (std::size_t round = 0; round < expected_rounds; ++round) {
                reduction.rounds.push_back(
                    gkr::CommittedFoldedLayerReductionSumcheckRound{
                        read_committed_message<Backend>(
                            reader, context, budget, limits, operation)});
            }
            reduction.packed_source_values =
                read_committed_message<Backend>(
                    reader, context, budget, limits, operation);
            proof.reductions.emplace_back(std::move(reduction));
        } else {
            gkr::CommittedLanedMultiplicationLayerReduction reduction;
            reduction.rounds.reserve(expected_rounds);
            for (std::size_t round = 0; round < expected_rounds; ++round) {
                reduction.rounds.push_back(
                    gkr::CommittedLanedLayerReductionSumcheckRound{
                        read_committed_message<Backend>(
                            reader, context, budget, limits, operation)});
            }
            reduction.packed_source_values =
                read_committed_message<Backend>(
                    reader, context, budget, limits, operation);
            proof.reductions.emplace_back(std::move(reduction));
        }
    }

    const std::uint8_t has_opening = reader.read_u8();
    if (has_opening > 1U ||
        (has_opening != 0U) !=
            (setup.gate_mle_profile ==
             GateMleProfile::OutsourcedBaseFold)) {
        reject(operation, "unexpected GateMLE opening presence");
    }
    if (has_opening != 0U) {
        if (!setup.outsourced_gate_mle) {
            reject(operation, "setup omits outsourced GateMLE key");
        }
        const auto nested_limits = base_limits(limits);
        proof.gate_mle_opening =
            delegation::base_wire_detail::read_outsourced_gate_proof(
                reader, *setup.outsourced_gate_mle, budget,
                nested_limits, operation);
    }
    return proof;
}

} // namespace laminate::protocol::detail::packed_proof_decode_detail

#endif // LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_COMMITTED_GKR_HPP
