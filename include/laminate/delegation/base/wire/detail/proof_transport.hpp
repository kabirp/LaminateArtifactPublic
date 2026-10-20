#ifndef LAMINATE_DELEGATION_BASE_WIRE_DETAIL_PROOF_TRANSPORT_HPP
#define LAMINATE_DELEGATION_BASE_WIRE_DETAIL_PROOF_TRANSPORT_HPP

/// @file proof_transport.hpp
/// @brief Canonical Base GKR proof encoding and setup-shaped decoding.

#include "laminate/delegation/base/wire/detail/gate_mle_proof.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"

#include <cstddef>
#include <stdexcept>
#include <utility>
#include <variant>

namespace laminate::delegation::base_wire_detail {

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
Bytes encode_proof_transport(
    const StorageContext &context,
    const protocol::LaminateBaseProof<Backend> &proof,
    ProofTransportSizeBreakdown *breakdown = nullptr) {
    constexpr const char *operation = "encode_base_response";
    ProofTransportSizeBreakdown measured;
    Bytes output;
    append_label(output, kBaseProofTransportDomain, operation);
    const Bytes header = gkr::encode_canonical(proof.header);
    wire_detail::append_size(output, header.size(), operation);
    output.insert(output.end(), header.begin(), header.end());
    wire_detail::append_size(output, proof.reductions.size(), operation);

    for (const gkr::EncryptedBaseLayerReductionProof<Backend> &reduction :
         proof.reductions) {
        if (const auto *affine =
                std::get_if<gkr::EncryptedBaseAffineLayerReduction<Backend>>(
                    &reduction)) {
            output.push_back(0);
            wire_detail::append_size(output, affine->rounds.size(),
                                     operation);
            for (const auto &round : affine->rounds) {
                const std::size_t start = output.size();
                measured.base_ciphertexts += append_extension<Backend>(
                    output, context, round.evaluations[0], operation);
                measured.base_ciphertexts += append_extension<Backend>(
                    output, context, round.evaluations[1], operation);
                account_public_extension(round.evaluations[0], measured);
                account_public_extension(round.evaluations[1], measured);
                measured.round_message_bytes += output.size() - start;
                ++measured.logical_round_messages;
                measured.extension_ciphertexts += 2U;
            }
            const std::size_t terminal_start = output.size();
            measured.base_ciphertexts += append_extension<Backend>(
                output, context, affine->source_vector, operation);
            account_public_extension(affine->source_vector, measured);
            measured.terminal_message_bytes +=
                output.size() - terminal_start;
            ++measured.extension_ciphertexts;
            const std::size_t partial_start = output.size();
            append_partial_gate_mle(output, affine->partial_gate_mle,
                                    operation);
            measured.partial_gate_mle_bytes +=
                output.size() - partial_start;
            measured.partial_gate_mle_field_elements +=
                affine->partial_gate_mle.evaluations.size();
            continue;
        }

        const auto &multiplication =
            std::get<gkr::EncryptedBaseMultiplicationLayerReduction<Backend>>(
                reduction);
        output.push_back(1);
        wire_detail::append_size(output, multiplication.rounds.size(),
                                 operation);
        for (const auto &round : multiplication.rounds) {
            const std::size_t start = output.size();
            measured.base_ciphertexts += append_extension<Backend>(
                output, context, round.evaluations[0], operation);
            measured.base_ciphertexts += append_extension<Backend>(
                output, context, round.evaluations[1], operation);
            account_public_extension(round.evaluations[0], measured);
            account_public_extension(round.evaluations[1], measured);
            measured.round_message_bytes += output.size() - start;
            ++measured.logical_round_messages;
            measured.extension_ciphertexts += 2U;
        }
        const std::size_t terminal_start = output.size();
        measured.base_ciphertexts += append_extension<Backend>(
            output, context, multiplication.source_vectors[0], operation);
        measured.base_ciphertexts += append_extension<Backend>(
            output, context, multiplication.source_vectors[1], operation);
        account_public_extension(multiplication.source_vectors[0], measured);
        account_public_extension(multiplication.source_vectors[1], measured);
        measured.terminal_message_bytes += output.size() - terminal_start;
        measured.extension_ciphertexts += 2U;
    }

    output.push_back(proof.gate_mle_opening.has_value() ? 1U : 0U);
    if (proof.gate_mle_opening) {
        const std::size_t opening_start = output.size();
        const Bytes opening = gates::encode_canonical(*proof.gate_mle_opening);
        wire_detail::append_size(output, opening.size(), operation);
        output.insert(output.end(), opening.begin(), opening.end());
        measured.gate_mle_opening_bytes += output.size() - opening_start;
    }
    measured.total_bytes = output.size();
    const std::size_t logical_component_bytes =
        measured.round_message_bytes + measured.terminal_message_bytes +
        measured.partial_gate_mle_bytes + measured.gate_mle_opening_bytes;
    if (logical_component_bytes > measured.total_bytes) {
        throw std::logic_error(
            "persistent Base proof components exceed transport encoding");
    }
    measured.statement_and_metadata_bytes =
        measured.total_bytes - logical_component_bytes;
    if (breakdown != nullptr) {
        *breakdown = measured;
    }
    return output;
}

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
protocol::LaminateBaseProof<Backend> decode_proof_transport(
    const StorageContext &context, Reader &reader,
    const payload::LayeredCircuit &circuit, const PublicSetup &setup,
    DecodeBudget &budget, const BaseWireDecodeLimits &limits,
    const char *operation) {
    require_label(reader, kBaseProofTransportDomain, operation);
    protocol::LaminateBaseProof<Backend> proof;
    proof.header = read_header(reader, operation);

    const std::size_t expected_reductions = circuit.layers.size() - 1U;
    const std::size_t reduction_count = reader.read_size();
    if (reduction_count != expected_reductions ||
        reduction_count > limits.max_reductions) {
        wire_detail::reject(operation,
                            "unexpected Base reduction count");
    }
    proof.reductions.reserve(reduction_count);
    for (std::size_t layer = 0; layer < reduction_count; ++layer) {
        const payload::LayerKind kind =
            payload::layer_kind(circuit.layers[layer]);
        const std::uint8_t encoded_kind = reader.read_u8();
        const std::size_t source_wire_variables =
            gkr::base_detail::ciphertext_index_variables(
                circuit, layer + 1U);
        const std::size_t expected_rounds =
            kind == payload::LayerKind::Affine
                ? source_wire_variables
                : gkr::base_detail::ciphertext_index_variables(
                      circuit, layer);
        const std::size_t round_count = reader.read_size();
        if (round_count != expected_rounds ||
            round_count > limits.max_rounds_per_reduction) {
            wire_detail::reject(operation,
                                "unexpected Base round count");
        }

        if (kind == payload::LayerKind::Affine) {
            if (encoded_kind != 0) {
                wire_detail::reject(operation,
                                    "wrong Base reduction kind");
            }
            gkr::EncryptedBaseAffineLayerReduction<Backend> reduction;
            reduction.rounds.reserve(round_count);
            for (std::size_t round = 0; round < round_count; ++round) {
                reduction.rounds.push_back(
                    gkr::EncryptedBaseLayerReductionSumcheckRound<Backend>{
                        {read_extension<Backend>(reader, context, budget,
                                                 operation),
                         read_extension<Backend>(reader, context, budget,
                                                 operation)}});
            }
            reduction.source_vector = read_extension<Backend>(
                reader, context, budget, operation);
            reduction.partial_gate_mle = read_partial_gate_mle(
                reader, circuit.shape.value_width(), budget, limits,
                operation);
            proof.reductions.emplace_back(std::move(reduction));
            continue;
        }

        if (encoded_kind != 1) {
            wire_detail::reject(operation, "wrong Base reduction kind");
        }
        gkr::EncryptedBaseMultiplicationLayerReduction<Backend> reduction;
        reduction.rounds.reserve(round_count);
        for (std::size_t round = 0; round < round_count; ++round) {
            reduction.rounds.push_back(
                gkr::EncryptedBaseLayerReductionSumcheckRound<Backend>{
                    {read_extension<Backend>(reader, context, budget,
                                             operation),
                     read_extension<Backend>(reader, context, budget,
                                             operation)}});
        }
        reduction.source_vectors[0] = read_extension<Backend>(
            reader, context, budget, operation);
        reduction.source_vectors[1] = read_extension<Backend>(
            reader, context, budget, operation);
        proof.reductions.emplace_back(std::move(reduction));
    }

    const std::uint8_t has_opening = reader.read_u8();
    if (has_opening > 1) {
        wire_detail::reject(operation,
                            "noncanonical GateMLE-opening flag");
    }
    const bool expected_opening =
        setup.gate_mle_profile == GateMleProfile::OutsourcedBaseFold;
    if ((has_opening != 0) != expected_opening) {
        wire_detail::reject(operation,
                            "GateMLE-opening presence disagrees with setup");
    }
    if (has_opening != 0) {
        if (!setup.outsourced_gate_mle) {
            wire_detail::reject(operation,
                                "setup omits outsourced GateMLE key");
        }
        proof.gate_mle_opening = read_outsourced_gate_proof(
            reader, *setup.outsourced_gate_mle, budget, limits, operation);
    }
    return proof;
}

} // namespace laminate::delegation::base_wire_detail

#endif // LAMINATE_DELEGATION_BASE_WIRE_DETAIL_PROOF_TRANSPORT_HPP
