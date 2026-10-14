/// @file proof.cpp
/// @brief Canonical logical proof encoding and plaintext GKR orchestration.

#include "laminate/gkr/proof.hpp"
#include "laminate/verification_profile.hpp"

#include "laminate/field/serialization.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace laminate::gkr {
namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::string_view kHeaderDomain =
    "LaminateImpl/LogicalProofHeader/v1";
constexpr std::string_view kProofDomain =
    "LaminateImpl/DecryptedGkrProof/v1";
constexpr std::string_view kHeaderTranscriptLabel =
    "laminate/gkr/proof-header/v1";

void append_u8(Bytes &output, std::uint8_t value) { output.push_back(value); }

void append_u64(Bytes &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

void append_size(Bytes &output, std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("logical proof: size does not fit u64");
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

void append_label(Bytes &output, std::string_view label) {
    append_size(output, label.size());
    output.insert(output.end(), label.begin(), label.end());
}

void append_fpk(Bytes &output, const Fpk &value) {
    const SerializedFpk encoded = serialize(value);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

void append_claim(Bytes &output, const SingleClaim &claim) {
    append_size(output, claim.point.size());
    for (const Fpk &coordinate : claim.point) {
        append_fpk(output, coordinate);
    }
    append_fpk(output, claim.value);
}

void append_header_body(Bytes &output, const ProofHeader &header) {
    append_u64(output, header.version);
    append_u8(output, static_cast<std::uint8_t>(header.profile.variant));
    append_u8(output, static_cast<std::uint8_t>(header.profile.gate_mle));
    append_u8(output,
              static_cast<std::uint8_t>(header.profile.cross_round_packing));
    append_u8(output, static_cast<std::uint8_t>(header.provenance));
    output.insert(output.end(), header.circuit_id.begin(),
                  header.circuit_id.end());
    output.insert(output.end(), header.setup_id.begin(), header.setup_id.end());
    output.insert(output.end(), header.trace_id.begin(), header.trace_id.end());
    append_size(output, header.layer_count);
}

void append_sumcheck(Bytes &output, const LayerReductionSumcheckProof &sumcheck) {
    append_size(output, sumcheck.rounds.size());
    for (const LayerReductionSumcheckRound &round : sumcheck.rounds) {
        append_fpk(output, round.at_endpoint);
        append_fpk(output, round.at_two);
    }
}

std::size_t num_vars(const payload::LayeredCircuit &circuit,
                     std::size_t layer_index) {
    const std::size_t wires =
        payload::layer_dimensions(circuit.layers.at(layer_index)).padded_size;
    const std::size_t width = circuit.shape.value_width();
    return (std::bit_width(wires) - 1U) +
           (std::bit_width(width) - 1U);
}

std::size_t wire_num_vars(const payload::LayeredCircuit &circuit,
                          std::size_t layer_index) {
    const std::size_t wires =
        payload::layer_dimensions(circuit.layers.at(layer_index)).padded_size;
    return std::bit_width(wires) - 1U;
}

std::size_t slot_num_vars(const payload::LayeredCircuit &circuit) {
    return std::bit_width(circuit.shape.value_width()) - 1U;
}

bool expected_round_count(const DecryptedLayerReductionProof &proof,
                          payload::LayerKind kind,
                          std::size_t source_wire_vars,
                          std::size_t source_slot_vars) {
    if (kind == payload::LayerKind::Affine) {
        const auto *affine = std::get_if<AffineLayerReductionProof>(&proof);
        return affine != nullptr &&
               affine->sumcheck.rounds.size() ==
                   source_wire_vars + source_slot_vars;
    }
    if (kind != payload::LayerKind::Multiplication ||
        source_wire_vars == 0 ||
        source_wire_vars - 1U >
            std::numeric_limits<std::size_t>::max() - source_slot_vars) {
        return false;
    }
    const auto *multiplication =
        std::get_if<MultiplicationLayerReductionProof>(&proof);
    return multiplication != nullptr &&
           multiplication->sumcheck.rounds.size() ==
               source_wire_vars - 1U + source_slot_vars;
}

} // namespace

void validate_profile(const ProtocolProfile &profile,
                      const PublicSetup &setup,
                      const payload::LayeredCircuit &circuit) {
    if (profile.gate_mle != setup.gate_mle_profile ||
        profile.cross_round_packing != CrossRoundPacking::None) {
        throw std::invalid_argument(
            "ProtocolProfile: setup or packing profile mismatch");
    }
    switch (profile.variant) {
    case ProtocolVariant::LaminateBase:
    case ProtocolVariant::LaminateFolded:
        if (circuit.shape.kind != payload::PayloadKind::Wide) {
            throw std::invalid_argument(
                "ProtocolProfile: Base/Folded require a wide circuit");
        }
        return;
    case ProtocolVariant::LaminateLaned:
        if (circuit.shape.kind != payload::PayloadKind::Laned) {
            throw std::invalid_argument(
                "ProtocolProfile: Laned requires a laned circuit");
        }
        return;
    }
    throw std::invalid_argument("ProtocolProfile: unknown protocol variant");
}

std::vector<std::uint8_t> encode_canonical(const ProofHeader &header) {
    Bytes output;
    append_label(output, kHeaderDomain);
    append_header_body(output, header);
    return output;
}

std::vector<std::uint8_t>
encode_canonical(const DecryptedGkrProof &proof) {
    Bytes output;
    append_label(output, kProofDomain);
    const Bytes header = encode_canonical(proof.header);
    append_size(output, header.size());
    output.insert(output.end(), header.begin(), header.end());
    append_claim(output, proof.output_claim);
    append_size(output, proof.reductions.size());
    for (const DecryptedLayerReductionProof &reduction : proof.reductions) {
        if (const auto *affine =
                std::get_if<AffineLayerReductionProof>(&reduction)) {
            append_u8(output, 0);
            append_sumcheck(output, affine->sumcheck);
            append_fpk(output, affine->source_value);
        } else {
            const auto &multiplication =
                std::get<MultiplicationLayerReductionProof>(reduction);
            append_u8(output, 1);
            append_sumcheck(output, multiplication.sumcheck);
            append_fpk(output, multiplication.left_value);
            append_fpk(output, multiplication.right_value);
        }
    }
    return output;
}

void observe_proof_header(const ProofHeader &header, Transcript &transcript) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    const Bytes encoded = encode_canonical(header);
    transcript.observe(kHeaderTranscriptLabel, encoded);
}

bool validate_proof_structure(const DecryptedGkrProof &proof,
                              const ProtocolProfile &expected_profile,
                              payload::TraceProvenance expected_provenance,
                              const Digest &expected_trace_id,
                              const PublicSetup &setup,
                              const payload::LayeredCircuit &circuit) {
    try {
        validate_profile(expected_profile, setup, circuit);
        if (circuit.layers.empty() ||
            proof.header.version != kLogicalProofVersion ||
            proof.header.profile != expected_profile ||
            proof.header.provenance != expected_provenance ||
            proof.header.circuit_id != setup.circuit_digest ||
            proof.header.setup_id != setup_digest(setup) ||
            proof.header.trace_id != expected_trace_id ||
            proof.header.layer_count != circuit.layers.size() ||
            proof.output_claim.point.size() != num_vars(circuit, 0) ||
            proof.reductions.size() != circuit.layers.size() - 1) {
            return false;
        }
        for (std::size_t layer = 0; layer < proof.reductions.size(); ++layer) {
            if (!expected_round_count(
                    proof.reductions[layer],
                    payload::layer_kind(circuit.layers[layer]),
                    wire_num_vars(circuit, layer + 1),
                    slot_num_vars(circuit))) {
                return false;
            }
        }
        return true;
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    } catch (const std::overflow_error &) {
        return false;
    }
}

DecryptedGkrProof prove_plaintext_gkr(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::PlainTrace &trace, const PublicSetup &setup,
    const ProtocolProfile &profile, std::vector<Fpk> output_point,
    Transcript &transcript) {
    setup.validate(payload, circuit);
    payload::validate_trace(payload, circuit, trace);
    validate_profile(profile, setup, circuit);

    DecryptedGkrProof proof;
    proof.header = ProofHeader{kLogicalProofVersion,
                               profile,
                               trace.provenance,
                               setup.circuit_digest,
                               setup_digest(setup),
                               payload::digest(trace, setup.circuit_digest),
                               circuit.layers.size()};
    proof.output_claim =
        make_layer_claim(trace.layers.front(), std::move(output_point));
    proof.reductions.reserve(circuit.layers.size() - 1);

    observe_proof_header(proof.header, transcript);
    gates::observe_gate_mle_setup(setup, transcript);
    observe_claim(proof.output_claim, transcript);
    const gates::DirectGateMle gate_mles(circuit);
    LayerClaim current = proof.output_claim;

    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        if (payload::layer_kind(circuit.layers[layer]) ==
            payload::LayerKind::Affine) {
            ProvedAffineLayerReduction reduction = prove_affine_layer_reduction(
                circuit, trace, layer, current, gate_mles, transcript);
            current = reduction.next_claim;
            proof.reductions.emplace_back(std::move(reduction.proof));
        } else {
            const auto *single = std::get_if<SingleClaim>(&current);
            if (single == nullptr) {
                throw std::logic_error(
                    "prove_plaintext_gkr: multiplication received a batch");
            }
            ProvedMultiplicationLayerReduction reduction =
                prove_multiplication_layer_reduction(circuit, trace, layer, *single,
                                               transcript);
            current = reduction.next_claim;
            proof.reductions.emplace_back(std::move(reduction.proof));
        }
    }
    if (!verify_terminal_claim(trace.layers.back(), current)) {
        throw std::logic_error(
            "prove_plaintext_gkr: terminal input claim failed");
    }
    return proof;
}

bool verify_plaintext_gkr(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> input_layer, const PublicSetup &setup,
    const ProtocolProfile &expected_profile,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id, const SingleClaim &expected_output_claim,
    const DecryptedGkrProof &proof, Transcript &transcript) {
    try {
        setup.validate(payload, circuit);
        if (!validate_proof_structure(proof, expected_profile,
                                      expected_provenance, expected_trace_id,
                                      setup, circuit) ||
            proof.output_claim != expected_output_claim) {
            return false;
        }
        observe_proof_header(proof.header, transcript);
        gates::observe_gate_mle_setup(setup, transcript);
        observe_claim(proof.output_claim, transcript);
        const gates::DirectGateMle gate_mles(circuit);
        LayerClaim current = proof.output_claim;

        for (std::size_t layer = 0; layer < proof.reductions.size(); ++layer) {
            if (payload::layer_kind(circuit.layers[layer]) ==
                payload::LayerKind::Affine) {
                const auto &reduction =
                    std::get<AffineLayerReductionProof>(proof.reductions[layer]);
                const std::optional<SingleClaim> next =
                    verify_affine_layer_reduction(circuit, layer, current, reduction,
                                            gate_mles, transcript);
                if (!next) {
                    return false;
                }
                current = *next;
            } else {
                const auto *single = std::get_if<SingleClaim>(&current);
                if (single == nullptr) {
                    return false;
                }
                const auto &reduction = std::get<MultiplicationLayerReductionProof>(
                    proof.reductions[layer]);
                const std::optional<SingleClaim> next =
                    verify_multiplication_layer_reduction(
                        circuit, layer, *single, reduction, transcript);
                if (!next) {
                    return false;
                }
                current = *next;
            }
        }
        return verify_terminal_claim(input_layer, current);
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    } catch (const std::bad_variant_access &) {
        return false;
    } catch (const std::overflow_error &) {
        return false;
    }
}

} // namespace laminate::gkr
