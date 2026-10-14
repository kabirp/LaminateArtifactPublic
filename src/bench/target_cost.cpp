/// @file target_cost.cpp
/// @brief RNS-aware expansion of the executable Laminate prover schedules.

#include "laminate/bench/target_cost.hpp"
#include "laminate/basefold/common.hpp"

#include "laminate/delegation/base/wire/format.hpp"

#include "laminate/field/serialization.hpp"
#include "laminate/gates/canonical_tables.hpp"
#include "laminate/gates/outsourced.hpp"
#include "laminate/gates/wide_opening.hpp"
#include "laminate/packing/outer_relation/tensor.hpp"
#include "laminate/packing/proof/r1cs.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"
#include "laminate/spartan/basefold_pcs.hpp"
#include "laminate/spartan/factored.hpp"
#include "laminate/spartan/sumcheck.hpp"

#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/ciphertext_commitment.hpp"
#include "laminate/params.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace laminate::bench {
namespace {

using Count = std::uint64_t;

Count as_count(std::size_t value, const char *name) {
    if (value > std::numeric_limits<Count>::max()) {
        throw std::overflow_error(std::string(name) + " does not fit u64");
    }
    return static_cast<Count>(value);
}

Count checked_add(Count left, Count right, const char *name) {
    if (right > std::numeric_limits<Count>::max() - left) {
        throw std::overflow_error(std::string(name) + " overflows");
    }
    return left + right;
}

Count checked_mul(Count left, Count right, const char *name) {
    if (left != 0 && right > std::numeric_limits<Count>::max() / left) {
        throw std::overflow_error(std::string(name) + " overflows");
    }
    return left * right;
}

void add(Count &destination, Count value, const char *name) {
    destination = checked_add(destination, value, name);
}

void add_primitives(ConcretePrimitiveUpperBound &destination,
                    const ConcretePrimitiveUpperBound &source) {
#define LAMINATE_ADD(field)                                                     \
    add(destination.field, source.field, "level operation " #field)
    LAMINATE_ADD(plain_multiplications);
    LAMINATE_ADD(online_vector_plain_multiplications);
    LAMINATE_ADD(online_vector_plaintext_preparations);
    LAMINATE_ADD(ciphertext_multiplications_no_relinearization);
    LAMINATE_ADD(relinearizations);
    LAMINATE_ADD(negations);
    LAMINATE_ADD(additions);
    LAMINATE_ADD(subtractions);
    LAMINATE_ADD(rotations);
#undef LAMINATE_ADD
}

RnsLevelOperations &level(ProverOperationLedger &ledger,
                          std::size_t rns_limbs) {
    auto found = std::find_if(
        ledger.levels.begin(), ledger.levels.end(),
        [&](const RnsLevelOperations &candidate) {
            return candidate.rns_limbs == rns_limbs;
        });
    if (found != ledger.levels.end()) {
        return *found;
    }
    ledger.levels.push_back(RnsLevelOperations{.rns_limbs = rns_limbs});
    std::sort(ledger.levels.begin(), ledger.levels.end(),
              [](const auto &left, const auto &right) {
                  return left.rns_limbs > right.rns_limbs;
              });
    return *std::find_if(
        ledger.levels.begin(), ledger.levels.end(),
        [&](const RnsLevelOperations &candidate) {
            return candidate.rns_limbs == rns_limbs;
        });
}

void add_switch_staircase(ProverOperationLedger &ledger,
                          std::size_t ciphertexts,
                          std::size_t start_limbs) {
    const Count count = as_count(ciphertexts, "modulus-switch ciphertexts");
    for (std::size_t limbs = start_limbs; limbs > 1; --limbs) {
        add(level(ledger, limbs).modulus_switches, count,
            "modulus switches");
    }
}

enum class BaseSwitchKind { ProofIngress, ProofMessage };

void add_base_switch_staircase(ProverOperationLedger &ledger,
                               std::size_t ciphertexts,
                               std::size_t start_limbs,
                               std::size_t end_limbs,
                               BaseSwitchKind kind) {
    if (end_limbs == 0 || end_limbs > start_limbs) {
        throw std::invalid_argument(
            "invalid Base modulus-switch staircase");
    }
    const Count count = as_count(ciphertexts, "Base switch ciphertexts");
    for (std::size_t limbs = start_limbs; limbs > end_limbs; --limbs) {
        RnsLevelOperations &row = level(ledger, limbs);
        add(row.modulus_switches, count, "Base modulus switches");
        if (kind == BaseSwitchKind::ProofIngress) {
            add(row.base_proof_ingress_switches, count,
                "Base proof-ingress switches");
        } else {
            add(row.base_proof_message_switches, count,
                "Base proof-message switches");
        }
    }
}

void add_transcript_packing_primitives(ProverOperationLedger &ledger) {
    if (ledger.aligned_ciphertexts == 0 ||
        ledger.logical_packed_outputs == 0 ||
        ledger.logical_packed_outputs > ledger.aligned_ciphertexts ||
        ledger.aligned_ciphertexts >
            std::numeric_limits<std::size_t>::max() /
                fhe::kFixedMessageCellCount ||
        ledger.paper_raw_ciphertext_footprint !=
            ledger.aligned_ciphertexts * fhe::kFixedMessageCellCount ||
        ledger.well_formedness_repetitions == 0 ||
        ledger.signed_digits_per_output == 0) {
        throw std::invalid_argument(
            "transcript-packing ledger metadata is incomplete");
    }

    const Count aligned = as_count(ledger.aligned_ciphertexts,
                                   "aligned ciphertexts");
    const Count outputs = as_count(ledger.logical_packed_outputs,
                                   "packed outputs");
    const Count tests = as_count(ledger.well_formedness_repetitions,
                                 "well-formedness repetitions");
    const Count digits = as_count(ledger.signed_digits_per_output,
                                  "packing digits");
    ConcretePrimitiveUpperBound &bottom = level(ledger, 1).primitives;

    // One-prime transcript packing contributes
    //
    //   PT-CT = D*r,  Add = D*(r-L) + T*(r-1),  Neg = T.
    add(bottom.plain_multiplications,
        checked_mul(aligned, digits, "digit plaintext products"),
        "digit plaintext products");
    add(bottom.additions,
        checked_mul(aligned - outputs, digits, "digit additions"),
        "digit additions");
    add(bottom.additions,
        checked_mul(aligned - 1, tests,
                    "well-formedness linear-combination additions"),
        "well-formedness linear-combination additions");
    add(bottom.negations, tests, "well-formedness first-term negations");
}

std::size_t layer_message_count(const ScheduleLayerFormula &layer_formula) {
    return static_cast<std::size_t>(
        layer_formula.operations.aligned_round_ciphertexts);
}

ScheduleOperations laned_witness_packing(
    const ScheduleOperations &operations) {
    ScheduleOperations result;
    result.witness_base_plain_multiplications =
        operations.witness_base_plain_multiplications;
    result.witness_base_additions = operations.witness_base_additions;
    return result;
}

ScheduleOperations without_laned_witness_packing(
    ScheduleOperations operations) {
    operations.witness_base_plain_multiplications = 0;
    operations.witness_base_additions = 0;
    return operations;
}

void add_layer_primitives(ProverOperationLedger &ledger,
                          const ScheduleOperations &operations,
                          std::size_t slot_count,
                          std::size_t rns_limbs) {
    add_primitives(level(ledger, rns_limbs).primitives,
                   concrete_primitive_upper_bound(operations, slot_count));
}

/// Laned witness packing consumes one noise level when B<N. SEAL keeps the
/// trace at L limbs while applying its masks, then prepares the packed source
/// at L-1 limbs. Consequently the multiplication reduction and its aligned
/// BhIP-round ciphertexts run one limb below affine reductions. This matters
/// for the paper model's linear-in-limb pricing.
void add_laned_layer(ProverOperationLedger &ledger,
                     const ScheduleLayerFormula &layer_formula,
                     std::size_t slot_count,
                     std::size_t core_rns_limbs) {
    const bool packing_consumes_level =
        layer_formula.kind == payload::LayerKind::Multiplication &&
        layer_formula.operations.witness_base_plain_multiplications != 0;
    const std::size_t messages = layer_message_count(layer_formula);
    if (!packing_consumes_level) {
        add_layer_primitives(ledger, layer_formula.operations, slot_count,
                             core_rns_limbs);
        add_switch_staircase(ledger, messages, core_rns_limbs);
        return;
    }
    if (core_rns_limbs < 4) {
        throw std::invalid_argument(
            "Laned witness packing needs a working limb above the "
            "three-limb transcript-alignment boundary");
    }

    add_layer_primitives(
        ledger, laned_witness_packing(layer_formula.operations), slot_count,
        core_rns_limbs);
    add_layer_primitives(
        ledger, without_laned_witness_packing(layer_formula.operations),
        slot_count, core_rns_limbs - 1);

    // One successful preparation switch per materialized packed source. Public
    // zero positions in the packed protocol domain never receive ciphertexts.
    // Failed speculative candidates are intentionally outside this portable
    // ledger. Public-zero values have no ciphertext or switch cost.
    add(level(ledger, core_rns_limbs).modulus_switches,
        as_count(layer_formula.source_materialized_packed_ciphertexts,
                 "Laned materialized packed source ciphertexts"),
        "Laned witness-packing switches");
    add_switch_staircase(ledger, messages, core_rns_limbs - 1);
}

std::size_t base_layer_extension_ciphertexts(
    const ScheduleLayerFormula &layer_formula) {
    const std::size_t terminal_extensions =
        layer_formula.kind == payload::LayerKind::Affine ? 1U : 2U;
    if (layer_formula.operations.logical_rounds >
        (std::numeric_limits<std::size_t>::max() - terminal_extensions) / 2U) {
        throw std::overflow_error(
            "Base extension-ciphertext count overflows");
    }
    return 2U * static_cast<std::size_t>(
                    layer_formula.operations.logical_rounds) +
           terminal_extensions;
}

/// Formula-only projection used when no exact normalization plan is
/// available. It deliberately treats every logical extension coordinate as
/// encrypted, so it is a dense upper bound rather than execution parity.
std::size_t base_layer_dense_ciphertext_upper_bound(
    const ScheduleLayerFormula &layer_formula) {
    const std::size_t extensions =
        base_layer_extension_ciphertexts(layer_formula);
    if (extensions >
        std::numeric_limits<std::size_t>::max() / kExtensionDegree) {
        throw std::overflow_error("Base proof ciphertext count overflows");
    }
    return extensions * kExtensionDegree;
}

std::size_t base_extension_ciphertexts(const ScheduleFormula &formula) {
    std::size_t result = 0;
    for (const ScheduleLayerFormula &layer : formula.layers) {
        const std::size_t extensions =
            base_layer_extension_ciphertexts(layer);
        if (extensions > std::numeric_limits<std::size_t>::max() - result) {
            throw std::overflow_error(
                "Base extension-ciphertext count overflows");
        }
        result += extensions;
    }
    return result;
}

std::size_t packed_output_count(std::size_t aligned_ciphertexts,
                                std::size_t slot_count) {
    if (slot_count < 2 * fhe::kFixedMessageCellCount ||
        !std::has_single_bit(slot_count)) {
        throw std::invalid_argument(
            "packed operation ledger requires power-of-two N >= 32");
    }
    const std::size_t capacity = slot_count / fhe::kFixedMessageCellCount;
    return aligned_ciphertexts / capacity +
           (aligned_ciphertexts % capacity == 0 ? 0 : 1);
}

std::vector<std::size_t> packed_output_owner_counts(
    std::size_t aligned_ciphertexts, std::size_t slot_count,
    std::size_t expected_outputs) {
    const std::size_t capacity = slot_count / fhe::kFixedMessageCellCount;
    if (capacity == 0 ||
        packed_output_count(aligned_ciphertexts, slot_count) !=
            expected_outputs) {
        throw std::invalid_argument(
            "packed owner counts disagree with the operation ledger");
    }
    std::vector<std::size_t> result;
    result.reserve(expected_outputs);
    for (std::size_t first = 0; first < aligned_ciphertexts;
         first += capacity) {
        result.push_back(std::min(capacity, aligned_ciphertexts - first));
    }
    return result;
}

Count basefold_merkle_payload_bytes(Count codeword_size) {
    if (codeword_size == 0 || !std::has_single_bit(codeword_size)) {
        throw std::invalid_argument(
            "BaseFold Merkle codeword size is not a power of two");
    }
    constexpr Count kLeafElements = 64;
    const Count leaf_size = std::min(codeword_size, kLeafElements);
    const Count leaves = codeword_size / leaf_size;
    const Count nodes = checked_add(leaves, leaves - 1,
                                    "BaseFold Merkle nodes");
    return checked_mul(nodes, Count{spartan::PcsDigest{}.size()},
                       "BaseFold Merkle bytes");
}

Count basefold_query_merkle_hashes(Count message_size,
                                   spartan::BaseFoldPcsParameters parameters) {
    if (message_size == 0 || !std::has_single_bit(message_size) ||
        message_size > std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(
            "BaseFold query geometry is invalid");
    }
    return spartan::basefold_opening_max_merkle_hashes(
        std::bit_width(message_size) - 1U, parameters);
}

std::size_t primitive_alignment_rotations(
    std::size_t aligned_ciphertexts, std::size_t slot_count) {
    const std::size_t capacity = slot_count / fhe::kFixedMessageCellCount;
    const std::size_t per_row = capacity / 2;
    std::size_t total = 0;
    for (std::size_t first = 0; first < aligned_ciphertexts;
         first += capacity) {
        const std::size_t group =
            std::min(capacity, aligned_ciphertexts - first);
        if (group <= per_row) {
            total += group - 1;
        } else {
            // Positions 1..per_row-1 use a row rotation, position per_row
            // uses only the column swap, and later positions use both.
            total += per_row + 2 * (group - per_row - 1);
        }
    }
    return total;
}

Count proof_header_bytes() {
    // Length-prefixed domain, version, tags, three digests, and layer count.
    return 8 + 34 + 8 + 4 + 3 * Digest{}.size() + 8;
}

Count base_metadata_bytes(const ScheduleFormula &formula) {
    const Count layers = as_count(formula.layers.size(), "Base layers");
    Count result = 5; // LMBP + version.
    add(result, 8 + proof_header_bytes(), "Base header");
    add(result, 8, "Base reduction count");
    add(result, checked_mul(layers, Count{9}, "Base layer framing"),
        "Base layer framing");
    add(result, 1, "Base opening flag");
    return result;
}

Count persistent_base_metadata_bytes(
    const ScheduleFormula &formula) {
    // Replace the five-byte LMBP/version prefix with the persistent
    // transport's length-prefixed domain label. Every later field has the
    // same width and order in the two encodings.
    return base_metadata_bytes(formula) - 5U + 8U +
           delegation::base_wire_detail::kBaseProofTransportDomain.size();
}

Count persistent_base_response_envelope_bytes(
    Count output_statement_bytes) {
    constexpr Count bindings = 4U * Digest{}.size();
    constexpr Count proof_length_prefix = sizeof(std::uint64_t);
    return checked_add(
        delegation::kBaseDelegationWireHeaderBytes,
        checked_add(bindings,
                    checked_add(output_statement_bytes,
                                proof_length_prefix,
                                "Base response output and proof prefix"),
                    "Base response payload"),
        "Base response envelope");
}

Count persistent_base_response_output_fhe_value_bytes(
    const payload::LayeredCircuit &circuit, Count ciphertext_bytes) {
    const Count output_values = as_count(
        payload::layer_dimensions(circuit.layers.front()).logical_size,
        "Base output values");
    // append_fhe_values writes the storage-context digest, a u64 vector
    // length, then a self-delimiting encrypted value. A ciphertext value is
    // one tag byte, one u64 payload length, and the persistent ciphertext.
    constexpr Count collection_framing = Digest{}.size() +
                                         sizeof(std::uint64_t);
    constexpr Count ciphertext_value_framing =
        1U + sizeof(std::uint64_t);
    return checked_add(
        collection_framing,
        checked_mul(output_values,
                    checked_add(ciphertext_value_framing, ciphertext_bytes,
                                "Base response output value"),
                    "Base response output values"),
        "Base response output FHE values");
}

Count base_partial_gate_mle_vectors(
    const payload::LayeredCircuit &circuit) {
    Count result = 0;
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        if (payload::layer_kind(circuit.layers[layer]) ==
            payload::LayerKind::Affine) {
            add(result, Count{1}, "Base affine partial GateMLE vectors");
        }
    }
    return result;
}

Count public_message_wire_overhead(const payload::LayeredCircuit &circuit,
                                   const ProverOperationLedger &ledger) {
    // Fixed-message packing places at most sixteen extension coefficients.
    // Reserve the larger of a digest and a sparse public message for every
    // aligned message, including exceptional ciphertext cancellations.
    const auto sparse_bytes = checked_add(
        gkr::kCommittedPublicSparseHeaderBytes,
        checked_mul(fhe::kFixedMessageCellCount,
                    gkr::kCommittedPublicSparseEntryBytes,
                    "public packed sparse entries"),
        "public packed sparse message bytes");
    const auto dense_bytes = checked_add(Count{10}, checked_mul(
        circuit.shape.slot_count, sizeof(std::uint64_t), "public packed slots"),
        "public packed dense message bytes");
    const auto public_bytes = std::min(sparse_bytes, dense_bytes);
    const auto encrypted_bytes = Count{1 + PoseidonDigest{}.size()};
    return checked_mul(ledger.aligned_ciphertexts,
        public_bytes > encrypted_bytes ? public_bytes - encrypted_bytes : 0,
        "public packed message overhead");
}

Count committed_gkr_bytes(const payload::LayeredCircuit &circuit,
                          const ProverOperationLedger &ledger,
                          Count public_overhead) {
    const Count layers = as_count(circuit.layers.size() - 1,
                                  "committed GKR layers");
    const Count commitments = as_count(ledger.aligned_ciphertexts,
                                       "GKR commitments");
    Count result = 17; // LM/COMMITTED/{F,L}/v3.
    add(result, 8 + proof_header_bytes(), "committed GKR header");
    add(result, 8, "committed GKR reduction count");
    add(result, checked_mul(layers, Count{9}, "committed layer framing"),
        "committed layer framing");
    add(result,
        checked_mul(commitments, Count{1 + PoseidonDigest{}.size()},
                    "tagged GKR commitments"),
        "GKR commitments");
    add(result, 1, "committed opening flag");
    add(result, public_overhead, "committed public messages");
    return result;
}

ProverOperationLedger base_formula_operation_ledger(
    const ScheduleFormula &formula, std::size_t slot_count,
    std::size_t core_rns_limbs,
    const payload::LayeredCircuit *circuit) {
    if (formula.protocol != ScheduleProtocol::Base || core_rns_limbs == 0 ||
        (circuit != nullptr &&
         (circuit->shape.slot_count != slot_count ||
          formula.layers.size() + 1U != circuit->layers.size()))) {
        throw std::invalid_argument("invalid Base operation-ledger input");
    }

    ProverOperationLedger result;
    result.protocol = ScheduleProtocol::Base;
    result.core_rns_limbs = core_rns_limbs;
    result.base_reductions.reserve(formula.layers.size());
    for (const ScheduleLayerFormula &layer_formula : formula.layers) {
        add_layer_primitives(result, layer_formula.operations, slot_count,
                             core_rns_limbs);

        const std::size_t extensions =
            base_layer_extension_ciphertexts(layer_formula);
        std::size_t public_zero_extensions = 0;
        std::size_t messages =
            base_layer_dense_ciphertext_upper_bound(layer_formula);
        if (circuit != nullptr) {
            const payload::HonestBaseProofMessageTopology topology =
                payload::derive_honest_base_proof_message_topology(
                    *circuit, layer_formula.layer);
            if (topology.round_extension_message_count +
                    topology.terminal_extension_message_count !=
                extensions) {
                throw std::invalid_argument(
                    "Base proof topology disagrees with the formula");
            }
            public_zero_extensions =
                topology.public_zero_extension_message_count;
            messages = topology.base_ciphertext_count;
        }

        const auto add_size = [](std::size_t &destination,
                                 std::size_t value, const char *what) {
            if (value >
                std::numeric_limits<std::size_t>::max() - destination) {
                throw std::overflow_error(what);
            }
            destination += value;
        };
        add_size(result.direct_transcript_extension_messages, extensions,
                 "Base extension-message count overflows");
        add_size(result.direct_transcript_public_zero_extension_messages,
                 public_zero_extensions,
                 "Base public-zero extension-message count overflows");
        add_size(result.direct_transcript_ciphertexts, messages,
                 "Base direct transcript count overflows");

        const Count proof_switches = checked_mul(
            as_count(messages, "Base proof-message ciphertexts"),
            as_count(core_rns_limbs - 1U,
                     "Base proof-message switch depth"),
            "Base proof-message switches");
        add(result.base_proof_message_switch_events, proof_switches,
            "Base proof-message switches");
        result.base_reductions.push_back(BaseReductionRnsOperations{
            .reduction_layer = layer_formula.layer,
            .natural_source_rns_limbs = 0,
            .proof_ingress_rns_limbs = core_rns_limbs,
            .live_source_ciphertexts =
                layer_formula.source_encrypted_ciphertexts,
            .proof_message_ciphertexts = messages,
            .ingress_switch_events = 0,
            .proof_message_switch_events = proof_switches,
        });
        add_base_switch_staircase(
            result, messages, core_rns_limbs, 1,
            BaseSwitchKind::ProofMessage);
    }
    return result;
}

} // namespace

ProverOperationLedger base_operation_ledger(
    const ScheduleFormula &formula, std::size_t slot_count,
    std::size_t core_rns_limbs) {
    return base_formula_operation_ledger(
        formula, slot_count, core_rns_limbs, nullptr);
}

ProverOperationLedger base_operation_ledger(
    const payload::LayeredCircuit &circuit,
    const ScheduleFormula &formula, std::size_t slot_count,
    std::size_t core_rns_limbs) {
    return base_formula_operation_ledger(
        formula, slot_count, core_rns_limbs, &circuit);
}

ProverOperationLedger base_operation_ledger(
    const ScheduleFormula &formula, std::size_t slot_count,
    const payload::HonestBaseProofNormalizationPlan &normalization_plan) {
    if (formula.protocol != ScheduleProtocol::Base ||
        formula.layers.empty() ||
        normalization_plan.reductions.size() != formula.layers.size()) {
        throw std::invalid_argument(
            "invalid schedule-aware Base operation-ledger input");
    }

    ProverOperationLedger result;
    result.protocol = ScheduleProtocol::Base;
    result.base_proof_ingress_normalization_modeled = true;
    result.base_reductions.reserve(formula.layers.size());
    for (std::size_t index = 0; index < formula.layers.size(); ++index) {
        const ScheduleLayerFormula &layer_formula = formula.layers[index];
        const payload::HonestBaseProofNormalizationLayerPlan &plan =
            normalization_plan.reductions[index];
        const std::size_t terminal_extensions =
            layer_formula.kind == payload::LayerKind::Affine ? 1U : 2U;
        const std::size_t round_extensions =
            base_layer_extension_ciphertexts(layer_formula) -
            terminal_extensions;
        const payload::HonestBaseProofMessageTopology topology =
            payload::derive_honest_base_proof_message_topology(plan);
        const std::size_t messages = plan.base_ciphertext_count;
        if (plan.reduction_layer != layer_formula.layer ||
            plan.kind != layer_formula.kind ||
            plan.natural_source_rns_limb_count <
                plan.proof_ingress_rns_limb_count ||
            plan.proof_ingress_rns_limb_count == 0 ||
            plan.live_source_ciphertext_count !=
                layer_formula.source_encrypted_ciphertexts ||
            plan.wire_variables !=
                layer_formula.reduction_domain_variables ||
            plan.round_extension_ciphertext_count != round_extensions ||
            plan.terminal_extension_ciphertext_count !=
                terminal_extensions ||
            plan.public_zero_extension_message_count !=
                topology.public_zero_extension_message_count ||
            plan.base_ciphertext_count != topology.base_ciphertext_count) {
            throw std::invalid_argument(
                "Base normalization plan disagrees with the formula");
        }

        const Count expected_ingress_switches = checked_mul(
            as_count(plan.live_source_ciphertext_count,
                     "Base live source ciphertexts"),
            as_count(plan.natural_source_rns_limb_count -
                         plan.proof_ingress_rns_limb_count,
                     "Base proof-ingress switch depth"),
            "Base proof-ingress switches");
        const Count expected_proof_switches = checked_mul(
            as_count(messages, "Base proof-message ciphertexts"),
            as_count(plan.proof_ingress_rns_limb_count - 1U,
                     "Base proof-message switch depth"),
            "Base proof-message switches");
        if (plan.ingress_switch_events != expected_ingress_switches ||
            plan.proof_message_switch_events != expected_proof_switches ||
            plan.switch_events != checked_add(
                expected_ingress_switches, expected_proof_switches,
                "Base reduction switch events")) {
            throw std::invalid_argument(
                "Base normalization-plan switch count is inconsistent");
        }

        result.core_rns_limbs = std::max(
            result.core_rns_limbs, plan.proof_ingress_rns_limb_count);
        add_layer_primitives(result, layer_formula.operations, slot_count,
                             plan.proof_ingress_rns_limb_count);
        const std::size_t extensions =
            topology.round_extension_message_count +
            topology.terminal_extension_message_count;
        if (extensions > std::numeric_limits<std::size_t>::max() -
                             result.direct_transcript_extension_messages ||
            topology.public_zero_extension_message_count >
                std::numeric_limits<std::size_t>::max() -
                    result
                        .direct_transcript_public_zero_extension_messages ||
            messages > std::numeric_limits<std::size_t>::max() -
                           result.direct_transcript_ciphertexts) {
            throw std::overflow_error(
                "Base direct transcript count overflows");
        }
        result.direct_transcript_extension_messages += extensions;
        result.direct_transcript_public_zero_extension_messages +=
            topology.public_zero_extension_message_count;
        result.direct_transcript_ciphertexts += messages;
        add(result.base_proof_ingress_switch_events,
            expected_ingress_switches, "Base proof-ingress switches");
        add(result.base_proof_message_switch_events,
            expected_proof_switches, "Base proof-message switches");
        result.base_reductions.push_back(BaseReductionRnsOperations{
            .reduction_layer = layer_formula.layer,
            .natural_source_rns_limbs =
                plan.natural_source_rns_limb_count,
            .proof_ingress_rns_limbs =
                plan.proof_ingress_rns_limb_count,
            .live_source_ciphertexts =
                plan.live_source_ciphertext_count,
            .proof_message_ciphertexts = messages,
            .ingress_switch_events = expected_ingress_switches,
            .proof_message_switch_events = expected_proof_switches,
        });
        add_base_switch_staircase(
            result, plan.live_source_ciphertext_count,
            plan.natural_source_rns_limb_count,
            plan.proof_ingress_rns_limb_count,
            BaseSwitchKind::ProofIngress);
        add_base_switch_staircase(
            result, messages, plan.proof_ingress_rns_limb_count, 1,
            BaseSwitchKind::ProofMessage);
    }

    if (result.base_proof_ingress_switch_events !=
            normalization_plan.ingress_switch_events ||
        result.base_proof_message_switch_events !=
            normalization_plan.proof_message_switch_events ||
        checked_add(result.base_proof_ingress_switch_events,
                    result.base_proof_message_switch_events,
                    "Base total normalization switches") !=
            normalization_plan.switch_events) {
        throw std::invalid_argument(
            "Base normalization-plan aggregate is inconsistent");
    }
    return result;
}

ProverOperationLedger packed_operation_ledger(
    const ScheduleFormula &formula, std::size_t slot_count,
    std::size_t core_rns_limbs,
    std::size_t well_formedness_repetitions,
    std::size_t signed_digits_per_output) {
    if ((formula.protocol != ScheduleProtocol::Folded &&
         formula.protocol != ScheduleProtocol::Laned) ||
        core_rns_limbs < 3 || well_formedness_repetitions == 0 ||
        signed_digits_per_output == 0) {
        throw std::invalid_argument("invalid packed operation-ledger input");
    }

    ProverOperationLedger result;
    result.protocol = formula.protocol;
    result.core_rns_limbs = core_rns_limbs;
    result.aligned_ciphertexts = static_cast<std::size_t>(
        formula.operations.aligned_round_ciphertexts);
    if (result.aligned_ciphertexts >
        std::numeric_limits<std::size_t>::max() /
            fhe::kFixedMessageCellCount) {
        throw std::overflow_error(
            "raw packed-transcript ciphertext count overflows");
    }
    result.paper_raw_ciphertext_footprint =
        result.aligned_ciphertexts * fhe::kFixedMessageCellCount;
    result.logical_packed_outputs =
        packed_output_count(result.aligned_ciphertexts, slot_count);
    result.well_formedness_repetitions = well_formedness_repetitions;
    result.signed_digits_per_output = signed_digits_per_output;

    if (formula.protocol == ScheduleProtocol::Folded) {
        add_primitives(level(result, core_rns_limbs).primitives,
                       concrete_primitive_upper_bound(formula.operations,
                                                      slot_count));
        add_switch_staircase(result, result.aligned_ciphertexts,
                             core_rns_limbs);
    } else {
        for (const ScheduleLayerFormula &layer_formula : formula.layers) {
            add_laned_layer(result, layer_formula, slot_count,
                            core_rns_limbs);
        }
    }

    // compact_for_transport normally reaches three limbs, but its public
    // noise guard may retain a noisier message at a higher level. Charge all
    // alignment rotations at the highest possible working level. The count
    // is exact and the limb placement is a clean runtime upper bound.
    add(level(result, core_rns_limbs).primitives.rotations,
        as_count(primitive_alignment_rotations(
                     result.aligned_ciphertexts, slot_count),
                 "alignment rotations"),
        "alignment rotations");

    add_transcript_packing_primitives(result);
    return result;
}

TargetRuntimeEstimate estimate_target_runtime(
    const ProverOperationLedger &ledger,
    const TargetRuntimeCalibration &calibration) {
    for (const double value : {calibration.ntt_ready_plain_ms,
                              calibration.online_plain_preparation_ms,
                              calibration.ciphertext_product_ms,
                              calibration.additive_ms,
                              calibration.key_switch_ms}) {
        if (!std::isfinite(value) || value < 0) {
            throw std::invalid_argument("primitive timings must be finite and nonnegative");
        }
    }
    const long double kNttReadyPlainMs =
        calibration.ntt_ready_plain_ms;
    const long double kOnlinePreparationMs =
        calibration.online_plain_preparation_ms;
    const long double kCiphertextProductMs =
        calibration.ciphertext_product_ms;
    const long double kAddMs =
        calibration.additive_ms;
    const long double kKeySwitchMs =
        calibration.key_switch_ms;
    constexpr long double kMillisecondsPerHour = 3'600'000.0L;

    long double all_ntt_ready_ms = 0;
    long double preprocessing_aware_ms = 0;
    long double switch_proxy_ms = 0;
    for (const RnsLevelOperations &row : ledger.levels) {
        const auto &operations = row.primitives;
        if (operations.online_vector_plain_multiplications >
                operations.plain_multiplications ||
            operations.online_vector_plaintext_preparations >
                operations.online_vector_plain_multiplications) {
            throw std::invalid_argument(
                "target-cost ledger has an invalid online-plaintext subset");
        }
        const long double limbs = static_cast<long double>(row.rns_limbs);
        const long double additive = static_cast<long double>(
            operations.negations + operations.additions +
            operations.subtractions);
        const long double common =
            static_cast<long double>(
                operations.ciphertext_multiplications_no_relinearization) *
                kCiphertextProductMs +
            additive * kAddMs +
            static_cast<long double>(operations.relinearizations +
                                     operations.rotations) *
                kKeySwitchMs;
        const long double ntt_plain =
            static_cast<long double>(operations.plain_multiplications) *
            kNttReadyPlainMs;
        const long double online_preparation =
            static_cast<long double>(
                operations.online_vector_plaintext_preparations) *
            kOnlinePreparationMs;
        all_ntt_ready_ms += limbs * (common + ntt_plain);
        preprocessing_aware_ms +=
            limbs * (common + ntt_plain + online_preparation);
        switch_proxy_ms +=
            limbs * static_cast<long double>(row.modulus_switches) *
            kKeySwitchMs;
    }
    return TargetRuntimeEstimate{
        .all_plain_ntt_ready_hours =
            static_cast<double>(all_ntt_ready_ms / kMillisecondsPerHour),
        .preprocessing_aware_hours = static_cast<double>(
            preprocessing_aware_ms / kMillisecondsPerHour),
        .all_plain_ntt_ready_with_modswitch_proxy_hours =
            static_cast<double>((all_ntt_ready_ms + switch_proxy_ms) /
                                kMillisecondsPerHour),
        .preprocessing_aware_with_modswitch_proxy_hours =
            static_cast<double>((preprocessing_aware_ms + switch_proxy_ms) /
                                kMillisecondsPerHour),
    };
}

PackedProverRuntimeBreakdown packed_prover_runtime_breakdown(
    const ProverOperationLedger &ledger,
    const TargetRuntimeCalibration &calibration) {
    if ((ledger.protocol != ScheduleProtocol::Folded &&
         ledger.protocol != ScheduleProtocol::Laned) ||
        ledger.aligned_ciphertexts == 0 ||
        ledger.logical_packed_outputs == 0 ||
        ledger.logical_packed_outputs > ledger.aligned_ciphertexts ||
        ledger.well_formedness_repetitions == 0 ||
        ledger.signed_digits_per_output == 0) {
        throw std::invalid_argument(
            "runtime breakdown requires a complete packed ledger");
    }

    // Step 1: reconstruct just the one-prime packing arithmetic. These are
    //
    //   D*r PT-CT, D*(r-L)+T*(r-1) additions, and T negations.
    //
    // Everything else in the original ledger belongs to GKR, online grid
    // alignment, or finalization before the committed-GKR boundary.
    ProverOperationLedger packing;
    packing.protocol = ledger.protocol;
    packing.paper_raw_ciphertext_footprint =
        ledger.paper_raw_ciphertext_footprint;
    packing.aligned_ciphertexts = ledger.aligned_ciphertexts;
    packing.logical_packed_outputs = ledger.logical_packed_outputs;
    packing.well_formedness_repetitions =
        ledger.well_formedness_repetitions;
    packing.signed_digits_per_output =
        ledger.signed_digits_per_output;

    add_transcript_packing_primitives(packing);

    // Step 2: price both ledgers with the same model, then subtract. Keeping
    // the split here prevents the Markdown report from acquiring a second
    // timing model.
    const TargetRuntimeEstimate total =
        estimate_target_runtime(ledger, calibration);
    const TargetRuntimeEstimate packing_runtime =
        estimate_target_runtime(packing, calibration);
    return PackedProverRuntimeBreakdown{
        .gkr_and_alignment_hours =
            total.preprocessing_aware_hours -
            packing_runtime.preprocessing_aware_hours,
        .transcript_packing_fhe_seconds =
            packing_runtime.preprocessing_aware_hours * 3'600.0,
    };
}

std::uint64_t one_prime_seal_ciphertext_bytes(std::size_t slot_count) {
    if (!std::has_single_bit(slot_count) || slot_count < 2) {
        throw std::invalid_argument(
            "one-prime ciphertext size requires power-of-two N");
    }
    return checked_add(checked_mul(Count{16}, as_count(slot_count, "N"),
                                   "one-prime ciphertext bytes"),
                       Count{113}, "one-prime ciphertext bytes");
}

namespace {

ProofSizeEstimate estimate_base_proof_size_for_topology(
    const payload::LayeredCircuit &circuit,
    const ScheduleFormula &formula, Count extensions,
    Count base_ciphertexts) {
    if (formula.protocol != ScheduleProtocol::Base) {
        throw std::invalid_argument("Base proof-size formula protocol mismatch");
    }
    const Count ciphertext =
        one_prime_seal_ciphertext_bytes(circuit.shape.slot_count);
    // append_extension contributes an eight-byte outer length. LMEX/v2 then
    // contributes a five-byte domain/version, an eight-byte degree, and one
    // presence mask. Each live coordinate contributes its own eight-byte
    // length and canonical one-prime ciphertext.
    const Count extension_framing_bytes = checked_mul(
        extensions, Count{22}, "Base extension framing bytes");
    const Count live_coordinate_bytes = checked_mul(
        base_ciphertexts,
        checked_add(Count{8}, ciphertext,
                    "Base coordinate ciphertext bytes"),
        "Base coordinate ciphertext bytes");
    const Count fhe_message_bytes = checked_add(
        extension_framing_bytes, live_coordinate_bytes,
        "Base FHE-message transport bytes");
    const Count metadata = base_metadata_bytes(formula);
    const Count partial_vector_bytes = checked_add(
        Count{8},
        checked_mul(as_count(circuit.shape.slot_count, "Base slots"),
                    Count{kSerializedFpkBytes},
                    "Base partial GateMLE field bytes"),
        "Base partial GateMLE vector bytes");
    const Count partial_bytes = checked_mul(
        base_partial_gate_mle_vectors(circuit), partial_vector_bytes,
        "Base partial GateMLE bytes");
    const Count persistent_fhe_message_bytes = checked_add(
        checked_mul(extensions, Count{9},
                    "persistent Base extension framing bytes"),
        live_coordinate_bytes,
        "persistent Base FHE-message transport bytes");
    const Count persistent_metadata =
        persistent_base_metadata_bytes(formula);
    const Count persistent_inner = checked_add(
        checked_add(persistent_fhe_message_bytes, partial_bytes,
                    "persistent Base proof bytes"),
        persistent_metadata, "persistent Base proof bytes");
    constexpr Count response_envelope_header =
        delegation::kBaseDelegationWireHeaderBytes;
    constexpr Count response_public_bindings = 4U * Digest{}.size();
    constexpr Count response_output_dimensions =
        4U * sizeof(std::uint64_t);
    constexpr Count response_proof_length_prefix = sizeof(std::uint64_t);
    const Count response_output_fhe_values =
        persistent_base_response_output_fhe_value_bytes(circuit,
                                                        ciphertext);
    const Count response_output_statement = checked_add(
        response_output_dimensions, response_output_fhe_values,
        "Base response output statement");
    const Count response_envelope =
        persistent_base_response_envelope_bytes(response_output_statement);
    return ProofSizeEstimate{
        .canonical_bytes_excluding_packing_argument =
            checked_add(checked_add(fhe_message_bytes, partial_bytes,
                                    "Base proof bytes"),
                        metadata, "Base proof bytes"),
        .fhe_message_bytes = fhe_message_bytes,
        .partial_gate_mle_bytes = partial_bytes,
        .gkr_commitment_bytes = 0,
        .statement_and_metadata_bytes = metadata,
        .one_prime_ciphertexts = base_ciphertexts,
        .persistent_base = PersistentBaseProofSizeEstimate{
            .inner_transport_bytes = persistent_inner,
            .fhe_message_bytes = persistent_fhe_message_bytes,
            .partial_gate_mle_bytes = partial_bytes,
            .statement_and_metadata_bytes = persistent_metadata,
            .response_envelope_header_bytes = response_envelope_header,
            .response_public_bindings_bytes = response_public_bindings,
            .response_output_dimensions_bytes =
                response_output_dimensions,
            .response_output_fhe_values_bytes =
                response_output_fhe_values,
            .response_output_statement_bytes =
                response_output_statement,
            .response_proof_length_prefix_bytes =
                response_proof_length_prefix,
            .response_envelope_bytes = response_envelope,
            .response_bytes = checked_add(
                persistent_inner, response_envelope,
                "persistent Base proof-response bytes"),
        },
    };
}

} // namespace

ProofSizeEstimate estimate_base_proof_size(
    const payload::LayeredCircuit &circuit,
    const ScheduleFormula &formula) {
    const Count extensions =
        as_count(base_extension_ciphertexts(formula), "Base extensions");
    return estimate_base_proof_size_for_topology(
        circuit, formula, extensions,
        checked_mul(extensions, Count{kExtensionDegree},
                    "Base ciphertext count"));
}

ProofSizeEstimate estimate_base_proof_size(
    const payload::LayeredCircuit &circuit,
    const ScheduleFormula &formula,
    const ProverOperationLedger &ledger) {
    const Count expected_extensions =
        as_count(base_extension_ciphertexts(formula), "Base extensions");
    const Count extensions = as_count(
        ledger.direct_transcript_extension_messages,
        "Base ledger extension messages");
    const Count public_zero_extensions = as_count(
        ledger.direct_transcript_public_zero_extension_messages,
        "Base ledger public-zero extension messages");
    const Count base_ciphertexts = as_count(
        ledger.direct_transcript_ciphertexts,
        "Base ledger ciphertexts");
    if (ledger.protocol != ScheduleProtocol::Base ||
        extensions != expected_extensions ||
        public_zero_extensions > extensions) {
        throw std::invalid_argument(
            "Base proof-size ledger disagrees with the formula topology");
    }
    const Count maximum_live_coordinates = checked_mul(
        extensions - public_zero_extensions, Count{kExtensionDegree},
        "Base maximum live coordinates");
    if (base_ciphertexts > maximum_live_coordinates) {
        throw std::invalid_argument(
            "Base proof-size ledger disagrees with the formula topology");
    }
    return estimate_base_proof_size_for_topology(
        circuit, formula, extensions, base_ciphertexts);
}

ProofSizeEstimate estimate_packed_proof_size(
    const payload::LayeredCircuit &circuit,
    const ProverOperationLedger &ledger) {
    if (ledger.protocol == ScheduleProtocol::Base) {
        throw std::invalid_argument(
            "packed proof-size formula received Base ledger");
    }
    const Count ciphertext =
        one_prime_seal_ciphertext_bytes(circuit.shape.slot_count);
    const Count tests = as_count(ledger.well_formedness_repetitions,
                                 "proof test ciphertexts");
    const Count digits = checked_mul(
        as_count(ledger.logical_packed_outputs, "packed proof outputs"),
        as_count(ledger.signed_digits_per_output, "packed proof digits"),
        "packed proof digit ciphertexts");
    const Count ciphertext_count = checked_add(tests, digits,
                                               "packed proof ciphertexts");
    const Count fhe_message_bytes = checked_mul(
        ciphertext_count, checked_add(Count{9}, ciphertext,
                                      "length-prefixed tagged ciphertext"),
        "packed proof FHE-message bytes");
    const Count public_overhead = public_message_wire_overhead(circuit, ledger);
    const Count committed = committed_gkr_bytes(circuit, ledger, public_overhead);
    const Count commitment_bytes = checked_mul(
        as_count(ledger.aligned_ciphertexts, "GKR commitments"),
        Count{PoseidonDigest{}.size()}, "GKR commitment bytes");

    // Outer prefix + committed length + reveal, digit, and Spartan lengths.
    // The per-ciphertext FHE-value tags are included with the messages above.
    // The separately estimated Spartan payload is omitted, but its length
    // field remains on wire.
    const Count framing = 14 + 8 + 8 + 8 + 8;
    const Count total = checked_add(
        checked_add(committed, framing, "packed proof framing"),
        fhe_message_bytes, "packed proof bytes");
    const Count metadata = total - fhe_message_bytes - commitment_bytes;
    return ProofSizeEstimate{
        .canonical_bytes_excluding_packing_argument = total,
        .fhe_message_bytes = fhe_message_bytes,
        .gkr_commitment_bytes = commitment_bytes,
        .public_message_overhead_bytes = public_overhead,
        .statement_and_metadata_bytes = metadata,
        .one_prime_ciphertexts = ciphertext_count,
    };
}

WideGateProofSizeEstimate estimate_wide_gate_proof_size(
    const payload::LayeredCircuit &circuit,
    const basefold::foldable::Parameters &parameters) {
    namespace fc = basefold::foldable;
    using gates::GateTableKind;
    if (circuit.shape.kind != payload::PayloadKind::Wide)
        throw std::invalid_argument("Wide gate size estimate needs a Wide circuit");
    const auto layout = gates::make_gate_table_layout(circuit, gates::GateTableSet::Wide);
    const auto blocks = gates::make_wide_public_blocks(layout);
    const auto public_shape = gates::plan_wide_public_commitment(layout);
    WideGateProofSizeEstimate result;
    gates::OutsourcedGateMleProof framing;
    framing.wide.emplace();
    framing.claimed_values.resize(2 * layout.wide_layers.size());
    std::vector<std::size_t> operands(layout.tables.size());
    std::vector<std::size_t> trace_sizes;
    const auto sparse_shape = [](const gates::GateTableDescriptor &table) {
        gates::sparse::SparseProductProof proof;
        const auto rows = std::bit_width(std::bit_ceil(table.support_size)) - 1U;
        const auto columns = std::bit_width(std::bit_ceil(table.local_variables + 1)) - 1U;
        proof.root_rounds.resize(rows);
        proof.layers.resize(columns);
        for (std::size_t layer = 0; layer < columns; ++layer)
            proof.layers[layer].rounds.resize(rows + layer);
        return proof;
    };
    for (const auto &layer : layout.wide_layers) {
        const bool active = layer.node_count != 0;
        trace_sizes.push_back(active ? layer.dimensions.internal_scalars : 0);
        auto &trace = framing.wide->traces.emplace_back();
        trace.has_adjoint = active;
        const std::size_t local_targets = active ? 3 : 2;
        trace.boundary_values.resize(local_targets);
        trace.terminal_values.resize(active ? local_targets : 0);
        trace.product.rounds.resize(active ?
            basefold::log2_exact(layer.dimensions.internal_scalars) : 0);
        for (std::size_t query = 0; query < (active ? 2 : 1) * local_targets; ++query) {
            const bool constant = query % local_targets == 1;
            auto &local = trace.local_openings.emplace_back();
            const auto table = [&](GateTableKind kind) {
                return gates::find_table_if(layout,
                    kind == GateTableKind::WideMaskDictionary ? 0 : layer.layer_index, kind);
            };
            const auto add_sparse = [&](const gates::GateTableDescriptor *descriptor) {
                if (!descriptor) return;
                local.products.push_back(sparse_shape(*descriptor));
                ++operands.at(descriptor->selector);
            };
            if (constant) {
                add_sparse(table(GateTableKind::AffineConstantUniform));
                add_sparse(table(GateTableKind::AffineConstantSlot));
            } else {
                if (const auto *uniform = table(GateTableKind::WideLocalUniformEdges)) {
                    local.action.emplace();
                    local.action->rounds.resize(basefold::log2_exact(layer.dimensions.slots));
                    add_sparse(uniform);
                }
                if (const auto *mask = table(GateTableKind::WideLocalMaskEdges)) {
                    local.masked.emplace();
                    local.masked->masks.rounds.resize(basefold::log2_exact(layout.wide_masks.mask_width));
                    local.masked->slots.rounds.resize(basefold::log2_exact(layer.dimensions.slots));
                    add_sparse(mask);
                    const auto *dictionary = table(GateTableKind::WideMaskDictionary);
                    if (!dictionary) throw std::invalid_argument("Wide size estimate lacks mask dictionary");
                    add_sparse(dictionary);
                }
            }
        }
    }
    Count dummy_pcs_bytes = 0;
    for (const auto &group : gates::wide_adjoint_group_layout(trace_sizes)) {
        framing.wide->adjoint_groups.emplace_back();
        add(dummy_pcs_bytes, fc::encode_canonical(
            framing.wide->adjoint_groups.back().opening).size(), "gate dummy PCS bytes");
        add(result.pcs_bytes_upper_bound, fc::proof_size_bound(
            {.m = group.message_size, .width = 1},
            2 * group.trace_indices.size(), parameters), "gate witness PCS bytes");
        ++result.adjoint_groups;
    }
    for (const auto &table : layout.tables) {
        const auto count = operands.at(table.selector);
        if (count == 0) continue;
        auto &opening = framing.wide->tables.emplace_back();
        opening.table_selector = table.selector;
        opening.column_targets.resize(count,
            std::vector<Fpk>(std::bit_ceil(table.local_variables + 1)));
        const auto block = std::find_if(blocks.begin(), blocks.end(),
            [&](const auto &item) { return item.selector == table.selector; });
        const gates::SparseTableCommitment shape{
            block->rows, block->rows, 1, block->columns, block->columns,
            {}, std::nullopt, block->offset};
        result.public_operands += count * gates::wide_public_operands_per_request(shape, public_shape);
    }
    if (result.public_operands) {
        result.public_message_size = public_shape.m;
        framing.wide->public_column_targets.resize(result.public_operands,
            std::vector<Fpk>(public_shape.width));
        // The outer encoder always includes the empty PCS payload. Replace
        // precisely that payload with its full shape-dependent cap below.
        add(dummy_pcs_bytes, fc::encode_canonical(framing.wide->public_opening).size(),
            "gate dummy public PCS bytes");
        add(result.pcs_bytes_upper_bound, fc::proof_size_bound(
            public_shape, result.public_operands,
            parameters), "gate public PCS bytes");
    }
    result.outer_bytes = gates::encode_canonical(framing).size() - dummy_pcs_bytes;
    result.canonical_bytes_upper_bound = checked_add(result.outer_bytes,
        result.pcs_bytes_upper_bound, "Wide gate proof bytes");
    return result;
}

SpartanPackingEstimate estimate_spartan_packing(
    const payload::LayeredCircuit &circuit,
    const ProverOperationLedger &ledger) {
    static_assert(spartan::kDefaultSourceSumcheckRounds == 2,
                  "update the Spartan phase model with the source schedule");
    if (ledger.protocol == ScheduleProtocol::Base ||
        ledger.aligned_ciphertexts == 0 ||
        ledger.logical_packed_outputs == 0 ||
        ledger.well_formedness_repetitions == 0 ||
        ledger.signed_digits_per_output == 0) {
        throw std::invalid_argument(
            "Spartan packing estimate requires a packed-protocol ledger");
    }
    const packing::OuterRelationPlan plan =
        packing::make_outer_relation_plan(packing::OuterRelationShape{
            .native_modulus = kOuterFieldOrder,
            .ring_degree = circuit.shape.slot_count,
            .aligned_ciphertexts = ledger.aligned_ciphertexts,
            .repetitions = ledger.well_formedness_repetitions,
            .logical_packed_outputs = ledger.logical_packed_outputs,
            .packing_digit_count = ledger.signed_digits_per_output,
            .ciphertext_components = 2,
            .public_input_capacity_bits = 59,
        });
    const packing::ProofOfPackingR1csLedger r1cs =
        packing::proof_of_packing_r1cs_ledger(plan);
    const auto pad = [](std::uint64_t value, const char *label) {
        if (value == 0 || value > (std::uint64_t{1} << 63U)) {
            throw std::overflow_error(std::string(label) +
                                      " cannot be padded");
        }
        return std::bit_ceil(value);
    };
    const std::uint64_t padded_constraints =
        pad(r1cs.matrix_rows, "Spartan matrix rows");
    const std::uint64_t public_side = checked_add(
        r1cs.total_public_inputs, Count{1}, "Spartan public side");
    const std::uint64_t assignment_half = pad(
        std::max(public_side, r1cs.total_witness_variables),
        "Spartan assignment half");
    const std::uint64_t row_variables =
        std::bit_width(padded_constraints) - 1U;
    const std::uint64_t assignment_variables =
        std::bit_width(assignment_half) - 1U;
    const std::uint64_t column_variables = assignment_variables + 1U;
    const auto checked_size = [](std::uint64_t value, const char *label) {
        if (value > std::numeric_limits<std::size_t>::max()) {
            throw std::overflow_error(std::string(label) +
                                      " exceeds size_t");
        }
        return static_cast<std::size_t>(value);
    };
    constexpr spartan::BaseFoldPcsParameters kBaseFold{
        .log_rate = kTranscriptPackingBaseFoldLogRate,
        .query_count = kTranscriptPackingBaseFoldQueries,
    };
    const std::uint64_t core_proof_max_bytes = checked_add(
        checked_add(
            checked_add(
                checked_add(
                    Count{80},
                    checked_mul(row_variables, Count{32},
                                "Spartan constraint rounds"),
                    "Spartan core proof"),
                Count{48}, "Spartan constraint terminal"),
            checked_mul(column_variables, Count{32},
                        "Spartan wiring rounds"),
            "Spartan core proof"),
        checked_add(
            // Matrix/assignment evaluations plus the factored and witness-
            // opening length fields. The two payloads are added separately.
            Count{48},
            spartan::basefold_opening_proof_max_size_bytes(
                checked_size(assignment_variables,
                             "Spartan assignment variables"),
                1U, kBaseFold),
            "Spartan witness opening"),
        "Spartan core proof");

    const std::vector<std::size_t> owner_counts =
        packed_output_owner_counts(ledger.aligned_ciphertexts,
                                   circuit.shape.slot_count,
                                   ledger.logical_packed_outputs);
    const packing::PackingTensorGeometry tensor_geometry =
        packing::packing_tensor_geometry(
            owner_counts, circuit.shape.slot_count,
            ledger.signed_digits_per_output, sizeof(Fq));

    spartan::FactoredMatrixCommitment factored_commitment;
    factored_commitment.tensors.reserve(tensor_geometry.outputs.size());
    std::vector<std::uint64_t> live_owners;
    std::vector<std::uint64_t> padded_owners;
    live_owners.reserve(tensor_geometry.outputs.size());
    padded_owners.reserve(tensor_geometry.outputs.size());
    Count largest_tensor_evaluations = 0;
    Count retained_merkle_bytes = 0;
    Count factored_sumcheck_rounds = 0;
    Count factored_merkle_hashes = 0;
    for (const packing::PackingTensorDescriptor &descriptor :
         tensor_geometry.outputs) {
        const Count live = as_count(descriptor.live_owner_count,
                                    "factored live owners");
        const Count padded = as_count(descriptor.padded_owner_count,
                                      "factored padded owners");
        const Count evaluations = checked_mul(
            padded, as_count(descriptor.ring_degree,
                             "factored ring degree"),
            "factored tensor evaluations");
        live_owners.push_back(live);
        padded_owners.push_back(padded);
        largest_tensor_evaluations =
            std::max(largest_tensor_evaluations, evaluations);
        const Count codeword_size = checked_mul(
            evaluations, Count{1} << kBaseFold.log_rate,
            "factored BaseFold codeword size");
        add(retained_merkle_bytes,
            basefold_merkle_payload_bytes(codeword_size),
            "retained factored Merkle bytes");
        const Count rounds = std::bit_width(evaluations) - 1U;
        add(factored_sumcheck_rounds, rounds,
            "factored sumcheck rounds");
        add(factored_merkle_hashes,
            basefold_query_merkle_hashes(evaluations, kBaseFold),
            "factored BaseFold Merkle hashes");

        factored_commitment.tensors.push_back(
            spartan::FactoredTensorCommitment{
                .shape = spartan::FactoredTensorShape{
                    .evaluation_count = evaluations,
                    .column_count = as_count(
                        descriptor.digit_count,
                        "factored digit columns"),
                },
                .columns = spartan::PcsCommitment{
                    .scheme = spartan::BaseFoldPcs::kSchemeIdentifier,
                    .evaluation_count = evaluations,
                    .width = as_count(descriptor.digit_count,
                                      "factored digit columns"),
                    .log_rate = static_cast<std::uint32_t>(
                        kBaseFold.log_rate),
                    .query_count = static_cast<std::uint32_t>(
                        kBaseFold.query_count),
                },
            });
    }
    const Count factored_proof_max_bytes = as_count(
        spartan::factored_matrix_evaluation_proof_max_size_bytes(
            factored_commitment, kBaseFold),
        "factored matrix maximum proof bytes");

    // This projection models resident factored preprocessing, which retains
    // the input columns while BaseFold retains another message copy and a
    // rate-expanded codeword. It does not model the external artifact-backed
    // setup used by the split-process benchmark. The native packing tensor is
    // already padded.
    const Count raw_tensor_bytes = tensor_geometry.total_padded_bytes;
    const Count basefold_message_bytes = raw_tensor_bytes;
    const Count basefold_codeword_bytes = checked_mul(
        raw_tensor_bytes, Count{1} << kBaseFold.log_rate,
        "factored BaseFold codeword bytes");
    Count retained_preprocessing_bytes = checked_add(
        checked_add(raw_tensor_bytes, basefold_message_bytes,
                    "factored retained message bytes"),
        basefold_codeword_bytes, "factored retained codeword bytes");
    retained_preprocessing_bytes = checked_add(
        retained_preprocessing_bytes, retained_merkle_bytes,
        "factored retained preprocessing bytes");

    // Opening starts with one weighted message, one equality operand, and one
    // rate-expanded weighted codeword: `(2 + rate)*K` Fq2 values.
    // Subsequent folds share the message allocation and release the weighted
    // base codeword before folded layers and their Merkle trees accumulate.
    const Count basefold_rate = Count{1} << kBaseFold.log_rate;
    const Count basefold_opening_fq2_bytes = checked_mul(
        checked_mul(checked_add(Count{2}, basefold_rate,
                                "factored opening rate factor"),
                    largest_tensor_evaluations,
                    "factored opening Fq2 elements"),
        Count{sizeof(Fq2)}, "factored opening Fq2 bytes");
    const Count opening_peak_bytes = checked_add(
        retained_preprocessing_bytes,
        basefold_opening_fq2_bytes,
        "factored opening peak bytes");

    // The witness commitment retains one H-entry Fq message, one rate-expanded
    // codeword, and its Merkle tree. The online phase model deliberately
    // excludes the caller's logical witness and the preprocessed R1CS key.
    const Count witness_codeword_size = checked_mul(
        assignment_half, Count{1} << kBaseFold.log_rate,
        "witness BaseFold codeword size");
    const Count retained_witness_pcs_bytes = checked_add(
        checked_add(
            checked_mul(assignment_half, Count{sizeof(Fq)},
                        "witness BaseFold message bytes"),
            checked_mul(witness_codeword_size, Count{sizeof(Fq)},
                        "witness BaseFold codeword bytes"),
            "witness BaseFold field bytes"),
        basefold_merkle_payload_bytes(witness_codeword_size),
        "retained witness BaseFold bytes");
    const Count padded_assignment_bytes = checked_mul(
        checked_mul(Count{2}, assignment_half,
                    "padded assignment elements"),
        Count{sizeof(Fq)}, "padded assignment bytes");
    const Count assignment_and_witness_pcs_bytes = checked_add(
        retained_witness_pcs_bytes, padded_assignment_bytes,
        "assignment and witness PCS bytes");
    constexpr Count kBaseFoldLeafElements = 64;
    const Count commitment_leaf_scratch_bytes = checked_mul(
        std::min(witness_codeword_size, kBaseFoldLeafElements),
        Count{sizeof(Fq)}, "witness commitment leaf scratch bytes");
    const Count assignment_commitment_peak = checked_add(
        assignment_and_witness_pcs_bytes,
        commitment_leaf_scratch_bytes,
        "assignment commitment peak bytes");

    // Two source-computed rounds leave quarter-domain Fq2 fold tables. The
    // constraint peak occurs while compacting the equality suffix: all three
    // base-field products, its original allocation, and the compacted suffix
    // coexist. Wiring peaks while the full matrix and its quarter checkpoint
    // coexist with z and the retained witness PCS.
    const Count constraint_source_product_bytes = checked_mul(
        checked_mul(Count{3}, padded_constraints,
                    "constraint source elements"),
        Count{sizeof(Fq)}, "constraint source bytes");
    const Count constraint_old_equality_bytes = checked_mul(
        padded_constraints / 2U, Count{sizeof(Fq2)},
        "constraint equality allocation bytes");
    const Count constraint_compact_equality_bytes = checked_mul(
        padded_constraints / 8U, Count{sizeof(Fq2)},
        "constraint compact equality bytes");
    const Count constraint_peak = checked_add(
        assignment_and_witness_pcs_bytes,
        checked_add(
            constraint_source_product_bytes,
            checked_add(constraint_old_equality_bytes,
                        constraint_compact_equality_bytes,
                        "constraint equality compaction bytes"),
            "constraint transient bytes"),
        "constraint peak bytes");
    const Count wiring_source_matrix_bytes = checked_mul(
        checked_mul(Count{2}, assignment_half,
                    "wiring source matrix elements"),
        Count{sizeof(Fq2)}, "wiring source matrix bytes");
    const Count wiring_checkpoint_bytes = checked_mul(
        assignment_half / 2U, Count{sizeof(Fq2)},
        "wiring checkpoint bytes");
    const Count wiring_peak = checked_add(
        assignment_and_witness_pcs_bytes,
        checked_add(wiring_source_matrix_bytes,
                    wiring_checkpoint_bytes,
                    "wiring transient bytes"),
        "wiring peak bytes");
    const Count witness_opening_scratch_bytes = checked_mul(
        checked_mul(std::max(checked_add(Count{2}, basefold_rate,
                                        "witness opening rate factor"),
                             checked_mul(Count{2}, basefold_rate,
                                         "witness opening replay factor")),
                    assignment_half,
                    "witness opening Fq2 elements"),
        Count{sizeof(Fq2)}, "witness opening scratch bytes");
    const Count witness_opening_peak = checked_add(
        retained_witness_pcs_bytes, witness_opening_scratch_bytes,
        "witness opening peak bytes");
    const Count core_peak = std::max(
        {assignment_commitment_peak, constraint_peak, wiring_peak,
         witness_opening_peak});

    const packing::ProofOfPackingR1csLayout layout =
        packing::make_proof_of_packing_r1cs_layout(plan);
    const Count aligned = as_count(ledger.aligned_ciphertexts,
                                   "regular aligned ciphertexts");
    const Count tests = as_count(ledger.well_formedness_repetitions,
                                 "regular well-formedness tests");
    const Count outputs = as_count(ledger.logical_packed_outputs,
                                   "factored output count");
    const Count digits = as_count(ledger.signed_digits_per_output,
                                  "factored digit count");
    const Count segments = as_count(layout.ciphertext_segments.size(),
                                    "Poseidon segment count");
    const std::size_t coordinate_variables =
        std::bit_width(plan.coordinates_per_ciphertext()) - 1U;
    if (coordinate_variables > row_variables || column_variables == 0 ||
        coordinate_variables > column_variables - 1U) {
        throw std::logic_error(
            "regular equality-table dimensions are inconsistent");
    }
    const Count row_high_elements =
        Count{1} << (row_variables - coordinate_variables);
    const Count column_high_elements =
        Count{1} << (column_variables - 1U - coordinate_variables);
    const Count affine_segment_visits = checked_mul(
        checked_mul(checked_mul(aligned, Count{2},
                                "owner component visits"),
                    Count{kPoseidonRate}, "owner rate visits"),
        segments, "owner affine segment visits");
    const Count factored_queries = checked_mul(
        outputs, as_count(kBaseFold.query_count,
                          "factored BaseFold query count"),
        "factored BaseFold queries");
    return SpartanPackingEstimate{
        .r1cs_constraints = r1cs.total_constraints,
        .r1cs_matrix_rows = r1cs.matrix_rows,
        .r1cs_logical_inputs = r1cs.total_logical_inputs,
        .r1cs_public_inputs = r1cs.total_public_inputs,
        .r1cs_witness_variables = r1cs.total_witness_variables,
        .r1cs_nonzero_entries_upper_bound =
            r1cs.total_nonzero_entries_upper_bound,
        .padded_constraints = padded_constraints,
        .assignment_half_size = assignment_half,
        .factored_output_live_owners = std::move(live_owners),
        .factored_output_padded_owners = std::move(padded_owners),
        .factored_tensor_live_elements =
            tensor_geometry.total_live_elements,
        .factored_tensor_padded_elements =
            tensor_geometry.total_padded_elements,
        .factored_tensor_live_bytes = tensor_geometry.total_live_bytes,
        .factored_tensor_padded_bytes = tensor_geometry.total_padded_bytes,
        .factored_largest_tensor_evaluations =
            largest_tensor_evaluations,
        .factored_retained_raw_tensor_bytes = raw_tensor_bytes,
        .factored_retained_basefold_message_bytes =
            basefold_message_bytes,
        .factored_retained_basefold_codeword_bytes =
            basefold_codeword_bytes,
        .factored_retained_basefold_merkle_bytes = retained_merkle_bytes,
        .factored_retained_preprocessing_bytes_model =
            retained_preprocessing_bytes,
        .factored_opening_peak_bytes_model = opening_peak_bytes,
        .regular_poseidon_segments = segments,
        .regular_poseidon_ciphertext_segment_visits = checked_mul(
            aligned, segments, "Poseidon ciphertext-segment visits"),
        .regular_poseidon_rate_interval_evaluations = checked_mul(
            checked_mul(aligned, segments,
                        "Poseidon ciphertext-segment visits"),
            Count{kPoseidonRate}, "Poseidon rate intervals"),
        .regular_poseidon_boundary_segment_visits = checked_mul(
            aligned - 1U, segments, "Poseidon boundary-segment visits"),
        .regular_poseidon_digest_terms = checked_mul(
            aligned, Count{kPoseidonDigestElements},
            "Poseidon digest terms"),
        .regular_challenge_bit_visits = checked_mul(
            Count{2}, plan.variables.witness.derived_challenge_bits.count,
            "regular challenge-bit visits"),
        .regular_test_ciphertext_pair_visits = checked_mul(
            Count{3}, checked_mul(tests, aligned,
                                  "regular test-ciphertext pairs"),
            "regular test-ciphertext visits"),
        .regular_owner_affine_segment_visits = affine_segment_visits,
        .regular_public_affine_range_evaluations = checked_add(
            tests, checked_mul(outputs, digits,
                               "packing public affine ranges"),
            "regular public affine ranges"),
        .regular_high_equality_table_elements = checked_add(
            checked_mul(Count{3}, row_high_elements,
                        "regular row-high equality tables"),
            checked_mul(Count{2}, column_high_elements,
                        "regular column-high equality tables"),
            "regular high equality tables"),
        .factored_sumcheck_rounds = factored_sumcheck_rounds,
        .factored_digit_weight_terms = checked_mul(
            outputs, digits, "factored digit weight terms"),
        .factored_terminal_owner_terms = aligned,
        .factored_terminal_affine_segment_visits =
            affine_segment_visits,
        .factored_basefold_openings = outputs,
        .factored_basefold_queries = factored_queries,
        .factored_basefold_query_fold_steps = checked_mul(
            as_count(kBaseFold.query_count,
                     "factored BaseFold query count"),
            factored_sumcheck_rounds,
            "factored BaseFold query folds"),
        .factored_basefold_merkle_hashes = factored_merkle_hashes,
        .core_proof_max_bytes = core_proof_max_bytes,
        .factored_proof_max_bytes = factored_proof_max_bytes,
        .proof_max_bytes = checked_add(
            core_proof_max_bytes, factored_proof_max_bytes,
            "Spartan and factored maximum proof bytes"),
        .core_retained_witness_pcs_bytes_model =
            retained_witness_pcs_bytes,
        .core_assignment_commitment_peak_bytes_model =
            assignment_commitment_peak,
        .core_constraint_peak_memory_bytes_model = constraint_peak,
        .core_wiring_peak_memory_bytes_model = wiring_peak,
        .core_witness_opening_peak_memory_bytes_model =
            witness_opening_peak,
        .core_peak_memory_bytes_model = core_peak,
    };
}

VerifierCryptoLedger estimate_verifier_crypto(
    const payload::LayeredCircuit &circuit,
    const ProverOperationLedger &ledger) {
    VerifierCryptoLedger result;
    if (ledger.protocol == ScheduleProtocol::Base) {
        result.one_prime_decryptions =
            as_count(ledger.direct_transcript_ciphertexts,
                     "Base verifier decryptions");
        result.recovered_gkr_messages =
            as_count(ledger.direct_transcript_extension_messages,
                     "Base extension messages");
        for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
            if (payload::layer_kind(circuit.layers[layer]) ==
                payload::LayerKind::Affine) {
                // Each carried claim opens one affine constant and one full
                // GateMLE value at the post-vector slot challenge.
                constexpr Count claims = 1;
                add(result.direct_gate_mle_queries,
                    checked_mul(Count{2}, claims,
                                "Base affine gate queries"),
                    "Base affine gate queries");
                add(result.base_partial_gate_mle_vectors, Count{1},
                    "Base affine partial GateMLE vectors");
            }
        }
        return result;
    }

    result.one_prime_decryptions = checked_mul(
        as_count(ledger.logical_packed_outputs, "verifier packed outputs"),
        as_count(ledger.signed_digits_per_output, "verifier digits"),
        "packed verifier decryptions");
    result.excluded_packing_partial_decryption_norm_checks =
        as_count(ledger.well_formedness_repetitions,
                 "verifier norm checks");
    result.excluded_packing_commitment_digests =
        as_count(ledger.aligned_ciphertexts,
                 "verifier packing commitment digests");
    result.recovered_gkr_messages =
        as_count(ledger.aligned_ciphertexts,
                 "recovered GKR messages");
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        if (payload::layer_kind(circuit.layers[layer]) ==
            payload::LayerKind::Affine) {
            constexpr Count claims = 1;
            add(result.direct_gate_mle_queries,
                checked_mul(Count{2}, claims,
                            "packed affine gate queries"),
                "packed affine gate queries");
        }
    }
    return result;
}

} // namespace laminate::bench
