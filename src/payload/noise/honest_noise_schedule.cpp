/// @file honest_noise_schedule.cpp
/// @brief Exact setup-time derivation of the operational payload schedule.

#include "laminate/payload/noise/honest_noise_schedule.hpp"

#include "laminate/params.hpp"
#include "laminate/gates/gate_mle.hpp"
#include "laminate/payload/setup/encoding.hpp"
#include "laminate/payload/noise/honest_base_proof_noise.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_set>
#include <variant>

namespace laminate::payload {
namespace {

using fhe::NaturalMagnitude;
using Bytes = std::vector<std::uint8_t>;

constexpr std::size_t kMaximumCalibrationDebitBits = 4096;
using Wide = unsigned __int128;

// 45427 / 65536 > ln(2). Combined with ceil(log2(x)), this gives
// a deterministic upper bound for ln(x) without platform floating point.
constexpr std::uint64_t kLn2UpperNumerator = 45'427;
constexpr std::uint64_t kLn2UpperDenominator = 65'536;

std::size_t bit_count(Wide value) {
    std::size_t result = 0;
    while (value != 0) {
        ++result;
        value >>= 1U;
    }
    return result;
}

std::size_t ceil_log2(Wide value) {
    if (value == 0) {
        throw std::invalid_argument(
            "honest switch heuristic: logarithm input is zero");
    }
    const std::size_t bits = bit_count(value);
    const Wide lower_power = Wide{1} << (bits - 1U);
    return bits - static_cast<std::size_t>(value == lower_power);
}

Wide checked_multiply(Wide left, Wide right, const char *description) {
    constexpr Wide maximum = ~Wide{0};
    if (left != 0 && right > maximum / left) {
        throw std::overflow_error(
            std::string("honest switch heuristic: ") + description +
            " overflows");
    }
    return left * right;
}

Wide divide_ceil(Wide value, Wide divisor) {
    if (divisor == 0) {
        throw std::invalid_argument(
            "honest switch heuristic: division by zero");
    }
    return value / divisor + static_cast<Wide>(value % divisor != 0);
}

Wide square_root_ceil(Wide value) {
    if (value <= 1) {
        return value;
    }
    const std::size_t bits = bit_count(value);
    Wide low = 0;
    Wide high = Wide{1} << ((bits + 1U) / 2U);
    while (low + 1U < high) {
        const Wide middle = low + (high - low) / 2U;
        if (middle >= divide_ceil(value, middle)) {
            high = middle;
        } else {
            low = middle;
        }
    }
    return high;
}

void append_u64(Bytes &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(
            static_cast<std::uint8_t>((value >> (8U * byte)) & 0xffU));
    }
}

void append_size(Bytes &output, std::size_t value) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                "honest payload schedule encoding: size does not fit u64");
        }
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

void append_label(Bytes &output, std::string_view label) {
    append_size(output, label.size());
    output.insert(output.end(), label.begin(), label.end());
}

bool at_most(const NaturalMagnitude &left,
             const NaturalMagnitude &right) {
    return !(right < left);
}

NaturalMagnitude power_of_two(std::size_t bits) {
    return NaturalMagnitude::shift_left(NaturalMagnitude(1), bits);
}

NaturalMagnitude canonical_phase(
    const NaturalMagnitude &canonical_error) {
    return NaturalMagnitude::add(
        NaturalMagnitude::multiply(canonical_error, kBaseFieldOrder),
        NaturalMagnitude((kBaseFieldOrder - 1) / 2));
}

bool phase_fits(const NaturalMagnitude &phase,
                std::span<const std::uint64_t> active_moduli) {
    const NaturalMagnitude twice =
        NaturalMagnitude::multiply(phase, std::uint64_t{2});
    return twice < NaturalMagnitude::product(active_moduli);
}

bool all_slots_are(const fhe::SlotVector &slots, const Fp &value) {
    return std::all_of(slots.begin(), slots.end(),
                       [&](const Fp &candidate) {
                           return candidate == value;
                       });
}

NaturalMagnitude plaintext_factor(
    const fhe::SlotVector &plaintext,
    const HonestPayloadNoiseCalibration &calibration) {
    if (all_slots_are(plaintext, Fp::zero())) {
        return NaturalMagnitude();
    }
    if (all_slots_are(plaintext, Fp::one())) {
        return NaturalMagnitude(1);
    }
    return power_of_two(
        calibration.plaintext_multiplication_debit_bits);
}

struct LayerGrowth {
    NaturalMagnitude factor;
};

LayerGrowth affine_growth(
    const LayeredCircuit &circuit, std::size_t layer_index,
    const AffineLayer &layer,
    const HonestPayloadNoiseCalibration &calibration) {
    const std::size_t source_size =
        layer_dimensions(circuit.layers.at(layer_index + 1U)).padded_size;
    std::vector<NaturalMagnitude> intermediate;
    intermediate.reserve(layer.intermediate_gates.size());
    const auto evaluate = [&](const AffineGate &gate) {
        NaturalMagnitude factor;
        for (const AffineTerm &term : gate.terms) {
            if (term.coefficient.is_zero()) continue;
            std::size_t debit = term.rotation == 0 ? 0 : calibration.rotation_debit_bits;
            if (!(term.coefficient == Fp::one()))
                debit += calibration.plaintext_multiplication_debit_bits;
            if (debit > kMaximumCalibrationDebitBits)
                throw std::invalid_argument("honest payload schedule: combined affine debit is too large");
            auto contribution = term.source < source_size
                ? NaturalMagnitude(1) : intermediate.at(term.source - source_size);
            contribution = NaturalMagnitude::multiply(contribution, power_of_two(debit));
            if (term.plaintext_index)
                contribution = NaturalMagnitude::multiply(contribution,
                    plaintext_factor(circuit.plaintexts.at(*term.plaintext_index), calibration));
            factor = NaturalMagnitude::add(factor, contribution);
        }
        return factor;
    };
    for (const auto &gate : layer.intermediate_gates)
        intermediate.push_back(evaluate(gate));
    NaturalMagnitude maximum;
    for (const auto &gate : layer.gates) {
        if (gate.origin == GateOrigin::Padding) continue;
        auto factor = evaluate(gate);
        if (maximum < factor) maximum = std::move(factor);
    }
    return LayerGrowth{.factor = std::move(maximum)};
}

LayerGrowth multiplication_growth(
    const LayeredCircuit &,
    const MultiplicationLayer &layer,
    const HonestPayloadNoiseCalibration &calibration) {
    NaturalMagnitude maximum;
    for (const MultiplicationGate &gate : layer.gates) {
        if (gate.origin == GateOrigin::Padding) {
            continue;
        }

        NaturalMagnitude gate_factor;
        if (gate.origin == GateOrigin::Forward) {
            gate_factor = power_of_two(0);
        } else {
            gate_factor = power_of_two(
                calibration.ctct_relinearized_debit_bits);
        }
        if (maximum < gate_factor) {
            maximum = std::move(gate_factor);
        }
    }
    return LayerGrowth{
        .factor = std::move(maximum),
    };
}

LayerGrowth layer_growth(
    const LayeredCircuit &circuit, std::size_t layer,
    const HonestPayloadNoiseCalibration &calibration) {
    if (const auto *affine =
            std::get_if<AffineLayer>(&circuit.layers.at(layer))) {
        return affine_growth(circuit, layer, *affine, calibration);
    }
    if (const auto *multiplication =
            std::get_if<MultiplicationLayer>(&circuit.layers.at(layer))) {
        return multiplication_growth(circuit, *multiplication,
                                     calibration);
    }
    throw std::logic_error(
        "honest payload schedule: input layer cannot be evaluated");
}

struct LayerNoiseEvaluation {
    std::vector<NaturalMagnitude> output_errors;
    NaturalMagnitude maximum_evaluated_error;
    NaturalMagnitude maximum_output_error;
    bool completed_relinearized_payload_multiplication = false;
};

void retain_maximum(NaturalMagnitude &maximum,
                    const NaturalMagnitude &candidate) {
    if (maximum < candidate) maximum = candidate;
}

// Keep only adjacent layers and the current affine program's intermediates.
// An error envelope of zero denotes a public value: fresh encrypted inputs
// have a positive bound, and encrypted operations never cancel an envelope.
// The converse is not guaranteed: ignored public-zero annihilation can leave
// a positive overestimate for a public value. Ignoring such cancellations
// avoids materializing public slot vectors or tracking ciphertext identities.
LayerNoiseEvaluation evaluate_layer_noise(
    const LayeredCircuit &circuit, std::size_t layer_index,
    std::span<const NaturalMagnitude> source_errors,
    std::span<const NaturalMagnitude> plaintext_factors,
    const HonestPayloadNoiseCalibration &calibration) {
    const Layer &layer = circuit.layers.at(layer_index);
    LayerNoiseEvaluation result;
    result.output_errors.resize(layer_dimensions(layer).padded_size);
    if (const auto *affine = std::get_if<AffineLayer>(&layer)) {
        std::vector<NaturalMagnitude> intermediate;
        intermediate.reserve(affine->intermediate_gates.size());
        const auto evaluate = [&](const AffineGate &gate) {
            NaturalMagnitude error;
            for (const AffineTerm &term : gate.terms) {
                if (term.coefficient.is_zero()) continue;
                NaturalMagnitude contribution = term.source < source_errors.size()
                    ? source_errors[term.source]
                    : intermediate.at(term.source - source_errors.size());
                std::size_t debit = term.rotation == 0
                    ? 0 : calibration.rotation_debit_bits;
                if (!(term.coefficient == Fp::one()))
                    debit += calibration.plaintext_multiplication_debit_bits;
                if (debit > kMaximumCalibrationDebitBits)
                    throw std::invalid_argument(
                        "honest payload schedule: combined affine debit is too large");
                contribution = NaturalMagnitude::shift_left(contribution, debit);
                // Rotation and scalar multiplication execute before a
                // possible zero diagonal mask. Their phase must also fit.
                retain_maximum(result.maximum_evaluated_error, contribution);
                if (term.plaintext_index) {
                    contribution = NaturalMagnitude::multiply(
                        contribution, plaintext_factors[*term.plaintext_index]);
                    retain_maximum(result.maximum_evaluated_error, contribution);
                }
                error = NaturalMagnitude::add(error, contribution);
            }
            // Public affine constants add no canonical error, matching the
            // calibrated HonestNoiseEnvelopeBackend's plaintext addition.
            retain_maximum(result.maximum_evaluated_error, error);
            return error;
        };
        for (const AffineGate &gate : affine->intermediate_gates)
            intermediate.push_back(evaluate(gate));
        for (std::size_t wire = 0; wire < affine->gates.size(); ++wire) {
            if (affine->gates[wire].origin == GateOrigin::Padding) continue;
            result.output_errors[wire] = evaluate(affine->gates[wire]);
            retain_maximum(result.maximum_output_error, result.output_errors[wire]);
        }
        return result;
    }
    if (const auto *multiplication = std::get_if<MultiplicationLayer>(&layer)) {
        const std::size_t pair_count = multiplication->dimensions.padded_size;
        for (std::size_t wire = 0; wire < multiplication->gates.size(); ++wire) {
            const GateOrigin origin = multiplication->gates[wire].origin;
            if (origin == GateOrigin::Padding) continue;
            const NaturalMagnitude &left = source_errors[wire];
            if (origin == GateOrigin::Forward) {
                result.output_errors[wire] = left;
            } else {
                const NaturalMagnitude &right = source_errors[pair_count + wire];
                // A payload product can dispatch to plaintext multiplication
                // after a public-zero annihilation and affine constant. A
                // positive bound is not proof that its value is encrypted;
                // cover both operation debits, even for two positive bounds.
                const std::size_t debit = std::max(
                    calibration.ctct_relinearized_debit_bits,
                    calibration.plaintext_multiplication_debit_bits);
                result.output_errors[wire] = NaturalMagnitude::shift_left(
                    left < right ? right : left, debit);
                result.completed_relinearized_payload_multiplication |=
                    !left.is_zero() && !right.is_zero();
            }
            retain_maximum(result.maximum_output_error, result.output_errors[wire]);
        }
        result.maximum_evaluated_error = result.maximum_output_error;
        return result;
    }
    throw std::logic_error(
        "honest payload schedule: input layer cannot be evaluated");
}

NaturalMagnitude switched_error(
    const NaturalMagnitude &input, std::uint64_t dropped_modulus,
    std::uint64_t rounding_error_bound) {
    return NaturalMagnitude::add(
        NaturalMagnitude::divide_ceil(input, dropped_modulus),
        NaturalMagnitude(rounding_error_bound));
}

std::uint64_t switch_event_count(std::size_t value) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                "honest payload schedule: switch-event count exceeds u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

std::uint64_t checked_switch_event_sum(std::uint64_t current,
                                       std::uint64_t added) {
    if (added > std::numeric_limits<std::uint64_t>::max() - current) {
        throw std::overflow_error(
            "honest payload schedule: switch-event count overflows");
    }
    return current + added;
}

std::uint64_t checked_switch_event_product(std::size_t left,
                                           std::size_t right) {
    const std::uint64_t converted_left = switch_event_count(left);
    const std::uint64_t converted_right = switch_event_count(right);
    if (converted_left != 0 &&
        converted_right >
            std::numeric_limits<std::uint64_t>::max() / converted_left) {
        throw std::overflow_error(
            "honest payload schedule: switch-event product overflows");
    }
    return converted_left * converted_right;
}

std::size_t checked_size_product(std::size_t left, std::size_t right,
                                 const char *description) {
    if (left != 0 &&
        right > std::numeric_limits<std::size_t>::max() / left) {
        throw std::overflow_error(
            std::string("honest payload schedule: ") + description +
            " overflows");
    }
    return left * right;
}

std::size_t checked_size_sum(std::size_t left, std::size_t right,
                             const char *description) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        throw std::overflow_error(
            std::string("honest payload schedule: ") + description +
            " overflows");
    }
    return left + right;
}

HonestBaseProofMessageTopology
derive_message_topology_from_source_support(
    const LayeredCircuit &circuit, std::size_t reduction_layer,
    const LayerWireSupport &source_support);

HonestBaseProofNormalizationPlan
derive_base_proof_normalization_plan_impl(
    const LayeredCircuit &circuit, const FheEvaluationPlan &plan) {
    plan.validate(circuit);
    const CanonicalTraceLayout trace_layout =
        canonical_trace_layout(circuit);
    HonestBaseProofNormalizationPlan result;
    result.reductions.reserve(circuit.layers.size() - 1U);
    for (std::size_t reduction_layer = 0;
         reduction_layer + 1U < circuit.layers.size(); ++reduction_layer) {
        const std::size_t source_layer = reduction_layer + 1U;
        const std::size_t natural_source_depth =
            plan.trace.required_mult_depth_by_layer[source_layer];
        const std::size_t proof_ingress_depth =
            plan.proof_ingress_mult_depth_by_layer[source_layer];
        if (natural_source_depth ==
                std::numeric_limits<std::size_t>::max() ||
            proof_ingress_depth ==
                std::numeric_limits<std::size_t>::max()) {
            throw std::overflow_error(
                "honest payload schedule: Base source limb count overflows");
        }
        const std::size_t natural_source_limbs = natural_source_depth + 1U;
        const std::size_t proof_ingress_limbs = proof_ingress_depth + 1U;
        if (proof_ingress_limbs > natural_source_limbs) {
            throw std::logic_error(
                "honest payload schedule: Base proof ingress exceeds the "
                "natural source level");
        }
        const std::size_t live_source_ciphertexts =
            trace_layout.value_counts[source_layer]
                .encrypted_ciphertexts;
        const std::size_t padded_source_wires =
            layer_dimensions(circuit.layers[source_layer]).padded_size;
        if (!std::has_single_bit(padded_source_wires)) {
            throw std::logic_error(
                "honest payload schedule: Base source width is not a "
                "power of two");
        }
        const LayerKind kind = layer_kind(circuit.layers[reduction_layer]);
        const std::size_t padded_output_wires =
            layer_dimensions(circuit.layers[reduction_layer]).padded_size;
        if (!std::has_single_bit(padded_output_wires)) {
            throw std::logic_error(
                "honest payload schedule: Base output width is not a "
                "power of two");
        }
        const std::size_t output_wire_variables =
            std::bit_width(padded_output_wires) - 1U;
        const std::size_t wire_variables =
            kind == LayerKind::Multiplication
                ? output_wire_variables
                : std::bit_width(padded_source_wires) - 1U;
        const HonestBaseProofMessageTopology message_topology =
            derive_message_topology_from_source_support(
                circuit, reduction_layer,
                trace_layout.wire_support[source_layer]);
        HonestBaseProofNormalizationLayerPlan layer{
            .reduction_layer = reduction_layer,
            .kind = kind,
            .natural_source_rns_limb_count = natural_source_limbs,
            .proof_ingress_rns_limb_count = proof_ingress_limbs,
            .live_source_ciphertext_count = live_source_ciphertexts,
            .wire_variables = wire_variables,
            .round_extension_ciphertext_count =
                message_topology.round_extension_message_count,
            .terminal_extension_ciphertext_count =
                message_topology.terminal_extension_message_count,
            .public_zero_extension_message_count =
                message_topology.public_zero_extension_message_count,
            .message_coordinate_masks =
                message_topology.message_coordinate_masks,
            .base_ciphertext_count =
                message_topology.base_ciphertext_count,
            .ingress_switch_events = checked_switch_event_product(
                live_source_ciphertexts,
                natural_source_limbs - proof_ingress_limbs),
            .proof_message_switch_events = checked_switch_event_product(
                message_topology.base_ciphertext_count,
                proof_ingress_depth),
        };
        layer.switch_events = checked_switch_event_sum(
            layer.ingress_switch_events,
            layer.proof_message_switch_events);
        result.ingress_switch_events = checked_switch_event_sum(
            result.ingress_switch_events, layer.ingress_switch_events);
        result.proof_message_switch_events = checked_switch_event_sum(
            result.proof_message_switch_events,
            layer.proof_message_switch_events);
        result.switch_events = checked_switch_event_sum(
            result.switch_events, layer.switch_events);
        result.reductions.push_back(std::move(layer));
    }
    return result;
}

void validate_exact_chain(
    std::span<const std::uint64_t> data_moduli_low_to_high,
    std::size_t ring_degree) {
    if (data_moduli_low_to_high.empty()) {
        throw std::invalid_argument(
            "honest payload schedule: data modulus chain is empty");
    }
    if (data_moduli_low_to_high.front() != kOuterFieldOrder) {
        throw std::invalid_argument(
            "honest payload schedule: q_0 must be the Laminate outer field");
    }
    if (ring_degree > std::numeric_limits<std::size_t>::max() / 2) {
        throw std::invalid_argument(
            "honest payload schedule: ring degree is too large");
    }
    const std::uint64_t ntt_order =
        static_cast<std::uint64_t>(2 * ring_degree);
    std::unordered_set<std::uint64_t> unique;
    for (const std::uint64_t modulus : data_moduli_low_to_high) {
        if (modulus < 3 || modulus % 2 == 0 ||
            std::bit_width(modulus) > 60 ||
            modulus % kBaseFieldOrder != 1 ||
            modulus % ntt_order != 1) {
            throw std::invalid_argument(
                "honest payload schedule: each exact data modulus must be "
                "an odd at-most-60-bit value congruent to one modulo t and "
                "2N");
        }
        if (!unique.insert(modulus).second) {
            throw std::invalid_argument(
                "honest payload schedule: data moduli must be distinct");
        }
    }
}

} // namespace

namespace {

static_assert(kExtensionDegree <= 8);
constexpr HonestBaseProofCoordinateMask kFullExtensionCoordinateMask =
    static_cast<HonestBaseProofCoordinateMask>(
        (std::uint16_t{1} << kExtensionDegree) - 1U);
constexpr HonestBaseProofCoordinateMask kBaseCoordinateMask = 1U;

std::vector<HonestBaseProofCoordinateMask> repeated_message_support(
    std::size_t count, HonestBaseProofCoordinateMask first,
    HonestBaseProofCoordinateMask later) {
    std::vector<HonestBaseProofCoordinateMask> result(count, later);
    if (!result.empty()) {
        result.front() = first;
    }
    return result;
}

void finalize_message_topology(HonestBaseProofMessageTopology &topology,
                               LayerKind kind,
                               std::size_t wire_variables) {
    topology.public_zero_extension_message_count = 0;
    topology.base_ciphertext_count = 0;
    topology.message_coordinate_masks.clear();

    for (HonestBaseProofMessageFamilyTopology &family : topology.families) {
        if (family.message_coordinate_masks.size() !=
            family.extension_message_count) {
            throw std::logic_error(
                "honest Base proof topology: family support has wrong "
                "length");
        }
        family.public_zero_extension_message_count = 0;
        family.base_ciphertext_count = 0;
        for (const HonestBaseProofCoordinateMask mask :
             family.message_coordinate_masks) {
            if ((static_cast<std::uint16_t>(mask) &
                 ~static_cast<std::uint16_t>(
                     kFullExtensionCoordinateMask)) != 0) {
                throw std::logic_error(
                    "honest Base proof topology: message mask exceeds the "
                    "extension degree");
            }
            family.public_zero_extension_message_count +=
                static_cast<std::size_t>(mask == 0);
            family.base_ciphertext_count = checked_size_sum(
                family.base_ciphertext_count,
                static_cast<std::size_t>(std::popcount(mask)),
                "Base family base-ciphertext count");
        }
        topology.public_zero_extension_message_count = checked_size_sum(
            topology.public_zero_extension_message_count,
            family.public_zero_extension_message_count,
            "Base public-zero message count");
        topology.base_ciphertext_count = checked_size_sum(
            topology.base_ciphertext_count, family.base_ciphertext_count,
            "Base proof base-ciphertext count");
    }

    const auto append_interleaved = [&](std::size_t first_family,
                                        std::size_t second_family) {
        for (std::size_t round = 0; round < wire_variables; ++round) {
            topology.message_coordinate_masks.push_back(
                topology.families.at(first_family)
                    .message_coordinate_masks.at(round));
            topology.message_coordinate_masks.push_back(
                topology.families.at(second_family)
                    .message_coordinate_masks.at(round));
        }
    };
    if (kind == LayerKind::Affine) {
        append_interleaved(0, 1);
        topology.message_coordinate_masks.push_back(
            topology.families.at(2)
                .message_coordinate_masks.front());
    } else if (kind == LayerKind::Multiplication) {
        append_interleaved(0, 1);
        topology.message_coordinate_masks.push_back(
            topology.families.at(2)
                .message_coordinate_masks.front());
        topology.message_coordinate_masks.push_back(
            topology.families.at(3)
                .message_coordinate_masks.front());
    } else {
        throw std::invalid_argument(
            "honest Base proof topology: unknown layer kind");
    }
    const std::size_t expected_messages = checked_size_sum(
        topology.round_extension_message_count,
        topology.terminal_extension_message_count,
        "Base extension-message count");
    if (topology.message_coordinate_masks.size() !=
        expected_messages) {
        throw std::logic_error(
            "honest Base proof topology: transcript support has wrong "
            "length");
    }
}

void assign_transcript_support(HonestBaseProofMessageTopology &topology,
                               LayerKind kind,
                               std::size_t wire_variables,
                               std::span<const HonestBaseProofCoordinateMask>
                                   support) {
    const std::size_t expected_size = checked_size_sum(
        topology.round_extension_message_count,
        topology.terminal_extension_message_count,
        "Base stored extension-message count");
    if (support.size() != expected_size) {
        throw std::invalid_argument(
            "honest Base proof topology: stored transcript support has "
            "wrong length");
    }
    std::size_t position = 0;
    const auto assign_interleaved = [&](std::size_t first_family,
                                        std::size_t second_family) {
        for (std::size_t round = 0; round < wire_variables; ++round) {
            topology.families.at(first_family)
                .message_coordinate_masks.at(round) =
                support[position++];
            topology.families.at(second_family)
                .message_coordinate_masks.at(round) =
                support[position++];
        }
    };
    if (kind == LayerKind::Affine) {
        assign_interleaved(0, 1);
        topology.families.at(2)
            .message_coordinate_masks.front() =
            support[position++];
    } else if (kind == LayerKind::Multiplication) {
        assign_interleaved(0, 1);
        topology.families.at(2)
            .message_coordinate_masks.front() =
            support[position++];
        topology.families.at(3)
            .message_coordinate_masks.front() =
            support[position++];
    }
    if (position != support.size()) {
        throw std::invalid_argument(
            "honest Base proof topology: stored transcript support has "
            "wrong length");
    }
}

} // namespace

namespace {

static HonestBaseProofMessageTopology make_dense_message_topology(
    LayerKind kind, std::size_t wire_variables) {
    HonestBaseProofMessageTopology result;
    if (kind == LayerKind::Affine) {
        result.families = {
            {HonestBaseProofMessageFamily::AffineRoundAtOne,
             wire_variables, 0,
             std::vector<HonestBaseProofCoordinateMask>(
                 wire_variables, kFullExtensionCoordinateMask), 0},
            {HonestBaseProofMessageFamily::AffineRoundAtTwo,
             wire_variables, 0,
             std::vector<HonestBaseProofCoordinateMask>(
                 wire_variables, kFullExtensionCoordinateMask), 0},
            {HonestBaseProofMessageFamily::AffineTerminal, 1U, 0,
             {wire_variables == 0 ? kBaseCoordinateMask
                                  : kFullExtensionCoordinateMask},
             0},
        };
        result.round_extension_message_count = checked_size_product(
            wire_variables, 2U, "Base affine round-message count");
        result.terminal_extension_message_count = 1U;
    } else if (kind == LayerKind::Multiplication) {
        const HonestBaseProofCoordinateMask first_round_message_mask =
            wire_variables == 1U
                ? kBaseCoordinateMask
                : kFullExtensionCoordinateMask;
        result.families = {
            {HonestBaseProofMessageFamily::MultiplicationRoundPrimary,
             wire_variables, 0,
             repeated_message_support(wire_variables,
                                      first_round_message_mask,
                                      kFullExtensionCoordinateMask), 0},
            {HonestBaseProofMessageFamily::MultiplicationRoundAtTwo,
             wire_variables, 0,
             repeated_message_support(wire_variables,
                                      first_round_message_mask,
                                      kFullExtensionCoordinateMask), 0},
            {HonestBaseProofMessageFamily::MultiplicationLeftTerminal,
             1U, 0,
             {wire_variables == 0 ? kBaseCoordinateMask
                                  : kFullExtensionCoordinateMask},
             0},
            {HonestBaseProofMessageFamily::MultiplicationRightTerminal,
             1U, 0,
             {wire_variables == 0 ? kBaseCoordinateMask
                                  : kFullExtensionCoordinateMask},
             0},
        };
        result.round_extension_message_count = checked_size_product(
            wire_variables, 2U,
            "Base multiplication round-message count");
        result.terminal_extension_message_count = 2U;
    } else {
        throw std::invalid_argument(
            "honest Base proof topology: unknown layer kind");
    }

    finalize_message_topology(result, kind, wire_variables);
    return result;
}

HonestBaseProofMessageTopology
derive_message_topology_from_source_support(
    const LayeredCircuit &circuit, std::size_t reduction_layer,
    const LayerWireSupport &source_support) {
    if (reduction_layer + 1U >= circuit.layers.size()) {
        throw std::out_of_range(
            "honest Base proof topology: reduction layer is out of range");
    }
    const LayerKind kind = layer_kind(circuit.layers[reduction_layer]);
    const std::size_t source_width =
        layer_dimensions(circuit.layers[reduction_layer + 1U]).padded_size;
    const std::size_t output_width =
        layer_dimensions(circuit.layers[reduction_layer]).padded_size;
    if (!std::has_single_bit(source_width) ||
        !std::has_single_bit(output_width)) {
        throw std::logic_error(
            "honest Base proof topology: non-power-of-two layer width");
    }
    const std::size_t wire_variables =
        kind == LayerKind::Multiplication
            ? std::bit_width(output_width) - 1U
            : std::bit_width(source_width) - 1U;
    HonestBaseProofMessageTopology result =
        make_dense_message_topology(kind, wire_variables);
    if (wire_variables == 0) {
        return result;
    }

    validate_layer_wire_support(source_support);
    if (source_support.padded_wire_count != source_width) {
        throw std::logic_error(
            "honest Base proof topology: source support has the wrong "
            "padded width");
    }
    if (kind == LayerKind::Affine) {
        const auto &layer = std::get<AffineLayer>(
            circuit.layers[reduction_layer]);
        std::vector<std::size_t> normalized_term_sources;
        if (!layer.intermediate_gates.empty()) {
            // Reverse structural support reaches the previous circuit layer;
            // local node IDs are not source-wire addresses. This does not
            // materialize slot vectors or enumerate composed paths.
            const auto structure = gates::DirectGateMle(circuit)
                .affine_structure(reduction_layer);
            normalized_term_sources.reserve(structure.terms.size());
            for (const auto &term : structure.terms)
                normalized_term_sources.push_back(term.source);
        } else {
            for (const AffineGate &gate : layer.gates) {
                std::vector<AffineTerm> terms = gate.terms;
                std::sort(terms.begin(), terms.end(),
                          [](const AffineTerm &left,
                             const AffineTerm &right) {
                    return std::tie(left.source, left.rotation, left.plaintext_index) <
                           std::tie(right.source, right.rotation, right.plaintext_index);
                });
                for (std::size_t begin = 0; begin < terms.size();) {
                    std::size_t end = begin + 1U;
                    Fp coefficient = terms[begin].coefficient;
                    while (end < terms.size() &&
                           terms[end].source == terms[begin].source &&
                           terms[end].rotation == terms[begin].rotation &&
                           terms[end].plaintext_index == terms[begin].plaintext_index) {
                        coefficient += terms[end].coefficient;
                        ++end;
                    }
                    if (!coefficient.is_zero()) {
                        normalized_term_sources.push_back(
                            terms[begin].source);
                    }
                    begin = end;
                }
            }
        }

        auto &at_one =
            result.families.at(0).message_coordinate_masks;
        auto &at_two =
            result.families.at(1).message_coordinate_masks;
        for (std::size_t round = 0; round < wire_variables; ++round) {
            const std::size_t bit = wire_variables - 1U - round;
            const std::size_t suffix_count =
                source_width >> (round + 1U);
            const std::size_t suffix_mask = suffix_count - 1U;
            std::vector<bool> live_suffix(suffix_count, false);
            std::vector<bool> live_high_suffix(suffix_count, false);
            for (std::size_t ordinal = 0;
                 ordinal < source_support.live_wire_count; ++ordinal) {
                const std::size_t source =
                    source_support.padded_index_of(ordinal);
                const std::size_t suffix = source & suffix_mask;
                live_suffix[suffix] = true;
                if (((source >> bit) & std::size_t{1}) != 0) {
                    live_high_suffix[suffix] = true;
                }
            }
            bool one_is_live = false;
            bool two_is_live = false;
            for (const std::size_t source : normalized_term_sources) {
                const std::size_t suffix = source & suffix_mask;
                two_is_live = two_is_live || live_suffix[suffix];
                one_is_live = one_is_live ||
                    (((source >> bit) & std::size_t{1}) != 0 &&
                     live_high_suffix[suffix]);
            }
            if (!one_is_live) {
                at_one[round] = 0;
            }
            if (!two_is_live) {
                at_two[round] = 0;
            }
        }
        if (output_width == 1U && circuit.shape.slot_count == 1U) {
            if (at_one.front() != 0) {
                at_one.front() = kBaseCoordinateMask;
            }
            if (at_two.front() != 0) {
                at_two.front() = kBaseCoordinateMask;
            }
        }
        finalize_message_topology(result, kind, wire_variables);
        return result;
    }
    if (kind != LayerKind::Multiplication) {
        throw std::logic_error(
            "honest Base proof topology: reduction layer is neither "
            "affine nor multiplication");
    }
    const auto &layer = std::get<MultiplicationLayer>(
        circuit.layers[reduction_layer]);
    bool has_live_contribution = false;
    for (std::size_t pair = 0; pair < layer.gates.size(); ++pair) {
        const MultiplicationGate &gate = layer.gates[pair];
        if (gate.origin == GateOrigin::Padding) {
            continue;
        }
        if (!source_support.is_live(pair) ||
            !source_support.is_live(output_width + pair)) {
            throw std::logic_error(
                "honest Base proof topology: multiplication is not the "
                "canonical dense-halves relation");
        }
        has_live_contribution = true;
    }

    auto &primary = result.families.at(0).message_coordinate_masks;
    auto &at_two = result.families.at(1).message_coordinate_masks;
    for (std::size_t round = 0; round < wire_variables; ++round) {
        // The transmitted primary endpoint is X=1 normally and X=0 in the
        // public singular branch tau=1. A setup-only topology must therefore
        // retain it whenever either Boolean branch can be live.
        if (!has_live_contribution) {
            primary[round] = 0;
        }
        if (!has_live_contribution) {
            at_two[round] = 0;
        }
    }
    finalize_message_topology(result, kind, wire_variables);
    return result;
}

} // namespace

HonestBaseProofMessageTopology derive_honest_base_proof_message_topology(
    const LayeredCircuit &circuit, std::size_t reduction_layer) {
    if (reduction_layer + 1U >= circuit.layers.size()) {
        throw std::out_of_range(
            "honest Base proof topology: reduction layer is out of range");
    }
    const LayerWireSupport source_support =
        canonical_layer_wire_support(circuit, reduction_layer + 1U);
    return derive_message_topology_from_source_support(
        circuit, reduction_layer, source_support);
}

HonestBaseProofMessageTopology derive_honest_base_proof_message_topology(
    const HonestBaseProofNormalizationLayerPlan &plan) {
    HonestBaseProofMessageTopology result =
        make_dense_message_topology(plan.kind, plan.wire_variables);
    assign_transcript_support(
        result, plan.kind, plan.wire_variables,
        plan.message_coordinate_masks);
    finalize_message_topology(result, plan.kind, plan.wire_variables);
    if (result.round_extension_message_count !=
            plan.round_extension_ciphertext_count ||
        result.terminal_extension_message_count !=
            plan.terminal_extension_ciphertext_count ||
        result.public_zero_extension_message_count !=
            plan.public_zero_extension_message_count ||
        result.base_ciphertext_count != plan.base_ciphertext_count) {
        throw std::invalid_argument(
            "honest Base proof topology: stored layer totals differ from "
            "per-message support");
    }
    return result;
}

std::uint64_t randomized_mod_switch_rounding_heuristic_bound(
    std::size_t ring_degree,
    std::uint64_t modeled_switch_events_upper_bound,
    std::size_t switch_model_failure_budget_bits) {
    if (ring_degree == 0 || modeled_switch_events_upper_bound == 0 ||
        switch_model_failure_budget_bits == 0 ||
        switch_model_failure_budget_bits > kMaximumCalibrationDebitBits) {
        throw std::invalid_argument(
            "honest switch heuristic: N, event bound, and failure bits "
            "must be positive and supported");
    }

    const Wide coefficient_events = checked_multiply(
        checked_multiply(Wide{2}, modeled_switch_events_upper_bound,
                         "coefficient-event count"),
        ring_degree, "coefficient-event count");
    const std::size_t coefficient_event_bits = ceil_log2(coefficient_events);
    if (switch_model_failure_budget_bits >
        std::numeric_limits<std::size_t>::max() - coefficient_event_bits) {
        throw std::overflow_error(
            "honest switch heuristic: logarithmic failure term overflows");
    }
    const std::size_t logarithm_bits =
        coefficient_event_bits + switch_model_failure_budget_bits;

    Wide numerator = checked_multiply(
        static_cast<Wide>(ring_degree) + 1U,
        kLn2UpperNumerator, "tail numerator");
    numerator = checked_multiply(
        numerator, logarithm_bits, "tail numerator");
    const Wide squared_tail = divide_ceil(
        numerator, Wide{2} * kLn2UpperDenominator);
    const Wide tail = square_root_ceil(squared_tail);
    if (tail >= std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(
            "honest switch heuristic: rounding allowance exceeds u64");
    }
    return static_cast<std::uint64_t>(tail) + 1U;
}

void HonestPayloadNoiseCalibration::validate(
    const LayeredCircuit &circuit) const {
    circuit.validate();
    if (fresh_canonical_error_bound == 0 ||
        switch_rounding_error_bound == 0 ||
        modeled_switch_events_upper_bound == 0 ||
        switch_model_failure_budget_bits == 0) {
        throw std::invalid_argument(
            "honest payload calibration: error and audit bounds must be "
            "positive");
    }
    if (ctct_relinearized_debit_bits > kMaximumCalibrationDebitBits ||
        plaintext_multiplication_debit_bits >
            kMaximumCalibrationDebitBits ||
        rotation_debit_bits > kMaximumCalibrationDebitBits ||
        maximum_switch_tax_bits > kMaximumCalibrationDebitBits ||
        switch_model_failure_budget_bits >
            kMaximumCalibrationDebitBits) {
        throw std::invalid_argument(
            "honest payload calibration: bit parameter exceeds supported "
            "range");
    }
    const std::uint64_t heuristic_bound =
        randomized_mod_switch_rounding_heuristic_bound(
            circuit.shape.slot_count,
            modeled_switch_events_upper_bound,
            switch_model_failure_budget_bits);
    if (switch_rounding_error_bound < heuristic_bound) {
        throw std::invalid_argument(
            "honest payload calibration: switch rounding allowance is "
            "below the randomized-tail deterministic-switch heuristic");
    }
}

const char *honest_base_proof_message_family_name(
    HonestBaseProofMessageFamily family) {
    switch (family) {
    case HonestBaseProofMessageFamily::AffineRoundAtOne:
        return "affine-round-at-one";
    case HonestBaseProofMessageFamily::AffineRoundAtTwo:
        return "affine-round-at-two";
    case HonestBaseProofMessageFamily::AffineTerminal:
        return "affine-terminal";
    case HonestBaseProofMessageFamily::MultiplicationRoundPrimary:
        return "multiplication-round-primary";
    case HonestBaseProofMessageFamily::MultiplicationRoundAtTwo:
        return "multiplication-round-at-two";
    case HonestBaseProofMessageFamily::MultiplicationLeftTerminal:
        return "multiplication-left-terminal";
    case HonestBaseProofMessageFamily::MultiplicationRightTerminal:
        return "multiplication-right-terminal";
    }
    return "unknown";
}

HonestBaseProofNormalizationPlan
derive_honest_base_proof_normalization_plan(
    const LayeredCircuit &circuit, const FheEvaluationPlan &plan) {
    circuit.validate();
    return derive_base_proof_normalization_plan_impl(circuit, plan);
}

void validate_honest_base_proof_normalization_plan(
    const LayeredCircuit &circuit, const FheEvaluationPlan &plan,
    const HonestBaseProofNormalizationPlan &normalization_plan) {
    const HonestBaseProofNormalizationPlan expected =
        derive_honest_base_proof_normalization_plan(circuit, plan);
    if (!(normalization_plan == expected)) {
        throw std::invalid_argument(
            "honest Base proof normalization plan: stored topology or "
            "switch count differs from exact re-derivation");
    }
}

bool honest_switch_within_tax_threshold(
    const NaturalMagnitude &input_phase_bound,
    const NaturalMagnitude &switched_phase_bound,
    std::uint64_t dropped_modulus,
    std::size_t maximum_switch_tax_bits) {
    if (dropped_modulus < 3 || dropped_modulus % 2 == 0 ||
        maximum_switch_tax_bits > kMaximumCalibrationDebitBits) {
        throw std::invalid_argument(
            "honest switch threshold: invalid modulus or bit target");
    }
    if (input_phase_bound.is_zero()) {
        throw std::invalid_argument(
            "honest switch threshold: input phase bound is zero");
    }
    const NaturalMagnitude left = NaturalMagnitude::multiply(
        switched_phase_bound, dropped_modulus);
    const NaturalMagnitude right = NaturalMagnitude::shift_left(
        input_phase_bound, maximum_switch_tax_bits);
    return at_most(left, right);
}

namespace {

void apply_honest_base_proof_ingress_depths_impl(
    const LayeredCircuit &circuit, HonestPayloadNoiseSchedule &schedule,
    std::span<const std::size_t> proof_ingress_mult_depth_by_layer,
    bool enforce_event_cap) {
    if (schedule.base_proof_noise_assessment) {
        throw std::invalid_argument(
            "honest payload schedule: changing proof ingress would stale "
            "the attached Base proof-noise assessment");
    }
    if (proof_ingress_mult_depth_by_layer.size() !=
        circuit.layers.size()) {
        throw std::invalid_argument(
            "honest payload schedule: expected one proof-ingress depth per "
            "layer");
    }
    schedule.evaluation_plan.proof_ingress_mult_depth_by_layer.assign(
        proof_ingress_mult_depth_by_layer.begin(),
        proof_ingress_mult_depth_by_layer.end());
    schedule.evaluation_plan.validate(circuit);
    schedule.base_proof_normalization_plan =
        derive_honest_base_proof_normalization_plan(
            circuit, schedule.evaluation_plan);
    schedule.modeled_base_proof_ingress_switch_events =
        schedule.base_proof_normalization_plan.ingress_switch_events;
    schedule.modeled_base_proof_message_switch_events =
        schedule.base_proof_normalization_plan.proof_message_switch_events;
    schedule.modeled_base_proof_switch_events =
        schedule.base_proof_normalization_plan.switch_events;
    schedule.modeled_switch_events = checked_switch_event_sum(
        schedule.modeled_payload_switch_events,
        schedule.modeled_base_proof_switch_events);
    if (enforce_event_cap &&
        schedule.modeled_switch_events >
            schedule.calibration.modeled_switch_events_upper_bound) {
        throw std::invalid_argument(
            "honest payload schedule: setup rounding calibration covers "
            "fewer switch events than the derived schedule");
    }
}

HonestPayloadNoiseSchedule derive_honest_payload_noise_schedule_impl(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    const HonestPayloadNoiseCalibration &calibration,
    bool enforce_event_cap) {
    calibration.validate(circuit);
    validate_exact_chain(data_moduli_low_to_high,
                         circuit.shape.slot_count);
    if (calibration.proof_suffix_level_reserve >=
        data_moduli_low_to_high.size()) {
        throw std::invalid_argument(
            "honest payload schedule: exact chain cannot hold the proof "
            "suffix reserve");
    }

    HonestPayloadNoiseSchedule result;
    result.calibration = calibration;
    result.data_moduli_low_to_high.assign(
        data_moduli_low_to_high.begin(), data_moduli_low_to_high.end());
    result.fresh_modulus_product_bits =
        NaturalMagnitude::product(data_moduli_low_to_high).bit_count();
    result.evaluation_plan = FheEvaluationPlan{
        .trace = TraceEncryptionPlan{std::vector<std::size_t>(
            circuit.layers.size(), 0)},
        .proof_ingress_mult_depth_by_layer =
            std::vector<std::size_t>(circuit.layers.size(), 0),
        .modulus_switches_after_layer =
            std::vector<std::size_t>(circuit.layers.size(), 0),
    };

    std::size_t active_limbs = data_moduli_low_to_high.size();
    NaturalMagnitude error(calibration.fresh_canonical_error_bound);
    result.fresh_phase_fits = phase_fits(
        canonical_phase(error), data_moduli_low_to_high.first(active_limbs));
    bool all_phases_fit = result.fresh_phase_fits;

    const std::size_t input_layer = circuit.layers.size() - 1;
    std::vector<NaturalMagnitude> source_errors(
        layer_dimensions(circuit.layers[input_layer]).padded_size);
    for (std::size_t wire = 0;
         wire < layer_dimensions(circuit.layers[input_layer]).logical_size;
         ++wire)
        source_errors[wire] = error;
    std::vector<NaturalMagnitude> plaintext_factors;
    plaintext_factors.reserve(circuit.plaintexts.size());
    for (const auto &plaintext : circuit.plaintexts)
        plaintext_factors.push_back(plaintext_factor(plaintext, calibration));
    result.evaluation_plan.trace.required_mult_depth_by_layer[input_layer] =
        active_limbs - 1;
    result.layers_in_evaluation_order.reserve(input_layer);

    for (std::size_t source_layer = input_layer; source_layer > 0;
         --source_layer) {
        const std::size_t output_layer = source_layer - 1;
        LayerGrowth growth = layer_growth(circuit, output_layer, calibration);
        LayerNoiseEvaluation evaluation = evaluate_layer_noise(
            circuit, output_layer, source_errors, plaintext_factors, calibration);
        const NaturalMagnitude &evaluated = evaluation.maximum_evaluated_error;
        NaturalMagnitude evaluated_phase = canonical_phase(evaluated);

        HonestPayloadLayerSchedule report{
            .layer = output_layer,
            .kind = layer_kind(circuit.layers[output_layer]),
            .layer_error_growth_factor = growth.factor,
            .input_canonical_error_bound = error,
            .evaluated_canonical_error_bound = evaluated,
            .output_canonical_error_bound = evaluation.maximum_output_error,
            .evaluated_phase_bound = evaluated_phase,
            .output_phase_bound = canonical_phase(evaluation.maximum_output_error),
            .input_rns_limb_count = active_limbs,
            .output_rns_limb_count = active_limbs,
            .completed_relinearized_payload_multiplication =
                evaluation.completed_relinearized_payload_multiplication,
            .evaluated_phase_fits = phase_fits(
                evaluated_phase,
                data_moduli_low_to_high.first(active_limbs)),
            .output_phase_fits = false,
        };

        if (evaluation.completed_relinearized_payload_multiplication) {
            const std::uint64_t dropped =
                data_moduli_low_to_high[active_limbs - 1];
            NaturalMagnitude candidate_error = switched_error(
                evaluated, dropped,
                calibration.switch_rounding_error_bound);
            NaturalMagnitude candidate_phase =
                canonical_phase(candidate_error);
            report.dropped_modulus = dropped;
            report.threshold_left = NaturalMagnitude::multiply(
                candidate_phase, dropped);
            report.threshold_right = NaturalMagnitude::shift_left(
                evaluated_phase,
                calibration.maximum_switch_tax_bits);

            if (active_limbs <=
                calibration.proof_suffix_level_reserve + 1) {
                report.decision =
                    HonestPayloadSwitchDecision::RetainForProofSuffix;
            } else if (honest_switch_within_tax_threshold(
                           evaluated_phase, candidate_phase, dropped,
                           calibration.maximum_switch_tax_bits)) {
                report.decision = HonestPayloadSwitchDecision::SwitchNow;
                report.output_canonical_error_bound = candidate_error;
                report.output_phase_bound = candidate_phase;
                --active_limbs;
                report.output_rns_limb_count = active_limbs;
                for (NaturalMagnitude &wire_error : evaluation.output_errors) {
                    // Public constants and padding have no ciphertext to
                    // switch, and must not acquire the rounding allowance.
                    if (!wire_error.is_zero())
                        wire_error = switched_error(
                            wire_error, dropped,
                            calibration.switch_rounding_error_bound);
                }
                result.evaluation_plan
                    .modulus_switches_after_layer[output_layer] = 1;
                const std::size_t switched_ciphertexts =
                    layer_dimensions(circuit.layers[output_layer])
                        .logical_size;
                result.modeled_payload_switch_events =
                    checked_switch_event_sum(
                        result.modeled_payload_switch_events,
                        switch_event_count(switched_ciphertexts));
                result.switch_points.push_back(HonestPayloadSwitchPoint{
                    .after_layer = output_layer,
                    .dropped_modulus = dropped,
                    .switched_ciphertext_count = switched_ciphertexts,
                    .input_rns_limb_count = active_limbs + 1,
                    .output_rns_limb_count = active_limbs,
                    .input_canonical_error_bound = evaluated,
                    .output_canonical_error_bound = candidate_error,
                });
            } else {
                report.decision =
                    HonestPayloadSwitchDecision::RetainForThreshold;
            }
        }

        report.output_phase_fits = phase_fits(
            report.output_phase_bound,
            data_moduli_low_to_high.first(active_limbs));
        all_phases_fit = all_phases_fit && report.evaluated_phase_fits &&
                         report.output_phase_fits;
        error = report.output_canonical_error_bound;
        source_errors = std::move(evaluation.output_errors);
        result.evaluation_plan.trace
            .required_mult_depth_by_layer[output_layer] = active_limbs - 1;
        result.layers_in_evaluation_order.push_back(std::move(report));
    }

    result.all_modeled_phases_fit = all_phases_fit;
    result.proof_suffix_reserve_preserved =
        active_limbs >= calibration.proof_suffix_level_reserve + 1;
    const std::size_t proof_ingress_depth =
        calibration.proof_suffix_level_reserve;
    // Layer 0 is returned for client decryption and is never a reverse-GKR
    // source. Keep that output at the level produced by payload evaluation;
    // only source layers enter the proof suffix.
    result.evaluation_plan.proof_ingress_mult_depth_by_layer[0] =
        result.evaluation_plan.trace.required_mult_depth_by_layer[0];
    for (std::size_t layer = 1; layer < circuit.layers.size(); ++layer) {
        result.evaluation_plan.proof_ingress_mult_depth_by_layer[layer] =
            std::min(
                result.evaluation_plan.trace
                    .required_mult_depth_by_layer[layer],
                proof_ingress_depth);
    }
    const std::vector<std::size_t> proof_ingress =
        result.evaluation_plan.proof_ingress_mult_depth_by_layer;
    apply_honest_base_proof_ingress_depths_impl(
        circuit, result, proof_ingress, enforce_event_cap);
    validate_honest_payload_plan_parity(
        circuit, result, result.evaluation_plan);
    return result;
}

} // namespace

HonestPayloadNoiseSchedule derive_honest_payload_noise_schedule(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    const HonestPayloadNoiseCalibration &calibration) {
    return derive_honest_payload_noise_schedule_impl(
        circuit, data_moduli_low_to_high, calibration, true);
}

HonestPayloadNoiseSchedule derive_uniform_honest_base_proof_schedule(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    HonestPayloadNoiseCalibration calibration,
    std::size_t proof_ingress_rns_limbs) {
    if (proof_ingress_rns_limbs == 0 ||
        proof_ingress_rns_limbs > data_moduli_low_to_high.size()) {
        throw std::invalid_argument(
            "uniform Base proof ingress must be within the data chain");
    }
    calibration.proof_suffix_level_reserve =
        proof_ingress_rns_limbs - 1U;
    HonestPayloadNoiseSchedule schedule =
        derive_honest_payload_noise_schedule(
            circuit, data_moduli_low_to_high, calibration);
    std::vector<std::size_t> ingress =
        schedule.evaluation_plan.trace.required_mult_depth_by_layer;
    for (std::size_t source_layer = 1; source_layer < ingress.size();
         ++source_layer) {
        ingress[source_layer] = proof_ingress_rns_limbs - 1U;
    }
    // Both inputs were constructed and validated immediately above. Use the
    // internal application boundary so production setup does not re-derive the
    // same large circuit schedule twice merely to validate its own output.
    apply_honest_base_proof_ingress_depths_impl(
        circuit, schedule, ingress, true);
    schedule.base_proof_ingress_policy =
        kUniformBaseProofIngressPolicyV1;
    return schedule;
}

HonestPayloadNoiseSchedule apply_honest_base_proof_ingress_depths(
    const LayeredCircuit &circuit, HonestPayloadNoiseSchedule schedule,
    std::span<const std::size_t> proof_ingress_mult_depth_by_layer) {
    validate_honest_payload_noise_schedule_core(circuit, schedule);
    schedule.base_proof_ingress_policy = {};
    apply_honest_base_proof_ingress_depths_impl(
        circuit, schedule, proof_ingress_mult_depth_by_layer, true);
    return schedule;
}

std::uint64_t honest_base_proof_ingress_search_event_upper_bound(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    HonestPayloadNoiseCalibration calibration) {
    calibration.validate(circuit);
    std::uint64_t maximum = 0;
    for (std::size_t reserve = 0;
         reserve < data_moduli_low_to_high.size(); ++reserve) {
        calibration.proof_suffix_level_reserve = reserve;
        const HonestPayloadNoiseSchedule candidate =
            derive_honest_payload_noise_schedule_impl(
                circuit, data_moduli_low_to_high, calibration, false);
        std::uint64_t proof_domain = 0;
        for (const HonestBaseProofNormalizationLayerPlan &reduction :
             candidate.base_proof_normalization_plan.reductions) {
            const std::size_t drops =
                reduction.natural_source_rns_limb_count - 1U;
            const std::uint64_t ingress_endpoint =
                checked_switch_event_product(
                    reduction.live_source_ciphertext_count, drops);
            const std::uint64_t message_endpoint =
                checked_switch_event_product(
                    reduction.base_ciphertext_count, drops);
            proof_domain = checked_switch_event_sum(
                proof_domain,
                std::max(ingress_endpoint, message_endpoint));
        }
        maximum = std::max(
            maximum,
            checked_switch_event_sum(
                candidate.modeled_payload_switch_events, proof_domain));
    }
    return maximum;
}

void validate_honest_payload_noise_schedule_core(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule) {
    HonestPayloadNoiseSchedule detached = schedule;
    detached.base_proof_noise_assessment.reset();
    const std::string_view stored_base_proof_policy =
        detached.base_proof_ingress_policy;
    detached.base_proof_ingress_policy = {};
    const std::vector<std::size_t> stored_ingress =
        detached.evaluation_plan.proof_ingress_mult_depth_by_layer;
    HonestPayloadNoiseSchedule expected =
        derive_honest_payload_noise_schedule(
            circuit, schedule.data_moduli_low_to_high,
            schedule.calibration);
    apply_honest_base_proof_ingress_depths_impl(
        circuit, expected, stored_ingress, true);
    if (!stored_base_proof_policy.empty()) {
        if (stored_base_proof_policy !=
            kUniformBaseProofIngressPolicyV1) {
            throw std::invalid_argument(
                "honest payload schedule: unknown Base proof-ingress "
                "policy");
        }
        const std::size_t uniform_depth =
            schedule.calibration.proof_suffix_level_reserve;
        if (stored_ingress.empty() ||
            stored_ingress.front() !=
                schedule.evaluation_plan.trace
                    .required_mult_depth_by_layer.front() ||
            !std::all_of(
                stored_ingress.begin() + 1, stored_ingress.end(),
                [&](std::size_t depth) {
                    return depth == uniform_depth;
                })) {
            throw std::invalid_argument(
                "honest payload schedule: uniform Base proof-ingress "
                "policy does not match the executable vector");
        }
        expected.base_proof_ingress_policy = stored_base_proof_policy;
        detached.base_proof_ingress_policy = stored_base_proof_policy;
    }
    if (!(detached == expected)) {
        throw std::invalid_argument(
            "honest payload schedule: stored source, report, switch-point, "
            "or executable-plan field differs from exact re-derivation");
    }
}

void validate_honest_payload_noise_schedule(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule) {
    validate_honest_payload_noise_schedule_core(circuit, schedule);
    if (schedule.base_proof_noise_assessment) {
        validate_honest_base_proof_noise_assessment_binding(
            circuit, schedule);
    }
}

namespace {

std::vector<std::uint8_t> encode_canonical_prevalidated(
    const Digest &circuit_digest,
    const HonestPayloadNoiseSchedule &schedule) {
    Bytes output;
    append_label(output, "LaminateImpl/HonestPayloadNoiseSchedule/v10");
    output.insert(output.end(), circuit_digest.begin(),
                  circuit_digest.end());
    append_label(output, schedule.policy);
    append_label(output, schedule.payload_noise_model);
    append_label(output, schedule.base_proof_ingress_policy);

    const HonestPayloadNoiseCalibration &calibration =
        schedule.calibration;
    append_u64(output, calibration.fresh_canonical_error_bound);
    append_size(output, calibration.ctct_relinearized_debit_bits);
    append_size(output,
                calibration.plaintext_multiplication_debit_bits);
    append_size(output, calibration.rotation_debit_bits);
    append_size(output, calibration.maximum_switch_tax_bits);
    append_u64(output, calibration.switch_rounding_error_bound);
    append_u64(output, calibration.modeled_switch_events_upper_bound);
    append_size(output, calibration.switch_model_failure_budget_bits);
    append_size(output, calibration.proof_suffix_level_reserve);

    append_size(output, schedule.data_moduli_low_to_high.size());
    for (const std::uint64_t modulus :
         schedule.data_moduli_low_to_high) {
        append_u64(output, modulus);
    }

    const FheEvaluationPlan &plan = schedule.evaluation_plan;
    append_size(output, plan.trace.required_mult_depth_by_layer.size());
    for (const std::size_t depth :
         plan.trace.required_mult_depth_by_layer) {
        append_size(output, depth);
    }
    append_size(output, plan.proof_ingress_mult_depth_by_layer.size());
    for (const std::size_t depth :
         plan.proof_ingress_mult_depth_by_layer) {
        append_size(output, depth);
    }
    append_size(output, plan.modulus_switches_after_layer.size());
    for (const std::size_t switches :
         plan.modulus_switches_after_layer) {
        append_size(output, switches);
    }

    const HonestBaseProofNormalizationPlan &normalization =
        schedule.base_proof_normalization_plan;
    append_size(output, normalization.reductions.size());
    for (const HonestBaseProofNormalizationLayerPlan &layer :
         normalization.reductions) {
        append_size(output, layer.reduction_layer);
        append_size(output, static_cast<std::size_t>(layer.kind));
        append_size(output, layer.natural_source_rns_limb_count);
        append_size(output, layer.proof_ingress_rns_limb_count);
        append_size(output, layer.live_source_ciphertext_count);
        append_size(output, layer.wire_variables);
        append_size(output, layer.round_extension_ciphertext_count);
        append_size(output, layer.terminal_extension_ciphertext_count);
        append_size(output, layer.public_zero_extension_message_count);
        append_size(output, layer.message_coordinate_masks.size());
        for (const HonestBaseProofCoordinateMask mask :
             layer.message_coordinate_masks) {
            output.push_back(mask);
        }
        append_size(output, layer.base_ciphertext_count);
        append_u64(output, layer.ingress_switch_events);
        append_u64(output, layer.proof_message_switch_events);
        append_u64(output, layer.switch_events);
    }
    append_u64(output, normalization.ingress_switch_events);
    append_u64(output, normalization.proof_message_switch_events);
    append_u64(output, normalization.switch_events);
    return output;
}

struct CertifiedScheduleDigests {
    Digest circuit{};
    Digest schedule{};
};

CertifiedScheduleDigests certified_schedule_digests(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule) {
    CertifiedScheduleDigests result;
    result.circuit = digest(circuit);
    result.schedule = sha256(
        encode_canonical_prevalidated(result.circuit, schedule));
    return result;
}

std::optional<Digest> certified_assessment_digest(
    const HonestPayloadNoiseSchedule &schedule) {
    if (!schedule.base_proof_noise_assessment) {
        return std::nullopt;
    }
    return honest_base_proof_noise_assessment_digest(
        *schedule.base_proof_noise_assessment);
}

} // namespace

std::vector<std::uint8_t> encode_canonical(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule) {
    validate_honest_payload_noise_schedule_core(circuit, schedule);
    return encode_canonical_prevalidated(digest(circuit), schedule);
}

Digest honest_payload_noise_schedule_digest(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule) {
    const Bytes encoded = encode_canonical(circuit, schedule);
    return sha256(encoded);
}

CertifiedHonestPayloadSchedule certify_honest_payload_noise_schedule(
    const LayeredCircuit &circuit, HonestPayloadNoiseSchedule schedule) {
    validate_honest_payload_noise_schedule(circuit, schedule);
    const CertifiedScheduleDigests digests =
        certified_schedule_digests(circuit, schedule);
    std::optional<Digest> assessment_digest =
        certified_assessment_digest(schedule);
    return CertifiedHonestPayloadSchedule(
        std::move(schedule), digests.circuit, digests.schedule,
        std::move(assessment_digest));
}

CertifiedHonestPayloadSchedule
derive_certified_uniform_honest_base_proof_schedule(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    HonestPayloadNoiseCalibration calibration,
    std::size_t proof_ingress_rns_limbs) {
    HonestPayloadNoiseSchedule schedule =
        derive_uniform_honest_base_proof_schedule(
            circuit, data_moduli_low_to_high, std::move(calibration),
            proof_ingress_rns_limbs);
    const CertifiedScheduleDigests digests =
        certified_schedule_digests(circuit, schedule);
    return CertifiedHonestPayloadSchedule(
        std::move(schedule), digests.circuit, digests.schedule,
        std::nullopt);
}

void CertifiedHonestPayloadSchedule::validate_circuit_digest(
    const Digest &expected) const {
    if (state().circuit_digest != expected) {
        throw std::invalid_argument(
            "certified honest payload schedule: circuit digest mismatch");
    }
}

const CertifiedHonestPayloadSchedule::State &
CertifiedHonestPayloadSchedule::state() const {
    if (!state_) {
        throw std::logic_error(
            "certified honest payload schedule: used after move");
    }
    return *state_;
}

void validate_honest_payload_plan_parity(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    const FheEvaluationPlan &plan) {
    circuit.validate();
    plan.validate(circuit);
    if (schedule.policy != kHonestDeterministicSwitchPolicyV3 ||
        schedule.payload_noise_model != kDependencyAwareHonestPayloadNoiseModelV1 ||
        schedule.evaluation_plan.modulus_switches_after_layer !=
            plan.modulus_switches_after_layer ||
        schedule.evaluation_plan.trace.required_mult_depth_by_layer !=
            plan.trace.required_mult_depth_by_layer ||
        schedule.evaluation_plan.proof_ingress_mult_depth_by_layer !=
            plan.proof_ingress_mult_depth_by_layer) {
        throw std::invalid_argument(
            "honest payload schedule: executable FHE plan differs from "
            "setup-derived switch points or trace levels");
    }
}

const HonestPayloadChainPrefixAssessment *
HonestPayloadChainPrefixSearch::selected() const {
    if (!selected_assessment) {
        return nullptr;
    }
    if (*selected_assessment >= assessments.size()) {
        throw std::logic_error(
            "honest payload prefix search: selected index is invalid");
    }
    return &assessments[*selected_assessment];
}

HonestPayloadChainPrefixSearch assess_honest_payload_chain_prefixes(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> maximum_data_moduli_low_to_high,
    const HonestPayloadNoiseCalibration &calibration) {
    calibration.validate(circuit);
    validate_exact_chain(maximum_data_moduli_low_to_high,
                         circuit.shape.slot_count);
    if (calibration.proof_suffix_level_reserve >=
        maximum_data_moduli_low_to_high.size()) {
        throw std::invalid_argument(
            "honest payload prefix search: maximum chain cannot hold the "
            "proof suffix reserve");
    }

    HonestPayloadChainPrefixSearch result;
    const std::size_t first_limbs =
        calibration.proof_suffix_level_reserve + 1;
    result.assessments.reserve(
        maximum_data_moduli_low_to_high.size() - first_limbs + 1);
    for (std::size_t limbs = first_limbs;
         limbs <= maximum_data_moduli_low_to_high.size(); ++limbs) {
        HonestPayloadNoiseSchedule schedule =
            derive_honest_payload_noise_schedule(
                circuit, maximum_data_moduli_low_to_high.first(limbs),
                calibration);
        result.assessments.push_back(
            HonestPayloadChainPrefixAssessment{
                .fresh_rns_limb_count = limbs,
                .fresh_modulus_product_bits =
                    schedule.fresh_modulus_product_bits,
                .schedule = std::move(schedule),
            });
        if (!result.selected_assessment &&
            result.assessments.back().payload_model_accepts()) {
            result.selected_assessment = result.assessments.size() - 1;
        }
    }
    return result;
}

} // namespace laminate::payload
