#ifndef LAMINATE_BENCH_PACKED_PROCESS_PROFILE_HPP
#define LAMINATE_BENCH_PACKED_PROCESS_PROFILE_HPP

/// @file packed_process_profile.hpp
/// @brief Explicit Folded/Laned split-process benchmark profiles.

#include "laminate/params.hpp"
#include "laminate/bench/payload_profile.hpp"
#include "laminate/bench/folded_pyramid_parameters.hpp"
#include "laminate/fhe/layout/fixed_message.hpp"
#include "laminate/gkr/ciphertext_commitment.hpp"
#include "laminate/packing/outer_relation/relation.hpp"
#include "laminate/packing/proof/r1cs.hpp"
#include "laminate/payload/evaluation/fhe_evaluation_plan.hpp"
#include "laminate/protocol/packed/setup.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <numeric>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace laminate::bench {

enum class PackedProcessVariant : std::uint8_t { Folded, Laned };
using PackedProcessTier = BenchmarkPayloadTier;

/// Whether a completed run is diagnostic stress evidence or an evaluation
/// parameter point. Reduced-security tiers are deliberately explicit and are
/// never promoted based on successful execution alone.
enum class PackedProcessEvidence : std::uint8_t {
    DiagnosticStressOnly,
    Evaluation,
};

struct PackedProcessProfile {
    PackedProcessVariant variant = PackedProcessVariant::Folded;
    PackedProcessTier tier = PackedProcessTier::Quick;
    std::size_t slots = kDefaultPolyModulusDegree;
    std::size_t lanes = 0;
    std::size_t multiplicative_depth = 0;
    /// Constant balanced/Diamond width or first CT-CT pyramid width.
    std::size_t middle_width = 0;
    std::size_t input_ciphertexts = kBenchmarkDiamondInputCiphertexts;
    std::size_t output_ciphertexts =
        kBenchmarkDiamondOutputCiphertexts;
    payload::WorkloadKind workload_kind = payload::WorkloadKind::Diamond;
    std::size_t payload_operations = 0;

    std::size_t packing_repetitions = 0;
    std::size_t selected_packing_repetitions =
        kPackingWellFormednessRepetitions;
    std::size_t basefold_queries = 0;
    std::size_t selected_basefold_queries =
        kTranscriptPackingBaseFoldQueries;
    std::size_t basefold_log_rate =
        kTranscriptPackingBaseFoldLogRate;
    gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy =
        gkr::CiphertextCommitmentPolicy::poseidon_v2();

    std::size_t proof_ingress_depth = 0;
    std::vector<int> data_prime_bit_sizes;
    int special_prime_bits = 60;
    /// Nonempty only for a profile whose tested modulus ordering is fixed.
    std::vector<std::uint64_t> exact_data_primes;
    std::uint64_t exact_special_prime = 0;
    PackedProcessEvidence evidence =
        PackedProcessEvidence::DiagnosticStressOnly;

    std::size_t fresh_rns_limbs() const {
        return data_prime_bit_sizes.size();
    }

    std::size_t fresh_modulus_width_sum_bits() const {
        return std::accumulate(data_prime_bit_sizes.begin(),
                               data_prime_bit_sizes.end(),
                               std::size_t{0});
    }

    std::size_t key_modulus_width_sum_bits() const {
        return fresh_modulus_width_sum_bits() +
               static_cast<std::size_t>(special_prime_bits);
    }

    bool is_reduced_security_stress_test() const {
        return evidence == PackedProcessEvidence::DiagnosticStressOnly;
    }

    bool admits_execution() const {
        return evidence == PackedProcessEvidence::DiagnosticStressOnly ||
               !ciphertext_commitment_policy.is_diagnostic_only();
    }
};

inline bool packed_process_uses_folded_pyramid_headroom(
    const PackedProcessProfile &profile) {
    return profile.variant == PackedProcessVariant::Folded &&
           profile.tier == PackedProcessTier::TargetMulHeavy;
}

inline protocol::ConservativePackedProofIngressPolicy
packed_process_proof_ingress_policy(const PackedProcessProfile &profile) {
    return packed_process_uses_folded_pyramid_headroom(profile)
        ? protocol::ConservativePackedProofIngressPolicy::FoldedAffine4
        : protocol::ConservativePackedProofIngressPolicy::VariantDefault;
}

/// Exact, formula-only transcript-packing R1CS geometry for the canonical
/// workload selected by a process profile. This does not construct
/// the payload circuit, packing coefficients, expanded R1CS matrices, or an
/// assignment.
struct PackedProcessR1csGeometry {
    std::uint64_t ring_degree = 0;
    std::uint64_t repetitions = 0;
    std::uint64_t aligned_ciphertexts = 0;
    std::uint64_t logical_packed_outputs = 0;
    std::uint64_t physical_packed_ciphertexts = 0;
    std::uint64_t packing_digit_count = 0;
    std::uint64_t ciphertext_commitment_policy_code = 0;
    packing::ProofOfPackingR1csLedger ledger;
    std::uint64_t padded_constraints = 0;
    std::uint64_t assignment_half_size = 0;
    std::uint64_t padded_assignment_variables = 0;

    bool operator==(const PackedProcessR1csGeometry &) const = default;
};

namespace detail {

inline std::size_t packed_profile_log2_exact(std::size_t value,
                                             std::string_view label) {
    if (value == 0 || !std::has_single_bit(value)) {
        throw std::invalid_argument(std::string(label) +
                                    " is not a power of two");
    }
    return std::bit_width(value) - 1U;
}

inline std::size_t packed_profile_checked_add(std::size_t left,
                                              std::size_t right,
                                              std::string_view label) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

inline std::size_t packed_profile_checked_multiply(
    std::size_t left, std::size_t right, std::string_view label) {
    if (left != 0 &&
        right > std::numeric_limits<std::size_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left * right;
}

inline std::size_t packed_profile_checked_size(
    std::uint64_t value, std::string_view label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(label) +
                                  " exceeds size_t");
    }
    return static_cast<std::size_t>(value);
}

inline std::size_t packed_profile_bit_ceil(std::size_t value,
                                           std::string_view label) {
    if (value == 0 || value >
                          (std::size_t{1}
                           << (std::numeric_limits<std::size_t>::digits -
                               1U))) {
        throw std::overflow_error(std::string(label) + " cannot be padded");
    }
    return std::bit_ceil(value);
}

} // namespace detail

/// Exact BhIP message count for the selected power-of-two-padded payload,
/// derived directly from its public profile. The setup path checks this
/// allocation-free formula against the independently compiled circuit.
inline std::size_t packed_process_bhip_round_count(
    const PackedProcessProfile &profile) {
    if (profile.variant == PackedProcessVariant::Laned &&
        profile.tier == PackedProcessTier::TargetMulHeavy) {
        throw std::invalid_argument(
            "target-mulHeavyPyramid contains cross-slot operations and requires "
            "a Wide payload; Laned profiles require target-balancedLaned");
    }
    if (profile.slots < 2 * fhe::kFixedMessageCellCount ||
        !std::has_single_bit(profile.slots) ||
        profile.multiplicative_depth == 0 || profile.middle_width == 0 ||
        profile.input_ciphertexts == 0 ||
        profile.input_ciphertexts > profile.middle_width ||
        profile.output_ciphertexts != 1) {
        throw std::invalid_argument(
            "packed process R1CS geometry requires a canonical payload "
            "profile");
    }
    const BenchmarkPayloadProfile payload_profile =
        benchmark_payload_profile(profile.tier);
    if (profile.workload_kind != payload_profile.workload_kind ||
        profile.multiplicative_depth != payload_profile.depth ||
        profile.middle_width != payload_profile.width ||
        profile.payload_operations != payload_profile.operation_count ||
        profile.input_ciphertexts != payload_profile.inputs ||
        profile.output_ciphertexts != payload_profile.outputs) {
        throw std::invalid_argument(
            "packed process profile disagrees with its payload tier");
    }
    const std::size_t padded_inputs = detail::packed_profile_bit_ceil(
        profile.input_ciphertexts, "payload input count");
    const auto layer_variables = [&](std::size_t width) {
        const std::size_t padded_width = detail::packed_profile_bit_ceil(
            width, "payload multiplication width");
        if (profile.variant == PackedProcessVariant::Folded) {
            return detail::packed_profile_log2_exact(
                padded_width, "payload multiplication width");
        }
        if (profile.lanes == 0 || profile.lanes > profile.slots ||
            profile.slots % profile.lanes != 0) {
            throw std::invalid_argument(
                "Laned packed process profile has invalid lane geometry");
        }
        const std::size_t chunks = profile.slots / profile.lanes;
        const std::size_t logical_ciphertexts =
            (padded_width + chunks - 1U) / chunks;
        const std::size_t padded_ciphertexts =
            detail::packed_profile_bit_ceil(
                logical_ciphertexts, "Laned payload ciphertext count");
        return detail::packed_profile_log2_exact(
            detail::packed_profile_checked_multiply(
                padded_ciphertexts, profile.slots,
                "Laned payload packed domain"),
            "Laned payload packed domain");
    };
    const std::size_t slot_variables =
        detail::packed_profile_log2_exact(profile.slots, "ring degree");
    std::size_t result = 0;
    for (const std::size_t width :
         benchmark_multiplication_widths(payload_profile)) {
        std::size_t variables = layer_variables(width);
        if (profile.variant == PackedProcessVariant::Folded) {
            variables = detail::packed_profile_checked_add(
                variables, slot_variables, "Folded payload variables");
        }
        const std::size_t messages = detail::packed_profile_checked_add(
            variables, 1U, "payload reduction messages");
        result = detail::packed_profile_checked_add(
            result,
            detail::packed_profile_checked_multiply(
                2U, messages, "paired payload reduction messages"),
            "payload BhIP messages");
    }
    std::size_t input_variables = [&] {
        if (profile.variant == PackedProcessVariant::Folded) {
            return detail::packed_profile_checked_add(
                detail::packed_profile_log2_exact(
                    padded_inputs, "payload input count"),
                slot_variables, "Folded payload input variables");
        }
        const std::size_t chunks = profile.slots / profile.lanes;
        const std::size_t logical_ciphertexts =
            (padded_inputs + chunks - 1U) / chunks;
        const std::size_t padded_ciphertexts =
            detail::packed_profile_bit_ceil(
                logical_ciphertexts, "Laned payload input ciphertexts");
        return detail::packed_profile_log2_exact(
            detail::packed_profile_checked_multiply(
                padded_ciphertexts, profile.slots,
                "Laned payload packed input domain"),
            "Laned payload packed input domain");
    }();
    return detail::packed_profile_checked_add(
        result,
        detail::packed_profile_checked_add(
            input_variables, 1U, "payload input reduction messages"),
        "payload BhIP messages");
}

/// Derive every reportable R1CS dimension from the profile in O(log r) work.
inline PackedProcessR1csGeometry packed_process_r1cs_geometry(
    const PackedProcessProfile &profile) {
    const std::size_t aligned =
        packed_process_bhip_round_count(profile);
    const std::size_t maximum_row_contributions =
        profile.slots / fhe::kFixedMessageCellCount;
    const std::size_t logical_outputs =
        (aligned + maximum_row_contributions - 1U) /
        maximum_row_contributions;
    packing::LazyTernaryParameters parameters =
        packing::selected_lazy_ternary_parameters();
    parameters.repetitions = profile.packing_repetitions;
    const packing::OuterRelationPlan plan =
        packing::make_outer_relation_plan(packing::OuterRelationShape{
            .native_modulus = kOuterFieldOrder,
            .ring_degree = profile.slots,
            .aligned_ciphertexts = aligned,
            .repetitions = parameters.repetitions,
            .logical_packed_outputs = logical_outputs,
            .packing_digit_count = parameters.packing_radix.digit_count,
            .ciphertext_components =
                gkr::kCiphertextCommitmentComponents,
            .public_input_capacity_bits =
                packing::outer_relation_public_input_capacity(
                    kOuterFieldOrder),
            .ciphertext_commitment_policy =
                profile.ciphertext_commitment_policy,
        });
    const packing::ProofOfPackingR1csLedger ledger =
        packing::proof_of_packing_r1cs_dimension_ledger(plan);
    const std::size_t padded_constraints =
        detail::packed_profile_bit_ceil(
            detail::packed_profile_checked_size(
                ledger.matrix_rows, "packing R1CS matrix rows"),
            "packing R1CS matrix rows");
    const std::size_t public_side = detail::packed_profile_checked_add(
        detail::packed_profile_checked_size(
            ledger.total_public_inputs, "packing R1CS public inputs"),
        1U, "packing R1CS public side");
    const std::size_t assignment_half = detail::packed_profile_bit_ceil(
        std::max(
            public_side,
            detail::packed_profile_checked_size(
                ledger.total_witness_variables,
                "packing R1CS witness extent")),
        "packing R1CS assignment half");
    return {
        .ring_degree = profile.slots,
        .repetitions = profile.packing_repetitions,
        .aligned_ciphertexts = aligned,
        .logical_packed_outputs = logical_outputs,
        .physical_packed_ciphertexts =
            plan.physical_packed_ciphertexts(),
        .packing_digit_count = parameters.packing_radix.digit_count,
        .ciphertext_commitment_policy_code =
            profile.ciphertext_commitment_policy.wire_code(),
        .ledger = ledger,
        .padded_constraints = padded_constraints,
        .assignment_half_size = assignment_half,
        .padded_assignment_variables =
            detail::packed_profile_checked_multiply(
                2U, assignment_half,
                "packing R1CS padded assignment"),
    };
}

inline constexpr std::string_view packed_process_variant_name(
    PackedProcessVariant variant) {
    switch (variant) {
    case PackedProcessVariant::Folded:
        return "folded";
    case PackedProcessVariant::Laned:
        return "laned";
    }
    throw std::logic_error("unknown packed benchmark variant");
}

inline constexpr std::string_view packed_process_tier_name(
    PackedProcessTier tier) {
    return benchmark_payload_tier_name(tier);
}

/// Lane counts exposed by the canonical Laned benchmark profiles. Folded
/// profiles do not have a lane dimension and therefore require `lanes == 0`.
inline constexpr bool packed_process_lane_count_is_supported(
    PackedProcessVariant variant, std::size_t lanes) {
    if (variant == PackedProcessVariant::Folded) {
        return lanes == 0;
    }
    return lanes == 1 || lanes == 128 ||
           lanes == kDefaultPolyModulusDegree;
}

inline std::vector<int> packed_benchmark_data_prime_bit_sizes(
    std::size_t count) {
    // q0 is the native packing field; q1 and q2 provide proof headroom.
    // Later primes serve payload evaluation. Privacy estimates are documented
    // in docs/PRIVACY_ESTIMATES.md; this chain alone does not certify noise.
    static constexpr int prefix[]{60, 48, 48, 37, 37, 37, 37,
                                  38, 38, 39};
    std::vector<int> result(count, 40);
    std::copy_n(prefix, std::min(count, std::size(prefix)), result.begin());
    return result;
}

inline PackedProcessProfile packed_process_profile(
    PackedProcessVariant variant, PackedProcessTier tier,
    std::size_t lanes) {
    if (!packed_process_lane_count_is_supported(variant, lanes)) {
        throw std::invalid_argument(
            variant == PackedProcessVariant::Folded
                ? "Folded packed process profiles require zero lanes"
                : "Laned packed process profiles require 1, 128, or 16384 "
                  "lanes");
    }

    if (variant == PackedProcessVariant::Laned &&
        tier == PackedProcessTier::TargetMulHeavy) {
        throw std::invalid_argument(
            "target-mulHeavyPyramid contains cross-slot operations and requires "
            "a Wide payload; Laned profiles require target-balancedLaned");
    }

    PackedProcessProfile result;
    result.variant = variant;
    result.tier = tier;
    result.lanes = lanes;
    result.proof_ingress_depth =
        variant == PackedProcessVariant::Folded
            ? protocol::kConservativeFoldedMultiplicationProofDepth
            : protocol::conservative_laned_multiplication_proof_depth(
                  lanes, result.slots);

    const BenchmarkPayloadProfile selected =
        benchmark_payload_profile(tier);
    result.multiplicative_depth = selected.depth;
    result.middle_width = selected.width;
    result.input_ciphertexts = selected.inputs;
    result.output_ciphertexts = selected.outputs;
    result.workload_kind = selected.workload_kind;
    result.payload_operations = selected.operation_count;

    switch (tier) {
    case PackedProcessTier::Quick:
        result.packing_repetitions = 4;
        result.basefold_queries = 4;
        result.ciphertext_commitment_policy =
            gkr::CiphertextCommitmentPolicy::
                diagnostic_simple_ct_hash_v2();
        break;
    case PackedProcessTier::TargetBalanced:
    case PackedProcessTier::TargetMulHeavy:
        result.packing_repetitions =
            kPackingWellFormednessRepetitions;
        result.basefold_queries =
            kTranscriptPackingBaseFoldQueries;
        result.evidence = PackedProcessEvidence::Evaluation;
        break;
    }

    // Target profiles add one payload head. The profile-specific evaluation
    // plan retains it across payload source layers; proof ingress keeps its
    // existing floors. Keep quick diagnostics on their reduced chain.
    const std::size_t target_payload_head =
        tier == PackedProcessTier::Quick ? 0U : 1U;
    result.data_prime_bit_sizes = packed_benchmark_data_prime_bit_sizes(
        result.multiplicative_depth + result.proof_ingress_depth +
        target_payload_head);
    if (packed_process_uses_folded_pyramid_headroom(result)) {
        result.exact_data_primes.assign(kFoldedPyramidDataPrimes.begin(),
                                       kFoldedPyramidDataPrimes.end());
        result.exact_special_prime = kFoldedPyramidSpecialPrime;
        result.data_prime_bit_sizes.clear();
        for (const auto prime : result.exact_data_primes)
            result.data_prime_bit_sizes.push_back(
                static_cast<int>(std::bit_width(prime)));
    }
    return result;
}

/// Keep target headroom in the natural payload trace until final output
/// normalization. Preparing copies at the profile's selected proof-ingress
/// levels must not consume limbs carried by the ongoing payload computation.
inline payload::FheEvaluationPlan packed_process_evaluation_plan(
    const PackedProcessProfile &profile,
    const payload::LayeredCircuit &circuit,
    std::span<const std::size_t> proof_ingress_depths) {
    if (profile.fresh_rns_limbs() == 0) {
        throw std::invalid_argument("packed process profile has no data limbs");
    }
    if (proof_ingress_depths.size() != circuit.layers.size() ||
        proof_ingress_depths.empty()) {
        throw std::invalid_argument("packed process proof ingress has the wrong layer count");
    }
    std::vector<std::size_t> natural_floors(
        proof_ingress_depths.begin(), proof_ingress_depths.end());
    if (profile.tier != PackedProcessTier::Quick) {
        for (std::size_t source = 1; source < natural_floors.size(); ++source) {
            if (packed_process_uses_folded_pyramid_headroom(profile)) {
                const std::size_t expected =
                    payload::layer_kind(circuit.layers.at(source - 1U)) ==
                        payload::LayerKind::Affine ? 3U : 5U;
                if (proof_ingress_depths[source] != expected)
                    throw std::invalid_argument(
                        "Folded pyramid requires the affine4/multiplication6 ingress policy");
            }
            // The Folded pyramid uses its four-limb affine source directly;
            // multiplication sources retain one spare limb before proof ingress.
            const std::size_t reserve =
                packed_process_uses_folded_pyramid_headroom(profile)
                    ? (payload::layer_kind(circuit.layers.at(source - 1U)) ==
                           payload::LayerKind::Affine ? 0U : 1U)
                    : 1U;
            if (natural_floors[source] >
                std::numeric_limits<std::size_t>::max() - reserve)
                throw std::overflow_error("packed payload headroom overflows source depth");
            natural_floors[source] += reserve;
        }
    }
    auto result = payload::FheEvaluationPlan::packed_payload_with_prompt_switches(
        circuit, profile.fresh_rns_limbs() - 1U, natural_floors);
    result.proof_ingress_mult_depth_by_layer.assign(
        proof_ingress_depths.begin(), proof_ingress_depths.end());
    // As in the underlying planner, entry zero is the normalized output,
    // rather than a source consumed by GKR.
    result.proof_ingress_mult_depth_by_layer.front() = 0;
    result.validate(circuit);
    return result;
}

} // namespace laminate::bench

#endif // LAMINATE_BENCH_PACKED_PROCESS_PROFILE_HPP
