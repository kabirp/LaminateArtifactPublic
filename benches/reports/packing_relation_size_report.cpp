/// @file packing_relation_size_report.cpp
/// @brief Formula-only target report for complete packing R1CS dimensions.

#include "laminate/bench/schedule_cost.hpp"
#include "laminate/bench/payload_profile.hpp"
#include "laminate/bench/target_cost.hpp"
#include "laminate/packing/proof/r1cs.hpp"
#include "laminate/packing/alignment/layout.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/fixtures/workloads.hpp"
#include "laminate/protocol/packed/setup.hpp"

#include <bit>
#include <cstddef>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace laminate;

namespace {

struct Options {
    bool folded = true;
    std::string profile = "target-balancedLaned";
    std::size_t lanes = 1;
};

std::size_t parse_size(std::string_view text) {
    std::size_t consumed = 0;
    const unsigned long long value = std::stoull(
        std::string(text), &consumed, 10);
    if (consumed != text.size()) {
        throw std::invalid_argument("invalid integer");
    }
    return static_cast<std::size_t>(value);
}

std::optional<Options> parse_options(int argc, char **argv) {
    Options result;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help" || argument == "-h") {
            std::cout
                << "Usage: laminate_packing_relation_size_report "
                   "[options]\n"
                << "  --protocol folded|laned [--lanes B]\n"
                << "  --profile target-balancedLaned|target-mulHeavyPyramid\n";
            return std::nullopt;
        }
        if (argument == "--protocol" && index + 1 < argc) {
            const std::string_view value(argv[++index]);
            if (value == "folded") {
                result.folded = true;
            } else if (value == "laned") {
                result.folded = false;
            } else {
                throw std::invalid_argument(
                    "--protocol must be folded or laned");
            }
        } else if (argument == "--profile" && index + 1 < argc) {
            result.profile = argv[++index];
        } else if (argument == "--lanes" && index + 1 < argc) {
            result.lanes = parse_size(argv[++index]);
        } else {
            throw std::invalid_argument(
                "unknown option: " + std::string(argument));
        }
    }
    if (!result.folded && result.lanes == 0) {
        throw std::invalid_argument("--lanes must be nonzero");
    }
    const auto profile = bench::benchmark_payload_profile(result.profile);
    if (!profile.is_target() ||
        !bench::benchmark_profile_is_in_campaign(
            result.folded ? "folded" : "laned", profile.tier)) {
        throw std::invalid_argument("profile is not in the selected campaign");
    }
    return result;
}

} // namespace

int main(int argc, char **argv) {
    try {
        constexpr std::size_t kRingDegree = 1U << 14U;
        const std::optional<Options> options = parse_options(argc, argv);
        if (!options) {
            return 0;
        }
        const payload::PayloadShape shape =
            options->folded
                ? payload::PayloadShape::wide(kRingDegree)
                : payload::PayloadShape::laned(options->lanes,
                                               kRingDegree);
        const payload::Workload workload = payload::make_workload(
            bench::benchmark_payload_workload_spec(
                bench::benchmark_payload_profile(options->profile), shape));
        const payload::LayeredCircuit circuit =
            payload::compile(workload.circuit);
        const std::size_t aligned_ciphertexts =
            options->folded
                ? protocol::folded_bhip_round_count(circuit)
                : protocol::laned_bhip_round_count(circuit);
        const bench::ScheduleFormula schedule =
            options->folded ? bench::folded_schedule_formula(circuit)
                           : bench::laned_schedule_formula(circuit);
        if (schedule.operations.aligned_round_ciphertexts !=
            aligned_ciphertexts) {
            throw std::logic_error(
                "protocol traversal and aligned ciphertext count differ");
        }
        const packing::PackingLayout layout =
            packing::make_fixed_message_coset_packing_layout(
                kRingDegree, aligned_ciphertexts,
                kRingDegree / fhe::kFixedMessageCellCount);
        const packing::OuterRelationPlan plan =
            packing::make_outer_relation_plan(packing::OuterRelationShape{
                .native_modulus = kOuterFieldOrder,
                .ring_degree = kRingDegree,
                .aligned_ciphertexts = layout.placements.size(),
                .repetitions = kPackingWellFormednessRepetitions,
                .logical_packed_outputs = layout.packed_ciphertext_count,
                .packing_digit_count =
                    packing::make_minimal_balanced_radix(
                        kBaseFieldOrder, kSelectedPackingRadixBase)
                        .digit_count,
                .ciphertext_components = 2,
                .public_input_capacity_bits = 59,
            });
        const packing::ProofOfPackingR1csLedger ledger =
            packing::proof_of_packing_r1cs_ledger(plan);
        const bench::ProverOperationLedger operation_ledger =
            bench::packed_operation_ledger(schedule, kRingDegree, 6);
        const bench::SpartanPackingEstimate argument =
            bench::estimate_spartan_packing(circuit, operation_ledger);
        if (argument.r1cs_matrix_rows != ledger.matrix_rows ||
            argument.r1cs_nonzero_entries_upper_bound !=
                ledger.total_nonzero_entries_upper_bound) {
            throw std::logic_error(
                "packing relation and argument ledgers disagree");
        }

        std::cout << "format=laminate-packing-relation-size-report-v3\n";
        std::cout << "classification.result_kind=formula-only\n";
        std::cout << "profile=" << options->profile << '\n';
        std::cout << "protocol="
                  << (options->folded ? "folded" : "laned") << '\n';
        std::cout << "B=";
        if (options->folded) {
            std::cout << "not-applicable\n";
        } else {
            std::cout << options->lanes << '\n';
        }
        std::cout << "r=" << aligned_ciphertexts << '\n';
        std::cout << "aligned_ciphertexts="
                  << ledger.aligned_ciphertexts << '\n';
        std::cout << "packed_outputs=" << layout.packed_ciphertext_count
                  << '\n';
        std::cout << "poseidon_per_ciphertext="
                  << ledger.poseidon_sbox_constraints_per_ciphertext +
                         ledger
                             .poseidon_checkpoint_constraints_per_ciphertext +
                         ledger.poseidon_output_constraints_per_ciphertext
                  << '\n';
        std::cout << "ciphertext_poseidon_constraints="
                  << ledger.ciphertext_poseidon_constraints << '\n';
        std::cout << "total_poseidon_constraints="
                  << ledger.total_poseidon_constraints << '\n';
        std::cout << "packing_relation_constraints="
                  << ledger.packing_relation_constraints << '\n';
        std::cout << "total_constraints=" << ledger.total_constraints
                  << '\n';
        std::cout << "matrix_rows=" << ledger.matrix_rows << '\n';
        std::cout << "ciphertext_poseidon_nonzero_entries_per_ciphertext="
                  << ledger
                         .ciphertext_poseidon_nonzero_entries_per_ciphertext
                  << '\n';
        std::cout << "ciphertext_poseidon_nonzero_entries="
                  << ledger.ciphertext_poseidon_nonzero_entries << '\n';
        std::cout << "packing_nonzero_entries_upper_bound="
                  << ledger.packing_relation_nonzero_entries_upper_bound
                  << '\n';
        std::cout << "total_nonzero_entries_upper_bound="
                  << ledger.total_nonzero_entries_upper_bound << '\n';
        std::cout << "spartan_padded_constraints="
                  << std::bit_ceil(ledger.matrix_rows) << '\n';
        std::cout << "factored_tensor_count="
                  << argument.factored_output_live_owners.size() << '\n';
        for (std::size_t output = 0;
             output < argument.factored_output_live_owners.size(); ++output) {
            std::cout << "factored_tensor_" << output
                      << "_live_owners="
                      << argument.factored_output_live_owners[output]
                      << '\n';
            std::cout << "factored_tensor_" << output
                      << "_padded_owners="
                      << argument.factored_output_padded_owners[output]
                      << '\n';
        }
        std::cout << "factored_tensor_live_elements="
                  << argument.factored_tensor_live_elements << '\n';
        std::cout << "factored_tensor_padded_elements="
                  << argument.factored_tensor_padded_elements << '\n';
        std::cout << "factored_tensor_live_bytes="
                  << argument.factored_tensor_live_bytes << '\n';
        std::cout << "factored_tensor_padded_bytes="
                  << argument.factored_tensor_padded_bytes << '\n';
        std::cout << "factored_retained_preprocessing_bytes_model="
                  << argument.factored_retained_preprocessing_bytes_model
                  << '\n';
        std::cout << "factored_opening_peak_bytes_model="
                  << argument.factored_opening_peak_bytes_model << '\n';
        std::cout << "spartan_core_proof_max_bytes="
                  << argument.core_proof_max_bytes << '\n';
        std::cout << "factored_proof_max_bytes="
                  << argument.factored_proof_max_bytes << '\n';
        std::cout << "packing_argument_proof_max_bytes="
                  << argument.proof_max_bytes << '\n';
        std::cout << "factored_sumcheck_rounds="
                  << argument.factored_sumcheck_rounds << '\n';
        std::cout << "factored_terminal_owner_terms="
                  << argument.factored_terminal_owner_terms << '\n';
        std::cout << "factored_basefold_queries="
                  << argument.factored_basefold_queries << '\n';
        std::cout << "factored_basefold_query_fold_steps="
                  << argument.factored_basefold_query_fold_steps << '\n';
        std::cout << "public_inputs=" << ledger.total_public_inputs
                  << '\n';
        std::cout << "logical_inputs=" << ledger.total_logical_inputs
                  << '\n';
        std::cout << "active_witness_variables="
                  << ledger.active_witness_variables << '\n';
        std::cout << "witness_extent="
                  << ledger.total_witness_variables << '\n';
        std::cout << "below_2^33="
                  << (ledger.matrix_rows < (std::uint64_t{1} << 33U) &&
                              ledger.total_witness_variables <
                                  (std::uint64_t{1} << 33U)
                          ? "true"
                          : "false")
                  << '\n';
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
