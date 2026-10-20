/// @file target_cost_report.cpp
/// @brief Formula-only target report with explicit RNS-level operation rows.

#include "benchmark_support.hpp"

#include "laminate/bench/schedule_cost.hpp"
#include "laminate/bench/target_cost.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/fixtures/workloads.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace laminate;
using namespace laminate::bench;
using namespace laminate::payload;

namespace {

struct Options {
    ScheduleProtocol protocol = ScheduleProtocol::Folded;
    std::size_t slots = 1U << 14U;
    std::size_t lanes = 1;
    std::size_t depth = kMaximumPayloadMultiplicativeDepth;
    std::size_t width = kBenchmarkDiamondMiddleWidth;
    std::size_t core_rns_limbs = 0;
    std::size_t bits_per_limb = 60;
};

ScheduleProtocol parse_protocol(std::string_view value) {
    if (value == "base") {
        return ScheduleProtocol::Base;
    }
    if (value == "folded") {
        return ScheduleProtocol::Folded;
    }
    if (value == "laned") {
        return ScheduleProtocol::Laned;
    }
    throw std::invalid_argument("--protocol must be base, folded, or laned");
}

std::optional<Options> parse_options(int argc, char **argv) {
    Options result;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help" || argument == "-h") {
            std::cout
                << "Usage: laminate_target_cost_report [options]\n"
                << "  --protocol base|folded|laned\n"
                << "  --slots N --lanes B --depth d --width W\n"
                << "  --core-rns-limbs L --bits-per-limb BITS\n"
                << "For Base formula-only reports, L is the configured "
                   "uniform proof-ingress limb count; no natural payload "
                   "levels are inferred.\n";
            return std::nullopt;
        }
        if (index + 1 == argc) {
            throw std::invalid_argument(std::string(argument) +
                                        " requires a value");
        }
        const std::string_view value(argv[++index]);
        if (argument == "--protocol") {
            result.protocol = parse_protocol(value);
        } else if (argument == "--slots") {
            result.slots = parse_size(value, argument);
        } else if (argument == "--lanes") {
            result.lanes = parse_size(value, argument);
        } else if (argument == "--depth") {
            result.depth = parse_size(value, argument);
        } else if (argument == "--width") {
            result.width = parse_size(value, argument);
        } else if (argument == "--core-rns-limbs") {
            result.core_rns_limbs = parse_size(value, argument);
        } else if (argument == "--bits-per-limb") {
            result.bits_per_limb = parse_size(value, argument);
        } else {
            throw std::invalid_argument("unknown option: " +
                                        std::string(argument));
        }
    }

    if (!std::has_single_bit(result.slots) || result.slots < 32 ||
        result.depth == 0 ||
        result.depth > kMaximumPayloadMultiplicativeDepth ||
        result.width == 0 ||
        result.bits_per_limb == 0) {
        throw std::invalid_argument(
            "N must be a power of two >=32; payload depth must be in 1..8; "
            "width and limb bits must be nonzero");
    }
    if (result.protocol == ScheduleProtocol::Laned &&
        (!std::has_single_bit(result.lanes) || result.lanes > result.slots)) {
        throw std::invalid_argument(
            "Laned requires a power-of-two 1 <= B <= N");
    }
    if (result.core_rns_limbs == 0) {
        // These are configured uniform formula inputs, not a proof of
        // circuit-wide noise sufficiency. Packed protocols use six data
        // primes; Base prices every reduction at a three-limb proof ingress.
        result.core_rns_limbs =
            result.protocol == ScheduleProtocol::Base ? 3 : 6;
    }
    if ((result.protocol == ScheduleProtocol::Base &&
         result.core_rns_limbs < 2) ||
        (result.protocol != ScheduleProtocol::Base &&
         result.core_rns_limbs < 3)) {
        throw std::invalid_argument("core RNS chain is too short");
    }
    return result;
}

ScheduleFormula make_formula(ScheduleProtocol protocol,
                             const LayeredCircuit &circuit) {
    switch (protocol) {
    case ScheduleProtocol::Base:
        return base_schedule_formula(circuit);
    case ScheduleProtocol::Folded:
        return folded_schedule_formula(circuit);
    case ScheduleProtocol::Laned:
        return laned_schedule_formula(circuit);
    }
    throw std::logic_error("unknown protocol");
}

void emit_primitives(const Record &record, const std::string &prefix,
                     const ConcretePrimitiveUpperBound &operations) {
    record.integer(prefix + ".plain_multiplications",
                   operations.plain_multiplications);
    record.integer(prefix + ".online_vector_plain_multiplications",
                   operations.online_vector_plain_multiplications);
    record.integer(prefix + ".online_vector_plaintext_preparations",
                   operations.online_vector_plaintext_preparations);
    record.integer(
        prefix + ".scalar_or_preprocessed_plain_multiplications",
        operations.plain_multiplications -
            operations.online_vector_plain_multiplications);
    record.integer(prefix + ".ciphertext_multiplications_no_relinearization",
                   operations.ciphertext_multiplications_no_relinearization);
    record.integer(prefix + ".relinearizations",
                   operations.relinearizations);
    record.integer(prefix + ".negations", operations.negations);
    record.integer(prefix + ".additions", operations.additions);
    record.integer(prefix + ".subtractions", operations.subtractions);
    record.integer(prefix + ".rotations", operations.rotations);
}

void emit_level_rows(const Record &record,
                     const ProverOperationLedger &ledger) {
    for (const RnsLevelOperations &row : ledger.levels) {
        const std::string prefix =
            "operations.rns_" + std::to_string(row.rns_limbs);
        emit_primitives(record, prefix, row.primitives);
        record.integer(prefix + ".modulus_switches",
                       row.modulus_switches);
        record.integer(prefix + ".base_proof_ingress_switches",
                       row.base_proof_ingress_switches);
        record.integer(prefix + ".base_proof_message_switches",
                       row.base_proof_message_switches);
    }
}

void emit_base_rns_placement(const Record &record,
                             const ProverOperationLedger &ledger) {
    if (ledger.protocol != ScheduleProtocol::Base) {
        return;
    }
    record.text(
        "base.proof_ingress_normalization_modeled",
        ledger.base_proof_ingress_normalization_modeled ? "yes" : "no");
    record.integer("base.proof_ingress_switch_events",
                   ledger.base_proof_ingress_switch_events);
    record.integer("base.proof_message_switch_events",
                   ledger.base_proof_message_switch_events);
    if (ledger.base_proof_message_switch_events >
        std::numeric_limits<std::uint64_t>::max() -
            ledger.base_proof_ingress_switch_events) {
        throw std::overflow_error("Base normalization switch total overflows");
    }
    record.integer(
        "base.normalization_switch_events",
        ledger.base_proof_ingress_switch_events +
            ledger.base_proof_message_switch_events);
    for (std::size_t index = 0; index < ledger.base_reductions.size();
         ++index) {
        const BaseReductionRnsOperations &reduction =
            ledger.base_reductions[index];
        const std::string prefix =
            "base.reduction." + std::to_string(index);
        record.integer(prefix + ".layer", reduction.reduction_layer);
        if (reduction.natural_source_rns_limbs == 0) {
            record.text(prefix + ".natural_source_rns_limbs",
                        "not-modeled-formula-only");
        } else {
            record.integer(prefix + ".natural_source_rns_limbs",
                           reduction.natural_source_rns_limbs);
        }
        record.integer(prefix + ".proof_ingress_rns_limbs",
                       reduction.proof_ingress_rns_limbs);
        record.integer(prefix + ".live_source_ciphertexts",
                       reduction.live_source_ciphertexts);
        record.integer(prefix + ".proof_message_ciphertexts",
                       reduction.proof_message_ciphertexts);
        record.integer(prefix + ".proof_ingress_switch_events",
                       reduction.ingress_switch_events);
        record.integer(prefix + ".proof_message_switch_events",
                       reduction.proof_message_switch_events);
    }
}

struct TraceGeometry {
    std::uint64_t logical_live_wires = 0;
    std::uint64_t stored_values = 0;
    std::uint64_t encrypted_ciphertexts = 0;
    std::uint64_t virtual_domain_positions = 0;
};

TraceGeometry trace_geometry(const LayeredCircuit &circuit) {
    TraceGeometry result;
    const auto add = [](std::uint64_t left, std::size_t right,
                        const char *what) {
        if (right > std::numeric_limits<std::uint64_t>::max() - left) {
            throw std::overflow_error(what);
        }
        return left + static_cast<std::uint64_t>(right);
    };
    const std::vector<LayerTraceValueCounts> layers =
        canonical_trace_value_counts(circuit);
    for (const LayerTraceValueCounts &layer : layers) {
        result.logical_live_wires = add(
            result.logical_live_wires, layer.logical_live_wires,
            "logical live trace-wire count overflows");
        result.stored_values = add(
            result.stored_values, layer.stored_values,
            "stored trace-value count overflows");
        result.encrypted_ciphertexts = add(
            result.encrypted_ciphertexts, layer.encrypted_ciphertexts,
            "encrypted trace-ciphertext count overflows");
        result.virtual_domain_positions = add(
            result.virtual_domain_positions, layer.virtual_wire_positions,
            "virtual trace position count overflows");
    }
    return result;
}

int run(const Options &options, int argc, char **argv) {
    const PayloadShape shape =
        options.protocol == ScheduleProtocol::Laned
            ? PayloadShape::laned(options.lanes, options.slots)
            : PayloadShape::wide(options.slots);
    const auto [workload, workload_timing] = timed([&] {
        return make_workload(WorkloadSpec{
            WorkloadKind::Diamond, shape, options.depth, options.width, 1});
    });
    const auto [circuit, layering_timing] =
        timed([&] { return compile(workload.circuit); });
    const auto [formula, formula_timing] = timed(
        [&] { return make_formula(options.protocol, circuit); });
    const ProverOperationLedger ledger =
        options.protocol == ScheduleProtocol::Base
            ? base_operation_ledger(circuit, formula, options.slots,
                                    options.core_rns_limbs)
            : packed_operation_ledger(formula, options.slots,
                                      options.core_rns_limbs);
    const ProofSizeEstimate proof_size =
        options.protocol == ScheduleProtocol::Base
            ? estimate_base_proof_size(circuit, formula, ledger)
            : estimate_packed_proof_size(circuit, ledger);
    const std::optional<WideGateProofSizeEstimate> gate_size =
        options.protocol == ScheduleProtocol::Laned ? std::nullopt :
            std::optional<WideGateProofSizeEstimate>(estimate_wide_gate_proof_size(circuit));
    const std::optional<SpartanPackingEstimate> spartan_packing =
        options.protocol == ScheduleProtocol::Base
            ? std::nullopt
            : std::optional<SpartanPackingEstimate>(
                  estimate_spartan_packing(circuit, ledger));
    const VerifierCryptoLedger verifier =
        estimate_verifier_crypto(circuit, ledger);
    const PayloadStats payload_stats = analyze(workload.circuit);
    const TraceGeometry trace = trace_geometry(circuit);

    const Record record;
    record.text("format", "laminate-target-cost-report-v14");
    record.text("classification.result_kind", "formula-only");
    record.text("classification.execution", "single-thread");
    record.text("classification.protocol",
                std::string(schedule_protocol_name(options.protocol)));
    record.text("classification.backend", "not-executed");
    record.text("classification.command", exact_command(argc, argv));
    record.text("classification.paper_model_scope",
                "listed-BGV-primitives-with-explicit-modswitch-sensitivity");
    record.text("classification.gate_mle_profile",
                options.protocol == ScheduleProtocol::Laned
                    ? "structured-sparse-basefold" : "wide-local-adjoint-foldable");
    record.text(
        "classification.gate_mle_cost_scope",
        gate_size ? "canonical-opening-wire-cap;prover-verifier-work-unmodeled" :
                    "logical-affine-query-count-only;opening-proof-bytes-and-work-unmodeled");

    record.text("workload.kind", "diamond");
    record.integer("workload.multiplicative_depth", options.depth);
    record.integer("workload.middle_width", options.width);
    record.integer("workload.input_ciphertexts",
                   workload.circuit.input_count);
    record.integer("workload.output_ciphertexts",
                   workload.circuit.outputs.size());
    record.integer("workload.logical_input_elements",
                   workload.circuit.input_count * shape.value_width());
    record.integer("workload.logical_output_elements",
                   workload.circuit.outputs.size() * shape.value_width());
    record.integer("workload.ct_ct_multiplicative_depth",
                   payload_stats.ct_ct_multiplicative_depth);
    record.integer("workload.alternating_multiplicative_depth",
                   payload_stats.alternating_multiplicative_depth);
    record.integer("workload.actual_additions", payload_stats.add_gates +
                                                    payload_stats.add_plain_gates);
    record.integer("workload.actual_multiplications",
                   payload_stats.mul_gates + payload_stats.mul_plain_gates);
    record.integer("workload.actual_operations",
                   payload_stats.add_gates + payload_stats.add_plain_gates +
                       payload_stats.mul_gates +
                       payload_stats.mul_plain_gates);
    record.integer("circuit.reduction_layers", circuit.layers.size() - 1);
    record.integer("circuit.logical_rounds",
                   formula.operations.logical_rounds);
    record.integer("trace.logical_live_wires",
                   trace.logical_live_wires);
    record.integer("trace.stored_values", trace.stored_values);
    record.integer("trace.encrypted_ciphertexts",
                   trace.encrypted_ciphertexts);
    record.integer("trace.public_plaintext_values",
                   trace.stored_values - trace.encrypted_ciphertexts);
    record.integer("trace.aliased_logical_wires",
                   trace.logical_live_wires - trace.stored_values);
    record.integer("trace.padded_domain_positions",
                   trace.virtual_domain_positions);
    record.integer("trace.structural_padding_positions",
                   trace.virtual_domain_positions -
                       trace.logical_live_wires);
    record.text("trace.target_storage_policy",
                "store-canonical-public-or-encrypted-values;omit-"
                "structural-padding;alias-setup-identical-values");
    record.text("trace.current_storage_implementation",
                "mixed-value-v3;checkpoint-replay-wired;target-bytes-stale");

    record.integer("parameters.N", options.slots);
    if (options.protocol == ScheduleProtocol::Laned) {
        record.integer("parameters.B", options.lanes);
    } else {
        record.text("parameters.B", "not-applicable");
    }
    record.integer("parameters.core_rns_limbs", options.core_rns_limbs);
    record.text(
        "parameters.core_rns_limbs_semantics",
        options.protocol == ScheduleProtocol::Base
            ? "configured-uniform-proof-ingress"
            : "configured-uniform-core-working-level");
    record.integer("parameters.threads", 1);
    record.integer("parameters.final_rns_limbs", 1);
    record.integer("parameters.bits_per_limb", options.bits_per_limb);
    record.integer("parameters.nominal_chain_headroom_prime_bits",
                   (options.core_rns_limbs - 1) * options.bits_per_limb);
    record.text("noise.classification",
                "selected-chain-estimate-not-circuit-wide-certificate");

    record.integer("packing.paper_raw_ciphertext_footprint",
                   ledger.paper_raw_ciphertext_footprint);
    record.integer("packing.aligned_ciphertexts",
                   ledger.aligned_ciphertexts);
    record.integer("packing.logical_packed_outputs",
                   ledger.logical_packed_outputs);
    record.integer("packing.well_formedness_repetitions",
                   ledger.well_formedness_repetitions);
    record.integer("packing.signed_digits_per_output",
                   ledger.signed_digits_per_output);
    emit_base_rns_placement(record, ledger);
    if (options.protocol == ScheduleProtocol::Base) {
        record.integer("base.proof_extension_messages",
                       ledger.direct_transcript_extension_messages);
        record.integer(
            "base.proof_public_zero_extension_messages",
            ledger.direct_transcript_public_zero_extension_messages);
        record.integer("base.proof_live_base_ciphertexts",
                       ledger.direct_transcript_ciphertexts);
        record.text("base.proof_topology",
                    "safe-circuit-derived-coordinate-support-upper-bound");
        record.text("base.proof_topology_target_exactness",
                    ledger.direct_transcript_public_zero_extension_messages ==
                            0U
                        ? "exact-all-target-coordinates-encrypted"
                        : "upper-bound-public-only-support-may-be-sparser");
    }
    emit_level_rows(record, ledger);

    record.text("runtime.full_online_server.status",
                "unavailable-formula-only");
    record.text(
        "runtime.full_online_server.missing_inputs",
        "approved-payload-modulus-and-proof-ingress-schedule;"
        "payload-evaluation-and-checkpoint-replay-calibration;"
        "host-phase-calibration");

    record.text("proof.size_scope", gate_size ?
        "canonical-gkr-core-packing-and-wide-gate-opening-caps" :
        "gkr-core-and-packing-components;excludes-laned-gate-opening");
    if (gate_size) {
        record.integer("proof.gate_mle_opening_max_bytes", gate_size->canonical_bytes_upper_bound);
        record.integer("proof.gate_mle_pcs_max_bytes", gate_size->pcs_bytes_upper_bound);
        record.integer("proof.gate_mle_outer_bytes", gate_size->outer_bytes);
        record.integer("proof.gate_mle_public_message_size", gate_size->public_message_size);
        record.integer("proof.gate_mle_public_operands", gate_size->public_operands);
        record.integer("proof.gate_mle_adjoint_groups", gate_size->adjoint_groups);
        record.integer("proof.gate_mle_queries", basefold::foldable::kDefaultQueries);
    } else {
        record.text("proof.gate_mle_opening_bytes", "unmodeled-laned-proof");
    }
    record.integer(
        "proof.canonical.bytes_excluding_packing_argument_and_gate_mle_opening",
                   proof_size.canonical_bytes_excluding_packing_argument);
    record.integer("proof.canonical.fhe_message_bytes",
                   proof_size.fhe_message_bytes);
    record.integer("proof.canonical.partial_gate_mle_bytes",
                   proof_size.partial_gate_mle_bytes);
    record.integer("proof.canonical.gkr_commitment_bytes",
                   proof_size.gkr_commitment_bytes);
    record.integer("proof.canonical.public_message_overhead_bytes",
                   proof_size.public_message_overhead_bytes);
    record.integer("proof.canonical.statement_and_metadata_bytes",
                   proof_size.statement_and_metadata_bytes);
    record.integer("proof.canonical.one_prime_ciphertexts",
                   proof_size.one_prime_ciphertexts);
    if (proof_size.persistent_base) {
        record.text("proof.transport.scope",
                    "excludes-variable-structured-gate-mle-opening");
        record.integer("proof.transport.bytes_excluding_gate_mle_opening",
                       proof_size.persistent_base->inner_transport_bytes);
        record.integer("proof.transport.fhe_message_bytes",
                       proof_size.persistent_base->fhe_message_bytes);
        record.integer(
            "proof.transport.partial_gate_mle_bytes",
            proof_size.persistent_base->partial_gate_mle_bytes);
        record.integer(
            "proof.transport.statement_and_metadata_bytes",
            proof_size.persistent_base->statement_and_metadata_bytes);
        record.integer(
            "proof.response.envelope_header_bytes",
            proof_size.persistent_base->response_envelope_header_bytes);
        record.integer(
            "proof.response.public_bindings_bytes",
            proof_size.persistent_base->response_public_bindings_bytes);
        record.integer(
            "proof.response.output_dimensions_bytes",
            proof_size.persistent_base->response_output_dimensions_bytes);
        record.integer(
            "proof.response.output_fhe_values_bytes",
            proof_size.persistent_base->response_output_fhe_values_bytes);
        record.integer(
            "proof.response.output_statement_bytes",
            proof_size.persistent_base->response_output_statement_bytes);
        record.integer(
            "proof.response.inner_length_prefix_bytes",
            proof_size.persistent_base->response_proof_length_prefix_bytes);
        record.integer("proof.response.duplicated_output_claim_bytes", 0);
        record.integer("proof.response.envelope_bytes",
                       proof_size.persistent_base->response_envelope_bytes);
        record.integer("proof.response.bytes_excluding_gate_mle_opening",
                       proof_size.persistent_base->response_bytes);
        record.integer(
            "proof.response.total_bytes_excluding_gate_mle_opening",
                       proof_size.persistent_base->response_bytes);
    }
    if (spartan_packing) {
        record.integer("packing.r1cs.constraints",
                       spartan_packing->r1cs_constraints);
        record.integer("packing.r1cs.matrix_rows",
                       spartan_packing->r1cs_matrix_rows);
        record.integer("packing.r1cs.logical_inputs",
                       spartan_packing->r1cs_logical_inputs);
        record.integer("packing.r1cs.public_inputs",
                       spartan_packing->r1cs_public_inputs);
        record.integer("packing.r1cs.witness_variables",
                       spartan_packing->r1cs_witness_variables);
        record.integer("packing.r1cs.nonzero_entries_upper_bound",
                       spartan_packing
                           ->r1cs_nonzero_entries_upper_bound);
        record.integer("packing.spartan.padded_constraints",
                       spartan_packing->padded_constraints);
        record.integer("packing.spartan.assignment_half_size",
                       spartan_packing->assignment_half_size);
        record.integer("packing.factored.tensor_count",
                       spartan_packing->factored_output_live_owners.size());
        for (std::size_t output = 0;
             output <
             spartan_packing->factored_output_live_owners.size(); ++output) {
            const std::string prefix =
                "packing.factored.tensor." + std::to_string(output);
            record.integer(
                prefix + ".live_owners",
                spartan_packing->factored_output_live_owners[output]);
            record.integer(
                prefix + ".padded_owners",
                spartan_packing->factored_output_padded_owners[output]);
        }
        record.integer("packing.factored.tensor_live_elements",
                       spartan_packing->factored_tensor_live_elements);
        record.integer("packing.factored.tensor_padded_elements",
                       spartan_packing->factored_tensor_padded_elements);
        record.integer("packing.factored.tensor_live_bytes",
                       spartan_packing->factored_tensor_live_bytes);
        record.integer("packing.factored.tensor_padded_bytes",
                       spartan_packing->factored_tensor_padded_bytes);
        record.integer("packing.factored.largest_tensor_evaluations",
                       spartan_packing
                           ->factored_largest_tensor_evaluations);
        record.integer("proof.spartan_core_max_bytes",
                       spartan_packing->core_proof_max_bytes);
        record.integer("proof.factored_matrix_max_bytes",
                       spartan_packing->factored_proof_max_bytes);
        record.integer("proof.packing_argument_max_bytes",
                       spartan_packing->proof_max_bytes);
        record.integer(
            "proof.estimated_total_max_bytes_excluding_gate_mle_opening",
            proof_size.canonical_bytes_excluding_packing_argument +
                spartan_packing->proof_max_bytes);
        if (gate_size) record.integer("proof.estimated_total_max_bytes",
            proof_size.canonical_bytes_excluding_packing_argument +
            spartan_packing->proof_max_bytes + gate_size->canonical_bytes_upper_bound + 8);
        record.integer("runtime.spartan_core_peak_memory_bytes_model",
                       spartan_packing->core_peak_memory_bytes_model);
        record.integer(
            "runtime.spartan_core_retained_witness_pcs_bytes_model",
            spartan_packing->core_retained_witness_pcs_bytes_model);
        record.integer(
            "runtime.spartan_core_assignment_commitment_peak_bytes_model",
            spartan_packing
                ->core_assignment_commitment_peak_bytes_model);
        record.integer(
            "runtime.spartan_core_constraint_peak_memory_bytes_model",
            spartan_packing
                ->core_constraint_peak_memory_bytes_model);
        record.integer(
            "runtime.spartan_core_wiring_peak_memory_bytes_model",
            spartan_packing->core_wiring_peak_memory_bytes_model);
        record.integer(
            "runtime.spartan_core_witness_opening_peak_memory_bytes_model",
            spartan_packing
                ->core_witness_opening_peak_memory_bytes_model);
        record.integer("runtime.factored.retained_raw_tensor_bytes",
                       spartan_packing
                           ->factored_retained_raw_tensor_bytes);
        record.integer("runtime.factored.retained_basefold_message_bytes",
                       spartan_packing
                           ->factored_retained_basefold_message_bytes);
        record.integer("runtime.factored.retained_basefold_codeword_bytes",
                       spartan_packing
                           ->factored_retained_basefold_codeword_bytes);
        record.integer("runtime.factored.retained_basefold_merkle_bytes",
                       spartan_packing
                           ->factored_retained_basefold_merkle_bytes);
        record.integer("runtime.factored.retained_preprocessing_bytes_model",
                       spartan_packing
                           ->factored_retained_preprocessing_bytes_model);
        record.integer("runtime.factored.opening_peak_bytes_model",
                       spartan_packing
                           ->factored_opening_peak_bytes_model);
        record.integer("verifier.factored.regular_poseidon_segments",
                       spartan_packing->regular_poseidon_segments);
        record.integer(
            "verifier.factored.regular_poseidon_ciphertext_segment_visits",
            spartan_packing
                ->regular_poseidon_ciphertext_segment_visits);
        record.integer(
            "verifier.factored.regular_poseidon_rate_interval_evaluations",
            spartan_packing
                ->regular_poseidon_rate_interval_evaluations);
        record.integer(
            "verifier.factored.regular_poseidon_boundary_segment_visits",
            spartan_packing
                ->regular_poseidon_boundary_segment_visits);
        record.integer(
            "verifier.factored.regular_poseidon_digest_terms",
            spartan_packing->regular_poseidon_digest_terms);
        record.integer(
            "verifier.factored.regular_challenge_bit_visits",
            spartan_packing->regular_challenge_bit_visits);
        record.integer(
            "verifier.factored.regular_test_ciphertext_pair_visits",
            spartan_packing->regular_test_ciphertext_pair_visits);
        record.integer(
            "verifier.factored.regular_owner_affine_segment_visits",
            spartan_packing->regular_owner_affine_segment_visits);
        record.integer(
            "verifier.factored.regular_public_affine_range_evaluations",
            spartan_packing
                ->regular_public_affine_range_evaluations);
        record.integer(
            "verifier.factored.regular_high_equality_table_elements",
            spartan_packing->regular_high_equality_table_elements);
        record.integer("verifier.factored.sumcheck_rounds",
                       spartan_packing->factored_sumcheck_rounds);
        record.integer("verifier.factored.digit_weight_terms",
                       spartan_packing->factored_digit_weight_terms);
        record.integer("verifier.factored.terminal_owner_terms",
                       spartan_packing->factored_terminal_owner_terms);
        record.integer(
            "verifier.factored.terminal_affine_segment_visits",
            spartan_packing
                ->factored_terminal_affine_segment_visits);
        record.integer("verifier.factored.basefold_openings",
                       spartan_packing->factored_basefold_openings);
        record.integer("verifier.factored.basefold_queries",
                       spartan_packing->factored_basefold_queries);
        record.integer("verifier.factored.basefold_query_fold_steps",
                       spartan_packing
                           ->factored_basefold_query_fold_steps);
        record.integer("verifier.factored.basefold_merkle_hashes",
                       spartan_packing
                           ->factored_basefold_merkle_hashes);
    }

    record.text(
        "verifier.scope",
        spartan_packing
            ? "gkr-and-packing-operation-counts;no-runtime-calibration"
            : "gkr-only");
    record.integer("verifier.excluding_packing.one_prime_decryptions",
                   verifier.one_prime_decryptions);
    record.integer("verifier.excluding_packing.recovered_gkr_messages",
                   verifier.recovered_gkr_messages);
    record.integer(
        "verifier.excluding_packing.logical_affine_gate_mle_queries",
                   verifier.direct_gate_mle_queries);
    record.text(
        "verifier.structured_gate_mle_opening_work",
        "unmodeled;logical-query-count-is-not-a-direct-evaluation-cost");
    record.integer(
        "verifier.excluding_packing.base_partial_gate_mle_vectors",
        verifier.base_partial_gate_mle_vectors);
    record.integer(
        "verifier.excluded_packing.partial_decryption_norm_checks",
        verifier.excluded_packing_partial_decryption_norm_checks);
    record.integer("verifier.excluded_packing.commitment_digests",
                   verifier.excluded_packing_commitment_digests);
    record.text(
        "verifier.excluding_packing.time",
        "not-priced-by-paper-model;client-crypto-and-host-work-listed-separately");

    emit_timing(record, "workload_construction", workload_timing);
    emit_timing(record, "circuit_layering", layering_timing);
    emit_timing(record, "formula_evaluation", formula_timing);
    return 0;
}

} // namespace

int main(int argc, char **argv) {
    try {
        const std::optional<Options> options = parse_options(argc, argv);
        return options ? run(*options, argc, argv) : 0;
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
