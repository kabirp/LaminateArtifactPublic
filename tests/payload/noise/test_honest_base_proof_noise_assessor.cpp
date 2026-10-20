/// @file test_honest_base_proof_noise_assessor.cpp
/// @brief Production streamed reductions behind the honest-noise assessor.

#include "test_helpers.hpp"

#include "laminate/gkr/detail/base/analysis/honest_noise_source.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/noise/honest_base_proof_noise.hpp"
#include "laminate/payload/fixtures/workloads.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;

constexpr HonestBaseProofCoordinateMask kFullCoordinateMask =
    static_cast<HonestBaseProofCoordinateMask>(
        (std::uint16_t{1} << kExtensionDegree) - 1U);

bool throws_invalid_argument(const auto &body) {
    try {
        body();
        return false;
    } catch (const std::invalid_argument &) {
        return true;
    }
}

std::vector<std::uint64_t> source_chain() {
    return {
        kOuterFieldOrder,
        1'152'921'497'895'862'273ULL,
        53'687'910'401ULL,
        96'638'238'721ULL,
        98'785'755'137ULL,
    };
}

HonestPayloadNoiseCalibration calibration() {
    return HonestPayloadNoiseCalibration{
        .fresh_canonical_error_bound = 64,
        .ctct_relinearized_debit_bits = 40,
        .plaintext_multiplication_debit_bits = 3,
        .rotation_debit_bits = 2,
        .maximum_switch_tax_bits = 10,
        .switch_rounding_error_bound = 649,
        .modeled_switch_events_upper_bound = 1'000'000,
        .switch_model_failure_budget_bits = 40,
        .proof_suffix_level_reserve = 2,
    };
}

HonestBaseProofNoiseCalibration proof_calibration() {
    return HonestBaseProofNoiseCalibration{
        .ctct_relinearized_debit_bits = 37,
        .plaintext_multiplication_debit_bits = 2,
        .rotation_debit_bits = 1,
    };
}

HonestNoiseEnvelopeParameters parameters(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule) {
    return derive_honest_base_proof_noise_parameters(
        circuit, schedule, proof_calibration());
}

PayloadCircuit mixed_reduction_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 3);
    const WireId product = builder.mul(0, 1);
    builder.set_outputs({builder.add(product, 2)});
    return builder.finish();
}

PayloadCircuit width_one_affine_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 1);
    builder.set_outputs({builder.add(0, 0)});
    return builder.finish();
}

PayloadCircuit width_one_multiplication_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 1);
    builder.set_outputs({builder.mul(0, 0)});
    return builder.finish();
}

PayloadCircuit nonuniform_plaintext_multiplication_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 1);
    const std::size_t plaintext = builder.add_plaintext(
        {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
    builder.set_outputs({builder.mul_plain(0, plaintext)});
    return builder.finish();
}

PayloadCircuit forwarding_multiplication_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 1);
    const WireId first = builder.mul(0, 0);
    const WireId second = builder.mul(first, first);
    builder.set_outputs({builder.add(second, 0)});
    return builder.finish();
}

PayloadCircuit propagated_public_zero_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 3);
    const std::size_t zero = builder.add_scalar_plaintext(Fp::zero());
    const WireId z = builder.mul_plain(0, zero);
    const WireId p = builder.mul(z, 1);
    const WireId q = builder.mul(p, 2);
    builder.set_outputs({q});
    return builder.finish();
}

LayerDimensions test_dimensions(std::size_t logical,
                                std::size_t padded) {
    return LayerDimensions{
        .logical_size = logical,
        .padded_size = padded,
        .payload_size = logical,
        .forward_size = 0,
    };
}

LayeredCircuit geometry_test_circuit(
    std::size_t input_count,
    std::vector<MultiplicationGate> multiplication_gates,
    std::vector<std::size_t> output_sources = {}) {
    const std::size_t input_width = std::bit_ceil(input_count);
    const std::size_t multiplication_count = multiplication_gates.size();
    const std::size_t multiplication_width =
        std::bit_ceil(std::max(std::size_t{1}, multiplication_count));
    const std::size_t source_width = 2U * multiplication_width;
    const fhe::SlotVector zero(8, Fp::zero());
    const fhe::SlotVector nonzero(8, Fp(3));
    fhe::SlotVector partial(8, Fp::zero());
    partial.front() = Fp(5);

    for (MultiplicationGate &gate : multiplication_gates) {
        gate.origin = GateOrigin::Payload;
    }
    multiplication_gates.resize(
        multiplication_width,
        MultiplicationGate{.origin = GateOrigin::Padding});

    std::vector<AffineGate> source_gates;
    source_gates.resize(
        source_width,
        AffineGate{{}, Fp::zero(), GateOrigin::Padding});
    for (std::size_t pair = 0; pair < multiplication_count; ++pair) {
        source_gates[pair] = AffineGate{
            .terms = {{pair % input_count, 0, Fp::one()}},
            .constant = Fp::zero(), .origin = GateOrigin::Payload};
        source_gates[multiplication_width + pair] = AffineGate{
            .terms = {{(pair + 1U) % input_count, 0, Fp::one()}},
            .constant = Fp::zero(), .origin = GateOrigin::Payload};
    }

    if (output_sources.empty()) {
        output_sources.resize(multiplication_count);
        for (std::size_t source = 0; source < multiplication_count;
             ++source) {
            output_sources[source] = source;
        }
    }
    std::vector<AffineTerm> output_terms;
    output_terms.reserve(output_sources.size());
    for (const std::size_t source : output_sources) {
        output_terms.push_back({source, 0, Fp::one()});
    }

    LayeredCircuit circuit{
        .shape = PayloadShape::wide(8),
        .payload_input_count = input_count,
        .payload_output_count = 1,
        .proof_multiplication_depth = 1,
        .plaintexts = {zero, nonzero, partial},
        .layers = {
            AffineLayer{
                test_dimensions(1, 1),
                {AffineGate{std::move(output_terms), Fp::zero(),
                            GateOrigin::Payload}}},
            MultiplicationLayer{
                test_dimensions(multiplication_count,
                                multiplication_width),
                std::move(multiplication_gates)},
            AffineLayer{test_dimensions(2U * multiplication_count,
                                        source_width),
                        std::move(source_gates)},
            InputLayer{test_dimensions(input_count, input_width)},
        },
    };
    circuit.validate();
    (void)canonical_trace_wire_support(circuit);
    return circuit;
}

LayeredCircuit low_only_dense_multiplication_circuit() {
    const LayerDimensions output = test_dimensions(1, 1);
    const LayerDimensions multiplication{
        .logical_size = 1,
        .padded_size = 2,
        .payload_size = 1,
        .forward_size = 0,
    };
    const LayerDimensions source{
        .logical_size = 2,
        .padded_size = 4,
        .payload_size = 2,
        .forward_size = 0,
    };
    const LayerDimensions input = test_dimensions(2, 2);
    LayeredCircuit circuit{
        .shape = PayloadShape::wide(8),
        .payload_input_count = 2,
        .payload_output_count = 1,
        .proof_multiplication_depth = 1,
        .layers = {
            AffineLayer{output,
                        {AffineGate{{{0, 0, Fp::one()}}, Fp::zero(),
                                    GateOrigin::Payload}}},
            MultiplicationLayer{
                multiplication,
                {MultiplicationGate{.origin = GateOrigin::Payload},
                 MultiplicationGate{.origin = GateOrigin::Padding}}},
            AffineLayer{
                source,
                {AffineGate{{{0, 0, Fp::one()}}, Fp::zero(),
                            GateOrigin::Payload},
                 AffineGate{{}, Fp::zero(), GateOrigin::Padding},
                 AffineGate{{{1, 0, Fp::one()}}, Fp::zero(),
                            GateOrigin::Payload},
                 AffineGate{{}, Fp::zero(), GateOrigin::Padding}}},
            InputLayer{input},
        },
    };
    circuit.validate();
    (void)canonical_trace_wire_support(circuit);
    return circuit;
}

void check_operational_message_masks(
    const LayeredCircuit &circuit, std::size_t reduction_layer,
    std::vector<HonestBaseProofCoordinateMask> expected,
    std::string_view description = {}) {
    const HonestPayloadNoiseSchedule schedule =
        derive_honest_payload_noise_schedule(
            circuit, source_chain(), calibration());
    const auto &plan =
        schedule.base_proof_normalization_plan.reductions.at(
            reduction_layer);
    CHECK(plan.message_coordinate_masks == expected);
    CHECK(derive_honest_base_proof_message_topology(
              circuit, reduction_layer)
              .message_coordinate_masks == expected);

    Transcript transcript("test/base-proof-noise/geometry/v1");
    HonestBaseProofReductionNoiseExecutionAudit audit;
    HonestBaseProofReductionNoiseAssessment assessment;
    try {
        assessment = assess_honest_base_proof_reduction_noise(
            circuit, schedule, reduction_layer,
            parameters(circuit, schedule), transcript, &audit);
    } catch (const std::logic_error &error) {
        throw std::logic_error(
            std::string(description) + ": " + error.what());
    }
    CHECK(assessment.topology_complete);
    CHECK(audit.observed_message_coordinate_masks == expected);
}

std::size_t reduction_of_kind(const LayeredCircuit &circuit,
                              LayerKind kind) {
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) == kind) {
            return layer;
        }
    }
    throw std::logic_error("noise-assessor fixture lacks a kind");
}

struct Run {
    HonestBaseProofReductionNoiseAssessment assessment;
    HonestBaseProofReductionNoiseExecutionAudit audit;
};

Run assess(const LayeredCircuit &circuit,
           const HonestPayloadNoiseSchedule &schedule,
           std::size_t reduction_layer, bool literal_zero_history) {
    Transcript transcript(
        literal_zero_history
            ? "test/base-proof-noise/zero-domain/v1"
            : "test/base-proof-noise/dense-domain/v1");
    transcript.observe(
        "test/base-proof-noise/history",
        literal_zero_history ? std::uint64_t{0} : std::uint64_t{17});
    HonestBaseProofReductionNoiseExecutionAudit audit;
    auto assessment = assess_honest_base_proof_reduction_noise(
        circuit, schedule, reduction_layer, parameters(circuit, schedule),
        transcript, &audit);
    return Run{std::move(assessment), std::move(audit)};
}

void check_common(const Run &run,
                  const HonestBaseProofNormalizationLayerPlan &plan) {
    CHECK(run.assessment.reduction_layer == plan.reduction_layer);
    CHECK(run.assessment.kind == plan.kind);
    CHECK(run.assessment.natural_source_rns_limb_count ==
          plan.natural_source_rns_limb_count);
    CHECK(run.assessment.proof_ingress_rns_limb_count ==
          plan.proof_ingress_rns_limb_count);
    CHECK(run.assessment.live_source_ciphertext_count ==
          plan.live_source_ciphertext_count);
    CHECK(run.assessment.source_rns_limb_count ==
          plan.proof_ingress_rns_limb_count);
    CHECK(run.assessment.wire_variables == plan.wire_variables);
    CHECK(run.assessment.expected_extension_message_count ==
          plan.round_extension_ciphertext_count +
              plan.terminal_extension_ciphertext_count);
    CHECK(run.assessment.observed_extension_message_count ==
          run.assessment.expected_extension_message_count);
    CHECK(run.assessment.ingress_switch_events ==
          plan.ingress_switch_events);
    CHECK(run.assessment.expected_proof_message_switch_events ==
          plan.proof_message_switch_events);
    CHECK(run.assessment.observed_proof_message_switch_events ==
          plan.proof_message_switch_events);
    CHECK(run.assessment.expected_switch_events == plan.switch_events);
    CHECK(run.assessment.observed_switch_events == plan.switch_events);
    CHECK(run.assessment.topology_complete);
    CHECK(run.assessment.all_messages_fit);
    CHECK(!run.assessment.first_failure.has_value());
    CHECK(run.audit.kind == plan.kind);
    CHECK(run.audit.virtual_source.padding_objects_returned == 0);
}

} // namespace

int main() {
    test::Runner runner("Base proof-noise reduction assessor");

    runner.run("proof calibration owns only proof operation debits", [] {
        const LayeredCircuit circuit = compile(mixed_reduction_payload());
        const HonestPayloadNoiseSchedule core =
            derive_honest_payload_noise_schedule(
                circuit, source_chain(), calibration());
        const HonestBaseProofNoiseCalibration proof = proof_calibration();
        const HonestNoiseEnvelopeParameters derived =
            derive_honest_base_proof_noise_parameters(
                circuit, core, proof);

        CHECK(derived.ring_degree == circuit.shape.slot_count);
        CHECK(derived.plaintext_modulus == kBaseFieldOrder);
        CHECK(derived.fresh_canonical_error_bound == NaturalMagnitude(
                  core.calibration.fresh_canonical_error_bound));
        CHECK(derived.switch_rounding_error_bound == NaturalMagnitude(
                  core.calibration.switch_rounding_error_bound));
        CHECK(derived.data_moduli == core.data_moduli_low_to_high);
        CHECK(derived.ctct_relinearized_debit_bits ==
              proof.ctct_relinearized_debit_bits);
        CHECK(derived.plaintext_multiplication_debit_bits ==
              proof.plaintext_multiplication_debit_bits);
        CHECK(derived.rotation_debit_bits == proof.rotation_debit_bits);
        CHECK(derived.ctct_relinearized_debit_bits !=
              core.calibration.ctct_relinearized_debit_bits);
        CHECK(derived.plaintext_multiplication_debit_bits !=
              core.calibration.plaintext_multiplication_debit_bits);
        CHECK(derived.rotation_debit_bits !=
              core.calibration.rotation_debit_bits);

        HonestPayloadNoiseCalibration changed_payload = calibration();
        changed_payload.ctct_relinearized_debit_bits = 0;
        changed_payload.plaintext_multiplication_debit_bits = 0;
        changed_payload.rotation_debit_bits = 0;
        const HonestPayloadNoiseSchedule changed_core =
            derive_honest_payload_noise_schedule(
                circuit, source_chain(), changed_payload);
        CHECK(derive_honest_base_proof_noise_parameters(
                  circuit, changed_core, proof) == derived);

        HonestPayloadNoiseSchedule stale = core;
        ++stale.fresh_modulus_product_bits;
        CHECK(throws_invalid_argument([&] {
            (void)derive_honest_base_proof_noise_parameters(
                circuit, stale, proof);
        }));

        HonestBaseProofNoiseCalibration invalid = proof;
        invalid.ctct_relinearized_debit_bits =
            kMaximumHonestNoiseEnvelopeDebitBits + 1U;
        CHECK(throws_invalid_argument([&] {
            (void)derive_honest_base_proof_noise_parameters(
                circuit, core, invalid);
        }));

        invalid = proof;
        invalid.plaintext_multiplication_debit_bits =
            kMaximumHonestNoiseEnvelopeDebitBits + 1U;
        CHECK(throws_invalid_argument([&] {
            (void)derive_honest_base_proof_noise_parameters(
                circuit, core, invalid);
        }));

        invalid = proof;
        invalid.rotation_debit_bits =
            kMaximumHonestNoiseEnvelopeDebitBits + 1U;
        CHECK(throws_invalid_argument([&] {
            (void)derive_honest_base_proof_noise_parameters(
                circuit, core, invalid);
        }));
    });

    runner.run("affine and multiplication assessments are history independent",
               [] {
        const LayeredCircuit circuit = compile(mixed_reduction_payload());
        CHECK(circuit.layers.size() == 4);
        const std::size_t affine =
            reduction_of_kind(circuit, LayerKind::Affine);
        const std::size_t multiplication =
            reduction_of_kind(circuit, LayerKind::Multiplication);
        const HonestPayloadNoiseSchedule schedule =
            derive_honest_payload_noise_schedule(
                circuit, source_chain(), calibration());

        for (const std::size_t layer : {affine, multiplication}) {
            const Run zero_history = assess(circuit, schedule, layer, true);
            const Run dense_history = assess(circuit, schedule, layer, false);
            CHECK(zero_history.assessment == dense_history.assessment);
            CHECK(zero_history.audit == dense_history.audit);
            CHECK(zero_history.audit.backend_operation_count != 0);
            CHECK(zero_history.audit.backend_operation_count ==
                  dense_history.audit.backend_operation_count);
            const auto &plan =
                schedule.base_proof_normalization_plan.reductions.at(layer);
            check_common(zero_history, plan);
        }
    });

    runner.run("nonuniform plaintext multiplication has an affine noise proof", [] {
        using Backend = HonestNoiseEnvelopeBackend;
        const auto payload = nonuniform_plaintext_multiplication_payload();
        const auto circuit = compile(payload);
        CHECK(circuit.layers.size() == 2);
        CHECK(layer_kind(circuit.layers.front()) == LayerKind::Affine);
        const auto &affine = std::get<AffineLayer>(circuit.layers.front());
        CHECK(affine.intermediate_gates.size() == 1);
        CHECK(affine.intermediate_gates.front().terms.front().plaintext_index == 0);
        const auto schedule = derive_honest_payload_noise_schedule(
            circuit, source_chain(), calibration());
        auto contexts = Backend::create(parameters(circuit, schedule));
        gkr::base_detail::HonestBaseVirtualSource source(
            circuit, schedule, 0, contexts.eval);
        auto reader = source.active_layer_reader(1);
        CHECK(reader.next().has_value());
        CHECK(!reader.next().has_value());
        CHECK(source.audit_counters().source_objects_returned == 1);
        CHECK(source.audit_counters().source_ciphertext_objects_returned == 1);
        const auto run = assess(circuit, schedule, 0, false);
        check_common(run, schedule.base_proof_normalization_plan.reductions.front());
    });

    runner.run("dense noise source preserves public forwarding one", [] {
        using Backend = HonestNoiseEnvelopeBackend;
        const LayeredCircuit circuit =
            compile(forwarding_multiplication_payload());
        const HonestPayloadNoiseSchedule schedule =
            derive_honest_payload_noise_schedule(
                circuit, source_chain(), calibration());

        bool found_forward = false;
        for (std::size_t layer = 0; layer + 1U < circuit.layers.size();
             ++layer) {
            const auto *multiplication =
                std::get_if<MultiplicationLayer>(&circuit.layers[layer]);
            if (multiplication == nullptr ||
                multiplication->dimensions.forward_size == 0) {
                continue;
            }
            auto contexts = Backend::create(parameters(circuit, schedule));
            gkr::base_detail::HonestBaseVirtualSource source(
                circuit, schedule, layer, contexts.eval);
            auto reader = source.reader();
            while (const auto pair = reader.next()) {
                const MultiplicationGate &gate =
                    multiplication->gates.at(pair->packed_index);
                if (gate.origin != GateOrigin::Forward) {
                    continue;
                }
                found_forward = true;
                CHECK(pair->left().is_encrypted());
                CHECK(pair->right().is_public());
                CHECK(pair->right().plaintext().is_one());
            }
        }
        CHECK(found_forward);
    });

    runner.run("dense noise source reuses propagated public classification",
               [] {
        using Backend = HonestNoiseEnvelopeBackend;
        const LayeredCircuit circuit =
            compile(propagated_public_zero_payload());
        const std::size_t q_reduction =
            reduction_of_kind(circuit, LayerKind::Multiplication);
        const std::size_t source_layer = q_reduction + 1U;
        const CanonicalTraceLayout trace = canonical_trace_layout(circuit);
        const auto aliases =
            laminate::gkr::detail::make_dense_multiplication_alias_plan(
                circuit, q_reduction, trace.wire_support.at(source_layer),
                trace.storage.at(source_layer));

        CHECK(aliases.live_pair_count == 1);
        const std::size_t left_operand = aliases.left_operand.front();
        const auto &left_signature = aliases.operands.at(left_operand);
        CHECK(left_signature.stored_ordinals.size() == 1);
        CHECK(left_signature.stored_ordinals.front().has_value());
        const std::size_t p_ordinal =
            *left_signature.stored_ordinals.front();
        const std::size_t p_padded =
            trace.storage.at(source_layer)
                .representative_padded_index_of(p_ordinal);
        const auto &source_affine =
            std::get<AffineLayer>(circuit.layers.at(source_layer));
        CHECK(!source_affine.gates.at(p_padded).terms.empty());
        const ClassifiedTraceValue &p_classification =
            trace.stored_value_classifications.at(source_layer).at(
                p_ordinal);
        CHECK(p_classification.has_value());
        CHECK(p_classification->is_zero());

        const HonestPayloadNoiseSchedule schedule =
            derive_honest_payload_noise_schedule(
                circuit, source_chain(), calibration());
        auto contexts = Backend::create(parameters(circuit, schedule));
        gkr::base_detail::HonestBaseVirtualSource source(
            circuit, schedule, q_reduction, contexts.eval);
        auto reader = source.reader();

        const std::uint64_t operations_before =
            contexts.eval.sequences->next_operation;
        const auto pair = reader.next();
        CHECK(pair.has_value());
        CHECK(pair->left().is_public_zero());
        CHECK(pair->right().is_encrypted());
        CHECK(contexts.eval.sequences->next_operation ==
              operations_before + 1U);
        CHECK(!reader.next().has_value());
        CHECK(source.audit_counters().source_objects_returned == 2);
        CHECK(source.audit_counters()
                  .source_ciphertext_objects_returned == 1);

        const Run q_run = assess(circuit, schedule, q_reduction, true);
        CHECK(q_run.audit.multiplication.has_value());
        const auto &q_streaming = *q_run.audit.multiplication;
        CHECK(q_run.audit.virtual_source.source_objects_returned ==
              2U * q_streaming.artifact_scans);
        CHECK(q_run.audit.virtual_source
                  .source_ciphertext_objects_returned ==
              q_streaming.artifact_scans);

        const std::size_t affine_reduction = source_layer;
        const std::size_t affine_source_layer = affine_reduction + 1U;
        const auto &affine_classifications =
            trace.stored_value_classifications.at(affine_source_layer);
        CHECK(affine_classifications.size() == 2);
        CHECK(std::count(affine_classifications.begin(),
                         affine_classifications.end(), std::nullopt) == 1);

        auto affine_contexts =
            Backend::create(parameters(circuit, schedule));
        gkr::base_detail::HonestBaseVirtualSource affine_source(
            circuit, schedule, affine_reduction, affine_contexts.eval);
        auto affine_reader =
            affine_source.active_layer_reader(affine_source_layer);
        std::size_t public_values = 0;
        std::size_t encrypted_values = 0;
        while (const auto record = affine_reader.next()) {
            public_values +=
                static_cast<std::size_t>(record->value.is_public());
            encrypted_values +=
                static_cast<std::size_t>(record->value.is_encrypted());
        }
        CHECK(public_values == 1);
        CHECK(encrypted_values == 1);
        CHECK(affine_reader.statistics().values_read == 2);
        CHECK(affine_reader.statistics().ciphertexts_read == 1);
        CHECK(affine_source.audit_counters().source_objects_returned == 2);
        CHECK(affine_source.audit_counters()
                  .source_ciphertext_objects_returned == 1);

        const Run affine_run =
            assess(circuit, schedule, affine_reduction, true);
        CHECK(affine_run.audit.affine.has_value());
        const auto &affine =
            *affine_run.audit.affine;
        CHECK(affine.source_ciphertexts_read ==
              affine.source_scans);
        CHECK(affine_run.audit.virtual_source.source_objects_returned ==
              2U * affine.source_scans);
        CHECK(affine_run.audit.virtual_source
                  .source_ciphertext_objects_returned ==
              affine.source_scans);

        const std::size_t public_affine_reduction = 0;
        CHECK(layer_kind(circuit.layers.at(public_affine_reduction)) ==
              LayerKind::Affine);
        const Run public_run =
            assess(circuit, schedule, public_affine_reduction, true);
        CHECK(public_run.audit.affine.has_value());
        const auto &public_streaming =
            *public_run.audit.affine;
        CHECK(public_streaming.source_ciphertexts_read == 0);
        CHECK(public_run.audit.virtual_source.source_objects_returned ==
              public_streaming.source_scans);
        CHECK(public_run.audit.virtual_source
                  .source_ciphertext_objects_returned == 0);
        CHECK(public_run.audit.backend_operation_count == 0);
        CHECK(public_run.assessment.topology_complete);
        CHECK(public_run.assessment.all_messages_fit);
        CHECK(public_run.assessment
                  .observed_proof_message_switch_events == 0);
        CHECK(public_run.assessment.observed_switch_events == 0);
        CHECK(public_run.assessment
                  .expected_proof_message_switch_events > 0);

        HonestBaseProofNoiseExecutionAudit full_audit;
        const HonestBaseProofNoiseAssessment full_assessment =
            assess_honest_base_proof_noise(
                circuit, schedule, parameters(circuit, schedule),
                &full_audit);
        CHECK(full_assessment.report_accepts());
        CHECK(full_assessment.observed_switch_events <
              schedule.modeled_base_proof_switch_events);
        CHECK(full_audit.reductions.at(public_affine_reduction)
                  .backend_operation_count == 0);

        HonestPayloadNoiseSchedule attached = schedule;
        attached.base_proof_noise_assessment = full_assessment;
        validate_honest_payload_noise_schedule(circuit, attached);
    });

    runner.run("padded dense source creates one object per stored read", [] {
        const LayeredCircuit circuit = geometry_test_circuit(
            3, std::vector<MultiplicationGate>(
                   3, MultiplicationGate{.origin = GateOrigin::Payload}));
        const std::size_t multiplication =
            reduction_of_kind(circuit, LayerKind::Multiplication);
        const HonestPayloadNoiseSchedule schedule =
            derive_honest_payload_noise_schedule(
                circuit, source_chain(), calibration());
        const Run run = assess(circuit, schedule, multiplication, true);
        const auto &plan =
            schedule.base_proof_normalization_plan.reductions.at(
                multiplication);
        check_common(run, plan);

        const LayerWireSupport support =
            canonical_layer_wire_support(circuit, multiplication + 1U);
        CHECK(support.live_wire_count == 6);
        CHECK(support.padded_wire_count == 8);
        CHECK(run.audit.multiplication.has_value());
        CHECK(!run.audit.affine.has_value());
        const auto &streaming = *run.audit.multiplication;
        const auto aliases =
            laminate::gkr::detail::make_dense_multiplication_alias_plan(
                circuit, multiplication);
        const std::uint64_t expected_scans = plan.wire_variables + 1U;
        CHECK(run.assessment.expected_extension_message_count == 6);
        CHECK(streaming.artifact_scans == expected_scans);
        CHECK(streaming.artifact_rewinds + 1U == expected_scans);
        CHECK(streaming.artifact_pairs_read ==
              expected_scans * aliases.live_pair_count);
        CHECK(streaming.artifact_values_read ==
              expected_scans * aliases.operands.size());
        CHECK(run.audit.virtual_source.source_objects_returned ==
              streaming.artifact_values_read);
        CHECK(run.audit.virtual_source.contribution_objects_returned == 0);
        CHECK(run.audit.virtual_source.structural_padding_positions_skipped ==
              expected_scans *
                  (aliases.pair_count - aliases.live_pair_count));
        CHECK(run.audit.virtual_source.padding_objects_returned == 0);
    });

    runner.run("dense primary support covers the tau-one low branch", [] {
        using Backend = HonestNoiseEnvelopeBackend;
        const LayeredCircuit circuit =
            low_only_dense_multiplication_circuit();
        const HonestPayloadNoiseSchedule schedule =
            derive_honest_payload_noise_schedule(
                circuit, source_chain(), calibration());
        const HonestBaseProofCoordinateMask f = kFullCoordinateMask;
        const HonestBaseProofCoordinateMask b = 1;
        const auto topology = derive_honest_base_proof_message_topology(
            circuit, 1);
        CHECK(topology.message_coordinate_masks ==
              std::vector<HonestBaseProofCoordinateMask>({b, b, f, f}));

        auto contexts = Backend::create(parameters(circuit, schedule));
        gkr::base_detail::HonestBaseVirtualSource source(
            circuit, schedule, 1, contexts.eval);
        SingleClaim claim{
            std::vector<Fpk>(gkr::base_detail::layer_vars(circuit, 1),
                             Fpk::zero()),
            Fpk::zero()};
        claim.point.front() = Fpk::one();
        Transcript transcript("test/base-proof-noise/tau-one-low/v1");
        Backend::clear_base_message_normalization_records(contexts.eval);
        gkr::detail::FileBackedMultiplicationStatistics statistics;
        (void)gkr::base_detail::prove_multiplication_reduction<Backend>(
            contexts.eval, circuit, source, 1, claim, transcript,
            &statistics);
        const auto records =
            Backend::base_message_normalization_records(contexts.eval);
        CHECK(records.size() == 4);
        CHECK(records.front().coefficients[0].present);
        for (std::size_t coefficient = 1;
             coefficient < kExtensionDegree; ++coefficient) {
            CHECK(!records.front().coefficients[coefficient].present);
        }
    });

    runner.run("affine masks retain only structural suffix support", [] {
        const auto ctct = [](std::size_t source) {
            (void)source;
            return MultiplicationGate{.origin = GateOrigin::Payload};
        };
        const HonestBaseProofCoordinateMask f = kFullCoordinateMask;

        // Source two has bits 10: at-one is live in round zero but not one.
        check_operational_message_masks(
            geometry_test_circuit(
                3, {ctct(0), ctct(1), ctct(2)}, {2}),
            0, {f, f, 0, f, f}, "affine live source two");
        // A term at padded index three still contributes during partial
        // off-Boolean rounds when its remaining suffix matches a live wire.
        check_operational_message_masks(
            geometry_test_circuit(
                3, {ctct(0), ctct(1), ctct(2)}, {3}),
            0, {0, f, f, f, f}, "affine padded term three");

        LayeredCircuit cancelled = geometry_test_circuit(
            3, {ctct(0), ctct(1), ctct(2)}, {2});
        auto &output = std::get<AffineLayer>(cancelled.layers.front());
        output.gates.front().terms.push_back(
            AffineTerm{2, 0, Fp::zero() - Fp::one()});
        cancelled.validate();
        check_operational_message_masks(
            cancelled, 0, {0, 0, 0, 0, f}, "affine cancelled duplicate");
    });

    runner.run("all-layer assessment composes the canonical topology", [] {
        const LayeredCircuit circuit = compile(mixed_reduction_payload());
        const HonestPayloadNoiseSchedule schedule =
            derive_honest_payload_noise_schedule(
                circuit, source_chain(), calibration());
        HonestBaseProofNoiseExecutionAudit audit;
        const HonestBaseProofNoiseAssessment assessment =
            assess_honest_base_proof_noise(
                circuit, schedule, parameters(circuit, schedule), &audit);

        CHECK(assessment.policy ==
              kHonestBaseProofNoiseAssessmentPolicyV6);
        CHECK(assessment.source_payload_schedule_digest ==
              honest_payload_noise_schedule_digest(circuit, schedule));
        CHECK(assessment.reductions.size() == 3);
        CHECK(audit.reductions.size() == 3);
        CHECK(assessment.topology_complete);
        CHECK(assessment.all_messages_fit);
        CHECK(assessment.report_accepts());
        CHECK(!assessment.first_failure.has_value());
        CHECK(assessment.observed_switch_events ==
              schedule.base_proof_normalization_plan.switch_events);

        std::uint64_t summed_operations = 0;
        std::uint64_t summed_observations = 0;
        gkr::base_detail::HonestBaseVirtualSourceAuditCounters
            summed_virtual_source;
        for (std::size_t layer = 0; layer < assessment.reductions.size();
             ++layer) {
            const auto &reduction = assessment.reductions[layer];
            const auto &plan =
                schedule.base_proof_normalization_plan.reductions[layer];
            const auto topology =
                derive_honest_base_proof_message_topology(plan);
            const std::size_t expected_observations =
                plan.round_extension_ciphertext_count +
                plan.terminal_extension_ciphertext_count;
            CHECK(reduction.reduction_layer == layer);
            CHECK(reduction.kind == plan.kind);
            CHECK(reduction.expected_extension_message_count ==
                  expected_observations);
            CHECK(reduction.observed_extension_message_count ==
                  expected_observations);
            CHECK(reduction.families.size() == topology.families.size());
            CHECK(reduction.expected_switch_events == plan.switch_events);
            CHECK(reduction.observed_switch_events == plan.switch_events);
            summed_operations +=
                audit.reductions[layer].backend_operation_count;
            summed_observations += expected_observations;
            summed_virtual_source.source_objects_returned +=
                audit.reductions[layer]
                    .virtual_source.source_objects_returned;
            summed_virtual_source.source_ciphertext_objects_returned +=
                audit.reductions[layer]
                    .virtual_source.source_ciphertext_objects_returned;
            summed_virtual_source.contribution_objects_returned +=
                audit.reductions[layer]
                    .virtual_source.contribution_objects_returned;
            summed_virtual_source.structural_padding_positions_skipped +=
                audit.reductions[layer]
                    .virtual_source.structural_padding_positions_skipped;
        }

        CHECK(audit.normalization_records_observed == summed_observations);
        CHECK(audit.backend_operation_count == summed_operations);
        CHECK(audit.backend_operation_count != 0);
        CHECK(audit.virtual_source.source_objects_returned ==
              summed_virtual_source.source_objects_returned);
        CHECK(audit.virtual_source.source_ciphertext_objects_returned ==
              summed_virtual_source.source_ciphertext_objects_returned);
        CHECK(audit.virtual_source.contribution_objects_returned == 0);
        CHECK(audit.virtual_source.structural_padding_positions_skipped ==
              summed_virtual_source.structural_padding_positions_skipped);
        CHECK(audit.virtual_source.padding_objects_returned == 0);
    });

    runner.run("all-layer failure selection follows reduction order", [] {
        const LayeredCircuit circuit = compile(mixed_reduction_payload());
        const HonestPayloadNoiseSchedule schedule =
            derive_honest_payload_noise_schedule(
                circuit, source_chain(), calibration());
        HonestNoiseEnvelopeParameters failing =
            parameters(circuit, schedule);
        failing.ctct_relinearized_debit_bits = 512;
        failing.plaintext_multiplication_debit_bits = 512;
        failing.rotation_debit_bits = 512;

        const HonestBaseProofNoiseAssessment assessment =
            assess_honest_base_proof_noise(circuit, schedule,
                                           std::move(failing));
        CHECK(assessment.topology_complete);
        CHECK(!assessment.all_messages_fit);
        CHECK(!assessment.report_accepts());
        CHECK(assessment.first_failure.has_value());

        std::size_t failing_reductions = 0;
        const HonestBaseProofNoiseFailure *canonical_first = nullptr;
        for (const auto &reduction : assessment.reductions) {
            if (!reduction.first_failure) {
                continue;
            }
            ++failing_reductions;
            if (canonical_first == nullptr) {
                canonical_first = &*reduction.first_failure;
            }
        }
        CHECK(failing_reductions >= 2);
        CHECK(canonical_first != nullptr);
        CHECK(assessment.first_failure == *canonical_first);
    });

    runner.run("failed proof-ingress switch rejects exact assessment", [] {
        const LayeredCircuit circuit = compile(width_one_affine_payload());
        HonestPayloadNoiseCalibration payload_calibration = calibration();
        payload_calibration.proof_suffix_level_reserve = 0;
        payload_calibration.switch_rounding_error_bound =
            10'000'000'000'000ULL;
        const HonestPayloadNoiseSchedule core =
            derive_honest_payload_noise_schedule(
                circuit, source_chain(), payload_calibration);
        CHECK(core.payload_model_accepts());
        CHECK(core.base_proof_normalization_plan.reductions.size() == 1);
        const auto &plan =
            core.base_proof_normalization_plan.reductions.front();
        CHECK(plan.natural_source_rns_limb_count == source_chain().size());
        CHECK(plan.proof_ingress_rns_limb_count == 1);

        const HonestNoiseEnvelopeParameters proof_parameters =
            parameters(circuit, core);
        const HonestBaseProofNoiseAssessment assessment =
            assess_honest_base_proof_noise(
                circuit, core, proof_parameters);
        CHECK(assessment.topology_complete);
        CHECK(!assessment.all_messages_fit);
        CHECK(!assessment.report_accepts());
        CHECK(assessment.reductions.size() == 1);
        const auto &reduction = assessment.reductions.front();
        CHECK(reduction.ingress_normalization_steps.size() == 4);
        CHECK(reduction.first_failed_ingress_step.has_value());
        CHECK(!reduction.all_ingress_phases_fit);
        CHECK(!reduction.all_messages_fit);

        const HonestPayloadNoiseSchedule attached =
            attach_honest_base_proof_noise_assessment(
                circuit, core, proof_parameters);
        CHECK(!honest_base_end_to_end_model_accepts(
            circuit, attached, proof_parameters));
    });

    runner.run("depth-seven diagnostic certifies its selected ingress", [] {
        WorkloadSpec spec{
            .kind = WorkloadKind::Diamond,
            .shape = PayloadShape::wide(16'384),
            .multiplicative_depth = 7,
            .width = 7,
            .seed = 1,
        };
        spec.input_count = 7;
        const LayeredCircuit circuit =
            compile(make_workload(spec).circuit);
        const std::vector<std::uint64_t> chain{
            1'053'858'393'162'252'289ULL,
            15'032'614'913ULL,
            53'687'910'401ULL,
            96'638'238'721ULL,
            98'785'755'137ULL,
            118'113'402'881ULL,
            122'408'435'713ULL,
            246'964'387'841ULL,
            272'734'584'833ULL,
        };
        const HonestBaseProofNoiseCalibration proof{
            .ctct_relinearized_debit_bits = 36,
            .plaintext_multiplication_debit_bits = 25,
            .rotation_debit_bits = 0,
        };
        HonestPayloadNoiseCalibration payload{
            .fresh_canonical_error_bound = 59'904,
            .ctct_relinearized_debit_bits = 36,
            .plaintext_multiplication_debit_bits = 24,
            .rotation_debit_bits = 34,
            .maximum_switch_tax_bits = 10,
            .switch_rounding_error_bound = 906,
            .modeled_switch_events_upper_bound = 520'808,
            .switch_model_failure_budget_bits = 110,
            .proof_suffix_level_reserve = 0,
        };
        std::array<bool, 3> exact_accepts{};
        std::array<bool, 3> admitted{};
        std::array<std::vector<std::size_t>, 3> failing_reductions{};
        for (std::size_t reserve = 0; reserve <= 2; ++reserve) {
            payload.proof_suffix_level_reserve = reserve;
            const HonestPayloadNoiseSchedule core =
                derive_honest_payload_noise_schedule(
                    circuit, chain, payload);
            const HonestNoiseEnvelopeParameters proof_parameters =
                derive_honest_base_proof_noise_parameters(
                    circuit, core, proof);
            const HonestPayloadNoiseSchedule attached =
                attach_honest_base_proof_noise_assessment(
                    circuit, core, proof_parameters);
            exact_accepts[reserve] =
                attached.payload_model_accepts() &&
                attached.base_proof_noise_assessment->report_accepts();
            for (const HonestBaseProofReductionNoiseAssessment &reduction :
                 attached.base_proof_noise_assessment->reductions) {
                if (!reduction.all_messages_fit) {
                    failing_reductions[reserve].push_back(
                        reduction.reduction_layer);
                }
            }
            admitted[reserve] = honest_base_end_to_end_model_accepts(
                circuit, attached, proof_parameters);
        }
        CHECK(!exact_accepts[0]);
        CHECK(!exact_accepts[1]);
        CHECK(exact_accepts[2]);
        CHECK(!failing_reductions[0].empty());
        CHECK(!failing_reductions[1].empty());
        CHECK(failing_reductions[2].empty());
        // These probes use one ingress level for every source. The selector
        // below instead admits each source independently, so its failing-layer
        // set can differ. Check the selected schedule and per-source minimality
        // separately.
        CHECK(!admitted[0]);
        CHECK(!admitted[1]);
        CHECK(admitted[2]);

        const HonestPayloadNoiseSchedule selected =
            select_minimal_honest_base_proof_ingress(
                circuit, chain, payload, proof);
        CHECK(selected.calibration.proof_suffix_level_reserve == 0);
        CHECK(selected.modeled_payload_switch_events == 49);
        CHECK(selected.modeled_base_proof_ingress_switch_events == 490);
        CHECK(selected.modeled_base_proof_message_switch_events == 1'344);
        CHECK(selected.modeled_base_proof_switch_events == 1'834);
        CHECK(selected.modeled_switch_events == 1'883);
        const std::uint64_t search_events =
            honest_base_proof_ingress_search_event_upper_bound(
                circuit, chain, payload);
        CHECK(search_events == 7'168);
        const std::uint64_t search_rounding =
            randomized_mod_switch_rounding_heuristic_bound(
                circuit.shape.slot_count, search_events,
                payload.switch_model_failure_budget_bits);
        CHECK(search_rounding == 887);
        CHECK(selected.evaluation_plan
                  .proof_ingress_mult_depth_by_layer.front() ==
              selected.evaluation_plan.trace
                  .required_mult_depth_by_layer.front());
        for (const HonestBaseProofNormalizationLayerPlan &reduction :
             selected.base_proof_normalization_plan.reductions) {
            const std::size_t expected_limbs =
                reduction.reduction_layer % 2U == 0 ? 2U : 3U;
            CHECK(reduction.proof_ingress_rns_limb_count ==
                  expected_limbs);
            if (expected_limbs > 1U) {
                std::vector<std::size_t> lowered =
                    selected.evaluation_plan
                        .proof_ingress_mult_depth_by_layer;
                lowered[reduction.reduction_layer + 1U] =
                    expected_limbs - 2U;
                HonestPayloadNoiseSchedule detached = selected;
                detached.base_proof_noise_assessment.reset();
                const HonestPayloadNoiseSchedule candidate =
                    apply_honest_base_proof_ingress_depths(
                        circuit, std::move(detached), lowered);
                Transcript transcript(
                    "test/BaseProofIngress/coordinate-minimality/v1");
                const auto local =
                    assess_honest_base_proof_reduction_noise(
                        circuit, candidate,
                        reduction.reduction_layer,
                        derive_honest_base_proof_noise_parameters(
                            circuit, candidate, proof),
                        transcript);
                CHECK(!local.all_messages_fit);
            }
        }
        // The scalar reserve is only a floor for the natural payload
        // schedule. Reduction 13 consumes three of its nine naturally
        // available limbs even though the selected floor is one limb, while
        // the later reduction 14 needs two. This guards against accidentally
        // treating the scalar floor as a per-source ceiling.
        const auto &early_high =
            selected.base_proof_normalization_plan.reductions.at(13);
        const auto &later_low =
            selected.base_proof_normalization_plan.reductions.at(14);
        CHECK(early_high.natural_source_rns_limb_count == 9);
        CHECK(early_high.proof_ingress_rns_limb_count == 3);
        CHECK(later_low.natural_source_rns_limb_count == 9);
        CHECK(later_low.proof_ingress_rns_limb_count == 2);
        const HonestNoiseEnvelopeParameters selected_parameters =
            derive_honest_base_proof_noise_parameters(
                circuit, selected, proof);
        CHECK(honest_base_proof_ingress_is_minimal(
            circuit, selected, selected_parameters));

        HonestPayloadNoiseCalibration undercovered = payload;
        undercovered.modeled_switch_events_upper_bound = search_events - 1U;
        CHECK(throws_invalid_argument([&] {
            (void)select_minimal_honest_base_proof_ingress(
                circuit, chain, undercovered, proof);
        }));
        HonestPayloadNoiseCalibration underrounded = payload;
        underrounded.modeled_switch_events_upper_bound = search_events;
        underrounded.switch_rounding_error_bound = 886;
        CHECK(throws_invalid_argument([&] {
            (void)select_minimal_honest_base_proof_ingress(
                circuit, chain, underrounded, proof);
        }));
    });

    runner.run("attached assessment preserves the payload-only binding", [] {
        const LayeredCircuit circuit = compile(mixed_reduction_payload());
        HonestPayloadNoiseSchedule attached =
            select_minimal_honest_base_proof_ingress(
                circuit, source_chain(), calibration(),
                proof_calibration());
        HonestPayloadNoiseSchedule core = attached;
        core.base_proof_noise_assessment.reset();
        const HonestNoiseEnvelopeParameters proof_parameters =
            parameters(circuit, core);
        const Digest core_digest =
            honest_payload_noise_schedule_digest(circuit, core);
        const std::vector<std::uint8_t> core_encoding =
            encode_canonical(circuit, core);

        HonestBaseProofNoiseExecutionAudit audit;
        attached = select_minimal_honest_base_proof_ingress(
            circuit, source_chain(), calibration(),
            proof_calibration(), &audit);
        CHECK(attached.base_proof_noise_assessment.has_value());
        CHECK(attached.payload_model_accepts());
        CHECK(honest_base_end_to_end_model_accepts(
            circuit, attached, proof_parameters));
        CHECK(honest_payload_noise_schedule_digest(circuit, attached) ==
              core_digest);
        CHECK(encode_canonical(circuit, attached) == core_encoding);
        CHECK(attached.base_proof_noise_assessment
                  ->source_payload_schedule_digest == core_digest);
        CHECK(attached.base_proof_noise_assessment
                  ->proof_noise_parameters_digest ==
              honest_noise_envelope_parameters_digest(proof_parameters));
        CHECK(honest_base_proof_noise_assessment_digest(
                  *attached.base_proof_noise_assessment) != Digest{});
        CHECK(audit.virtual_source.padding_objects_returned == 0);

        validate_honest_payload_noise_schedule(circuit, attached);
        validate_honest_base_proof_noise_assessment(
            circuit, attached, proof_parameters);
    });

    runner.run("exact validation rejects parameter and report drift", [] {
        const LayeredCircuit circuit = compile(mixed_reduction_payload());
        const HonestPayloadNoiseSchedule core =
            derive_honest_payload_noise_schedule(
                circuit, source_chain(), calibration());
        const HonestNoiseEnvelopeParameters proof_parameters =
            parameters(circuit, core);
        const HonestPayloadNoiseSchedule attached =
            attach_honest_base_proof_noise_assessment(
                circuit, core, proof_parameters);

        HonestNoiseEnvelopeParameters wrong_parameters = proof_parameters;
        ++wrong_parameters.plaintext_multiplication_debit_bits;
        CHECK(throws_invalid_argument([&] {
            validate_honest_base_proof_noise_assessment(
                circuit, attached, wrong_parameters);
        }));

        HonestPayloadNoiseSchedule changed_report = attached;
        auto &bound = changed_report.base_proof_noise_assessment
                          ->reductions.front()
                          .families.front()
                          .maximum_pre_normalization_canonical_error_bound;
        bound = NaturalMagnitude::add(bound, NaturalMagnitude(1));
        CHECK(honest_base_proof_noise_assessment_digest(
                  *changed_report.base_proof_noise_assessment) !=
              honest_base_proof_noise_assessment_digest(
                  *attached.base_proof_noise_assessment));
        // The lightweight execution check validates topology and bindings;
        // the offline exact boundary additionally replays all arithmetic.
        validate_honest_payload_noise_schedule(circuit, changed_report);
        CHECK(throws_invalid_argument([&] {
            validate_honest_base_proof_noise_assessment(
                circuit, changed_report, proof_parameters);
        }));

        HonestPayloadNoiseSchedule changed_topology = attached;
        ++changed_topology.base_proof_noise_assessment
              ->reductions.front()
              .families.front()
              .extension_message_count;
        CHECK(throws_invalid_argument([&] {
            validate_honest_payload_noise_schedule(
                circuit, changed_topology);
        }));

        changed_topology = attached;
        ++changed_topology.base_proof_noise_assessment
              ->observed_switch_events;
        CHECK(throws_invalid_argument([&] {
            validate_honest_payload_noise_schedule(
                circuit, changed_topology);
        }));

        changed_topology = attached;
        ++changed_topology.base_proof_noise_assessment
              ->reductions.front()
              .ingress_normalization_steps.front()
              .dropped_modulus;
        CHECK(throws_invalid_argument([&] {
            validate_honest_payload_noise_schedule(
                circuit, changed_topology);
        }));

        changed_topology = attached;
        ++changed_topology.base_proof_noise_assessment
              ->reductions.front()
              .families.front()
              .normalization_steps.front()
              .dropped_modulus;
        CHECK(throws_invalid_argument([&] {
            validate_honest_payload_noise_schedule(
                circuit, changed_topology);
        }));

        HonestPayloadNoiseSchedule forged = core;
        forged.base_proof_noise_assessment =
            HonestBaseProofNoiseAssessment{
                .policy = kHonestBaseProofNoiseAssessmentPolicyV6,
                .source_payload_schedule_digest =
                    honest_payload_noise_schedule_digest(circuit, core),
                .proof_noise_parameters_digest =
                    honest_noise_envelope_parameters_digest(
                        proof_parameters),
                .observed_switch_events =
                    core.modeled_base_proof_switch_events,
                .topology_complete = true,
                .all_messages_fit = true,
            };
        CHECK(throws_invalid_argument([&] {
            validate_honest_payload_noise_schedule(circuit, forged);
        }));
        CHECK(throws_invalid_argument([&] {
            (void)honest_base_end_to_end_model_accepts(
                circuit, forged, proof_parameters);
        }));
    });

    runner.run("a derived insufficient proof envelope remains non-admitting",
               [] {
        const LayeredCircuit circuit = compile(mixed_reduction_payload());
        const HonestPayloadNoiseSchedule core =
            derive_honest_payload_noise_schedule(
                circuit, source_chain(), calibration());
        HonestNoiseEnvelopeParameters failing = parameters(circuit, core);
        failing.ctct_relinearized_debit_bits = 512;
        failing.plaintext_multiplication_debit_bits = 512;
        failing.rotation_debit_bits = 512;
        const HonestPayloadNoiseSchedule attached =
            attach_honest_base_proof_noise_assessment(
                circuit, core, failing);
        CHECK(attached.base_proof_noise_assessment.has_value());
        CHECK(!honest_base_end_to_end_model_accepts(
            circuit, attached, failing));
        CHECK(attached.base_proof_noise_assessment->first_failure
                  .has_value());
        validate_honest_payload_noise_schedule(circuit, attached);
        validate_honest_base_proof_noise_assessment(
            circuit, attached, failing);

        HonestPayloadNoiseSchedule malformed_failure = attached;
        malformed_failure.base_proof_noise_assessment->first_failure
            ->coefficient_index = kExtensionDegree;
        for (auto &reduction :
             malformed_failure.base_proof_noise_assessment->reductions) {
            if (reduction.first_failure) {
                reduction.first_failure->coefficient_index =
                    kExtensionDegree;
                break;
            }
        }
        CHECK(throws_invalid_argument([&] {
            validate_honest_payload_noise_schedule(
                circuit, malformed_failure);
        }));
    });

    runner.run("width-one reductions retain only terminal families", [] {
        for (const PayloadCircuit &payload :
             {width_one_affine_payload(),
              width_one_multiplication_payload()}) {
            const LayeredCircuit circuit = compile(payload);
            const HonestPayloadNoiseSchedule attached =
                select_minimal_honest_base_proof_ingress(
                    circuit, source_chain(), calibration(),
                    proof_calibration());
            HonestPayloadNoiseSchedule core = attached;
            core.base_proof_noise_assessment.reset();
            const HonestNoiseEnvelopeParameters proof_parameters =
                parameters(circuit, core);
            CHECK(honest_base_end_to_end_model_accepts(
                circuit, attached, proof_parameters));

            bool found = false;
            for (std::size_t index = 0;
                 index < core.base_proof_normalization_plan
                             .reductions.size();
                 ++index) {
                const auto &plan =
                    core.base_proof_normalization_plan.reductions[index];
                if (plan.wire_variables != 0) {
                    continue;
                }
                found = true;
                CHECK(plan.round_extension_ciphertext_count == 0);
                const auto &assessment =
                    attached.base_proof_noise_assessment
                        ->reductions[index];
                CHECK(assessment.observed_extension_message_count ==
                      plan.terminal_extension_ciphertext_count);
                for (const auto &family : assessment.families) {
                    if (family.extension_message_count == 0) {
                        CHECK(family.normalization_steps.empty());
                    } else {
                        CHECK(family.normalization_steps.size() + 1U ==
                              plan.proof_ingress_rns_limb_count);
                    }
                }
            }
            CHECK(found);
        }
    });

    return runner.summary();
}
