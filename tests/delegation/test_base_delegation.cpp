/// @file test_base_delegation.cpp
/// @brief Bounded role-separated LaminateBase delegation on Mock FHE.

#include "test_helpers.hpp"

#include "laminate/delegation/base/client.hpp"
#include "laminate/delegation/base/profiling/client.hpp"
#include "laminate/delegation/base/reference/resident.hpp"
#include "laminate/delegation/base/server.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"
#include "laminate/transcript/hash.hpp"
#include "laminate/verification_profile.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::delegation;
using namespace laminate::fhe;
using namespace laminate::payload;

namespace {

template <typename Proof>
concept HasPlaintextOutputClaim = requires(Proof proof) {
    proof.output_claim;
};

static_assert(!std::is_default_constructible_v<BaseClientNonce>);
static_assert(!std::is_copy_constructible_v<BaseClientNonce>);
static_assert(!std::is_copy_constructible_v<BaseClientAwaitingResponse>);
static_assert(!std::is_copy_constructible_v<BaseClientOpenedResponse>);
static_assert(
    !std::is_copy_constructible_v<
        reference::BaseServerEvaluated<MockBackend>>);
static_assert(std::is_move_constructible_v<BaseClientNonce>);
static_assert(std::is_move_constructible_v<BaseClientAwaitingResponse>);
static_assert(std::is_move_constructible_v<BaseClientOpenedResponse>);
static_assert(
    std::is_move_constructible_v<
        reference::BaseServerEvaluated<MockBackend>>);
static_assert(
    !HasPlaintextOutputClaim<gkr::EncryptedBaseProof<MockBackend>>);

constexpr std::size_t kSlots = 8;

BaseClientNonce nonce(std::uint8_t seed) {
    std::array<std::uint8_t, 32> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>(seed + index);
    }
    return make_base_client_nonce(bytes);
}

SlotVector values(std::uint64_t seed) {
    SlotVector result;
    result.reserve(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        result.emplace_back(seed + 5 * slot + slot * slot);
    }
    return result;
}

std::uint64_t counted_fhe_operations(const OperationCounts &counts) {
    return counts.encrypt + counts.decrypt + counts.negate + counts.add +
           counts.sub + counts.mul_no_relin + counts.relinearize +
           counts.add_plain + counts.mul_plain_scalar +
           counts.mul_plain_vector + counts.rotate + counts.mod_switch +
           counts.logical_ext_add + counts.logical_ext_sub +
           counts.logical_ext_mul + counts.logical_ext_mul_plain;
}

struct Roles {
    MockBackend::Contexts contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 12,
        .bits_per_limb = 300,
    });
    PublicSetup public_setup;
    EvaluationSetup<MockBackend> server;
    ClientSetup<MockBackend> client;

    Roles(const PayloadCircuit &payload, const LayeredCircuit &circuit)
        : public_setup(make_direct_setup(payload, circuit)),
          server(make_evaluation_setup<MockBackend>(public_setup,
                                                     contexts.eval)),
          client(make_client_setup<MockBackend>(public_setup,
                                                 contexts.client)) {}
};

PayloadCircuit one_product_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 2);
    builder.set_outputs({builder.mul(0, 1)});
    return builder.finish();
}

PayloadCircuit padded_rotation_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 3);
    builder.set_outputs({builder.rotate(0, 1), builder.rotate(1, 3),
                         builder.rotate(2, 5)});
    return builder.finish();
}

PayloadCircuit aliased_dense_products_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 2);
    builder.set_outputs(
        {builder.mul(0, 1), builder.mul(0, 1), builder.mul(0, 1)});
    return builder.finish();
}

void check_complete_base_exchange() {
    const PayloadCircuit payload = one_product_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(7), values(53)};
    const PlainTrace expected = synthesize_trace(payload, circuit, inputs);
    Roles roles(payload, circuit);
    const protocol::CertifiedBaseClientSetup<MockBackend> certified =
        protocol::certify_base_client_setup<MockBackend>(
            payload, circuit, roles.client);

    MockBackend::reset_counts(roles.contexts.eval);
    auto encrypted_inputs = encrypt_wide_payload_inputs<MockBackend>(
        roles.contexts.client, payload, inputs);
    CHECK(MockBackend::counts(roles.contexts.eval).encrypt == inputs.size());
    BaseClientRequestStart<MockBackend> started =
        base_client_detail::
            bind_validated_base_request_session<MockBackend>(
                certified, inputs, std::move(encrypted_inputs), nonce(1));
    CHECK(MockBackend::counts(roles.contexts.eval).encrypt == inputs.size());
    CHECK(started.request.encrypted_inputs.size() == inputs.size());
    CHECK(started.request.trace_id != Digest{});

    MockBackend::reset_counts(roles.contexts.eval);
    reference::BaseServerEvaluationResult<MockBackend> evaluated =
        reference::evaluate_base_request<MockBackend>(
            payload, circuit, roles.server, started.request,
            FheEvaluationPlan::without_payload_switches(circuit, 5));
    const OperationCounts evaluation_counts =
        MockBackend::counts(roles.contexts.eval);
    CHECK(evaluation_counts.decrypt == 0);
    CHECK(evaluation_counts.encrypt == 0);
    CHECK(evaluation_counts.sub == 0);
    CHECK(evaluation_counts.mul_no_relin == 1);
    CHECK(evaluated.output.values.size() == 1);
    CHECK(evaluated.output.dimensions.padded_size == 1);
    CHECK(evaluated.output.values.data() !=
          evaluated.state.trace().layers.front().wires.data());

    MockBackend::reset_counts(roles.contexts.eval);
    Transcript prover_transcript("test/delegation/base/v1");
    const BaseResponse<MockBackend> response =
        reference::prove_base_request<MockBackend>(
            payload, circuit, roles.server, std::move(evaluated),
            prover_transcript);
    CHECK(MockBackend::counts(roles.contexts.eval).decrypt == 0);

    // Recreate the same client state without re-encrypting the request so the
    // opt-in timing path can be compared against ordinary verification.
    auto unprofiled =
        base_client_detail::bind_validated_base_request_session<MockBackend>(
            certified, inputs, started.request.encrypted_inputs, nonce(1));
    verification_profile::VerificationBreakdown breakdown;
    Transcript verifier_transcript("test/delegation/base/v1");
    std::optional<BaseClientOpenedResponse> opened;
    {
        verification_profile::ScopedVerificationSession session(breakdown);
        opened = open_base_response<MockBackend>(
            certified, std::move(started.state), response,
            verifier_transcript);
    }
    CHECK(opened.has_value());
    CHECK(breakdown.phase_entries(
              verification_profile::Category::OutputDecryption) == 1U);
    CHECK(breakdown.phase_entries(
              verification_profile::Category::Recovery) > 0U);
    CHECK(MockBackend::counts(roles.contexts.eval).decrypt == 1);
    MockBackend::reset_counts(roles.contexts.eval);
    protocol::BaseVerifierTimings verifier_timings;
    std::optional<std::vector<SlotVector>> outputs;
    {
        verification_profile::ScopedVerificationSession session(breakdown);
        outputs = verify_opened_base_response_profiled<MockBackend>(
            certified, std::move(*opened), response, verifier_transcript,
            verifier_timings);
    }
    CHECK(breakdown.phase_entries(
              verification_profile::Category::OutputDecryption) == 1U);
    CHECK(MockBackend::counts(roles.contexts.eval).decrypt ==
          protocol::measure_proof_size(response.proof).base_ciphertexts);
    CHECK(verifier_timings.layers.size() == response.proof.reductions.size());
    CHECK(outputs.has_value());
    CHECK(outputs->size() == 1);
    CHECK(outputs->front() == expected.layers.front().front());

    Transcript ordinary_transcript("test/delegation/base/v1");
    const auto ordinary_outputs = verify_base_response<MockBackend>(
        certified, std::move(unprofiled.state), response, ordinary_transcript);
    CHECK(ordinary_outputs == outputs);
    CHECK(ordinary_transcript.challenge_fpk() ==
          verifier_transcript.challenge_fpk());
}

void check_session_binding() {
    const PayloadCircuit payload = one_product_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(11), values(71)};
    Roles roles(payload, circuit);

    BaseClientRequestStart<MockBackend> first =
        reference::begin_base_request_resident_reference<MockBackend>(
            payload, circuit, roles.client, inputs, nonce(7));
    reference::BaseServerEvaluationResult<MockBackend>
        first_evaluated =
            reference::evaluate_base_request<MockBackend>(
            payload, circuit, roles.server, first.request,
            FheEvaluationPlan::without_payload_switches(circuit, 5));
    Transcript prover_transcript("test/delegation/base/session/v1");
    const BaseResponse<MockBackend> first_response =
        reference::prove_base_request<MockBackend>(
            payload, circuit, roles.server,
            std::move(first_evaluated), prover_transcript);

    BaseClientRequestStart<MockBackend> second =
        reference::begin_base_request_resident_reference<MockBackend>(
            payload, circuit, roles.client, inputs, nonce(107));
    CHECK(first_response.session_id != second.request.session_id);

    Transcript verifier_transcript("test/delegation/base/session/v1");
    CHECK(!reference::verify_base_response_resident_reference<MockBackend>(
               payload, circuit, roles.client,
               std::move(second.state), first_response,
               verifier_transcript)
               .has_value());
}

void check_encrypted_statement_binding() {
    const PayloadCircuit payload = one_product_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(13), values(89)};
    Roles roles(payload, circuit);

    BaseClientRequestStart<MockBackend> started =
        reference::begin_base_request_resident_reference<MockBackend>(
            payload, circuit, roles.client, inputs, nonce(23));
    auto evaluated =
        reference::evaluate_base_request<MockBackend>(
            payload, circuit, roles.server, started.request,
            FheEvaluationPlan::without_payload_switches(circuit, 5));
    Transcript prover_transcript(
        "test/delegation/base/statement-binding/v1");
    BaseResponse<MockBackend> response =
        reference::prove_base_request<MockBackend>(
            payload, circuit, roles.server, std::move(evaluated),
            prover_transcript);
    CHECK(!response.output.values.empty());
    CHECK(response.output.values.front().is_encrypted());
    response.output.values.front().ciphertext().slots.front() += Fp::one();

    Transcript verifier_transcript(
        "test/delegation/base/statement-binding/v1");
    CHECK(!reference::verify_base_response_resident_reference<MockBackend>(
               payload, circuit, roles.client, std::move(started.state),
               response, verifier_transcript)
               .has_value());
}

void check_padding_stays_plaintext_zero() {
    const PayloadCircuit payload = padded_rotation_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(3), values(37), values(91)};
    Roles roles(payload, circuit);
    BaseClientRequestStart<MockBackend> started =
        reference::begin_base_request_resident_reference<MockBackend>(
            payload, circuit, roles.client, inputs, nonce(19));

    MockBackend::reset_counts(roles.contexts.eval);
    reference::BaseServerEvaluationResult<MockBackend> evaluated =
        reference::evaluate_base_request<MockBackend>(
            payload, circuit, roles.server, started.request,
            FheEvaluationPlan::without_payload_switches(circuit, 3));
    const OperationCounts counts = MockBackend::counts(roles.contexts.eval);
    CHECK(counts.encrypt == 0);
    CHECK(counts.sub == 0);

    const auto support = canonical_trace_wire_support(circuit);
    const auto storage = canonical_trace_storage_layout(circuit);
    const auto &trace = evaluated.state.trace();
    bool saw_padding = false;
    for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
        CHECK(trace.layers[layer].wires.size() ==
              storage[layer].stored_wire_count);
        CHECK(trace.layers[layer].dimensions.padded_size ==
              support[layer].padded_wire_count);
        saw_padding = saw_padding ||
                      support[layer].live_wire_count <
                          support[layer].padded_wire_count;
    }
    CHECK(saw_padding);
    CHECK(evaluated.output.values.size() == 3);
    CHECK(evaluated.output.dimensions.padded_size == 4);

    bool rejected_without_padding_materialization = false;
    try {
        Transcript transcript("test/delegation/base/padded/v1");
        (void)reference::prove_base_request<MockBackend>(
            payload, circuit, roles.server, std::move(evaluated),
            transcript);
    } catch (const std::logic_error &) {
        rejected_without_padding_materialization = true;
    }
    CHECK(rejected_without_padding_materialization);
}

void check_aliased_dense_source_is_valid_compact_trace() {
    const PayloadCircuit payload = aliased_dense_products_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(23), values(61)};
    const auto support = canonical_trace_wire_support(circuit);
    const auto storage = canonical_trace_storage_layout(circuit);
    bool found_alias = false;
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        found_alias = found_alias ||
                      storage[layer].stored_wire_count <
                          support[layer].live_wire_count;
    }
    CHECK(found_alias);

    Roles roles(payload, circuit);
    BaseClientRequestStart<MockBackend> started =
        reference::begin_base_request_resident_reference<MockBackend>(
            payload, circuit, roles.client, inputs, nonce(31));
    reference::BaseServerEvaluationResult<MockBackend> evaluated =
        reference::evaluate_base_request<MockBackend>(
            payload, circuit, roles.server, started.request,
            FheEvaluationPlan::without_payload_switches(circuit, 5));
    const auto &trace = evaluated.state.trace();
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        CHECK(trace.layers[layer].wires.size() ==
              storage[layer].stored_wire_count);
    }
    CHECK(evaluated.output.values.size() == 3);
}

void check_bound_schedule_rejects_unbound_resident_plan() {
    const PayloadCircuit payload = one_product_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(17), values(83)};
    MockBackend::Contexts contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 12,
        .bits_per_limb = 300,
    });
    PublicSetup public_setup = make_direct_setup(payload, circuit);
    Digest bound_schedule{};
    bound_schedule.front() = 1U;
    public_setup.honest_payload_noise_schedule_digest = bound_schedule;
    const EvaluationSetup<MockBackend> server =
        make_evaluation_setup<MockBackend>(public_setup, contexts.eval);
    const ClientSetup<MockBackend> client =
        make_client_setup<MockBackend>(public_setup, contexts.client);
    BaseClientRequestStart<MockBackend> started =
        reference::begin_base_request_resident_reference<MockBackend>(
            payload, circuit, client, inputs, nonce(29));

    MockBackend::reset_counts(contexts.eval);
    bool rejected = false;
    try {
        (void)reference::evaluate_base_request<MockBackend>(
            payload, circuit, server, started.request,
            FheEvaluationPlan::without_payload_switches(circuit, 5));
    } catch (const std::invalid_argument &) {
        rejected = true;
    }
    CHECK(rejected);
    CHECK(counted_fhe_operations(MockBackend::counts(contexts.eval)) == 0);
}

void check_certified_client_setup_owns_immutable_static_inputs() {
    PayloadCircuit payload = one_product_payload();
    LayeredCircuit circuit = compile(payload);
    MockBackend::Contexts contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 12,
        .bits_per_limb = 300,
    });
    PublicSetup public_setup = make_direct_setup(payload, circuit);
    ClientSetup<MockBackend> client = make_client_setup<MockBackend>(
        public_setup, contexts.client);
    protocol::CertifiedBaseClientSetup<MockBackend> certified =
        protocol::certify_base_client_setup<MockBackend>(
            payload, circuit, client);

    const Digest circuit_id = certified.circuit_id();
    const std::size_t payload_gate_count = payload.gates.size();
    const std::size_t layer_count = circuit.layers.size();
    payload.gates.clear();
    circuit.layers.clear();
    client.public_setup.circuit_digest = Digest{};
    CHECK(certified.circuit_id() == circuit_id);
    CHECK(certified.payload().gates.size() == payload_gate_count);
    CHECK(certified.circuit().layers.size() == layer_count);
    CHECK(certified.layout().storage.size() == layer_count);

    protocol::CertifiedBaseClientSetup<MockBackend> moved =
        std::move(certified);
    CHECK(moved.circuit_id() == circuit_id);
    bool moved_from_rejected = false;
    try {
        (void)certified.circuit_id();
    } catch (const std::logic_error &) {
        moved_from_rejected = true;
    }
    CHECK(moved_from_rejected);
}

void check_certified_client_static_setup_round_trip() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 2);
    const std::size_t bias = builder.add_scalar_plaintext(Fp(7));
    const WireId shifted = builder.add_plain(0, bias);
    const WireId rotated = builder.rotate(shifted, 1);
    builder.set_outputs({builder.mul(rotated, 1)});
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit circuit = compile(payload);
    MockBackend::Contexts contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 12,
        .bits_per_limb = 300,
    });
    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const auto certified =
        protocol::certify_base_client_setup<MockBackend>(
            payload, circuit,
            make_client_setup<MockBackend>(public_setup, contexts.client));
    const std::vector<std::uint8_t> encoded =
        protocol::encode_base_client_static_setup(certified);
    const protocol::BaseClientStaticSetupDecodeLimits limits{
        .max_artifact_bytes = 1U << 20U,
        .max_slots = kSlots,
        .max_payload_plaintexts = 16,
        .max_payload_gates = 128,
        .max_payload_outputs = 16,
        .max_layers = 16,
        .max_layer_gates = 128,
        .max_affine_terms = 1024,
        .max_storage_entries = 2048,
    };
    auto authenticated =
        protocol::decode_authenticated_base_client_static_setup(
            encoded, sha256(encoded), certified.setup_id(),
            certified.circuit_id(), limits);
    const auto restored = protocol::restore_base_client_setup<MockBackend>(
        std::move(authenticated),
        make_client_setup<MockBackend>(public_setup, contexts.client));
    CHECK(payload::encode_canonical(restored.payload()) ==
          payload::encode_canonical(certified.payload()));
    CHECK(payload::encode_canonical(restored.circuit()) ==
          payload::encode_canonical(certified.circuit()));
    CHECK(restored.layout() == certified.layout());
    CHECK(restored.setup_id() == certified.setup_id());

    std::vector<std::uint8_t> corrupted = encoded;
    corrupted.back() ^= 1U;
    bool corruption_rejected = false;
    try {
        (void)protocol::decode_authenticated_base_client_static_setup(
            corrupted, sha256(encoded), certified.setup_id(),
            certified.circuit_id(), limits);
    } catch (const std::invalid_argument &) {
        corruption_rejected = true;
    }
    CHECK(corruption_rejected);

    Digest wrong_circuit = certified.circuit_id();
    wrong_circuit.front() ^= 1U;
    bool binding_rejected = false;
    try {
        (void)protocol::decode_authenticated_base_client_static_setup(
            encoded, sha256(encoded), certified.setup_id(), wrong_circuit,
            limits);
    } catch (const std::invalid_argument &) {
        binding_rejected = true;
    }
    CHECK(binding_rejected);
}

} // namespace

int main() {
    laminate::test::Runner runner("test_base_delegation");
    runner.run("test-only resident one-request/one-response Base exchange verifies",
               check_complete_base_exchange);
    runner.run("test-only resident session identifiers prevent proof replay",
               check_session_binding);
    runner.run("the full encrypted response binds the Fiat-Shamir point",
               check_encrypted_statement_binding);
    runner.run("compact padding is plaintext zero, never ciphertext",
               check_padding_stays_plaintext_zero);
    runner.run("compact evaluation accepts canonical aliased storage",
               check_aliased_dense_source_is_valid_compact_trace);
    runner.run("bound schedules reject the unbound resident plan overload",
               check_bound_schedule_rejects_unbound_resident_plan);
    runner.run("certified client setup owns immutable static inputs",
               check_certified_client_setup_owns_immutable_static_inputs);
    runner.run("certified client static setup is authenticated and restored",
               check_certified_client_static_setup_round_trip);
    return runner.summary();
}
