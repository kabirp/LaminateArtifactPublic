/// @file test_laned_fhe_evaluator_seal.cpp
/// @brief Focused real-BGV test for homomorphic Laned payload evaluation.

#include "test_helpers.hpp"

#include "laminate/delegation/laned/client.hpp"
#include "laminate/delegation/laned/reference/client.hpp"
#include "laminate/delegation/laned/reference/server.hpp"
#include "laminate/fhe/seal_backend.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/payload/trace.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

using namespace laminate;
using namespace laminate::delegation;
using namespace laminate::fhe;
using namespace laminate::payload;

namespace {

constexpr std::size_t kSlots = 1024;
constexpr std::size_t kLanes = 8;

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-seal-trace-" + std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (!std::filesystem::exists(path_)) {
                return;
            }
        }
        throw std::runtime_error("failed to select a temporary directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

SlotVector lane_values(std::uint64_t seed) {
    SlotVector result;
    result.reserve(kLanes);
    for (std::size_t lane = 0; lane < kLanes; ++lane) {
        result.emplace_back(seed + 3 * lane + lane * lane);
    }
    return result;
}

PayloadCircuit mixed_laned_payload() {
    PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots), 2);
    const std::size_t scalar = builder.add_scalar_plaintext(Fp(3));
    const std::size_t lane_bias = builder.add_plaintext(
        {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});

    const WireId scaled = builder.mul_plain(0, scalar);
    const WireId lane_shifted = builder.add_plain(1, lane_bias);
    const WireId product = builder.mul(scaled, lane_shifted);
    builder.set_outputs({builder.add(product, scaled)});
    return builder.finish();
}

PayloadCircuit live_zero_laned_payload() {
    PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots), 3);
    const std::size_t zero = builder.add_scalar_plaintext(Fp::zero());
    const std::size_t constant = builder.add_scalar_plaintext(Fp(11));
    const WireId public_zero = builder.mul_plain(0, zero);
    builder.set_outputs(
        {public_zero, builder.add_plain(public_zero, constant)});
    return builder.finish();
}

void check_real_seal_compact_padding_and_live_zero_counts() {
    const PayloadCircuit payload = live_zero_laned_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<LayerWireSupport> support =
        canonical_trace_wire_support(circuit);
    CHECK(support.back().live_wire_count == 3);
    CHECK(support.back().padded_wire_count == 4);
    CHECK(support.front().live_wire_count == 2);

    SealBackend::Contexts contexts = SealBackend::create(SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = 4,
        .bits_per_data_prime = 40,
        .special_prime_bits = 40,
        .security_level = seal::sec_level_type::none,
    });
    const std::vector<SlotVector> inputs{
        lane_values(5), lane_values(41), lane_values(89)};
    const auto encrypted_inputs =
        encrypt_laned_payload_inputs<SealBackend>(contexts.client, payload,
                                                  inputs);
    const std::size_t fresh_depth = SealBackend::remaining_mult_depth(
        contexts.eval, encrypted_inputs.front());
    CHECK(fresh_depth > 0);

    SealBackend::reset_counts(contexts.eval);
    SealBackend::set_counting(contexts.eval, true);
    const EncryptedTrace<SealBackend> compact =
        evaluate_laned_fhe_trace_into<SealBackend>(
            contexts.eval, payload, circuit, encrypted_inputs,
            FheEvaluationPlan::without_payload_switches(circuit,
                                                         fresh_depth - 1),
            InMemoryTraceSink<SealBackend>{contexts.eval});
    SealBackend::set_counting(contexts.eval, false);
    const SealBackend::OperationCounts counts =
        SealBackend::counts(contexts.eval);

    // The live zero output remains a public plaintext. Neither it nor the
    // padded fourth input enters the raw ciphertext backend.
    CHECK(counts.calls(SealBackend::OperationKind::Sub) == 0);
    CHECK(counts.calls(SealBackend::OperationKind::MulPlainScalar) == 0);
    CHECK(compact.layers.back().wires.size() == 3);
    CHECK(compact.layers.front().wires.size() == 2);
    CHECK(compact.layers.front().wires[0].is_public_zero());
    CHECK(compact.layers.front().wires[1].is_public());
    CHECK(!compact.layers.front().wires[1].is_public_zero());
    const SlotVector zero_output = compact.layers.front()
                                       .wires[0]
                                       .plaintext()
                                       .materialize(kSlots);
    CHECK(std::all_of(zero_output.begin(), zero_output.end(),
                      [](const Fp &value) { return value.is_zero(); }));
    const SlotVector constant_output = compact.layers.front()
                                           .wires[1]
                                           .plaintext()
                                           .materialize(kSlots);
    CHECK(std::all_of(constant_output.begin(), constant_output.end(),
                      [](const Fp &value) { return value == Fp(11); }));
}

} // namespace

int main() {
    test::Runner runner("test_fhe_evaluator_seal");

    runner.run("real SEAL role boundary evaluates a mixed Laned payload", [] {
        const PayloadCircuit payload = mixed_laned_payload();
        const LayeredCircuit circuit = compile(payload);
        const std::vector<SlotVector> inputs{lane_values(5), lane_values(41)};
        const PlainTrace reference =
            synthesize_trace(payload, circuit, inputs);

        SealBackend::Contexts contexts = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 4,
            .bits_per_data_prime = 40,
            .special_prime_bits = 40,
            .security_level = seal::sec_level_type::none,
        });
        const PublicSetup public_setup = make_direct_setup(payload, circuit);
        const EvaluationSetup<SealBackend> server =
            make_evaluation_setup<SealBackend>(public_setup, contexts.eval);
        const ClientSetup<SealBackend> client =
            make_client_setup<SealBackend>(public_setup, contexts.client);
        std::array<std::uint8_t, 32> nonce_bytes{};
        for (std::size_t index = 0; index < nonce_bytes.size(); ++index) {
            nonce_bytes[index] = static_cast<std::uint8_t>(31 + index);
        }
        LanedClientRequestStart<SealBackend> started =
            delegation::reference::begin_laned_request_resident_reference<SealBackend>(
                payload, circuit, client, inputs,
                make_laned_client_nonce(nonce_bytes));

        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        const EncryptedTrace<SealBackend> compact =
            evaluate_laned_fhe_trace<SealBackend>(
                contexts.eval, payload, circuit,
                started.request.encrypted_inputs,
                FheEvaluationPlan::switch_after_multiplication_layers(
                    circuit, 1));
        SealBackend::set_counting(contexts.eval, false);

        const SealBackend::OperationCounts counts =
            SealBackend::counts(contexts.eval);
        CHECK(counts.calls(SealBackend::OperationKind::Decrypt) == 0);
        CHECK(counts.calls(SealBackend::OperationKind::MulNoRelin) > 0);
        CHECK(counts.calls(SealBackend::OperationKind::Relinearize) > 0);
        CHECK(counts.calls(SealBackend::OperationKind::MulPlainScalar) > 0);
        CHECK(counts.calls(SealBackend::OperationKind::MulPlainVector) == 0);
        CHECK(counts.calls(SealBackend::OperationKind::AddPlain) > 0);
        CHECK(counts.calls(SealBackend::OperationKind::ModSwitch) > 0);

        CHECK(compact.provenance ==
              TraceProvenance::FheEvaluated);
        CHECK(compact.circuit_id ==
              combined_digest(payload, circuit));
        CHECK(compact.trace_id ==
              fhe_evaluated_trace_id<SealBackend>(
                  payload, circuit, started.request.encrypted_inputs));
        CHECK(compact.backend_context_id.has_value());
        CHECK(*compact.backend_context_id ==
              SealBackend::storage_context_id(contexts.eval));
        CHECK(!compact.layers.front().wires.empty());

        int minimum_noise = std::numeric_limits<int>::max();
        bool saw_ciphertext = false;
        for (const EncryptedTraceLayer<SealBackend> &layer :
             compact.layers) {
            for (const FheValue<SealBackend> &value : layer.wires) {
                if (value.is_public()) {
                    CHECK(value.plaintext().materialize(kSlots).size() ==
                          kSlots);
                    continue;
                }
                saw_ciphertext = true;
                minimum_noise = std::min(
                    minimum_noise,
                    SealBackend::invariant_noise_budget(contexts.client,
                                                        value.ciphertext()));
            }
        }
        CHECK(saw_ciphertext);
        CHECK(minimum_noise > 0);

        const auto decrypted = decrypt_trace_layers<SealBackend>(
            contexts.client, circuit, compact);
        CHECK(decrypted == reference.layers);

        // The same real-SEAL evaluation can emit prepared snapshots directly
        // into a bounded file store. This toy store exercises persistence and
        // repeated decoding; it is not a target-scale disk run.
        TemporaryDirectory directory;
        const FheEvaluationPlan disk_plan =
            FheEvaluationPlan::switch_after_multiplication_layers(circuit,
                                                                   1);
        FileLanedServerEvaluationResult<SealBackend> file_evaluated =
            delegation::reference::evaluate_laned_request_file_reference<SealBackend>(
                payload, circuit, server, started.request, disk_plan,
                directory.path(),
                FileTraceStoreOptions{
                    .max_total_bytes = std::uint64_t{1} << 30U,
                    .min_free_bytes = 1,
                });
        const FileTraceStoreWriteResult &disk_result =
            file_evaluated.state.trace_store;
        const std::vector<std::uint8_t> evaluation_bundle =
            SealBackend::serialize_evaluation_context_bundle(contexts.eval);
        const std::vector<std::uint8_t> client_bundle =
            SealBackend::serialize_client_context_bundle(contexts.client);
        SealBackend::Contexts reloaded =
            SealBackend::deserialize_context_bundles(evaluation_bundle,
                                                     client_bundle);
        CHECK(SealBackend::storage_context_id(reloaded.eval) ==
              SealBackend::storage_context_id(contexts.eval));
        CHECK(SealBackend::storage_ciphertext_byte_limit(reloaded.eval) ==
              SealBackend::storage_ciphertext_byte_limit(contexts.eval));
        const auto disk_trace = FileEncryptedTraceStore<SealBackend>::open(
            contexts.eval, directory.path(), payload, circuit,
            disk_result.descriptor.provenance,
            disk_result.descriptor.trace_id);
        const auto reloaded_disk_trace =
            FileEncryptedTraceStore<SealBackend>::open(
                reloaded.eval, directory.path(), payload, circuit,
                disk_result.descriptor.provenance,
                disk_result.descriptor.trace_id);
        const auto other_key = SealBackend::create(contexts.eval.parameters);
        CHECK(throws_invalid_argument([&] {
            (void)FileEncryptedTraceStore<SealBackend>::open(
                other_key.eval, directory.path(), payload, circuit,
                disk_result.descriptor.provenance,
                disk_result.descriptor.trace_id);
        }));

        TemporaryDirectory mismatched_sink_directory;
        CHECK(throws_invalid_argument([&] {
            (void)evaluate_laned_fhe_trace_into<SealBackend>(
                contexts.eval, payload, circuit,
                started.request.encrypted_inputs, disk_plan,
                FileEncryptedTraceSink<SealBackend>(
                    other_key.eval, mismatched_sink_directory.path(),
                    FileTraceStoreOptions{
                        .max_total_bytes = std::uint64_t{1} << 30U,
                        .min_free_bytes = 1,
                    }));
        }));
        CHECK(!std::filesystem::exists(
            mismatched_sink_directory.path() / "manifest.bin"));

        TemporaryDirectory mismatched_trace_directory;
        CHECK(throws_invalid_argument([&] {
            (void)write_file_encrypted_trace<SealBackend>(
                other_key.eval, mismatched_trace_directory.path(),
                FileTraceStoreOptions{
                    .max_total_bytes = std::uint64_t{1} << 30U,
                    .min_free_bytes = 1,
                },
                circuit, compact);
        }));
        CHECK(!std::filesystem::exists(
            mismatched_trace_directory.path()));
        CHECK(disk_result.descriptor == descriptor_of(compact));
        CHECK(disk_trace.descriptor() == disk_result.descriptor);
        for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
            const auto support =
                canonical_layer_wire_support(circuit, layer);
            auto reader = disk_trace.layer_reader(layer);
            std::size_t live = 0;
            for (std::size_t padded = 0;
                 padded < support.padded_wire_count; ++padded) {
                const auto actual = reader.next();
                CHECK(actual.has_value());
                if (!support.is_live(padded)) {
                    CHECK(actual->is_public_zero());
                    continue;
                }
                CHECK(!actual->is_public_zero());
                const FheValue<SealBackend> &compact_value =
                    compact.layers[layer].wires[live];
                CHECK(actual->is_public() == compact_value.is_public());
                CHECK(materialize_or_decrypt<SealBackend>(
                          contexts.client, *actual) ==
                      expand_for_encryption(
                          circuit.shape,
                          reference.layers[layer][padded]));
                if (actual->is_public()) {
                    CHECK(actual->plaintext() ==
                          compact_value.plaintext());
                } else {
                    CHECK(SealBackend::rns_limb_count(
                              contexts.eval, actual->ciphertext()) ==
                          SealBackend::rns_limb_count(
                              contexts.eval,
                              compact_value.ciphertext()));
                }
                ++live;
            }
            CHECK(live == compact.layers[layer].wires.size());
            CHECK(!reader.next().has_value());

            auto reloaded_reader = reloaded_disk_trace.layer_reader(layer);
            live = 0;
            for (std::size_t padded = 0;
                 padded < support.padded_wire_count; ++padded) {
                const auto actual = reloaded_reader.next();
                CHECK(actual.has_value());
                if (!support.is_live(padded)) {
                    CHECK(actual->is_public_zero());
                    continue;
                }
                CHECK(!actual->is_public_zero());
                CHECK(materialize_or_decrypt<SealBackend>(
                          reloaded.client, *actual) ==
                      expand_for_encryption(
                          circuit.shape,
                          reference.layers[layer][padded]));
                ++live;
            }
            CHECK(live == compact.layers[layer].wires.size());
            CHECK(!reloaded_reader.next().has_value());
        }

        const Digest request_commitment =
            packed_request_commitment<SealBackend>(
                PackedProtocolVariant::Laned, started.request.setup_id,
                started.request.session_id, started.request.circuit_id,
                started.request.trace_id);
        const Digest statement_digest =
            packed_encrypted_statement_digest<SealBackend>(
                PackedProtocolVariant::Laned, request_commitment,
                started.request.setup_id, started.request.session_id,
                started.request.circuit_id, started.request.trace_id,
                file_evaluated.output.dimensions,
                file_evaluated.output.values);
        Transcript output_transcript(
            "test/delegation/laned/seal-output-point/v1");
        output_transcript.observe(
            "delegation-setup-id",
            std::span<const std::uint8_t>(started.request.setup_id));
        output_transcript.observe(
            "delegation-session-id",
            std::span<const std::uint8_t>(started.request.session_id));
        const std::vector<Fpk> output_point = derive_packed_output_point(
            output_transcript, PackedProtocolVariant::Laned,
            statement_digest, gkr::laned_layer_variables(circuit, 0));
        const std::vector<SlotVector> decrypted_output =
            decrypt_trace_layer<SealBackend>(
                client.context, circuit, circuit.shape,
                EncryptedTraceLayerView<SealBackend>{
                    TraceLayerLayout::BPeriodic,
                    file_evaluated.output.dimensions, 0,
                    file_evaluated.output.values},
                0);
        const gkr::SingleClaim actual_claim = gkr::make_packed_laned_claim(
            decrypted_output, gkr::laned_layout(circuit, 0), output_point);
        const gkr::SingleClaim expected_claim = gkr::make_packed_laned_claim(
            reference.layers.front(), gkr::laned_layout(circuit, 0),
            output_point);
        CHECK(actual_claim == expected_claim);
    });
    runner.run("real SEAL compact Laned padding stays plaintext",
               check_real_seal_compact_padding_and_live_zero_counts);

    return runner.summary();
}
