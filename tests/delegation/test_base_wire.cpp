/// @file test_base_wire.cpp
/// @brief Canonical, bounded one-request/one-response Base envelopes.

#include "test_helpers.hpp"

#include "laminate/delegation/base/client.hpp"
#include "laminate/delegation/base/reference/resident.hpp"
#include "laminate/delegation/base/server.hpp"
#include "laminate/delegation/base/wire/codec.hpp"
#include "laminate/fhe/mock_backend.hpp"
#ifdef LAMINATE_WITH_SEAL
#include "laminate/fhe/seal_backend.hpp"
#endif
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace.hpp"
#include "laminate/protocol/reference/base.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::delegation;
using namespace laminate::fhe;
using namespace laminate::payload;

namespace {

constexpr std::size_t kSlots = 8;

BaseWireDecodeLimits limits() {
    return BaseWireDecodeLimits{
        .max_message_bytes = 64U << 20U,
        .max_ciphertexts = 1U << 16U,
        .max_ciphertext_bytes = 2U << 20U,
        .max_total_ciphertext_bytes = 48U << 20U,
        .max_claim_coordinates = 128,
        .max_proof_bytes = 48U << 20U,
        .max_reductions = 64,
        .max_rounds_per_reduction = 256,
        .max_gate_proof_rounds = 256,
        .max_partial_gate_values = 1U << 16U,
        .max_gate_claims = 1U << 16U,
        .max_gate_target_values = 1U << 20U,
        .max_basefold_queries = 512,
        .max_merkle_path_digests = 128,
        .max_total_field_elements = 1U << 22U,
        .max_total_digests = 1U << 22U,
    };
}

BaseClientNonce nonce(std::uint8_t seed) {
    std::array<std::uint8_t, 32> random{};
    for (std::size_t index = 0; index < random.size(); ++index) {
        random[index] = static_cast<std::uint8_t>(seed + index);
    }
    return make_base_client_nonce(random);
}

SlotVector values(std::uint64_t seed) {
    SlotVector result;
    result.reserve(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        result.emplace_back(seed + 7 * slot + slot * slot);
    }
    return result;
}

PayloadCircuit product_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 2);
    builder.set_outputs({builder.mul(0, 1)});
    return builder.finish();
}

PayloadCircuit wide_affine_product_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 2);
    const auto mask = builder.add_plaintext(values(7));
    const auto input = builder.mul_plain(builder.rotate(0, 5), mask);
    builder.set_outputs({builder.add_plain(builder.mul(input, 1), mask)});
    return builder.finish();
}

template <typename Function> void check_rejected(Function &&function) {
    bool rejected = false;
    try {
        std::forward<Function>(function)();
    } catch (const std::invalid_argument &) {
        rejected = true;
    }
    CHECK(rejected);
}

struct Roles {
    MockBackend::Contexts contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 12,
        .bits_per_limb = 300,
    });
    std::shared_ptr<const gates::GateTableProverKey> prover_key;
    PublicSetup public_setup;
    EvaluationSetup<MockBackend> server;
    ClientSetup<MockBackend> client;

    Roles(const PayloadCircuit &payload, const LayeredCircuit &circuit,
          bool outsourced)
        : prover_key(
              outsourced
                  ? std::make_shared<gates::GateTableProverKey>(
                        gates::preprocess_gate_tables(
                            circuit, gates::GateTableSet::Wide))
                  : nullptr),
          public_setup(
              prover_key
                  ? make_outsourced_gate_setup(payload, circuit,
                                               prover_key->verifier)
                  : make_direct_setup(payload, circuit)),
          server(make_evaluation_setup<MockBackend>(
              public_setup, contexts.eval, prover_key)),
          client(make_client_setup<MockBackend>(public_setup,
                                                contexts.client)) {}
};

void check_ciphertexts(
    const MockBackend::EvalContext &eval,
    const std::vector<MockBackend::Ciphertext> &expected,
    const std::vector<MockBackend::Ciphertext> &actual) {
    CHECK(expected.size() == actual.size());
    for (std::size_t index = 0; index < expected.size(); ++index) {
        CHECK(MockBackend::serialize_for_storage(eval, expected[index]) ==
              MockBackend::serialize_for_storage(eval, actual[index]));
    }
}

template <FheBackend Backend>
void install_mixed_round_fixture(gkr::EncryptedBaseProof<Backend> &proof,
                                 std::size_t slot_count) {
    std::vector<Fpk> public_slot_values;
    public_slot_values.reserve(slot_count);
    for (std::size_t slot = 0; slot < slot_count; ++slot) {
        public_slot_values.push_back(Fpk::from_base(Fp(31 + slot)));
    }
    for (auto &layer : proof.reductions) {
        bool installed = false;
        std::visit(
            [&](auto &reduction) {
                for (auto &round : reduction.rounds) {
                    for (std::size_t evaluation = 0;
                         evaluation < 2U; ++evaluation) {
                        auto &candidate = round.evaluations[evaluation];
                        for (std::size_t coefficient = 0;
                             coefficient < kExtensionDegree;
                             ++coefficient) {
                            if (!candidate[coefficient].is_encrypted()) {
                                continue;
                            }
                            FheValue<Backend> saved =
                                candidate[coefficient];
                            Fpk::Coefficients public_coefficients{};
                            public_coefficients[
                                (coefficient + 1U) % kExtensionDegree] =
                                Fp(19);
                            candidate =
                                ExtensionValue<Backend>::public_scalar(
                                    Fpk(public_coefficients));
                            candidate[coefficient] = std::move(saved);
                            round.evaluations[1U - evaluation] =
                                ExtensionValue<Backend>::public_slots(
                                    public_slot_values);
                            installed = true;
                            return;
                        }
                    }
                }
            },
            layer);
        if (installed) {
            return;
        }
    }
    throw std::logic_error(
        "mixed proof-message fixture needs an encrypted coefficient");
}

template <FheBackend Backend>
const ExtensionValue<Backend> &find_mixed_round_value(
    const gkr::EncryptedBaseProof<Backend> &proof) {
    for (const auto &layer : proof.reductions) {
        const ExtensionValue<Backend> *result = nullptr;
        std::visit(
            [&](const auto &reduction) {
                for (const auto &round : reduction.rounds) {
                    for (const auto &value : round.evaluations) {
                        if (value.has_public_nonzero() &&
                            value.ciphertext_count() != 0) {
                            result = &value;
                            return;
                        }
                    }
                }
            },
            layer);
        if (result != nullptr) {
            return *result;
        }
    }
    throw std::logic_error("mixed proof-message fixture was not decoded");
}

template <FheBackend Backend>
const ExtensionValue<Backend> &find_public_slot_round_value(
    const gkr::EncryptedBaseProof<Backend> &proof) {
    for (const auto &layer : proof.reductions) {
        const ExtensionValue<Backend> *result = nullptr;
        std::visit(
            [&](const auto &reduction) {
                for (const auto &round : reduction.rounds) {
                    for (const auto &value : round.evaluations) {
                        if (value.is_public() &&
                            std::any_of(
                                value.begin(), value.end(),
                                [](const auto &coefficient) {
                                    return coefficient.plaintext()
                                        .is_slots();
                                })) {
                            result = &value;
                            return;
                        }
                    }
                }
            },
            layer);
        if (result != nullptr) {
            return *result;
        }
    }
    throw std::logic_error(
        "public-slot proof-message fixture was not decoded");
}

void check_round_trip(bool outsourced) {
    const PayloadCircuit payload = outsourced ? wide_affine_product_payload() : product_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(3), values(61)};
    const PlainTrace expected = synthesize_trace(payload, circuit, inputs);
    Roles roles(payload, circuit, outsourced);
    const protocol::CertifiedBaseClientSetup<MockBackend> certified_client =
        protocol::certify_base_client_setup<MockBackend>(
            payload, circuit, roles.client);

    BaseClientRequestStart<MockBackend> started =
        begin_base_request<MockBackend>(certified_client, inputs, nonce(9));
    const auto request_bytes = encode_base_request<MockBackend>(
        roles.contexts.eval, started.request);
    const BaseRequest<MockBackend> request = decode_base_request<MockBackend>(
        roles.contexts.eval, request_bytes, limits());
    CHECK(request.setup_id == started.request.setup_id);
    CHECK(request.session_id == started.request.session_id);
    CHECK(request.circuit_id == started.request.circuit_id);
    CHECK(request.trace_id == started.request.trace_id);
    check_ciphertexts(roles.contexts.eval, started.request.encrypted_inputs,
                      request.encrypted_inputs);
    CHECK(encode_base_request<MockBackend>(roles.contexts.eval, request) ==
          request_bytes);

    auto evaluated =
        reference::evaluate_base_request<MockBackend>(
            payload, circuit, roles.server, request,
            FheEvaluationPlan::without_payload_switches(circuit, 5));
    Transcript prover_transcript("test/delegation/base-wire/v1");
    const BaseResponse<MockBackend> response =
        reference::prove_base_request<MockBackend>(
            payload, circuit, roles.server, std::move(evaluated),
            prover_transcript);

    base_wire_detail::ProofTransportSizeBreakdown transport_size;
    const auto response_bytes = encode_base_response<MockBackend>(
        roles.contexts.eval, response, &transport_size);
    CHECK(transport_size.total_bytes < response_bytes.size());
    CHECK(transport_size.logical_round_messages != 0);
    CHECK(transport_size.base_ciphertexts != 0);
    CHECK(transport_size.base_ciphertexts <
          transport_size.extension_ciphertexts * kExtensionDegree);
    CHECK(transport_size.statement_and_metadata_bytes +
              transport_size.round_message_bytes +
              transport_size.terminal_message_bytes +
              transport_size.partial_gate_mle_bytes +
              transport_size.gate_mle_opening_bytes ==
          transport_size.total_bytes);
    CHECK((outsourced && transport_size.gate_mle_opening_bytes != 0) ||
          (!outsourced && transport_size.gate_mle_opening_bytes == 0));

    const BaseResponse<MockBackend> decoded =
        decode_base_response<MockBackend>(
            roles.contexts.eval, certified_client, response_bytes, limits(),
            TraceProvenance::FheEvaluated);
    CHECK(decoded.output.dimensions == response.output.dimensions);
    CHECK(decoded.output.values.size() == response.output.values.size());
    CHECK(protocol::encode_canonical<MockBackend>(decoded.proof) ==
          protocol::encode_canonical<MockBackend>(response.proof));
    base_wire_detail::ProofTransportSizeBreakdown decoded_size;
    CHECK(encode_base_response<MockBackend>(roles.contexts.eval, decoded,
                                            &decoded_size) ==
          response_bytes);
    CHECK(decoded_size.total_bytes == transport_size.total_bytes);
    CHECK(decoded_size.base_ciphertexts == transport_size.base_ciphertexts);
    CHECK(decoded_size.logical_round_messages ==
          transport_size.logical_round_messages);

    if (outsourced) {
        // This mirrors the GCP quick profile's N > W geometry: encrypted GKR
        // reduces ciphertext indices, while the Wide GateMLE action proof
        // separately reduces all log(N) SIMD-slot coordinates. A valid gate
        // proof must not be rejected by the smaller GKR round bound.
        BaseWireDecodeLimits split_round_limits = limits();
        split_round_limits.max_rounds_per_reduction = 1;
        (void)decode_base_response<MockBackend>(
            roles.contexts.eval, certified_client, response_bytes,
            split_round_limits, TraceProvenance::FheEvaluated);

        split_round_limits.max_gate_proof_rounds = 2;
        check_rejected([&] {
            (void)decode_base_response<MockBackend>(
                roles.contexts.eval, certified_client, response_bytes,
                split_round_limits, TraceProvenance::FheEvaluated);
        });

        CHECK(response.proof.gate_mle_opening->wide.has_value());
        const auto reject_mutation = [&](const auto &mutate) {
            auto changed = response;
            mutate(*changed.proof.gate_mle_opening);
            const auto bytes = encode_base_response<MockBackend>(roles.contexts.eval, changed);
            check_rejected([&] {
                (void)decode_base_response<MockBackend>(roles.contexts.eval, certified_client,
                    bytes, limits(), TraceProvenance::FheEvaluated);
            });
        };
        reject_mutation([](auto &proof) { proof.wide.reset(); });
        reject_mutation([&](auto &proof) {
            proof.claimed_values.resize(4U * roles.prover_key->verifier.layout.wide_layers.size() + 1U);
        });
        {
            auto truncated = gates::encode_canonical(*response.proof.gate_mle_opening);
            const std::size_t trace_header_offset = sizeof(std::uint64_t) +
                base_wire_detail::kOutsourcedGateProofDomain.size() + sizeof(std::uint64_t) +
                response.proof.gate_mle_opening->claimed_values.size() * kSerializedFpkBytes + 1U;
            truncated.resize(trace_header_offset + sizeof(std::uint64_t));
            std::vector<std::uint8_t> framed;
            wire_detail::append_size(framed, truncated.size(), "truncated Wide fixture");
            framed.insert(framed.end(), truncated.begin(), truncated.end());
            base_wire_detail::Reader reader(framed, "truncated Wide fixture");
            const auto policy = limits();
            base_wire_detail::DecodeBudget budget(policy, "truncated Wide fixture");
            bool early_rejection = false;
            try {
                (void)base_wire_detail::read_outsourced_gate_proof(reader,
                    roles.prover_key->verifier, budget, policy, "truncated Wide fixture");
            } catch (const std::invalid_argument &error) {
                early_rejection = std::string_view(error.what()).find(
                    "truncated Wide trace headers") != std::string_view::npos;
            }
            CHECK(early_rejection);
        }
        reject_mutation([](auto &proof) {
            proof.wide->traces.resize(proof.claimed_values.size() + 1);
        });
        reject_mutation([](auto &proof) {
            proof.wide->traces.front().local_openings.front().products.resize(4);
        });
        reject_mutation([](auto &proof) {
            proof.wide->traces.front().product.rounds.resize(basefold::foldable::kMaxVariables + 1);
        });
        reject_mutation([](auto &proof) {
            proof.wide->public_opening.initial.frontier.resize(10000);
        });
        reject_mutation([](auto &proof) {
            proof.wide->tables.front().column_targets.push_back({});
        });
        reject_mutation([](auto &proof) { proof.wide->adjoint_groups.clear(); });
        reject_mutation([](auto &proof) {
            proof.wide->adjoint_groups.push_back(proof.wide->adjoint_groups.front());
        });
        reject_mutation([](auto &proof) {
            proof.wide->adjoint_groups.front().opening.sumcheck.operand_evaluations.push_back(Fpk::zero());
        });
        reject_mutation([](auto &proof) { proof.wide->public_column_targets.clear(); });
        reject_mutation([](auto &proof) {
            proof.wide->public_column_targets.front().pop_back();
        });
        reject_mutation([](auto &proof) {
            proof.wide->public_column_targets.push_back(proof.wide->public_column_targets.front());
        });
        reject_mutation([](auto &proof) { proof.wide->public_opening = {}; });
        auto restrictive = limits();
        restrictive.max_basefold_queries = roles.prover_key->verifier.foldable_parameters.num_queries - 1;
        check_rejected([&] {
            (void)decode_base_response<MockBackend>(roles.contexts.eval, certified_client,
                response_bytes, restrictive, TraceProvenance::FheEvaluated);
        });
        restrictive = limits();
        restrictive.max_total_digests = 0;
        check_rejected([&] {
            (void)decode_base_response<MockBackend>(roles.contexts.eval, certified_client,
                response_bytes, restrictive, TraceProvenance::FheEvaluated);
        });
    }

    Transcript verifier_transcript("test/delegation/base-wire/v1");
    const auto outputs = verify_base_response<MockBackend>(
        certified_client, std::move(started.state), decoded,
        verifier_transcript);
    CHECK(outputs.has_value());
    CHECK(outputs->size() == 1);
    CHECK(outputs->front() == expected.layers.front().front());

    BaseResponse<MockBackend> mixed_response = response;
    install_mixed_round_fixture(mixed_response.proof, kSlots);
    base_wire_detail::ProofTransportSizeBreakdown mixed_size;
    const auto mixed_bytes = encode_base_response<MockBackend>(
        roles.contexts.eval, mixed_response, &mixed_size);
    const BaseResponse<MockBackend> mixed_decoded =
        decode_base_response<MockBackend>(
            roles.contexts.eval, certified_client, mixed_bytes, limits(),
            TraceProvenance::FheEvaluated);
    const auto &decoded_mixed =
        find_mixed_round_value(mixed_decoded.proof);
    const auto &decoded_public_slots =
        find_public_slot_round_value(mixed_decoded.proof);
    CHECK(decoded_mixed.has_public_nonzero());
    CHECK(decoded_mixed.ciphertext_count() == 1);
    CHECK(decoded_public_slots.is_public());
    CHECK(decoded_public_slots.has_public_nonzero());
    CHECK(decoded_public_slots.ciphertext_count() == 0);
    CHECK(encode_base_response<MockBackend>(roles.contexts.eval,
                                            mixed_decoded) == mixed_bytes);
    CHECK(mixed_size.public_plaintext_coefficients != 0);
    CHECK(mixed_size.public_plaintext_field_elements != 0);

    if (!outsourced) {
        BaseWireDecodeLimits exact_field_limit = limits();
        exact_field_limit.max_total_field_elements =
            mixed_size.public_plaintext_field_elements +
            mixed_size.partial_gate_mle_field_elements;
        (void)decode_base_response<MockBackend>(
            roles.contexts.eval, mixed_bytes, exact_field_limit, payload,
            circuit, roles.public_setup, TraceProvenance::FheEvaluated);
        --exact_field_limit.max_total_field_elements;
        check_rejected([&] {
            (void)decode_base_response<MockBackend>(
                roles.contexts.eval, mixed_bytes, exact_field_limit,
                payload, circuit, roles.public_setup,
                TraceProvenance::FheEvaluated);
        });
    }
}

void check_malformed_and_resource_rejection() {
    const base_wire_detail::CiphertextFootprint quick_request{
        64, 155'189'248};
    const base_wire_detail::CiphertextFootprint quick_output{
        1, 851'968};
    const base_wire_detail::CiphertextFootprint quick_proof{
        3'144, 1'030'225'920};
    const base_wire_detail::BaseWireCiphertextBudget quick_budget =
        base_wire_detail::derive_ciphertext_budget(
            quick_request, quick_output, quick_proof);
    CHECK(quick_budget.max_count_per_message == 3'145);
    CHECK(quick_budget.max_bytes_per_message == 1'031'077'888);

    const PayloadCircuit payload = product_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(5), values(101)};
    Roles roles(payload, circuit, false);
    BaseClientRequestStart<MockBackend> started =
        reference::begin_base_request_resident_reference<MockBackend>(
            payload, circuit, roles.client, inputs, nonce(43));
    const auto request = encode_base_request<MockBackend>(
        roles.contexts.eval, started.request);

    auto wrong_domain = request;
    wrong_domain.front() ^= 1U;
    check_rejected([&] {
        (void)decode_base_request<MockBackend>(
            roles.contexts.eval, wrong_domain, limits());
    });
    auto truncated = request;
    truncated.pop_back();
    check_rejected([&] {
        (void)decode_base_request<MockBackend>(
            roles.contexts.eval, truncated, limits());
    });
    BaseWireDecodeLimits message_limit = limits();
    message_limit.max_message_bytes = request.size() - 1U;
    check_rejected([&] {
        (void)decode_base_request<MockBackend>(
            roles.contexts.eval, request, message_limit);
    });
    BaseWireDecodeLimits count_limit = limits();
    count_limit.max_ciphertexts = 1;
    check_rejected([&] {
        (void)decode_base_request<MockBackend>(
            roles.contexts.eval, request, count_limit);
    });
    BaseWireDecodeLimits ciphertext_limit = limits();
    ciphertext_limit.max_ciphertext_bytes = 1;
    check_rejected([&] {
        (void)decode_base_request<MockBackend>(
            roles.contexts.eval, request, ciphertext_limit);
    });

    auto evaluated =
        reference::evaluate_base_request<MockBackend>(
            payload, circuit, roles.server, started.request,
            FheEvaluationPlan::without_payload_switches(circuit, 5));
    Transcript prover_transcript(
        "test/delegation/base-wire/reject/v1");
    const BaseResponse<MockBackend> response =
        reference::prove_base_request<MockBackend>(
            payload, circuit, roles.server, std::move(evaluated),
            prover_transcript);
    base_wire_detail::ProofTransportSizeBreakdown response_size;
    const auto encoded = encode_base_response<MockBackend>(
        roles.contexts.eval, response, &response_size);

    BaseWireDecodeLimits proof_limit = limits();
    proof_limit.max_proof_bytes = 0;
    check_rejected([&] {
        (void)decode_base_response<MockBackend>(
            roles.contexts.eval, encoded, proof_limit, payload, circuit,
            roles.public_setup, TraceProvenance::FheEvaluated);
    });
    BaseWireDecodeLimits reduction_limit = limits();
    reduction_limit.max_reductions = 0;
    check_rejected([&] {
        (void)decode_base_response<MockBackend>(
            roles.contexts.eval, encoded, reduction_limit, payload, circuit,
            roles.public_setup, TraceProvenance::FheEvaluated);
    });
    const std::size_t output_ciphertext_count =
        static_cast<std::size_t>(std::count_if(
            response.output.values.begin(), response.output.values.end(),
            [](const auto &value) { return value.is_encrypted(); }));
    CHECK(output_ciphertext_count != 0);
    BaseWireDecodeLimits aggregate_ciphertext_limit = limits();
    aggregate_ciphertext_limit.max_ciphertexts =
        output_ciphertext_count + response_size.base_ciphertexts;
    (void)decode_base_response<MockBackend>(
        roles.contexts.eval, encoded, aggregate_ciphertext_limit, payload,
        circuit, roles.public_setup, TraceProvenance::FheEvaluated);
    --aggregate_ciphertext_limit.max_ciphertexts;
    check_rejected([&] {
        (void)decode_base_response<MockBackend>(
            roles.contexts.eval, encoded, aggregate_ciphertext_limit,
            payload, circuit, roles.public_setup,
            TraceProvenance::FheEvaluated);
    });
    check_rejected([&] {
        (void)decode_base_response<MockBackend>(
            roles.contexts.eval, encoded, limits(), payload, circuit,
            roles.public_setup, TraceProvenance::SyntheticTrace);
    });
    PublicSetup wrong_setup = roles.public_setup;
    wrong_setup.circuit_digest.front() ^= 1U;
    check_rejected([&] {
        (void)decode_base_response<MockBackend>(
            roles.contexts.eval, encoded, limits(), payload, circuit,
            wrong_setup, TraceProvenance::FheEvaluated);
    });

    auto malformed_proof = encoded;
    const auto proof_tag = std::search(
        malformed_proof.begin(), malformed_proof.end(),
        base_wire_detail::kBaseProofTransportDomain.begin(),
        base_wire_detail::kBaseProofTransportDomain.end());
    CHECK(proof_tag != malformed_proof.end());
    *proof_tag ^= 1U;
    check_rejected([&] {
        (void)decode_base_response<MockBackend>(
            roles.contexts.eval, malformed_proof, limits(), payload,
            circuit, roles.public_setup, TraceProvenance::FheEvaluated);
    });

    BaseResponse<MockBackend> bad_dimensions = response;
    ++bad_dimensions.output.dimensions.logical_size;
    check_rejected([&] {
        (void)encode_base_response<MockBackend>(roles.contexts.eval,
                                                bad_dimensions);
    });
}

#ifdef LAMINATE_WITH_SEAL
void check_seal_response_round_trip() {
    constexpr std::size_t seal_slots = 1024;
    PayloadBuilder builder(PayloadShape::wide(seal_slots), 2);
    builder.set_outputs({builder.mul(0, 1)});
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit circuit = compile(payload);
    const auto make_values = [](std::uint64_t seed) {
        SlotVector result(seal_slots);
        for (std::size_t slot = 0; slot < result.size(); ++slot) {
            result[slot] = Fp(seed + 3 * slot + slot * slot);
        }
        return result;
    };
    const std::vector<SlotVector> inputs{make_values(7), make_values(83)};
    const PlainTrace trace = synthesize_trace(payload, circuit, inputs);
    const PublicSetup setup = make_direct_setup(payload, circuit);
    SealBackend::Contexts contexts = SealBackend::create(SealParameters{
        .poly_modulus_degree = seal_slots,
        .fresh_rns_limbs = 5,
        .bits_per_data_prime = 40,
        .special_prime_bits = 40,
        .security_level = seal::sec_level_type::none,
    });
    SealBackend::ClientContext client_only =
        SealBackend::deserialize_client_context_bundle(
            SealBackend::serialize_client_context_bundle(contexts.client));
    CHECK(SealBackend::storage_context_id(client_only) ==
          SealBackend::storage_context_id(contexts.eval));
    const auto client = make_client_setup<SealBackend>(setup, client_only);

    BaseClientRequestStart<SealBackend> started =
        reference::begin_base_request_resident_reference<SealBackend>(
            payload, circuit, client, inputs, nonce(41));
    const auto request_bytes = encode_base_request<SealBackend>(
        client_only, started.request);
    CHECK(request_bytes == encode_base_request<SealBackend>(
                               contexts.eval, started.request));
    const BaseRequest<SealBackend> decoded_request =
        decode_base_request<SealBackend>(client_only, request_bytes,
                                         limits());
    CHECK(encode_base_request<SealBackend>(client_only, decoded_request) ==
          request_bytes);

    const EncryptedTrace<SealBackend> encrypted = encrypt_compact_synthetic_trace<SealBackend>(
        contexts.eval, client_only, payload, circuit, trace,
        TraceEncryptionPlan::uniform(circuit, 4));
    const std::size_t output_variables =
        gkr::base_detail::layer_vars(circuit, 0);
    Transcript output_coin(
        "test/delegation/base-wire/seal-output/v1");
    const gkr::SingleClaim output_claim = gkr::make_layer_claim(
        trace.layers.front(),
        output_coin.challenge_vector(output_variables));
    const auto evaluation = make_evaluation_setup<SealBackend>(
        setup, contexts.eval);
    Transcript prover_transcript(
        "test/delegation/base-wire/seal-proof/v1");
    const protocol::LaminateBaseProof<SealBackend> proof =
        protocol::reference::prove_base<SealBackend>(
            payload, circuit, encrypted, evaluation, output_claim.point,
            prover_transcript);
    Digest session{};
    session.front() = 1U;
    const BaseResponse<SealBackend> response{
        setup_digest(setup), session,
        payload::combined_digest(payload, circuit), encrypted.trace_id,
        BaseFheOutput<SealBackend>{encrypted.layers.front().dimensions,
                                   encrypted.layers.front().wires},
        proof};
    base_wire_detail::ProofTransportSizeBreakdown transport_size;
    const auto encoded = encode_base_response<SealBackend>(
        contexts.eval, response, &transport_size);
    CHECK(encode_base_response<SealBackend>(client_only, response) ==
          encoded);
    CHECK(transport_size.total_bytes < encoded.size());
    const BaseResponse<SealBackend> decoded =
        decode_base_response<SealBackend>(
            client_only, encoded, limits(), payload, circuit, setup,
            TraceProvenance::SyntheticTrace);
    CHECK(encode_base_response<SealBackend>(client_only, decoded) ==
          encoded);
    CHECK(protocol::encode_canonical<SealBackend>(decoded.proof) ==
          protocol::encode_canonical<SealBackend>(proof));

    BaseResponse<SealBackend> mixed_response = response;
    install_mixed_round_fixture(mixed_response.proof, seal_slots);
    base_wire_detail::ProofTransportSizeBreakdown mixed_size;
    const auto mixed_encoded = encode_base_response<SealBackend>(
        contexts.eval, mixed_response, &mixed_size);
    const BaseResponse<SealBackend> mixed_decoded =
        decode_base_response<SealBackend>(
            client_only, mixed_encoded, limits(), payload, circuit, setup,
            TraceProvenance::SyntheticTrace);
    CHECK(find_mixed_round_value(mixed_decoded.proof).ciphertext_count() ==
          1);
    CHECK(find_public_slot_round_value(mixed_decoded.proof).is_public());
    CHECK(mixed_size.public_plaintext_coefficients != 0);
    CHECK(encode_base_response<SealBackend>(client_only, mixed_decoded) ==
          mixed_encoded);

    Transcript verifier_transcript(
        "test/delegation/base-wire/seal-proof/v1");
    CHECK(protocol::reference::verify_base<SealBackend>(
        payload, circuit, trace.layers.back(), client, trace.provenance,
        encrypted.trace_id, output_claim, decoded.proof,
        verifier_transcript));
}
#endif

} // namespace

int main() {
    laminate::test::Runner runner("test_base_delegation_wire");
    runner.run("one Base request and one combined response round trip",
               [] { check_round_trip(false); });
    runner.run("outsourced combined response round trips with BaseFold",
               [] { check_round_trip(true); });
    runner.run("malformed and oversized Base envelopes fail closed",
               check_malformed_and_resource_rejection);
#ifdef LAMINATE_WITH_SEAL
    runner.run("real SEAL combined Base response round trips",
               check_seal_response_round_trip);
#endif
    return runner.summary();
}
