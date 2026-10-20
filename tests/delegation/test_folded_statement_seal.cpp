/// @file test_folded_statement_seal.cpp
/// @brief Real-SEAL Folded request, encrypted-output binding, and opening.

#include "test_helpers.hpp"

#include "laminate/delegation/folded/client.hpp"
#include "laminate/delegation/folded/reference/client.hpp"
#include "laminate/delegation/folded/reference/server.hpp"
#include "laminate/delegation/folded/wire/codec.hpp"
#include "laminate/fhe/seal_backend.hpp"
#include "laminate/payload/compiler.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::delegation;
using namespace laminate::fhe;
using namespace laminate::payload;

namespace {

constexpr std::size_t kSlots = 1024;

static_assert(fhe::CiphertextStorageContext<
              SealBackend, SealBackend::ClientContext>);

SlotVector values(std::uint64_t seed) {
    SlotVector result;
    result.reserve(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        result.emplace_back(seed + 3U * slot + slot * slot);
    }
    return result;
}

FoldedClientNonce nonce() {
    std::array<std::uint8_t, 32> random{};
    for (std::size_t index = 0; index < random.size(); ++index) {
        random[index] = static_cast<std::uint8_t>(19U + index);
    }
    return make_folded_client_nonce(random);
}

void check_real_seal_folded_statement_opening() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 2);
    const WireId product = builder.mul(0, 1);
    builder.set_outputs({builder.add(product, 0)});
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(7), values(41)};

    SealBackend::Contexts contexts = SealBackend::create(SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = 5,
        .bits_per_data_prime = 40,
        .special_prime_bits = 40,
        .security_level = seal::sec_level_type::none,
    });
    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const EvaluationSetup<SealBackend> server =
        make_packed_evaluation_setup<SealBackend>(public_setup,
                                                  contexts.eval);
    const ClientSetup<SealBackend> client =
        make_client_setup<SealBackend>(public_setup, contexts.client);
    FoldedClientRequestStart<SealBackend> started =
        delegation::reference::begin_folded_request_resident_reference<SealBackend>(payload, circuit, client, inputs,
                                           nonce());
    const std::vector<std::uint8_t> encoded_request =
        encode_folded_evaluation_request<SealBackend>(
            client.context, started.request);
    const FoldedWireDecodeLimits request_limits{
        .max_message_bytes = encoded_request.size(),
        .max_ciphertexts = inputs.size(),
        .max_ciphertext_bytes = encoded_request.size(),
        .max_total_ciphertext_bytes = encoded_request.size(),
        .max_proof_bytes = 0,
    };
    const FoldedEvaluationRequest<SealBackend> decoded_request =
        decode_folded_evaluation_request<SealBackend>(
            server.context, encoded_request, request_limits);
    CHECK(encode_folded_evaluation_request<SealBackend>(
              server.context, decoded_request) == encoded_request);
    const std::size_t fresh_depth = SealBackend::remaining_mult_depth(
        contexts.eval, decoded_request.encrypted_inputs.front());
    auto evaluated = delegation::reference::evaluate_folded_request_resident_reference<SealBackend>(
        payload, circuit, server, decoded_request,
        FheEvaluationPlan::without_payload_switches(circuit,
                                                     fresh_depth - 1U));
    FoldedResponse<SealBackend> response{
        evaluated.state.setup_id, evaluated.state.session_id,
        evaluated.state.circuit_id, evaluated.state.trace_id,
        std::move(evaluated.output), {}};
    Transcript transcript("test/delegation/folded/seal-statement/v1");
    auto opened = delegation::reference::open_folded_response_resident_reference<SealBackend>(
        payload, circuit, client, std::move(started.state), response,
        transcript);
    CHECK(opened.has_value());

    FoldedClientRequestStart<SealBackend> different_session =
        delegation::reference::begin_folded_request_resident_reference<SealBackend>(payload, circuit, client, inputs,
                                           nonce());
    Transcript rejected("test/delegation/folded/seal-statement/v1");
    CHECK(!delegation::reference::open_folded_response_resident_reference<SealBackend>(
        payload, circuit, client, std::move(different_session.state),
        response, rejected));
}

} // namespace

int main() {
    test::Runner runner("test_folded_statement_seal");
    runner.run("real SEAL binds and opens the Folded encrypted statement",
               check_real_seal_folded_statement_opening);
    return runner.summary();
}
