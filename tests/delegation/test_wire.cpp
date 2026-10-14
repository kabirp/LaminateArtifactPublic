/// @file test_wire.cpp
/// @brief Fail-closed canonical one-round Laned delegation envelopes.

#include "test_helpers.hpp"

#include "laminate/delegation/laned/wire/format.hpp"
#include "laminate/fhe/mock_backend.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::delegation;
using namespace laminate::fhe;

namespace {

Digest digest(std::uint8_t seed) {
    Digest result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::uint8_t>(seed + 3U * index);
    }
    return result;
}

MockBackend::Contexts contexts(std::size_t slots = 8,
                               std::size_t limbs = 5) {
    return MockBackend::create(MockParameters{
        .slot_count = slots,
        .fresh_rns_limbs = limbs,
        .bits_per_limb = 60,
    });
}

MockBackend::Ciphertext ciphertext(
    const MockBackend::ClientContext &client, std::uint64_t seed) {
    SlotVector slots(MockBackend::slot_count(client), Fp::zero());
    for (std::size_t index = 0; index < slots.size(); ++index) {
        slots[index] = Fp(seed + 7U * index);
    }
    return MockBackend::encrypt(client, slots);
}

LanedWireDecodeLimits limits(std::size_t message_bytes = 1U << 20U) {
    return LanedWireDecodeLimits{
        .max_message_bytes = message_bytes,
        .max_ciphertexts = 16,
        .max_ciphertext_bytes = 64U << 10U,
        .max_total_ciphertext_bytes = 512U << 10U,
        .max_proof_bytes = 512U << 10U,
    };
}

template <typename Function> bool rejects(Function &&function) {
    try {
        std::forward<Function>(function)();
        return false;
    } catch (const std::invalid_argument &) {
        return true;
    } catch (const std::runtime_error &) {
        return true;
    }
}

void check_ciphertexts_equal(
    const MockBackend::EvalContext &eval,
    std::span<const MockBackend::Ciphertext> expected,
    std::span<const MockBackend::Ciphertext> actual) {
    CHECK(expected.size() == actual.size());
    for (std::size_t index = 0; index < expected.size(); ++index) {
        CHECK(MockBackend::serialize_for_storage(eval, expected[index]) ==
              MockBackend::serialize_for_storage(eval, actual[index]));
    }
}

void check_values_equal(
    const MockBackend::EvalContext &eval,
    std::span<const fhe::FheValue<MockBackend>> expected,
    std::span<const fhe::FheValue<MockBackend>> actual) {
    CHECK(expected.size() == actual.size());
    for (std::size_t index = 0; index < expected.size(); ++index) {
        CHECK(expected[index].is_public() == actual[index].is_public());
        if (expected[index].is_public()) {
            CHECK(expected[index].plaintext() == actual[index].plaintext());
        } else {
            CHECK(MockBackend::serialize_for_storage(
                      eval, expected[index].ciphertext()) ==
                  MockBackend::serialize_for_storage(
                      eval, actual[index].ciphertext()));
        }
    }
}

LanedEvaluationRequest<MockBackend> request_fixture(
    const MockBackend::Contexts &backend) {
    return LanedEvaluationRequest<MockBackend>{
        digest(1), digest(2), digest(3), digest(4),
        {ciphertext(backend.client, 11),
         ciphertext(backend.client, 29)}};
}

LanedResponse<MockBackend> response_fixture(
    const MockBackend::Contexts &backend) {
    LanedResponse<MockBackend> response{
        digest(1), digest(2), digest(3), digest(4),
        LanedFheOutput<MockBackend>{
            payload::LayerDimensions{4, 4, 2, 2},
            {fhe::FheValue<MockBackend>::public_zero(),
             fhe::FheValue<MockBackend>::public_scalar(Fp(17)),
             fhe::FheValue<MockBackend>::public_slots(
                 {Fp(1), Fp(2), Fp(3), Fp(4), Fp(5), Fp(6), Fp(7),
                  Fp(8)}),
             fhe::FheValue<MockBackend>::from_ciphertext(
                 ciphertext(backend.client, 61))}},
        {}};
    response.proof.transcript_packing.well_formedness_reveals.push_back(
        ciphertext(backend.client, 71));
    response.proof.transcript_packing
        .digit_decomposed_packed_values.push_back(
            ciphertext(backend.client, 89));
    // These tests exercise the outer delegation envelope, not Spartan
    // semantics. Keep its opaque opening minimally nonempty so the fixture is
    // nevertheless a canonically encodable packed proof.
    response.proof.transcript_packing.proof_of_packing
        .witness_opening.bytes = {0xa5U};
    return response;
}

std::size_t request_first_ciphertext_offset() {
    constexpr std::size_t bindings = 4U * Digest{}.size();
    constexpr std::size_t context = Digest{}.size();
    constexpr std::size_t count = 8;
    constexpr std::size_t blob_length = 8;
    return kLanedDelegationWireHeaderBytes + bindings + context + count +
           blob_length;
}

std::size_t request_ciphertext_count_offset() {
    constexpr std::size_t bindings = 4U * Digest{}.size();
    constexpr std::size_t context = Digest{}.size();
    return kLanedDelegationWireHeaderBytes + bindings + context;
}

void write_u64(std::vector<std::uint8_t> &encoded, std::size_t offset,
               std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        encoded.at(offset + byte) = static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff});
    }
}

std::size_t payload_length_offset() {
    return kLanedDelegationWireDomain.size() + 1U + 1U + 2U;
}

void test_request_roundtrip_and_response_determinism() {
    const auto backend = contexts();
    const LanedWireDecodeLimits decode_limits = limits();

    const auto request = request_fixture(backend);
    const auto request_bytes =
        encode_laned_evaluation_request<MockBackend>(backend.eval, request);
    CHECK(request_bytes ==
          encode_laned_evaluation_request<MockBackend>(backend.eval,
                                                        request));
    const auto decoded_request =
        decode_laned_evaluation_request<MockBackend>(
            backend.eval, request_bytes, decode_limits);
    CHECK(decoded_request.setup_id == request.setup_id);
    CHECK(decoded_request.session_id == request.session_id);
    CHECK(decoded_request.circuit_id == request.circuit_id);
    CHECK(decoded_request.trace_id == request.trace_id);
    check_ciphertexts_equal(backend.eval, request.encrypted_inputs,
                            decoded_request.encrypted_inputs);
    CHECK(encode_laned_evaluation_request<MockBackend>(backend.eval,
                                                        decoded_request) ==
          request_bytes);

    const auto response = response_fixture(backend);
    const auto response_bytes =
        encode_laned_response<MockBackend>(backend.eval, response);
    CHECK(response_bytes ==
          encode_laned_response<MockBackend>(backend.eval, response));
    const auto decoded =
        decode_opaque_laned_response_envelope<MockBackend>(
            backend.eval, response_bytes, decode_limits);
    CHECK(decoded.setup_id == response.setup_id);
    CHECK(decoded.session_id == response.session_id);
    CHECK(decoded.circuit_id == response.circuit_id);
    CHECK(decoded.trace_id == response.trace_id);
    CHECK(decoded.output.dimensions == response.output.dimensions);
    check_values_equal(backend.eval, response.output.values,
                       decoded.output.values);
    CHECK(decoded.opaque_proof_bytes ==
          protocol::encode_canonical<MockBackend>(response.proof));
}

void test_combined_response_is_bounded_and_canonical() {
    const auto backend = contexts();
    const auto response = response_fixture(backend);
    const auto encoded =
        encode_laned_response<MockBackend>(backend.eval, response);
    const auto decoded =
        decode_opaque_laned_response_envelope<MockBackend>(
            backend.eval, encoded, limits());

    LanedWireDecodeLimits proof_too_large = limits();
    proof_too_large.max_proof_bytes =
        decoded.opaque_proof_bytes.size() - 1U;
    CHECK(rejects([&] {
        (void)decode_opaque_laned_response_envelope<MockBackend>(
            backend.eval, encoded, proof_too_large);
    }));

    auto wrong_proof_tag = encoded;
    const auto found = std::search(
        wrong_proof_tag.begin(), wrong_proof_tag.end(),
        wire_detail::kCanonicalLanedProofPrefix.begin(),
        wire_detail::kCanonicalLanedProofPrefix.end());
    CHECK(found != wrong_proof_tag.end());
    *found ^= 0x20U;
    CHECK(rejects([&] {
        (void)decode_opaque_laned_response_envelope<MockBackend>(
            backend.eval, wrong_proof_tag, limits());
    }));

    auto trailing = encoded;
    trailing.push_back(0);
    write_u64(trailing, payload_length_offset(),
              trailing.size() - kLanedDelegationWireHeaderBytes);
    CHECK(rejects([&] {
        (void)decode_opaque_laned_response_envelope<MockBackend>(
            backend.eval, trailing, limits(trailing.size()));
    }));
}

void test_header_binding_and_framing_rejections() {
    const auto backend = contexts();
    const auto request = request_fixture(backend);
    const auto encoded =
        encode_laned_evaluation_request<MockBackend>(backend.eval, request);

    auto wrong_domain = encoded;
    wrong_domain.front() ^= 1U;
    CHECK(rejects([&] {
        (void)decode_laned_evaluation_request<MockBackend>(
            backend.eval, wrong_domain, limits());
    }));

    auto wrong_version = encoded;
    wrong_version.at(kLanedDelegationWireDomain.size()) =
        kLanedDelegationWireVersion + 1U;
    CHECK(rejects([&] {
        (void)decode_laned_evaluation_request<MockBackend>(
            backend.eval, wrong_version, limits());
    }));

    CHECK(rejects([&] {
        (void)decode_opaque_laned_response_envelope<MockBackend>(
            backend.eval, encoded, limits());
    }));

    auto wrong_flags = encoded;
    wrong_flags.at(kLanedDelegationWireDomain.size() + 2U) = 1U;
    CHECK(rejects([&] {
        (void)decode_laned_evaluation_request<MockBackend>(
            backend.eval, wrong_flags, limits());
    }));

    auto zero_binding = encoded;
    std::fill_n(
        zero_binding.begin() + static_cast<std::ptrdiff_t>(
                                   kLanedDelegationWireHeaderBytes),
        Digest{}.size(), std::uint8_t{0});
    CHECK(rejects([&] {
        (void)decode_laned_evaluation_request<MockBackend>(
            backend.eval, zero_binding, limits());
    }));

    auto impossible_payload_size = encoded;
    std::fill_n(
        impossible_payload_size.begin() + static_cast<std::ptrdiff_t>(
                                              payload_length_offset()),
        8, std::uint8_t{0xff});
    CHECK(rejects([&] {
        (void)decode_laned_evaluation_request<MockBackend>(
            backend.eval, impossible_payload_size, limits());
    }));

    auto truncated = encoded;
    truncated.pop_back();
    write_u64(truncated, payload_length_offset(),
              truncated.size() - kLanedDelegationWireHeaderBytes);
    CHECK(rejects([&] {
        (void)decode_laned_evaluation_request<MockBackend>(
            backend.eval, truncated, limits());
    }));

    LanedWireDecodeLimits too_small = limits(encoded.size() - 1U);
    CHECK(rejects([&] {
        (void)decode_laned_evaluation_request<MockBackend>(
            backend.eval, encoded, too_small);
    }));
}

void test_resource_and_backend_rejections() {
    const auto backend = contexts();
    const auto request = request_fixture(backend);
    const auto encoded =
        encode_laned_evaluation_request<MockBackend>(backend.eval, request);

    LanedWireDecodeLimits too_many = limits();
    too_many.max_ciphertexts = 1;
    CHECK(rejects([&] {
        (void)decode_laned_evaluation_request<MockBackend>(
            backend.eval, encoded, too_many);
    }));

    auto overflowing_count = encoded;
    std::fill_n(
        overflowing_count.begin() + static_cast<std::ptrdiff_t>(
                                        request_ciphertext_count_offset()),
        8, std::uint8_t{0xff});
    LanedWireDecodeLimits unbounded_count = limits();
    unbounded_count.max_ciphertexts =
        std::numeric_limits<std::size_t>::max();
    CHECK(rejects([&] {
        (void)decode_laned_evaluation_request<MockBackend>(
            backend.eval, overflowing_count, unbounded_count);
    }));

    const std::size_t one_ciphertext_bytes =
        MockBackend::serialize_for_storage(
            backend.eval, request.encrypted_inputs.front())
            .size();
    LanedWireDecodeLimits ciphertext_too_large = limits();
    ciphertext_too_large.max_ciphertext_bytes = one_ciphertext_bytes - 1U;
    CHECK(rejects([&] {
        (void)decode_laned_evaluation_request<MockBackend>(
            backend.eval, encoded, ciphertext_too_large);
    }));

    LanedWireDecodeLimits batch_too_large = limits();
    batch_too_large.max_total_ciphertext_bytes =
        2U * one_ciphertext_bytes - 1U;
    CHECK(rejects([&] {
        (void)decode_laned_evaluation_request<MockBackend>(
            backend.eval, encoded, batch_too_large);
    }));

    auto malformed_backend_bytes = encoded;
    malformed_backend_bytes.at(request_first_ciphertext_offset()) ^= 1U;
    CHECK(rejects([&] {
        (void)decode_laned_evaluation_request<MockBackend>(
            backend.eval, malformed_backend_bytes, limits());
    }));

    const auto wrong_backend = contexts(8, 6);
    CHECK(rejects([&] {
        (void)decode_laned_evaluation_request<MockBackend>(
            wrong_backend.eval, encoded, limits());
    }));

    const auto response = response_fixture(backend);
    const auto response_bytes =
        encode_laned_response<MockBackend>(backend.eval, response);
    LanedWireDecodeLimits output_too_wide = limits();
    output_too_wide.max_ciphertexts = response.output.values.size() - 1U;
    CHECK(rejects([&] {
        (void)decode_opaque_laned_response_envelope<MockBackend>(
            backend.eval, response_bytes, output_too_wide);
    }));
}

void test_response_shape_and_zero_binding_reject_before_encoding() {
    const auto backend = contexts();
    auto response = response_fixture(backend);
    response.output.dimensions.logical_size = 3;
    CHECK(rejects([&] {
        (void)encode_laned_response<MockBackend>(backend.eval, response);
    }));

    response = response_fixture(backend);
    response.session_id = Digest{};
    CHECK(rejects([&] {
        (void)encode_laned_response<MockBackend>(backend.eval, response);
    }));

    response = response_fixture(backend);
    response.proof.transcript_packing.proof_of_packing
        .witness_opening.bytes.clear();
    CHECK(rejects([&] {
        (void)encode_laned_response<MockBackend>(backend.eval, response);
    }));
}

} // namespace

int main() {
    test::Runner runner("test_delegation_wire");
    runner.run("request round-trips and combined response is deterministic",
               test_request_roundtrip_and_response_determinism);
    runner.run("combined response is bounded and canonical",
               test_combined_response_is_bounded_and_canonical);
    runner.run("domain, version, type, binding, flags, and framing reject",
               test_header_binding_and_framing_rejections);
    runner.run("resource limits and backend decoders fail closed",
               test_resource_and_backend_rejections);
    runner.run("response shape and zero binding reject before encoding",
               test_response_shape_and_zero_binding_reject_before_encoding);
    return runner.summary();
}
