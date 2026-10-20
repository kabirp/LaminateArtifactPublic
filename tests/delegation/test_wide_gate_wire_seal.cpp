/// @file test_wide_gate_wire_seal.cpp
/// @brief Real BGV ciphertexts with outsourced Wide GateMLE proof transport.

#include "test_helpers.hpp"
#include "laminate/delegation/base/wire/codec.hpp"
#include "laminate/fhe/seal_backend.hpp"
#include "laminate/gates/canonical_tables.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/protocol/reference/base.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace laminate;
using namespace laminate::delegation;
using namespace laminate::fhe;
using namespace laminate::payload;

namespace {
constexpr std::size_t kSlots = 1024;

SlotVector values(std::uint64_t seed) {
    SlotVector result(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot)
        result[slot] = Fp(seed + 3 * slot + slot * slot);
    return result;
}

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

template<class Function> bool rejected(Function &&function) {
    try { function(); return false; }
    catch (const std::invalid_argument &) { return true; }
}

void outsourced_wide_round_trip() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 2);
    const auto mask = builder.add_plaintext(values(13));
    const auto transformed = builder.mul_plain(builder.rotate(builder.add(0, 1), 5), mask);
    builder.set_outputs({builder.add_plain(builder.mul(transformed, 1), mask)});
    const auto payload = builder.finish();
    const auto circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(7), values(83)};
    const auto plain = synthesize_trace(payload, circuit, inputs);
    const auto prover_key = std::make_shared<gates::GateTableProverKey>(
        gates::preprocess_gate_tables(circuit, gates::GateTableSet::Wide));
    const auto setup = make_outsourced_gate_setup(payload, circuit, prover_key->verifier);
    CHECK(prover_key->verifier.wide_public_commitment);
    auto contexts = SealBackend::create(SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = 6,
        .bits_per_data_prime = 50,
        .special_prime_bits = 50,
        .security_level = seal::sec_level_type::none,
    });
    const auto client_only = SealBackend::deserialize_client_context_bundle(
        SealBackend::serialize_client_context_bundle(contexts.client));
    const auto client = make_client_setup<SealBackend>(setup, client_only);
    const auto server = make_evaluation_setup<SealBackend>(setup, contexts.eval, prover_key);
    // This bounded fixture encrypts a synthetic trace. The arithmetic and
    // transport use real BGV; file-backed FHE evaluation has separate tests.
    const auto encrypted = encrypt_compact_synthetic_trace<SealBackend>(
        contexts.eval, client_only, payload, circuit, plain,
        TraceEncryptionPlan::uniform(circuit, 5));
    Transcript output_coin("test/wide-gates/seal-wire/output/v1");
    const auto claim = gkr::make_layer_claim(plain.layers.front(),
        output_coin.challenge_vector(gkr::base_detail::layer_vars(circuit, 0)));
    const char *domain = "test/wide-gates/seal-wire/proof/v1";
    Transcript prover(domain);
    const auto proof = protocol::reference::prove_base<SealBackend>(
        payload, circuit, encrypted, server, claim.point, prover);
    CHECK(proof.gate_mle_opening);
    CHECK(proof.gate_mle_opening->wide);
    const auto &wide = *proof.gate_mle_opening->wide;
    CHECK(!wide.adjoint_groups.empty());
    CHECK(!wide.tables.empty());
    CHECK(prover_key->verifier.wide_public_commitment->width > 1);
    CHECK(!wide.public_column_targets.empty());
    CHECK(!wide.public_opening.initial.values.empty());

    Digest session{};session.front() = 1;
    const BaseResponse<SealBackend> response{
        setup_digest(setup), session, combined_digest(payload, circuit), encrypted.trace_id,
        BaseFheOutput<SealBackend>{encrypted.layers.front().dimensions,
                                   encrypted.layers.front().wires}, proof};
    base_wire_detail::ProofTransportSizeBreakdown size;
    const auto bytes = encode_base_response<SealBackend>(contexts.eval, response, &size);
    CHECK(size.gate_mle_opening_bytes != 0);
    CHECK(encode_base_response<SealBackend>(client_only, response) == bytes);
    const auto decode = [&](const auto &encoded, const BaseWireDecodeLimits &policy) {
        return decode_base_response<SealBackend>(client_only, encoded, policy,
            payload, circuit, setup, TraceProvenance::SyntheticTrace);
    };
    auto derived_limits = limits();
    const auto sparse_requests = 24U * prover_key->verifier.layout.wide_layers.size();
    derived_limits.max_gate_target_values =
        base_wire_detail::gate_target_values_upper_bound(
            prover_key->verifier, sparse_requests);
    auto missing_public_index = prover_key->verifier;
    missing_public_index.wide_public_commitment.reset();
    CHECK(rejected([&] {
        (void)base_wire_detail::gate_target_values_upper_bound(
            missing_public_index, sparse_requests);
    }));
    CHECK(rejected([&] {
        (void)base_wire_detail::gate_target_values_upper_bound(
            prover_key->verifier, std::numeric_limits<std::size_t>::max());
    }));
    std::size_t target_values = 0;
    std::size_t maximum_table_width = 0;
    for (const auto &table : prover_key->verifier.tables)
        maximum_table_width = std::max(maximum_table_width, table.physical_width);
    for (const auto &table : wide.tables)
        for (const auto &row : table.column_targets) target_values += row.size();
    for (const auto &row : wide.public_column_targets) target_values += row.size();
    CHECK(target_values <= derived_limits.max_gate_target_values);
    std::cout << "[INFO] target matrix entries=" << target_values
              << ", legacy cap=" << sparse_requests * maximum_table_width
              << ", complete cap=" << derived_limits.max_gate_target_values << '\n';
    auto legacy_limits = derived_limits;
    legacy_limits.max_gate_target_values = sparse_requests * maximum_table_width;
    CHECK(target_values > legacy_limits.max_gate_target_values);
    std::string legacy_error;
    try {
        (void)decode(bytes, legacy_limits);
    } catch (const std::invalid_argument &error) {
        legacy_error = error.what();
    }
    CHECK(legacy_error ==
          "decode_base_response: Wide public target values exceed limit");
    const auto decoded = decode(bytes, derived_limits);
    CHECK(encode_base_response<SealBackend>(client_only, decoded) == bytes);
    CHECK(protocol::encode_canonical<SealBackend>(decoded.proof) ==
          protocol::encode_canonical<SealBackend>(proof));
    Transcript verifier(domain);
    CHECK(protocol::reference::verify_base<SealBackend>(payload, circuit, plain.layers.back(),
        client, TraceProvenance::SyntheticTrace, encrypted.trace_id, claim, decoded.proof, verifier));
    CHECK(prover.challenge_fpk() == verifier.challenge_fpk());

    auto exact_targets = derived_limits;
    exact_targets.max_gate_target_values = target_values;
    CHECK(encode_base_response<SealBackend>(client_only, decode(bytes, exact_targets)) == bytes);
    --exact_targets.max_gate_target_values;
    CHECK(rejected([&] { (void)decode(bytes, exact_targets); }));

    const auto rejects_claim = [&](const auto &mutate) {
        auto changed = response;mutate(*changed.proof.gate_mle_opening->wide);
        const auto changed_bytes = encode_base_response<SealBackend>(contexts.eval, changed);
        const auto transported = decode(changed_bytes, limits());
        Transcript coin(domain);
        CHECK(!protocol::reference::verify_base<SealBackend>(payload, circuit, plain.layers.back(),
            client, TraceProvenance::SyntheticTrace, encrypted.trace_id, claim, transported.proof, coin));
    };
    rejects_claim([](auto &opening) { opening.adjoint_groups.front().root[0] ^= 1; });
    rejects_claim([](auto &opening) {
        opening.public_opening.sumcheck.operand_evaluations.front() += Fpk::one();
    });
    rejects_claim([](auto &opening) { opening.tables.front().column_targets.front().front() += Fpk::one(); });
    rejects_claim([](auto &opening) { opening.public_column_targets.front().back() += Fpk::one(); });
    auto truncated = bytes;truncated.pop_back();
    CHECK(rejected([&] { (void)decode(truncated, limits()); }));
    auto restrictive = limits();restrictive.max_basefold_queries =
        prover_key->verifier.foldable_parameters.num_queries - 1;
    CHECK(rejected([&] { (void)decode(bytes, restrictive); }));
}
} // namespace

int main() {
    test::Runner runner("test_wide_gate_wire_seal");
    runner.run("real SEAL outsourced Wide openings round trip and reject tampering",
               outsourced_wide_round_trip);
    return runner.summary();
}
