/// @file test_packed_gkr_transcript.cpp
/// @brief Public transcript replay and deferred plaintext GKR checks.

#include "test_helpers.hpp"
#include "packed_setup_fixture.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/detail/folded/reference/prover.hpp"
#include "laminate/gkr/detail/folded/verifier.hpp"
#include "laminate/gkr/detail/laned/reference/prover.hpp"
#include "laminate/gkr/detail/laned/verifier.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/protocol/detail/packing/gkr_transcript_replay.hpp"
#include "laminate/protocol/detail/packing/messages.hpp"
#include "laminate/protocol/detail/packing/transcript_reader.hpp"
#include "laminate/protocol/metrics/profiling.hpp"
#include "laminate/protocol/reference/folded.hpp"
#include "laminate/protocol/reference/laned.hpp"

#include <memory>
#include <string>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;
using namespace laminate::protocol;

namespace {

SlotVector values(std::size_t width, std::uint64_t seed) {
    SlotVector result;
    for (std::size_t i = 0; i < width; ++i) {
        result.emplace_back(seed + i * i + 3 * i);
    }
    return result;
}

template <ProtocolVariant Variant>
void exercise(GateMleProfile profile, std::size_t lane_count = 4,
              bool singleton = false) {
    constexpr bool folded = Variant == ProtocolVariant::LaminateFolded;
    constexpr std::size_t slots = 16;
    const std::size_t width = folded ? slots : lane_count;
    const std::size_t input_count = singleton ? 1 : 4;
    PayloadBuilder builder(folded ? PayloadShape::wide(slots)
                                  : PayloadShape::laned(lane_count, slots),
                           input_count);
    WireId result = builder.mul(0, singleton ? 0 : 1);
    if (!singleton) {
        result = builder.add(result, builder.mul(2, 3));
    }
    const auto mask = builder.add_plaintext(
        folded ? values(width, 2) : SlotVector(width, Fp(5)));
    result = builder.mul_plain(result, mask);
    if constexpr (folded) {
        result = builder.rotate(result, 1);
    }
    result = builder.add_plain(result, mask);
    builder.set_outputs({result});
    const auto payload = builder.finish();
    const auto circuit = compile(payload);
    std::vector<SlotVector> inputs;
    for (std::size_t i = 0; i < input_count; ++i) {
        inputs.push_back(values(width, 7 + 19 * i));
    }
    const auto plain = synthesize_trace(payload, circuit, inputs);
    auto setup = make_direct_setup(payload, circuit);
    std::shared_ptr<const gates::GateTableProverKey> key;
    if (profile == GateMleProfile::OutsourcedBaseFold) {
        key = std::make_shared<gates::GateTableProverKey>(
            gates::preprocess_gate_tables(
                circuit, folded ? gates::GateTableSet::Wide
                                : gates::GateTableSet::Laned));
        setup = make_outsourced_gate_setup(payload, circuit, key->verifier);
    } else if (profile == GateMleProfile::DummyCommittedDirect) {
        setup = make_dummy_committed_setup(payload, circuit);
    }
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = slots, .fresh_rns_limbs = 14, .bits_per_limb = 120});
    MockBackend::preprocess_fixed_message_cells(contexts.eval);
    const std::size_t ingress = folded ? kFoldedFixtureProofIngressRnsLimbs
                                      : kLanedFixtureProofIngressRnsLimbs;
    auto encrypted = encrypt_compact_synthetic_trace<MockBackend>(
        contexts.eval, contexts.client, payload, circuit, plain,
        TraceEncryptionPlan::uniform(circuit, ingress - 1U));
    const auto evaluation = make_packed_evaluation_setup<MockBackend>(
        setup, contexts.eval, key);
    const auto client = make_client_setup<MockBackend>(setup, contexts.client);
    const std::size_t variables = folded
        ? gkr::base_detail::layer_vars(circuit, 0)
        : gkr::laned_layer_variables(circuit, 0);
    // Include Boolean endpoints to exercise multiplication's tau=1 branch.
    std::vector<Fpk> point(variables, Fpk::from_base(Fp(19)));
    point.front() = Fpk::one();
    const auto output = [&] {
        if constexpr (folded) {
            return make_layer_claim(plain.layers.front(), point);
        } else {
            return make_packed_laned_claim(
                plain.layers.front(), laned_layout(circuit, 0), point);
        }
    }();
    const std::string domain = "test/packed-public-gkr/v1";
    Transcript prover_coin(domain);
    prover_coin.observe("request-prefix", std::uint64_t{71});
    observe_packed_fiat_shamir_schedule(prover_coin);
    const auto raw = [&] {
        if constexpr (folded) {
            return folded_detail::prove_folded_gkr_resident<MockBackend>(
                payload, circuit, encrypted, evaluation, output.point,
                prover_coin, std::vector<std::size_t>(circuit.layers.size(), ingress));
        } else {
            return laned_detail::prove_laned_gkr_resident<MockBackend>(
                payload, circuit, encrypted, evaluation,
                std::vector<std::size_t>(circuit.layers.size(), ingress),
                output.point, prover_coin);
        }
    }();
    auto committed = commit_gkr_round_messages<MockBackend>(raw);
    if (committed.gate_mle_opening) {
        const std::size_t affine_count = std::count_if(
            circuit.layers.begin(), circuit.layers.end(), [](const auto &layer) {
                return layer_kind(layer) == LayerKind::Affine;
            });
        CHECK(committed.gate_mle_opening->claimed_values.size() ==
              2U * affine_count);
        if constexpr (folded) {
            CHECK(committed.gate_mle_opening->wide.has_value());
            CHECK(committed.gate_mle_opening->wide->traces.size() == affine_count);
        }
    }
    Transcript public_coin(domain);
    public_coin.observe("request-prefix", std::uint64_t{71});
    MockBackend::reset_counts(contexts.eval);
    BaseVerifierTimings timing;
    const auto plan = protocol::detail::replay_packed_gkr_transcript<
        Variant, MockBackend>(circuit, setup, committed, output.point,
                              public_coin, &timing);
    CHECK(plan.has_value());
    CHECK(MockBackend::counts(contexts.eval).decrypt == 0);
    CHECK(timing.layers.size() == committed.reductions.size());
    auto public_probe = public_coin;
    auto prover_probe = prover_coin;
    CHECK(public_probe.challenge_fpk() == prover_probe.challenge_fpk());
    CHECK(public_probe.challenge_fq2() == prover_probe.challenge_fq2());

    // The independent plaintext verifier must see
    // exactly the same challenge stream and accept the same round algebra.
    Transcript full_coin(domain);
    full_coin.observe("request-prefix", std::uint64_t{71});
    observe_packed_fiat_shamir_schedule(full_coin);
    const bool full_accepts = [&] {
        if constexpr (folded) {
            return folded_detail::verify_encrypted_gkr<MockBackend>(
                payload, circuit, plain.layers.back(), client,
                plain.provenance, encrypted.trace_id, output, raw, full_coin);
        } else {
            return laned_detail::verify_encrypted_gkr<MockBackend>(
                payload, circuit, plain.layers.back(), client,
                plain.provenance, encrypted.trace_id, output, raw, full_coin);
        }
    }();
    CHECK(full_accepts);
    auto full_probe = full_coin;
    prover_probe = prover_coin;
    CHECK(full_probe.challenge_fpk() == prover_probe.challenge_fpk());
    CHECK(full_probe.challenge_fq2() == prover_probe.challenge_fq2());

    std::vector<SlotVector> messages;
    for_each_transcript_packing_round_value<MockBackend>(raw,
        [&](const FheValue<MockBackend> &value) {
            messages.push_back(materialize_or_decrypt<MockBackend>(
                contexts.client, value));
        });
    auto accepts = [&](const auto &candidate, const SingleClaim &claim,
                       const std::vector<SlotVector> &logical,
                       std::span<const SlotVector> input) {
        protocol::detail::PackedTranscriptReader reader(logical);
        auto checker = plan->make_plaintext_verifier(
            input, claim, candidate, reader);
        CHECK(!checker.verify_gate_opening());
        try {
            return checker.run();
        } catch (const std::exception &) {
            return false;
        }
    };
    CHECK(accepts(committed, output, messages, plain.layers.back()));
    auto changed_output = output;
    changed_output.value += Fpk::one();
    CHECK(!accepts(committed, changed_output, messages, plain.layers.back()));
    changed_output = output;
    changed_output.point.front() += Fpk::one();
    CHECK(!accepts(committed, changed_output, messages, plain.layers.back()));
    auto changed_inputs = plain.layers.back();
    for (auto &wire : changed_inputs) {
        for (auto &slot : wire) { slot += Fp(1); }
    }
    CHECK(!accepts(committed, output, messages, changed_inputs));
    // Each recovered message is checked; alter all repetitions of its first
    // fixed cell so the mutation remains a well-shaped packed plaintext.
    for (std::size_t message = 0; message < messages.size(); ++message) {
        auto changed = messages;
        for (std::size_t slot = 0; slot < changed[message].size(); ++slot) {
            changed[message][slot] += Fp(1);
        }
        CHECK(!accepts(committed, output, changed, plain.layers.back()));
    }
    auto extra_messages = messages;
    extra_messages.push_back(messages.front());
    CHECK(!accepts(committed, output, extra_messages, plain.layers.back()));

    // A plan certifies an exact borrowed proof, not merely its dimensions.
    auto copy = committed;
    CHECK(!accepts(copy, output, messages, plain.layers.back()));
    const auto original_header = committed.header;
    committed.header.trace_id.front() ^= 1U;
    CHECK(!accepts(committed, output, messages, plain.layers.back()));
    committed.header = original_header;
    if (committed.gate_mle_opening) {
        committed.gate_mle_opening->claimed_values.front() += Fpk::one();
        CHECK(!accepts(committed, output, messages, plain.layers.back()));
        Transcript rejected(domain);
        rejected.observe("request-prefix", std::uint64_t{71});
        CHECK(!(protocol::detail::replay_packed_gkr_transcript<
            Variant, MockBackend>(circuit, setup, committed, output.point,
                                  rejected)).has_value());
        committed.gate_mle_opening->claimed_values.front() -= Fpk::one();
    }
    auto wrong_prefix = Transcript(domain);
    wrong_prefix.observe("request-prefix", std::uint64_t{72});
    const auto wrong_plan = protocol::detail::replay_packed_gkr_transcript<
        Variant, MockBackend>(circuit, setup, committed, output.point, wrong_prefix);
    if (wrong_plan) {
        protocol::detail::PackedTranscriptReader reader(messages);
        CHECK(!wrong_plan->make_plaintext_verifier(
            plain.layers.back(), output, committed, reader).run());
    }
    std::visit([](auto &reduction) { reduction.rounds.pop_back(); },
               committed.reductions.front());
    Transcript malformed(domain);
    CHECK(!(protocol::detail::replay_packed_gkr_transcript<Variant, MockBackend>(
        circuit, setup, committed, output.point, malformed)).has_value());
}

// Reject malformed packing setup before proof work, preserving both the
// caller's prefix and challenge counter for a corrected request.
template <ProtocolVariant Variant>
void rejected_request_preserves_transcript() {
    constexpr bool folded = Variant == ProtocolVariant::LaminateFolded;
    constexpr std::size_t slots = 16;
    PayloadBuilder builder(folded ? PayloadShape::wide(slots)
                                  : PayloadShape::laned(4, slots), 2);
    builder.set_outputs({builder.add(0, 1)});
    const auto payload = builder.finish();
    const auto circuit = compile(payload);
    const auto setup = make_direct_setup(payload, circuit);
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = slots, .fresh_rns_limbs = 14, .bits_per_limb = 120});
    const auto evaluation = make_packed_evaluation_setup<MockBackend>(
        setup, contexts.eval);
    const EncryptedTrace<MockBackend> trace;
    const std::vector<Fpk> point(folded
        ? gkr::base_detail::layer_vars(circuit, 0)
        : gkr::laned_layer_variables(circuit, 0), Fpk::one());

    for (const bool profiled : {false, true}) {
        Transcript transcript("test/packed-rejected-request/v1");
        transcript.observe("caller-prefix", std::uint64_t{53});
        (void)transcript.challenge_fpk();
        Transcript unchanged = transcript;
        bool rejected = false;
        try {
            if constexpr (folded) {
                const FoldedSetup invalid_packing_setup;
                if (profiled) {
                    FoldedProverTimings timings;
                    (void)prove_folded_reference_profiled<MockBackend>(
                        payload, circuit, trace, evaluation,
                        invalid_packing_setup, point, transcript, timings);
                } else {
                    (void)reference::prove_folded<MockBackend>(
                        payload, circuit, trace, evaluation,
                        invalid_packing_setup, point, transcript);
                }
            } else {
                const LanedSetup invalid_packing_setup;
                if (profiled) {
                    LanedProverTimings timings;
                    (void)prove_laned_reference_profiled<MockBackend>(
                        payload, circuit, trace, evaluation,
                        invalid_packing_setup, point, transcript, timings);
                } else {
                    (void)reference::prove_laned<MockBackend>(
                        payload, circuit, trace, evaluation,
                        invalid_packing_setup, point, transcript);
                }
            }
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
        CHECK(transcript.challenge_fpk() == unchanged.challenge_fpk());
        CHECK(transcript.challenge_fq2() == unchanged.challenge_fq2());
    }
}

} // namespace

int main() {
    test::Runner runner("packed GKR public transcript replay");
    for (const auto profile : {GateMleProfile::Direct,
                               GateMleProfile::DummyCommittedDirect,
                               GateMleProfile::OutsourcedBaseFold}) {
        runner.run("Folded profile " + std::to_string(static_cast<int>(profile)),
                   [=] { exercise<ProtocolVariant::LaminateFolded>(profile); });
        runner.run("Laned profile " + std::to_string(static_cast<int>(profile)),
                   [=] { exercise<ProtocolVariant::LaminateLaned>(profile); });
    }
    runner.run("Laned B=1 singleton input", [] {
        exercise<ProtocolVariant::LaminateLaned>(GateMleProfile::Direct, 1, true);
    });
    runner.run("Laned B=N singleton input", [] {
        exercise<ProtocolVariant::LaminateLaned>(GateMleProfile::Direct, 16, true);
    });
    runner.run("Folded singleton input", [] {
        exercise<ProtocolVariant::LaminateFolded>(GateMleProfile::Direct, 4, true);
    });
    runner.run("Folded rejected request preserves transcript", [] {
        rejected_request_preserves_transcript<ProtocolVariant::LaminateFolded>();
    });
    runner.run("Laned rejected request preserves transcript", [] {
        rejected_request_preserves_transcript<ProtocolVariant::LaminateLaned>();
    });
    return runner.summary();
}
