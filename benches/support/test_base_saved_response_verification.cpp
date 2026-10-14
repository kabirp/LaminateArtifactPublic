// Exercise the same read-only saved-response path used by the benchmark
// adapter, with bounded proofs and real persisted SEAL client keys.
#define main laminate_base_benchmark_main
#include "../protocol/base_checkpoint_benchmark.cpp"
#undef main

#include "test_helpers.hpp"
#include "laminate/delegation/base/reference/resident.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include <map>

namespace {

class SavedResponseDirectory {
  public:
    SavedResponseDirectory() {
        std::string pattern = (std::filesystem::temp_directory_path() /
                               "laminate-saved-response-XXXXXX").string();
        std::vector<char> bytes(pattern.begin(), pattern.end());
        bytes.push_back('\0');
        const auto result = ::mkdtemp(bytes.data());
        if (!result) throw std::runtime_error("cannot create saved-response fixture");
        path = std::filesystem::canonical(result);
    }
    ~SavedResponseDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
    std::filesystem::path path;
};

template <typename F> bool saved_response_rejects(F &&call) {
    try { call(); } catch (const std::exception &) { return true; }
    return false;
}

void saved_response_text(const std::filesystem::path &path, std::string_view value) {
    write_private_bundle(path, {reinterpret_cast<const std::uint8_t *>(value.data()), value.size()});
}

using SourceSnapshot = std::map<std::string, std::vector<std::uint8_t>>;
SourceSnapshot saved_response_snapshot(const std::filesystem::path &source) {
    SourceSnapshot result;
    for (const auto &entry : std::filesystem::recursive_directory_iterator(source)) {
        const auto name = entry.path().lexically_relative(source).generic_string();
        if (entry.is_directory()) result[name + '/'] = {};
        else result[name] = read_bounded_file(entry.path(), std::uint64_t{1} << 30U);
    }
    return result;
}

BaseWireDecodeLimits saved_response_test_limits() {
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

template <typename Backend>
void check_saved_response_roundtrip(typename Backend::Contexts contexts, std::size_t slots,
                                    bool outsourced = false) {
    PayloadBuilder builder(PayloadShape::wide(slots), 2);
    const auto bias = builder.add_scalar_plaintext(Fp(7));
    builder.set_outputs({builder.add_plain(builder.add(0, 1), bias)});
    const auto payload = builder.finish();
    const auto circuit = compile(payload);
    const auto prover_key = outsourced
        ? std::make_shared<gates::GateTableProverKey>(
            gates::preprocess_gate_tables(circuit, gates::GateTableSet::Wide))
        : std::shared_ptr<gates::GateTableProverKey>{};
    const auto public_setup = outsourced
        ? make_outsourced_gate_setup(payload, circuit, prover_key->verifier)
        : make_direct_setup(payload, circuit);
    auto client_context = [&] {
        if constexpr (std::is_same_v<Backend, SealBackend>) {
            // Recovery must operate with the serialized original secret keys,
            // rather than accidentally using a fresh client/server key pair.
            SavedResponseDirectory directory;
            const auto key_path = directory.path / "client.bin";
            const auto key_bytes = SealBackend::serialize_client_context_bundle(contexts.client);
            write_private_bundle(key_path, key_bytes);
            return SealBackend::deserialize_client_context_bundle(
                read_bounded_file(key_path, key_bytes.size()));
        } else {
            return contexts.client;
        }
    }();
    const auto client = protocol::certify_base_client_setup<Backend>(
        payload, circuit, make_client_setup<Backend>(public_setup, std::move(client_context)));
    const auto server = make_evaluation_setup<Backend>(public_setup, contexts.eval, prover_key);
    std::vector<SlotVector> inputs(2, SlotVector(slots));
    for (std::size_t wire = 0; wire < inputs.size(); ++wire)
        for (std::size_t slot = 0; slot < slots; ++slot)
            inputs[wire][slot] = Fp(7 + 3 * wire + slot);
    std::array<std::uint8_t, 32> entropy{};
    entropy.fill(41);
    auto begun = begin_base_request<Backend>(client, inputs, make_base_client_nonce(entropy));
    const auto request_bytes = encode_base_request<Backend>(client.context(), begun.request);
    auto evaluated = delegation::reference::evaluate_base_request<Backend>(
        payload, circuit, server, begun.request,
        FheEvaluationPlan::without_payload_switches(circuit, 4));
    Transcript prover_transcript(kProcessTranscriptDomain);
    const auto response = delegation::reference::prove_base_request<Backend>(
        payload, circuit, server, std::move(evaluated), prover_transcript);
    const auto response_bytes = encode_base_response<Backend>(contexts.eval, response);
    const auto limits = saved_response_test_limits();
    const auto restored = [&] {
        return restore_saved_base_client_session<Backend>(client, inputs, request_bytes, limits);
    };
    SavedResponseVerificationMeasurements measurements;
    CHECK(verify_saved_base_response<Backend>(
        client, restored(), response_bytes, limits, {}, &measurements) == 1);
    CHECK(measurements.decode_response.wall_ms > 0);
    CHECK(measurements.open_response.wall_ms > 0);
    CHECK(measurements.verify.wall_ms > 0);
    CHECK(measurements.components.output_decryption.wall_ms > 0);
    CHECK(measurements.components.vcoed().wall_ms > 0);
    CHECK(!measurements.verifier.layers.empty());
    CHECK(encode_base_request<Backend>(client.context(), begun.request) == request_bytes);
    CHECK(encode_base_response<Backend>(contexts.eval, response) == response_bytes);

    // Replay diagnostics from the exact transcript state used by verification.
    // Changing a public terminal coefficient must remain a rejected proof.
    Transcript audit_transcript(kProcessTranscriptDomain);
    auto audit_opened = open_base_response<Backend>(client, restored(), response, audit_transcript);
    CHECK(audit_opened.has_value());
    std::ostringstream valid_audit;
    audit_saved_first_affine(client, response,
        base_client_detail::ClientStateAccess::output_claim(*audit_opened),
        audit_transcript, Record(&valid_audit));
    CHECK(valid_audit.str().find("audit.affine.constant_matches_direct=yes\n") != std::string::npos);
    CHECK(valid_audit.str().find("audit.affine.partial_gate_mle.matches_direct=yes\n") != std::string::npos);
    CHECK(valid_audit.str().find("audit.affine.terminal_identity_direct_public=pass\n") != std::string::npos);
    auto wrong_partial = response;
    std::get<gkr::EncryptedBaseAffineLayerReduction<Backend>>(
        wrong_partial.proof.reductions.front()).partial_gate_mle.evaluations.front() += Fpk::one();
    const auto wrong_partial_bytes = encode_base_response<Backend>(contexts.eval, wrong_partial);
    bool audited_rejection = false;
    std::ostringstream failed_audit;
    const auto on_failure = [&](const BaseResponse<Backend> &failed,
                                const gkr::SingleClaim &claim, Transcript original) {
        audited_rejection = true;
        audit_saved_first_affine(client, failed, claim, original, Record(&failed_audit));
    };
    CHECK(saved_response_rejects([&] {
        (void)verify_saved_base_response<Backend>(
            client, restored(), wrong_partial_bytes, limits, {}, nullptr, on_failure);
    }));
    CHECK(audited_rejection);
    CHECK(failed_audit.str().find("audit.affine.partial_gate_mle.mismatched_values=1\n") != std::string::npos);
    CHECK(failed_audit.str().find("audit.affine.terminal_identity_saved_public=fail\n") != std::string::npos);
    CHECK(failed_audit.str().find("audit.affine.terminal_identity_direct_public=pass\n") != std::string::npos);

    if (outsourced) {
        auto wrong_constant = response;
        CHECK(wrong_constant.proof.gate_mle_opening.has_value());
        CHECK(!wrong_constant.proof.gate_mle_opening->claimed_values.empty());
        wrong_constant.proof.gate_mle_opening->claimed_values.front() += Fpk::one();
        audited_rejection = false;
        failed_audit.str("");
        failed_audit.clear();
        CHECK(saved_response_rejects([&] {
            (void)verify_saved_base_response<Backend>(client, restored(),
                encode_base_response<Backend>(contexts.eval, wrong_constant),
                limits, {}, nullptr, on_failure);
        }));
        CHECK(audited_rejection);
        CHECK(failed_audit.str().find("audit.affine.constant_matches_direct=no\n") != std::string::npos);
    }

    std::string last_stage;
    const auto broken_audit = [](const BaseResponse<Backend> &,
                                 const gkr::SingleClaim &, Transcript) {
        throw std::runtime_error("deliberate diagnostic failure");
    };
    std::string original_failure;
    try {
        (void)verify_saved_base_response<Backend>(client, restored(), wrong_partial_bytes,
            limits, [&](std::string_view value) { last_stage = value; }, nullptr, broken_audit);
    } catch (const std::exception &error) {
        original_failure = error.what();
    }
    CHECK(original_failure.find("saved response proof verification FAILED at affine-reduction") == 0);
    CHECK(last_stage == "verification_failed");

    if constexpr (std::is_same_v<Backend, SealBackend>) {
        BaseResponseNoiseGroup healthy;
        healthy.inspect(client.context(), response.output.values.front(), "output.0");
        CHECK(healthy.ciphertexts == 1);
        CHECK(healthy.minimum_budget_bits > 0);
        CHECK(healthy.zero_budget_ciphertexts == 0);
        auto exhausted = response.output.values.front().ciphertext();
        for (std::size_t step = 0; step < 32 &&
             SealBackend::invariant_noise_budget(client.context(), exhausted) > 0; ++step)
            exhausted = SealBackend::mul_plain_scalar(contexts.eval, exhausted, Fp(32768));
        BaseResponseNoiseGroup depleted;
        depleted.inspect(client.context(), FheValue<SealBackend>::from_ciphertext(exhausted), "deliberately-depleted");
        CHECK(depleted.minimum_budget_bits == 0);
        CHECK(depleted.zero_budget_ciphertexts == 1);
        CHECK(depleted.first_zero_location == "deliberately-depleted");
        std::ostringstream noise_audit;
        audit_base_response_noise(client.context(), response, 0, Record(&noise_audit));
        CHECK(noise_audit.str().find("audit.noise.rounds.zero_budget_ciphertexts=0\n") != std::string::npos);
        CHECK(noise_audit.str().find("audit.noise.terminal.zero_budget_ciphertexts=0\n") != std::string::npos);
    }

    auto wrong_inputs = inputs;
    wrong_inputs.front().front() += Fp::one();
    CHECK(saved_response_rejects([&] {
        (void)restore_saved_base_client_session<Backend>(client, wrong_inputs, request_bytes, limits);
    }));
    auto wrong_request = begun.request;
    wrong_request.trace_id[0] ^= 1U;
    auto changed_request = encode_base_request<Backend>(client.context(), wrong_request);
    CHECK(saved_response_rejects([&] {
        (void)restore_saved_base_client_session<Backend>(client, inputs, changed_request, limits);
    }));
    wrong_request = begun.request;
    wrong_request.session_id[0] ^= 1U;
    changed_request = encode_base_request<Backend>(client.context(), wrong_request);
    CHECK(saved_response_rejects([&] {
        auto different_session = restore_saved_base_client_session<Backend>(
            client, inputs, changed_request, limits);
        (void)verify_saved_base_response<Backend>(
            client, std::move(different_session), response_bytes, limits);
    }));
    auto damaged_response = response_bytes;
    damaged_response.back() ^= 1U;
    CHECK(saved_response_rejects([&] {
        (void)verify_saved_base_response<Backend>(client, restored(), damaged_response, limits);
    }));
    auto constrained = limits;
    constrained.max_message_bytes = response_bytes.size() - 1;
    CHECK(saved_response_rejects([&] {
        (void)verify_saved_base_response<Backend>(client, restored(), response_bytes, constrained);
    }));
}

void check_saved_response_source_is_immutable(std::string_view client_failure) {
    SavedResponseDirectory directory;
    const auto source = directory.path / "source";
    create_process_run_tree(source);
    { RunLifecycleLock lock(source, RunLifecycleLockMode::Shared); }
    for (const auto *file : {"shared/setup-activity.jsonl", "client/activity.jsonl", "server/activity.jsonl"}) {
        saved_response_text(source / file, "{\"event\":\"stop\",\"stage\":\"complete\"}\n");
        std::filesystem::permissions(source / file, std::filesystem::perms::owner_read);
    }
    saved_response_text(source / "shared/setup-result.txt", "setup.result=PASS\n");
    saved_response_text(source / "shared/setup-process-exit.txt", "process.exit_status=0\n");
    saved_response_text(source / "server/result.txt", "server.result=PASS\n");
    saved_response_text(source / "server/process-exit.txt", "process.exit_status=0\n");
    saved_response_text(source / "client/process-exit.txt", "process.exit_status=1\n");
    saved_response_text(source / "client/failure.txt", client_failure);
    saved_response_text(source / "shared/setup.bin", "corrupted setup fixture");
    ProcessCommand command{.action = ProcessAction::VerifySavedResponse, .variant = "base",
        .profile = "quick", .run_directory = source, .output_directory = directory.path / "diagnostic"};
    // Eligibility remains exact, and neither a completed client nor an
    // incomplete server may use this diagnostic entry point.
    for (const std::string_view unsupported : {
             "FAILED: client verification FAILED at affine-reduction | layer 0\n",
             "FAILED: client verification FAILED at affine-reduction | layer 1 | "
                 "terminal identity failed: sum GateMLE*W != reduced claim "
                 "(a corrupt operand, e.g. exhausted noise budget, produces exactly this)\n",
             "FAILED: unrelated client error\n"}) {
        saved_response_text(source / "client/failure.txt", unsupported);
        CHECK(saved_response_rejects([&] { require_saved_response_failure(command); }));
    }
    saved_response_text(source / "client/failure.txt", client_failure);
    saved_response_text(source / "client/process-exit.txt", "process.exit_status=0\n");
    CHECK(saved_response_rejects([&] { require_saved_response_failure(command); }));
    saved_response_text(source / "client/process-exit.txt", "process.exit_status=1\n");
    saved_response_text(source / "server/process-exit.txt", "process.exit_status=1\n");
    CHECK(saved_response_rejects([&] { require_saved_response_failure(command); }));
    saved_response_text(source / "server/process-exit.txt", "process.exit_status=0\n");
    saved_response_text(source / "shared/setup-process-exit.txt", "process.exit_status=1\n");
    CHECK(saved_response_rejects([&] { require_saved_response_failure(command); }));
    saved_response_text(source / "shared/setup-process-exit.txt", "process.exit_status=0\n");
    const auto before = saved_response_snapshot(source);
    {
        RunLifecycleLock active(source, RunLifecycleLockMode::Shared);
        CHECK(saved_response_rejects([&] { SavedResponseSourceLock lock(source); }));
    }
    {
        SavedResponseSourceLock lock(source);
        require_saved_response_failure(command);
        require_saved_response_output_directory(command);
        CHECK(saved_response_rejects([&] { RunLifecycleLock active(source, RunLifecycleLockMode::Shared); }));
    }
    const auto output = command.output_directory;
    command.output_directory = source / "nested-diagnostic";
    CHECK(saved_response_rejects([&] { require_saved_response_output_directory(command); }));
    command.output_directory = directory.path;
    CHECK(saved_response_rejects([&] { require_saved_response_output_directory(command); }));
    command.output_directory = output;
    CHECK(saved_response_rejects([&] { (void)run_saved_response_verification(command, 0, nullptr); }));
    CHECK(std::filesystem::is_regular_file(output / "failure.txt"));
    CHECK(!std::filesystem::exists(output / "result.txt"));
    CHECK(saved_response_snapshot(source) == before);
    CHECK(saved_response_rejects([&] { require_saved_response_output_directory(command); }));
    std::filesystem::remove(source / "shared/lifecycle.lock");
    CHECK(saved_response_rejects([&] { SavedResponseSourceLock lock(source); }));
    CHECK(!std::filesystem::exists(source / "shared/lifecycle.lock"));
}

} // namespace

int main() {
    laminate::test::Runner runner("saved Base response verification");
    runner.run("diagnostic parameter compatibility requires an exact supported chain", [] {
        for (const std::string_view name :
             {"quick", "target-balancedLaned", "target-mulHeavyPyramid"}) {
            const auto selected = process_profile(name);
            const ProcessCommand command{.action = ProcessAction::VerifySavedResponse,
                .variant = "base", .profile = std::string(name),
                .run_directory = "/tmp/base-saved-parameter-fixture"};
            auto options = process_options(command, selected,
                derive_host_resource_budget(8'500'000'000'000ULL, 372'000'000'000ULL));
            options.diagnostic.slots = 1024;
            const auto current = process_client_seal_parameters(selected, options);
            CHECK(validated_process_client_seal_parameters(current, selected, options,
                ClientProcessLoadMode::Online) == current);
            for (const auto version : {BaseSealParameterVersion::Current,
                     BaseSealParameterVersion::TenDataPrimes,
                     BaseSealParameterVersion::ElevenDataPrimes}) {
                const auto parameters = process_client_seal_parameters(selected, options, version);
                CHECK(validated_process_client_seal_parameters(parameters, selected, options,
                    ClientProcessLoadMode::SavedResponseDiagnostic) == parameters);
                if (parameters != current)
                    CHECK(saved_response_rejects([&] {
                        (void)validated_process_client_seal_parameters(parameters, selected, options,
                            ClientProcessLoadMode::Online);
                    }));
                for (const int field : {0, 1, 2, 3, 4}) {
                    auto changed = parameters;
                    if (field == 0) changed.exact_data_primes[1] += 2;
                    if (field == 1) std::swap(changed.exact_data_primes[1], changed.exact_data_primes[2]);
                    if (field == 2) changed.exact_special_prime += 2;
                    if (field == 3) changed.generate_galois_keys = !changed.generate_galois_keys;
                    if (field == 4) ++changed.max_key_modulus_bits;
                    CHECK(saved_response_rejects([&] {
                        (void)validated_process_client_seal_parameters(changed, selected, options,
                            ClientProcessLoadMode::SavedResponseDiagnostic);
                    }));
                }
            }
        }
    });
    runner.run("reconstructs the original Mock session and rejects changed evidence", [] {
        check_saved_response_roundtrip<MockBackend>(MockBackend::create(MockParameters{
            .slot_count = 8, .fresh_rns_limbs = 5, .bits_per_limb = 300}), 8);
    });
    runner.run("verifies a saved SEAL proof using persisted original client keys", [] {
        check_saved_response_roundtrip<SealBackend>(SealBackend::create(SealParameters{
            .poly_modulus_degree = 1024, .fresh_rns_limbs = 5,
            .bits_per_data_prime = 40, .special_prime_bits = 40,
            .security_level = seal::sec_level_type::none}), 1024);
    });
    runner.run("audits a saved SEAL affine reduction with outsourced Wide GateMLE claims", [] {
        check_saved_response_roundtrip<SealBackend>(SealBackend::create(SealParameters{
            .poly_modulus_degree = 1024, .fresh_rns_limbs = 5,
            .bits_per_data_prime = 40, .special_prime_bits = 40,
            .security_level = seal::sec_level_type::none}), 1024, true);
    });
    runner.run("diagnostic failure preserves source bytes and cannot resume an active run", [] {
        check_saved_response_source_is_immutable(
            "FAILED: decode_base_response: Wide public target values exceed limit\n");
    });
    runner.run("first-affine proof failure admits read-only diagnostics with unchanged source evidence", [] {
        check_saved_response_source_is_immutable(
            "FAILED: client verification FAILED at affine-reduction | layer 0 | "
            "terminal identity failed: sum GateMLE*W != reduced claim "
            "(a corrupt operand, e.g. exhausted noise budget, produces exactly this)\n");
    });
    return runner.summary();
}
