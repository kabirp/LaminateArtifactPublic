// Include the process implementation so recovery tests exercise the same
// validation helpers as setup, without bypassing its GCP host admission.
#define main laminate_base_benchmark_main
#include "../protocol/base_checkpoint_benchmark.cpp"
#undef main

#include "test_helpers.hpp"
#include <map>

namespace {

class RecoveryDirectory {
  public:
    RecoveryDirectory() {
        std::string pattern = (std::filesystem::temp_directory_path() /
                               "laminate-base-recovery-XXXXXX").string();
        std::vector<char> name(pattern.begin(), pattern.end());
        name.push_back('\0');
        const auto result = ::mkdtemp(name.data());
        if (!result) throw std::runtime_error("cannot create recovery fixture");
        path = result;
    }
    ~RecoveryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
    std::filesystem::path path;
};

template <class F> bool recovery_rejects(F &&call) {
    try { call(); } catch (const std::exception &) { return true; }
    return false;
}

void recovery_text(const std::filesystem::path &path, std::string_view value) {
    write_private_bundle(path, {reinterpret_cast<const std::uint8_t *>(value.data()),
                                value.size()});
}

using RecoverySnapshot = std::map<std::string, std::vector<std::uint8_t>>;
RecoverySnapshot recovery_snapshot(const std::filesystem::path &directory) {
    RecoverySnapshot result;
    for (const auto &entry : std::filesystem::recursive_directory_iterator(directory)) {
        const auto name = entry.path().lexically_relative(directory).generic_string();
        if (entry.is_directory()) result[name + '/'] = {};
        else result[name] = read_bounded_file(entry.path(), std::uint64_t{1} << 30U);
    }
    return result;
}

struct RecoveryFixture {
    RecoveryDirectory temporary;
    ProcessCommand command{
        .action = ProcessAction::Setup, .variant = "base", .profile = "quick",
        .run_directory = temporary.path / "recovered",
        .recover_from = temporary.path / "failed"};
    ProcessProfile selected = process_profile("quick");
    Options options;
    RunProfile profile;
    LayeredCircuit circuit;
    ProcessSetupRecord stored;
    std::vector<std::uint8_t> server, client, client_static;

    RecoveryFixture() {
        // Keep the persistence and cryptography real, with a small circuit.
        // Full named-profile geometry and host capacity have separate tests.
        options = process_options(command, selected,
            derive_host_resource_budget(8'500'000'000'000ULL, 372'000'000'000ULL));
        options.work_directory = temporary.path;
        options.diagnostic.slots = 1024;
        options.diagnostic.depth = 2;
        options.diagnostic.width = 4;
        options.diagnostic.inputs = 4;
        options.diagnostic.operation_count.reset();
        options.diagnostic.client_private_persistent_disk_bytes =
            base_client_preprocessing_bytes_upper(options.diagnostic.slots);
        options.diagnostic.max_live_disk_bytes = reserve_role_private_disk(
            options.host_budget, options.diagnostic.client_private_persistent_disk_bytes);
        profile = make_run_profile(options, false);
        circuit = compile(profile.payload);
        const auto schedule = derive_certified_uniform_honest_base_proof_schedule(
            circuit, profile.seal_parameters.exact_data_primes,
            profile.calibration, selected.proof_ingress_rns_limbs);
        const auto gates = preprocess_outsourced_gate_mle_setup(
            profile.payload, circuit, gates::GateTableSet::Wide,
            {.wide_scratch_parent = temporary.path / "gate-scratch"});
        const auto public_setup = bind_certified_uniform_honest_base_proof_schedule(
            gates.public_setup, profile.payload, circuit, schedule);
        const auto preflight = finish_diagnostic_preflight(
            options, profile, circuit, schedule, public_setup);
        auto contexts = SealBackend::create(profile.seal_parameters);
        const auto certified = protocol::certify_base_client_setup<SealBackend>(
            profile.payload, circuit,
            make_client_setup<SealBackend>(public_setup, std::move(contexts.client)));
        server = SealBackend::serialize_evaluation_context_bundle(contexts.eval);
        client = SealBackend::serialize_client_context_bundle(certified.context());
        client_static = protocol::encode_base_client_static_setup(certified);

        stored.variant = "base";
        stored.profile = "quick";
        stored.git_commit = "8396bc6dcf50f2bcf0e39e22b584bec57daac117";
        stored.build_type = "Release";
        stored.seal_acceleration = LAMINATE_SEAL_ACCELERATION;
        stored.run_id.fill(17);
        stored.public_setup_digest = setup_digest(public_setup);
        stored.payload_digest = public_setup.payload_digest;
        stored.layered_digest = public_setup.layered_digest;
        stored.circuit_digest = public_setup.circuit_digest;
        stored.schedule_digest = schedule.digest();
        stored.gate_mle_verifier = public_setup.outsourced_gate_mle;
        stored.proof_schedule_policy = kUniformBaseProofIngressPolicyV1;
        stored.proof_ingress_rns_limbs = selected.proof_ingress_rns_limbs;
        stored.fresh_modulus_product_bits = schedule.schedule().fresh_modulus_product_bits;
        stored.host_budget = options.host_budget;
        stored.replay_budgets = preflight.replay_budgets;
        stored.replay_plan_digest = base_replay_plan_digest(preflight.replay_plan);
        stored.client_peak_resident_bytes = preflight.client_peak_resident_bytes_upper;
        stored.client_wire_limits = preflight.wire_limits;
        stored.server_bytes = server.size();
        stored.server_digest = sha256(server);
        stored.client_context_bytes = client.size();
        stored.client_context_digest = sha256(client);
        stored.client_static_bytes = client_static.size();
        stored.client_static_digest = sha256(client_static);

        create_process_run_tree(command.recover_from);
        gates::export_gate_table_prover_key(*gates.prover_key,
            command.recover_from / "server/preprocessing/gate-mle");
        { RunLifecycleLock lock(command.recover_from, RunLifecycleLockMode::Shared); }
        publish_private_file(command.recover_from / "server/preprocessing/server.bin", server);
        publish_private_file(command.recover_from / "client/preprocessing/client.bin", client);
        publish_private_file(command.recover_from / "client/preprocessing/client-static.bin", client_static);
        write_setup();
        auto source_command = command;
        source_command.run_directory = command.recover_from;
        publish_process_run_binding(source_command, digest_hex(stored.run_id));
        recovery_text(command.recover_from / "shared/setup-failure.txt",
                      "FAILED: setup profile exceeds its decode limit\n");
        recovery_text(command.recover_from / "shared/setup-process-exit.txt",
                      "process.exit_status=1\n");
        recovery_text(command.recover_from / "shared/setup-activity.jsonl",
                      "{\"event\":\"stage\",\"stage\":\"verifying_preprocessing\"}\n"
                      "{\"event\":\"stop\",\"stage\":\"exception\"}\n");
    }

    void write_setup() const {
        write_private_bundle(command.recover_from / "shared/setup.bin", encode_process_setup(stored));
    }
};

} // namespace

int main() {
    laminate::test::Runner runner("Base setup recovery");
    runner.run("client profile parameters survive rotation-key policy persistence", [&] {
        for (const std::string_view name :
             {"quick", "target-balancedLaned", "target-mulHeavyPyramid"}) {
            const auto selected = process_profile(name);
            const ProcessCommand command{
                .action = ProcessAction::RunClient,
                .variant = "base",
                .profile = std::string(name),
                .run_directory = "/tmp/base-client-profile-fixture",
            };
            auto options = process_options(command, selected,
                derive_host_resource_budget(8'500'000'000'000ULL,
                                            372'000'000'000ULL));
            options.diagnostic.slots = 1024;
            // Model the setup's actual payload-gate selection independently
            // of the client helper. Target geometry is checked separately.
            const bool rotation_payload = name == "target-mulHeavyPyramid";
            const auto setup_parameters = diagnostic_seal_parameters(
                options.diagnostic.slots, selected.workload_kind, rotation_payload);
            const auto contexts = SealBackend::create(setup_parameters);
            const auto restored = SealBackend::deserialize_client_context_bundle(
                SealBackend::serialize_client_context_bundle(contexts.client));
            const auto expected = process_client_seal_parameters(selected, options);
            CHECK(restored.parameters == expected);
            const auto ten_prime_profile = process_client_seal_parameters(
                selected, options, BaseSealParameterVersion::TenDataPrimes);
            const auto eleven_prime_profile = process_client_seal_parameters(
                selected, options, BaseSealParameterVersion::ElevenDataPrimes);
            // Quick and balanced retain every serialized parameter, including
            // the exact prime order, security caps and key-generation policy.
            if (!rotation_payload) CHECK(expected == eleven_prime_profile);
            CHECK(expected.fresh_rns_limbs == 11);
            CHECK(ten_prime_profile.fresh_rns_limbs == 10);
            CHECK(expected.exact_data_primes.size() == ten_prime_profile.exact_data_primes.size() + 1U);
            CHECK(std::equal(ten_prime_profile.exact_data_primes.begin(), ten_prime_profile.exact_data_primes.end(),
                             eleven_prime_profile.exact_data_primes.begin()));
            CHECK(expected.exact_data_primes.back() == (rotation_payload
                ? 35'156'991'246'337ULL : 1'095'233'372'161ULL));
            CHECK(ten_prime_profile.exact_special_prime == 8'590'163'969ULL);
            CHECK(eleven_prime_profile.exact_special_prime == ten_prime_profile.exact_special_prime);
            CHECK(std::equal(eleven_prime_profile.exact_data_primes.begin(),
                             eleven_prime_profile.exact_data_primes.begin() + 3,
                             expected.exact_data_primes.begin()));
            CHECK((eleven_prime_profile.exact_data_primes == expected.exact_data_primes) == !rotation_payload);
            CHECK(expected.exact_special_prime == (rotation_payload
                ? 1'152'921'504'606'748'673ULL : ten_prime_profile.exact_special_prime));
            CHECK(NaturalMagnitude::product(expected.exact_data_primes).bit_count() ==
                  (rotation_payload ? 490U : 430U));
            if (rotation_payload) {
                CHECK(restored.parameters != diagnostic_seal_parameters(
                    options.diagnostic.slots, selected.workload_kind, false));
            }
            auto mismatched = expected;
            mismatched.exact_data_primes[1] += 2;
            CHECK(restored.parameters != mismatched);
        }
        // Galois-key generation is a separate choice from the profile family.
        CHECK(diagnostic_seal_parameters(1024, WorkloadKind::Diamond, true)
                  .exact_special_prime == 8'590'163'969ULL);
        CHECK(diagnostic_seal_parameters(1024, WorkloadKind::MulHeavyPyramid, false)
                  .exact_special_prime == 1'152'921'504'606'748'673ULL);
    });
    try {
        RecoveryFixture fixture;
        const auto pristine = recovery_snapshot(fixture.command.recover_from);
        runner.run("setup disk admission counts an exported gate cache once", [&] {
            auto saved = load_process_setup_recovery(fixture.command);
            const auto preflight = restore_setup_recovery_preflight(
                saved, fixture.selected, fixture.options, fixture.profile, fixture.circuit);
            const auto gate_bytes =
                preflight.capacity_components.gate_mle_preprocessing.local_disk_bytes;
            CHECK(gate_bytes > 0);
            const auto before = diagnostic_required_available_disk(
                fixture.options, preflight, DiagnosticHostAdmissionPoint::SetupStart);
            const auto after = diagnostic_required_available_disk(
                fixture.options, preflight, DiagnosticHostAdmissionPoint::SetupStart, gate_bytes);
            CHECK(before == preflight.setup_start_available_disk_bytes);
            CHECK(after + gate_bytes == before);
            // The same envelope applies after a fresh export or recovery.
            CHECK(after < before);
            CHECK(diagnostic_required_available_disk(fixture.options, preflight,
                DiagnosticHostAdmissionPoint::ServerStart) == preflight.server_start_available_disk_bytes);
            CHECK(recovery_rejects([&] {
                diagnostic_required_available_disk(fixture.options, preflight,
                    DiagnosticHostAdmissionPoint::SetupStart, gate_bytes + 1);
            }));
            CHECK(recovery_rejects([&] {
                diagnostic_required_available_disk(fixture.options, preflight,
                    DiagnosticHostAdmissionPoint::ServerStart, gate_bytes);
            }));
            auto preprocessing_dominates = preflight;
            preprocessing_dominates.all_preprocessing_bytes_upper = before;
            CHECK(diagnostic_required_available_disk(fixture.options, preprocessing_dominates,
                DiagnosticHostAdmissionPoint::SetupStart, gate_bytes) ==
                before + fixture.options.diagnostic.min_free_disk_bytes);
            CHECK(recovery_snapshot(fixture.command.recover_from) == pristine);
        });
        runner.run("restores saved SEAL keys, schedule and client verifier state", [&] {
            auto saved = load_process_setup_recovery(fixture.command);
            CHECK(saved.stored == fixture.stored);
            const auto preflight = restore_setup_recovery_preflight(
                saved, fixture.selected, fixture.options, fixture.profile, fixture.circuit);
            auto contexts = restore_setup_recovery_contexts(saved, fixture.profile.seal_parameters);
            const auto certified = protocol::certify_base_client_setup<SealBackend>(
                fixture.profile.payload, fixture.circuit,
                make_client_setup<SealBackend>(preflight.public_setup, std::move(contexts.client)));
            CHECK(SealBackend::serialize_evaluation_context_bundle(contexts.eval) == saved.server_bytes);
            CHECK(SealBackend::serialize_client_context_bundle(certified.context()) == saved.client_context_bytes);
            CHECK(protocol::encode_base_client_static_setup(certified) == saved.client_static_bytes);
            CHECK(recovery_snapshot(fixture.command.recover_from) == pristine);
            CHECK(!std::filesystem::exists(fixture.command.run_directory));

            // The destination receives a new identity; each role's saved state
            // survives publication and reopening without changing the source.
            create_process_run_tree(fixture.command.run_directory);
            gates::export_gate_table_prover_key(*saved.gate_key,
                fixture.command.run_directory / "server/preprocessing/gate-mle");
            const auto reopened = gates::reopen_gate_table_prover_key(*saved.stored.gate_mle_verifier,
                fixture.command.run_directory / "server/preprocessing/gate-mle");
            CHECK(reopened.verifier == *saved.stored.gate_mle_verifier);
            auto recovered_record = saved.stored;
            recovered_record.run_id.fill(29);
            recovered_record.git_commit = LAMINATE_BASE_CHECKPOINT_GIT_COMMIT;
            publish_private_file(fixture.command.run_directory / "shared/setup.bin",
                                 encode_process_setup(recovered_record));
            publish_private_file(fixture.command.run_directory / "server/preprocessing/server.bin", saved.server_bytes);
            publish_private_file(fixture.command.run_directory / "client/preprocessing/client.bin", saved.client_context_bytes);
            publish_private_file(fixture.command.run_directory / "client/preprocessing/client-static.bin", saved.client_static_bytes);
            CHECK(load_process_setup(fixture.command) == recovered_record);
            CHECK(recovery_snapshot(fixture.command.recover_from) == pristine);
        });
        runner.run("existing destination and overlapping source are preserved", [&] {
            const auto destination = recovery_snapshot(fixture.command.run_directory);
            CHECK(recovery_rejects([&] { create_process_run_tree(fixture.command.run_directory); }));
            CHECK(recovery_snapshot(fixture.command.run_directory) == destination);
            auto command = fixture.command;
            command.run_directory = command.recover_from;
            CHECK(recovery_rejects([&] { load_process_setup_recovery(command); }));
            command.run_directory = command.recover_from / "nested";
            CHECK(recovery_rejects([&] { load_process_setup_recovery(command); }));
            CHECK(recovery_snapshot(fixture.command.recover_from) == pristine);
        });
        runner.run("source lock prevents recovery while another role is active", [&] {
            RunLifecycleLock active(fixture.command.recover_from, RunLifecycleLockMode::Shared);
            CHECK(recovery_rejects([&] { load_process_setup_recovery(fixture.command); }));
            CHECK(recovery_snapshot(fixture.command.recover_from) == pristine);
        });
        runner.run("corrupted role artifacts fail before any destination write", [&] {
            for (const auto relative : {"server/preprocessing/server.bin", "server/preprocessing/gate-mle/tables.bin", "client/preprocessing/client.bin",
                                        "client/preprocessing/client-static.bin"}) {
                const auto path = fixture.command.recover_from / relative;
                auto corrupted = pristine.at(relative);
                corrupted.back() ^= 1U;
                write_private_bundle(path, corrupted);
                CHECK(recovery_rejects([&] { load_process_setup_recovery(fixture.command); }));
                CHECK(read_bounded_file(path, corrupted.size()) == corrupted);
                write_private_bundle(path, pristine.at(relative));
            }
            CHECK(recovery_snapshot(fixture.command.recover_from) == pristine);
        });
        runner.run("completed setup and unrelated failures cannot be recovered", [&] {
            const auto result = fixture.command.recover_from / "shared/setup-result.txt";
            recovery_text(result, "setup.result=PASS\n");
            CHECK(recovery_rejects([&] { load_process_setup_recovery(fixture.command); }));
            std::filesystem::remove(result);
            const auto failure = fixture.command.recover_from / "shared/setup-failure.txt";
            recovery_text(failure, "FAILED: unrelated failure\n");
            CHECK(recovery_rejects([&] { load_process_setup_recovery(fixture.command); }));
            write_private_bundle(failure, pristine.at("shared/setup-failure.txt"));
            CHECK(recovery_snapshot(fixture.command.recover_from) == pristine);
        });
        runner.run("unsupported revisions and ordinary build mismatches remain rejected", [&] {
            const auto original = fixture.stored.git_commit;
            fixture.stored.git_commit = "unsupported-old-revision";
            fixture.write_setup();
            CHECK(recovery_rejects([&] { load_process_setup_recovery(fixture.command); }));
            CHECK(recovery_rejects([&] { require_process_build_match(fixture.stored); }));
            fixture.stored.git_commit = original;
            fixture.write_setup();
            CHECK(recovery_rejects([&] { require_process_build_match(fixture.stored); }));
            CHECK(recovery_snapshot(fixture.command.recover_from) == pristine);
        });
        runner.run("recovery binds the schedule, resource plan, and SEAL parameters", [&] {
            auto saved = load_process_setup_recovery(fixture.command);
            const auto original = saved.stored;
            for (const int field : {0, 1, 2, 3, 4}) {
                saved.stored = original;
                if (field == 0) saved.stored.schedule_digest[0] ^= 1U;
                if (field == 1) saved.stored.public_setup_digest[0] ^= 1U;
                if (field == 2) saved.stored.replay_plan_digest[0] ^= 1U;
                if (field == 3) ++saved.stored.client_peak_resident_bytes;
                if (field == 4) ++saved.stored.client_wire_limits.max_ciphertexts;
                CHECK(recovery_rejects([&] {
                    restore_setup_recovery_preflight(saved, fixture.selected, fixture.options,
                                                     fixture.profile, fixture.circuit);
                }));
            }
            auto wrong_parameters = fixture.profile.seal_parameters;
            wrong_parameters.generate_galois_keys = !wrong_parameters.generate_galois_keys;
            CHECK(recovery_rejects([&] { restore_setup_recovery_contexts(saved, wrong_parameters); }));
            CHECK(recovery_snapshot(fixture.command.recover_from) == pristine);
        });
        runner.run("rejects a client key from a different SEAL setup", [&] {
            auto saved = load_process_setup_recovery(fixture.command);
            const auto other = SealBackend::create(fixture.profile.seal_parameters);
            saved.client_context_bytes =
                SealBackend::serialize_client_context_bundle(other.client);
            CHECK(recovery_rejects([&] {
                restore_setup_recovery_contexts(saved, fixture.profile.seal_parameters);
            }));
            CHECK(recovery_snapshot(fixture.command.recover_from) == pristine);
        });
    } catch (const std::exception &error) {
        std::cerr << "Recovery fixture failed: " << error.what() << '\n';
        return 1;
    }
    return runner.summary();
}
