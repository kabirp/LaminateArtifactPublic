// Compile the production profile factory and shared setup preflight directly:
// this test must never silently retain a separate "known-good" parameter list.
#define main laminate_base_benchmark_main
#include "../protocol/base_checkpoint_benchmark.cpp"
#undef main

int main(int argc, char **argv) {
    try {
        if (argc != 2 || (std::string_view(argv[1]) != "current" &&
                          std::string_view(argv[1]) != "insufficient-noise")) {
            throw std::invalid_argument("expected current or insufficient-noise");
        }
        const bool insufficient_noise = std::string_view(argv[1]) == "insufficient-noise";
        const ProcessCommand command{
            .action = ProcessAction::VerifySavedResponse, .variant = "base",
            .profile = "target-mulHeavyPyramid",
            .run_directory = "/tmp/laminate-target-noise-preflight-no-artifacts"};
        const auto selected = process_profile(command.profile);
        const auto options = process_options(command, selected,
            derive_host_resource_budget(8'500'000'000'000ULL, 372'000'000'000ULL));
        auto profile = make_run_profile(options);
        if (insufficient_noise)
            profile.seal_parameters = process_client_seal_parameters(
                selected, options, BaseSealParameterVersion::ElevenDataPrimes);
        const auto circuit = compile(profile.payload);
        const auto schedule = derive_certified_uniform_honest_base_proof_schedule(
            circuit, profile.seal_parameters.exact_data_primes,
            profile.calibration, selected.proof_ingress_rns_limbs);
        std::cout << "Diagnostic only: exact target dependency cones; profile="
                  << (insufficient_noise ? "insufficient-noise-eleven-data-primes" : "current")
                  << "; no benchmark artifacts or GateMLE commitments are created.\n";
        try {
            require_target_pyramid_noise_preflight(
                profile.payload, circuit, profile.inputs, profile.seal_parameters,
                schedule.schedule().evaluation_plan,
                options.diagnostic.max_resident_ram_bytes, std::cout);
        } catch (const std::runtime_error &error) {
            if (insufficient_noise && std::string_view(error.what()).starts_with(
                    "target ciphertext preflight FAILED:")) {
                std::cout << "Insufficient-noise profile rejection PASS: "
                          << error.what() << '\n';
                return 0;
            }
            throw;
        }
        if (insufficient_noise)
            throw std::runtime_error("insufficient-noise profile unexpectedly passed the preflight");
        std::cout << "Current-profile sampled noise preflight PASS\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "Target noise preflight test FAILED: " << error.what() << '\n';
        return 1;
    }
}
