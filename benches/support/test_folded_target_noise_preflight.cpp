#include "folded_target_noise_preflight.hpp"
#include "laminate/payload/fixtures/workloads.hpp"

#include <chrono>
#include <iostream>

int main() {
    using namespace laminate;
    using namespace laminate::bench;
    using namespace laminate::payload;
    using namespace laminate::fhe;
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto scratch = std::filesystem::temp_directory_path() /
        ("laminate-folded-live-key-preflight-test-" + std::to_string(stamp));
    try {
        const auto profile = packed_process_profile(
            PackedProcessVariant::Folded, PackedProcessTier::TargetMulHeavy, 0);
        const auto spec = benchmark_payload_workload_spec(
            benchmark_payload_profile("target-mulHeavyPyramid"), PayloadShape::wide(profile.slots), 1);
        const auto target = make_payload_circuit(spec);
        const auto circuit = compile(target);
        const auto inputs = make_workload_inputs(spec);
        const auto public_setup = make_direct_setup(target, circuit);
        const auto ingress = protocol::derive_conservative_packed_proof_ingress_schedule(
            protocol::PackingGkrVariant::Folded, target, circuit, public_setup,
            packed_process_proof_ingress_policy(profile));
        std::vector<std::size_t> depths;
        for (const auto limbs : ingress.rns_limbs_by_layer()) depths.push_back(limbs - 1U);
        const auto plan = packed_process_evaluation_plan(profile, circuit, depths);
        const SealParameters parameters{
            .poly_modulus_degree = profile.slots,
            .fresh_rns_limbs = profile.fresh_rns_limbs(),
            .data_prime_bit_sizes = {},
            .exact_data_primes = profile.exact_data_primes,
            .exact_special_prime = profile.exact_special_prime,
            .special_prime_bits = profile.special_prime_bits,
            .security_level = seal::sec_level_type::none,
            .generate_galois_keys = true};
        auto contexts = SealBackend::create(parameters);
        // The preflight must reject a changed natural plan before encryption,
        // even if its independent proof-ingress levels are still legal.
        auto changed = plan;
        changed.modulus_switches_after_layer[15] += 1;
        bool rejected = false;
        try {
            require_folded_pyramid_live_key_preflight(
                target, circuit, inputs, contexts.eval, contexts.client, changed,
                scratch, std::uint64_t{16} << 30U, std::cout);
        } catch (const std::invalid_argument &) { rejected = true; }
        if (!rejected || std::filesystem::exists(scratch))
            throw std::runtime_error("changed plan did not reject before creating scratch");
        require_folded_pyramid_live_key_preflight(
            target, circuit, inputs, contexts.eval, contexts.client, plan,
            scratch, std::uint64_t{16} << 30U, std::cout);
        if (std::filesystem::exists(scratch))
            throw std::runtime_error("preflight scratch directory was not removed");
        std::cout << "Folded current-profile same-key preflight regression PASS\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "Folded live-key preflight regression FAILED: " << error.what() << '\n';
        return 1;
    }
}
