/// @file test_packed_process_profile.cpp
/// @brief Folded/Laned process-profile and target-chain policy tests.

#include "test_helpers.hpp"

#include "laminate/bench/packed_process_profile.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/fixtures/workloads.hpp"

using namespace laminate;
using namespace laminate::bench;
using laminate::test::Runner;

namespace {

constexpr std::size_t representative_lanes(PackedProcessVariant variant) {
    return variant == PackedProcessVariant::Laned ? 128 : 0;
}

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

void check_profile_payload_headroom(PackedProcessVariant variant,
                                    PackedProcessTier tier,
                                    std::size_t lanes) {
    const auto profile = packed_process_profile(variant, tier, lanes);
    const auto shape = variant == PackedProcessVariant::Folded
        ? payload::PayloadShape::wide(profile.slots)
        : payload::PayloadShape::laned(lanes, profile.slots);
    const auto payload_circuit = payload::make_payload_circuit(payload::WorkloadSpec{
        .kind = payload::WorkloadKind::Diamond,
        .shape = shape,
        .multiplicative_depth = profile.multiplicative_depth,
        .width = 4,
        .seed = 1,
        .input_count = 4});
    const auto circuit = payload::compile(payload_circuit);
    const auto ingress = protocol::derive_conservative_packed_proof_ingress_schedule(
        variant == PackedProcessVariant::Folded
            ? protocol::PackingGkrVariant::Folded : protocol::PackingGkrVariant::Laned,
        payload_circuit, circuit, make_direct_setup(payload_circuit, circuit),
        packed_process_proof_ingress_policy(profile));
    std::vector<std::size_t> proof_depths;
    for (const auto limbs : ingress.rns_limbs_by_layer()) proof_depths.push_back(limbs - 1U);
    proof_depths.front() = 0;
    const auto selected = packed_process_evaluation_plan(profile, circuit, proof_depths);
    if (packed_process_uses_folded_pyramid_headroom(profile)) {
        CHECK(ingress.policy() == protocol::kConservativePackedProofIngressPolicyV4);
        const std::vector<std::size_t> natural_limbs{
            1,4,7,7,8,8,9,9,10,10,11,11,12,12,13,13,14,14};
        const std::vector<std::size_t> proof_limbs{
            1,4,6,4,6,4,6,4,6,4,6,4,6,4,6,4,6,4};
        CHECK(natural_limbs.size() == circuit.layers.size());
        for (std::size_t i = 0; i < natural_limbs.size(); ++i) {
            CHECK(selected.trace.required_mult_depth_by_layer[i] + 1 == natural_limbs[i]);
            CHECK(selected.proof_ingress_mult_depth_by_layer[i] + 1 == proof_limbs[i]);
        }
        CHECK(selected.modulus_switches_after_layer ==
              (std::vector<std::size_t>{3,3,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,0}));
        auto wrong = proof_depths;
        wrong[1] = 2;
        CHECK(throws_invalid_argument([&] {
            (void)packed_process_evaluation_plan(profile, circuit, wrong);
        }));
        return;
    }
    const auto extra = tier == PackedProcessTier::Quick ? 0U : 1U;
    const auto previous = payload::FheEvaluationPlan::packed_payload_with_prompt_switches(
        circuit, profile.fresh_rns_limbs() - 1U - extra, proof_depths);
    CHECK(selected.proof_ingress_mult_depth_by_layer == previous.proof_ingress_mult_depth_by_layer);
    CHECK(selected.trace.required_mult_depth_by_layer.front() == 0);
    CHECK(selected.modulus_switches_after_layer.front() ==
          previous.modulus_switches_after_layer.front() + extra);
    std::size_t multiplication_layers = 0;
    for (std::size_t layer = 1; layer < circuit.layers.size(); ++layer) {
        CHECK(selected.trace.required_mult_depth_by_layer[layer] ==
              previous.trace.required_mult_depth_by_layer[layer] + extra);
        CHECK(selected.modulus_switches_after_layer[layer] ==
              previous.modulus_switches_after_layer[layer]);
        if (payload::layer_kind(circuit.layers[layer]) == payload::LayerKind::Multiplication) {
            ++multiplication_layers;
            CHECK(selected.modulus_switches_after_layer[layer] >= 1);
        }
    }
    CHECK(multiplication_layers == profile.multiplicative_depth);
    if (tier == PackedProcessTier::Quick) CHECK(selected == previous);
}

} // namespace

int main() {
    Runner runner("packed process profiles");

    runner.run("quick is an explicit reduced-security stress test", [] {
                   for (const PackedProcessVariant variant : {
                            PackedProcessVariant::Folded,
                            PackedProcessVariant::Laned}) {
                       const PackedProcessProfile quick =
                           packed_process_profile(
                               variant, PackedProcessTier::Quick,
                               representative_lanes(variant));
                       CHECK(quick.packing_repetitions == 4);
                       CHECK(quick.basefold_queries == 4);
                       CHECK(quick.selected_packing_repetitions == 120);
                       CHECK(quick.selected_basefold_queries == 150);
                       CHECK(quick.basefold_log_rate == 3);
                       CHECK(quick.ciphertext_commitment_policy ==
                             gkr::CiphertextCommitmentPolicy::
                                 diagnostic_simple_ct_hash_v2());
                       CHECK(quick.is_reduced_security_stress_test());
                       CHECK(quick.admits_execution());
                   }
               });

    runner.run("evaluation profiles reject the diagnostic ciphertext hash",
               [] {
                   PackedProcessProfile candidate = packed_process_profile(
                       PackedProcessVariant::Folded,
                       PackedProcessTier::TargetBalanced, 0);
                   CHECK(candidate.admits_execution());
                   candidate.ciphertext_commitment_policy =
                       gkr::CiphertextCommitmentPolicy::
                           diagnostic_simple_ct_hash_v2();
                   CHECK(!candidate.admits_execution());
               });

    runner.run("targets retain an extra payload limb across every multiplication", [] {
        for (const auto tier : {PackedProcessTier::TargetBalanced, PackedProcessTier::TargetMulHeavy})
            check_profile_payload_headroom(PackedProcessVariant::Folded, tier, 0);
        for (const auto lanes : {1U, 128U, 16384U})
            check_profile_payload_headroom(PackedProcessVariant::Laned,
                                          PackedProcessTier::TargetBalanced, lanes);
    });

    runner.run("quick payload and proof level schedules remain unchanged", [] {
        check_profile_payload_headroom(PackedProcessVariant::Folded, PackedProcessTier::Quick, 0);
        for (const auto lanes : {1U, 128U, 16384U})
            check_profile_payload_headroom(PackedProcessVariant::Laned, PackedProcessTier::Quick, lanes);
    });

    runner.run("target geometries and security choices are executable",
               [] {
                   for (const PackedProcessTier tier : {
                            PackedProcessTier::TargetBalanced,
                            PackedProcessTier::TargetMulHeavy}) {
                       for (const PackedProcessVariant variant : {
                                PackedProcessVariant::Folded,
                                PackedProcessVariant::Laned}) {
                           if (variant == PackedProcessVariant::Laned &&
                               tier == PackedProcessTier::TargetMulHeavy) {
                               continue;
                           }
                           const PackedProcessProfile target =
                               packed_process_profile(
                                   variant, tier,
                                   representative_lanes(variant));
                           CHECK(target.slots ==
                                 (std::size_t{1} << 14U));
                           CHECK(target.multiplicative_depth == 8);
                           CHECK(target.middle_width ==
                                 (tier == PackedProcessTier::TargetBalanced
                                      ? 65'536
                                      : 434'176));
                           CHECK(target.payload_operations == 1'048'576);
                           CHECK(target.input_ciphertexts == 64);
                           CHECK(target.output_ciphertexts == 1);
                           CHECK(target.packing_repetitions == 120);
                           CHECK(target.basefold_queries == 150);
                           CHECK(target.selected_basefold_queries == 150);
                           CHECK(target.basefold_log_rate == 3);
                           CHECK(target.evidence ==
                                 PackedProcessEvidence::Evaluation);
                           CHECK(target.ciphertext_commitment_policy ==
                                 gkr::CiphertextCommitmentPolicy::
                                     poseidon_v2());
                           CHECK(!target.ciphertext_commitment_policy
                                      .is_diagnostic_only());
                           CHECK(target.admits_execution());
                       }
                   }
               });

    runner.run("payload BhIP and packing R1CS geometry are exact formulas",
               [] {
                   const auto folded_quick = packed_process_r1cs_geometry(
                       packed_process_profile(
                           PackedProcessVariant::Folded,
                           PackedProcessTier::Quick, 0));
                   const auto folded_balanced = packed_process_r1cs_geometry(
                       packed_process_profile(
                           PackedProcessVariant::Folded,
                           PackedProcessTier::TargetBalanced, 0));
                   const auto folded_mulheavy = packed_process_r1cs_geometry(
                       packed_process_profile(
                           PackedProcessVariant::Folded,
                           PackedProcessTier::TargetMulHeavy, 0));
                   const auto laned_quick = packed_process_r1cs_geometry(
                       packed_process_profile(
                           PackedProcessVariant::Laned,
                           PackedProcessTier::Quick, 128));
                   const auto laned_balanced = packed_process_r1cs_geometry(
                       packed_process_profile(
                           PackedProcessVariant::Laned,
                           PackedProcessTier::TargetBalanced, 128));


                   CHECK(folded_quick.aligned_ciphertexts == 321);
                   CHECK(folded_balanced.aligned_ciphertexts == 517);
                   CHECK(folded_mulheavy.aligned_ciphertexts == 509);
                   CHECK(laned_quick.aligned_ciphertexts == 231);
                   CHECK(laned_balanced.aligned_ciphertexts == 399);
                   CHECK(!folded_quick.ledger
                              .nonzero_entry_counts_available);
                   CHECK(!folded_balanced.ledger
                              .nonzero_entry_counts_available);

                   CHECK(folded_quick.ledger
                             .ciphertext_commitment_constraints_per_ciphertext ==
                         2 * folded_quick.ring_degree + kPoseidonDigestElements);
                   CHECK(folded_quick.ledger.total_constraints ==
                         folded_quick.ledger
                                 .ciphertext_commitment_constraints +
                             folded_quick.ledger
                                 .packing_relation_constraints);
                   CHECK(folded_quick.ledger.total_constraints ==
                         52'859'322ULL);
                   CHECK(folded_quick.ledger.matrix_rows ==
                         52'887'552ULL);
                   CHECK(folded_quick.padded_constraints ==
                         (std::uint64_t{1} << 26U));
                   CHECK(folded_quick.ledger.total_public_inputs ==
                         264'114ULL);
                   CHECK(folded_quick.ledger.active_witness_variables ==
                         63'113'736ULL);
                   CHECK(folded_quick.ledger.total_witness_variables ==
                         64'192'512ULL);

                   CHECK(folded_balanced.ledger.total_constraints ==
                         3'167'501'480ULL);
                   CHECK(folded_balanced.ledger.matrix_rows ==
                         3'167'518'720ULL);
                   CHECK(folded_balanced.padded_constraints ==
                         (std::uint64_t{1} << 32U));
                   CHECK(folded_balanced.assignment_half_size ==
                         (std::uint64_t{1} << 32U));
                   CHECK(folded_balanced.padded_assignment_variables ==
                         (std::uint64_t{1} << 33U));
                   CHECK(folded_balanced.ledger.total_public_inputs ==
                         4'068'438ULL);
                   CHECK(folded_balanced.ledger.active_witness_variables ==
                         3'180'374'098ULL);
                   CHECK(folded_balanced.ledger.total_witness_variables ==
                         3'181'396'898ULL);
                   CHECK(laned_balanced.ledger
                             .ciphertext_commitment_constraints_per_ciphertext ==
                         folded_balanced.ledger
                             .ciphertext_commitment_constraints_per_ciphertext);
                   CHECK(laned_balanced.padded_constraints ==
                         (std::uint64_t{1} << 32U));
                   CHECK(folded_mulheavy.padded_constraints ==
                         (std::uint64_t{1} << 32U));
               });

    runner.run("BhIP formulas agree with compiled protocol traversal",
               [] {
                   for (const PackedProcessTier tier : {
                            PackedProcessTier::Quick,
                            PackedProcessTier::TargetBalanced,
                            PackedProcessTier::TargetMulHeavy}) {
                       for (const PackedProcessVariant variant : {
                                PackedProcessVariant::Folded,
                                PackedProcessVariant::Laned}) {
                           if (variant == PackedProcessVariant::Laned &&
                               tier == PackedProcessTier::TargetMulHeavy) {
                               continue;
                           }
                           PackedProcessProfile representative =
                               packed_process_profile(
                                   variant, tier,
                                   representative_lanes(variant));
                           const payload::PayloadShape shape =
                               variant == PackedProcessVariant::Folded
                                   ? payload::PayloadShape::wide(
                                         representative.slots)
                                   : payload::PayloadShape::laned(
                                         representative.lanes,
                                         representative.slots);
                           const payload::PayloadCircuit payload =
                               payload::make_payload_circuit(
                                   benchmark_payload_workload_spec(
                                       benchmark_payload_profile(
                                           representative.tier),
                                       shape));
                           const payload::LayeredCircuit circuit =
                               payload::compile(payload);
                           const std::size_t compiled =
                               variant == PackedProcessVariant::Folded
                                   ? protocol::folded_bhip_round_count(circuit)
                                   : protocol::laned_bhip_round_count(circuit);
                           CHECK(packed_process_bhip_round_count(
                                     representative) == compiled);
                       }
                   }
               });

    runner.run("variant-specific fixed schedules determine candidate chains",
               [] {
                   const PackedProcessProfile folded =
                       packed_process_profile(
                           PackedProcessVariant::Folded,
                           PackedProcessTier::TargetBalanced, 0);
                   const PackedProcessProfile laned =
                       packed_process_profile(
                           PackedProcessVariant::Laned,
                           PackedProcessTier::TargetBalanced, 128);
                   CHECK(folded.proof_ingress_depth == 5);
                   CHECK(folded.fresh_rns_limbs() == 14);
                   CHECK(folded.fresh_modulus_width_sum_bits() == 579);
                   CHECK(folded.key_modulus_width_sum_bits() == 639);
                   CHECK(folded.data_prime_bit_sizes ==
                         (std::vector<int>{60, 48, 48, 37, 37, 37, 37,
                                           38, 38, 39, 40, 40, 40, 40}));
                   CHECK(folded.special_prime_bits == 60);
                   CHECK(laned.proof_ingress_depth == 6);
                   CHECK(laned.fresh_rns_limbs() == 15);
                   CHECK(laned.fresh_modulus_width_sum_bits() == 619);
                   CHECK(laned.key_modulus_width_sum_bits() == 679);
                   CHECK(laned.data_prime_bit_sizes ==
                         (std::vector<int>{60, 48, 48, 37, 37, 37, 37,
                                           38, 38, 39, 40, 40, 40, 40, 40}));
                   CHECK(laned.special_prime_bits == 60);
                   CHECK(folded.data_prime_bit_sizes.front() == 60);
                   CHECK(laned.data_prime_bit_sizes.front() == 60);
                   CHECK(laned.lanes == 128);
                   CHECK(folded.lanes == 0);
               });

    runner.run("Folded pyramid fixes the626-bit chain without changing balanced", [] {
        const auto pyramid = packed_process_profile(PackedProcessVariant::Folded,
            PackedProcessTier::TargetMulHeavy, 0);
        CHECK(pyramid.fresh_rns_limbs() == 14);
        CHECK(pyramid.exact_data_primes == std::vector<std::uint64_t>(
            kFoldedPyramidDataPrimes.begin(), kFoldedPyramidDataPrimes.end()));
        CHECK(pyramid.exact_special_prime == kFoldedPyramidSpecialPrime);
        CHECK(pyramid.data_prime_bit_sizes == (std::vector<int>{
            60,48,48,37,37,37,45,45,45,45,45,45,45,45}));
        CHECK(pyramid.exact_data_primes.back() == 35'156'991'246'337ULL);
        for (const auto prime : pyramid.exact_data_primes)
            CHECK((prime - 1U) % (2U * pyramid.slots * 65'537U) == 0);
        const auto balanced = packed_process_profile(PackedProcessVariant::Folded,
            PackedProcessTier::TargetBalanced, 0);
        CHECK(balanced.exact_data_primes.empty());
        CHECK(balanced.exact_special_prime == 0);
        CHECK(packed_process_proof_ingress_policy(balanced) ==
              protocol::ConservativePackedProofIngressPolicy::VariantDefault);
        // Validate the exact tested levels on the actual million-gate public
        // workload, independently of the small scheduling fixture above.
        const auto payload = payload::make_payload_circuit(
            benchmark_payload_workload_spec(benchmark_payload_profile(pyramid.tier),
                payload::PayloadShape::wide(pyramid.slots)));
        const auto circuit = payload::compile(payload);
        const auto ingress = protocol::derive_conservative_packed_proof_ingress_schedule(
            protocol::PackingGkrVariant::Folded, payload, circuit,
            make_direct_setup(payload, circuit), packed_process_proof_ingress_policy(pyramid));
        std::vector<std::size_t> depths;
        for (auto limbs : ingress.rns_limbs_by_layer()) depths.push_back(limbs - 1U);
        const auto plan = packed_process_evaluation_plan(pyramid, circuit, depths);
        CHECK(plan.trace.required_mult_depth_by_layer ==
              (std::vector<std::size_t>{0,3,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13}));
    });

    runner.run("Laned profiles expose exactly the selected lane counts", [] {
        static constexpr std::size_t supported_lanes[]{1, 128,
                                                       std::size_t{1} << 14U};
        static constexpr std::size_t expected_aligned[][2]{
            {195, 287},
            {231, 399},
            {321, 517},
        };
        static constexpr PackedProcessTier tiers[]{
            PackedProcessTier::Quick,
            PackedProcessTier::TargetBalanced,
        };

        for (std::size_t lane_index = 0;
             lane_index < std::size(supported_lanes); ++lane_index) {
            for (std::size_t tier_index = 0; tier_index < std::size(tiers);
                 ++tier_index) {
                const PackedProcessProfile profile = packed_process_profile(
                    PackedProcessVariant::Laned, tiers[tier_index],
                    supported_lanes[lane_index]);
                CHECK(profile.lanes == supported_lanes[lane_index]);
                CHECK(profile.proof_ingress_depth ==
                      (profile.lanes == profile.slots ? 5U : 6U));
                CHECK(packed_process_r1cs_geometry(profile)
                          .aligned_ciphertexts ==
                      expected_aligned[lane_index][tier_index]);
            }
        }
    });

    runner.run("full-width Laned omits exactly the witness-packing head", [] {
        for (const auto tier : {PackedProcessTier::Quick,
                                PackedProcessTier::TargetBalanced}) {
            const auto full = packed_process_profile(
                PackedProcessVariant::Laned, tier,
                kDefaultPolyModulusDegree);
            const auto narrow = packed_process_profile(
                PackedProcessVariant::Laned, tier, 128);
            const auto single = packed_process_profile(
                PackedProcessVariant::Laned, tier, 1);
            const auto folded = packed_process_profile(
                PackedProcessVariant::Folded, tier, 0);
            CHECK(full.proof_ingress_depth + 1U == narrow.proof_ingress_depth);
            CHECK(full.fresh_rns_limbs() + 1U == narrow.fresh_rns_limbs());
            auto without_last_head = narrow.data_prime_bit_sizes;
            without_last_head.pop_back();
            CHECK(full.data_prime_bit_sizes == without_last_head);
            CHECK(full.data_prime_bit_sizes == folded.data_prime_bit_sizes);
            CHECK(full.special_prime_bits == folded.special_prime_bits);
            CHECK(single.data_prime_bit_sizes == narrow.data_prime_bit_sizes);
            CHECK(full.packing_repetitions == narrow.packing_repetitions);
            CHECK(full.basefold_queries == narrow.basefold_queries);
            CHECK(full.basefold_log_rate == narrow.basefold_log_rate);
            if (tier == PackedProcessTier::TargetBalanced) {
                CHECK(full.fresh_rns_limbs() == 14);
                CHECK(full.fresh_modulus_width_sum_bits() == 579);
                CHECK(full.key_modulus_width_sum_bits() == 639);
            } else {
                CHECK(full.fresh_rns_limbs() == 11);
                CHECK(narrow.fresh_rns_limbs() == 12);
            }
        }
    });

    runner.run("target campaign admits both Wide payloads and three Laned widths", [] {
        CHECK(benchmark_profile_is_in_campaign(
            "base", PackedProcessTier::TargetMulHeavy));
        CHECK(benchmark_profile_is_in_campaign(
            "folded", PackedProcessTier::TargetMulHeavy));
        CHECK(benchmark_profile_is_in_campaign(
            "laned", PackedProcessTier::TargetBalanced));
        CHECK(benchmark_profile_is_in_campaign(
            "base", PackedProcessTier::TargetBalanced));
        CHECK(benchmark_profile_is_in_campaign(
            "folded", PackedProcessTier::TargetBalanced));
        CHECK(!benchmark_profile_is_in_campaign(
            "laned", PackedProcessTier::TargetMulHeavy));
        for (const auto variant : {"base", "folded", "laned"}) {
            CHECK(benchmark_profile_is_in_campaign(
                variant, PackedProcessTier::Quick));
        }
    });

    runner.run("Laned profiles reject cross-slot mulheavy payloads", [] {
        for (const std::size_t lanes : {1U, 128U, 16'384U}) {
            CHECK(throws_invalid_argument([lanes] {
                (void)packed_process_profile(PackedProcessVariant::Laned,
                                             PackedProcessTier::TargetMulHeavy,
                                             lanes);
            }));
        }
        auto altered = packed_process_profile(
            PackedProcessVariant::Folded, PackedProcessTier::TargetMulHeavy, 0);
        altered.variant = PackedProcessVariant::Laned;
        altered.lanes = 128;
        CHECK(throws_invalid_argument([&] {
            (void)packed_process_r1cs_geometry(altered);
        }));
    });

    runner.run("profiles reject unsupported lane counts", [] {
        CHECK(throws_invalid_argument([] {
            (void)packed_process_profile(PackedProcessVariant::Folded,
                                         PackedProcessTier::Quick, 1);
        }));
        for (const std::size_t lanes : {std::size_t{0}, std::size_t{2},
                                        std::size_t{64},
                                        std::size_t{16'383}}) {
            CHECK(throws_invalid_argument([lanes] {
                (void)packed_process_profile(PackedProcessVariant::Laned,
                                             PackedProcessTier::Quick,
                                             lanes);
            }));
        }
    });

    return runner.summary();
}
