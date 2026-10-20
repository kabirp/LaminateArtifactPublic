/// @file test_lazy_ternary_seal.cpp
/// @brief Live SEAL checks for lazy-ternary evaluation and diagnostics.

#include "test_helpers.hpp"

#include "laminate/fhe/seal_backend.hpp"
#include "laminate/packing/analysis/honest_finalization.hpp"
#include "laminate/packing/analysis/unbound_lazy_ternary_diagnostic.hpp"
#include "laminate/packing/evaluation/lazy_ternary.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/protocol/folded.hpp"
#include "laminate/protocol/reference/folded.hpp"
#include "laminate/protocol/packed/wire/proof.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::packing;
using namespace laminate::gkr;
using namespace laminate::payload;
using namespace laminate::protocol;

namespace {

constexpr std::size_t kSlots = 1024;

SealBackend::Contexts make_contexts() {
    return SealBackend::create(SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = 4,
        .bits_per_data_prime = 60,
        .special_prime_bits = 60,
        .security_level = seal::sec_level_type::none,
    });
}

SlotVector make_message(std::uint64_t seed) {
    SlotVector result(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        result[slot] = Fp(seed + 13 * slot + slot * slot);
    }
    return result;
}

LazyTernaryParameters evaluation_parameters(
    std::size_t repetitions,
    std::uint64_t radix_base = kSelectedPackingRadixBase,
    std::uint64_t honest_error_bound =
        kSelectedPackingHonestErrorBound) {
    return LazyTernaryParameters{
        .repetitions = repetitions,
        .honest_error_bound = honest_error_bound,
        .packing_radix =
            make_minimal_balanced_radix(kBaseFieldOrder, radix_base),
    };
}

std::vector<SlotVector> expected_packed_plaintexts(
    const PackingLayout &layout,
    const std::vector<SlotVector> &messages) {
    std::vector<SlotVector> result(
        layout.packed_ciphertext_count,
        SlotVector(layout.slot_count, Fp::zero()));
    for (const PackingPlacement &placement : layout.placements) {
        for (std::size_t offset = 0; offset < placement.length; ++offset) {
            result[placement.packed_index]
                  [packing_destination_slot(
                      layout, placement, offset)] =
                messages[placement.message_index]
                        [packing_source_slot(
                            layout, placement, offset)];
        }
    }
    return result;
}

} // namespace

int main() {
    test::Runner runner("test_lazy_ternary_seal");
    SealBackend::Contexts contexts = make_contexts();

    const std::vector<std::size_t> widths{16, 24, 16, 8};
    std::vector<SlotVector> messages;
    std::vector<SealBackend::Ciphertext> ciphertexts;
    for (std::size_t index = 0; index < widths.size(); ++index) {
        messages.push_back(make_message(101 + 97 * index));
        ciphertexts.push_back(
            SealBackend::encrypt(contexts.client, messages.back()));
    }

    runner.run("aligned list is bottom-level normalized before FS", [&] {
        const auto aligned =
            prepare_normalized_aligned_transcript<SealBackend>(
                contexts.eval, ciphertexts, widths);
        CHECK(aligned.values.size() == aligned.layout.placements.size());
        for (const auto &value : aligned.values) {
            CHECK(value.is_encrypted());
            CHECK(SealBackend::rns_limb_count(
                      contexts.eval, value.ciphertext()) == 1);
            CHECK(SealBackend::is_normalized_for_coefficient_commitment(
                value.ciphertext()));
        }

        Transcript first("test/lazy-ternary");
        Transcript second("test/lazy-ternary");
        const auto a = run_unbound_lazy_ternary_diagnostic<SealBackend>(
            contexts.eval, aligned, first, evaluation_parameters(16));
        const auto b = run_unbound_lazy_ternary_diagnostic<SealBackend>(
            contexts.eval, aligned, second, evaluation_parameters(16));
        CHECK(a.parameters.packing_radix.base ==
              kSelectedPackingRadixBase);
        CHECK(a.parameters.packing_radix.digit_count == 4);
        CHECK(a.parameters.honest_error_bound ==
              kSelectedPackingHonestErrorBound);
        CHECK(a.public_challenges == b.public_challenges);

        Transcript changed("test/lazy-ternary");
        const auto base41 = run_unbound_lazy_ternary_diagnostic<SealBackend>(
            contexts.eval, aligned, changed, evaluation_parameters(16, 41));
        CHECK(base41.parameters.packing_radix.digit_count == 3);
        CHECK(base41.public_challenges != a.public_challenges);

        Transcript changed_bound("test/lazy-ternary");
        const auto beta_zero =
            run_unbound_lazy_ternary_diagnostic<SealBackend>(
                contexts.eval, aligned, changed_bound,
                evaluation_parameters(16, 41, 0));
        CHECK(beta_zero.public_challenges != a.public_challenges);
        const auto beta_zero_diagnostics =
            assess_observed_lazy_ternary_diagnostic<SealBackend>(
                contexts.client, aligned, beta_zero);
        CHECK(beta_zero_diagnostics.configured_input_bound ==
              (kBaseFieldOrder - 1) / 2);
        CHECK(!beta_zero_diagnostics
                   .observed_inputs_within_configured_bound);
    });

    runner.run("live tests pass their configured public bound", [&] {
        const auto aligned =
            prepare_normalized_aligned_transcript<SealBackend>(
                contexts.eval, ciphertexts, widths);
        Transcript transcript("test/lazy-ternary/live");
        const auto evaluation =
            run_unbound_lazy_ternary_diagnostic<SealBackend>(
                contexts.eval, aligned, transcript,
                evaluation_parameters(kPackingWellFormednessRepetitions));
        const ObservedLazyTernaryDiagnostics diagnostics =
            assess_observed_lazy_ternary_diagnostic<SealBackend>(
                contexts.client, aligned, evaluation);

        CHECK(diagnostics.observed_max_input_norm > 0);
        CHECK(diagnostics.configured_input_bound ==
              canonical_partial_decryption_bound(
                  kBaseFieldOrder, kSelectedPackingHonestErrorBound));
        CHECK(diagnostics.observed_inputs_within_configured_bound);
        CHECK(diagnostics.configured_test_threshold ==
              lazy_ternary_test_threshold(
                  diagnostics.configured_input_bound,
                  aligned.values.size()));
        CHECK(diagnostics.present_test_ciphertexts > 0);
        CHECK(diagnostics.accepted_tests ==
              kPackingWellFormednessRepetitions);
        CHECK(diagnostics.all_tests_within_configured_threshold);

        const auto expected =
            expected_packed_plaintexts(aligned.layout, messages);
        CHECK(evaluation.logical_packed_outputs == expected.size());
        CHECK(evaluation.packed_digit_values.size() ==
              expected.size() *
                  evaluation.parameters.packing_radix.digit_count);
        CHECK(decrypt_and_recompose_signed_digit_packing<SealBackend>(
                  contexts.client, evaluation.packed_digit_values,
                  evaluation.logical_packed_outputs,
                  evaluation.parameters.packing_radix) == expected);
    });

    runner.run("all-public packing stays plaintext through SEAL", [&] {
        const std::vector<FheValue<SealBackend>> public_values{
            FheValue<SealBackend>::public_slots(messages[0]),
            FheValue<SealBackend>::public_slots(messages[1]),
        };
        const std::vector<std::size_t> public_widths{16, 24};
        const PackingLayout layout =
            make_prefix_packing_layout(kSlots, public_widths);
        const auto aligned =
            prepare_normalized_aligned_transcript<SealBackend>(
                contexts.eval, public_values, layout);
        Transcript transcript("test/lazy-ternary/public-seal");
        const auto evaluation =
            run_unbound_lazy_ternary_diagnostic<SealBackend>(
                contexts.eval, aligned, transcript,
                evaluation_parameters(8));

        for (const auto &value : aligned.values) {
            CHECK(value.is_public());
        }
        for (const auto &value : evaluation.test_values) {
            CHECK(!value.encrypted_contribution);
        }
        for (const auto &value : evaluation.packed_digit_values) {
            CHECK(!value.encrypted_contribution);
        }
        const std::vector<SlotVector> public_messages{
            messages[0], messages[1]};
        CHECK(decrypt_and_recompose_signed_digit_packing<SealBackend>(
                  contexts.client, evaluation.packed_digit_values,
                  evaluation.logical_packed_outputs,
                  evaluation.parameters.packing_radix) ==
              expected_packed_plaintexts(layout, public_messages));
    });

    runner.run("mixed SEAL reveals keep an exact public sidecar", [&] {
        const std::vector<FheValue<SealBackend>> mixed_values{
            FheValue<SealBackend>::from_ciphertext(ciphertexts[0]),
            FheValue<SealBackend>::public_scalar(Fp(40'000)),
        };
        const std::vector<std::size_t> full_widths{kSlots, kSlots};
        const auto aligned =
            prepare_normalized_aligned_transcript<SealBackend>(
                contexts.eval, mixed_values,
                make_prefix_packing_layout(kSlots, full_widths));
        LazyTernaryChallengeMatrix challenges(
            1, std::vector<LazyTernaryChallenge>(aligned.values.size()));
        const auto encrypted_placement = std::find_if(
            aligned.layout.placements.begin(),
            aligned.layout.placements.end(),
            [](const PackingPlacement &placement) {
                return placement.message_index == 0;
            });
        const auto public_placement = std::find_if(
            aligned.layout.placements.begin(),
            aligned.layout.placements.end(),
            [](const PackingPlacement &placement) {
                return placement.message_index == 1;
            });
        CHECK(encrypted_placement != aligned.layout.placements.end());
        CHECK(public_placement != aligned.layout.placements.end());
        const std::size_t encrypted_index = static_cast<std::size_t>(
            encrypted_placement - aligned.layout.placements.begin());
        const std::size_t public_index = static_cast<std::size_t>(
            public_placement - aligned.layout.placements.begin());
        challenges[0][encrypted_index].plus_bit = true;
        challenges[0][public_index].plus_bit = true;
        const auto evaluation =
            evaluate_lazy_ternary<SealBackend>(
                contexts.eval, aligned, challenges,
                evaluation_parameters(1));
        const auto &test = evaluation.test_values.front();

        CHECK(test.encrypted_contribution);
        CHECK(test.public_offset ==
              PublicPlaintext::from_scalar(Fp(40'000)));
        CHECK(test.public_c0_coordinates.size() == kSlots);
        CHECK(SealBackend::serialize(*test.encrypted_contribution) ==
              SealBackend::serialize(
                  aligned.values[encrypted_index].ciphertext()));
        const auto composed =
            normalized_mixed_value_coordinates<SealBackend>(
                contexts.eval, test);
        const auto encrypted_coordinates =
            SealBackend::coefficient_commitment_ntt_coordinate_view(
                *test.encrypted_contribution);
        CHECK(composed.size() == 2 * kSlots);
        CHECK(std::equal(composed.begin() + kSlots, composed.end(),
                         encrypted_coordinates.begin() + kSlots));
    });

    runner.run("SEAL public t-wrap is not relifted in native q", [&] {
        const std::vector<FheValue<SealBackend>> public_values{
            FheValue<SealBackend>::public_scalar(Fp(40'000)),
            FheValue<SealBackend>::public_scalar(Fp(40'000)),
        };
        const std::vector<std::size_t> full_widths{kSlots, kSlots};
        const auto aligned =
            prepare_normalized_aligned_transcript<SealBackend>(
                contexts.eval, public_values,
                make_prefix_packing_layout(kSlots, full_widths));
        LazyTernaryChallengeMatrix challenges(
            1, std::vector<LazyTernaryChallenge>(aligned.values.size()));
        const auto first = std::find_if(
            aligned.layout.placements.begin(),
            aligned.layout.placements.end(),
            [](const PackingPlacement &placement) {
                return placement.message_index == 0;
            });
        const auto second = std::find_if(
            aligned.layout.placements.begin(),
            aligned.layout.placements.end(),
            [](const PackingPlacement &placement) {
                return placement.message_index == 1;
            });
        CHECK(first != aligned.layout.placements.end());
        CHECK(second != aligned.layout.placements.end());
        challenges[0][static_cast<std::size_t>(
            first - aligned.layout.placements.begin())]
            .plus_bit = true;
        challenges[0][static_cast<std::size_t>(
            second - aligned.layout.placements.begin())]
            .plus_bit = true;
        const auto evaluation =
            evaluate_lazy_ternary<SealBackend>(
                contexts.eval, aligned, challenges,
                evaluation_parameters(1));
        const auto &test = evaluation.test_values.front();

        CHECK(!test.encrypted_contribution);
        CHECK(test.public_offset ==
              PublicPlaintext::from_scalar(Fp(80'000)));
        CHECK(test.public_c0_coordinates.size() == kSlots);
        const auto canonical_wrapped =
            normalized_public_value_coordinates<SealBackend>(
                contexts.eval, test.public_offset);
        CHECK(!std::equal(test.public_c0_coordinates.begin(),
                          test.public_c0_coordinates.end(),
                          canonical_wrapped.begin()));
    });

    runner.run("integer ciphertext multiples retain exact native-q coordinates", [&] {
        auto source = ciphertexts.front();
        SealBackend::mod_switch_to_lowest(contexts.eval, source);
        SealBackend::normalize_for_coefficient_commitment(contexts.eval, source);
        const auto original =
            SealBackend::coefficient_commitment_ntt_coordinate_view(source);
        for (const std::int64_t count :
             {0, 1, -1, 2, -2, 32768, -32768, 32769, -32769,
              65536, -65536, 65537, -65537}) {
            lazy_ternary_detail::ExactZeroCiphertextAccumulator<SealBackend>
                accumulator;
            lazy_ternary_detail::add_integer_ciphertext_multiple<SealBackend>(
                contexts.eval, source, count, accumulator);
            const auto result = std::move(accumulator).finish();
            CHECK(result.has_value() == (count != 0));
            if (!result) {
                continue;
            }
            const auto actual =
                SealBackend::coefficient_commitment_ntt_coordinate_view(*result);
            CHECK(actual.size() == original.size());
            const std::uint64_t multiplier =
                count < 0 ? kOuterFieldOrder - static_cast<std::uint64_t>(-count)
                          : static_cast<std::uint64_t>(count);
            for (std::size_t i = 0; i < actual.size(); ++i) {
                const auto expected = static_cast<std::uint64_t>(
                    (static_cast<unsigned __int128>(original[i]) * multiplier) %
                    kOuterFieldOrder);
                CHECK(actual[i] == expected);
            }
        }

        lazy_ternary_detail::ExactZeroCiphertextAccumulator<SealBackend>
            cancelling;
        lazy_ternary_detail::add_integer_ciphertext_multiple<SealBackend>(
            contexts.eval, source, 32769, cancelling);
        lazy_ternary_detail::add_integer_ciphertext_multiple<SealBackend>(
            contexts.eval, source, -32769, cancelling);
        CHECK(!std::move(cancelling).finish());
    });

    runner.run("publicly cancelling reveals never become ciphertexts", [&] {
        const std::vector<SealBackend::Ciphertext> repeated{
            ciphertexts.front(), ciphertexts.front()};
        const std::vector<std::size_t> full_widths{kSlots, kSlots};
        const auto aligned =
            prepare_normalized_aligned_transcript<SealBackend>(
                contexts.eval, repeated, full_widths);
        std::size_t duplicate = aligned.values.size();
        for (std::size_t index = 1;
             index < aligned.values.size(); ++index) {
            if (SealBackend::serialize(aligned.values[0].ciphertext()) ==
                SealBackend::serialize(
                    aligned.values[index].ciphertext())) {
                duplicate = index;
                break;
            }
        }
        CHECK(duplicate < aligned.values.size());

        LazyTernaryChallengeMatrix cancelling(
            1, std::vector<LazyTernaryChallenge>(
                   aligned.values.size()));
        cancelling.front()[0].plus_bit = true;
        cancelling.front()[duplicate].minus_bit = true;
        const auto evaluation =
            evaluate_lazy_ternary<SealBackend>(
                contexts.eval, aligned, cancelling,
                evaluation_parameters(1));
        CHECK(evaluation.test_values.size() == 1);
        CHECK(!evaluation.test_values.front().encrypted_contribution);
        CHECK(evaluation.test_values.front().public_offset.is_zero());
        CHECK(evaluation.test_values.front()
                  .public_c0_coordinates.empty());
    });

    runner.run("distinct correlated SEAL terms cancel to canonical null", [&] {
        auto source = ciphertexts.front();
        SealBackend::mod_switch_to_lowest(contexts.eval, source);
        SealBackend::normalize_for_coefficient_commitment(
            contexts.eval, source);
        auto negative = SealBackend::negate(contexts.eval, source);
        CHECK(SealBackend::serialize(source) !=
              SealBackend::serialize(negative));

        const PackingLayout layout = make_prefix_packing_layout(
            kSlots, std::vector<std::size_t>{kSlots, kSlots});
        const PackingPlacement &first = layout.placements.front();
        const auto matching = std::find_if(
            layout.placements.begin(), layout.placements.end(),
            [&](const PackingPlacement &placement) {
                return placement.message_index == 1 &&
                       placement.source_begin == first.source_begin &&
                       placement.length == first.length &&
                       placement.rotation_steps == first.rotation_steps;
            });
        CHECK(matching != layout.placements.end());
        const std::size_t matching_index = static_cast<std::size_t>(
            matching - layout.placements.begin());
        std::vector<FheValue<SealBackend>> aligned_values(
            layout.placements.size(),
            FheValue<SealBackend>::public_zero());
        aligned_values.front() =
            FheValue<SealBackend>::from_ciphertext(source);
        aligned_values[matching_index] =
            FheValue<SealBackend>::from_ciphertext(negative);
        const NormalizedAlignedTranscript<SealBackend> aligned{
            .layout = layout,
            .values = std::move(aligned_values),
            .public_coordinates =
                std::vector<std::vector<std::uint64_t>>(
                    layout.placements.size()),
            .public_sources =
                std::vector<bool>(layout.placements.size(), false),
            .ciphertext_list_digest = std::nullopt,
        };
        CHECK(SealBackend::serialize(aligned.values.front().ciphertext()) !=
              SealBackend::serialize(
                  aligned.values[matching_index].ciphertext()));
        LazyTernaryChallengeMatrix challenges(
            1, std::vector<LazyTernaryChallenge>(aligned.values.size()));
        challenges.front()[0].plus_bit = true;
        challenges.front()[matching_index].plus_bit = true;

        SealBackend::reset_counts(contexts.eval);
        const auto evaluation =
            evaluate_lazy_ternary<SealBackend>(
                contexts.eval, aligned, challenges,
                evaluation_parameters(1));
        CHECK(evaluation.test_values.size() == 1);
        CHECK(!evaluation.test_values.front().encrypted_contribution);
        CHECK(evaluation.test_values.front().public_offset.is_zero());
        CHECK(evaluation.test_values.front()
                  .public_c0_coordinates.empty());
        const auto counts = SealBackend::counts(contexts.eval);
        CHECK(counts.calls(SealBackend::OperationKind::Encrypt) == 0);

        auto public_nonzero = aligned;
        public_nonzero.values[matching_index] =
            FheValue<SealBackend>::from_ciphertext(
                SealBackend::add_plain_scalar(
                    contexts.eval, negative, Fp(7)));
        bool rejected_unbound_public = false;
        try {
            (void)evaluate_lazy_ternary<SealBackend>(
                contexts.eval, public_nonzero, challenges,
                evaluation_parameters(1));
        } catch (const std::logic_error &) {
            rejected_unbound_public = true;
        }
        CHECK(rejected_unbound_public);
    });

    runner.run("unsupported signed-digit planes remain public zero", [&] {
        const auto aligned =
            prepare_normalized_aligned_transcript<SealBackend>(
                contexts.eval, ciphertexts, widths);
        LazyTernaryParameters parameters =
            evaluation_parameters(1);
        ++parameters.packing_radix.digit_count;
        parameters.packing_radix.validate();
        LazyTernaryChallengeMatrix zero_tests(
            1, std::vector<LazyTernaryChallenge>(
                   aligned.values.size()));
        const auto evaluation =
            evaluate_lazy_ternary<SealBackend>(
                contexts.eval, aligned, zero_tests, parameters);
        for (std::size_t output = 0;
             output < evaluation.logical_packed_outputs; ++output) {
            const auto &unsupported =
                evaluation.packed_digit_values
                    [output * parameters.packing_radix.digit_count +
                     parameters.packing_radix.digit_count - 1];
            CHECK(!unsupported.encrypted_contribution);
            CHECK(unsupported.public_offset.is_zero());
            CHECK(unsupported.public_c0_coordinates.empty());
        }
        CHECK(decrypt_and_recompose_signed_digit_packing<SealBackend>(
                  contexts.client, evaluation.packed_digit_values,
                  evaluation.logical_packed_outputs,
                  evaluation.parameters.packing_radix) ==
              expected_packed_plaintexts(aligned.layout, messages));
    });

    runner.run("aligned boundary rejects malformed ciphertext metadata", [&] {
        auto aligned = prepare_normalized_aligned_transcript<SealBackend>(
            contexts.eval, ciphertexts, widths);
        auto &malformed = aligned.values.front().ciphertext();
        malformed.raw.resize(*contexts.eval.context,
                             malformed.raw.parms_id(), 3);

        bool rejected = false;
        try {
            Transcript transcript("test/lazy-ternary/malformed-metadata");
            (void)run_unbound_lazy_ternary_diagnostic<SealBackend>(
                contexts.eval, aligned, transcript,
                evaluation_parameters(16));
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("observed pre-switch list certifies finalization", [&] {
        std::vector<SealBackend::Ciphertext> reserved = ciphertexts;
        for (auto &ciphertext : reserved) {
            // Selected Folded/Laned transport reaches packing with q0,q1,q2.
            SealBackend::mod_switch_to_next(contexts.eval, ciphertext);
        }
        auto draft = materialize_aligned_transcript<SealBackend>(
            contexts.eval, reserved,
            make_prefix_packing_layout(kSlots, widths));
        std::vector<SealBackend::Ciphertext> draft_ciphertexts;
        draft_ciphertexts.reserve(draft.values.size());
        for (const auto &value : draft.values) {
            CHECK(value.is_encrypted());
            draft_ciphertexts.push_back(value.ciphertext());
        }
        const auto assessment =
            assess_observed_honest_finalization_batch<SealBackend>(
                contexts.eval, contexts.client, draft_ciphertexts,
                HonestFinalizationPolicy{
                    .plaintext_modulus = kBaseFieldOrder,
                    .secret_hamming_weight_upper = kSlots,
                    .target_error_bound =
                        kSelectedPackingHonestErrorBound,
                    .final_rounding_reserve =
                        kPackingFinalRoundingErrorBound,
                });
        CHECK(assessment.ciphertext_count == draft.values.size());
        CHECK(assessment.all_ciphertexts_are_size_two);
        CHECK(assessment.all_correction_factors_are_one);
        CHECK(assessment.all_observed_finalizations_certified);
        CHECK(assessment.minimum_budget_slack_bits > 0);

        const auto aligned = finalize_aligned_transcript<SealBackend>(
            contexts.eval, std::move(draft));
        for (const auto &value : aligned.values) {
            CHECK(value.is_encrypted());
            CHECK(SealBackend::rns_limb_count(
                      contexts.eval, value.ciphertext()) == 1);
        }
    });

    runner.run("structured coset packing preserves fixed message cells", [&] {
        const PackingLayout layout =
            make_fixed_message_coset_packing_layout(
                kSlots, ciphertexts.size(), 2);
        const auto aligned =
            prepare_normalized_aligned_transcript<SealBackend>(
                contexts.eval, ciphertexts, layout);
        Transcript transcript("test/lazy-ternary/cosets");
        const auto evaluation =
            run_unbound_lazy_ternary_diagnostic<SealBackend>(
                contexts.eval, aligned, transcript,
                evaluation_parameters(8));

        const auto expected = expected_packed_plaintexts(layout, messages);
        CHECK(evaluation.logical_packed_outputs == expected.size());
        CHECK(decrypt_and_recompose_signed_digit_packing<SealBackend>(
                  contexts.client, evaluation.packed_digit_values,
                  evaluation.logical_packed_outputs,
                  evaluation.parameters.packing_radix) == expected);
    });

    runner.run("structured cosets use both BGV rows", [&] {
        constexpr std::size_t message_count =
            kSlots / fhe::kFixedMessageCellCount;
        std::vector<SlotVector> row_messages;
        std::vector<SealBackend::Ciphertext> row_ciphertexts;
        row_messages.reserve(message_count);
        row_ciphertexts.reserve(message_count);
        for (std::size_t index = 0; index < message_count; ++index) {
            row_messages.push_back(messages[index % messages.size()]);
            row_ciphertexts.push_back(
                ciphertexts[index % ciphertexts.size()]);
        }

        const PackingLayout layout =
            make_fixed_message_coset_packing_layout(
                kSlots, message_count, message_count);
        CHECK(layout.packed_ciphertext_count == 1);
        CHECK(layout.placements.back().destination_begin >= kSlots / 2);
        const auto aligned =
            prepare_normalized_aligned_transcript<SealBackend>(
                contexts.eval, row_ciphertexts, layout);
        Transcript transcript("test/lazy-ternary/both-rows");
        const auto evaluation =
            run_unbound_lazy_ternary_diagnostic<SealBackend>(
                contexts.eval, aligned, transcript,
                evaluation_parameters(4));

        CHECK(decrypt_and_recompose_signed_digit_packing<SealBackend>(
                  contexts.client, evaluation.packed_digit_values,
                  evaluation.logical_packed_outputs,
                  evaluation.parameters.packing_radix) ==
              expected_packed_plaintexts(layout, row_messages));
    });

    runner.run("missing outer relation permits a forged packed output", [&] {
        const auto aligned =
            prepare_normalized_aligned_transcript<SealBackend>(
                contexts.eval, ciphertexts, widths);
        Transcript transcript("test/lazy-ternary/forgery");
        auto evaluation = run_unbound_lazy_ternary_diagnostic<SealBackend>(
            contexts.eval, aligned, transcript, evaluation_parameters(16));

        auto forged = SealBackend::encrypt(
            contexts.client, SlotVector(kSlots, Fp(999)));
        SealBackend::mod_switch_to_lowest(contexts.eval, forged);
        SealBackend::normalize_for_coefficient_commitment(contexts.eval,
                                                           forged);
        evaluation.packed_digit_values.front().encrypted_contribution =
            std::move(forged);
        evaluation.packed_digit_values.front().public_offset =
            PublicPlaintext::from_scalar(Fp::zero());
        evaluation.packed_digit_values.front()
            .public_c0_coordinates.clear();

        const ObservedLazyTernaryDiagnostics diagnostics =
            assess_observed_lazy_ternary_diagnostic<SealBackend>(
                contexts.client, aligned, evaluation);
        CHECK(diagnostics.all_tests_within_configured_threshold);
        CHECK(SealBackend::decrypt(
                  contexts.client,
                  *evaluation.packed_digit_values.front()
                       .encrypted_contribution) ==
              SlotVector(kSlots, Fp(999)));
    });

    runner.run("canonical Folded proof crosses the real-SEAL decoder", [&] {
        PayloadBuilder builder(PayloadShape::wide(kSlots), 1);
        const std::size_t offset =
            builder.add_plaintext(SlotVector(kSlots, Fp(7)));
        builder.set_outputs({builder.add_plain(0, offset)});
        const PayloadCircuit payload = builder.finish();
        const LayeredCircuit circuit = compile(payload);
        const PlainTrace trace = synthesize_trace(
            payload, circuit,
            std::vector<SlotVector>{make_message(17)});
        const PublicSetup public_setup = make_direct_setup(payload, circuit);
        EncryptedTrace<SealBackend> encrypted =
            encrypt_compact_synthetic_trace<SealBackend>(
                contexts.eval, contexts.client, payload, circuit, trace,
                TraceEncryptionPlan::uniform(circuit, 3));

        auto packing_parameters = selected_lazy_ternary_parameters();
        packing_parameters.repetitions = 1;
        const FoldedSetup packing_setup =
            setup_folded_honest_candidate<SealBackend>(
                circuit, contexts.eval,
                std::vector<std::size_t>(circuit.layers.size(), 4U),
                packing_parameters,
                spartan::BaseFoldPcsParameters{
                    .log_rate = 1, .query_count = 1},
                spartan::Options{
                    .matrix_evaluation =
                        spartan::MatrixEvaluationMode::CommittedFactored});
        const auto evaluation = make_packed_evaluation_setup<SealBackend>(
            public_setup, contexts.eval);
        const SingleClaim output_claim = make_layer_claim(
            trace.layers.front(),
            std::vector<Fpk>(base_detail::layer_vars(circuit, 0),
                             Fpk::from_base(Fp(19))));

        constexpr std::string_view kDomain =
            "test/packed-proof-codec/seal/folded/v1";
        Transcript prover_transcript(kDomain);
        const LaminateFoldedProof<SealBackend> proof =
            reference::prove_folded<SealBackend>(
                payload, circuit, encrypted, evaluation, packing_setup,
                output_claim.point, prover_transcript);
        const std::vector<std::uint8_t> encoded =
            encode_canonical(proof);
        const FoldedVerifierSetup compact_setup =
            verifier_setup(packing_setup);
        const std::size_t byte_limit = encoded.size();
        const PackedProofDecodeLimits limits{
            .max_proof_bytes = byte_limit,
            .max_ciphertexts = byte_limit,
            .max_ciphertext_bytes = byte_limit,
            .max_total_ciphertext_bytes = byte_limit,
            .max_collection_elements = byte_limit,
            .max_total_field_elements = byte_limit,
            .max_total_digests = byte_limit,
        };
        const LaminateFoldedProof<SealBackend> decoded =
            decode_canonical_folded_proof<SealBackend>(
                contexts.eval, encoded, circuit, public_setup,
                compact_setup, limits);
        CHECK(encode_canonical(decoded) == encoded);

        const SealBackend::PublicVerifierContext projected_verifier =
            SealBackend::make_public_verifier_context(contexts.client);
        const std::vector<std::uint8_t> verifier_bundle =
            SealBackend::serialize_public_verifier_context_bundle(
                projected_verifier);
        SealBackend::PublicVerifierContext restored_verifier =
            SealBackend::deserialize_public_verifier_context_bundle(
                verifier_bundle,
                SealBackend::storage_context_id(contexts.client),
                SealPublicVerifierContextDecodeLimits{
                    .max_bundle_bytes = verifier_bundle.size(),
                    .max_poly_modulus_degree = kSlots,
                    .max_rns_limbs = 4,
                });
        CHECK(SealBackend::serialize_public_verifier_context_bundle(
                  restored_verifier) == verifier_bundle);
        const LaminateFoldedProof<SealBackend> public_decoded =
            decode_canonical_folded_proof<SealBackend>(
                restored_verifier, encoded, circuit, public_setup,
                compact_setup, limits);
        CHECK(encode_canonical(public_decoded) == encoded);

        const ClientSetup<SealBackend> client =
            make_client_setup<SealBackend>(public_setup, contexts.client);
        const PackedClientSetup<SealBackend> packed_client =
            make_packed_client_setup_from_verifier_context<SealBackend>(
                client, restored_verifier);
        Transcript verifier_transcript(kDomain);
        CHECK(verify_folded<SealBackend>(
            payload, circuit, trace.layers.back(),
            packed_client.verifier_context(), compact_setup,
            packed_client.client_setup(), trace.provenance,
            encrypted.trace_id, output_claim, public_decoded,
            verifier_transcript));

        auto trailing = encoded;
        trailing.push_back(0U);
        bool rejected = false;
        try {
            (void)decode_canonical_folded_proof<SealBackend>(
                packed_client.verifier_context(), trailing, circuit,
                public_setup,
                compact_setup,
                PackedProofDecodeLimits{
                    .max_proof_bytes = trailing.size(),
                    .max_ciphertexts = trailing.size(),
                    .max_ciphertext_bytes = trailing.size(),
                    .max_total_ciphertext_bytes = trailing.size(),
                    .max_collection_elements = trailing.size(),
                    .max_total_field_elements = trailing.size(),
                    .max_total_digests = trailing.size(),
                });
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("aligned-list digest rejects post-commitment mutation", [&] {
        auto aligned = prepare_normalized_aligned_transcript<SealBackend>(
            contexts.eval, ciphertexts, widths);
        aligned.values.front() = aligned.values.back();
        bool rejected = false;
        try {
            Transcript transcript("test/lazy-ternary/mutation");
            (void)run_unbound_lazy_ternary_diagnostic<SealBackend>(
                contexts.eval, aligned, transcript,
                evaluation_parameters(4));
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    return runner.summary();
}
