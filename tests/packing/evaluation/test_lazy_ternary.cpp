/// @file test_lazy_ternary.cpp
/// @brief Exact mixed public/encrypted transcript-packing checks.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/packing/analysis/unbound_lazy_ternary_diagnostic.hpp"
#include "laminate/packing/evaluation/lazy_ternary.hpp"
#include "laminate/protocol/detail/packing/aligned_commitments.hpp"
#include "laminate/protocol/detail/packing/transcript_reader.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::packing;

namespace {

constexpr std::size_t kSlots = 8;

MockBackend::Contexts make_contexts() {
    return MockBackend::create(MockParameters{.slot_count = kSlots});
}

LazyTernaryParameters parameters(std::size_t repetitions) {
    return LazyTernaryParameters{
        .repetitions = repetitions,
        .honest_error_bound = kSelectedPackingHonestErrorBound,
        .packing_radix =
            make_minimal_balanced_radix(kBaseFieldOrder, 17),
    };
}

SlotVector constant_slots(std::uint64_t value) {
    return SlotVector(kSlots, Fp(value));
}

std::vector<SlotVector> expected_packed_plaintexts(
    const PackingLayout &layout,
    std::span<const SlotVector> messages) {
    std::vector<SlotVector> result(
        layout.packed_ciphertext_count,
        SlotVector(layout.slot_count, Fp::zero()));
    for (const PackingPlacement &placement : layout.placements) {
        for (std::size_t offset = 0; offset < placement.length; ++offset) {
            result[placement.packed_index]
                  [packing_destination_slot(layout, placement, offset)] =
                messages[placement.message_index]
                        [packing_source_slot(layout, placement, offset)];
        }
    }
    return result;
}

std::uint64_t add_mod_q(std::uint64_t left, std::uint64_t right) {
    return left >= kOuterFieldOrder - right
               ? left - (kOuterFieldOrder - right)
               : left + right;
}

} // namespace

int main() {
    test::Runner runner("test_lazy_ternary");

    runner.run("duplicate ciphertexts keep integer multiplicities in native q", [&] {
        auto contexts = make_contexts();
        auto source = MockBackend::encrypt(contexts.client, constant_slots(7));
        MockBackend::normalize_for_coefficient_commitment(contexts.eval, source);
        constexpr std::size_t kCopies = kBaseFieldOrder;
        NormalizedAlignedTranscript<MockBackend> aligned;
        aligned.layout = make_prefix_packing_layout(
            kSlots, std::vector<std::size_t>(kCopies, 1));
        aligned.values.assign(
            kCopies, FheValue<MockBackend>::from_ciphertext(source));
        aligned.public_coordinates.resize(kCopies);
        aligned.public_sources.assign(kCopies, false);
        lazy_ternary_detail::validate_aligned_transcript<MockBackend>(
            contexts.eval, aligned);
        const auto original =
            MockBackend::coefficient_commitment_ntt_coordinate_view(source);
        std::vector<LazyTernaryChallenge> row(kCopies);

        for (const std::int64_t count :
             {0, 1, -1, 2, -2, 517, -517, 32768, -32768, 32769,
              -32769, 65536, -65536, 65537, -65537}) {
            const std::uint64_t magnitude = count < 0 ? -count : count;
            std::fill(row.begin(), row.end(), LazyTernaryChallenge{});
            std::fill_n(row.begin(), magnitude,
                        LazyTernaryChallenge{count > 0, count < 0});
            MockBackend::reset_counts(contexts.eval);
            const auto result = lazy_ternary_detail::form_test_value<MockBackend>(
                contexts.eval, aligned, row);
            CHECK(result.encrypted_contribution.has_value() == (count != 0));
            const auto actual = normalized_mixed_value_coordinates<MockBackend>(
                contexts.eval, result);
            CHECK(actual.size() == original.size());
            const std::uint64_t multiplier =
                count < 0 ? kOuterFieldOrder - magnitude : magnitude;
            for (std::size_t i = 0; i < actual.size(); ++i) {
                const auto expected = static_cast<std::uint64_t>(
                    (static_cast<unsigned __int128>(original[i]) * multiplier) %
                    kOuterFieldOrder);
                CHECK(actual[i] == expected);
            }
            const auto operations = MockBackend::counts(contexts.eval);
            if (magnitude <= (kBaseFieldOrder - 1) / 2) {
                CHECK(operations.mul_plain_scalar == (magnitude > 1 ? 1 : 0));
                CHECK(operations.negate == (count == -1 ? 1 : 0));
                CHECK(operations.add == 0);
            } else if (magnitude == kBaseFieldOrder) {
                CHECK(operations.mul_plain_scalar == 1);
                CHECK(operations.add == 2);
            }
        }

        std::fill(row.begin(), row.end(), LazyTernaryChallenge{});
        std::fill_n(row.begin(), 32768, LazyTernaryChallenge{true, false});
        std::fill_n(row.begin() + 32768, 32768,
                    LazyTernaryChallenge{false, true});
        MockBackend::reset_counts(contexts.eval);
        const auto cancelled = lazy_ternary_detail::form_test_value<MockBackend>(
            contexts.eval, aligned, row);
        CHECK(!cancelled.encrypted_contribution);
        CHECK(MockBackend::counts(contexts.eval).mul_plain_scalar == 0);
        CHECK(MockBackend::counts(contexts.eval).negate == 0);
        CHECK(MockBackend::counts(contexts.eval).add == 0);
    });

    runner.run("all-public packing creates no ciphertext", [&] {
        auto contexts = make_contexts();
        const std::vector<SlotVector> messages{
            {Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19), Fp(23)},
            {Fp(29), Fp(31), Fp(37), Fp(41), Fp(43), Fp(47), Fp(53), Fp(59)},
        };
        const std::vector<FheValue<MockBackend>> values{
            FheValue<MockBackend>::public_slots(messages[0]),
            FheValue<MockBackend>::public_slots(messages[1]),
        };
        const std::vector<std::size_t> widths{3, 5};
        const PackingLayout layout =
            make_prefix_packing_layout(kSlots, widths);

        MockBackend::reset_counts(contexts.eval);
        const auto aligned =
            prepare_normalized_aligned_transcript<MockBackend>(
                contexts.eval, values, layout);
        Transcript transcript("test/lazy-ternary/public");
        const auto evaluation =
            run_unbound_lazy_ternary_diagnostic<MockBackend>(
                contexts.eval, aligned, transcript, parameters(4));

        for (const auto &value : aligned.values) {
            CHECK(value.is_public());
        }
        for (const auto &value : evaluation.test_values) {
            CHECK(!value.encrypted_contribution);
        }
        for (const auto &value : evaluation.packed_digit_values) {
            CHECK(!value.encrypted_contribution);
        }
        CHECK(MockBackend::counts(contexts.eval).encrypt == 0);
        CHECK(MockBackend::counts(contexts.eval).add_plain == 0);
        CHECK(MockBackend::counts(contexts.eval).mul_plain_scalar == 0);
        CHECK(MockBackend::counts(contexts.eval).mul_plain_vector == 0);
        CHECK(decrypt_and_recompose_signed_digit_packing<MockBackend>(
                  contexts.client, evaluation.packed_digit_values,
                  evaluation.logical_packed_outputs,
                  evaluation.parameters.packing_radix) ==
              expected_packed_plaintexts(layout, messages));
        CHECK(MockBackend::counts(contexts.eval).decrypt == 0);
    });

    runner.run("public t-wrap keeps its exact native-q sidecar", [&] {
        auto contexts = make_contexts();
        const std::vector<FheValue<MockBackend>> values{
            FheValue<MockBackend>::public_scalar(Fp(40'000)),
            FheValue<MockBackend>::public_scalar(Fp(40'000)),
        };
        const std::vector<std::size_t> widths{kSlots, kSlots};
        const auto aligned =
            prepare_normalized_aligned_transcript<MockBackend>(
                contexts.eval, values,
                make_prefix_packing_layout(kSlots, widths));
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
        const std::size_t first_index =
            static_cast<std::size_t>(first - aligned.layout.placements.begin());
        const std::size_t second_index = static_cast<std::size_t>(
            second - aligned.layout.placements.begin());
        challenges[0][first_index].plus_bit = true;
        challenges[0][second_index].plus_bit = true;

        const auto evaluation =
            evaluate_lazy_ternary<MockBackend>(
                contexts.eval, aligned, challenges, parameters(1));
        const auto &test = evaluation.test_values.front();
        CHECK(!test.encrypted_contribution);
        CHECK(test.public_offset ==
              PublicPlaintext::from_scalar(Fp(80'000)));
        CHECK(test.public_c0_coordinates.size() == kSlots);

        const auto first_coordinates =
            normalized_aligned_coordinates(aligned, first_index);
        const auto second_coordinates =
            normalized_aligned_coordinates(aligned, second_index);
        for (std::size_t coordinate = 0; coordinate < kSlots;
             ++coordinate) {
            CHECK(test.public_c0_coordinates[coordinate] ==
                  add_mod_q(first_coordinates[coordinate],
                            second_coordinates[coordinate]));
        }
        const auto canonical_wrapped =
            normalized_public_value_coordinates<MockBackend>(
                contexts.eval, test.public_offset);
        CHECK(test.public_c0_coordinates[0] != canonical_wrapped[0]);
        const auto composed =
            normalized_mixed_value_coordinates<MockBackend>(
                contexts.eval, test);
        CHECK(std::equal(test.public_c0_coordinates.begin(),
                         test.public_c0_coordinates.end(),
                         composed.begin()));
    });

    runner.run("mixed test keeps public arithmetic out of ciphertext", [&] {
        auto contexts = make_contexts();
        const SlotVector encrypted_plaintext = constant_slots(40'000);
        const auto ciphertext =
            MockBackend::encrypt(contexts.client, encrypted_plaintext);
        const std::vector<FheValue<MockBackend>> values{
            FheValue<MockBackend>::from_ciphertext(ciphertext),
            FheValue<MockBackend>::public_scalar(Fp(40'000)),
        };
        const std::vector<std::size_t> widths{kSlots, kSlots};
        const auto aligned =
            prepare_normalized_aligned_transcript<MockBackend>(
                contexts.eval, values,
                make_prefix_packing_layout(kSlots, widths));
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

        MockBackend::reset_counts(contexts.eval);
        const auto evaluation =
            evaluate_lazy_ternary<MockBackend>(
                contexts.eval, aligned, challenges, parameters(1));
        const auto &test = evaluation.test_values.front();
        CHECK(test.encrypted_contribution);
        CHECK(test.public_offset ==
              PublicPlaintext::from_scalar(Fp(40'000)));
        CHECK(test.public_c0_coordinates.size() == kSlots);
        CHECK(MockBackend::serialize(*test.encrypted_contribution) ==
              MockBackend::serialize(
                  aligned.values[encrypted_index].ciphertext()));
        CHECK(MockBackend::counts(contexts.eval).encrypt == 0);
        CHECK(MockBackend::counts(contexts.eval).add_plain == 0);

        SlotVector recovered =
            MockBackend::decrypt(contexts.client,
                                 *test.encrypted_contribution);
        const SlotVector public_slots =
            test.public_offset.materialize(kSlots);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            recovered[slot] += public_slots[slot];
        }
        CHECK(recovered == constant_slots(80'000));

        const auto encrypted_coordinates =
            MockBackend::coefficient_commitment_ntt_coordinate_view(
                *test.encrypted_contribution);
        const auto composed =
            normalized_mixed_value_coordinates<MockBackend>(
                contexts.eval, test);
        CHECK(composed[0] ==
              add_mod_q(encrypted_coordinates[0],
                        test.public_c0_coordinates[0]));
        CHECK(composed[0] != recovered[0].value());
    });

    runner.run("public mutation changes the aligned binding", [&] {
        auto contexts = make_contexts();
        const std::vector<std::size_t> widths{kSlots};
        const PackingLayout layout =
            make_prefix_packing_layout(kSlots, widths);
        const std::vector<FheValue<MockBackend>> first{
            FheValue<MockBackend>::public_scalar(Fp(7)),
        };
        const std::vector<FheValue<MockBackend>> second{
            FheValue<MockBackend>::public_scalar(Fp(8)),
        };
        const auto first_aligned =
            prepare_normalized_aligned_transcript<MockBackend>(
                contexts.eval, first, layout);
        const auto second_aligned =
            prepare_normalized_aligned_transcript<MockBackend>(
                contexts.eval, second, layout);
        CHECK(first_aligned.ciphertext_list_digest !=
              second_aligned.ciphertext_list_digest);

        Transcript first_transcript("test/lazy-ternary/public-binding");
        Transcript second_transcript("test/lazy-ternary/public-binding");
        const auto first_evaluation =
            run_unbound_lazy_ternary_diagnostic<MockBackend>(
                contexts.eval, first_aligned, first_transcript,
                parameters(8));
        const auto second_evaluation =
            run_unbound_lazy_ternary_diagnostic<MockBackend>(
                contexts.eval, second_aligned, second_transcript,
                parameters(8));
        CHECK(first_evaluation.public_challenges !=
              second_evaluation.public_challenges);
    });

    runner.run("standalone public zero uses an implicit stable binding", [&] {
        auto contexts = make_contexts();
        const std::vector<FheValue<MockBackend>> values{
            FheValue<MockBackend>::public_zero(),
        };
        const PackingLayout layout = make_prefix_packing_layout(
            kSlots, std::vector<std::size_t>{kSlots});
        const auto implicit =
            prepare_normalized_aligned_transcript<MockBackend>(
                contexts.eval, values, layout);
        CHECK(implicit.values.front().is_public_zero());
        CHECK(implicit.public_sources.front());
        CHECK(implicit.public_coordinates.front().empty());
        CHECK(implicit.ciphertext_list_digest);

        // Materialized zero coordinates and implicit zeros must produce
        // the same transcript binding and Fiat--Shamir challenges.
        auto explicit_zeros = implicit;
        explicit_zeros.public_coordinates.front().assign(
            2 * kSlots, 0);
        Transcript implicit_transcript(
            "test/lazy-ternary/implicit-zero-binding");
        Transcript explicit_transcript(
            "test/lazy-ternary/implicit-zero-binding");
        const auto implicit_evaluation =
            run_unbound_lazy_ternary_diagnostic<MockBackend>(
                contexts.eval, implicit, implicit_transcript,
                parameters(4));
        const auto explicit_evaluation =
            run_unbound_lazy_ternary_diagnostic<MockBackend>(
                contexts.eval, explicit_zeros, explicit_transcript,
                parameters(4));
        CHECK(implicit_evaluation.public_challenges ==
              explicit_evaluation.public_challenges);
    });

    runner.run("distinct encrypted terms cancel to canonical null", [&] {
        auto contexts = make_contexts();
        auto source = MockBackend::encrypt(
            contexts.client, constant_slots(19));
        MockBackend::mod_switch_to_lowest(contexts.eval, source);
        MockBackend::normalize_for_coefficient_commitment(
            contexts.eval, source);
        auto negative = MockBackend::negate(contexts.eval, source);
        CHECK(MockBackend::serialize(source) !=
              MockBackend::serialize(negative));

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
        std::vector<FheValue<MockBackend>> aligned_values(
            layout.placements.size(),
            FheValue<MockBackend>::public_zero());
        aligned_values.front() =
            FheValue<MockBackend>::from_ciphertext(source);
        aligned_values[matching_index] =
            FheValue<MockBackend>::from_ciphertext(negative);
        const NormalizedAlignedTranscript<MockBackend> aligned{
            .layout = layout,
            .values = std::move(aligned_values),
            .public_coordinates =
                std::vector<std::vector<std::uint64_t>>(
                    layout.placements.size()),
            .public_sources =
                std::vector<bool>(layout.placements.size(), false),
            .ciphertext_list_digest = std::nullopt,
        };
        CHECK(MockBackend::serialize(aligned.values.front().ciphertext()) !=
              MockBackend::serialize(
                  aligned.values[matching_index].ciphertext()));
        LazyTernaryChallengeMatrix challenges(
            1, std::vector<LazyTernaryChallenge>(aligned.values.size()));
        challenges.front()[0].plus_bit = true;
        challenges.front()[matching_index].plus_bit = true;

        MockBackend::reset_counts(contexts.eval);
        const auto evaluation =
            evaluate_lazy_ternary<MockBackend>(
                contexts.eval, aligned, challenges, parameters(1));
        CHECK(evaluation.test_values.size() == 1);
        CHECK(!evaluation.test_values.front().encrypted_contribution);
        CHECK(evaluation.test_values.front().public_offset.is_zero());
        CHECK(evaluation.test_values.front()
                  .public_c0_coordinates.empty());
        CHECK(MockBackend::counts(contexts.eval).encrypt == 0);
    });

    runner.run("verifier public zeros skip packing work", [&] {
        auto contexts = make_contexts();
        const auto verifier =
            MockBackend::make_public_verifier_context(contexts.client);
        const std::vector<std::optional<PublicPlaintext>> public_projection{
            PublicPlaintext::from_scalar(Fp::zero()),
            std::nullopt,
        };
        const std::vector<std::size_t> widths{3, 5};
        MockBackend::reset_counts(contexts.eval);
        const auto aligned =
            prepare_verifier_aligned_projection<MockBackend>(
                verifier, public_projection,
                make_prefix_packing_layout(kSlots, widths));
        CHECK(!aligned.ciphertext_list_digest);
        for (std::size_t index = 0; index < aligned.values.size(); ++index) {
            CHECK(aligned.values[index].is_public_zero());
        }
        CHECK(aligned.public_sources[0]);
        CHECK(aligned.public_coordinates[0].empty());
        CHECK(!aligned.public_sources[1]);
        CHECK(aligned.public_coordinates[1].empty());
        LazyTernaryChallengeMatrix challenges(
            1, std::vector<LazyTernaryChallenge>(aligned.values.size()));
        for (auto &challenge : challenges.front()) {
            challenge.plus_bit = true;
        }
        const auto evaluation =
            evaluate_verifier_lazy_ternary<MockBackend>(
                verifier, aligned, challenges, parameters(1));
        CHECK(!evaluation.test_values.front().encrypted_contribution);
        CHECK(evaluation.test_values.front().public_offset.is_zero());
        CHECK(evaluation.test_values.front()
                  .public_c0_coordinates.empty());
        for (const auto &value : evaluation.packed_digit_values) {
            CHECK(!value.encrypted_contribution);
            CHECK(value.public_offset.is_zero());
            CHECK(value.public_c0_coordinates.empty());
        }
        CHECK(MockBackend::counts(contexts.eval).encrypt == 0);
        CHECK(MockBackend::counts(contexts.eval).rotate == 0);
        CHECK(MockBackend::counts(contexts.eval).mul_plain_scalar == 0);
        CHECK(MockBackend::counts(contexts.eval).mul_plain_vector == 0);

        Transcript unbound_transcript(
            "test/lazy-ternary/verifier-projection");
        bool rejected_unbound_use = false;
        try {
            (void)run_unbound_lazy_ternary_diagnostic<MockBackend>(
                contexts.eval, aligned, unbound_transcript,
                parameters(1));
        } catch (const std::invalid_argument &) {
            rejected_unbound_use = true;
        }
        CHECK(rejected_unbound_use);
    });

    runner.run("key-free verifier projection matches evaluation context",
               [&] {
        auto contexts = make_contexts();
        const auto verifier =
            MockBackend::make_public_verifier_context(contexts.client);
        const std::vector<std::optional<PublicPlaintext>> public_values{
            PublicPlaintext::from_scalar(Fp(40'000)),
            PublicPlaintext::from_slots(
                {Fp(3), Fp(5), Fp(7), Fp(11),
                 Fp(13), Fp(17), Fp(19), Fp(23)}),
            std::nullopt,
        };
        const PackingLayout layout = make_prefix_packing_layout(
            kSlots, std::vector<std::size_t>{3, 5, 4});
        const auto evaluation_projection =
            prepare_verifier_aligned_projection<MockBackend>(
                contexts.eval, public_values, layout);
        const auto restricted_projection =
            prepare_verifier_aligned_projection<MockBackend>(
                verifier, public_values, layout);
        CHECK(evaluation_projection.values.size() ==
              restricted_projection.values.size());
        CHECK(evaluation_projection.public_sources ==
              restricted_projection.public_sources);
        CHECK(evaluation_projection.public_coordinates ==
              restricted_projection.public_coordinates);

        LazyTernaryChallengeMatrix challenges(
            2, std::vector<LazyTernaryChallenge>(
                   layout.placements.size()));
        for (std::size_t index = 0; index < layout.placements.size();
             ++index) {
            challenges[0][index].plus_bit = index % 2U == 0U;
            challenges[0][index].minus_bit = index % 2U != 0U;
            challenges[1][index].plus_bit = index % 3U == 0U;
            challenges[1][index].minus_bit = index % 3U == 1U;
        }
        const auto evaluation =
            evaluate_lazy_ternary<MockBackend>(
                contexts.eval, evaluation_projection, challenges,
                parameters(2));
        const auto restricted =
            evaluate_verifier_lazy_ternary<MockBackend>(
                verifier, restricted_projection, challenges,
                parameters(2));
        const auto compare = [](const auto &left, const auto &right) {
            CHECK(!left.encrypted_contribution);
            CHECK(!right.encrypted_contribution);
            CHECK(left.public_offset == right.public_offset);
            CHECK(left.public_c0_coordinates ==
                  right.public_c0_coordinates);
            CHECK(left.public_term_count == right.public_term_count);
        };
        CHECK(evaluation.test_values.size() == restricted.test_values.size());
        CHECK(evaluation.packed_digit_values.size() ==
              restricted.packed_digit_values.size());
        for (std::size_t index = 0; index < evaluation.test_values.size();
             ++index) {
            compare(evaluation.test_values[index],
                    restricted.test_values[index]);
        }
        for (std::size_t index = 0;
             index < evaluation.packed_digit_values.size(); ++index) {
            compare(evaluation.packed_digit_values[index],
                    restricted.packed_digit_values[index]);
        }
    });

    runner.run("composed collector does not retain public-zero coordinates",
               [&] {
        auto contexts = make_contexts();
        const PackingLayout layout = make_prefix_packing_layout(
            kSlots, std::vector<std::size_t>{4, 4, 4});
        protocol::detail::AlignedCommitmentCollector<MockBackend> collector(
            contexts.eval, layout);
        const auto zero_commitment = collector.commit(
            FheValue<MockBackend>::public_zero());
        const auto nonzero_commitment = collector.commit(
            FheValue<MockBackend>::public_scalar(Fp(7)));
        const auto repeated_zero_commitment = collector.commit(
            FheValue<MockBackend>::public_zero());
        auto collected = std::move(collector).finish();

        CHECK(collected.aligned().values[0].is_public_zero());
        CHECK(collected.aligned().public_sources[0]);
        CHECK(collected.aligned().public_coordinates[0].empty());
        CHECK(collected.aligned().values[1].is_public());
        CHECK(!collected.aligned().values[1].is_public_zero());
        CHECK(collected.aligned().public_sources[1]);
        CHECK(collected.aligned().public_coordinates[1].size() ==
              2 * kSlots);
        CHECK(collected.aligned().values[2].is_public_zero());
        CHECK(collected.aligned().public_sources[2]);
        CHECK(collected.aligned().public_coordinates[2].empty());
        CHECK(collected.commitments()[0] == zero_commitment);
        CHECK(collected.commitments()[1] == nonzero_commitment);
        CHECK(collected.commitments()[2] == repeated_zero_commitment);
        CHECK(repeated_zero_commitment == zero_commitment);

        const std::vector<std::uint64_t> formal_zero(2 * kSlots, 0);
        CHECK(zero_commitment ==
              gkr::hash_commit_normalized_ciphertext_coordinates(
                  kSlots, formal_zero));

        LazyTernaryChallengeMatrix challenges(
            1, std::vector<LazyTernaryChallenge>(
                   collected.aligned().values.size()));
        for (auto &challenge : challenges.front()) {
            challenge.plus_bit = true;
        }
        const auto evaluation =
            evaluate_lazy_ternary<MockBackend>(
                contexts.eval, collected.aligned(), challenges,
                parameters(1));
        CHECK(evaluation.test_values.size() == 1);
    });

    runner.run("packed reader enforces canonical public messages", [&] {
        SlotVector logical(fhe::kFixedMessageCellCount);
        for (std::size_t cell = 0; cell < logical.size(); ++cell) {
            logical[cell] = Fp(7 * cell + 3);
        }
        SlotVector public_slots(2 * fhe::kFixedMessageCellCount,
                                Fp::zero());
        for (std::size_t cell = 0; cell < logical.size(); ++cell) {
            public_slots[fhe::fixed_message_cell_slot(
                public_slots.size(), cell)] = logical[cell];
        }
        const gkr::CommittedPackedMessage canonical =
            gkr::CommittedPackedMessage::public_message(
                PublicPlaintext::from_slots(public_slots));
        const std::vector<SlotVector> recovered{logical};
        protocol::detail::PackedTranscriptReader reader(recovered);
        CHECK(reader.read(canonical, 2) ==
              protocol::detail::decode_fixed_message(logical, 2));
        CHECK(reader.all_messages_consumed());

        public_slots[fhe::fixed_message_cell_slot(public_slots.size(), 0)] +=
            Fp::one();
        const gkr::CommittedPackedMessage tampered =
            gkr::CommittedPackedMessage::public_message(
                PublicPlaintext::from_slots(std::move(public_slots)));
        protocol::detail::PackedTranscriptReader tampered_reader(recovered);
        bool rejected = false;
        try {
            (void)tampered_reader.read(tampered, 2);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
        CHECK(!tampered_reader.all_messages_consumed());
    });

    return runner.summary();
}
