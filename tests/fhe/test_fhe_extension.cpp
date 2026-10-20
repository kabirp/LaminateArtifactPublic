/// @file test_fhe_extension.cpp
/// @brief Backend-generic extension promotion and partial-evaluation tests.

#include "test_helpers.hpp"

#include "laminate/fhe/extension.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/poly/eq.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;

namespace {

Fpk value(std::uint64_t seed) {
    Fpk::Coefficients coefficients{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        coefficients[coefficient] = Fp(seed + 11 * coefficient);
    }
    return Fpk(coefficients);
}

template <FheBackend Backend>
typename Backend::ExtCiphertext encrypt_private_test_extension(
    const typename Backend::ClientContext &client,
    std::span<const Fpk> values) {
    const PlainExtension plaintext = encode_extension_plain(values);
    typename Backend::ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        result[coefficient] =
            Backend::encrypt(client, plaintext[coefficient]);
    }
    return result;
}

} // namespace

int main() {
    test::Runner runner("test_fhe_extension");

    runner.run("slot-varying promotion decrypts coefficientwise", [] {
        auto contexts = MockBackend::create(MockParameters{.slot_count = 8});
        SlotVector base;
        std::vector<Fpk> weights;
        for (std::size_t slot = 0; slot < 8; ++slot) {
            base.emplace_back(slot + 2);
            weights.push_back(value(19 + slot));
        }
        const auto ciphertext = MockBackend::encrypt(contexts.client, base);
        const auto promoted =
            promote_scale<MockBackend>(contexts.eval, ciphertext, weights);
        const std::vector<Fpk> decrypted =
            decrypt_extension<MockBackend>(contexts.client, promoted);
        for (std::size_t slot = 0; slot < 8; ++slot) {
            CHECK(decrypted[slot] == weights[slot] * base[slot]);
        }
    });

    runner.run("optional accumulation moves once and counts later additions",
               [] {
        constexpr std::size_t kSlots = 8;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        std::vector<Fpk> left_values;
        std::vector<Fpk> right_values;
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            left_values.push_back(value(31 + slot));
            right_values.push_back(value(79 + slot));
        }
        auto left = encrypt_private_test_extension<MockBackend>(
            contexts.client, left_values);
        auto right = encrypt_private_test_extension<MockBackend>(
            contexts.client, right_values);
        std::optional<MockBackend::ExtCiphertext> accumulator;

        MockBackend::reset_counts(contexts.eval);
        accumulate_extension<MockBackend>(
            contexts.eval, accumulator, std::move(left));
        CHECK(accumulator.has_value());
        CHECK(MockBackend::counts(contexts.eval).logical_ext_add == 0);
        CHECK(MockBackend::counts(contexts.eval).add == 0);

        accumulate_extension<MockBackend>(
            contexts.eval, accumulator, std::move(right));
        const OperationCounts counts = MockBackend::counts(contexts.eval);
        CHECK(counts.logical_ext_add == 1);
        CHECK(counts.add == kExtensionDegree);
        const std::vector<Fpk> actual = decrypt_extension<MockBackend>(
            contexts.client, *accumulator);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            CHECK(actual[slot] == left_values[slot] + right_values[slot]);
        }
    });

    runner.run("first typed extension term moves into accumulator", [] {
        constexpr std::size_t kSlots = 8;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        std::vector<Fpk> plaintext;
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            plaintext.push_back(value(83 + slot));
        }
        ExtensionValue<MockBackend> term(
            encrypt_private_test_extension<MockBackend>(
                contexts.client, plaintext));
        std::array<const Fp *, kExtensionDegree> term_storage{};
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            term_storage[coefficient] =
                term[coefficient].ciphertext().slots.data();
        }
        ExtensionValue<MockBackend> accumulator;
        MockBackend::reset_counts(contexts.eval);

        extension_add_assign<MockBackend>(
            contexts.eval, accumulator, std::move(term));

        CHECK(read_extension_value<MockBackend>(
                  contexts.client, accumulator) == plaintext);
        CHECK(MockBackend::counts(contexts.eval).logical_ext_add == 0);
        CHECK(MockBackend::counts(contexts.eval).add == 0);
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            CHECK(accumulator[coefficient].ciphertext().slots.data() ==
                  term_storage[coefficient]);
        }
    });

    runner.run("typed extension arithmetic records one logical operation",
               [] {
        constexpr std::size_t kSlots = 8;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        std::vector<Fpk> left_values;
        std::vector<Fpk> right_values;
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            left_values.push_back(value(101 + slot));
            right_values.push_back(value(401 + slot));
        }
        const ExtensionValue<MockBackend> left(
            encrypt_private_test_extension<MockBackend>(
                contexts.client, left_values));
        const ExtensionValue<MockBackend> right(
            encrypt_private_test_extension<MockBackend>(
                contexts.client, right_values));

        MockBackend::reset_counts(contexts.eval);
        const auto sum = extension_add<MockBackend>(
            contexts.eval, left, right);
        CHECK(sum.ciphertext_count() == kExtensionDegree);
        const OperationCounts add_counts =
            MockBackend::counts(contexts.eval);
        CHECK(add_counts.logical_ext_add == 1);
        CHECK(add_counts.add == kExtensionDegree);

        MockBackend::reset_counts(contexts.eval);
        const auto difference = extension_sub<MockBackend>(
            contexts.eval, left, right);
        CHECK(difference.ciphertext_count() == kExtensionDegree);
        const OperationCounts sub_counts =
            MockBackend::counts(contexts.eval);
        CHECK(sub_counts.logical_ext_sub == 1);
        CHECK(sub_counts.sub == kExtensionDegree);
    });

    runner.run("known-zero typed extension work stays on the host", [] {
        constexpr std::size_t kSlots = 16;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        std::vector<Fpk> plaintext;
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            plaintext.push_back(value(701 + slot));
        }
        const ExtensionValue<MockBackend> encrypted(
            encrypt_private_test_extension<MockBackend>(
                contexts.client, plaintext));

        MockBackend::reset_counts(contexts.eval);
        const auto scalar_zero = scale_extension_value<MockBackend>(
            contexts.eval, encrypted, Fpk::zero());
        CHECK(scalar_zero.is_public_zero());
        OperationCounts counts = MockBackend::counts(contexts.eval);
        CHECK(counts.logical_ext_mul_plain == 0);
        CHECK(counts.mul_plain_scalar_api_calls == 0);
        CHECK(counts.mul_plain_vector_api_calls == 0);

        MockBackend::reset_counts(contexts.eval);
        const auto vector_zero = scale_extension_value<MockBackend>(
            contexts.eval, encrypted,
            std::vector<Fpk>(kSlots, Fpk::zero()));
        CHECK(vector_zero.is_public_zero());
        counts = MockBackend::counts(contexts.eval);
        CHECK(counts.logical_ext_mul_plain == 0);
        CHECK(counts.mul_plain_scalar_api_calls == 0);
        CHECK(counts.mul_plain_vector_api_calls == 0);
        CHECK(counts.mul_plain_vector_api_elements == 0);

        const ExtensionValue<MockBackend> public_zero;
        const std::array<Fpk, 2> prefix{value(17), value(29)};
        MockBackend::reset_counts(contexts.eval);
        const auto bound = partial_evaluate_slot_index_point<MockBackend>(
            contexts.eval, public_zero, prefix);
        CHECK(bound.is_public_zero());
        counts = MockBackend::counts(contexts.eval);
        CHECK(counts.rotate == 0);
        CHECK(counts.logical_ext_add == 0);
        CHECK(counts.logical_ext_mul_plain == 0);
        CHECK(counts.mul_plain_vector_api_calls == 0);
        CHECK(counts.mul_plain_vector_api_elements == 0);

        const MockBackend::ExtCiphertext raw_public_zero{};
        MockBackend::reset_counts(contexts.eval);
        const auto raw_bound = partial_evaluate_slot_index_point<MockBackend>(
            contexts.eval, raw_public_zero, prefix);
        CHECK(std::none_of(raw_bound.begin(), raw_bound.end(),
                           [](const auto &coefficient) {
                               return coefficient.has_value();
                           }));
        counts = MockBackend::counts(contexts.eval);
        CHECK(counts.rotate == 0);
        CHECK(counts.logical_ext_add == 0);
        CHECK(counts.logical_ext_mul_plain == 0);
        CHECK(counts.mul_plain_vector_api_calls == 0);
        CHECK(counts.mul_plain_vector_api_elements == 0);
    });

    runner.run("empty sparse accumulation finishes as symbolic zero", [] {
        constexpr std::size_t kSlots = 8;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        SparseExtensionAccumulator<MockBackend> accumulator;

        MockBackend::reset_counts(contexts.eval);
        const auto finished = std::move(accumulator).finish();
        for (const auto &coefficient : finished) {
            CHECK(!coefficient.has_value());
        }
        CHECK(decrypt_extension<MockBackend>(contexts.client, finished) ==
              std::vector<Fpk>(kSlots, Fpk::zero()));
        const OperationCounts counts = MockBackend::counts(contexts.eval);
        CHECK(counts.encrypt == 0);
        CHECK(counts.add == 0);
        CHECK(counts.sub == 0);
        CHECK(counts.mul_plain_scalar == 0);
        CHECK(counts.mul_plain_vector == 0);
    });

    runner.run("sparse scalar accumulation defers encrypted zeros", [] {
        constexpr std::size_t kSlots = 8;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        SlotVector left_slots;
        SlotVector right_slots;
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            left_slots.emplace_back(3 + slot);
            right_slots.emplace_back(19 + 2 * slot);
        }
        const auto left =
            MockBackend::encrypt(contexts.client, left_slots);
        const auto right =
            MockBackend::encrypt(contexts.client, right_slots);
        Fpk::Coefficients left_coefficients{};
        left_coefficients[0] = Fp(5);
        left_coefficients[3] = Fp(7);
        Fpk::Coefficients right_coefficients{};
        right_coefficients[3] = Fp(11);
        right_coefficients[5] = Fp(13);
        const Fpk left_weight(left_coefficients);
        const Fpk right_weight(right_coefficients);

        SparseExtensionAccumulator<MockBackend> accumulator;
        MockBackend::reset_counts(contexts.eval);
        accumulator.accumulate_scaled_base(
            contexts.eval, left, left_weight);
        accumulator.accumulate_scaled_base(
            contexts.eval, right, right_weight);
        CHECK(accumulator.active_coefficient_count() == 3);
        CHECK(!accumulator.has_only_coefficient_zero());
        const OperationCounts sparse_counts =
            MockBackend::counts(contexts.eval);
        CHECK(sparse_counts.mul_plain_scalar_api_calls == 4);
        CHECK(sparse_counts.mul_plain_scalar == 4);
        CHECK(sparse_counts.add == 1);
        CHECK(sparse_counts.sub == 0);
        CHECK(sparse_counts.logical_ext_add == 0);

        const auto finished = std::move(accumulator).finish();
        const OperationCounts finished_counts =
            MockBackend::counts(contexts.eval);
        CHECK(finished_counts.sub == 0);
        CHECK(finished_counts.add == 1);
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            const bool expected_present =
                coefficient == 0 || coefficient == 3 || coefficient == 5;
            CHECK(finished[coefficient].has_value() == expected_present);
        }
        const std::vector<Fpk> actual =
            decrypt_extension<MockBackend>(contexts.client, finished);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            CHECK(actual[slot] ==
                  left_weight * left_slots[slot] +
                      right_weight * right_slots[slot]);
        }
    });

    runner.run("sparse slot accumulation builds only live coordinates", [] {
        constexpr std::size_t kSlots = 8;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        SlotVector source_slots;
        std::vector<Fpk> weights;
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            source_slots.emplace_back(23 + slot);
            Fpk::Coefficients coefficients{};
            coefficients[0] = Fp(31 + slot);
            if (slot % 2 == 0) {
                coefficients[4] = Fp(47 + slot);
            }
            weights.emplace_back(coefficients);
        }
        const auto source =
            MockBackend::encrypt(contexts.client, source_slots);

        SparseExtensionAccumulator<MockBackend> accumulator;
        MockBackend::reset_counts(contexts.eval);
        accumulator.accumulate_scaled_slots(
            contexts.eval, source, weights);
        CHECK(accumulator.active_coefficient_count() == 2);
        const OperationCounts sparse_counts =
            MockBackend::counts(contexts.eval);
        CHECK(sparse_counts.mul_plain_vector_api_calls == 2);
        CHECK(sparse_counts.mul_plain_vector_api_elements ==
              2 * kSlots);
        CHECK(sparse_counts.mul_plain_vector == 2);
        CHECK(sparse_counts.sub == 0);

        const auto finished = std::move(accumulator).finish();
        CHECK(MockBackend::counts(contexts.eval).sub == 0);
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            const bool expected_present = coefficient == 0 || coefficient == 4;
            CHECK(finished[coefficient].has_value() == expected_present);
        }
        const std::vector<Fpk> actual =
            decrypt_extension<MockBackend>(contexts.client, finished);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            CHECK(actual[slot] == weights[slot] * source_slots[slot]);
        }
    });

    runner.run("coefficient-zero sparse value uses prepared promotion", [] {
        constexpr std::size_t kSlots = 16;
        auto contexts = MockBackend::create(MockParameters{
            .slot_count = kSlots,
            .fresh_rns_limbs = 8,
            .bits_per_limb = 128,
        });
        SlotVector source_slots;
        std::vector<Fpk> basis_values;
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            source_slots.emplace_back(7 + slot);
            basis_values.push_back(value(101 + slot));
        }
        const auto source =
            MockBackend::encrypt(contexts.client, source_slots);
        const auto basis = prepare_fpk_slot_basis<MockBackend>(
            contexts.eval, source, basis_values);
        const Fp scalar(17);

        SparseExtensionAccumulator<MockBackend> accumulator;
        MockBackend::reset_counts(contexts.eval);
        accumulator.accumulate_scaled_base(
            contexts.eval, source, Fpk::from_base(scalar));
        CHECK(accumulator.active_coefficient_count() == 1);
        CHECK(accumulator.has_only_coefficient_zero());
        const auto actual_ciphertext =
            std::move(accumulator).apply_prepared_basis(
                contexts.eval, basis);
        const OperationCounts counts = MockBackend::counts(contexts.eval);
        CHECK(counts.sub == 0);
        CHECK(counts.logical_ext_mul_plain == 0);
        CHECK(counts.prepared_extension_promotion_api_calls == 1);
        CHECK(counts.mul_plain_scalar_api_calls == 1);
        CHECK(counts.mul_plain_vector_api_calls == 0);
        CHECK(counts.mul_plain_vector == kExtensionDegree);

        const std::vector<Fpk> actual = decrypt_extension<MockBackend>(
            contexts.client, actual_ciphertext);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            CHECK(actual[slot] ==
                  basis_values[slot] * scalar * source_slots[slot]);
        }
    });

    runner.run("scalar extension helpers never build slot plaintexts", [] {
        constexpr std::size_t kSlots = 16;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        SlotVector base;
        std::vector<Fpk> extension_values;
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            base.emplace_back(slot + 2);
            extension_values.push_back(value(101 + slot));
        }
        const Fpk scalar = value(41);
        const auto base_ciphertext =
            MockBackend::encrypt(contexts.client, base);

        MockBackend::reset_counts(contexts.eval);
        const auto promoted = promote_scale<MockBackend>(
            contexts.eval, base_ciphertext, scalar);
        const OperationCounts promotion_counts =
            MockBackend::counts(contexts.eval);
        CHECK(promotion_counts.mul_plain_scalar_api_calls ==
              kExtensionDegree);
        CHECK(promotion_counts.mul_plain_vector_api_calls == 0);
        CHECK(promotion_counts.mul_plain_vector_api_elements == 0);
        CHECK(promotion_counts.mul_plain_scalar == kExtensionDegree);
        CHECK(promotion_counts.mul_plain_vector == 0);
        const std::vector<Fpk> promoted_values =
            decrypt_extension<MockBackend>(contexts.client, promoted);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            CHECK(promoted_values[slot] == scalar * base[slot]);
        }

        const auto encrypted_extension =
            encrypt_private_test_extension<MockBackend>(
                contexts.client, extension_values);
        MockBackend::reset_counts(contexts.eval);
        const auto scaled = scale_extension<MockBackend>(
            contexts.eval, encrypted_extension, scalar);
        const OperationCounts scale_counts =
            MockBackend::counts(contexts.eval);
        CHECK(scale_counts.logical_ext_mul_plain == 1);
        CHECK(scale_counts.mul_plain_scalar_api_calls ==
              kExtensionDegree * kExtensionDegree);
        CHECK(scale_counts.mul_plain_vector_api_calls == 0);
        CHECK(scale_counts.mul_plain_vector_api_elements == 0);
        const std::vector<Fpk> scaled_values =
            decrypt_extension<MockBackend>(contexts.client, scaled);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            CHECK(scaled_values[slot] == extension_values[slot] * scalar);
        }
    });

    runner.run("mixed extension reduction reuses each high negation", [] {
        constexpr std::size_t kSlots = 8;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        SlotVector base_slots;
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            base_slots.emplace_back(13 + slot);
        }
        ExtensionValue<MockBackend> left;
        left[kExtensionDegree - 1] =
            FheValue<MockBackend>::from_ciphertext(
                MockBackend::encrypt(contexts.client, base_slots));
        ExtensionValue<MockBackend> right;
        right[kExtensionDegree - 1] =
            FheValue<MockBackend>::public_scalar(Fp::one());

        MockBackend::reset_counts(contexts.eval);
        const ExtensionValue<MockBackend> product =
            extension_mul_no_relin<MockBackend>(contexts.eval, left,
                                                right);
        const OperationCounts counts = MockBackend::counts(contexts.eval);

        // x^14 first contributes to x^9, which is reduced once more. Each
        // high coefficient is negated once and reused for both nonzero terms
        // of x^8 + x^3 + 1.
        CHECK(counts.negate == 2);
        CHECK(counts.mul_plain_scalar == 0);
        CHECK(counts.mul_plain_vector == 0);

        Fpk::Coefficients basis_coefficients{};
        basis_coefficients[kExtensionDegree - 1] = Fp::one();
        const Fpk basis(basis_coefficients);
        const std::vector<Fpk> actual =
            read_extension_value<MockBackend>(contexts.client, product);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            CHECK(actual[slot] ==
                  basis * basis * Fpk::from_base(base_slots[slot]));
        }
    });

    runner.run("public extension scaling uses cancellation-aware reduction",
               [] {
        constexpr std::size_t kSlots = 8;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        SlotVector source_slots;
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            source_slots.emplace_back(23 + slot);
        }
        const auto source =
            MockBackend::encrypt(contexts.client, source_slots);

        // x^7(x^2 + x^7) has two equal and opposite contributions to x:
        // x^9 = -x^4-x and x^14 = x^4+x-x^6. A raw sparse extension
        // ciphertext cannot express that the resulting coefficient is
        // publicly zero, so public multiplication must use typed reduction.
        ExtensionValue<MockBackend> extension_source;
        extension_source[7] =
            FheValue<MockBackend>::from_ciphertext(source);
        Fpk::Coefficients weight_coefficients{};
        weight_coefficients[2] = Fp::one();
        weight_coefficients[7] = Fp::one();
        const Fpk weight(weight_coefficients);

        MockBackend::reset_counts(contexts.eval);
        const auto scaled = scale_extension_value<MockBackend>(
            contexts.eval, extension_source, weight);
        const OperationCounts scalar_counts =
            MockBackend::counts(contexts.eval);
        CHECK(scalar_counts.logical_ext_mul_plain == 1);
        CHECK(scalar_counts.mul_plain_scalar_api_calls == 0);
        CHECK(scalar_counts.encrypt == 0);

        Fpk::Coefficients source_coefficients{};
        const std::vector<Fpk> scaled_plaintext =
            read_extension_value<MockBackend>(contexts.client, scaled);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            source_coefficients[7] = source_slots[slot];
            CHECK(scaled_plaintext[slot] ==
                  Fpk(source_coefficients) * weight);
        }

        const std::vector<Fpk> basis_values(kSlots, weight);
        const auto prepared = prepare_fpk_slot_basis<MockBackend>(
            contexts.eval, source, basis_values);
        MixedExtensionAccumulator<MockBackend> accumulator;
        accumulator.accumulate_extension(contexts.eval, extension_source);
        MockBackend::reset_counts(contexts.eval);
        const auto prepared_scaled =
            std::move(accumulator).apply_prepared_basis(
                contexts.eval, prepared, basis_values);
        const OperationCounts prepared_counts =
            MockBackend::counts(contexts.eval);
        CHECK(prepared_counts.logical_ext_mul_plain == 1);
        CHECK(prepared_counts.prepared_extension_promotion_api_calls == 0);
        CHECK(prepared_counts.prepared_extension_basis_api_calls == 0);
        CHECK(prepared_counts.encrypt == 0);
        const std::vector<Fpk> prepared_plaintext =
            read_extension_value<MockBackend>(contexts.client,
                                              prepared_scaled);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            source_coefficients[7] = source_slots[slot];
            CHECK(prepared_plaintext[slot] ==
                  Fpk(source_coefficients) * weight);
        }
    });

    runner.run("prepared Fpk basis removes online slot vectors", [] {
        constexpr std::size_t kSlots = 16;
        auto contexts = MockBackend::create(MockParameters{
            .slot_count = kSlots,
            .fresh_rns_limbs = 8,
            .bits_per_limb = 128,
        });
        SlotVector base;
        std::vector<Fpk> basis;
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            base.emplace_back(3 + slot);
            basis.push_back(value(67 + slot));
        }
        const Fpk scalar = value(131);
        const auto source =
            MockBackend::encrypt(contexts.client, base);

        MockBackend::reset_counts(contexts.eval);
        const auto prepared = prepare_fpk_slot_basis<MockBackend>(
            contexts.eval, source, basis);
        const auto aggregate = promote_scale<MockBackend>(
            contexts.eval, source, scalar);
        const auto product = scale_extension_prepared<MockBackend>(
            contexts.eval, aggregate, prepared);
        const OperationCounts counts = MockBackend::counts(contexts.eval);

        const std::vector<Fpk> decrypted =
            decrypt_extension<MockBackend>(contexts.client, product);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            CHECK(decrypted[slot] ==
                  (scalar * base[slot]) * basis[slot]);
        }
        CHECK(counts.prepared_extension_basis_setup_calls == 1);
        CHECK(counts.prepared_extension_basis_api_calls == 1);
        CHECK(counts.mul_plain_vector_api_calls == 0);
        CHECK(counts.mul_plain_vector_api_elements == 0);
        CHECK(counts.mul_plain_scalar_api_calls == kExtensionDegree);
        CHECK(counts.mul_plain_vector ==
              kExtensionDegree * kExtensionDegree);
        CHECK(product.front().has_value());
        CHECK(product.front()->depth_half_levels == 3);
        CHECK(prepared.storage.level_representations == 0);
        CHECK(prepared.storage.host_basis_bytes ==
              kExtensionDegree * kSlots * sizeof(Fp));
    });

    runner.run("prepared Fp basis is exact-level and value-equivalent", [] {
        constexpr std::size_t kSlots = 16;
        auto contexts = MockBackend::create(MockParameters{
            .slot_count = kSlots,
            .fresh_rns_limbs = 7,
            .bits_per_limb = 128,
        });
        SlotVector input;
        SlotVector basis;
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            input.emplace_back(17 + slot);
            basis.emplace_back(101 + 3 * slot);
        }
        auto source = MockBackend::encrypt(contexts.client, input);
        MockBackend::mod_switch_to_next(contexts.eval, source);
        const auto prepared = prepare_fp_slot_basis<MockBackend>(
            contexts.eval, source, basis);
        MockBackend::reset_counts(contexts.eval);
        const auto actual = mul_plain_prepared<MockBackend>(
            contexts.eval, source, prepared);
        const auto expected = MockBackend::mul_plain(
            contexts.eval, source, basis);
        const auto counts = MockBackend::counts(contexts.eval);
        CHECK(MockBackend::decrypt(contexts.client, actual) ==
              MockBackend::decrypt(contexts.client, expected));
        CHECK(actual.depth_half_levels == expected.depth_half_levels);
        CHECK(actual.noise_loss_bits == expected.noise_loss_bits);
        CHECK(prepared.storage.level_representations == 1);
        CHECK(prepared.storage.ntt_coefficient_bytes ==
              kSlots * source.rns_limbs * sizeof(std::uint64_t));
        CHECK(counts.mul_plain_vector_api_calls == 1);
        CHECK(counts.prepared_base_basis_api_calls == 1);

        auto wrong_level = source;
        MockBackend::mod_switch_to_next(contexts.eval, wrong_level);
        bool rejected = false;
        try {
            (void)mul_plain_prepared<MockBackend>(
                contexts.eval, wrong_level, prepared);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("prepared Fpk basis accepts unrelinearized products", [] {
        constexpr std::size_t kSlots = 16;
        auto contexts = MockBackend::create(MockParameters{
            .slot_count = kSlots,
            .fresh_rns_limbs = 10,
            .bits_per_limb = 128,
        });
        std::vector<Fpk> left;
        std::vector<Fpk> right;
        std::vector<Fpk> basis;
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            left.push_back(value(211 + slot));
            right.push_back(value(401 + slot));
            basis.push_back(value(601 + slot));
        }
        const auto encrypted_left =
            encrypt_private_test_extension<MockBackend>(contexts.client,
                                                        left);
        const auto encrypted_right =
            encrypt_private_test_extension<MockBackend>(contexts.client,
                                                        right);
        CHECK(encrypted_left.front().has_value());
        const auto prepared = prepare_fpk_slot_basis<MockBackend>(
            contexts.eval, *encrypted_left.front(), basis);

        auto product_first = MockBackend::ext_mul_no_relin(
            contexts.eval, encrypted_left, encrypted_right);
        CHECK(product_first.front().has_value());
        CHECK(!product_first.front()->relinearized);
        auto prepared_after = scale_extension_prepared<MockBackend>(
            contexts.eval, product_first, prepared);
        CHECK(prepared_after.front().has_value());
        CHECK(!prepared_after.front()->relinearized);
        MockBackend::ext_relinearize(contexts.eval, prepared_after);

        const auto prepared_right = scale_extension_prepared<MockBackend>(
            contexts.eval, encrypted_right, prepared);
        auto prepared_before = MockBackend::ext_mul_no_relin(
            contexts.eval, encrypted_left, prepared_right);
        MockBackend::ext_relinearize(contexts.eval, prepared_before);
        CHECK(decrypt_extension<MockBackend>(contexts.client,
                                             prepared_after) ==
              decrypt_extension<MockBackend>(contexts.client,
                                             prepared_before));
        CHECK(prepared_before.front().has_value());
        CHECK(prepared_after.front()->depth_half_levels ==
              prepared_before.front()->depth_half_levels);
        CHECK(prepared_after.front()->noise_loss_bits ==
              prepared_before.front()->noise_loss_bits);
    });

    runner.run("wire prefixes are bound from the original ciphertexts", [] {
        auto contexts = MockBackend::create(MockParameters{.slot_count = 8});
        std::vector<MockBackend::Ciphertext> wires;
        std::vector<SlotVector> plaintext;
        for (std::size_t wire = 0; wire < 8; ++wire) {
            SlotVector slots;
            for (std::size_t slot = 0; slot < 8; ++slot) {
                slots.emplace_back(3 + 17 * wire + slot);
            }
            plaintext.push_back(slots);
            wires.push_back(MockBackend::encrypt(contexts.client, slots));
        }
        const std::vector<Fpk> prefix{value(71), value(83)};
        MockBackend::reset_counts(contexts.eval);
        const auto partial = partial_evaluate_ciphertext_index_point<MockBackend>(
            contexts.eval, wires, prefix);
        const OperationCounts counts = MockBackend::counts(contexts.eval);
        CHECK(counts.mul_plain_scalar_api_calls ==
              wires.size() * kExtensionDegree);
        CHECK(counts.mul_plain_vector_api_calls == 0);
        CHECK(counts.mul_plain_vector_api_elements == 0);
        CHECK(partial.size() == 2);
        const std::vector<Fpk> prefix_weights =
            poly::eq_evaluations(prefix);
        for (std::size_t suffix = 0; suffix < partial.size(); ++suffix) {
            const std::vector<Fpk> decrypted =
                decrypt_extension<MockBackend>(contexts.client,
                                               partial[suffix]);
            for (std::size_t slot = 0; slot < 8; ++slot) {
                Fpk expected = Fpk::zero();
                for (std::size_t bound = 0; bound < prefix_weights.size();
                     ++bound) {
                    expected +=
                        prefix_weights[bound] *
                        plaintext[bound * partial.size() + suffix][slot];
                }
                CHECK(decrypted[slot] == expected);
            }
        }
    });

    runner.run("extension serialization follows final-level switching", [] {
        auto contexts = MockBackend::create(MockParameters{.slot_count = 8});
        const auto base = MockBackend::encrypt(
            contexts.client, SlotVector(8, Fp(9)));
        auto extension = promote_base<MockBackend>(contexts.eval, base);
        CHECK(extension.front().has_value());
        for (std::size_t coefficient = 1;
             coefficient < kExtensionDegree; ++coefficient) {
            CHECK(!extension[coefficient].has_value());
        }
        const auto before = serialize_extension<MockBackend>(extension);
        CHECK(before == serialize_extension<MockBackend>(extension));
        for (auto &coefficient : extension) {
            if (coefficient) {
                MockBackend::mod_switch_to_lowest(contexts.eval,
                                                  *coefficient);
            }
        }
        CHECK(before != serialize_extension<MockBackend>(extension));
        CHECK(decrypt_extension<MockBackend>(contexts.client, extension) ==
              std::vector<Fpk>(8, Fpk::from_base(Fp(9))));
    });

    runner.run("slot prefixes bind from a fixed grid checkpoint", [] {
        constexpr std::size_t kSlots = 16;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        std::vector<Fpk> plaintext;
        plaintext.reserve(kSlots);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            plaintext.push_back(value(101 + slot));
        }
        const auto checkpoint = encrypt_private_test_extension<MockBackend>(
            contexts.client, plaintext);

        for (std::size_t prefix_size = 1; prefix_size <= 4; ++prefix_size) {
            std::vector<Fpk> prefix;
            for (std::size_t variable = 0; variable < prefix_size;
                 ++variable) {
                prefix.push_back(value(307 + 19 * variable));
            }
            const auto bound = partial_evaluate_slot_index_point<MockBackend>(
                contexts.eval, checkpoint, prefix);
            const std::vector<Fpk> decrypted =
                decrypt_extension<MockBackend>(contexts.client, bound);
            const std::vector<Fpk> weights = poly::eq_evaluations(prefix);
            const std::size_t suffix_count = kSlots / weights.size();
            for (std::size_t suffix = 0; suffix < suffix_count; ++suffix) {
                Fpk expected = Fpk::zero();
                for (std::size_t bound_index = 0;
                     bound_index < weights.size(); ++bound_index) {
                    expected +=
                        weights[bound_index] *
                        plaintext[bound_index * suffix_count + suffix];
                }
                CHECK(decrypted[suffix] == expected);
            }
            for (const auto &limb : bound) {
                CHECK(limb.has_value());
                CHECK(limb->depth_half_levels == 2);
            }
        }
    });

    runner.run("paired slot prefix binding reuses one public mask", [] {
        constexpr std::size_t kSlots = 16;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        std::vector<Fpk> left_plaintext;
        std::vector<Fpk> right_plaintext;
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            left_plaintext.push_back(value(401 + slot));
            right_plaintext.push_back(value(701 + 3 * slot));
        }
        const auto left = encrypt_private_test_extension<MockBackend>(
            contexts.client, left_plaintext);
        const auto right = encrypt_private_test_extension<MockBackend>(
            contexts.client, right_plaintext);
        const std::vector<Fpk> prefix{value(17), value(29), value(43)};

        const auto expected_left = partial_evaluate_slot_index_point<MockBackend>(
            contexts.eval, left, prefix);
        const auto expected_right = partial_evaluate_slot_index_point<MockBackend>(
            contexts.eval, right, prefix);
        const auto actual = partial_evaluate_slot_index_point_pair<MockBackend>(
            contexts.eval, left, right, prefix);
        CHECK(decrypt_extension<MockBackend>(contexts.client, actual[0]) ==
              decrypt_extension<MockBackend>(contexts.client,
                                             expected_left));
        CHECK(decrypt_extension<MockBackend>(contexts.client, actual[1]) ==
              decrypt_extension<MockBackend>(contexts.client,
                                             expected_right));
    });

    runner.run("two extension scalars use one ciphertext", [] {
        constexpr std::size_t kSlots = 16;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        MockBackend::preprocess_fixed_message_cells(contexts.eval);
        CHECK(MockBackend::counts(contexts.eval)
                  .fixed_message_basis_setup_calls ==
              kFixedMessageCellCount);
        MockBackend::reset_counts(contexts.eval);
        const std::array<Fpk, 2> expected{value(701), value(809)};
        std::array<ExtensionValue<MockBackend>, 2> replicated{};
        for (std::size_t index = 0; index < expected.size(); ++index) {
            replicated[index] = ExtensionValue<MockBackend>(
                encrypt_private_test_extension<MockBackend>(
                    contexts.client,
                    std::vector<Fpk>(kSlots, expected[index])));
        }
        const auto packed = pack_replicated_extension_values<MockBackend>(
            contexts.eval, replicated);
        CHECK(unpack_extension_scalars<MockBackend>(
                  contexts.client, packed, expected.size()) ==
              std::vector<Fpk>(expected.begin(), expected.end()));
        CHECK(packed.is_encrypted());
        const auto &counts = MockBackend::counts(contexts.eval);
        CHECK(counts.fixed_message_basis_api_calls ==
              kFixedMessageCellCount);
        CHECK(counts.fixed_message_basis_avoided_vector_elements ==
              kFixedMessageCellCount * kSlots);
        CHECK(counts.fixed_message_basis_avoided_batch_encodes ==
              kFixedMessageCellCount);
        CHECK(counts.fixed_message_basis_avoided_hash_probes ==
              kFixedMessageCellCount);
        CHECK(counts.mul_plain_vector_api_calls == 0);
        CHECK(counts.mul_plain_vector_api_elements == 0);
    });

    runner.run("all-public-zero packed messages remain public", [] {
        constexpr std::size_t kSlots = 16;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        const std::array<ExtensionValue<MockBackend>, 2> public_zeros{};
        const auto packed = pack_replicated_extension_values<MockBackend>(
            contexts.eval, public_zeros);
        CHECK(packed.is_public_zero());
        const auto &counts = MockBackend::counts(contexts.eval);
        CHECK(counts.add == 0);
        CHECK(counts.mul_plain_scalar == 0);
        CHECK(counts.mul_plain_vector == 0);
    });

    runner.run("large fixed messages occupy one subgroup coset", [] {
        constexpr std::size_t kSlots = 64;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        MockBackend::preprocess_fixed_message_cells(contexts.eval);
        const std::array<Fpk, 2> expected{value(907), value(1009)};
        std::array<ExtensionValue<MockBackend>, 2> replicated{};
        for (std::size_t index = 0; index < expected.size(); ++index) {
            replicated[index] = ExtensionValue<MockBackend>(
                encrypt_private_test_extension<MockBackend>(
                    contexts.client,
                    std::vector<Fpk>(kSlots, expected[index])));
        }

        const auto packed = pack_replicated_extension_values<MockBackend>(
            contexts.eval, replicated);
        const SlotVector plaintext =
            materialize_or_decrypt<MockBackend>(contexts.client, packed);
        std::vector<bool> occupied(kSlots, false);
        for (std::size_t cell = 0; cell < kFixedMessageCellCount; ++cell) {
            occupied[fixed_message_cell_slot(kSlots, cell)] = true;
        }
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            CHECK(occupied[slot] || plaintext[slot].is_zero());
        }
        CHECK(unpack_extension_scalars<MockBackend>(
                  contexts.client, packed, expected.size()) ==
              std::vector<Fpk>(expected.begin(), expected.end()));
    });

    return runner.summary();
}
