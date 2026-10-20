/// @file test_noise_envelope_backend.cpp
/// @brief Exact bound-only backend and dense-topology marker tests.

#include "test_helpers.hpp"

#include "laminate/fhe/extension.hpp"
#include "laminate/fhe/noise/envelope_backend.hpp"
#include "laminate/fhe/value.hpp"

#include <cstdint>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;

namespace {

NoiseEnvelopeParameters parameters() {
    return NoiseEnvelopeParameters{
        .policy = DeterministicNoisePolicy{
            .ring_degree = 16,
            .plaintext_modulus = kBaseFieldOrder,
            .secret_hamming_weight_upper = 16,
            .sampled_error_coefficient_bound = 21,
        },
        .data_moduli = {1'000'000'007ULL, 1'000'000'021ULL,
                        1'000'000'033ULL, 1'000'000'087ULL},
        .special_modulus = 1'000'000'123ULL,
    };
}

} // namespace

int main() {
    test::Runner runner("test_noise_envelope_backend");

    runner.run("backend carries exact fresh and switch bounds", [] {
        auto contexts = NoiseEnvelopeBackend::create(parameters());
        const auto ciphertext = NoiseEnvelopeBackend::encrypt(
            contexts.client, SlotVector(16, Fp(7)));
        const auto expected = bound_fresh_asymmetric_encryption(
            contexts.eval.parameters.policy,
            contexts.eval.parameters.policy.plaintext_radius(),
            contexts.eval.parameters.data_moduli);
        CHECK(ciphertext.deterministic_noise_bound.partial_decryption_bound ==
              expected.partial_decryption_bound);
        CHECK(NoiseEnvelopeBackend::remaining_mult_depth(
                  contexts.eval, ciphertext) == 3);

        auto switched = ciphertext;
        NoiseEnvelopeBackend::mod_switch_to_next(contexts.eval, switched);
        const auto expected_switch = bound_modulus_switch(
            contexts.eval.parameters.policy, expected, 2,
            contexts.eval.parameters.data_moduli);
        CHECK(switched.deterministic_noise_bound.partial_decryption_bound ==
              expected_switch.partial_decryption_bound);
        CHECK(switched.rns_limbs == 3);
    });

    runner.run("zero vector challenge keeps its structural operation", [] {
        auto contexts = NoiseEnvelopeBackend::create(parameters());
        const auto ciphertext = NoiseEnvelopeBackend::encrypt(
            contexts.client, SlotVector(16, Fp(9)));
        const auto promoted = promote_scale<NoiseEnvelopeBackend>(
            contexts.eval, ciphertext,
            std::vector<Fpk>(16, Fpk::zero()));
        const std::uint64_t l1 =
            16 * contexts.eval.parameters.policy.plaintext_radius();
        const auto expected = bound_plaintext_multiplication(
            ciphertext.deterministic_noise_bound, l1,
            contexts.eval.parameters.data_moduli);
        for (const auto &coefficient : promoted) {
            CHECK(coefficient.has_value());
            CHECK(coefficient->deterministic_noise_bound
                      .partial_decryption_bound ==
                  expected.partial_decryption_bound);
        }
        CHECK(forces_challenge_independent_topology<NoiseEnvelopeBackend>(
            contexts.eval));
    });

    runner.run("zero scalar challenge keeps scalar topology", [] {
        auto contexts = NoiseEnvelopeBackend::create(parameters());
        const auto ciphertext = NoiseEnvelopeBackend::encrypt(
            contexts.client, SlotVector(16, Fp(9)));
        const auto promoted = promote_scale<NoiseEnvelopeBackend>(
            contexts.eval, ciphertext, Fpk::zero());
        const auto expected = bound_plaintext_multiplication(
            ciphertext.deterministic_noise_bound,
            contexts.eval.parameters.policy.plaintext_radius(),
            contexts.eval.parameters.data_moduli);
        for (const auto &coefficient : promoted) {
            CHECK(coefficient.has_value());
            CHECK(coefficient->deterministic_noise_bound
                      .partial_decryption_bound ==
                  expected.partial_decryption_bound);
            CHECK(coefficient->identity != ciphertext.identity);
        }
    });

    runner.run("sparse accumulation retains bound-only dense topology", [] {
        auto contexts = NoiseEnvelopeBackend::create(parameters());
        const auto ciphertext = NoiseEnvelopeBackend::encrypt(
            contexts.client, SlotVector(16, Fp(9)));
        SparseExtensionAccumulator<NoiseEnvelopeBackend> accumulator;
        accumulator.accumulate_scaled_base(
            contexts.eval, ciphertext, Fpk::zero());
        CHECK(accumulator.active_coefficient_count() == kExtensionDegree);
        CHECK(!accumulator.has_only_coefficient_zero());
        const auto sparse = std::move(accumulator).finish();
        const auto dense = promote_scale<NoiseEnvelopeBackend>(
            contexts.eval, ciphertext, Fpk::zero());
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            CHECK(sparse[coefficient].has_value());
            CHECK(dense[coefficient].has_value());
            CHECK(sparse[coefficient]->deterministic_noise_bound
                      .partial_decryption_bound ==
                  dense[coefficient]->deterministic_noise_bound
                      .partial_decryption_bound);
        }
    });

    runner.run("mixed accumulation retains bound-only dense topology", [] {
        auto contexts = NoiseEnvelopeBackend::create(parameters());
        const auto ciphertext = NoiseEnvelopeBackend::encrypt(
            contexts.client, SlotVector(16, Fp(9)));
        const auto source =
            FheValue<NoiseEnvelopeBackend>::from_ciphertext(ciphertext);

        MixedExtensionAccumulator<NoiseEnvelopeBackend> scalar_accumulator;
        scalar_accumulator.accumulate_scaled_base(
            contexts.eval, source, Fpk::zero());
        const auto scalar_result =
            std::move(scalar_accumulator).finish(contexts.eval);
        const auto scalar_envelope = promote_scale<NoiseEnvelopeBackend>(
            contexts.eval, ciphertext, Fpk::zero());

        MixedExtensionAccumulator<NoiseEnvelopeBackend> slot_accumulator;
        slot_accumulator.accumulate_scaled_slots(
            contexts.eval, source,
            std::vector<Fpk>(16, Fpk::zero()));
        const auto slot_result =
            std::move(slot_accumulator).finish(contexts.eval);
        const auto slot_envelope = promote_scale<NoiseEnvelopeBackend>(
            contexts.eval, ciphertext,
            std::vector<Fpk>(16, Fpk::zero()));

        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            CHECK(scalar_result[coefficient].is_encrypted());
            CHECK(slot_result[coefficient].is_encrypted());
            CHECK(scalar_envelope[coefficient].has_value());
            CHECK(slot_envelope[coefficient].has_value());
            CHECK(scalar_result[coefficient]
                      .ciphertext()
                      .deterministic_noise_bound
                      .partial_decryption_bound ==
                  scalar_envelope[coefficient]
                      ->deterministic_noise_bound
                      .partial_decryption_bound);
            CHECK(slot_result[coefficient]
                      .ciphertext()
                      .deterministic_noise_bound
                      .partial_decryption_bound ==
                  slot_envelope[coefficient]
                      ->deterministic_noise_bound
                      .partial_decryption_bound);
        }

        MixedExtensionAccumulator<NoiseEnvelopeBackend> public_accumulator;
        public_accumulator.accumulate_scaled_base(
            contexts.eval,
            FheValue<NoiseEnvelopeBackend>::public_scalar(Fp(7)),
            Fpk::zero());
        CHECK(std::move(public_accumulator)
                  .finish(contexts.eval)
                  .is_public_zero());
    });

    runner.run("zero extension scalar retains dense topology", [] {
        auto contexts = NoiseEnvelopeBackend::create(parameters());
        NoiseEnvelopeBackend::ExtCiphertext extension{};
        for (auto &coefficient : extension) {
            coefficient = NoiseEnvelopeBackend::encrypt(
                contexts.client, SlotVector(16, Fp(7)));
        }
        Fpk::Coefficients dense_coefficients{};
        dense_coefficients.fill(Fp::one());
        const auto from_zero = scale_extension<NoiseEnvelopeBackend>(
            contexts.eval, extension, Fpk::zero());
        const auto from_dense = scale_extension<NoiseEnvelopeBackend>(
            contexts.eval, extension, Fpk(dense_coefficients));
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            CHECK(from_zero[coefficient].has_value());
            CHECK(from_dense[coefficient].has_value());
            CHECK(from_zero[coefficient]->deterministic_noise_bound
                      .partial_decryption_bound ==
                  from_dense[coefficient]->deterministic_noise_bound
                      .partial_decryption_bound);
        }

        const ExtensionValue<NoiseEnvelopeBackend> typed(extension);
        const auto typed_scalar = scale_extension_value<
            NoiseEnvelopeBackend>(contexts.eval, typed, Fpk::zero());
        const auto typed_vector = scale_extension_value<
            NoiseEnvelopeBackend>(
            contexts.eval, typed,
            std::vector<Fpk>(16, Fpk::zero()));
        CHECK(typed_scalar.ciphertext_count() == kExtensionDegree);
        CHECK(typed_vector.ciphertext_count() == kExtensionDegree);
    });

    runner.run("raw self subtraction requires the public-value layer", [] {
        auto contexts = NoiseEnvelopeBackend::create(parameters());
        const auto ciphertext = NoiseEnvelopeBackend::encrypt(
            contexts.client, SlotVector(16, Fp(5)));
        bool rejected = false;
        try {
            (void)NoiseEnvelopeBackend::sub(
                contexts.eval, ciphertext, ciphertext);
        } catch (const std::logic_error &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("copied ciphertext values cancel without a bound operation",
               [] {
        auto contexts = NoiseEnvelopeBackend::create(parameters());
        const FheValue<NoiseEnvelopeBackend> left =
            FheValue<NoiseEnvelopeBackend>::from_ciphertext(
                NoiseEnvelopeBackend::encrypt(
                    contexts.client, SlotVector(16, Fp(5))));
        const FheValue<NoiseEnvelopeBackend> copied = left;
        const std::uint64_t next_identity = contexts.eval.identities->next;

        const FheValue<NoiseEnvelopeBackend> difference =
            value_sub<NoiseEnvelopeBackend>(contexts.eval, left, copied);

        CHECK(difference.is_public_zero());
        CHECK(contexts.eval.identities->next == next_identity);
    });

    runner.run("ciphertext identity is scoped to its bound context", [] {
        auto first = NoiseEnvelopeBackend::create(parameters());
        auto second = NoiseEnvelopeBackend::create(parameters());
        const FheValue<NoiseEnvelopeBackend> left =
            FheValue<NoiseEnvelopeBackend>::from_ciphertext(
                NoiseEnvelopeBackend::encrypt(
                    first.client, SlotVector(16, Fp(5))));
        const FheValue<NoiseEnvelopeBackend> unrelated =
            FheValue<NoiseEnvelopeBackend>::from_ciphertext(
                NoiseEnvelopeBackend::encrypt(
                    second.client, SlotVector(16, Fp(5))));
        CHECK(left.ciphertext().identity == unrelated.ciphertext().identity);

        bool rejected = false;
        try {
            (void)value_sub<NoiseEnvelopeBackend>(
                first.eval, left, unrelated);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    return runner.summary();
}
