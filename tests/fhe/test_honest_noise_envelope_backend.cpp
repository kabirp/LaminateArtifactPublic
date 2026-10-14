/// @file test_honest_noise_envelope_backend.cpp
/// @brief Honest-input operational error-algebra tests.

#include "test_helpers.hpp"

#include "laminate/fhe/extension.hpp"
#include "laminate/fhe/noise/honest_envelope_backend.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/fhe/value.hpp"
#include "laminate/gkr/detail/base/fhe/message_normalization.hpp"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;

namespace {

HonestNoiseEnvelopeParameters parameters() {
    return HonestNoiseEnvelopeParameters{
        .ring_degree = 16,
        .plaintext_modulus = kBaseFieldOrder,
        .fresh_canonical_error_bound = NaturalMagnitude(7),
        .ctct_relinearized_debit_bits = 5,
        .plaintext_multiplication_debit_bits = 3,
        .rotation_debit_bits = 2,
        .switch_rounding_error_bound = NaturalMagnitude(7),
        .data_moduli = {2'000'003ULL, 2'000'033ULL},
    };
}

void check_bound(const HonestNoiseEnvelopeBackend::Ciphertext &ciphertext,
                 std::uint64_t expected) {
    CHECK(ciphertext.canonical_error_bound == NaturalMagnitude(expected));
}

void check_parameter_binding_changes(
    const HonestNoiseEnvelopeParameters &baseline,
    const HonestNoiseEnvelopeParameters &changed) {
    CHECK(encode_canonical(baseline) != encode_canonical(changed));
    CHECK(honest_noise_envelope_parameters_digest(baseline) !=
          honest_noise_envelope_parameters_digest(changed));
}

template <typename Backend>
constexpr bool has_base_normalization_hook = requires(
    const typename Backend::EvalContext &context,
    const typename Backend::ExtCiphertext &before,
    const typename Backend::ExtCiphertext &after) {
    Backend::observe_base_message_normalization(context, before, after);
};

} // namespace

int main() {
    test::Runner runner("test_honest_noise_envelope_backend");

    runner.run("parameter encoding and digest are deterministic", [] {
        const HonestNoiseEnvelopeParameters first = parameters();
        const HonestNoiseEnvelopeParameters second = parameters();
        const std::vector<std::uint8_t> first_encoding =
            encode_canonical(first);
        CHECK(first_encoding == encode_canonical(first));
        CHECK(first_encoding == encode_canonical(second));
        CHECK(honest_noise_envelope_parameters_digest(first) ==
              honest_noise_envelope_parameters_digest(second));
        CHECK(honest_noise_envelope_parameters_digest(first) ==
              sha256(first_encoding));
    });

    runner.run("parameter binding covers every independently valid field",
               [] {
        const HonestNoiseEnvelopeParameters baseline = parameters();

        HonestNoiseEnvelopeParameters changed = baseline;
        changed.ring_degree = 32;
        check_parameter_binding_changes(baseline, changed);

        changed = baseline;
        changed.fresh_canonical_error_bound = NaturalMagnitude(8);
        check_parameter_binding_changes(baseline, changed);

        changed = baseline;
        ++changed.ctct_relinearized_debit_bits;
        check_parameter_binding_changes(baseline, changed);

        changed = baseline;
        ++changed.plaintext_multiplication_debit_bits;
        check_parameter_binding_changes(baseline, changed);

        changed = baseline;
        ++changed.rotation_debit_bits;
        check_parameter_binding_changes(baseline, changed);

        changed = baseline;
        changed.switch_rounding_error_bound = NaturalMagnitude(8);
        check_parameter_binding_changes(baseline, changed);

        changed = baseline;
        changed.data_moduli.front() = 2'000'039ULL;
        check_parameter_binding_changes(baseline, changed);

        changed = baseline;
        changed.data_moduli.push_back(2'000'081ULL);
        check_parameter_binding_changes(baseline, changed);
    });

    runner.run("parameter binding preserves coefficient-prime order", [] {
        const HonestNoiseEnvelopeParameters baseline = parameters();
        HonestNoiseEnvelopeParameters reordered = baseline;
        std::swap(reordered.data_moduli[0], reordered.data_moduli[1]);
        CHECK(reordered.data_moduli != baseline.data_moduli);
        check_parameter_binding_changes(baseline, reordered);
    });

    runner.run("magnitude encoding and binding retain values above u64", [] {
        const NaturalMagnitude low_high_word = NaturalMagnitude::add(
            NaturalMagnitude::shift_left(NaturalMagnitude(1), 80),
            NaturalMagnitude(7));
        const NaturalMagnitude different_high_word = NaturalMagnitude::add(
            NaturalMagnitude::shift_left(NaturalMagnitude(1), 81),
            NaturalMagnitude(7));
        CHECK(!low_high_word.fits_u64());
        CHECK(!different_high_word.fits_u64());
        CHECK(encode_canonical(low_high_word).size() == 24);
        CHECK(encode_canonical(different_high_word).size() == 24);
        CHECK(encode_canonical(low_high_word) !=
              encode_canonical(different_high_word));

        HonestNoiseEnvelopeParameters first = parameters();
        HonestNoiseEnvelopeParameters second = parameters();
        first.fresh_canonical_error_bound = low_high_word;
        second.fresh_canonical_error_bound = different_high_word;
        check_parameter_binding_changes(first, second);

        first = parameters();
        second = parameters();
        first.switch_rounding_error_bound = low_high_word;
        second.switch_rounding_error_bound = different_high_word;
        check_parameter_binding_changes(first, second);
    });

    runner.run("parameter encoding rejects the unsupported plaintext field",
               [] {
        HonestNoiseEnvelopeParameters changed = parameters();
        changed.plaintext_modulus -= 2;
        bool encoding_rejected = false;
        try {
            (void)encode_canonical(changed);
        } catch (const std::invalid_argument &) {
            encoding_rejected = true;
        }
        CHECK(encoding_rejected);

        bool digest_rejected = false;
        try {
            (void)honest_noise_envelope_parameters_digest(changed);
        } catch (const std::invalid_argument &) {
            digest_rejected = true;
        }
        CHECK(digest_rejected);
    });

    runner.run("scalar algebra follows the configured exact recurrences", [] {
        auto contexts = HonestNoiseEnvelopeBackend::create(parameters());
        const auto fresh = HonestNoiseEnvelopeBackend::encrypt(
            contexts.client, SlotVector(16, Fp(9)));
        check_bound(fresh, 7);
        CHECK(fresh.rns_limbs == 2);
        CHECK(fresh.component_count == 2);
        CHECK(fresh.all_phases_fit());

        check_bound(HonestNoiseEnvelopeBackend::add(
                        contexts.eval, fresh, fresh),
                    14);
        check_bound(HonestNoiseEnvelopeBackend::add_plain_scalar(
                        contexts.eval, fresh, Fp(123)),
                    7);
        check_bound(HonestNoiseEnvelopeBackend::add_plain(
                        contexts.eval, fresh,
                        SlotVector(16, Fp(123))),
                    7);

        const auto vector_scaled = HonestNoiseEnvelopeBackend::mul_plain(
            contexts.eval, fresh, SlotVector(16, Fp::zero()));
        const auto scalar_scaled =
            HonestNoiseEnvelopeBackend::mul_plain_scalar(
                contexts.eval, fresh, Fp::zero());
        check_bound(vector_scaled, 56);
        check_bound(scalar_scaled, 56);
        const auto no_rotation = HonestNoiseEnvelopeBackend::rotate(
            contexts.eval, fresh, 0);
        const auto wrapped_rotation = HonestNoiseEnvelopeBackend::rotate(
            contexts.eval, fresh, 2 * parameters().ring_degree);
        check_bound(no_rotation, 7);
        check_bound(wrapped_rotation, 7);
        CHECK(no_rotation.identity == fresh.identity);
        CHECK(no_rotation.last_operation_sequence ==
              fresh.last_operation_sequence);
        CHECK(wrapped_rotation.identity == fresh.identity);
        const auto rotated = HonestNoiseEnvelopeBackend::rotate(
            contexts.eval, fresh, 1);
        check_bound(rotated, 28);
        CHECK(rotated.identity != fresh.identity);

        auto product = HonestNoiseEnvelopeBackend::mul_no_relin(
            contexts.eval, vector_scaled, fresh);
        check_bound(product, 1'792);
        CHECK(product.component_count == 3);
        const std::uint64_t product_identity = product.identity;
        HonestNoiseEnvelopeBackend::relinearize(contexts.eval, product);
        check_bound(product, 1'792);
        CHECK(product.component_count == 2);
        CHECK(product.identity != product_identity);
    });

    runner.run("switch uses ceil division plus the configured rounding bound",
               [] {
        auto contexts = HonestNoiseEnvelopeBackend::create(parameters());
        auto ciphertext = HonestNoiseEnvelopeBackend::source_ciphertext(
            contexts.eval, NaturalMagnitude(2'000'034), 2);
        HonestNoiseEnvelopeBackend::mod_switch_to_next(
            contexts.eval, ciphertext);
        // ceil(2,000,034 / 2,000,033) + 7 = 9.
        check_bound(ciphertext, 9);
        CHECK(ciphertext.rns_limbs == 1);
        CHECK(HonestNoiseEnvelopeBackend::fits_active_modulus(
            contexts.eval, ciphertext));
    });

    runner.run("strict phase fit records the first failing operation and level",
               [] {
        HonestNoiseEnvelopeParameters small = parameters();
        small.data_moduli = {1'000'003ULL, 2'000'033ULL};
        auto contexts = HonestNoiseEnvelopeBackend::create(std::move(small));

        CHECK(honest_noise_fits_active_modulus(
            kBaseFieldOrder, NaturalMagnitude(7),
            std::array<std::uint64_t, 1>{1'000'003ULL}));
        CHECK(!honest_noise_fits_active_modulus(
            kBaseFieldOrder, NaturalMagnitude(8),
            std::array<std::uint64_t, 1>{1'000'003ULL}));

        auto switched = HonestNoiseEnvelopeBackend::encrypt(
            contexts.client, SlotVector(16, Fp::one()));
        CHECK(switched.all_phases_fit());
        HonestNoiseEnvelopeBackend::mod_switch_to_next(contexts.eval,
                                                       switched);
        check_bound(switched, 8);
        CHECK(!switched.all_phases_fit());
        CHECK(switched.first_failure.has_value());
        CHECK(switched.first_failure->operation ==
              HonestNoiseEnvelopeOperation::ModulusSwitch);
        CHECK(switched.first_failure->input_rns_limbs == 2);
        CHECK(switched.first_failure->output_rns_limbs == 1);

        const std::uint64_t failure_sequence =
            switched.first_failure->operation_sequence;
        const auto inherited = HonestNoiseEnvelopeBackend::add_plain_scalar(
            contexts.eval, switched, Fp(11));
        CHECK(inherited.first_failure->operation_sequence ==
              failure_sequence);
        CHECK(HonestNoiseEnvelopeBackend::fits_active_modulus(
                  contexts.eval, inherited) == false);
    });

    runner.run("source records are live unique values and never public padding",
               [] {
        auto contexts = HonestNoiseEnvelopeBackend::create(parameters());
        const auto left = HonestNoiseEnvelopeBackend::source_ciphertext(
            contexts.eval, NaturalMagnitude(7), 2);
        const auto right = HonestNoiseEnvelopeBackend::source_ciphertext(
            contexts.eval, NaturalMagnitude(7), 2);
        CHECK(left.identity != right.identity);

        const auto distinct_difference = HonestNoiseEnvelopeBackend::sub(
            contexts.eval, left, right);
        check_bound(distinct_difference, 14);

        bool exact_zero_rejected = false;
        try {
            (void)HonestNoiseEnvelopeBackend::sub(
                contexts.eval, left, left);
        } catch (const std::logic_error &) {
            exact_zero_rejected = true;
        }
        CHECK(exact_zero_rejected);

        bool rejected_public_zero = false;
        try {
            (void)HonestNoiseEnvelopeBackend::source_ciphertext(
                contexts.eval, NaturalMagnitude(), 2);
        } catch (const std::invalid_argument &) {
            rejected_public_zero = true;
        }
        CHECK(rejected_public_zero);
    });

    runner.run("ciphertext ownership rejects cross-context identity collisions",
               [] {
        auto first = HonestNoiseEnvelopeBackend::create(parameters());
        auto second = HonestNoiseEnvelopeBackend::create(parameters());
        const auto left = HonestNoiseEnvelopeBackend::encrypt(
            first.client, SlotVector(16, Fp(3)));
        const auto unrelated = HonestNoiseEnvelopeBackend::encrypt(
            second.client, SlotVector(16, Fp(4)));
        CHECK(left.identity == unrelated.identity);
        CHECK(left.context_token.get() != unrelated.context_token.get());

        bool subtraction_rejected = false;
        try {
            (void)HonestNoiseEnvelopeBackend::sub(
                first.eval, left, unrelated);
        } catch (const std::invalid_argument &) {
            subtraction_rejected = true;
        }
        CHECK(subtraction_rejected);

        bool decryption_rejected = false;
        try {
            (void)HonestNoiseEnvelopeBackend::decrypt(second.client, left);
        } catch (const std::invalid_argument &) {
            decryption_rejected = true;
        }
        CHECK(decryption_rejected);

        auto modified_context = first.eval;
        ++modified_context.parameters.rotation_debit_bits;
        bool modified_context_rejected = false;
        try {
            (void)HonestNoiseEnvelopeBackend::rotate(
                modified_context, left, 1);
        } catch (const std::invalid_argument &) {
            modified_context_rejected = true;
        }
        CHECK(modified_context_rejected);
    });

    runner.run("mixed-level alignment switches before adding and keeps the "
               "first failure",
               [] {
        HonestNoiseEnvelopeParameters mixed = parameters();
        mixed.data_moduli = {1'000'003ULL, 2'000'033ULL};
        auto contexts = HonestNoiseEnvelopeBackend::create(std::move(mixed));
        const auto high = HonestNoiseEnvelopeBackend::source_ciphertext(
            contexts.eval, NaturalMagnitude(2'000'034), 2);
        const auto low = HonestNoiseEnvelopeBackend::source_ciphertext(
            contexts.eval, NaturalMagnitude(7), 1);
        CHECK(high.all_phases_fit());
        CHECK(low.all_phases_fit());

        const auto sum = HonestNoiseEnvelopeBackend::add(
            contexts.eval, high, low);
        // Alignment first computes ceil(2,000,034 / 2,000,033) + 7 = 9.
        check_bound(sum, 16);
        CHECK(sum.rns_limbs == 1);
        CHECK(sum.first_failure.has_value());
        CHECK(sum.first_failure->operation ==
              HonestNoiseEnvelopeOperation::ModulusSwitch);
        CHECK(sum.first_failure->input_rns_limbs == 2);
        CHECK(sum.first_failure->output_rns_limbs == 1);
    });

    runner.run("recurrences remain exact above 64 bits", [] {
        HonestNoiseEnvelopeParameters wide = parameters();
        wide.data_moduli = {
            1'000'000'000'039ULL, 1'000'000'000'061ULL,
            1'000'000'000'063ULL, 1'000'000'000'091ULL};
        auto contexts = HonestNoiseEnvelopeBackend::create(std::move(wide));
        const NaturalMagnitude beta = NaturalMagnitude::shift_left(
            NaturalMagnitude(1), 80);
        const auto source = HonestNoiseEnvelopeBackend::source_ciphertext(
            contexts.eval, beta, 4);
        CHECK(!source.canonical_error_bound.fits_u64());
        CHECK(source.all_phases_fit());

        const auto sum = HonestNoiseEnvelopeBackend::add(
            contexts.eval, source, source);
        CHECK(sum.canonical_error_bound ==
              NaturalMagnitude::shift_left(NaturalMagnitude(1), 81));
        const auto scaled = HonestNoiseEnvelopeBackend::mul_plain_scalar(
            contexts.eval, source, Fp(9));
        CHECK(scaled.canonical_error_bound ==
              NaturalMagnitude::shift_left(NaturalMagnitude(1), 83));
        const auto product = HonestNoiseEnvelopeBackend::mul_no_relin(
            contexts.eval, source, source);
        CHECK(product.canonical_error_bound ==
              NaturalMagnitude::shift_left(NaturalMagnitude(1), 85));

        auto switched = source;
        HonestNoiseEnvelopeBackend::mod_switch_to_next(
            contexts.eval, switched);
        const NaturalMagnitude expected = NaturalMagnitude::add(
            NaturalMagnitude::divide_ceil(
                beta, 1'000'000'000'091ULL),
            NaturalMagnitude(7));
        CHECK(switched.canonical_error_bound == expected);
    });

    runner.run("raw self subtraction requires the public-value layer", [] {
        auto contexts = HonestNoiseEnvelopeBackend::create(parameters());
        auto source = HonestNoiseEnvelopeBackend::source_ciphertext(
            contexts.eval, NaturalMagnitude(7), 2);
        HonestNoiseEnvelopeBackend::mod_switch_to_next(contexts.eval,
                                                       source);
        check_bound(source, 8);
        bool rejected = false;
        try {
            (void)HonestNoiseEnvelopeBackend::sub(
                contexts.eval, source, source);
        } catch (const std::logic_error &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("copied ciphertext values cancel without a noise operation",
               [] {
        auto contexts = HonestNoiseEnvelopeBackend::create(parameters());
        const FheValue<HonestNoiseEnvelopeBackend> left =
            FheValue<HonestNoiseEnvelopeBackend>::from_ciphertext(
                HonestNoiseEnvelopeBackend::source_ciphertext(
                    contexts.eval, NaturalMagnitude(7), 2));
        const FheValue<HonestNoiseEnvelopeBackend> copied = left;
        const std::uint64_t next_identity =
            contexts.eval.sequences->next_identity;
        const std::uint64_t next_operation =
            contexts.eval.sequences->next_operation;

        const FheValue<HonestNoiseEnvelopeBackend> difference =
            value_sub<HonestNoiseEnvelopeBackend>(
                contexts.eval, left, copied);

        CHECK(difference.is_public_zero());
        CHECK(contexts.eval.sequences->next_identity == next_identity);
        CHECK(contexts.eval.sequences->next_operation == next_operation);
    });

    runner.run("zero Fiat-Shamir scalars retain the dense extension topology",
               [] {
        auto contexts = HonestNoiseEnvelopeBackend::create(parameters());
        const auto source = HonestNoiseEnvelopeBackend::source_ciphertext(
            contexts.eval, NaturalMagnitude(7), 2);
        CHECK(forces_challenge_independent_topology<
              HonestNoiseEnvelopeBackend>(contexts.eval));

        Fpk::Coefficients dense_coefficients{};
        dense_coefficients.fill(Fp::one());
        const auto from_zero = promote_scale<HonestNoiseEnvelopeBackend>(
            contexts.eval, source, Fpk::zero());
        const auto from_dense = promote_scale<HonestNoiseEnvelopeBackend>(
            contexts.eval, source, Fpk(dense_coefficients));
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            CHECK(from_zero[coefficient].has_value());
            CHECK(from_dense[coefficient].has_value());
            CHECK(from_zero[coefficient]->canonical_error_bound ==
                  from_dense[coefficient]->canonical_error_bound);
            check_bound(*from_zero[coefficient], 56);
            CHECK(from_zero[coefficient]->identity != source.identity);
        }
    });

    runner.run("Base normalization records exact extension boundaries", [] {
        auto contexts = HonestNoiseEnvelopeBackend::create(parameters());
        HonestNoiseEnvelopeBackend::ExtCiphertext encrypted_message;
        std::array<std::uint64_t, kExtensionDegree> input_identities{};
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            encrypted_message[coefficient] =
                HonestNoiseEnvelopeBackend::source_ciphertext(
                    contexts.eval, NaturalMagnitude(7 + coefficient), 2);
            CHECK(encrypted_message[coefficient].has_value());
            input_identities[coefficient] =
                encrypted_message[coefficient]->identity;
        }
        ExtensionValue<HonestNoiseEnvelopeBackend> message(
            std::move(encrypted_message));

        CHECK(HonestNoiseEnvelopeBackend::
                  base_message_normalization_records(contexts.eval)
                      .empty());
        gkr::base_detail::switch_message_to_lowest<
            HonestNoiseEnvelopeBackend>(contexts.eval, message);
        const auto first_records = HonestNoiseEnvelopeBackend::
            base_message_normalization_records(contexts.eval);
        CHECK(first_records.size() == 1);
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            const HonestBaseNormalizationCoefficientRecord &record =
                first_records[0].coefficients[coefficient];
            CHECK(record.present);
            CHECK(record.input_canonical_error_bound ==
                  NaturalMagnitude(7 + coefficient));
            // Every nonzero beta is below q_1, so ceil(beta/q_1)+7=8.
            CHECK(record.output_canonical_error_bound ==
                  NaturalMagnitude(8));
            CHECK(record.input_rns_limbs == 2);
            CHECK(record.output_rns_limbs == 1);
            CHECK(record.input_component_count == 2);
            CHECK(record.output_component_count == 2);
            CHECK(record.input_identity == input_identities[coefficient]);
            CHECK(message[coefficient].is_encrypted());
            CHECK(record.output_identity ==
                  message[coefficient].ciphertext().identity);
            CHECK(record.output_identity != record.input_identity);
            CHECK(!record.input_first_failure.has_value());
            CHECK(!record.output_first_failure.has_value());
        }

        gkr::base_detail::switch_message_to_lowest<
            HonestNoiseEnvelopeBackend>(contexts.eval, message);
        const auto two_records = HonestNoiseEnvelopeBackend::
            base_message_normalization_records(contexts.eval);
        CHECK(two_records.size() == 2);
        for (const auto &record : two_records[1].coefficients) {
            CHECK(record.present);
            CHECK(record.input_canonical_error_bound ==
                  NaturalMagnitude(8));
            CHECK(record.output_canonical_error_bound ==
                  NaturalMagnitude(8));
            CHECK(record.input_rns_limbs == 1);
            CHECK(record.output_rns_limbs == 1);
            CHECK(record.input_identity == record.output_identity);
        }

        HonestNoiseEnvelopeBackend::clear_base_message_normalization_records(
            contexts.eval);
        CHECK(HonestNoiseEnvelopeBackend::
                  base_message_normalization_records(contexts.eval)
                      .empty());
    });

    runner.run("ordinary Mock normalization has no observer requirement", [] {
        static_assert(!has_base_normalization_hook<MockBackend>);
        auto contexts = MockBackend::create(MockParameters{
            .slot_count = 16,
            .fresh_rns_limbs = 3,
        });
        MockBackend::ExtCiphertext encrypted_base_message;
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            encrypted_base_message[coefficient] = MockBackend::encrypt(
                contexts.client,
                SlotVector(16, Fp(3 + coefficient)));
        }
        ExtensionValue<MockBackend> via_base_helper(
            std::move(encrypted_base_message));

        MockBackend::reset_counts(contexts.eval);
        gkr::base_detail::switch_message_to_lowest<MockBackend>(
            contexts.eval, via_base_helper);
        const OperationCounts base_counts =
            MockBackend::counts(contexts.eval);
        CHECK(base_counts.mod_switch ==
              kExtensionDegree * std::uint64_t{2});

        const MockBackend::ExtCiphertext normalized_base =
            via_base_helper.encrypted_projection();
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            CHECK(normalized_base[coefficient].has_value());
            CHECK(normalized_base[coefficient]->rns_limbs == 1);
        }
    });

    runner.run("invalid setup-bound inputs fail closed", [] {
        HonestNoiseEnvelopeParameters invalid = parameters();
        invalid.switch_rounding_error_bound = NaturalMagnitude();
        bool rejected = false;
        try {
            (void)HonestNoiseEnvelopeBackend::create(std::move(invalid));
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    return runner.summary();
}
