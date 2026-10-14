/// @file test_seal_backend.cpp
/// @brief Differential tests for the optional Microsoft SEAL BGV backend.

#include "test_helpers.hpp"

#include "laminate/fhe/storage/ciphertext.hpp"
#include "laminate/fhe/extension.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/fhe/seal_backend.hpp"
#include "laminate/fhe/noise/seal_envelope.hpp"
#include "laminate/fhe/value.hpp"
#include "laminate/packing/analysis/deterministic_completeness.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/payload/fixtures/workloads.hpp"
#include "laminate/protocol/analysis/noise_completeness.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;

static_assert(protocol::PackingCompletenessEncoderBackend<SealBackend>);
static_assert(PersistableFheBackend<SealBackend>);

namespace {

constexpr std::size_t kSlots = 1024;

/// Exercise the typed fold boundary with a rotation whose public algebraic
/// relation is known to the test. All other behavior is the real SEAL
/// backend, including transparent-result recovery.
class TransparentFoldProbeBackend : public SealBackend {
  public:
    static Ciphertext rotate(const EvalContext &context,
                             const Ciphertext &ciphertext,
                             std::size_t) {
        return SealBackend::negate(context, ciphertext);
    }
};

static_assert(FheBackend<TransparentFoldProbeBackend>);

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

SlotVector slots(std::uint64_t seed) {
    SlotVector result(kSlots);
    for (std::size_t slot = 0; slot < result.size(); ++slot) {
        result[slot] = Fp(seed + 7 * slot + slot * slot);
    }
    return result;
}

SealBackend::Contexts make_seal_contexts() {
    return SealBackend::create(SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = 5,
        .bits_per_data_prime = 60,
        .special_prime_bits = 60,
        .security_level = seal::sec_level_type::none,
    });
}

SealBackend::Contexts make_tracked_seal_contexts(
    std::size_t data_limbs = 3) {
    return SealBackend::create(SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = data_limbs,
        .bits_per_data_prime = 60,
        .special_prime_bits = 60,
        .security_level = seal::sec_level_type::none,
        .track_deterministic_noise_bounds = true,
    });
}

SealBackend::ExtCiphertext encrypt_private_test_extension(
    const SealBackend::ClientContext &client,
    const std::vector<Fpk> &values) {
    const PlainExtension plaintext = encode_extension_plain(values);
    SealBackend::ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        result[coefficient] =
            SealBackend::encrypt(client, plaintext[coefficient]);
    }
    return result;
}

std::vector<Fpk> extension_values(std::uint64_t seed) {
    std::vector<Fpk> result(kSlots);
    for (std::size_t slot = 0; slot < result.size(); ++slot) {
        Fpk::Coefficients coefficients{};
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            coefficients[coefficient] =
                Fp(seed + 11 * slot + 17 * coefficient);
        }
        result[slot] = Fpk(coefficients);
    }
    return result;
}

void check_same_noise_metadata(
    const SealBackend::Ciphertext &actual,
    const SealBackend::Ciphertext &expected) {
    CHECK(actual.noise_loss_bits == expected.noise_loss_bits);
    CHECK(actual.deterministic_noise_bound.has_value() ==
          expected.deterministic_noise_bound.has_value());
    if (!actual.deterministic_noise_bound) {
        return;
    }
    const DeterministicNoiseBound &actual_bound =
        *actual.deterministic_noise_bound;
    const DeterministicNoiseBound &expected_bound =
        *expected.deterministic_noise_bound;
    CHECK(actual_bound.partial_decryption_bound ==
          expected_bound.partial_decryption_bound);
    CHECK(actual_bound.operation_count == expected_bound.operation_count);
    CHECK(actual_bound.first_failure.has_value() ==
          expected_bound.first_failure.has_value());
    if (actual_bound.first_failure) {
        CHECK(actual_bound.first_failure->operation ==
              expected_bound.first_failure->operation);
        CHECK(actual_bound.first_failure->reason ==
              expected_bound.first_failure->reason);
        CHECK(actual_bound.first_failure->bound_bit_count ==
              expected_bound.first_failure->bound_bit_count);
        CHECK(actual_bound.first_failure->modulus_bit_count ==
              expected_bound.first_failure->modulus_bit_count);
    }
}

} // namespace

int main() {
    test::Runner runner("test_seal_backend");
    SealBackend::Contexts seal_contexts = make_seal_contexts();
    MockBackend::Contexts mock_contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 5,
        .bits_per_limb = 60,
    });

    runner.run("setup exposes the requested BGV chain", [&] {
        CHECK(SealBackend::slot_count(seal_contexts.eval) == kSlots);
        CHECK(SealBackend::slot_count(seal_contexts.client) == kSlots);
        CHECK(SealBackend::coefficient_moduli(seal_contexts.eval).size() == 6);
        const auto ciphertext =
            SealBackend::encrypt(seal_contexts.client, slots(3));
        CHECK(SealBackend::rns_limb_count(seal_contexts.eval, ciphertext) ==
              5);
        CHECK(SealBackend::data_coefficient_moduli(
                  seal_contexts.eval, ciphertext).size() == 5);
        CHECK(SealBackend::data_coefficient_moduli(
                  seal_contexts.client, ciphertext) ==
              SealBackend::data_coefficient_moduli(
                  seal_contexts.eval, ciphertext));
        CHECK(SealBackend::lowest_coefficient_modulus(
                  seal_contexts.eval) == kOuterFieldOrder);
        CHECK(SealBackend::remaining_mult_depth(seal_contexts.eval,
                                                ciphertext) == 4);
        const auto coefficient_moduli =
            SealBackend::coefficient_moduli(seal_contexts.eval);
        for (std::size_t index = 0; index < 5; ++index) {
            CHECK(coefficient_moduli[index] % kBaseFieldOrder == 1);
        }
        CHECK(coefficient_moduli.back() % (2 * kSlots) == 1);
        auto switched = ciphertext;
        SealBackend::mod_switch_to_next(seal_contexts.eval, switched);
        CHECK(SealBackend::data_coefficient_moduli(
                  seal_contexts.eval, switched).size() == 4);
        CHECK(SealBackend::data_coefficient_moduli(
                  seal_contexts.client, switched) ==
              SealBackend::data_coefficient_moduli(
                  seal_contexts.eval, switched));

        const auto shorter = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 2,
            .bits_per_data_prime = 60,
            .special_prime_bits = 60,
            .security_level = seal::sec_level_type::none,
        });
        CHECK(SealBackend::lowest_coefficient_modulus(shorter.eval) ==
              SealBackend::lowest_coefficient_modulus(seal_contexts.eval));
        CHECK(!ciphertext.deterministic_noise_bound.has_value());
    });

    runner.run("client encryption may hide an all-zero private input", [&] {
        SealBackend::reset_counts(seal_contexts.eval);
        SealBackend::set_counting(seal_contexts.eval, true);
        const auto private_zero_ciphertext = SealBackend::encrypt(
            seal_contexts.client, SlotVector(kSlots, Fp::zero()));
        SealBackend::set_counting(seal_contexts.eval, false);

        CHECK(!private_zero_ciphertext.raw.is_transparent());
        CHECK(SealBackend::decrypt(seal_contexts.client,
                                   private_zero_ciphertext) ==
              SlotVector(kSlots, Fp::zero()));
        CHECK(SealBackend::counts(seal_contexts.eval)
                  .calls(SealBackend::OperationKind::Encrypt) == 1);
    });

    runner.run("first SEAL term moves into a public-zero accumulator", [&] {
        using Value = FheValue<SealBackend>;
        const SlotVector clear = slots(17);
        Value term = Value::from_ciphertext(
            SealBackend::encrypt(seal_contexts.client, clear));
        const std::uint64_t *term_storage = term.ciphertext().raw.data();
        Value accumulator = Value::public_zero();
        SealBackend::reset_counts(seal_contexts.eval);
        SealBackend::set_counting(seal_contexts.eval, true);

        value_add_assign(seal_contexts.eval, accumulator,
                         std::move(term));

        SealBackend::set_counting(seal_contexts.eval, false);
        CHECK(accumulator.is_encrypted());
        CHECK(accumulator.ciphertext().raw.data() == term_storage);
        CHECK(SealBackend::decrypt(seal_contexts.client,
                                   accumulator.ciphertext()) == clear);
        CHECK(SealBackend::counts(seal_contexts.eval)
                  .calls(SealBackend::OperationKind::Add) == 0);
    });

    runner.run("setup enforces exact data and key modulus caps", [&] {
        const std::size_t fresh_bits =
            SealBackend::fresh_ciphertext_modulus_bits(seal_contexts.eval);
        const std::size_t key_bits =
            SealBackend::key_modulus_bits(seal_contexts.eval);
        CHECK(fresh_bits <= 5 * 60);
        CHECK(key_bits <= 6 * 60);
        CHECK(SealBackend::fresh_ciphertext_modulus_width_sum_bits(
                  seal_contexts.eval) == 5 * 60);
        CHECK(SealBackend::key_modulus_width_sum_bits(seal_contexts.eval) ==
              6 * 60);

        const auto capped = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 5,
            .bits_per_data_prime = 60,
            .special_prime_bits = 60,
            .security_level = seal::sec_level_type::none,
            .max_fresh_ciphertext_modulus_bits = fresh_bits,
            .max_key_modulus_bits = key_bits,
        });
        CHECK(SealBackend::fresh_ciphertext_modulus_bits(capped.eval) ==
              fresh_bits);
        CHECK(SealBackend::key_modulus_bits(capped.eval) == key_bits);

        bool rejected = false;
        try {
            (void)SealBackend::create(SealParameters{
                .poly_modulus_degree = kSlots,
                .fresh_rns_limbs = 5,
                .bits_per_data_prime = 60,
                .special_prime_bits = 60,
                .security_level = seal::sec_level_type::none,
                .max_fresh_ciphertext_modulus_bits = fresh_bits - 1,
            });
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);

        rejected = false;
        try {
            (void)SealBackend::create(SealParameters{
                .poly_modulus_degree = kSlots,
                .fresh_rns_limbs = 5,
                .bits_per_data_prime = 60,
                .special_prime_bits = 60,
                .security_level = seal::sec_level_type::none,
                .max_key_modulus_bits = key_bits - 1,
            });
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("depth-8 diagnostic profile is exact and capped", [&] {
        SealParameters parameters =
            make_depth8_diagnostic_parameters(false);
        CHECK(parameters.poly_modulus_degree == (std::size_t{1} << 14));
        CHECK(parameters.fresh_rns_limbs == 10);
        CHECK(parameters.exact_data_primes.size() == 10);
        CHECK(parameters.exact_data_primes.front() == kOuterFieldOrder);
        CHECK(parameters.security_level == seal::sec_level_type::none);
        CHECK(!parameters.generate_galois_keys);

        const auto contexts = SealBackend::create(parameters);
        CHECK(SealBackend::fresh_ciphertext_modulus_bits(contexts.eval) ==
              390);
        CHECK(SealBackend::fresh_ciphertext_modulus_width_sum_bits(
                  contexts.eval) == 393);
        CHECK(SealBackend::key_modulus_bits(contexts.eval) == 423);
        CHECK(SealBackend::key_modulus_width_sum_bits(contexts.eval) == 427);

        const payload::Workload diamond = payload::make_workload(
            payload::WorkloadSpec{
                .kind = payload::WorkloadKind::Diamond,
                .shape = payload::PayloadShape::laned(
                    parameters.poly_modulus_degree,
                    parameters.poly_modulus_degree),
                .multiplicative_depth =
                    kMaximumPayloadMultiplicativeDepth,
                .width = 1,
                .seed = 17,
            });
        const payload::LayeredCircuit layered =
            payload::compile(diamond.circuit);
        const payload::PayloadStats diamond_stats =
            payload::analyze(diamond.circuit);
        CHECK(diamond_stats.ct_ct_multiplicative_depth ==
              kMaximumPayloadMultiplicativeDepth);
        CHECK(diamond_stats.alternating_multiplicative_depth ==
              kMaximumPayloadMultiplicativeDepth);

        const auto encrypted_inputs =
            payload::encrypt_laned_payload_inputs<SealBackend>(
                contexts.client, diamond.circuit, diamond.inputs);
        const auto trace = payload::evaluate_laned_fhe_trace<SealBackend>(
            contexts.eval, diamond.circuit, layered, encrypted_inputs,
            payload::FheEvaluationPlan::at_evaluation_levels(
                layered, parameters.fresh_rns_limbs - 1, 1,
                kMaximumPayloadMultiplicativeDepth - 1));
        CHECK(payload::decrypt_trace_layer<SealBackend>(
                  contexts.client, layered, trace, 0) ==
              payload::evaluate(diamond.circuit, diamond.inputs)
                  .output_values(diamond.circuit));

        int minimum_retained_noise = std::numeric_limits<int>::max();
        for (const auto &layer : trace.layers) {
            for (const auto &wire : layer.wires) {
                if (wire.is_public()) {
                    continue;
                }
                minimum_retained_noise = std::min(
                    minimum_retained_noise,
                    SealBackend::invariant_noise_budget(contexts.client,
                                                        wire.ciphertext()));
            }
        }
        CHECK(minimum_retained_noise > 0);
        CHECK(trace.layers.front().wires.front().is_encrypted());
        CHECK(SealBackend::invariant_noise_budget(
                  contexts.client,
                  trace.layers.front().wires.front().ciphertext()) > 0);

        std::vector<std::uint64_t> expected_moduli =
            parameters.exact_data_primes;
        expected_moduli.push_back(parameters.exact_special_prime);
        CHECK(SealBackend::coefficient_moduli(contexts.eval) ==
              expected_moduli);

        SlotVector input(parameters.poly_modulus_degree);
        for (std::size_t slot = 0; slot < input.size(); ++slot) {
            input[slot] = Fp(211 + 7 * slot + slot * slot);
        }
        auto ciphertext = SealBackend::encrypt(contexts.client, input);
        for (std::size_t drop = 0; drop < 7; ++drop) {
            SealBackend::mod_switch_to_next(contexts.eval, ciphertext);
            CHECK(SealBackend::correction_factor_is_one(ciphertext));
        }
        CHECK(SealBackend::rns_limb_count(contexts.eval, ciphertext) == 3);
        CHECK(SealBackend::decrypt(contexts.client, ciphertext) == input);

        SealBackend::mod_switch_to_next(contexts.eval, ciphertext);
        CHECK(SealBackend::rns_limb_count(contexts.eval, ciphertext) == 2);
        CHECK(SealBackend::correction_factor_is_one(ciphertext));
        CHECK(SealBackend::decrypt(contexts.client, ciphertext) == input);

        SealBackend::mod_switch_to_next(contexts.eval, ciphertext);
        CHECK(SealBackend::rns_limb_count(contexts.eval, ciphertext) == 1);
        CHECK(SealBackend::correction_factor_is_one(ciphertext));
        CHECK(SealBackend::decrypt(contexts.client, ciphertext) == input);

        parameters.max_fresh_ciphertext_modulus_bits = 389;
        bool rejected = false;
        try {
            (void)SealBackend::create(parameters);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("noise envelope imports the exact live modulus chain", [&] {
        const NoiseEnvelopeParameters envelope =
            make_noise_envelope_parameters(seal_contexts.eval);
        const std::vector<std::uint64_t> seal_moduli =
            SealBackend::coefficient_moduli(seal_contexts.eval);

        CHECK(envelope.policy.ring_degree == kSlots);
        CHECK(envelope.policy.plaintext_modulus == kBaseFieldOrder);
        CHECK(envelope.policy.secret_hamming_weight_upper == kSlots);
        CHECK(envelope.policy.sampled_error_coefficient_bound == 21);
        CHECK(envelope.data_moduli.size() + 1 == seal_moduli.size());
        CHECK(envelope.special_modulus == seal_moduli.back());
        CHECK(std::equal(envelope.data_moduli.begin(),
                         envelope.data_moduli.end(),
                         seal_moduli.begin()));
    });

    runner.run("ordinary SEAL paths cannot claim envelope scope", [&] {
        auto tracked = make_tracked_seal_contexts();
        const std::vector<SealBackend::Ciphertext> messages{
            SealBackend::encrypt(tracked.client, slots(17))};
        const auto layout =
            packing::make_fixed_message_coset_packing_layout(
                kSlots, messages.size(),
                kSlots / kFixedMessageCellCount);
        bool rejected = false;
        try {
            (void)packing::certify_deterministic_packing_completeness<
                SealBackend>(
                tracked.eval, messages, layout,
                make_noise_envelope_parameters(tracked.eval).policy,
                kSelectedPackingHonestErrorBound,
                packing::DeterministicPackingCertificateScope::
                    ChallengeIndependentEnvelope);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("opt-in hard bounds follow live SEAL operations", [&] {
        auto tracked = make_tracked_seal_contexts();
        auto left = SealBackend::encrypt(tracked.client, slots(3));
        auto right = SealBackend::encrypt(tracked.client, slots(11));
        CHECK(left.deterministic_noise_bound.has_value());
        CHECK(left.deterministic_noise_bound->certifies_no_wrap());

        auto sum = SealBackend::add(tracked.eval, left, right);
        sum = SealBackend::add_plain(tracked.eval, sum, slots(5));
        auto product = SealBackend::mul(tracked.eval, sum, right);
        product = SealBackend::mul_plain(tracked.eval, product, slots(7));
        product = SealBackend::rotate(tracked.eval, product, 37);
        CHECK(product.deterministic_noise_bound.has_value());
        CHECK(product.deterministic_noise_bound->certifies_no_wrap());

        SealBackend::mod_switch_to_lowest(tracked.eval, product);
        SealBackend::normalize_for_coefficient_commitment(tracked.eval,
                                                          product);
        const auto &bound = *product.deterministic_noise_bound;
        const std::uint64_t observed =
            SealBackend::partial_decryption_infinity_norm(tracked.client,
                                                           product);
        CHECK(bound.certifies_no_wrap());
        CHECK(bound.partial_decryption_bound.fits_u64());
        CHECK(!(bound.partial_decryption_bound <
                NaturalMagnitude(observed)));
    });

    runner.run("hard bounds fail at the first insufficient operation", [&] {
        auto tracked = make_tracked_seal_contexts(1);
        const auto left = SealBackend::encrypt(tracked.client, slots(2));
        const auto right = SealBackend::encrypt(tracked.client, slots(13));
        const auto product =
            SealBackend::mul_no_relin(tracked.eval, left, right);

        CHECK(product.deterministic_noise_bound.has_value());
        CHECK(!product.deterministic_noise_bound->certifies_no_wrap());
        CHECK(product.deterministic_noise_bound->first_failure.has_value());
        CHECK(product.deterministic_noise_bound->first_failure->operation ==
              DeterministicNoiseOperation::CiphertextMultiplication);
        CHECK(product.deterministic_noise_bound->first_failure->reason ==
              DeterministicNoiseFailureReason::CiphertextModulusWrap);
    });

    runner.run("arithmetic preserves same-level and mixed-level semantics",
               [] {
        auto contexts = make_tracked_seal_contexts(4);
        const auto high_left =
            SealBackend::encrypt(contexts.client, slots(5));
        auto low_left = high_left;
        auto low_right =
            SealBackend::encrypt(contexts.client, slots(41));
        SealBackend::mod_switch_to_next(contexts.eval, low_left);
        SealBackend::mod_switch_to_next(contexts.eval, low_right);

        const auto same_level_sum =
            SealBackend::add(contexts.eval, low_left, low_right);
        CHECK(same_level_sum.raw.parms_id() == low_left.raw.parms_id());
        CHECK(same_level_sum.deterministic_noise_bound.has_value());

        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        const auto mixed_level_sum =
            SealBackend::add(contexts.eval, high_left, low_right);
        SealBackend::set_counting(contexts.eval, false);
        CHECK(mixed_level_sum.raw.parms_id() == low_right.raw.parms_id());
        CHECK(SealBackend::decrypt(contexts.client, mixed_level_sum) ==
              SealBackend::decrypt(contexts.client, same_level_sum));
        CHECK(SealBackend::rns_limb_count(contexts.eval, high_left) == 4);
        CHECK(SealBackend::rns_limb_count(contexts.eval, low_right) == 3);
        auto counts = SealBackend::counts(contexts.eval);
        CHECK(counts.calls(SealBackend::OperationKind::Add) == 1);
        CHECK(counts.calls(SealBackend::OperationKind::ModSwitch) == 1);

        const auto same_level_product =
            SealBackend::mul_no_relin(contexts.eval, low_left, low_right);
        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        const auto mixed_level_product = SealBackend::mul_no_relin(
            contexts.eval, high_left, low_right);
        SealBackend::set_counting(contexts.eval, false);
        CHECK(mixed_level_product.raw.parms_id() ==
              low_right.raw.parms_id());
        CHECK(mixed_level_product.raw.size() == 3);
        CHECK(SealBackend::decrypt(contexts.client, mixed_level_product) ==
              SealBackend::decrypt(contexts.client,
                                   same_level_product));
        CHECK(mixed_level_product.deterministic_noise_bound.has_value());
        counts = SealBackend::counts(contexts.eval);
        CHECK(counts.calls(SealBackend::OperationKind::MulNoRelin) == 1);
        CHECK(counts.calls(SealBackend::OperationKind::ModSwitch) == 1);
    });

    runner.run("in-place addition preserves levels, metadata, and operands",
               [] {
        auto contexts = make_tracked_seal_contexts(4);
        using Ciphertext = SealBackend::Ciphertext;

        const Ciphertext high_left =
            SealBackend::encrypt(contexts.client, slots(5));
        const Ciphertext high_term =
            SealBackend::encrypt(contexts.client, slots(41));
        Ciphertext low_left = high_left;
        Ciphertext low_term = high_term;
        SealBackend::mod_switch_to_next(contexts.eval, low_left);
        SealBackend::mod_switch_to_next(contexts.eval, low_term);

        const auto check_add =
            [&](const Ciphertext &left, const Ciphertext &term,
                std::uint64_t expected_switches) {
                const Ciphertext expected =
                    SealBackend::add(contexts.eval, left, term);
                Ciphertext actual = left;
                const std::vector<std::uint8_t> term_before =
                    SealBackend::serialize(term);

                SealBackend::reset_counts(contexts.eval);
                SealBackend::set_counting(contexts.eval, true);
                add_assign<SealBackend>(contexts.eval, actual, term);
                SealBackend::set_counting(contexts.eval, false);

                CHECK(SealBackend::serialize(actual) ==
                      SealBackend::serialize(expected));
                CHECK(SealBackend::serialize(term) == term_before);
                CHECK(actual.raw.parms_id() == expected.raw.parms_id());
                CHECK(actual.raw.size() == expected.raw.size());
                CHECK(actual.raw.correction_factor() ==
                      expected.raw.correction_factor());
                check_same_noise_metadata(actual, expected);
                const auto counts = SealBackend::counts(contexts.eval);
                CHECK(counts.calls(SealBackend::OperationKind::Add) == 1);
                CHECK(counts.calls(SealBackend::OperationKind::ModSwitch) ==
                      expected_switches);
            };

        check_add(low_left, low_term, 0);
        check_add(high_left, low_term, 1);
        check_add(low_left, high_term, 1);

        const Ciphertext lazy_product = SealBackend::mul_no_relin(
            contexts.eval, low_left, low_term);
        CHECK(lazy_product.raw.size() == 3);
        check_add(lazy_product, low_term, 0);
        check_add(low_left, lazy_product, 0);

        const Ciphertext doubled_expected =
            SealBackend::add(contexts.eval, low_left, low_left);
        Ciphertext doubled = low_left;
        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        add_assign<SealBackend>(contexts.eval, doubled, doubled);
        SealBackend::set_counting(contexts.eval, false);
        CHECK(SealBackend::serialize(doubled) ==
              SealBackend::serialize(doubled_expected));
        check_same_noise_metadata(doubled, doubled_expected);
        CHECK(SealBackend::counts(contexts.eval).calls(
                  SealBackend::OperationKind::Add) == 1);
    });

    runner.run("raw in-place addition rejects public-zero cancellation",
               [] {
        auto contexts = make_tracked_seal_contexts(3);
        const auto source =
            SealBackend::encrypt(contexts.client, slots(17));
        const auto negated = SealBackend::negate(contexts.eval, source);
        auto cancelled = source;

        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        bool cancellation_rejected = false;
        try {
            add_assign<SealBackend>(contexts.eval, cancelled, negated);
        } catch (const std::logic_error &error) {
            cancellation_rejected =
                std::string(error.what()).find("fhe::FheValue") !=
                std::string::npos;
        }
        SealBackend::set_counting(contexts.eval, false);
        CHECK(cancellation_rejected);
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::serialize(cancelled);
        }));
        const auto counts = SealBackend::counts(contexts.eval);
        CHECK(counts.calls(SealBackend::OperationKind::Add) == 1);

        auto rejected = source;
        const auto rejected_before = rejected;
        auto invalid_term = negated;
        invalid_term.raw.is_ntt_form() = !source.raw.is_ntt_form();
        bool threw = false;
        try {
            add_assign<SealBackend>(contexts.eval, rejected, invalid_term);
        } catch (const std::exception &) {
            threw = true;
        }
        CHECK(threw);
        CHECK(SealBackend::serialize(rejected) ==
              SealBackend::serialize(rejected_before));
        check_same_noise_metadata(rejected, rejected_before);
    });

    runner.run("typed arithmetic recovers transparent public plaintexts",
               [] {
        auto contexts = make_tracked_seal_contexts(3);
        const SlotVector source_slots = slots(17);
        const auto source =
            SealBackend::encrypt(contexts.client, source_slots);

        const auto negative_source =
            SealBackend::negate(contexts.eval, source);
        const auto zero = value_add<SealBackend>(
            contexts.eval,
            FheValue<SealBackend>::from_ciphertext(source),
            FheValue<SealBackend>::from_ciphertext(negative_source));
        CHECK(zero.is_public_zero());

        constexpr std::uint64_t kShift = 9;
        const auto shifted = SealBackend::add_plain_scalar(
            contexts.eval, source, Fp(kShift));
        const auto negative_shifted =
            SealBackend::negate(contexts.eval, shifted);
        const auto public_nonzero = value_add<SealBackend>(
            contexts.eval,
            FheValue<SealBackend>::from_ciphertext(source),
            FheValue<SealBackend>::from_ciphertext(negative_shifted));
        CHECK(public_nonzero.is_public());
        CHECK(public_nonzero.plaintext().is_scalar());
        CHECK(public_nonzero.plaintext().scalar() ==
              Fp(kBaseFieldOrder - kShift));

        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        const auto public_difference = value_sub<SealBackend>(
            contexts.eval,
            FheValue<SealBackend>::from_ciphertext(shifted),
            FheValue<SealBackend>::from_ciphertext(source));
        SealBackend::set_counting(contexts.eval, false);
        CHECK(public_difference.is_public());
        CHECK(public_difference.plaintext().is_scalar());
        CHECK(public_difference.plaintext().scalar() == Fp(kShift));
        CHECK(SealBackend::counts(contexts.eval)
                  .calls(SealBackend::OperationKind::Sub) == 1);
        CHECK(SealBackend::counts(contexts.eval)
                  .calls(SealBackend::OperationKind::Encrypt) == 0);

        ExtensionValue<SealBackend> extension_source;
        extension_source[0] =
            FheValue<SealBackend>::from_ciphertext(source);
        ExtensionValue<SealBackend> extension_negative_shifted;
        extension_negative_shifted[0] =
            FheValue<SealBackend>::from_ciphertext(negative_shifted);
        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        const auto public_extension_sum = extension_add<SealBackend>(
            contexts.eval, extension_source,
            extension_negative_shifted);
        SealBackend::set_counting(contexts.eval, false);
        CHECK(public_extension_sum[0].is_public());
        CHECK(public_extension_sum[0].plaintext().is_scalar());
        CHECK(public_extension_sum[0].plaintext().scalar() ==
              Fp(kBaseFieldOrder - kShift));
        CHECK(SealBackend::counts(contexts.eval)
                  .calls(SealBackend::OperationKind::LogicalExtAdd) == 1);
        CHECK(SealBackend::counts(contexts.eval)
                  .calls(SealBackend::OperationKind::Add) == 1);
        CHECK(SealBackend::counts(contexts.eval)
                  .calls(SealBackend::OperationKind::Encrypt) == 0);

        MixedExtensionAccumulator<SealBackend> accumulator;
        const Fpk alpha = Fpk::from_base(Fp(7));
        const Fpk beta = Fpk::from_base(Fp(11));
        accumulator.accumulate_scaled_base(
            contexts.eval, source, alpha);
        accumulator.accumulate_scaled_base(
            contexts.eval, source, Fpk::zero() - alpha);
        accumulator.accumulate_scaled_base(
            contexts.eval, source, beta);
        const auto result = std::move(accumulator).finish(contexts.eval);
        CHECK(result[0].is_encrypted());
        SlotVector expected = source_slots;
        for (Fp &value : expected) {
            value *= Fp(11);
        }
        CHECK(SealBackend::decrypt(
                  contexts.client, result[0].ciphertext()) == expected);
        for (std::size_t coefficient = 1;
             coefficient < kExtensionDegree; ++coefficient) {
            CHECK(result[coefficient].is_public_zero());
        }

        // The mixed accumulator must preserve a public nonzero created by
        // cancellation of related ciphertexts; it must not request an
        // encrypted zero/nonzero sentinel from the server backend.
        SealBackend::reset_counts(contexts.eval);
        MixedExtensionAccumulator<SealBackend> public_accumulator;
        public_accumulator.accumulate_scaled_base(
            contexts.eval, source, Fpk::one());
        public_accumulator.accumulate_scaled_base(
            contexts.eval, negative_shifted, Fpk::one());
        const auto public_result =
            std::move(public_accumulator).finish(contexts.eval);
        CHECK(public_result[0].is_public());
        CHECK(public_result[0].plaintext().is_scalar());
        CHECK(public_result[0].plaintext().scalar() ==
              Fp(kBaseFieldOrder - kShift));
        for (std::size_t coefficient = 1;
             coefficient < kExtensionDegree; ++coefficient) {
            CHECK(public_result[coefficient].is_public_zero());
        }
        CHECK(SealBackend::counts(contexts.eval)
                  .calls(SealBackend::OperationKind::Encrypt) == 0);

        // At X=2 the one-variable MLE is -low + 2*high. Choosing
        // low=2*high+shift makes that checkpoint a public nonzero and covers
        // the Folded resident prefix path directly.
        const auto doubled = SealBackend::add(contexts.eval, source, source);
        const auto low = SealBackend::add_plain_scalar(
            contexts.eval, doubled, Fp(kShift));
        const std::array<FheValue<SealBackend>, 2> wires{
            FheValue<SealBackend>::from_ciphertext(low),
            FheValue<SealBackend>::from_ciphertext(source)};
        const std::array<Fpk, 1> prefix{Fpk::from_base(Fp(2))};
        SealBackend::reset_counts(contexts.eval);
        const auto partial = partial_evaluate_ciphertext_index_point<SealBackend>(
            contexts.eval, wires, prefix);
        CHECK(partial.size() == 1);
        CHECK(partial.front()[0].is_public());
        CHECK(partial.front()[0].plaintext().is_scalar());
        CHECK(partial.front()[0].plaintext().scalar() ==
              Fp(kBaseFieldOrder - kShift));
        for (std::size_t coefficient = 1;
             coefficient < kExtensionDegree; ++coefficient) {
            CHECK(partial.front()[coefficient].is_public_zero());
        }
        CHECK(SealBackend::counts(contexts.eval)
                  .calls(SealBackend::OperationKind::Encrypt) == 0);
    });

    runner.run("public extension scaling preserves transparent reduction",
               [] {
        auto contexts = make_tracked_seal_contexts(3);
        const SlotVector source_slots = slots(29);
        const auto source =
            SealBackend::encrypt(contexts.client, source_slots);

        // (c0 + c4*x^4)(1 + x^4) has constant coefficient c0-c4.
        // Related ciphertexts c0=Enc(m) and c4=Enc(m)+p therefore leave the
        // public value -p after extension reduction.
        constexpr std::uint64_t kShift = 13;
        const auto shifted = SealBackend::add_plain_scalar(
            contexts.eval, source, Fp(kShift));
        ExtensionValue<SealBackend> mixed;
        mixed[0] = FheValue<SealBackend>::from_ciphertext(source);
        mixed[4] = FheValue<SealBackend>::from_ciphertext(shifted);
        Fpk::Coefficients scalar_coefficients{};
        scalar_coefficients[0] = Fp::one();
        scalar_coefficients[4] = Fp::one();
        const Fpk scalar(scalar_coefficients);

        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        const auto scalar_scaled = scale_extension_value<SealBackend>(
            contexts.eval, mixed, scalar);
        SealBackend::set_counting(contexts.eval, false);
        CHECK(scalar_scaled[0].is_public());
        CHECK(scalar_scaled[0].plaintext().is_scalar());
        CHECK(scalar_scaled[0].plaintext().scalar() ==
              Fp(kBaseFieldOrder - kShift));
        CHECK(SealBackend::counts(contexts.eval)
                  .calls(SealBackend::OperationKind::LogicalExtMulPlain) ==
              1);
        CHECK(SealBackend::counts(contexts.eval)
                  .calls(SealBackend::OperationKind::Encrypt) == 0);

        const std::vector<Fpk> scalar_plaintext =
            read_extension_value<SealBackend>(contexts.client,
                                              scalar_scaled);
        Fpk::Coefficients mixed_coefficients{};
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            mixed_coefficients[0] = source_slots[slot];
            mixed_coefficients[4] = source_slots[slot] + Fp(kShift);
            CHECK(scalar_plaintext[slot] ==
                  Fpk(mixed_coefficients) * scalar);
        }

        std::vector<Fpk> vector_basis;
        SlotVector expected_public_constant;
        vector_basis.reserve(kSlots);
        expected_public_constant.reserve(kSlots);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            const Fp factor(3 + slot);
            Fpk::Coefficients coefficients{};
            coefficients[0] = factor;
            coefficients[4] = factor;
            vector_basis.emplace_back(coefficients);
            expected_public_constant.push_back(
                Fp::zero() - Fp(kShift) * factor);
        }

        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        const auto vector_scaled = scale_extension_value<SealBackend>(
            contexts.eval, mixed, vector_basis);
        SealBackend::set_counting(contexts.eval, false);
        CHECK(vector_scaled[0].is_public());
        CHECK(vector_scaled[0].plaintext().materialize(kSlots) ==
              expected_public_constant);
        CHECK(SealBackend::counts(contexts.eval)
                  .calls(SealBackend::OperationKind::LogicalExtMulPlain) ==
              1);
        CHECK(SealBackend::counts(contexts.eval)
                  .calls(SealBackend::OperationKind::Encrypt) == 0);

        const auto prepared = prepare_fpk_slot_basis<SealBackend>(
            contexts.eval, source, vector_basis);
        MixedExtensionAccumulator<SealBackend> accumulator;
        accumulator.accumulate_extension(contexts.eval, mixed);
        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        const auto prepared_scaled =
            std::move(accumulator).apply_prepared_basis(
                contexts.eval, prepared, vector_basis);
        SealBackend::set_counting(contexts.eval, false);
        CHECK(prepared_scaled[0].is_public());
        CHECK(prepared_scaled[0].plaintext().materialize(kSlots) ==
              expected_public_constant);
        const auto prepared_counts = SealBackend::counts(contexts.eval);
        CHECK(prepared_counts.calls(
                  SealBackend::OperationKind::LogicalExtMulPlain) == 1);
        CHECK(prepared_counts.prepared_extension_promotion_api_calls == 0);
        CHECK(prepared_counts.prepared_extension_basis_api_calls == 0);
        CHECK(prepared_counts.calls(
                  SealBackend::OperationKind::Encrypt) == 0);

        // One encrypted coefficient is still not generally safe for the raw
        // path: x^7(x^2+x^7) contributes -Enc(m) and +Enc(m) to x.
        ExtensionValue<SealBackend> single_coordinate;
        single_coordinate[7] =
            FheValue<SealBackend>::from_ciphertext(source);
        Fpk::Coefficients cancelling_coefficients{};
        cancelling_coefficients[2] = Fp::one();
        cancelling_coefficients[7] = Fp::one();
        const Fpk cancelling_scalar(cancelling_coefficients);
        const auto cancelled = scale_extension_value<SealBackend>(
            contexts.eval, single_coordinate, cancelling_scalar);
        CHECK(cancelled[1].is_public_zero());

        const std::vector<Fpk> cancelling_basis(kSlots,
                                                cancelling_scalar);
        const auto cancelling_prepared =
            prepare_fpk_slot_basis<SealBackend>(
                contexts.eval, source, cancelling_basis);
        MixedExtensionAccumulator<SealBackend> cancelling_accumulator;
        cancelling_accumulator.accumulate_extension(
            contexts.eval, single_coordinate);
        const auto prepared_cancelled =
            std::move(cancelling_accumulator).apply_prepared_basis(
                contexts.eval, cancelling_prepared, cancelling_basis);
        CHECK(prepared_cancelled[1].is_public_zero());
    });

    runner.run("same-level extension addition preserves logical accounting",
               [] {
        auto contexts = make_tracked_seal_contexts(4);
        auto high_left =
            encrypt_private_test_extension(contexts.client,
                                           extension_values(3));
        auto low_term =
            encrypt_private_test_extension(contexts.client,
                                           extension_values(101));
        for (auto &coefficient : high_left) {
            CHECK(coefficient.has_value());
            SealBackend::mod_switch_to_next(
                contexts.eval, *coefficient);
        }
        for (auto &coefficient : low_term) {
            CHECK(coefficient.has_value());
            SealBackend::mod_switch_to_next(
                contexts.eval, *coefficient);
        }
        const auto expected =
            SealBackend::ext_add(contexts.eval, high_left, low_term);
        auto actual = high_left;
        std::array<std::vector<std::uint8_t>, kExtensionDegree> term_before;
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            CHECK(low_term[coefficient].has_value());
            term_before[coefficient] =
                SealBackend::serialize(*low_term[coefficient]);
        }

        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        ext_add_assign<SealBackend>(contexts.eval, actual, low_term);
        SealBackend::set_counting(contexts.eval, false);

        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            CHECK(actual[coefficient].has_value());
            CHECK(expected[coefficient].has_value());
            CHECK(low_term[coefficient].has_value());
            CHECK(SealBackend::serialize(*actual[coefficient]) ==
                  SealBackend::serialize(*expected[coefficient]));
            CHECK(SealBackend::serialize(*low_term[coefficient]) ==
                  term_before[coefficient]);
            check_same_noise_metadata(*actual[coefficient],
                                      *expected[coefficient]);
        }
        const auto counts = SealBackend::counts(contexts.eval);
        CHECK(counts.calls(SealBackend::OperationKind::LogicalExtAdd) == 1);
        CHECK(counts.calls(SealBackend::OperationKind::Add) ==
              kExtensionDegree);
        CHECK(counts.calls(SealBackend::OperationKind::ModSwitch) ==
              0);

        auto mismatched = low_term;
        for (auto &coefficient : mismatched) {
            CHECK(coefficient.has_value());
            SealBackend::mod_switch_to_next(
                contexts.eval, *coefficient);
        }
        bool rejected = false;
        try {
            ext_add_assign<SealBackend>(
                contexts.eval, actual, mismatched);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("base arithmetic decrypt-matches Mock", [&] {
        const SlotVector left = slots(5);
        const SlotVector right = slots(41);
        const SlotVector varying = slots(9);
        const SlotVector scalar(kSlots, Fp(7));
        const SlotVector zero(kSlots, Fp::zero());
        const SlotVector negative_scalar(
            kSlots, Fp(kBaseFieldOrder - 1));
        const auto a = SealBackend::encrypt(seal_contexts.client, left);
        const auto b = SealBackend::encrypt(seal_contexts.client, right);
        const auto ma = MockBackend::encrypt(mock_contexts.client, left);
        const auto mb = MockBackend::encrypt(mock_contexts.client, right);

        CHECK(SealBackend::decrypt(
                  seal_contexts.client,
                  SealBackend::add(seal_contexts.eval, a, b)) ==
              MockBackend::decrypt(
                  mock_contexts.client,
                  MockBackend::add(mock_contexts.eval, ma, mb)));
        CHECK(SealBackend::decrypt(
                  seal_contexts.client,
                  SealBackend::sub(seal_contexts.eval, a, b)) ==
              MockBackend::decrypt(
                  mock_contexts.client,
                  MockBackend::sub(mock_contexts.eval, ma, mb)));
        CHECK(SealBackend::decrypt(
                  seal_contexts.client,
                  SealBackend::mul(seal_contexts.eval, a, b)) ==
              MockBackend::decrypt(
                  mock_contexts.client,
                  MockBackend::mul(mock_contexts.eval, ma, mb)));
        CHECK(SealBackend::decrypt(
                  seal_contexts.client,
                  SealBackend::add_plain(seal_contexts.eval, a, varying)) ==
              MockBackend::decrypt(
                  mock_contexts.client,
                  MockBackend::add_plain(mock_contexts.eval, ma, varying)));
        CHECK(SealBackend::decrypt(
                  seal_contexts.client,
                  SealBackend::mul_plain(seal_contexts.eval, a, scalar)) ==
              MockBackend::decrypt(
                  mock_contexts.client,
                  MockBackend::mul_plain(mock_contexts.eval, ma, scalar)));
        CHECK(SealBackend::decrypt(
                  seal_contexts.client,
                  SealBackend::mul_plain(seal_contexts.eval, a, varying)) ==
              MockBackend::decrypt(
                  mock_contexts.client,
                  MockBackend::mul_plain(mock_contexts.eval, ma, varying)));
        const auto public_zero = value_mul<SealBackend>(
            seal_contexts.eval,
            FheValue<SealBackend>::from_ciphertext(a),
            FheValue<SealBackend>::public_slots(zero));
        CHECK(public_zero.is_public_zero());
        CHECK(materialize_or_decrypt<SealBackend>(
                  seal_contexts.client, public_zero) == zero);
        CHECK(SealBackend::decrypt(
                  seal_contexts.client,
                  SealBackend::mul_plain(
                      seal_contexts.eval, a, negative_scalar)) ==
              MockBackend::decrypt(
                  mock_contexts.client,
                  MockBackend::mul_plain(
                      mock_contexts.eval, ma, negative_scalar)));
    });

    runner.run("scalar plaintext addition avoids a slot vector", [] {
        auto contexts = make_tracked_seal_contexts(4);
        auto left = SealBackend::encrypt(contexts.client, slots(19));
        auto right = SealBackend::encrypt(contexts.client, slots(31));
        SealBackend::mod_switch_to_next(contexts.eval, left);
        SealBackend::mod_switch_to_next(contexts.eval, right);
        const auto source =
            SealBackend::mul_no_relin(contexts.eval, left, right);

        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        const auto scalar = SealBackend::add_plain_scalar(
            contexts.eval, source, Fp(kBaseFieldOrder - 17));
        const auto vector = SealBackend::add_plain(
            contexts.eval, source,
            SlotVector(kSlots, Fp(kBaseFieldOrder - 17)));
        SealBackend::set_counting(contexts.eval, false);

        CHECK(SealBackend::decrypt(contexts.client, scalar) ==
              SealBackend::decrypt(contexts.client, vector));
        CHECK(scalar.raw.parms_id() == source.raw.parms_id());
        CHECK(scalar.raw.size() == source.raw.size());
        CHECK(scalar.raw.correction_factor() ==
              source.raw.correction_factor());
        CHECK(scalar.deterministic_noise_bound.has_value());
        CHECK(vector.deterministic_noise_bound.has_value());
        CHECK(scalar.deterministic_noise_bound->certifies_no_wrap() ==
              vector.deterministic_noise_bound->certifies_no_wrap());

        const SealBackend::OperationCounts counts =
            SealBackend::counts(contexts.eval);
        CHECK(counts.add_plain_scalar_api_calls == 1);
        CHECK(counts.add_plain_vector_api_calls == 1);
        CHECK(counts.add_plain_vector_api_elements == kSlots);
        CHECK(counts.calls(SealBackend::OperationKind::AddPlain) == 2);
    });

    runner.run("raw scalar-zero multiplication requires a public value", [] {
        auto contexts = make_tracked_seal_contexts(4);
        auto left = SealBackend::encrypt(contexts.client, slots(19));
        auto right = SealBackend::encrypt(contexts.client, slots(31));
        SealBackend::mod_switch_to_next(contexts.eval, left);
        SealBackend::mod_switch_to_next(contexts.eval, right);
        left = SealBackend::mul_no_relin(contexts.eval, left, right);

        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        bool rejected = false;
        try {
            (void)SealBackend::mul_plain_scalar(
                contexts.eval, left, Fp::zero());
        } catch (const std::logic_error &error) {
            rejected = std::string(error.what()).find("fhe::FheValue") !=
                       std::string::npos;
        }
        SealBackend::set_counting(contexts.eval, false);
        CHECK(rejected);

        const SealBackend::OperationCounts counts =
            SealBackend::counts(contexts.eval);
        CHECK(counts.mul_plain_scalar_api_calls == 1);
        CHECK(counts.mul_plain_vector_api_calls == 0);
        CHECK(counts.mul_plain_vector_api_elements == 0);
        CHECK(counts.calls(SealBackend::OperationKind::MulPlainScalar) == 0);
        CHECK(counts.calls(SealBackend::OperationKind::MulPlainVector) == 0);
        CHECK(counts.calls(SealBackend::OperationKind::ModSwitch) == 0);
    });

    runner.run("server-preprocessed plaintexts are shared across levels", [] {
        auto contexts = make_tracked_seal_contexts(3);
        const SlotVector multiplier = slots(37);
        CHECK(SealBackend::preprocess_plaintext(
            contexts.eval, multiplier));
        CHECK(!SealBackend::preprocess_plaintext(
            contexts.eval, multiplier));

        const auto stats =
            SealBackend::plaintext_preprocessing_stats(contexts.eval);
        CHECK(stats.logical_plaintexts == 1);
        CHECK(stats.level_representations == 3);
        CHECK(stats.ntt_coefficient_bytes ==
              kSlots * sizeof(std::uint64_t) * (3 + 2 + 1));

        const SlotVector input = slots(91);
        SlotVector expected(kSlots);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            expected[slot] = input[slot] * multiplier[slot];
        }
        auto ciphertext = SealBackend::encrypt(contexts.client, input);
        CHECK(SealBackend::decrypt(
                  contexts.client,
                  SealBackend::mul_plain(
                      contexts.eval, ciphertext, multiplier)) == expected);

        SealBackend::mod_switch_to_next(contexts.eval, ciphertext);
        CHECK(SealBackend::decrypt(
                  contexts.client,
                  SealBackend::mul_plain(
                      contexts.eval, ciphertext, multiplier)) == expected);
    });

    runner.run("one-level Fp basis bypasses the all-level cache", [] {
        auto contexts = make_tracked_seal_contexts(3);
        const SlotVector input = slots(151);
        const SlotVector basis = slots(223);
        auto source = SealBackend::encrypt(contexts.client, input);
        SealBackend::mod_switch_to_next(contexts.eval, source);
        const auto cache_before =
            SealBackend::plaintext_preprocessing_stats(contexts.eval);

        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        const auto prepared = prepare_fp_slot_basis<SealBackend>(
            contexts.eval, source, basis);
        const auto actual = mul_plain_prepared<SealBackend>(
            contexts.eval, source, prepared);
        SealBackend::set_counting(contexts.eval, false);
        const auto cache_after =
            SealBackend::plaintext_preprocessing_stats(contexts.eval);
        const auto counts = SealBackend::counts(contexts.eval);

        SlotVector expected(kSlots);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            expected[slot] = input[slot] * basis[slot];
        }
        CHECK(SealBackend::decrypt(contexts.client, actual) == expected);
        CHECK(cache_after.logical_plaintexts == cache_before.logical_plaintexts);
        CHECK(cache_after.level_representations ==
              cache_before.level_representations);
        CHECK(cache_after.ntt_coefficient_bytes ==
              cache_before.ntt_coefficient_bytes);
        CHECK(prepared.storage.level_representations == 1);
        CHECK(prepared.storage.ntt_coefficient_bytes ==
              kSlots * 2U * sizeof(std::uint64_t));
        CHECK(prepared.storage.host_basis_bytes == 0);
        CHECK(counts.prepared_base_basis_setup_calls == 1);
        CHECK(counts.prepared_base_basis_level_representations == 1);
        CHECK(counts.prepared_base_basis_ntt_bytes_created ==
              prepared.storage.ntt_coefficient_bytes);
        CHECK(counts.prepared_base_basis_api_calls == 1);
        CHECK(counts.mul_plain_vector_api_calls == 0);
        CHECK(counts.mul_plain_vector_api_elements == 0);
        CHECK(counts.calls(SealBackend::OperationKind::MulPlainVector) == 1);

        auto wrong_level = source;
        SealBackend::mod_switch_to_next(contexts.eval, wrong_level);
        CHECK(throws_invalid_argument([&] {
            (void)mul_plain_prepared<SealBackend>(
                contexts.eval, wrong_level, prepared);
        }));
    });

    runner.run("lazy products reject raw public-zero subtraction", [&] {
        auto left = SealBackend::encrypt(seal_contexts.client, slots(2));
        auto right = SealBackend::encrypt(seal_contexts.client, slots(17));
        std::vector<SealBackend::Ciphertext> prepared{left, right};
        mod_switch_to_rns_limb_count<SealBackend>(seal_contexts.eval,
                                                  prepared, 3);
        CHECK(SealBackend::rns_limb_count(seal_contexts.eval, prepared[0]) ==
              3);
        auto product = SealBackend::mul_no_relin(
            seal_contexts.eval, prepared[0], prepared[1]);
        CHECK(product.raw.size() == 3);
        SealBackend::relinearize(seal_contexts.eval, product);
        CHECK(product.raw.size() == 2);

        SealBackend::reset_counts(seal_contexts.eval);
        SealBackend::set_counting(seal_contexts.eval, true);
        bool rejected = false;
        try {
            (void)SealBackend::sub(
                seal_contexts.eval, prepared[0], prepared[0]);
        } catch (const std::logic_error &error) {
            rejected = std::string(error.what()).find("fhe::FheValue") !=
                       std::string::npos;
        }
        SealBackend::set_counting(seal_contexts.eval, false);
        CHECK(rejected);
        const SealBackend::OperationCounts zero_counts =
            SealBackend::counts(seal_contexts.eval);
        CHECK(zero_counts.calls(SealBackend::OperationKind::Sub) == 0);
        CHECK(zero_counts.calls(SealBackend::OperationKind::ModSwitch) == 0);
    });

    runner.run("copied ciphertext values cancel without raw FHE work", [&] {
        const FheValue<SealBackend> left =
            FheValue<SealBackend>::from_ciphertext(
                SealBackend::encrypt(seal_contexts.client, slots(29)));
        const FheValue<SealBackend> copied = left;

        SealBackend::reset_counts(seal_contexts.eval);
        SealBackend::set_counting(seal_contexts.eval, true);
        const FheValue<SealBackend> difference =
            value_sub<SealBackend>(seal_contexts.eval, left, copied);
        SealBackend::set_counting(seal_contexts.eval, false);

        CHECK(difference.is_public_zero());
        const SealBackend::OperationCounts counts =
            SealBackend::counts(seal_contexts.eval);
        CHECK(counts.calls(SealBackend::OperationKind::Sub) == 0);
        CHECK(counts.calls(SealBackend::OperationKind::Encrypt) == 0);
    });

    runner.run("grid rotations and fold match the plaintext grid", [&] {
        const SlotVector input = slots(73);
        const auto ciphertext =
            SealBackend::encrypt(seal_contexts.client, input);
        for (std::size_t step : {std::size_t{0}, std::size_t{1},
                                 std::size_t{5}, kSlots / 2 - 1,
                                 kSlots / 2, kSlots / 2 + 1, kSlots - 1}) {
            CHECK(SealBackend::decrypt(
                      seal_contexts.client,
                      SealBackend::rotate(seal_contexts.eval, ciphertext,
                                          step)) ==
                  grid_rotate(input, step));
        }
        Fp sum = Fp::zero();
        for (const Fp &value : input) {
            sum += value;
        }
        CHECK(SealBackend::decrypt(
                  seal_contexts.client,
                  SealBackend::fold(seal_contexts.eval, ciphertext)) ==
              SlotVector(kSlots, sum));

        const auto transparent_fold =
            value_fold<TransparentFoldProbeBackend>(
                seal_contexts.eval,
                FheValue<TransparentFoldProbeBackend>::from_ciphertext(
                    ciphertext));
        CHECK(transparent_fold.is_public_zero());
    });

    runner.run("extension multiplication decrypts exactly", [&] {
        const std::vector<Fpk> left = extension_values(3);
        const std::vector<Fpk> right = extension_values(101);
        const auto encrypted_left =
            encrypt_private_test_extension(seal_contexts.client, left);
        const auto encrypted_right =
            encrypt_private_test_extension(seal_contexts.client, right);
        const auto product = SealBackend::ext_mul(
            seal_contexts.eval, encrypted_left, encrypted_right);
        const std::vector<Fpk> decrypted =
            decrypt_extension<SealBackend>(seal_contexts.client, product);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            CHECK(decrypted[slot] == left[slot] * right[slot]);
        }
    });

    runner.run("extension reduction keeps exact cancellation sparse", [&] {
        const auto left_base =
            SealBackend::encrypt(seal_contexts.client, slots(13));
        const auto right_base =
            SealBackend::encrypt(seal_contexts.client, slots(71));
        SealBackend::ExtCiphertext left{};
        SealBackend::ExtCiphertext right{};
        left[0] = left_base;
        left[4] = left_base;
        right[0] = right_base;
        right[4] = right_base;

        const auto encrypted_product = SealBackend::ext_mul_no_relin(
            seal_contexts.eval, left, right);
        CHECK(!encrypted_product[0].has_value());
        CHECK(encrypted_product[3].has_value());
        CHECK(encrypted_product[4].has_value());

        PlainExtensionScalar scalar_plaintext{};
        scalar_plaintext[0] = Fp::one();
        scalar_plaintext[4] = Fp::one();
        const auto scalar_product = SealBackend::ext_mul_plain_scalar(
            seal_contexts.eval, left, scalar_plaintext);
        CHECK(!scalar_product[0].has_value());
        CHECK(scalar_product[3].has_value());
        CHECK(scalar_product[4].has_value());

        PlainExtension vector_plaintext{};
        for (SlotVector &coefficient : vector_plaintext) {
            coefficient.assign(kSlots, Fp::zero());
        }
        vector_plaintext[0].assign(kSlots, Fp::one());
        vector_plaintext[4].assign(kSlots, Fp::one());
        const auto vector_product = SealBackend::ext_mul_plain(
            seal_contexts.eval, left, vector_plaintext);
        CHECK(!vector_product[0].has_value());
        CHECK(vector_product[3].has_value());
        CHECK(vector_product[4].has_value());

        const auto prepared = SealBackend::prepare_extension_slot_basis(
            seal_contexts.eval, left_base, vector_plaintext);
        const auto prepared_product = SealBackend::ext_mul_plain_prepared(
            seal_contexts.eval, left, prepared);
        CHECK(!prepared_product[0].has_value());
        CHECK(prepared_product[3].has_value());
        CHECK(prepared_product[4].has_value());
    });

    runner.run("public-zero extension coordinates stay symbolic", [&] {
        const std::vector<Fpk> private_zero_values(
            kSlots, Fpk::zero());
        const auto private_zero = encrypt_private_test_extension(
            seal_contexts.client, private_zero_values);
        CHECK(std::all_of(
            private_zero.begin(), private_zero.end(),
            [](const auto &coefficient) {
                return coefficient.has_value();
            }));

        const SealBackend::ExtCiphertext public_zero{};
        SealBackend::reset_counts(seal_contexts.eval);
        SealBackend::set_counting(seal_contexts.eval, true);
        const auto added = SealBackend::ext_add(
            seal_contexts.eval, public_zero, private_zero);
        const auto subtracted = SealBackend::ext_sub(
            seal_contexts.eval, private_zero, public_zero);
        const auto multiplied = SealBackend::ext_mul(
            seal_contexts.eval, public_zero, private_zero);
        const auto scaled = scale_extension<SealBackend>(
            seal_contexts.eval, private_zero, Fpk::zero());
        SealBackend::set_counting(seal_contexts.eval, false);

        CHECK(std::all_of(
            added.begin(), added.end(), [](const auto &coefficient) {
                return coefficient.has_value();
            }));
        CHECK(std::all_of(
            subtracted.begin(), subtracted.end(),
            [](const auto &coefficient) {
                return coefficient.has_value();
            }));
        CHECK(std::none_of(
            multiplied.begin(), multiplied.end(),
            [](const auto &coefficient) {
                return coefficient.has_value();
            }));
        CHECK(std::none_of(
            scaled.begin(), scaled.end(),
            [](const auto &coefficient) {
                return coefficient.has_value();
            }));
        CHECK(decrypt_extension<SealBackend>(seal_contexts.client, added) ==
              private_zero_values);
        CHECK(decrypt_extension<SealBackend>(seal_contexts.client,
                                             subtracted) ==
              private_zero_values);
        const SealBackend::OperationCounts counts =
            SealBackend::counts(seal_contexts.eval);
        CHECK(counts.calls(SealBackend::OperationKind::Add) == 0);
        CHECK(counts.calls(SealBackend::OperationKind::Sub) == 0);
        CHECK(counts.calls(SealBackend::OperationKind::MulNoRelin) == 0);
        CHECK(counts.calls(SealBackend::OperationKind::MulPlainScalar) == 0);
        CHECK(counts.calls(SealBackend::OperationKind::MulPlainVector) == 0);
        CHECK(counts.calls(SealBackend::OperationKind::Relinearize) == 0);
    });

    runner.run("scalar extension helpers avoid slot plaintext inputs", [&] {
        const SlotVector base = slots(37);
        const Fpk scalar = extension_values(211).front();
        const auto base_ciphertext =
            SealBackend::encrypt(seal_contexts.client, base);

        SealBackend::reset_counts(seal_contexts.eval);
        SealBackend::set_counting(seal_contexts.eval, true);
        const auto promoted = promote_scale<SealBackend>(
            seal_contexts.eval, base_ciphertext, scalar);
        SealBackend::set_counting(seal_contexts.eval, false);
        const SealBackend::OperationCounts promotion_counts =
            SealBackend::counts(seal_contexts.eval);
        CHECK(promotion_counts.mul_plain_scalar_api_calls ==
              kExtensionDegree);
        CHECK(promotion_counts.mul_plain_vector_api_calls == 0);
        CHECK(promotion_counts.mul_plain_vector_api_elements == 0);
        CHECK(promotion_counts.calls(
                  SealBackend::OperationKind::MulPlainScalar) ==
              kExtensionDegree);
        CHECK(promotion_counts.calls(
                  SealBackend::OperationKind::MulPlainVector) == 0);
        const std::vector<Fpk> promoted_values =
            decrypt_extension<SealBackend>(seal_contexts.client, promoted);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            CHECK(promoted_values[slot] == scalar * base[slot]);
        }

        const std::vector<Fpk> extension = extension_values(307);
        const auto encrypted =
            encrypt_private_test_extension(seal_contexts.client, extension);
        SealBackend::reset_counts(seal_contexts.eval);
        SealBackend::set_counting(seal_contexts.eval, true);
        const auto scaled = scale_extension<SealBackend>(
            seal_contexts.eval, encrypted, scalar);
        SealBackend::set_counting(seal_contexts.eval, false);
        const SealBackend::OperationCounts scale_counts =
            SealBackend::counts(seal_contexts.eval);
        CHECK(scale_counts.calls(
                  SealBackend::OperationKind::LogicalExtMulPlain) == 1);
        CHECK(scale_counts.mul_plain_scalar_api_calls ==
              kExtensionDegree * kExtensionDegree);
        CHECK(scale_counts.mul_plain_vector_api_calls == 0);
        CHECK(scale_counts.mul_plain_vector_api_elements == 0);
        const std::vector<Fpk> scaled_values =
            decrypt_extension<SealBackend>(seal_contexts.client, scaled);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            CHECK(scaled_values[slot] == extension[slot] * scalar);
        }
    });

    runner.run("one-level prepared Fpk basis avoids online encoding", [&] {
        const SlotVector base = slots(73);
        const std::vector<Fpk> basis = extension_values(401);
        const Fpk scalar = extension_values(509).front();
        const auto source =
            SealBackend::encrypt(seal_contexts.client, base);

        SealBackend::reset_counts(seal_contexts.eval);
        SealBackend::set_counting(seal_contexts.eval, true);
        const auto prepared = prepare_fpk_slot_basis<SealBackend>(
            seal_contexts.eval, source, basis);
        const auto aggregate = promote_scale<SealBackend>(
            seal_contexts.eval, source, scalar);
        const auto product = scale_extension_prepared<SealBackend>(
            seal_contexts.eval, aggregate, prepared);
        SealBackend::set_counting(seal_contexts.eval, false);

        const std::vector<Fpk> decrypted =
            decrypt_extension<SealBackend>(seal_contexts.client, product);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            CHECK(decrypted[slot] ==
                  (scalar * base[slot]) * basis[slot]);
        }
        const auto counts = SealBackend::counts(seal_contexts.eval);
        CHECK(counts.prepared_extension_basis_setup_calls == 1);
        CHECK(counts.prepared_extension_basis_api_calls == 1);
        CHECK(counts.prepared_extension_basis_level_representations ==
              prepared.storage.level_representations);
        CHECK(counts.prepared_extension_basis_ntt_bytes_created ==
              prepared.storage.ntt_coefficient_bytes);
        CHECK(prepared.storage.level_representations > 0);
        CHECK(prepared.storage.level_representations <= kExtensionDegree);
        CHECK(prepared.storage.ntt_coefficient_bytes > 0);
        CHECK(prepared.storage.host_basis_bytes == 0);
        CHECK(counts.mul_plain_vector_api_calls == 0);
        CHECK(counts.mul_plain_vector_api_elements == 0);
        CHECK(counts.calls(SealBackend::OperationKind::MulPlainScalar) ==
              kExtensionDegree);
        CHECK(counts.calls(SealBackend::OperationKind::MulPlainVector) ==
              prepared.storage.level_representations *
                  kExtensionDegree);

        auto wrong_level = aggregate;
        for (auto &coefficient : wrong_level) {
            CHECK(coefficient.has_value());
            SealBackend::mod_switch_to_next(seal_contexts.eval,
                                            *coefficient);
        }
        bool rejected = false;
        try {
            (void)scale_extension_prepared<SealBackend>(
                seal_contexts.eval, wrong_level, prepared);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("prepared promotion has a distinct API counter", [&] {
        const SlotVector base = slots(83);
        const std::vector<Fpk> basis = extension_values(419);
        const auto source =
            SealBackend::encrypt(seal_contexts.client, base);
        const auto prepared = prepare_fpk_slot_basis<SealBackend>(
            seal_contexts.eval, source, basis);

        SealBackend::reset_counts(seal_contexts.eval);
        SealBackend::set_counting(seal_contexts.eval, true);
        const auto promoted = promote_scale_prepared<SealBackend>(
            seal_contexts.eval, source, prepared);
        SealBackend::set_counting(seal_contexts.eval, false);

        const auto counts = SealBackend::counts(seal_contexts.eval);
        CHECK(counts.prepared_extension_promotion_api_calls == 1);
        CHECK(counts.prepared_extension_basis_api_calls == 0);
        CHECK(counts.calls(
                  SealBackend::OperationKind::LogicalExtMulPlain) == 0);

        const std::vector<Fpk> decrypted =
            decrypt_extension<SealBackend>(seal_contexts.client,
                                           promoted);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            CHECK(decrypted[slot] == basis[slot] * base[slot]);
        }
    });

    runner.run("prepared Fpk basis accepts size-three ciphertexts", [&] {
        const std::vector<Fpk> left = extension_values(613);
        const std::vector<Fpk> right = extension_values(809);
        const std::vector<Fpk> basis = extension_values(1009);
        const auto encrypted_left =
            encrypt_private_test_extension(seal_contexts.client, left);
        const auto encrypted_right =
            encrypt_private_test_extension(seal_contexts.client, right);
        CHECK(encrypted_left.front().has_value());
        const auto prepared = prepare_fpk_slot_basis<SealBackend>(
            seal_contexts.eval, *encrypted_left.front(), basis);

        const auto raw_product = SealBackend::ext_mul_no_relin(
            seal_contexts.eval, encrypted_left, encrypted_right);
        for (const auto &coefficient : raw_product) {
            CHECK(coefficient.has_value());
            CHECK(coefficient->raw.size() == 3);
        }
        auto prepared_after = scale_extension_prepared<SealBackend>(
            seal_contexts.eval, raw_product, prepared);
        for (const auto &coefficient : prepared_after) {
            CHECK(coefficient.has_value());
            CHECK(coefficient->raw.size() == 3);
        }
        SealBackend::ext_relinearize(seal_contexts.eval, prepared_after);

        const auto prepared_right = scale_extension_prepared<SealBackend>(
            seal_contexts.eval, encrypted_right, prepared);
        auto prepared_before = SealBackend::ext_mul_no_relin(
            seal_contexts.eval, encrypted_left, prepared_right);
        SealBackend::ext_relinearize(seal_contexts.eval, prepared_before);
        CHECK(decrypt_extension<SealBackend>(seal_contexts.client,
                                             prepared_after) ==
              decrypt_extension<SealBackend>(seal_contexts.client,
                                             prepared_before));
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            CHECK(prepared_after[coefficient].has_value());
            CHECK(prepared_before[coefficient].has_value());
            CHECK(prepared_after[coefficient]->noise_loss_bits ==
                  prepared_before[coefficient]->noise_loss_bits);
        }
    });

    runner.run("fixed round packing decrypts two extension scalars", [&] {
        const std::array<Fpk, 2> expected{
            extension_values(211).front(),
            extension_values(307).front()};
        std::array<ExtensionValue<SealBackend>, 2> replicated{};
        for (std::size_t index = 0; index < expected.size(); ++index) {
            replicated[index] = ExtensionValue<SealBackend>(
                encrypt_private_test_extension(
                    seal_contexts.client,
                    std::vector<Fpk>(kSlots, expected[index])));
        }
        SealBackend::reset_counts(seal_contexts.eval);
        SealBackend::set_counting(seal_contexts.eval, true);
        SealBackend::preprocess_fixed_message_cells(seal_contexts.eval);
        const auto setup_counts = SealBackend::counts(seal_contexts.eval);
        CHECK(setup_counts.fixed_message_basis_setup_calls ==
              kFixedMessageCellCount);
        SealBackend::reset_counts(seal_contexts.eval);
        const auto packed =
            pack_replicated_extension_values<SealBackend>(
                seal_contexts.eval, replicated);
        SealBackend::set_counting(seal_contexts.eval, false);
        CHECK(unpack_extension_scalars<SealBackend>(
                  seal_contexts.client, packed, expected.size()) ==
              std::vector<Fpk>(expected.begin(), expected.end()));
        CHECK(packed.is_encrypted());
        CHECK(SealBackend::invariant_noise_budget(
                  seal_contexts.client, packed.ciphertext()) > 0);
        const auto counts = SealBackend::counts(seal_contexts.eval);
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

    runner.run("centered coefficient conversion round trips exactly", [&] {
        SlotVector expected(kSlots, Fp::zero());
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            expected[slot] = Fp(97 * slot + 31);
        }
        const auto coefficients =
            SealBackend::encode_centered_plaintext_coefficients(
                seal_contexts.eval, expected);
        CHECK(SealBackend::decode_centered_plaintext_coefficients(
                  seal_contexts.eval, coefficients) == expected);

        std::vector<std::int64_t> small_coefficients(kSlots);
        for (std::size_t coefficient = 0; coefficient < kSlots;
             ++coefficient) {
            small_coefficients[coefficient] =
                static_cast<std::int64_t>(coefficient % 41) - 20;
        }
        const SlotVector digit_slots =
            SealBackend::decode_centered_plaintext_coefficients(
                seal_contexts.eval, small_coefficients);
        CHECK(SealBackend::encode_centered_plaintext_coefficients(
                  seal_contexts.eval, digit_slots) == small_coefficients);

        auto malformed = coefficients;
        malformed.front() =
            static_cast<std::int64_t>((kBaseFieldOrder - 1) / 2 + 1);
        bool rejected = false;
        try {
            (void)SealBackend::decode_centered_plaintext_coefficients(
                seal_contexts.eval, malformed);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("BGV multiplication center-lifts negative digits", [&] {
        auto ciphertext = SealBackend::encrypt(
            seal_contexts.client, slots(541));
        SealBackend::mod_switch_to_lowest(seal_contexts.eval, ciphertext);
        SealBackend::normalize_for_coefficient_commitment(
            seal_contexts.eval, ciphertext);
        const auto before =
            SealBackend::partial_decryption_centered_coefficients(
                seal_contexts.client, ciphertext);

        std::vector<std::int64_t> negative_one(kSlots, 0);
        negative_one.front() = -1;
        const SlotVector multiplier =
            SealBackend::decode_centered_plaintext_coefficients(
                seal_contexts.eval, negative_one);
        const auto product = SealBackend::mul_plain(
            seal_contexts.eval, ciphertext, multiplier);
        const auto after =
            SealBackend::partial_decryption_centered_coefficients(
                seal_contexts.client, product);
        CHECK(after.size() == before.size());
        for (std::size_t coefficient = 0; coefficient < before.size();
             ++coefficient) {
            CHECK(after[coefficient] == -before[coefficient]);
        }
    });

    runner.run("coefficient normalization preserves BGV plaintext", [&] {
        auto ciphertext = SealBackend::mul(
            seal_contexts.eval,
            SealBackend::encrypt(seal_contexts.client, slots(13)),
            SealBackend::encrypt(seal_contexts.client, slots(19)));
        SealBackend::mod_switch_to_lowest(seal_contexts.eval, ciphertext);
        CHECK(SealBackend::is_normalized_for_coefficient_commitment(
            ciphertext));
        const SlotVector expected =
            SealBackend::decrypt(seal_contexts.client, ciphertext);

        // Build an equivalent noncanonical representation explicitly. The
        // LCM-aware modulus chain keeps ordinary mod-switches at factor one.
        constexpr std::uint64_t kArtificialCorrection = 7;
        ciphertext = SealBackend::mul_plain(
            seal_contexts.eval, ciphertext,
            SlotVector(kSlots, Fp(kArtificialCorrection)));
        ciphertext.raw.correction_factor() = kArtificialCorrection;
        CHECK(!SealBackend::is_normalized_for_coefficient_commitment(
            ciphertext));
        CHECK(SealBackend::decrypt(seal_contexts.client, ciphertext) ==
              expected);
        SealBackend::normalize_for_coefficient_commitment(
            seal_contexts.eval, ciphertext);
        CHECK(SealBackend::is_normalized_for_coefficient_commitment(
            ciphertext));
        CHECK(SealBackend::decrypt(seal_contexts.client, ciphertext) ==
              expected);

        // Canonicalization is idempotent and the exact partial-decryption
        // threshold has an inclusive boundary.
        SealBackend::normalize_for_coefficient_commitment(
            seal_contexts.eval, ciphertext);
        const std::uint64_t norm =
            SealBackend::partial_decryption_infinity_norm(
                seal_contexts.client, ciphertext);
        const std::uint64_t canonical_error =
            SealBackend::canonical_error_infinity_norm(
                seal_contexts.eval, seal_contexts.client, ciphertext);
        const auto public_verifier =
            SealBackend::make_public_verifier_context(
                seal_contexts.eval);
        CHECK(SealBackend::canonical_error_infinity_norm(
                  public_verifier, seal_contexts.client, ciphertext) ==
              canonical_error);
        CHECK(norm > 0);
        CHECK(canonical_error > 0);
        CHECK(canonical_error < norm);
        CHECK(SealBackend::partial_decryption_within_bound(
            seal_contexts.client, ciphertext, norm));
        CHECK(!SealBackend::partial_decryption_within_bound(
            seal_contexts.client, ciphertext, norm - 1));

        auto wrong_size = ciphertext;
        wrong_size.raw.resize(*seal_contexts.eval.context,
                              wrong_size.raw.parms_id(), 3);
        CHECK(SealBackend::correction_factor_is_one(wrong_size));
        CHECK(!SealBackend::is_normalized_for_coefficient_commitment(
            wrong_size));
    });

    runner.run("partial-decryption norm rejects a non-bottom ciphertext", [&] {
        auto ciphertext =
            SealBackend::encrypt(seal_contexts.client, slots(23));
        CHECK(SealBackend::correction_factor_is_one(ciphertext));
        CHECK(!SealBackend::is_normalized_for_coefficient_commitment(
            ciphertext));
        bool rejected = false;
        try {
            (void)SealBackend::partial_decryption_infinity_norm(
                seal_contexts.client, ciphertext);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);

        rejected = false;
        try {
            SealBackend::normalize_for_coefficient_commitment(
                seal_contexts.eval, ciphertext);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("serialization, counters, and noise diagnostics are live", [&] {
        SealBackend::reset_counts(seal_contexts.eval);
        SealBackend::set_counting(seal_contexts.eval, true);
        const auto left =
            SealBackend::encrypt(seal_contexts.client, slots(7));
        const auto right =
            SealBackend::encrypt(seal_contexts.client, slots(29));
        const int fresh_noise = SealBackend::invariant_noise_budget(
            seal_contexts.client, left);
        auto product =
            SealBackend::mul(seal_contexts.eval, left, right);
        const int product_noise = SealBackend::invariant_noise_budget(
            seal_contexts.client, product);
        const std::vector<std::uint8_t> top =
            SealBackend::serialize(product);
        CHECK(top == SealBackend::serialize(product));
        SealBackend::mod_switch_to_lowest(seal_contexts.eval, product);
        const std::vector<std::uint8_t> bottom =
            SealBackend::serialize(product);
        (void)SealBackend::decrypt(seal_contexts.client, product);
        SealBackend::set_counting(seal_contexts.eval, false);

        CHECK(fresh_noise > 0);
        CHECK(product_noise > 0);
        CHECK(product_noise < fresh_noise);
        CHECK(bottom.size() < top.size());
        const auto counts = SealBackend::counts(seal_contexts.eval);
        CHECK(counts.calls(SealBackend::OperationKind::Encrypt) == 2);
        CHECK(counts.calls(SealBackend::OperationKind::MulNoRelin) == 1);
        CHECK(counts.calls(SealBackend::OperationKind::Relinearize) == 1);
        CHECK(counts.calls(SealBackend::OperationKind::ModSwitch) == 4);
        CHECK(counts.calls(SealBackend::OperationKind::Decrypt) == 1);
        CHECK(counts.buckets(SealBackend::OperationKind::MulNoRelin).at(5) ==
              1);
    });

    runner.run("SEAL storage roundtrip preserves backend state", [&] {
        const auto left =
            SealBackend::encrypt(seal_contexts.client, slots(43));
        const auto right =
            SealBackend::encrypt(seal_contexts.client, slots(71));
        auto ciphertext =
            SealBackend::mul(seal_contexts.eval, left, right);
        SealBackend::mod_switch_to_next(seal_contexts.eval, ciphertext);
        CHECK(ciphertext.noise_loss_bits != 0);

        const std::vector<std::uint8_t> encoded =
            SealBackend::serialize_for_storage(seal_contexts.eval,
                                               ciphertext);
        const SealBackend::Ciphertext decoded =
            SealBackend::deserialize_from_storage(seal_contexts.eval,
                                                  encoded);
        const SealBackend::Ciphertext private_decoded =
            deserialize_validated_private_ciphertext<SealBackend>(
                seal_contexts.eval, encoded);
        CHECK(decoded.noise_loss_bits == ciphertext.noise_loss_bits);
        CHECK(private_decoded.noise_loss_bits ==
              ciphertext.noise_loss_bits);
        CHECK(!decoded.deterministic_noise_bound.has_value());
        CHECK(!private_decoded.deterministic_noise_bound.has_value());
        CHECK(SealBackend::serialize(decoded) ==
              SealBackend::serialize(ciphertext));
        CHECK(SealBackend::serialize(private_decoded) ==
              SealBackend::serialize(ciphertext));
        CHECK(SealBackend::decrypt(seal_contexts.client, decoded) ==
              SealBackend::decrypt(seal_contexts.client, ciphertext));
        CHECK(SealBackend::serialize_for_storage(seal_contexts.eval,
                                                 decoded) == encoded);
    });

    runner.run("validated-private SEAL decode preserves every RNS level",
               [&] {
        auto ciphertext =
            SealBackend::encrypt(seal_contexts.client, slots(59));
        for (;;) {
            const std::size_t expected_limbs =
                SealBackend::rns_limb_count(seal_contexts.eval,
                                             ciphertext);
            const std::vector<std::uint8_t> encoded =
                SealBackend::serialize_for_storage(seal_contexts.eval,
                                                   ciphertext);
            const SealBackend::Ciphertext strict =
                SealBackend::deserialize_from_storage(seal_contexts.eval,
                                                      encoded);
            const SealBackend::Ciphertext private_decoded =
                deserialize_validated_private_ciphertext<SealBackend>(
                    seal_contexts.eval, encoded);
            CHECK(SealBackend::rns_limb_count(seal_contexts.eval, strict) ==
                  expected_limbs);
            CHECK(SealBackend::rns_limb_count(seal_contexts.eval,
                                              private_decoded) ==
                  expected_limbs);
            CHECK(SealBackend::serialize(private_decoded) ==
                  SealBackend::serialize(strict));
            CHECK(SealBackend::decrypt(seal_contexts.client,
                                       private_decoded) == slots(59));
            if (expected_limbs == 1) {
                break;
            }
            SealBackend::mod_switch_to_next(seal_contexts.eval,
                                            ciphertext);
        }
    });

    runner.run("SEAL storage rejects corrupt and lossy encodings", [&] {
        const auto ciphertext =
            SealBackend::encrypt(seal_contexts.client, slots(97));
        const std::vector<std::uint8_t> encoded =
            SealBackend::serialize_for_storage(seal_contexts.eval,
                                               ciphertext);

        auto truncated = encoded;
        truncated.pop_back();
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_from_storage(seal_contexts.eval,
                                                        truncated);
        }));
        CHECK(throws_invalid_argument([&] {
            (void)deserialize_validated_private_ciphertext<SealBackend>(
                seal_contexts.eval, truncated);
        }));

        auto trailing = encoded;
        trailing.push_back(0);
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_from_storage(seal_contexts.eval,
                                                        trailing);
        }));

        auto wrong_version = encoded;
        wrong_version[8] = 2;
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_from_storage(
                seal_contexts.eval, wrong_version);
        }));

        auto internal_trailing = encoded;
        internal_trailing.push_back(0);
        constexpr std::size_t kRawLengthOffset =
            8 + 1 + 1 + 32 + 8;
        for (std::size_t byte = kRawLengthOffset;
             byte < kRawLengthOffset + 8; ++byte) {
            if (++internal_trailing[byte] != 0) {
                break;
            }
        }
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_from_storage(
                seal_contexts.eval, internal_trailing);
        }));

        auto corrupt_raw = encoded;
        constexpr std::size_t kRawOffset = kRawLengthOffset + 8;
        corrupt_raw[kRawOffset] ^= 0xffU;
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_from_storage(seal_contexts.eval,
                                                        corrupt_raw);
        }));

        const auto incompatible = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 4,
            .bits_per_data_prime = 60,
            .special_prime_bits = 60,
            .security_level = seal::sec_level_type::none,
        });
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_from_storage(incompatible.eval,
                                                        encoded);
        }));

        const auto other_key = make_seal_contexts();
        CHECK(SealBackend::storage_context_id(other_key.eval) !=
              SealBackend::storage_context_id(seal_contexts.eval));
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_from_storage(other_key.eval,
                                                        encoded);
        }));

        const auto tracked = make_tracked_seal_contexts();
        const auto bounded =
            SealBackend::encrypt(tracked.client, slots(113));
        CHECK(bounded.deterministic_noise_bound.has_value());
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::serialize_for_storage(tracked.eval,
                                                     bounded);
        }));
    });

    return runner.summary();
}
