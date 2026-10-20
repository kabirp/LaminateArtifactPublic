/// @file test_deterministic_noise.cpp
/// @brief Exact arithmetic and BGV-rule tests for hard noise bounds.

#include "test_helpers.hpp"

#include "laminate/fhe/noise/deterministic.hpp"
#include "laminate/params.hpp"

#include <array>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;

namespace {

constexpr std::uint64_t kQ0 = 1'152'921'422'732'787'713ULL;
constexpr std::uint64_t kQ1 = 1'152'921'409'847'689'217ULL;
constexpr std::uint64_t kQ2 = 1'152'921'396'962'590'721ULL;
constexpr std::uint64_t kQk = 1'152'921'435'617'886'209ULL;

DeterministicNoisePolicy toy_policy() {
    return DeterministicNoisePolicy{
        .ring_degree = 16,
        .plaintext_modulus = kBaseFieldOrder,
        .secret_hamming_weight_upper = 16,
        .sampled_error_coefficient_bound = 21,
    };
}

bool natural_decode_rejects(
    const std::vector<std::uint8_t> &encoded) {
    try {
        (void)decode_canonical_natural_magnitude(encoded);
        return false;
    } catch (const std::invalid_argument &) {
        return true;
    }
}

void write_u64(std::vector<std::uint8_t> &encoded, std::size_t offset,
               std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        encoded.at(offset + byte) = static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff});
    }
}

} // namespace

int main() {
    test::Runner runner("test_deterministic_noise");

    runner.run("natural magnitudes retain carries and exact division", [] {
        const NaturalMagnitude maximum(
            std::numeric_limits<std::uint64_t>::max());
        const NaturalMagnitude squared = NaturalMagnitude::multiply(
            maximum, maximum);
        CHECK(squared.bit_count() == 128);
        CHECK(!squared.fits_u64());

        const NaturalMagnitude recovered = NaturalMagnitude::divide_floor(
            squared, std::numeric_limits<std::uint64_t>::max());
        CHECK(recovered == maximum);
        CHECK(NaturalMagnitude::divide_ceil(NaturalMagnitude(17), 8)
                  .to_u64() == 3);
        CHECK(NaturalMagnitude::divide_floor(NaturalMagnitude(17), 8)
                  .to_u64() == 2);
    });

    runner.run("natural magnitude canonical decoding round trips", [] {
        const NaturalMagnitude maximum(
            std::numeric_limits<std::uint64_t>::max());
        const std::array<NaturalMagnitude, 3> values{
            NaturalMagnitude(), maximum,
            NaturalMagnitude::multiply(maximum, maximum),
        };
        for (const NaturalMagnitude &value : values) {
            const std::vector<std::uint8_t> encoded =
                encode_canonical(value);
            CHECK(decode_canonical_natural_magnitude(encoded) == value);
            CHECK(encode_canonical(
                      decode_canonical_natural_magnitude(encoded)) ==
                  encoded);
        }
    });

    runner.run("natural magnitude decoder rejects malformed encodings", [] {
        const std::vector<std::uint8_t> canonical =
            encode_canonical(NaturalMagnitude(9));

        for (std::size_t prefix = 0; prefix < canonical.size(); ++prefix) {
            CHECK(natural_decode_rejects(std::vector<std::uint8_t>(
                canonical.begin(), canonical.begin() + prefix)));
        }

        std::vector<std::uint8_t> trailing = canonical;
        trailing.push_back(0);
        CHECK(natural_decode_rejects(trailing));

        std::vector<std::uint8_t> nonnormalized = canonical;
        write_u64(nonnormalized, 8, 0);
        CHECK(natural_decode_rejects(nonnormalized));

        std::vector<std::uint8_t> excessive_count(8, 0);
        write_u64(excessive_count, 0, (std::uint64_t{1} << 16U) + 1U);
        CHECK(natural_decode_rejects(excessive_count));
    });

    runner.run("fresh asymmetric bound follows the pinned support", [] {
        const auto policy = toy_policy();
        const auto bound = bound_fresh_asymmetric_encryption(
            policy, policy.plaintext_radius(), std::array{kQ0, kQ1});

        const std::uint64_t beta = 21 * (1 + 16 + 16);
        const std::uint64_t expected =
            policy.plaintext_radius() + kBaseFieldOrder * beta;
        CHECK(bound.partial_decryption_bound.to_u64() == expected);
        CHECK(bound.operation_count == 1);
        CHECK(bound.certifies_no_wrap());
        CHECK(canonical_error_bound(policy,
                                    bound.partial_decryption_bound)
                  .to_u64() == beta);
    });

    runner.run("ring operations use one common partial-decryption unit", [] {
        const auto policy = toy_policy();
        const auto fresh = bound_fresh_asymmetric_encryption(
            policy, 0, std::array{kQ0, kQ1, kQ2});
        const auto sum = bound_addition(
            fresh, fresh, std::array{kQ0, kQ1, kQ2});
        CHECK(sum.partial_decryption_bound.to_u64() ==
              2 * fresh.partial_decryption_bound.to_u64());

        const auto plain = bound_plaintext_multiplication(
            sum, 9, std::array{kQ0, kQ1, kQ2});
        CHECK(plain.partial_decryption_bound.to_u64() ==
              18 * fresh.partial_decryption_bound.to_u64());

        const auto product = bound_ciphertext_multiplication(
            policy, fresh, fresh, std::array{kQ0, kQ1, kQ2});
        CHECK(product.partial_decryption_bound == NaturalMagnitude::multiply(
                  NaturalMagnitude::multiply(
                      fresh.partial_decryption_bound,
                      fresh.partial_decryption_bound),
                  16));
        CHECK(product.certifies_no_wrap());
    });

    runner.run("key switching includes RNS residues and special drop", [] {
        const auto policy = toy_policy();
        const auto fresh = bound_fresh_asymmetric_encryption(
            policy, 0, std::array{kQ0, kQ1, kQ2});
        const auto switched = bound_key_switch(
            policy, fresh, std::array{kQ0, kQ1, kQ2}, kQk,
            DeterministicNoiseOperation::Rotation);

        CHECK(switched.operation_count == 2);
        CHECK(switched.partial_decryption_bound <
              NaturalMagnitude::product(std::array{kQ0, kQ1, kQ2}));
        CHECK(switched.certifies_no_wrap());
    });

    runner.run("modulus switching divides inherited error", [] {
        const auto policy = toy_policy();
        const auto fresh = bound_fresh_asymmetric_encryption(
            policy, 0, std::array{kQ0, kQ1, kQ2});
        const auto switched = bound_modulus_switch(
            policy, fresh, 2, std::array{kQ0, kQ1, kQ2});

        CHECK(switched.certifies_no_wrap());
        CHECK(switched.partial_decryption_bound.bit_count() <
              fresh.partial_decryption_bound.bit_count());
        CHECK(switched.operation_count == 2);

        bool rejected_size_three = false;
        try {
            (void)bound_modulus_switch(
                policy, fresh, 3, std::array{kQ0, kQ1, kQ2});
        } catch (const std::invalid_argument &) {
            rejected_size_three = true;
        }
        CHECK(rejected_size_three);
    });

    runner.run("undersized modulus records the first failed obligation", [] {
        const DeterministicNoisePolicy policy{
            .ring_degree = 16,
            .plaintext_modulus = 17,
            .secret_hamming_weight_upper = 16,
            .sampled_error_coefficient_bound = 21,
        };
        const auto failed = bound_fresh_asymmetric_encryption(
            policy, 8, std::array<std::uint64_t, 1>{257});
        CHECK(!failed.certifies_no_wrap());
        CHECK(failed.first_failure.has_value());
        CHECK(failed.first_failure->operation ==
              DeterministicNoiseOperation::FreshAsymmetricEncryption);
        CHECK(failed.first_failure->reason ==
              DeterministicNoiseFailureReason::CiphertextModulusWrap);
    });

    return runner.summary();
}
