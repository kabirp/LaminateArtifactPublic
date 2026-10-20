/// @file seal_honest_noise_calibration.cpp
/// @brief Offline real-SEAL calibration for the honest-input noise model.

#include "benchmark_support.hpp"

#include "laminate/fhe/extension.hpp"
#include "laminate/fhe/seal_backend.hpp"
#include "laminate/fhe/layout/slot_grid.hpp"
#include "laminate/params.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"

#include "seal/util/ntt.h"
#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <bit>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate {
namespace {

using fhe::SealBackend;
using fhe::SealParameters;
using fhe::SlotVector;

class Magnitude {
  public:
    Magnitude() = default;
    explicit Magnitude(std::uint64_t value) {
        if (value != 0) {
            limbs_.push_back(value);
        }
    }

    static Magnitude from_limbs(const std::uint64_t *limbs,
                                std::size_t count) {
        Magnitude result;
        result.limbs_.assign(limbs, limbs + count);
        result.trim();
        return result;
    }

    bool is_zero() const { return limbs_.empty(); }
    bool fits_u64() const { return limbs_.size() <= 1; }

    std::uint64_t to_u64() const {
        if (!fits_u64()) {
            throw std::overflow_error("magnitude does not fit u64");
        }
        return limbs_.empty() ? 0 : limbs_.front();
    }

    std::size_t bit_count() const {
        return limbs_.empty()
                   ? 0
                   : 64U * (limbs_.size() - 1) +
                         std::bit_width(limbs_.back());
    }

    friend bool operator<(const Magnitude &left, const Magnitude &right) {
        if (left.limbs_.size() != right.limbs_.size()) {
            return left.limbs_.size() < right.limbs_.size();
        }
        for (std::size_t index = left.limbs_.size(); index > 0; --index) {
            if (left.limbs_[index - 1] != right.limbs_[index - 1]) {
                return left.limbs_[index - 1] < right.limbs_[index - 1];
            }
        }
        return false;
    }

    friend bool operator<=(const Magnitude &left, const Magnitude &right) {
        return !(right < left);
    }

    static Magnitude add(const Magnitude &left, const Magnitude &right) {
        Magnitude result;
        const std::size_t count =
            std::max(left.limbs_.size(), right.limbs_.size());
        result.limbs_.resize(count);
        unsigned __int128 carry = 0;
        for (std::size_t index = 0; index < count; ++index) {
            const unsigned __int128 sum = carry +
                (index < left.limbs_.size() ? left.limbs_[index] : 0) +
                (index < right.limbs_.size() ? right.limbs_[index] : 0);
            result.limbs_[index] = static_cast<std::uint64_t>(sum);
            carry = sum >> 64U;
        }
        if (carry != 0) {
            result.limbs_.push_back(static_cast<std::uint64_t>(carry));
        }
        return result;
    }

    static Magnitude subtract(const Magnitude &left,
                              const Magnitude &right) {
        if (left < right) {
            throw std::logic_error("negative magnitude subtraction");
        }
        Magnitude result;
        result.limbs_.resize(left.limbs_.size());
        std::uint64_t borrow = 0;
        for (std::size_t index = 0; index < left.limbs_.size(); ++index) {
            const std::uint64_t right_limb =
                index < right.limbs_.size() ? right.limbs_[index] : 0;
            const std::uint64_t after_right = left.limbs_[index] - right_limb;
            const bool first_borrow = left.limbs_[index] < right_limb;
            const std::uint64_t after_borrow = after_right - borrow;
            const bool second_borrow = after_right < borrow;
            result.limbs_[index] = after_borrow;
            borrow = static_cast<std::uint64_t>(first_borrow || second_borrow);
        }
        if (borrow != 0) {
            throw std::logic_error("magnitude subtraction underflow");
        }
        result.trim();
        return result;
    }

    Magnitude shifted_left(std::size_t bits) const {
        if (is_zero()) {
            return {};
        }
        const std::size_t whole = bits / 64U;
        const unsigned partial = static_cast<unsigned>(bits % 64U);
        Magnitude result;
        result.limbs_.assign(whole, 0);
        result.limbs_.resize(whole + limbs_.size() + (partial != 0));
        std::uint64_t carry = 0;
        for (std::size_t index = 0; index < limbs_.size(); ++index) {
            result.limbs_[whole + index] =
                partial == 0 ? limbs_[index]
                             : (limbs_[index] << partial) | carry;
            carry = partial == 0 ? 0 : limbs_[index] >> (64U - partial);
        }
        if (partial != 0) {
            result.limbs_[whole + limbs_.size()] = carry;
        }
        result.trim();
        return result;
    }

    std::pair<Magnitude, std::uint64_t> divide(
        std::uint64_t divisor) const {
        if (divisor == 0) {
            throw std::invalid_argument("magnitude division by zero");
        }
        Magnitude quotient;
        quotient.limbs_.resize(limbs_.size());
        unsigned __int128 remainder = 0;
        for (std::size_t index = limbs_.size(); index > 0; --index) {
            const unsigned __int128 current =
                (remainder << 64U) | limbs_[index - 1];
            quotient.limbs_[index - 1] =
                static_cast<std::uint64_t>(current / divisor);
            remainder = current % divisor;
        }
        quotient.trim();
        return {std::move(quotient), static_cast<std::uint64_t>(remainder)};
    }

    Magnitude divide_ceil(std::uint64_t divisor) const {
        auto [quotient, remainder] = divide(divisor);
        return remainder == 0 ? quotient
                              : add(quotient, Magnitude(1));
    }

    std::string decimal() const {
        if (is_zero()) {
            return "0";
        }
        Magnitude remaining = *this;
        std::vector<std::uint32_t> chunks;
        while (!remaining.is_zero()) {
            auto [quotient, remainder] = remaining.divide(1'000'000'000ULL);
            chunks.push_back(static_cast<std::uint32_t>(remainder));
            remaining = std::move(quotient);
        }
        std::string result = std::to_string(chunks.back());
        for (std::size_t index = chunks.size() - 1; index > 0; --index) {
            std::string chunk = std::to_string(chunks[index - 1]);
            result.append(9 - chunk.size(), '0');
            result += chunk;
        }
        return result;
    }

  private:
    void trim() {
        while (!limbs_.empty() && limbs_.back() == 0) {
            limbs_.pop_back();
        }
    }

    std::vector<std::uint64_t> limbs_;
};

struct SignedMagnitude {
    bool negative = false;
    Magnitude magnitude;
};

SignedMagnitude add_signed(const SignedMagnitude &left,
                           const SignedMagnitude &right) {
    if (left.negative == right.negative) {
        return SignedMagnitude{
            left.negative,
            Magnitude::add(left.magnitude, right.magnitude)};
    }
    if (left.magnitude < right.magnitude) {
        return SignedMagnitude{
            right.negative,
            Magnitude::subtract(right.magnitude, left.magnitude)};
    }
    return SignedMagnitude{
        left.negative,
        Magnitude::subtract(left.magnitude, right.magnitude)};
}

constexpr std::size_t kUnitRingDegree = std::size_t{1} << 10U;
constexpr std::size_t kTargetRingDegree = std::size_t{1} << 14U;
constexpr std::uint64_t kDefaultSpecialPrime = 8'590'163'969ULL;

const std::vector<std::uint64_t> kDefaultUnitDataPrimes{
    kOuterFieldOrder,
    15'032'614'913ULL,
    1'152'921'497'895'862'273ULL,
    53'687'910'401ULL,
};

struct Options {
    std::size_t ring_degree = kUnitRingDegree;
    std::vector<std::uint64_t> data_primes = kDefaultUnitDataPrimes;
    std::uint64_t special_prime = kDefaultSpecialPrime;
    std::size_t samples = 8;
    std::uint64_t quantile_ppm = 990'000;
    std::size_t magnitude_margin_bits = 8;
    std::size_t debit_margin_bits = 2;
    // Payload slots lie in F_t. q0 is a coefficient modulus, not a message
    // bound, even though it is also Laminate's outer proof-field order.
    std::uint64_t message_maximum = kBaseFieldOrder - 1;
    std::uint64_t plaintext_maximum = 252;
    std::uint64_t plaintext_seed = 0x4c616d696e617465ULL;
    std::size_t chain_depth = 0;
    std::size_t proof_suffix_limbs = 0;
    std::uint64_t modeled_switch_events = 10'000;
    std::size_t switch_failure_bits = 40;
    std::string run_tier = "unit";
    bool data_primes_explicit = false;
    bool special_prime_explicit = false;
    bool modeled_switch_events_explicit = false;
    bool switch_failure_bits_explicit = false;
};

[[noreturn]] void usage(const char *program, int status) {
    std::ostream &out = status == EXIT_SUCCESS ? std::cout : std::cerr;
    out << "Usage: " << program << " [options]\n"
        << "  --run-tier unit|target\n"
        << "  --ring-degree N\n"
        << "  --data-primes q0,q1,...,qL  Exact bottom-to-top data chain\n"
        << "  --special-prime p             Exact key-switching prime\n"
        << "  --samples N\n"
        << "  --quantile-ppm Q              Nearest-rank quantile (1..1000000)\n"
        << "  --magnitude-margin-bits B     Left shift for error candidates\n"
        << "  --debit-margin-bits B         Added to operation debit candidates\n"
        << "  --message-maximum M           Encrypted slots lie in [0,M]\n"
        << "  --plaintext-maximum M         PT multiplier slots lie in [0,M]\n"
        << "  --plaintext-seed S            Reproducible plaintext generator seed\n"
        << "  --chain-depth d               Accumulated Diamond CTCT depth\n"
        << "  --proof-suffix-limbs L        Limbs retained by stress-chain switches\n"
        << "  --modeled-switch-events R     Global payload-plus-proof switch bound\n"
        << "  --switch-failure-bits K       Heuristic global failure target 2^-K\n";
    std::exit(status);
}

std::uint64_t parse_u64(std::string_view text, std::string_view option) {
    std::uint64_t value = 0;
    const auto result = std::from_chars(
        text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} ||
        result.ptr != text.data() + text.size()) {
        throw std::invalid_argument(
            std::string(option) + " expects an unsigned integer");
    }
    return value;
}

std::vector<std::uint64_t> parse_primes(
    std::string_view text, std::string_view option) {
    if (text.empty()) {
        throw std::invalid_argument(
            std::string(option) + " expects a nonempty comma-separated list");
    }
    std::vector<std::uint64_t> result;
    std::size_t begin = 0;
    while (begin <= text.size()) {
        const std::size_t comma = text.find(',', begin);
        const std::size_t end =
            comma == std::string_view::npos ? text.size() : comma;
        if (end == begin) {
            throw std::invalid_argument(
                std::string(option) + " contains an empty entry");
        }
        result.push_back(parse_u64(text.substr(begin, end - begin), option));
        if (comma == std::string_view::npos) {
            break;
        }
        begin = comma + 1;
    }
    return result;
}

Options parse_options(int argc, char **argv) {
    Options result;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help") {
            usage(argv[0], EXIT_SUCCESS);
        }
        if (index + 1 == argc) {
            throw std::invalid_argument(
                std::string(argument) + " expects a value");
        }
        const std::string_view value(argv[++index]);
        if (argument == "--run-tier") {
            result.run_tier = value;
        } else if (argument == "--ring-degree") {
            result.ring_degree = bench::parse_size(value, argument);
        } else if (argument == "--data-primes") {
            result.data_primes = parse_primes(value, argument);
            result.data_primes_explicit = true;
        } else if (argument == "--special-prime") {
            result.special_prime = parse_u64(value, argument);
            result.special_prime_explicit = true;
        } else if (argument == "--samples") {
            result.samples = bench::parse_size(value, argument);
        } else if (argument == "--quantile-ppm") {
            result.quantile_ppm = parse_u64(value, argument);
        } else if (argument == "--magnitude-margin-bits") {
            result.magnitude_margin_bits =
                bench::parse_size(value, argument);
        } else if (argument == "--debit-margin-bits") {
            result.debit_margin_bits = bench::parse_size(value, argument);
        } else if (argument == "--message-maximum") {
            result.message_maximum = parse_u64(value, argument);
        } else if (argument == "--plaintext-maximum") {
            result.plaintext_maximum = parse_u64(value, argument);
        } else if (argument == "--plaintext-seed") {
            result.plaintext_seed = parse_u64(value, argument);
        } else if (argument == "--chain-depth") {
            result.chain_depth = bench::parse_size(value, argument);
        } else if (argument == "--proof-suffix-limbs") {
            result.proof_suffix_limbs = bench::parse_size(value, argument);
        } else if (argument == "--modeled-switch-events") {
            result.modeled_switch_events = parse_u64(value, argument);
            result.modeled_switch_events_explicit = true;
        } else if (argument == "--switch-failure-bits") {
            result.switch_failure_bits = bench::parse_size(value, argument);
            result.switch_failure_bits_explicit = true;
        } else {
            throw std::invalid_argument(
                "unknown option: " + std::string(argument));
        }
    }
    return result;
}

std::size_t selected_chain_depth(const Options &options) {
    return options.chain_depth != 0
               ? options.chain_depth
               : (options.run_tier == "target" ? 8 : 1);
}

std::size_t selected_proof_suffix_limbs(const Options &options) {
    if (options.proof_suffix_limbs != 0) {
        return options.proof_suffix_limbs;
    }
    if (options.run_tier == "target") {
        return 3;
    }
    // The unit proxy has one multiplicative layer, hence it can execute at
    // most one level drop. Keep the default four-prime fixture reachable.
    return std::min<std::size_t>(3, options.data_primes.size() - 1);
}

void validate_options(const Options &options) {
    if (!std::has_single_bit(options.ring_degree) ||
        options.ring_degree < 2 ||
        options.ring_degree > kTargetRingDegree) {
        throw std::invalid_argument(
            "ring degree must be a power of two no larger than 2^14");
    }
    if (options.run_tier != "unit" && options.run_tier != "target") {
        throw std::invalid_argument("run tier must be unit or target");
    }
    const std::size_t required_ring_degree =
        options.run_tier == "target" ? kTargetRingDegree : kUnitRingDegree;
    if (options.ring_degree != required_ring_degree) {
        throw std::invalid_argument(
            options.run_tier == "target"
                ? "target tier requires N=2^14"
                : "unit tier requires N=2^10");
    }
    if (options.run_tier == "target" &&
        (!options.data_primes_explicit ||
         !options.special_prime_explicit ||
         !options.modeled_switch_events_explicit ||
         !options.switch_failure_bits_explicit)) {
        throw std::invalid_argument(
            "target runs require an explicit exact data chain, special "
            "prime, switch-event bound, and switch failure target");
    }
    if (options.samples == 0 || options.quantile_ppm == 0 ||
        options.quantile_ppm > 1'000'000 ||
        options.magnitude_margin_bits > 63 ||
        options.debit_margin_bits > 63 ||
        options.modeled_switch_events == 0 ||
        options.switch_failure_bits == 0 ||
        options.switch_failure_bits > 4096 ||
        options.message_maximum >= kBaseFieldOrder ||
        options.plaintext_maximum >= kBaseFieldOrder) {
        throw std::invalid_argument("invalid sampling or margin parameter");
    }
    if (selected_chain_depth(options) == 0 ||
        selected_chain_depth(options) > 8 ||
        selected_proof_suffix_limbs(options) == 0 ||
        selected_proof_suffix_limbs(options) >=
            options.data_primes.size()) {
        throw std::invalid_argument(
            "invalid accumulated-chain depth or proof suffix");
    }
    const std::size_t required_proxy_switches =
        options.data_primes.size() - selected_proof_suffix_limbs(options);
    if (selected_chain_depth(options) < required_proxy_switches) {
        throw std::invalid_argument(
            "accumulated proxy cannot reach the requested proof suffix with "
            "at most one switch per multiplicative layer");
    }
    if (options.data_primes.size() < 2 ||
        options.data_primes.front() != kOuterFieldOrder ||
        options.special_prime == 0) {
        throw std::invalid_argument(
            "exact chain must start at the outer field and contain two limbs");
    }

    const std::uint64_t ntt_order =
        static_cast<std::uint64_t>(2 * options.ring_degree);
    std::vector<std::uint64_t> seen;
    for (const std::uint64_t prime : options.data_primes) {
        if (prime < 3 || prime % ntt_order != 1 ||
            prime % kBaseFieldOrder != 1 ||
            std::bit_width(prime) > 60 ||
            std::find(seen.begin(), seen.end(), prime) != seen.end()) {
            throw std::invalid_argument(
                "every data prime must be distinct, at most 60 bits, and one "
                "modulo both 2N and t");
        }
        seen.push_back(prime);
    }
    if (options.special_prime % ntt_order != 1 ||
        std::bit_width(options.special_prime) > 60 ||
        std::find(seen.begin(), seen.end(), options.special_prime) !=
            seen.end()) {
        throw std::invalid_argument(
            "special prime must be distinct, at most 60 bits, and one modulo 2N");
    }
}

std::uint64_t splitmix64(std::uint64_t &state) {
    state += 0x9e3779b97f4a7c15ULL;
    std::uint64_t value = state;
    value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31U);
}

SlotVector random_slots(std::size_t count, std::uint64_t maximum,
                        std::uint64_t &state) {
    SlotVector result;
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        result.emplace_back(splitmix64(state) % (maximum + 1));
    }
    return result;
}

/// Recover the exact centered canonical-error coefficients at any live RNS
/// level. This is intentionally benchmark-local and secret-key-only. The
/// operational scheduler has no dependency on it.
///
/// For SEAL BGV, decryption returns
/// `correction_factor^{-1} * (c_0 + c_1 s) mod t`. Thus, after CRT composition
/// into `[0,Q)` and centering the phase in `(-Q/2,Q/2]`, the exact numerator is
///
///   centered_Q(c_0 + c_1 s)
///     - centered_t(correction_factor * decoded_message),
///
/// which must be divisible by `t`; its quotient is the canonical error. The
/// Q-centering happens before message removal. This remains correct for a
/// non-one correction factor even though this benchmark requires every data
/// prime to be one modulo `t`, which keeps SEAL's switch correction at one.
std::vector<SignedMagnitude> canonical_error_coefficients(
    const SealBackend::EvalContext &eval,
    const SealBackend::ClientContext &client,
    const SealBackend::Ciphertext &ciphertext) {
    const auto data = client.context->get_context_data(
        ciphertext.raw.parms_id());
    if (!data || ciphertext.raw.size() != 2 ||
        !ciphertext.raw.is_ntt_form() || !client.secret_key) {
        throw std::invalid_argument(
            "noise calibration requires a live size-two NTT BGV ciphertext");
    }
    const auto &moduli = data->parms().coeff_modulus();
    const std::size_t limbs = moduli.size();
    const std::size_t degree = data->parms().poly_modulus_degree();
    const auto key_data = client.context->key_context_data();
    if (!key_data ||
        key_data->parms().coeff_modulus().size() < limbs) {
        throw std::logic_error("secret-key RNS basis is shorter than ciphertext");
    }

    std::vector<std::uint64_t> phase(limbs * degree);
    const std::uint64_t *secret = client.secret_key->data().data();
    for (std::size_t limb = 0; limb < limbs; ++limb) {
        const seal::Modulus &modulus = moduli[limb];
        const std::uint64_t *c0 = ciphertext.raw.data(0) + limb * degree;
        const std::uint64_t *c1 = ciphertext.raw.data(1) + limb * degree;
        const std::uint64_t *s = secret + limb * degree;
        std::uint64_t *destination = phase.data() + limb * degree;
        for (std::size_t coefficient = 0; coefficient < degree;
             ++coefficient) {
            destination[coefficient] = seal::util::add_uint_mod(
                c0[coefficient],
                seal::util::multiply_uint_mod(
                    c1[coefficient], s[coefficient], modulus),
                modulus);
        }
        seal::util::inverse_ntt_negacyclic_harvey(
            destination, data->small_ntt_tables()[limb]);
    }

    data->rns_tool()->base_q()->compose_array(
        phase.data(), degree, seal::MemoryManager::GetPool());
    const Magnitude modulus_product = Magnitude::from_limbs(
        data->total_coeff_modulus(), limbs);
    const Magnitude half_modulus = modulus_product.divide(2).first;

    const SlotVector message = SealBackend::decrypt(client, ciphertext);
    const std::vector<std::int64_t> message_coefficients =
        SealBackend::encode_centered_plaintext_coefficients(eval, message);
    if (message_coefficients.size() != degree) {
        throw std::logic_error("plaintext encoder returned the wrong degree");
    }
    const std::uint64_t t = kBaseFieldOrder;
    const seal::Modulus plain_modulus(t);
    const std::uint64_t correction = ciphertext.raw.correction_factor();

    std::vector<SignedMagnitude> result;
    result.reserve(degree);
    for (std::size_t coefficient = 0; coefficient < degree;
         ++coefficient) {
        const Magnitude composed_phase = Magnitude::from_limbs(
            phase.data() + coefficient * limbs, limbs);
        SignedMagnitude centered_phase =
            half_modulus < composed_phase
                ? SignedMagnitude{
                      true,
                      Magnitude::subtract(modulus_product, composed_phase)}
                : SignedMagnitude{false, composed_phase};

        const std::int64_t message_coefficient =
            message_coefficients[coefficient];
        const std::uint64_t message_residue =
            message_coefficient >= 0
                ? static_cast<std::uint64_t>(message_coefficient)
                : t - (std::uint64_t{0} -
                       static_cast<std::uint64_t>(message_coefficient));
        const std::uint64_t corrected_residue =
            seal::util::multiply_uint_mod(
                message_residue, correction, plain_modulus);
        const std::int64_t corrected_message =
            corrected_residue <= t / 2
                ? static_cast<std::int64_t>(corrected_residue)
                : -static_cast<std::int64_t>(t - corrected_residue);

        const std::uint64_t corrected_magnitude =
            corrected_message < 0
                ? std::uint64_t{0} -
                      static_cast<std::uint64_t>(corrected_message)
                : static_cast<std::uint64_t>(corrected_message);
        const SignedMagnitude negated_message{
            corrected_message > 0, Magnitude(corrected_magnitude)};
        SignedMagnitude numerator = add_signed(
            centered_phase, negated_message);
        auto [quotient, remainder] = numerator.magnitude.divide(t);
        if (remainder != 0) {
            throw std::logic_error(
                "phase minus corrected message is not divisible by t");
        }
        numerator.magnitude = std::move(quotient);
        if (numerator.magnitude.is_zero()) {
            numerator.negative = false;
        }
        result.push_back(std::move(numerator));
    }
    return result;
}

struct CanonicalErrorMeasurement {
    std::vector<SignedMagnitude> coefficients;
    Magnitude infinity_norm;
};

CanonicalErrorMeasurement canonical_error_measurement(
    const SealBackend::EvalContext &eval,
    const SealBackend::ClientContext &client,
    const SealBackend::Ciphertext &ciphertext) {
    if (SealBackend::invariant_noise_budget(client, ciphertext) <= 0) {
        throw std::runtime_error(
            "sample exhausted invariant noise; refusing to calibrate from a "
            "possibly mis-decrypted message");
    }
    CanonicalErrorMeasurement result{
        .coefficients = canonical_error_coefficients(
            eval, client, ciphertext),
    };
    for (const SignedMagnitude &coefficient : result.coefficients) {
        if (result.infinity_norm < coefficient.magnitude) {
            result.infinity_norm = coefficient.magnitude;
        }
    }
    return result;
}

Magnitude canonical_error_norm(
    const SealBackend::EvalContext &eval,
    const SealBackend::ClientContext &client,
    const SealBackend::Ciphertext &ciphertext) {
    return canonical_error_measurement(eval, client, ciphertext).infinity_norm;
}

std::size_t required_debit_bits(const Magnitude &input,
                                const Magnitude &output) {
    if (input.is_zero()) {
        throw std::logic_error("operation input has zero canonical-error norm");
    }
    if (output <= input) {
        return 0;
    }
    std::size_t bits = output.bit_count() - input.bit_count();
    if (input.shifted_left(bits) < output) {
        ++bits;
    }
    return bits;
}

Magnitude coefficientwise_switch_allowance(
    const CanonicalErrorMeasurement &input,
    const CanonicalErrorMeasurement &output,
    std::uint64_t dropped_modulus) {
    if (input.coefficients.size() != output.coefficients.size()) {
        throw std::logic_error(
            "modulus-switch error vectors have different degrees");
    }
    Magnitude maximum;
    for (std::size_t coefficient = 0;
         coefficient < input.coefficients.size(); ++coefficient) {
        const Magnitude inherited =
            input.coefficients[coefficient].magnitude.divide_ceil(
                dropped_modulus);
        const Magnitude &after = output.coefficients[coefficient].magnitude;
        const Magnitude residual =
            inherited < after
                ? Magnitude::subtract(after, inherited)
                : Magnitude();
        if (maximum < residual) {
            maximum = residual;
        }
    }
    return maximum;
}

template <typename Value>
Value nearest_rank(std::vector<Value> values, std::uint64_t quantile_ppm) {
    if (values.empty()) {
        throw std::logic_error("cannot summarize an empty sample set");
    }
    std::sort(values.begin(), values.end());
    const unsigned __int128 numerator =
        static_cast<unsigned __int128>(quantile_ppm) * values.size() +
        1'000'000 - 1;
    const std::size_t rank = static_cast<std::size_t>(
        numerator / 1'000'000);
    return values.at(std::max<std::size_t>(1, rank) - 1);
}

std::string decimal(const Magnitude &value) { return value.decimal(); }

std::string decimal(std::size_t value) { return std::to_string(value); }

std::string decimal_list(std::span<const std::uint64_t> values) {
    return bench::join(std::vector<std::uint64_t>(values.begin(), values.end()));
}

template <typename Value>
struct StratifiedObservations {
    std::vector<Value> pooled;
    std::map<std::string, std::vector<Value>> by_stratum;
};

template <typename Value>
void observe(StratifiedObservations<Value> &observations,
             std::string stratum, const Value &value) {
    observations.pooled.push_back(value);
    observations.by_stratum[std::move(stratum)].push_back(value);
}

std::string level_stratum(std::string_view path, std::size_t input_limbs) {
    return std::string(path) + "_input_limbs_" +
           std::to_string(input_limbs);
}

template <typename Value>
Value maximum_stratum_quantile(
    const StratifiedObservations<Value> &observations,
    std::uint64_t quantile_ppm) {
    std::optional<Value> maximum;
    for (const auto &[name, values] : observations.by_stratum) {
        (void)name;
        Value candidate = nearest_rank(values, quantile_ppm);
        if (!maximum || *maximum < candidate) {
            maximum = std::move(candidate);
        }
    }
    if (!maximum) {
        throw std::logic_error("cannot summarize empty observation strata");
    }
    return *maximum;
}

struct Observations {
    StratifiedObservations<Magnitude> fresh;
    StratifiedObservations<std::size_t> ctct_debits;
    StratifiedObservations<std::size_t> plaintext_debits;
    StratifiedObservations<std::size_t> rotation_debits;
    StratifiedObservations<std::size_t>
        base_proof_plaintext_debits;
    StratifiedObservations<std::size_t>
        base_proof_scalar_plaintext_debits;
    StratifiedObservations<std::size_t>
        base_proof_vector_plaintext_debits;
    StratifiedObservations<Magnitude> switch_allowances;
    StratifiedObservations<Magnitude> fresh_switch_allowances;
    StratifiedObservations<Magnitude> product_switch_allowances;
    StratifiedObservations<std::size_t> accumulated_ctct_debits;
    StratifiedObservations<Magnitude> accumulated_switch_allowances;
    std::size_t accumulated_initial_limbs = 0;
    std::size_t accumulated_final_limbs = 0;
    std::size_t accumulated_switches = 0;
};

void require_slots(const SealBackend::ClientContext &client,
                   const SealBackend::Ciphertext &ciphertext,
                   const SlotVector &expected, const char *operation);

const SealBackend::Ciphertext *require_coordinate_presence(
    const std::optional<SealBackend::Ciphertext> &coordinate,
    bool expected_present, const char *operation) {
    if (coordinate.has_value() != expected_present) {
        throw std::logic_error(
            std::string(operation) +
            " returned the wrong public extension-coordinate support");
    }
    return coordinate ? &*coordinate : nullptr;
}

Fpk random_extension_weight(std::uint64_t &state) {
    Fpk::Coefficients coefficients{};
    for (Fp &coefficient : coefficients) {
        coefficient = Fp(splitmix64(state) % kBaseFieldOrder);
    }
    return Fpk(coefficients);
}

std::vector<Fpk> random_extension_weights(
    std::size_t count, std::uint64_t &state) {
    std::vector<Fpk> result;
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        result.push_back(random_extension_weight(state));
    }
    return result;
}

void collect_base_proof_plaintext_debits(
    const Options &options, const SealBackend::Contexts &contexts,
    const SealBackend::Ciphertext &source,
    std::span<const Fp> source_slots,
    const Magnitude &source_error, std::size_t input_limbs,
    std::uint64_t &random_state, Observations &observations) {
    const Fpk scalar_weight = random_extension_weight(random_state);
    const auto scalar_result = fhe::promote_scale<SealBackend>(
        contexts.eval, source, scalar_weight);
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        SlotVector expected;
        expected.reserve(source_slots.size());
        const Fp multiplier = scalar_weight.coefficients()[coefficient];
        for (const Fp &slot : source_slots) {
            expected.push_back(slot * multiplier);
        }
        const SealBackend::Ciphertext *result_coordinate =
            require_coordinate_presence(
                scalar_result[coefficient], !multiplier.is_zero(),
                "Base proof scalar promotion");
        if (!result_coordinate) {
            continue;
        }
        require_slots(contexts.client, *result_coordinate, expected,
                      "Base proof scalar promotion");
        const std::size_t debit = required_debit_bits(
            source_error,
            canonical_error_norm(contexts.eval, contexts.client,
                                 *result_coordinate));
        const std::string stratum =
            level_stratum("scalar", input_limbs);
        observe(observations.base_proof_scalar_plaintext_debits,
                stratum, debit);
        observe(observations.base_proof_plaintext_debits,
                stratum, debit);
    }

    const std::vector<Fpk> vector_weights = random_extension_weights(
        options.ring_degree, random_state);
    const auto vector_result = fhe::promote_scale<SealBackend>(
        contexts.eval, source, vector_weights);
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        SlotVector expected;
        expected.reserve(source_slots.size());
        bool expected_present = false;
        for (std::size_t slot = 0; slot < source_slots.size(); ++slot) {
            const Fp multiplier =
                vector_weights[slot].coefficients()[coefficient];
            expected_present = expected_present || !multiplier.is_zero();
            expected.push_back(
                source_slots[slot] * multiplier);
        }
        const SealBackend::Ciphertext *result_coordinate =
            require_coordinate_presence(
                vector_result[coefficient], expected_present,
                "Base proof vector promotion");
        if (!result_coordinate) {
            continue;
        }
        require_slots(contexts.client, *result_coordinate, expected,
                      "Base proof vector promotion");
        const std::size_t debit = required_debit_bits(
            source_error,
            canonical_error_norm(contexts.eval, contexts.client,
                                 *result_coordinate));
        const std::string stratum =
            level_stratum("vector", input_limbs);
        observe(observations.base_proof_vector_plaintext_debits,
                stratum, debit);
        observe(observations.base_proof_plaintext_debits,
                stratum, debit);
    }
}

void require_slots(const SealBackend::ClientContext &client,
                   const SealBackend::Ciphertext &ciphertext,
                   const SlotVector &expected, const char *operation) {
    if (SealBackend::decrypt(client, ciphertext) != expected) {
        throw std::runtime_error(
            std::string(operation) + " sample decrypted incorrectly");
    }
}

void run_phase_identity_self_checks(
    const Options &options, const SealBackend::Contexts &contexts) {
    std::uint64_t state = 0x70686173652d6964ULL;
    const std::uint64_t maximum =
        std::min<std::uint64_t>(options.message_maximum, 31);
    const SlotVector slots = random_slots(
        options.ring_degree, maximum, state);
    auto ciphertext = SealBackend::encrypt(contexts.client, slots);
    require_slots(contexts.client, ciphertext, slots,
                  "phase-identity fresh ciphertext");
    const CanonicalErrorMeasurement top = canonical_error_measurement(
        contexts.eval, contexts.client, ciphertext);
    if (top.coefficients.size() != options.ring_degree) {
        throw std::logic_error(
            "phase-identity check returned the wrong polynomial degree");
    }

    // Construct a semantically equivalent ciphertext with a non-one BGV
    // correction factor. `canonical_error_coefficients` checks coefficient by
    // coefficient that centered(phase)-centered(correction*message) is exactly
    // divisible by t; this exercises that identity without relying on the
    // correction-preserving evaluation-chain restriction.
    constexpr std::uint64_t kArtificialCorrection = 7;
    auto corrected = SealBackend::mul_plain(
        contexts.eval, ciphertext,
        SlotVector(options.ring_degree, Fp(kArtificialCorrection)));
    corrected.raw.correction_factor() = kArtificialCorrection;
    require_slots(contexts.client, corrected, slots,
                  "phase-identity corrected ciphertext");
    (void)canonical_error_measurement(
        contexts.eval, contexts.client, corrected);

    SealBackend::mod_switch_to_lowest(contexts.eval, ciphertext);
    require_slots(contexts.client, ciphertext, slots,
                  "phase-identity bottom ciphertext");
    const CanonicalErrorMeasurement bottom = canonical_error_measurement(
        contexts.eval, contexts.client, ciphertext);
    if (bottom.coefficients.size() != options.ring_degree ||
        SealBackend::rns_limb_count(contexts.eval, ciphertext) != 1) {
        throw std::logic_error(
            "phase-identity bottom-level check did not reach one limb");
    }
}

void collect_accumulated_chain(
    const Options &options, const SealBackend::Contexts &contexts,
    std::uint64_t &random_state, Observations &observations) {
    SlotVector left_slots = random_slots(
        options.ring_degree, options.message_maximum, random_state);
    SlotVector right_slots = random_slots(
        options.ring_degree, options.message_maximum, random_state);
    auto left = SealBackend::encrypt(contexts.client, left_slots);
    auto right = SealBackend::encrypt(contexts.client, right_slots);
    observe(observations.fresh, "accumulated",
            canonical_error_norm(contexts.eval, contexts.client, left));
    observe(observations.fresh, "accumulated",
            canonical_error_norm(contexts.eval, contexts.client, right));

    const Fp bias(splitmix64(random_state) % kBaseFieldOrder);
    const SlotVector scalar_bias(options.ring_degree, bias);

    const std::size_t suffix_limbs =
        selected_proof_suffix_limbs(options);
    const std::size_t initial_limbs =
        SealBackend::rns_limb_count(contexts.eval, left);
    std::size_t switches = 0;
    for (std::size_t depth = 0; depth < selected_chain_depth(options);
         ++depth) {
        const std::size_t input_limbs =
            SealBackend::rns_limb_count(contexts.eval, left);
        const CanonicalErrorMeasurement left_error =
            canonical_error_measurement(
                contexts.eval, contexts.client, left);
        const CanonicalErrorMeasurement right_error =
            canonical_error_measurement(
                contexts.eval, contexts.client, right);
        auto right_plus_bias = SealBackend::add_plain(
            contexts.eval, right, scalar_bias);
        auto left_plus_bias = SealBackend::add_plain(
            contexts.eval, left, scalar_bias);
        for (Fp &slot : right_slots) {
            slot += bias;
        }
        for (Fp &slot : left_slots) {
            slot += bias;
        }
        require_slots(contexts.client, right_plus_bias, right_slots,
                      "accumulated Diamond right-plus-bias");
        require_slots(contexts.client, left_plus_bias, left_slots,
                      "accumulated Diamond left-plus-bias");
        const Magnitude shifted_right_error = canonical_error_norm(
            contexts.eval, contexts.client, right_plus_bias);
        const Magnitude shifted_left_error = canonical_error_norm(
            contexts.eval, contexts.client, left_plus_bias);
        if (right_error.infinity_norm < shifted_right_error ||
            shifted_right_error < right_error.infinity_norm ||
            left_error.infinity_norm < shifted_left_error ||
            shifted_left_error < left_error.infinity_norm) {
            throw std::logic_error(
                "plaintext addition changed the canonical error");
        }

        auto next_left = SealBackend::mul(
            contexts.eval, left, right_plus_bias);
        auto next_right = SealBackend::mul(
            contexts.eval, right, left_plus_bias);
        SlotVector next_left_slots(options.ring_degree);
        SlotVector next_right_slots(options.ring_degree);
        for (std::size_t slot = 0; slot < options.ring_degree; ++slot) {
            next_left_slots[slot] =
                (left_slots[slot] - bias) * right_slots[slot];
            next_right_slots[slot] =
                (right_slots[slot] - bias) * left_slots[slot];
        }
        require_slots(contexts.client, next_left, next_left_slots,
                      "accumulated Diamond left product");
        require_slots(contexts.client, next_right, next_right_slots,
                      "accumulated Diamond right product");
        const CanonicalErrorMeasurement next_left_error =
            canonical_error_measurement(
                contexts.eval, contexts.client, next_left);
        const CanonicalErrorMeasurement next_right_error =
            canonical_error_measurement(
                contexts.eval, contexts.client, next_right);
        for (const std::size_t debit : {
                 required_debit_bits(
                     std::max(left_error.infinity_norm,
                              shifted_right_error),
                     next_left_error.infinity_norm),
                 required_debit_bits(
                     std::max(right_error.infinity_norm,
                              shifted_left_error),
                     next_right_error.infinity_norm)}) {
            const std::string stratum =
                level_stratum("accumulated", input_limbs);
            observe(observations.ctct_debits, stratum, debit);
            observe(observations.accumulated_ctct_debits,
                    stratum, debit);
        }

        if (SealBackend::rns_limb_count(contexts.eval, next_left) >
            suffix_limbs) {
            const std::uint64_t dropped =
                SealBackend::data_coefficient_moduli(
                    contexts.eval, next_left).back();
            SealBackend::mod_switch_to_next(contexts.eval, next_left);
            SealBackend::mod_switch_to_next(contexts.eval, next_right);
            require_slots(contexts.client, next_left, next_left_slots,
                          "accumulated Diamond left switch");
            require_slots(contexts.client, next_right, next_right_slots,
                          "accumulated Diamond right switch");
            const CanonicalErrorMeasurement switched_left_error =
                canonical_error_measurement(
                    contexts.eval, contexts.client, next_left);
            const CanonicalErrorMeasurement switched_right_error =
                canonical_error_measurement(
                    contexts.eval, contexts.client, next_right);
            for (Magnitude allowance : {
                     coefficientwise_switch_allowance(
                         next_left_error, switched_left_error, dropped),
                     coefficientwise_switch_allowance(
                         next_right_error, switched_right_error, dropped)}) {
                const std::string stratum =
                    level_stratum("accumulated", input_limbs);
                observe(observations.switch_allowances,
                        stratum, allowance);
                observe(observations.accumulated_switch_allowances,
                        stratum, allowance);
            }
            ++switches;
        }
        left = std::move(next_left);
        right = std::move(next_right);
        left_slots = std::move(next_left_slots);
        right_slots = std::move(next_right_slots);
    }
    const std::size_t final_limbs =
        SealBackend::rns_limb_count(contexts.eval, left);
    const std::size_t expected_switches = initial_limbs - suffix_limbs;
    if (final_limbs != suffix_limbs || switches != expected_switches) {
        throw std::logic_error(
            "accumulated proxy did not reach its declared proof suffix");
    }
    if (observations.accumulated_initial_limbs == 0) {
        observations.accumulated_initial_limbs = initial_limbs;
        observations.accumulated_final_limbs = final_limbs;
        observations.accumulated_switches = switches;
    } else if (observations.accumulated_initial_limbs != initial_limbs ||
               observations.accumulated_final_limbs != final_limbs ||
               observations.accumulated_switches != switches) {
        throw std::logic_error(
            "accumulated proxy level path changed between samples");
    }
}

Observations collect(
    const Options &options, const SealBackend::Contexts &contexts) {
    Observations observations;
    std::uint64_t random_state = options.plaintext_seed;
    for (std::size_t sample = 0; sample < options.samples; ++sample) {
        SlotVector left_slots = random_slots(
            options.ring_degree, options.message_maximum, random_state);
        SlotVector right_slots = random_slots(
            options.ring_degree, options.message_maximum, random_state);
        SlotVector plaintext = random_slots(
            options.ring_degree, options.plaintext_maximum, random_state);
        auto left = SealBackend::encrypt(contexts.client, left_slots);
        auto right = SealBackend::encrypt(contexts.client, right_slots);
        observe(observations.fresh, "primitive",
                canonical_error_norm(
                    contexts.eval, contexts.client, left));
        observe(observations.fresh, "primitive",
                canonical_error_norm(
                    contexts.eval, contexts.client, right));

        while (true) {
            const std::size_t input_limbs =
                SealBackend::rns_limb_count(contexts.eval, left);
            const CanonicalErrorMeasurement left_error =
                canonical_error_measurement(
                    contexts.eval, contexts.client, left);
            const CanonicalErrorMeasurement right_error =
                canonical_error_measurement(
                    contexts.eval, contexts.client, right);

            collect_base_proof_plaintext_debits(
                options, contexts, left, left_slots,
                left_error.infinity_norm, input_limbs, random_state,
                observations);

            auto product = SealBackend::mul(contexts.eval, left, right);
            SlotVector product_slots(options.ring_degree);
            for (std::size_t slot = 0; slot < options.ring_degree; ++slot) {
                product_slots[slot] = left_slots[slot] * right_slots[slot];
            }
            require_slots(contexts.client, product, product_slots,
                          "CT-CT plus relinearization");
            const CanonicalErrorMeasurement product_error =
                canonical_error_measurement(
                    contexts.eval, contexts.client, product);
            observe(
                observations.ctct_debits,
                level_stratum("primitive", input_limbs),
                required_debit_bits(
                    std::max(left_error.infinity_norm,
                             right_error.infinity_norm),
                    product_error.infinity_norm));

            auto plaintext_product = SealBackend::mul_plain(
                contexts.eval, left, plaintext);
            SlotVector plaintext_product_slots(options.ring_degree);
            for (std::size_t slot = 0; slot < options.ring_degree; ++slot) {
                plaintext_product_slots[slot] =
                    left_slots[slot] * plaintext[slot];
            }
            require_slots(contexts.client, plaintext_product,
                          plaintext_product_slots, "PT-CT multiplication");
            const Magnitude plaintext_product_error = canonical_error_norm(
                contexts.eval, contexts.client, plaintext_product);
            observe(
                observations.plaintext_debits,
                level_stratum("primitive", input_limbs),
                required_debit_bits(
                    left_error.infinity_norm, plaintext_product_error));

            const std::size_t rotation =
                1 + static_cast<std::size_t>(
                        splitmix64(random_state) %
                        (options.ring_degree - 1));
            auto rotated = SealBackend::rotate(
                contexts.eval, left, rotation);
            require_slots(contexts.client, rotated,
                          fhe::grid_rotate(left_slots, rotation), "rotation");
            const Magnitude rotation_error = canonical_error_norm(
                contexts.eval, contexts.client, rotated);
            observe(
                observations.rotation_debits,
                level_stratum("primitive", input_limbs),
                required_debit_bits(
                    left_error.infinity_norm, rotation_error));

            if (SealBackend::rns_limb_count(contexts.eval, left) == 1) {
                break;
            }
            const std::uint64_t dropped =
                SealBackend::data_coefficient_moduli(
                    contexts.eval, left).back();
            auto switched_left = left;
            SealBackend::mod_switch_to_next(contexts.eval, switched_left);
            require_slots(contexts.client, switched_left, left_slots,
                          "fresh-state modulus switch");
            const CanonicalErrorMeasurement switched_left_error =
                canonical_error_measurement(
                    contexts.eval, contexts.client, switched_left);
            const Magnitude fresh_allowance =
                coefficientwise_switch_allowance(
                    left_error, switched_left_error, dropped);
            const std::string fresh_stratum =
                level_stratum("fresh", input_limbs);
            observe(observations.fresh_switch_allowances,
                    fresh_stratum, fresh_allowance);
            observe(observations.switch_allowances,
                    fresh_stratum, fresh_allowance);

            auto switched_product = product;
            SealBackend::mod_switch_to_next(
                contexts.eval, switched_product);
            require_slots(contexts.client, switched_product, product_slots,
                          "product-state modulus switch");
            const CanonicalErrorMeasurement switched_product_error =
                canonical_error_measurement(
                    contexts.eval, contexts.client, switched_product);
            const Magnitude product_allowance =
                coefficientwise_switch_allowance(
                    product_error, switched_product_error, dropped);
            const std::string product_stratum =
                level_stratum("product", input_limbs);
            observe(observations.product_switch_allowances,
                    product_stratum, product_allowance);
            observe(observations.switch_allowances,
                    product_stratum, product_allowance);

            left = std::move(switched_left);
            SealBackend::mod_switch_to_next(contexts.eval, right);
        }

        collect_accumulated_chain(
            options, contexts, random_state, observations);
    }
    return observations;
}

template <typename Value>
void emit_distribution(const bench::Record &record,
                       std::string_view prefix,
                       const std::vector<Value> &values,
                       std::uint64_t quantile_ppm) {
    const auto [minimum, maximum] = std::minmax_element(
        values.begin(), values.end());
    record.integer(std::string(prefix) + ".samples", values.size());
    record.text(std::string(prefix) + ".minimum", decimal(*minimum));
    record.text(std::string(prefix) + ".quantile",
                decimal(nearest_rank(values, quantile_ppm)));
    record.text(std::string(prefix) + ".maximum", decimal(*maximum));
}

template <typename Value>
void emit_stratified_distribution(
    const bench::Record &record, std::string_view prefix,
    const StratifiedObservations<Value> &observations,
    std::uint64_t quantile_ppm) {
    emit_distribution(record, prefix, observations.pooled, quantile_ppm);
    record.integer(std::string(prefix) + ".strata",
                   observations.by_stratum.size());
    for (const auto &[name, values] : observations.by_stratum) {
        emit_distribution(record,
                          std::string(prefix) + ".stratum." + name,
                          values, quantile_ppm);
    }
    record.text(std::string(prefix) + ".candidate_selection",
                "maximum-of-per-stratum-nearest-rank-quantiles");
}

int run(int argc, char **argv) {
    const Options options = parse_options(argc, argv);
    validate_options(options);

    SealParameters parameters{
        .poly_modulus_degree = options.ring_degree,
        .fresh_rns_limbs = options.data_primes.size(),
        .exact_data_primes = options.data_primes,
        .exact_special_prime = options.special_prime,
        .special_prime_bits =
            static_cast<int>(std::bit_width(options.special_prime)),
        .security_level = seal::sec_level_type::none,
        .generate_galois_keys = true,
    };
    auto [contexts, setup_timing] = bench::timed(
        [&] { return SealBackend::create(parameters); });
    run_phase_identity_self_checks(options, contexts);
    const auto [observations, timing] = bench::timed(
        [&] { return collect(options, contexts); });

    const Magnitude fresh_quantile = maximum_stratum_quantile(
        observations.fresh, options.quantile_ppm);
    const std::size_t ctct_quantile = maximum_stratum_quantile(
        observations.ctct_debits, options.quantile_ppm);
    const std::size_t plaintext_quantile = maximum_stratum_quantile(
        observations.plaintext_debits, options.quantile_ppm);
    const std::size_t rotation_quantile = maximum_stratum_quantile(
        observations.rotation_debits, options.quantile_ppm);
    const std::size_t base_proof_plaintext_quantile =
        maximum_stratum_quantile(
            observations.base_proof_plaintext_debits,
            options.quantile_ppm);
    const Magnitude switch_quantile = maximum_stratum_quantile(
        observations.switch_allowances, options.quantile_ppm);
    const Magnitude fresh_candidate = fresh_quantile.shifted_left(
        options.magnitude_margin_bits);
    const Magnitude switch_margin_diagnostic = switch_quantile.shifted_left(
        options.magnitude_margin_bits);
    const std::uint64_t randomized_tail_heuristic =
        payload::randomized_mod_switch_rounding_heuristic_bound(
            options.ring_degree, options.modeled_switch_events,
            options.switch_failure_bits);
    if (!switch_margin_diagnostic.fits_u64()) {
        throw std::overflow_error(
            "switch recurrence candidate does not fit scheduler u64");
    }
    if (!(switch_quantile <= Magnitude(randomized_tail_heuristic))) {
        throw std::runtime_error(
            "observed deterministic-switch recurrence exceeds the "
            "configured randomized-tail heuristic");
    }

    const bench::Record record;
    record.text("format", "laminate-seal-honest-noise-calibration-v3");
    record.text("classification.result_kind",
                "offline-secret-key-empirical-candidate-calibration");
    record.text("classification.schedule_use",
                "forbidden-online;candidate-for-setup-only");
    record.text("classification.probability_claim",
                "randomized-rounding-Hoeffding-tail-applied-heuristically-"
                "to-deterministic-switch-on-honest-ciphertexts");
    record.text("classification.output_scope",
                "partial-candidate-inputs-for-offline-review-only;not-a-"
                "complete-payload-or-Base-proof-noise-calibration");
    record.text("classification.modulus_switch",
                "microsoft-seal-deterministic-mod-t-and-divide");
    record.text("execution.threading", "single-threaded");
    record.text("execution.run_tier", options.run_tier);
    record.text("reproduction.command", bench::exact_command(argc, argv));
    record.text("reproduction.git_commit", LAMINATE_GIT_COMMIT);
    record.text("reproduction.git_dirty", LAMINATE_GIT_DIRTY);
    record.text("reproduction.utc", bench::utc_timestamp());
    record.integer("parameters.ring_degree", options.ring_degree);
    record.text("parameters.data_primes_low_to_high",
                decimal_list(options.data_primes));
    record.integer("parameters.special_prime", options.special_prime);
    record.integer("parameters.fresh_modulus_bits",
                   SealBackend::fresh_ciphertext_modulus_bits(contexts.eval));
    record.integer("parameters.key_modulus_bits",
                   SealBackend::key_modulus_bits(contexts.eval));
    record.integer("sampling.independent_encryptions", 4 * options.samples);
    record.integer("sampling.requested_samples", options.samples);
    record.integer("sampling.quantile_ppm", options.quantile_ppm);
    record.integer("sampling.message_maximum", options.message_maximum);
    record.integer("sampling.plaintext_maximum", options.plaintext_maximum);
    record.integer("sampling.plaintext_seed", options.plaintext_seed);
    record.integer("sampling.accumulated_chain_depth",
                   selected_chain_depth(options));
    record.integer("sampling.accumulated_chain_proof_suffix_limbs",
                   selected_proof_suffix_limbs(options));
    record.integer("sampling.accumulated_chain_initial_limbs",
                   observations.accumulated_initial_limbs);
    record.integer("sampling.accumulated_chain_final_limbs",
                   observations.accumulated_final_limbs);
    record.integer("sampling.accumulated_chain_switches",
                   observations.accumulated_switches);
    record.integer("model.modeled_switch_events_upper_bound",
                   options.modeled_switch_events);
    record.integer("model.switch_failure_budget_bits",
                   options.switch_failure_bits);
    record.integer("model.secret_hamming_weight_upper",
                   options.ring_degree);
    record.integer("model.randomized_tail_heuristic_rounding_bound",
                   randomized_tail_heuristic);
    record.text(
        "model.deterministic_switch_status",
        "engineering-heuristic-for-honest-ciphertexts-not-randomized-"
        "switch-theorem");
    record.text("sampling.accumulated_chain_policy",
                "two-neighbor-diamond-proxy;left-times-right-plus-bias;"
                "right-times-left-plus-bias;ctct-relinearize;deterministic-"
                "switch-after-ctct-until-proof-suffix;optional-ptct-and-"
                "rotation-calibrated-separately-at-every-level");
    record.text(
        "sampling.base_proof_plaintext_policy",
        "production-promote-scale-scalar-and-vector;full-F_t-domain-"
        "splitmix64-mod-t-weights;omit-only-public-all-zero-extension-"
        "coordinates;every-rns-level");
    record.text("sampling.base_proof_rotation_policy",
                "not-used-by-file-backed-base-proof-topology");
    record.integer("margin.magnitude_bits",
                   options.magnitude_margin_bits);
    record.integer("margin.debit_bits", options.debit_margin_bits);

    emit_stratified_distribution(
        record, "observed.fresh_canonical_error",
        observations.fresh, options.quantile_ppm);
    emit_stratified_distribution(
        record, "observed.ctct_relinearized_debit_bits",
        observations.ctct_debits, options.quantile_ppm);
    emit_stratified_distribution(
        record, "observed.plaintext_ct_debit_bits",
        observations.plaintext_debits, options.quantile_ppm);
    emit_stratified_distribution(
        record, "observed.rotation_debit_bits",
        observations.rotation_debits, options.quantile_ppm);
    emit_stratified_distribution(
        record, "observed.base_proof.plaintext_ct_debit_bits",
        observations.base_proof_plaintext_debits,
        options.quantile_ppm);
    emit_stratified_distribution(
        record, "observed.base_proof.scalar_plaintext_ct_debit_bits",
        observations.base_proof_scalar_plaintext_debits,
        options.quantile_ppm);
    emit_stratified_distribution(
        record, "observed.base_proof.vector_plaintext_ct_debit_bits",
        observations.base_proof_vector_plaintext_debits,
        options.quantile_ppm);
    emit_stratified_distribution(
        record, "observed.switch_coefficient_recurrence_allowance",
        observations.switch_allowances, options.quantile_ppm);
    emit_stratified_distribution(
        record,
        "observed.switch_coefficient_recurrence_allowance.fresh_state",
        observations.fresh_switch_allowances, options.quantile_ppm);
    emit_stratified_distribution(
        record,
        "observed.switch_coefficient_recurrence_allowance.product_state",
        observations.product_switch_allowances, options.quantile_ppm);
    emit_stratified_distribution(
        record, "observed.accumulated_chain.ctct_relinearized_debit_bits",
        observations.accumulated_ctct_debits, options.quantile_ppm);
    emit_stratified_distribution(
        record,
        "observed.accumulated_chain.switch_coefficient_recurrence_allowance",
        observations.accumulated_switch_allowances, options.quantile_ppm);

    record.text("candidate.fresh_canonical_error_bound",
                decimal(fresh_candidate));
    record.integer("candidate.ctct_relinearized_debit_bits",
                   ctct_quantile + options.debit_margin_bits);
    record.integer("candidate.plaintext_multiplication_debit_bits",
                   plaintext_quantile + options.debit_margin_bits);
    record.integer("candidate.rotation_debit_bits",
                   rotation_quantile + options.debit_margin_bits);
    record.integer(
        "candidate.base_proof.ctct_relinearized_debit_bits",
        ctct_quantile + options.debit_margin_bits);
    record.integer(
        "candidate.base_proof.plaintext_multiplication_debit_bits",
        base_proof_plaintext_quantile + options.debit_margin_bits);
    record.integer("candidate.base_proof.rotation_debit_bits", 0);
    record.text(
        "candidate.base_proof.ctct_source",
        "shared-SEAL-CTCT-plus-relinearization-primitive-and-accumulated-"
        "strata");
    record.text(
        "candidate.base_proof.plaintext_source",
        "production-promote-scale-scalar-and-vector-full-F_t-strata");
    record.text(
        "candidate.base_proof.status",
        "partial-empirical-operation-debits;requires-reviewed-operation-"
        "evidence-and-complete-assessment-at-the-exact-chain");
    record.text("candidate.empirical_switch_recurrence_with_margin",
                decimal(switch_margin_diagnostic));
    record.integer("candidate.switch_rounding_error_bound",
                   randomized_tail_heuristic);
    record.text("candidate.scheduler_magnitude_fields_fit_u64",
                fresh_candidate.fits_u64() &&
                        switch_margin_diagnostic.fits_u64()
                    ? "yes"
                    : "no");
    record.text("candidate.status",
                "empirical-operation-debits;switch-bound-is-randomized-tail-"
                "heuristic-for-deterministic-honest-switching;not-a-theorem-"
                "for-deterministic-adversarial-inputs");
    record.text("candidate.omitted_scheduler_fields",
                "maximum_switch_tax_bits;proof_suffix_level_reserve");
    record.text("observed.switch_allowance_definition",
                "max_coefficient(max(0,abs(error_after)-"
                "ceil(abs(error_before)/dropped_prime)));paired-transition-"
                "recurrence-residual-not-an-isolated-rounding-term");
    bench::emit_timing(record, "key_and_context_setup", setup_timing);
    bench::emit_timing(record, "sampling", timing);
    const bench::SystemInfo system = bench::system_info();
    record.text("environment.os", system.os);
    record.text("environment.cpu", system.cpu);
    record.integer("environment.peak_rss_bytes", system.peak_rss_bytes);
    record.text("verification.phase_identity_self_check", "PASS");
    record.text("verification.accumulated_suffix_reached", "PASS");
    record.text("verification.observed_switch_within_tail_heuristic",
                "PASS");
    record.text("verification.result", "PASS");
    return EXIT_SUCCESS;
}

} // namespace
} // namespace laminate

int main(int argc, char **argv) {
    try {
        return laminate::run(argc, argv);
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
