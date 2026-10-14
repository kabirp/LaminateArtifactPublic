/// @file deterministic.cpp
/// @brief Exact integer implementation of deterministic BGV noise rules.

#include "laminate/fhe/noise/deterministic.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>
#include <utility>

namespace laminate::fhe {
namespace {

using Wide = unsigned __int128;

void append_u64(std::vector<std::uint8_t> &output,
                std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

NaturalMagnitude add_scalar(const NaturalMagnitude &value,
                            std::uint64_t scalar) {
    return NaturalMagnitude::add(value, NaturalMagnitude(scalar));
}

NaturalMagnitude twice(const NaturalMagnitude &value) {
    return NaturalMagnitude::multiply(value, std::uint64_t{2});
}

NaturalMagnitude modulus_product(
    std::span<const std::uint64_t> moduli) {
    if (moduli.empty()) {
        throw std::invalid_argument(
            "deterministic noise: modulus list is empty");
    }
    for (const std::uint64_t modulus : moduli) {
        if (modulus < 3 || modulus % 2 == 0) {
            throw std::invalid_argument(
                "deterministic noise: coefficient moduli must be odd");
        }
    }
    return NaturalMagnitude::product(moduli);
}

std::optional<DeterministicNoiseFailure> inherited_failure(
    const DeterministicNoiseBound &left,
    const DeterministicNoiseBound *right = nullptr) {
    if (left.first_failure) {
        return left.first_failure;
    }
    return right == nullptr ? std::nullopt : right->first_failure;
}

void record_failure(DeterministicNoiseBound &bound,
                    DeterministicNoiseOperation operation,
                    DeterministicNoiseFailureReason reason,
                    const NaturalMagnitude &failed_bound,
                    const NaturalMagnitude &modulus) {
    if (!bound.first_failure) {
        bound.first_failure = DeterministicNoiseFailure{
            .operation = operation,
            .reason = reason,
            .bound_bit_count = failed_bound.bit_count(),
            .modulus_bit_count = modulus.bit_count(),
        };
    }
}

void require_centered(DeterministicNoiseBound &bound,
                      DeterministicNoiseOperation operation,
                      DeterministicNoiseFailureReason reason,
                      const NaturalMagnitude &candidate,
                      const NaturalMagnitude &modulus) {
    if (!(twice(candidate) < modulus)) {
        record_failure(bound, operation, reason, candidate, modulus);
    }
}

DeterministicNoiseBound unary_result(
    const DeterministicNoiseBound &input,
    NaturalMagnitude partial_decryption_bound) {
    return DeterministicNoiseBound{
        .partial_decryption_bound =
            std::move(partial_decryption_bound),
        .operation_count = input.operation_count + 1,
        .first_failure = input.first_failure,
    };
}

DeterministicNoiseBound binary_result(
    const DeterministicNoiseBound &left,
    const DeterministicNoiseBound &right,
    NaturalMagnitude partial_decryption_bound) {
    return DeterministicNoiseBound{
        .partial_decryption_bound =
            std::move(partial_decryption_bound),
        .operation_count =
            std::max(left.operation_count, right.operation_count) + 1,
        .first_failure = inherited_failure(left, &right),
    };
}

NaturalMagnitude key_switch_accumulated_error(
    const DeterministicNoisePolicy &policy,
    std::span<const std::uint64_t> data_moduli) {
    NaturalMagnitude residue_l1_sum;
    for (const std::uint64_t modulus : data_moduli) {
        residue_l1_sum = NaturalMagnitude::add(
            residue_l1_sum, NaturalMagnitude(modulus - 1));
    }
    residue_l1_sum = NaturalMagnitude::multiply(
        residue_l1_sum,
        static_cast<std::uint64_t>(policy.ring_degree));
    return NaturalMagnitude::multiply(
        residue_l1_sum, policy.sampled_error_coefficient_bound);
}

} // namespace

NaturalMagnitude::NaturalMagnitude(std::uint64_t value) {
    if (value != 0) {
        limbs_.push_back(value);
    }
}

NaturalMagnitude::NaturalMagnitude(std::vector<std::uint64_t> limbs)
    : limbs_(std::move(limbs)) {
    trim();
}

void NaturalMagnitude::trim() {
    while (!limbs_.empty() && limbs_.back() == 0) {
        limbs_.pop_back();
    }
}

bool NaturalMagnitude::is_zero() const { return limbs_.empty(); }

std::size_t NaturalMagnitude::bit_count() const {
    return limbs_.empty()
               ? 0
               : 64 * (limbs_.size() - 1) +
                     std::bit_width(limbs_.back());
}

bool NaturalMagnitude::fits_u64() const { return limbs_.size() <= 1; }

std::uint64_t NaturalMagnitude::to_u64() const {
    if (!fits_u64()) {
        throw std::overflow_error(
            "natural magnitude: value does not fit uint64");
    }
    return limbs_.empty() ? 0 : limbs_.front();
}

bool operator<(const NaturalMagnitude &left,
               const NaturalMagnitude &right) {
    if (left.limbs_.size() != right.limbs_.size()) {
        return left.limbs_.size() < right.limbs_.size();
    }
    return std::lexicographical_compare(
        left.limbs_.rbegin(), left.limbs_.rend(), right.limbs_.rbegin(),
        right.limbs_.rend());
}

NaturalMagnitude NaturalMagnitude::add(const NaturalMagnitude &left,
                                       const NaturalMagnitude &right) {
    std::vector<std::uint64_t> result(
        std::max(left.limbs_.size(), right.limbs_.size()) + 1, 0);
    std::uint64_t carry = 0;
    for (std::size_t index = 0; index + 1 < result.size(); ++index) {
        const Wide sum =
            Wide{index < left.limbs_.size() ? left.limbs_[index] : 0} +
            (index < right.limbs_.size() ? right.limbs_[index] : 0) +
            carry;
        result[index] = static_cast<std::uint64_t>(sum);
        carry = static_cast<std::uint64_t>(sum >> 64);
    }
    result.back() = carry;
    return NaturalMagnitude(std::move(result));
}

NaturalMagnitude NaturalMagnitude::multiply(
    const NaturalMagnitude &left, const NaturalMagnitude &right) {
    if (left.is_zero() || right.is_zero()) {
        return NaturalMagnitude();
    }

    std::vector<std::uint64_t> result(
        left.limbs_.size() + right.limbs_.size(), 0);
    for (std::size_t left_index = 0;
         left_index < left.limbs_.size(); ++left_index) {
        std::uint64_t carry = 0;
        for (std::size_t right_index = 0;
             right_index < right.limbs_.size(); ++right_index) {
            const std::size_t output_index = left_index + right_index;
            const Wide product =
                Wide{left.limbs_[left_index]} *
                    right.limbs_[right_index] +
                result[output_index] + carry;
            result[output_index] =
                static_cast<std::uint64_t>(product);
            carry = static_cast<std::uint64_t>(product >> 64);
        }
        result[left_index + right.limbs_.size()] = carry;
    }
    return NaturalMagnitude(std::move(result));
}

NaturalMagnitude NaturalMagnitude::multiply(
    const NaturalMagnitude &value, std::uint64_t scalar) {
    return multiply(value, NaturalMagnitude(scalar));
}

NaturalMagnitude NaturalMagnitude::shift_left(
    const NaturalMagnitude &value, std::size_t bits) {
    if (value.is_zero() || bits == 0) {
        return value;
    }
    const std::size_t word_shift = bits / 64;
    const std::size_t bit_shift = bits % 64;
    const std::size_t extra = bit_shift == 0 ? 0 : 1;
    const std::size_t maximum = value.limbs_.max_size();
    if (word_shift > maximum || extra > maximum - word_shift ||
        value.limbs_.size() > maximum - word_shift - extra) {
        throw std::length_error(
            "natural magnitude: left shift exceeds maximum size");
    }
    std::vector<std::uint64_t> result(
        value.limbs_.size() + word_shift + extra, 0);
    std::uint64_t carry = 0;
    for (std::size_t index = 0; index < value.limbs_.size(); ++index) {
        const Wide shifted =
            (Wide{value.limbs_[index]} << bit_shift) | carry;
        result[index + word_shift] = static_cast<std::uint64_t>(shifted);
        carry = static_cast<std::uint64_t>(shifted >> 64);
    }
    if (bit_shift != 0) {
        result[value.limbs_.size() + word_shift] = carry;
    }
    return NaturalMagnitude(std::move(result));
}

NaturalMagnitude NaturalMagnitude::divide_floor(
    const NaturalMagnitude &value, std::uint64_t divisor) {
    if (divisor == 0) {
        throw std::invalid_argument(
            "natural magnitude: division by zero");
    }
    if (value.is_zero()) {
        return NaturalMagnitude();
    }

    std::vector<std::uint64_t> quotient(value.limbs_.size(), 0);
    std::uint64_t remainder = 0;
    for (std::size_t index = value.limbs_.size(); index-- > 0;) {
        const Wide dividend =
            (Wide{remainder} << 64) | value.limbs_[index];
        quotient[index] = static_cast<std::uint64_t>(dividend / divisor);
        remainder = static_cast<std::uint64_t>(dividend % divisor);
    }
    return NaturalMagnitude(std::move(quotient));
}

NaturalMagnitude NaturalMagnitude::divide_ceil(
    const NaturalMagnitude &value, std::uint64_t divisor) {
    if (divisor == 0) {
        throw std::invalid_argument(
            "natural magnitude: division by zero");
    }
    const NaturalMagnitude quotient = divide_floor(value, divisor);
    const NaturalMagnitude reconstructed = multiply(quotient, divisor);
    return reconstructed == value ? quotient : add_scalar(quotient, 1);
}

NaturalMagnitude NaturalMagnitude::product(
    std::span<const std::uint64_t> factors) {
    NaturalMagnitude result(1);
    for (const std::uint64_t factor : factors) {
        result = multiply(result, factor);
    }
    return result;
}

std::vector<std::uint8_t>
encode_canonical(const NaturalMagnitude &value) {
    if (value.limbs_.size() >
        (std::numeric_limits<std::size_t>::max() - 8U) / 8U) {
        throw std::overflow_error(
            "natural magnitude encoding: size overflows");
    }
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value.limbs_.size() >
            std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                "natural magnitude encoding: limb count does not fit u64");
        }
    }

    std::vector<std::uint8_t> output;
    output.reserve(8U + value.limbs_.size() * 8U);
    append_u64(output, static_cast<std::uint64_t>(value.limbs_.size()));
    for (const std::uint64_t limb : value.limbs_) {
        append_u64(output, limb);
    }
    return output;
}

NaturalMagnitude decode_canonical_natural_magnitude(
    std::span<const std::uint8_t> encoded) {
    constexpr std::size_t kWordBytes = sizeof(std::uint64_t);
    constexpr std::size_t kMaximumLimbs = 1U << 16U;
    if (encoded.size() < kWordBytes) {
        throw std::invalid_argument(
            "natural magnitude encoding is truncated");
    }
    auto read_word = [&](std::size_t offset) {
        std::uint64_t result = 0;
        for (std::size_t byte = 0; byte < kWordBytes; ++byte) {
            result |= static_cast<std::uint64_t>(encoded[offset + byte])
                      << (8U * byte);
        }
        return result;
    };
    const std::uint64_t encoded_count = read_word(0);
    if (encoded_count > kMaximumLimbs ||
        encoded_count >
            (std::numeric_limits<std::size_t>::max() - kWordBytes) /
                kWordBytes) {
        throw std::invalid_argument(
            "natural magnitude limb count exceeds its decode limit");
    }
    const std::size_t count = static_cast<std::size_t>(encoded_count);
    const std::size_t expected = kWordBytes + count * kWordBytes;
    if (encoded.size() != expected) {
        throw std::invalid_argument(
            "natural magnitude encoding has trailing or missing data");
    }
    std::vector<std::uint64_t> limbs;
    limbs.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        limbs.push_back(read_word(kWordBytes + index * kWordBytes));
    }
    if (!limbs.empty() && limbs.back() == 0) {
        throw std::invalid_argument(
            "natural magnitude encoding is not normalized");
    }
    return NaturalMagnitude(std::move(limbs));
}

const char *deterministic_noise_operation_name(
    DeterministicNoiseOperation operation) {
    switch (operation) {
    case DeterministicNoiseOperation::FreshAsymmetricEncryption:
        return "fresh-asymmetric-encryption";
    case DeterministicNoiseOperation::Negation:
        return "negation";
    case DeterministicNoiseOperation::Addition:
        return "addition";
    case DeterministicNoiseOperation::Subtraction:
        return "subtraction";
    case DeterministicNoiseOperation::PlaintextAddition:
        return "plaintext-addition";
    case DeterministicNoiseOperation::PlaintextMultiplication:
        return "plaintext-multiplication";
    case DeterministicNoiseOperation::CiphertextMultiplication:
        return "ciphertext-multiplication";
    case DeterministicNoiseOperation::Relinearization:
        return "relinearization";
    case DeterministicNoiseOperation::Rotation:
        return "rotation";
    case DeterministicNoiseOperation::ModulusSwitch:
        return "modulus-switch";
    }
    return "unknown";
}

const char *deterministic_noise_failure_name(
    DeterministicNoiseFailureReason reason) {
    switch (reason) {
    case DeterministicNoiseFailureReason::CiphertextModulusWrap:
        return "ciphertext-modulus-wrap";
    case DeterministicNoiseFailureReason::KeySwitchAccumulatorWrap:
        return "key-switch-accumulator-wrap";
    case DeterministicNoiseFailureReason::ModulusSwitchPrecondition:
        return "modulus-switch-precondition";
    }
    return "unknown";
}

void DeterministicNoisePolicy::validate() const {
    if (ring_degree < 2 || plaintext_modulus < 3 ||
        plaintext_modulus % 2 == 0 ||
        secret_hamming_weight_upper == 0 ||
        secret_hamming_weight_upper > ring_degree ||
        sampled_error_coefficient_bound == 0 ||
        ring_degree > std::numeric_limits<std::uint64_t>::max()) {
        throw std::invalid_argument(
            "deterministic noise: invalid public policy");
    }
}

std::uint64_t DeterministicNoisePolicy::plaintext_radius() const {
    validate();
    return (plaintext_modulus - 1) / 2;
}

bool fits_centered_modulus(
    const NaturalMagnitude &bound,
    std::span<const std::uint64_t> moduli) {
    return twice(bound) < modulus_product(moduli);
}

DeterministicNoiseBound bound_fresh_asymmetric_encryption(
    const DeterministicNoisePolicy &policy,
    std::uint64_t message_coefficient_bound,
    std::span<const std::uint64_t> data_moduli) {
    policy.validate();
    if (message_coefficient_bound > policy.plaintext_radius()) {
        throw std::invalid_argument(
            "deterministic noise: plaintext bound exceeds centered radius");
    }

    // e = e_0 + e_1*s - e_pk*u. The public-key error, fresh errors,
    // and ternary u are all sampled independently, but this rule uses only
    // their supports: |e| <= E * (1 + h + N).
    NaturalMagnitude convolution_terms(
        policy.secret_hamming_weight_upper);
    convolution_terms = add_scalar(
        convolution_terms,
        static_cast<std::uint64_t>(policy.ring_degree));
    convolution_terms = add_scalar(convolution_terms, 1);
    const NaturalMagnitude beta = NaturalMagnitude::multiply(
        convolution_terms, policy.sampled_error_coefficient_bound);
    NaturalMagnitude phase = NaturalMagnitude::multiply(
        beta, policy.plaintext_modulus);
    phase = add_scalar(phase, message_coefficient_bound);

    DeterministicNoiseBound result{
        .partial_decryption_bound = std::move(phase),
        .operation_count = 1,
    };
    const NaturalMagnitude modulus = modulus_product(data_moduli);
    require_centered(
        result,
        DeterministicNoiseOperation::FreshAsymmetricEncryption,
        DeterministicNoiseFailureReason::CiphertextModulusWrap,
        result.partial_decryption_bound, modulus);
    return result;
}

DeterministicNoiseBound bound_negation(
    const DeterministicNoiseBound &input) {
    return unary_result(input, input.partial_decryption_bound);
}

DeterministicNoiseBound bound_addition(
    const DeterministicNoiseBound &left,
    const DeterministicNoiseBound &right,
    std::span<const std::uint64_t> data_moduli,
    DeterministicNoiseOperation operation) {
    if (operation != DeterministicNoiseOperation::Addition &&
        operation != DeterministicNoiseOperation::Subtraction) {
        throw std::invalid_argument(
            "deterministic noise: invalid additive operation");
    }
    NaturalMagnitude phase = NaturalMagnitude::add(
        left.partial_decryption_bound, right.partial_decryption_bound);
    DeterministicNoiseBound result = binary_result(
        left, right, std::move(phase));
    const NaturalMagnitude modulus = modulus_product(data_moduli);
    require_centered(
        result, operation,
        DeterministicNoiseFailureReason::CiphertextModulusWrap,
        result.partial_decryption_bound, modulus);
    return result;
}

DeterministicNoiseBound bound_plaintext_addition(
    const DeterministicNoiseBound &input,
    std::uint64_t plaintext_coefficient_bound,
    std::span<const std::uint64_t> data_moduli) {
    NaturalMagnitude phase = add_scalar(
        input.partial_decryption_bound, plaintext_coefficient_bound);
    DeterministicNoiseBound result = unary_result(input, std::move(phase));
    const NaturalMagnitude modulus = modulus_product(data_moduli);
    require_centered(
        result, DeterministicNoiseOperation::PlaintextAddition,
        DeterministicNoiseFailureReason::CiphertextModulusWrap,
        result.partial_decryption_bound, modulus);
    return result;
}

DeterministicNoiseBound bound_plaintext_multiplication(
    const DeterministicNoiseBound &input,
    std::uint64_t plaintext_coefficient_l1_bound,
    std::span<const std::uint64_t> data_moduli) {
    NaturalMagnitude phase = NaturalMagnitude::multiply(
        input.partial_decryption_bound,
        plaintext_coefficient_l1_bound);
    DeterministicNoiseBound result = unary_result(input, std::move(phase));
    const NaturalMagnitude modulus = modulus_product(data_moduli);
    require_centered(
        result, DeterministicNoiseOperation::PlaintextMultiplication,
        DeterministicNoiseFailureReason::CiphertextModulusWrap,
        result.partial_decryption_bound, modulus);
    return result;
}

DeterministicNoiseBound bound_ciphertext_multiplication(
    const DeterministicNoisePolicy &policy,
    const DeterministicNoiseBound &left,
    const DeterministicNoiseBound &right,
    std::span<const std::uint64_t> data_moduli) {
    policy.validate();
    NaturalMagnitude phase = NaturalMagnitude::multiply(
        left.partial_decryption_bound, right.partial_decryption_bound);
    phase = NaturalMagnitude::multiply(
        phase, static_cast<std::uint64_t>(policy.ring_degree));
    DeterministicNoiseBound result = binary_result(
        left, right, std::move(phase));
    const NaturalMagnitude modulus = modulus_product(data_moduli);
    require_centered(
        result, DeterministicNoiseOperation::CiphertextMultiplication,
        DeterministicNoiseFailureReason::CiphertextModulusWrap,
        result.partial_decryption_bound, modulus);
    return result;
}

DeterministicNoiseBound bound_key_switch(
    const DeterministicNoisePolicy &policy,
    const DeterministicNoiseBound &input,
    std::span<const std::uint64_t> data_moduli,
    std::uint64_t special_modulus,
    DeterministicNoiseOperation operation) {
    policy.validate();
    if (operation != DeterministicNoiseOperation::Relinearization &&
        operation != DeterministicNoiseOperation::Rotation) {
        throw std::invalid_argument(
            "deterministic noise: key switch must be relin or rotation");
    }
    if (special_modulus < 3 || special_modulus % 2 == 0) {
        throw std::invalid_argument(
            "deterministic noise: invalid special modulus");
    }

    // SEAL decomposes the target into one non-centered residue polynomial per
    // data prime. For residue row j, ||target_j||_1 <= N(q_j-1). Each
    // symmetric evaluation-key encryption has error infinity norm at most E.
    const NaturalMagnitude accumulated_beta =
        key_switch_accumulated_error(policy, data_moduli);
    const NaturalMagnitude accumulated_phase = NaturalMagnitude::multiply(
        accumulated_beta, policy.plaintext_modulus);

    DeterministicNoiseBound result = unary_result(
        input, input.partial_decryption_bound);
    std::vector<std::uint64_t> key_moduli(data_moduli.begin(),
                                         data_moduli.end());
    key_moduli.push_back(special_modulus);
    const NaturalMagnitude key_modulus = modulus_product(key_moduli);
    require_centered(
        result, operation,
        DeterministicNoiseFailureReason::KeySwitchAccumulatorWrap,
        accumulated_phase, key_modulus);

    // The special-prime BGV switch divides inherited evaluation-key error by
    // q_k and contributes at most h+1 new canonical error units.
    NaturalMagnitude switched_beta = NaturalMagnitude::divide_ceil(
        accumulated_beta, special_modulus);
    switched_beta = add_scalar(
        switched_beta, policy.secret_hamming_weight_upper + 1);
    const NaturalMagnitude switched_phase = NaturalMagnitude::multiply(
        switched_beta, policy.plaintext_modulus);
    result.partial_decryption_bound = NaturalMagnitude::add(
        input.partial_decryption_bound, switched_phase);

    const NaturalMagnitude data_modulus = modulus_product(data_moduli);
    require_centered(
        result, operation,
        DeterministicNoiseFailureReason::CiphertextModulusWrap,
        result.partial_decryption_bound, data_modulus);
    return result;
}

NaturalMagnitude canonical_error_bound(
    const DeterministicNoisePolicy &policy,
    const NaturalMagnitude &partial_decryption_bound) {
    policy.validate();
    return NaturalMagnitude::divide_floor(
        add_scalar(partial_decryption_bound, policy.plaintext_radius()),
        policy.plaintext_modulus);
}

DeterministicModulusSwitchTransition derive_modulus_switch_transition(
    const DeterministicNoisePolicy &policy,
    const DeterministicNoiseBound &input,
    std::size_t ciphertext_component_count,
    std::span<const std::uint64_t> data_moduli_low_to_high) {
    policy.validate();
    if (ciphertext_component_count != 2) {
        throw std::invalid_argument(
            "deterministic noise: modulus switch requires size two");
    }
    if (data_moduli_low_to_high.size() < 2) {
        throw std::invalid_argument(
            "deterministic noise: modulus switch needs two data primes");
    }
    (void)modulus_product(data_moduli_low_to_high);

    const std::uint64_t dropped = data_moduli_low_to_high.back();
    const auto retained = data_moduli_low_to_high.first(
        data_moduli_low_to_high.size() - 1);
    const NaturalMagnitude retained_modulus = modulus_product(retained);

    // This is the exact fail-closed precondition used by the finalization
    // audit: ceil(P/q_l) + t(h+1) must remain centered modulo Q_{l-1}.
    NaturalMagnitude switch_phase = NaturalMagnitude::divide_ceil(
        input.partial_decryption_bound, dropped);
    const NaturalMagnitude rounding_phase = NaturalMagnitude::multiply(
        NaturalMagnitude(policy.secret_hamming_weight_upper + 1),
        policy.plaintext_modulus);
    switch_phase = NaturalMagnitude::add(switch_phase, rounding_phase);

    DeterministicNoiseBound result = unary_result(
        input, input.partial_decryption_bound);
    require_centered(
        result, DeterministicNoiseOperation::ModulusSwitch,
        DeterministicNoiseFailureReason::ModulusSwitchPrecondition,
        switch_phase, retained_modulus);

    const NaturalMagnitude input_beta = canonical_error_bound(
        policy, input.partial_decryption_bound);
    const NaturalMagnitude scaled_beta = NaturalMagnitude::divide_ceil(
        input_beta, dropped);
    const NaturalMagnitude rounding_beta(
        policy.secret_hamming_weight_upper + 1);
    const NaturalMagnitude output_beta = NaturalMagnitude::add(
        scaled_beta, rounding_beta);
    result.partial_decryption_bound = add_scalar(
        NaturalMagnitude::multiply(output_beta, policy.plaintext_modulus),
        policy.plaintext_radius());
    require_centered(
        result, DeterministicNoiseOperation::ModulusSwitch,
        DeterministicNoiseFailureReason::CiphertextModulusWrap,
        result.partial_decryption_bound, retained_modulus);
    return DeterministicModulusSwitchTransition{
        .dropped_modulus = dropped,
        .input_canonical_error_bound = input_beta,
        .scaled_inherited_error_bound = scaled_beta,
        .rounding_error_bound = rounding_beta,
        .output_canonical_error_bound = output_beta,
        .output_bound = std::move(result),
    };
}

DeterministicNoiseBound bound_modulus_switch(
    const DeterministicNoisePolicy &policy,
    const DeterministicNoiseBound &input,
    std::size_t ciphertext_component_count,
    std::span<const std::uint64_t> data_moduli_low_to_high) {
    return derive_modulus_switch_transition(
               policy, input, ciphertext_component_count,
               data_moduli_low_to_high)
        .output_bound;
}

} // namespace laminate::fhe
