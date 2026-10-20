#ifndef LAMINATE_FHE_NOISE_DETERMINISTIC_HPP
#define LAMINATE_FHE_NOISE_DETERMINISTIC_HPP

/// @file deterministic.hpp
/// @brief Exact, fail-closed BGV coefficient-noise bounds.
///
/// The analyzer tracks
///
///   P(ct) = ||centered(c_0 + c_1 s + ...)||_infinity
///
/// as an integer coefficient bound at the ciphertext's current modulus.  It
/// uses arbitrary-size unsigned integers, so an insufficient modulus records
/// a failed proof obligation instead of overflowing or silently saturating.
/// The rules are deterministic worst-case rules for the pinned SEAL sampler;
/// they deliberately make no square-root cancellation assumption.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace laminate::fhe {

/// Small unsigned big integer used only by the offline bound analyzer.
class NaturalMagnitude {
  public:
    NaturalMagnitude() = default;
    explicit NaturalMagnitude(std::uint64_t value);

    bool is_zero() const;
    std::size_t bit_count() const;
    bool fits_u64() const;
    std::uint64_t to_u64() const;

    friend bool operator==(const NaturalMagnitude &left,
                           const NaturalMagnitude &right) = default;
    friend bool operator<(const NaturalMagnitude &left,
                          const NaturalMagnitude &right);

    static NaturalMagnitude add(const NaturalMagnitude &left,
                                const NaturalMagnitude &right);
    static NaturalMagnitude multiply(const NaturalMagnitude &left,
                                     const NaturalMagnitude &right);
    static NaturalMagnitude multiply(const NaturalMagnitude &value,
                                     std::uint64_t scalar);
    static NaturalMagnitude shift_left(const NaturalMagnitude &value,
                                       std::size_t bits);
    static NaturalMagnitude divide_floor(const NaturalMagnitude &value,
                                         std::uint64_t divisor);
    static NaturalMagnitude divide_ceil(const NaturalMagnitude &value,
                                        std::uint64_t divisor);
    static NaturalMagnitude product(std::span<const std::uint64_t> factors);

  private:
    explicit NaturalMagnitude(std::vector<std::uint64_t> limbs);
    void trim();

    friend std::vector<std::uint8_t>
    encode_canonical(const NaturalMagnitude &value);
    friend NaturalMagnitude decode_canonical_natural_magnitude(
        std::span<const std::uint8_t> encoded);

    /// Little-endian base-2^64 limbs. An empty vector is zero.
    std::vector<std::uint64_t> limbs_;
};

/// Exact self-delimiting encoding of an arbitrary-precision magnitude.
///
/// The format is a little-endian u64 normalized-limb count followed by that
/// many little-endian u64 limbs, least significant first. Zero has count
/// zero. No conversion through `to_u64()` occurs.
std::vector<std::uint8_t>
encode_canonical(const NaturalMagnitude &value);

/// Decode the exact normalized encoding produced by `encode_canonical`.
/// Truncated data, trailing data, a zero high limb, and unreasonable limb
/// counts are rejected before constructing the magnitude.
NaturalMagnitude decode_canonical_natural_magnitude(
    std::span<const std::uint8_t> encoded);

enum class DeterministicNoiseOperation {
    FreshAsymmetricEncryption,
    Negation,
    Addition,
    Subtraction,
    PlaintextAddition,
    PlaintextMultiplication,
    CiphertextMultiplication,
    Relinearization,
    Rotation,
    ModulusSwitch,
};

enum class DeterministicNoiseFailureReason {
    CiphertextModulusWrap,
    KeySwitchAccumulatorWrap,
    ModulusSwitchPrecondition,
};

const char *deterministic_noise_operation_name(
    DeterministicNoiseOperation operation);
const char *deterministic_noise_failure_name(
    DeterministicNoiseFailureReason reason);

/// First failed inequality in one ciphertext's public derivation.
struct DeterministicNoiseFailure {
    DeterministicNoiseOperation operation =
        DeterministicNoiseOperation::FreshAsymmetricEncryption;
    DeterministicNoiseFailureReason reason =
        DeterministicNoiseFailureReason::CiphertextModulusWrap;
    std::size_t bound_bit_count = 0;
    std::size_t modulus_bit_count = 0;
};

/// Public assumptions used by every operation rule.
struct DeterministicNoisePolicy {
    std::size_t ring_degree = 0;
    std::uint64_t plaintext_modulus = 0;
    /// Public upper bound on the ternary secret's Hamming weight.
    std::uint64_t secret_hamming_weight_upper = 0;
    /// Absolute support of each pinned error-sampler coefficient. SEAL 4.1.2
    /// with its default centered-binomial sampler has support [-21,21].
    std::uint64_t sampled_error_coefficient_bound = 21;

    void validate() const;
    std::uint64_t plaintext_radius() const;
};

/// Bound and accumulated proof obligations for one ciphertext.
struct DeterministicNoiseBound {
    NaturalMagnitude partial_decryption_bound;
    std::size_t operation_count = 0;
    std::optional<DeterministicNoiseFailure> first_failure;

    bool certifies_no_wrap() const { return !first_failure.has_value(); }
};

/// Bound a fresh public-key BGV encryption. `message_coefficient_bound` is the
/// infinity norm of the centered plaintext polynomial (zero for a private
/// encryption whose hidden message is zero).
DeterministicNoiseBound bound_fresh_asymmetric_encryption(
    const DeterministicNoisePolicy &policy,
    std::uint64_t message_coefficient_bound,
    std::span<const std::uint64_t> data_moduli);

DeterministicNoiseBound bound_negation(
    const DeterministicNoiseBound &input);

DeterministicNoiseBound bound_addition(
    const DeterministicNoiseBound &left,
    const DeterministicNoiseBound &right,
    std::span<const std::uint64_t> data_moduli,
    DeterministicNoiseOperation operation =
        DeterministicNoiseOperation::Addition);

/// Add one centered plaintext polynomial coefficientwise.
DeterministicNoiseBound bound_plaintext_addition(
    const DeterministicNoiseBound &input,
    std::uint64_t plaintext_coefficient_bound,
    std::span<const std::uint64_t> data_moduli);

/// Multiply by a plaintext polynomial with the stated coefficient l1 norm.
DeterministicNoiseBound bound_plaintext_multiplication(
    const DeterministicNoiseBound &input,
    std::uint64_t plaintext_coefficient_l1_bound,
    std::span<const std::uint64_t> data_moduli);

/// Multiply two ciphertexts before relinearization. Negacyclic convolution
/// contributes the factor `ring_degree`.
DeterministicNoiseBound bound_ciphertext_multiplication(
    const DeterministicNoisePolicy &policy,
    const DeterministicNoiseBound &left,
    const DeterministicNoiseBound &right,
    std::span<const std::uint64_t> data_moduli);

/// Add one SEAL RNS key switch. The rule includes the symmetric evaluation-key
/// error, the special-prime mod-t-and-divide step, and its h+1 rounding term.
DeterministicNoiseBound bound_key_switch(
    const DeterministicNoisePolicy &policy,
    const DeterministicNoiseBound &input,
    std::span<const std::uint64_t> data_moduli,
    std::uint64_t special_modulus,
    DeterministicNoiseOperation operation);

/// Drop the final entry of `data_moduli_low_to_high` using SEAL's BGV
/// mod-t-and-divide rule. The current h+1 rounding proof supports only a
/// size-two ciphertext; other component counts are rejected.
DeterministicNoiseBound bound_modulus_switch(
    const DeterministicNoisePolicy &policy,
    const DeterministicNoiseBound &input,
    std::size_t ciphertext_component_count,
    std::span<const std::uint64_t> data_moduli_low_to_high);

/// Exact public intermediates for one BGV mod-t-and-divide transition.
struct DeterministicModulusSwitchTransition {
    std::uint64_t dropped_modulus = 0;
    NaturalMagnitude input_canonical_error_bound;
    /// ceil(beta / dropped_modulus).
    NaturalMagnitude scaled_inherited_error_bound;
    /// h+1 canonical error units introduced by rounding with a ternary key.
    NaturalMagnitude rounding_error_bound;
    NaturalMagnitude output_canonical_error_bound;
    DeterministicNoiseBound output_bound;
};

DeterministicModulusSwitchTransition derive_modulus_switch_transition(
    const DeterministicNoisePolicy &policy,
    const DeterministicNoiseBound &input,
    std::size_t ciphertext_component_count,
    std::span<const std::uint64_t> data_moduli_low_to_high);

/// Canonical error bound implied by a partial-decryption bound:
/// floor((P + (t-1)/2) / t).
NaturalMagnitude canonical_error_bound(
    const DeterministicNoisePolicy &policy,
    const NaturalMagnitude &partial_decryption_bound);

/// Whether `bound` lies in the centered interval of the modulus product.
bool fits_centered_modulus(
    const NaturalMagnitude &bound,
    std::span<const std::uint64_t> moduli);

} // namespace laminate::fhe

#endif // LAMINATE_FHE_NOISE_DETERMINISTIC_HPP
