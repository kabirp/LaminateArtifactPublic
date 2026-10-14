#ifndef LAMINATE_PARAMS_HPP
#define LAMINATE_PARAMS_HPP

/// @file params.hpp
/// @brief Central protocol parameters shared by every LaminateImpl module.

#include <array>
#include <cstddef>
#include <cstdint>

namespace laminate {

/// FHE plaintext modulus and payload base-field order.
inline constexpr std::uint64_t kBaseFieldOrder = 65537;

/// Since kBaseFieldOrder - 1 = 2^16, Fp supports roots through order 2^16.
inline constexpr std::size_t kBaseFieldTwoAdicity = 16;

/// Extension degree used for GKR and sumcheck challenges.
inline constexpr std::size_t kExtensionDegree = 8;

/// x^8 + x^3 + 1, constant coefficient first.
inline constexpr std::array<std::uint64_t, kExtensionDegree + 1>
    kExtensionModulusPoly = {1, 0, 0, 1, 0, 0, 0, 0, 1};

/// Polynomial modulus degree used by the named GCP benchmark profiles.
/// Component tests and diagnostic tools may explicitly choose another degree.
inline constexpr std::size_t kDefaultPolyModulusDegree = 1U << 14;

/// Arithmetic round-by-round integrity target before Fiat--Shamir. The final
/// incorrect-acceptance bound also depends on the adversary's move budget and
/// on hash and extraction assumptions; see docs/STATUS.md.
inline constexpr std::size_t kTargetSecurityBits = 110;

/// Proven unique-decoding BaseFold policy: one FRI per batch, rate 1/8,
/// and one final block of 150 query paths. Supports at most 34 folds in the
/// existing Fp^8 and Fq^2 fields. See basefold/soundness.hpp and
/// docs/BASEFOLD_SOUNDNESS.md for the RBR bound and its scope.
inline constexpr std::size_t kBaseFoldIntegrityTargetBits = 110;
inline constexpr std::size_t kGateMleBaseFoldLogRate = 3;
inline constexpr std::size_t kGateMleBaseFoldQueries = 150;

/// Concrete payload profile used by examples, benchmarks, and retained
/// parameter reports. These are workload-generator limits, not restrictions
/// on the payload circuit IR or the protocol APIs.
inline constexpr std::size_t kMaximumPayloadMultiplicativeDepth = 8;
inline constexpr std::size_t kBenchmarkDiamondInputCiphertexts = 64;
inline constexpr std::size_t kBenchmarkDiamondOutputCiphertexts = 1;
inline constexpr std::size_t kBenchmarkDiamondMiddleWidth = 61'681;
inline constexpr std::size_t kBenchmarkPayloadOperationCount = 1U << 20;

/// The balanced target retains eight equal CT-CT multiplication widths.
/// Its remaining operations are ciphertext additions and uniform scalar adds.
inline constexpr std::size_t kBenchmarkBalancedMultiplicationGateCount =
    kBenchmarkPayloadOperationCount / 2;
inline constexpr std::size_t kBenchmarkBalancedAdditionGateCount =
    (9 * kBenchmarkPayloadOperationCount + 10) / 20;
inline constexpr std::size_t kBenchmarkBalancedAddPlainGateCount =
    kBenchmarkPayloadOperationCount -
    kBenchmarkBalancedMultiplicationGateCount -
    kBenchmarkBalancedAdditionGateCount;
inline constexpr std::size_t kBenchmarkBalancedMiddleWidth = 65'536;

/// The multiplication-heavy target uses an approximately 85/10/5 split of
/// CT-CT multiplication, ciphertext addition, and Wide operations. Rotations
/// and nonuniform PT-CT products split the Wide budget equally. PT-CT products
/// run parallel to the first CT-CT layer and join the second layer's operands,
/// preserving CT-CT multiplication depth eight with PT-CT gates affine.
/// The width array gives generator-stage quotas. Some products of masked
/// inputs compile at an earlier depth; fixture tests pin the actual widths.
inline constexpr std::size_t kBenchmarkMulHeavyMultiplicationGateCount =
    (17 * kBenchmarkPayloadOperationCount + 10) / 20;
inline constexpr std::size_t kBenchmarkMulHeavyAdditionGateCount =
    (kBenchmarkPayloadOperationCount + 5) / 10;
inline constexpr std::size_t kBenchmarkMulHeavyWideGateCount =
    kBenchmarkPayloadOperationCount -
    kBenchmarkMulHeavyMultiplicationGateCount -
    kBenchmarkMulHeavyAdditionGateCount;
inline constexpr std::size_t kBenchmarkMulHeavyMulPlainGateCount =
    kBenchmarkMulHeavyWideGateCount / 2;
inline constexpr std::size_t kBenchmarkMulHeavyRotationGateCount =
    kBenchmarkMulHeavyWideGateCount -
    kBenchmarkMulHeavyMulPlainGateCount;
inline constexpr std::array<std::size_t,
                            kMaximumPayloadMultiplicativeDepth>
    kBenchmarkMulHeavyMultiplicationWidths = {
        434'176, 230'272, 115'136, 57'568,
        28'784,  14'392,  7'196,   3'766,
};

inline constexpr std::size_t benchmark_width_sum(
    const std::array<std::size_t,
                     kMaximumPayloadMultiplicativeDepth> &widths) {
    std::size_t result = 0;
    for (const std::size_t width : widths) {
        result += width;
    }
    return result;
}

static_assert(kBenchmarkBalancedMiddleWidth *
                  kMaximumPayloadMultiplicativeDepth ==
              kBenchmarkBalancedMultiplicationGateCount);
static_assert(benchmark_width_sum(kBenchmarkMulHeavyMultiplicationWidths) ==
              kBenchmarkMulHeavyMultiplicationGateCount);
static_assert(kBenchmarkMulHeavyMultiplicationGateCount +
                  kBenchmarkMulHeavyAdditionGateCount +
                  kBenchmarkMulHeavyMulPlainGateCount +
                  kBenchmarkMulHeavyRotationGateCount ==
              kBenchmarkPayloadOperationCount);
static_assert(kBenchmarkMulHeavyMultiplicationWidths.front() +
                  kBenchmarkMulHeavyMulPlainGateCount <=
              2 * kBenchmarkMulHeavyMultiplicationWidths[1]);

/// A Diamond performs `2*D*W` constant-width operations and `W-O`
/// additions in its terminal contraction.
inline constexpr std::size_t benchmark_diamond_operation_count(
    std::size_t depth, std::size_t width, std::size_t outputs) {
    return 2 * depth * width + width - outputs;
}

static_assert(benchmark_diamond_operation_count(
                  kMaximumPayloadMultiplicativeDepth,
                  kBenchmarkDiamondMiddleWidth,
                  kBenchmarkDiamondOutputCiphertexts) ==
              kBenchmarkPayloadOperationCount);

/// Native scalar field used by Poseidon, the packing R1CS, Spartan, and
/// BaseFold.  The prime has the factorization
///
///   q - 1 = 117 * 65,537 * 2^37.
///
/// It is therefore simultaneously a 60-bit BGV coefficient modulus with
/// correction-factor-preserving q = 1 (mod t), and a BaseFold field with
/// enough two-adicity for the target 2^32-variable witness at inverse rate
/// eight (the message-size ceiling is 2^34). Seven is a quadratic non-residue;
/// raising it by the odd cofactor
/// gives the primitive 2^37 root recorded below.
inline constexpr std::uint64_t kOuterFieldOrder =
    1'053'858'393'162'252'289ULL;
inline constexpr std::size_t kOuterFieldTwoAdicity = 37;
inline constexpr std::uint64_t kOuterFieldMaxTwoAdicRoot =
    218'306'605'351'835'581ULL;
inline constexpr std::uint64_t kOuterFieldQuadraticNonResidue = 7;
static_assert((kOuterFieldOrder >> 59U) == 1U);
static_assert((kOuterFieldOrder - 1U) %
                      (std::uint64_t{1} << kOuterFieldTwoAdicity) ==
                  0,
              "the final ciphertext prime must retain its 2-adic NTT roots");
static_assert(kOuterFieldOrder % kBaseFieldOrder == 1);
static_assert(((kOuterFieldOrder - 1) >> kOuterFieldTwoAdicity) ==
              117ULL * kBaseFieldOrder);

/// Poseidon ciphertext-commitment profile. Six capacity and digest elements
/// give a birthday collision scale of q^3, about 2^180. The round counts meet
/// the reference inequalities at design target M=180, with two extra full
/// rounds and a 7.5% partial-round margin. The quantitative collision curve
/// used in the concrete integrity bound remains a cryptographic assumption.
/// See crypto/README.md and tests/crypto/check_poseidon_parameters.py.
inline constexpr std::size_t kPoseidonDesignSecurityBits = 180;
inline constexpr std::size_t kPoseidonWidth = 16;
inline constexpr std::size_t kPoseidonRate = 10;
inline constexpr std::size_t kPoseidonCapacity =
    kPoseidonWidth - kPoseidonRate;
inline constexpr std::size_t kPoseidonFullRounds = 8;
inline constexpr std::size_t kPoseidonPartialRounds = 25;
inline constexpr std::size_t kPoseidonDigestElements = 6;
static_assert(kPoseidonCapacity == kPoseidonDigestElements);

/// Transcript-packing parameters for N=2^14.
///
/// Signed base 17 uses four coefficient digits. The honest-error envelope
/// beta_e=17,781 reserves N+2 for the final SEAL modulus-switch rounding and
/// 1,395 for scaled inherited noise. Alignment reserves at least two drops;
/// the prover also needs one upstream prime to meet the inherited-noise bound.
inline constexpr std::uint64_t kSelectedPackingRadixBase = 17;
/// Admission target for the interactive, round-by-round integrity analysis
/// before Fiat--Shamir and before instantiating the random oracle. The
/// quadratic extension has about 120 challenge bits, but degree and event
/// losses still have to be included in the protocol-level bound.
inline constexpr std::size_t kInteractiveIntegrityTargetBits = 110;

/// The native field is 60 bits, so transcript-packing sumchecks sample from a
/// roughly 120-bit quadratic extension.
inline constexpr std::size_t kTranscriptPackingChallengeBits = 120;

/// Repetitions in the implemented lazy-ternary well-formedness test. Its
/// fixed-list bad-acceptance term is at most 2^-T; this is only one component
/// of the full interactive integrity analysis.
inline constexpr std::size_t kPackingWellFormednessRepetitions = 120;

/// Packing witness and factored-matrix openings share the gate PCS policy.
/// The lazy-ternary ciphertext tests have their own independent parameter T.
inline constexpr std::size_t kTranscriptPackingBaseFoldLogRate =
    kGateMleBaseFoldLogRate;
inline constexpr std::size_t kTranscriptPackingBaseFoldQueries =
    kGateMleBaseFoldQueries;

inline constexpr std::size_t kPackingReservedMultDepth = 2;
inline constexpr std::uint64_t kPackingFinalRoundingErrorBound =
    kDefaultPolyModulusDegree + 2;
inline constexpr std::uint64_t kSelectedPackingHonestErrorBound = 17'781;
inline constexpr std::uint64_t kPackingInheritedErrorAllowance =
    kSelectedPackingHonestErrorBound - kPackingFinalRoundingErrorBound;

static_assert(kPackingInheritedErrorAllowance == 1'395);

} // namespace laminate

#endif // LAMINATE_PARAMS_HPP
