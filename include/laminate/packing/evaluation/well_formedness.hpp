#ifndef LAMINATE_PACKING_EVALUATION_WELL_FORMEDNESS_HPP
#define LAMINATE_PACKING_EVALUATION_WELL_FORMEDNESS_HPP

/// @file well_formedness.hpp
/// @brief Auditable arithmetic for transcript-packing well-formedness.
///
/// This module supplies challenge generation and the public arithmetic
/// checks used by selected setup admission. It does not define a sound
/// transcript-packing profile: an honest-noise certificate,
/// a proof of the revealed linear combinations, and a Fiat--Shamir analysis
/// are still separate obligations.

#include "laminate/transcript/transcript.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace laminate::packing {

enum class TestCoefficientDistribution : std::uint8_t {
    BinarySubset,
    /// X = b_plus - b_minus for two independent Fiat--Shamir bits. Thus X is
    /// zero with probability 1/2 and each of +/-1 with probability 1/4.
    LazyTernary,
};

/// Shape of the public well-formedness relation proved by an outer circuit.
struct WellFormednessRelationShape {
    std::size_t ring_degree = 0;
    std::size_t ciphertext_count = 0;
    std::size_t repetitions = 0;
    std::size_t ciphertext_components = 2;
    TestCoefficientDistribution distribution =
        TestCoefficientDistribution::LazyTernary;
    /// Number of challenge bits represented by one outer-circuit field input.
    /// A field modulus strictly below 2^60 safely carries at most 59 bits.
    std::size_t public_input_capacity_bits = 59;
};

/// Constraint ledger for online Fiat--Shamir coefficients.
///
/// A preprocessed R1CS cannot treat online public inputs as constant matrix
/// coefficients. `coefficient_products` counts the multiplication constraints
/// for public-coefficient/witness-coordinate products.
struct WellFormednessConstraintEstimate {
    std::uint64_t revealed_ciphertext_coordinates = 0;
    std::uint64_t coefficient_products = 0;
    std::uint64_t output_relations = 0;
    std::uint64_t challenge_bits = 0;
    std::uint64_t booleanity_constraints = 0;
    std::uint64_t packed_public_inputs = 0;
    std::uint64_t public_input_recomposition_constraints = 0;
    std::uint64_t subtotal_constraints = 0;
};

WellFormednessConstraintEstimate estimate_well_formedness_constraints(
    const WellFormednessRelationShape &shape);

/// Shape of the fixed-coefficient relation that binds signed-digit packed
/// outputs to the same aligned ciphertext list.
struct FixedPackingRelationShape {
    std::size_t ring_degree = 0;
    std::size_t aligned_ciphertexts = 0;
    std::size_t packed_digit_ciphertexts = 0;
    std::size_t digit_count = 0;
    std::size_t ciphertext_components = 2;
};

struct FixedPackingRelationEstimate {
    std::uint64_t witness_input_coordinates = 0;
    std::uint64_t public_output_coordinates = 0;
    /// One R1CS linear-equality constraint per public output coordinate.
    std::uint64_t output_relation_constraints = 0;
    /// Conservative constant terms in the pointwise NTT-coordinate relation.
    /// Aligned SEAL ciphertexts are committed in NTT form, so this is O(Nfc),
    /// not the O(N^2fc) density of a coefficient-basis convolution matrix.
    std::uint64_t constant_matrix_terms = 0;
};

FixedPackingRelationEstimate estimate_fixed_packing_relation(
    const FixedPackingRelationShape &shape);

/// The original binary test's exact completeness/soundness gap, expressed in
/// the centered partial-decryption norm used by its proof.
struct BinarySubsetGap {
    std::uint64_t honest_test_bound = 0;
    std::uint64_t bad_ciphertext_trigger = 0;
    std::uint64_t per_ciphertext_slack_factor = 0;
};

BinarySubsetGap analyze_binary_subset_gap(
    std::uint64_t honest_partial_decryption_bound,
    std::size_t ciphertext_count);

/// For odd plaintext modulus `t`, convert an honest canonical BGV error bound
/// `beta_e` into
/// `P = t*beta_e + (t-1)/2` with checked arithmetic.
std::uint64_t canonical_partial_decryption_bound(
    std::uint64_t plaintext_modulus,
    std::uint64_t honest_error_bound);

/// For odd plaintext modulus `t`, convert a public bound `|y| <= Y` on a
/// normalized partial-decryption
/// coefficient into the corresponding canonical BGV error bound
///
///   |e| <= floor((Y + (t-1)/2) / t).
///
/// This is the soundness-side conversion. It must not be confused with
/// `canonical_partial_decryption_bound`, which maps the honest setup promise
/// in the opposite direction.
std::uint64_t canonical_error_bound_from_partial_decryption(
    std::uint64_t plaintext_modulus,
    std::uint64_t partial_decryption_bound);

/// Draw public binary masks directly from the Fiat--Shamir transcript.
///
/// Precondition: the caller has already observed the commitment to every
/// ciphertext being tested. No seed is returned and no caller-managed PRG is
/// involved.
std::vector<std::vector<bool>> derive_binary_subset_challenges(
    Transcript &transcript, std::size_t repetitions,
    std::size_t ciphertext_count);

/// Draw the dense lazy-ternary masks used by the well-formedness checks.
///
/// Both Fiat--Shamir bits are retained. In particular, a zero coefficient can
/// be encoded by either `00` or `11`; forgetting that distinction would make
/// a later packed-public-input relation fail to bind the exact transcript.
struct LazyTernaryChallenge {
    bool plus_bit = false;
    bool minus_bit = false;

    std::int8_t coefficient() const;
    bool operator==(const LazyTernaryChallenge &) const = default;
};

using LazyTernaryChallengeMatrix =
    std::vector<std::vector<LazyTernaryChallenge>>;

LazyTernaryChallengeMatrix derive_lazy_ternary_challenges(
    Transcript &transcript, std::size_t repetitions,
    std::size_t ciphertext_count);

/// Exact integer threshold `floor((37/4) * P * sqrt(r))` used by the
/// lazy-ternary client check.
///
/// The implementation uses checked 128-bit integer arithmetic rather than a
/// floating-point approximation. It throws if an input is zero or the exact
/// intermediate/result does not fit the supported integer domain.
std::uint64_t lazy_ternary_test_threshold(
    std::uint64_t honest_partial_decryption_bound,
    std::size_t ciphertext_count);

/// One concrete BGV plaintext mask represented by its centered polynomial
/// coefficients. These must be the coefficients emitted by the real encoder,
/// not the logical SIMD slots from which the plaintext was constructed.
using SignedCoefficientMask = std::vector<std::int64_t>;

/// Every input contribution to one final packed ciphertext.
struct PackingRowCoefficientLifts {
    std::vector<SignedCoefficientMask> contributions;
};

struct PackingRowWeight {
    /// W_l = sum_h sqrt(sum_i p[l,i,h]^2), for reporting only.
    long double approximate_mixed_norm = 0;
    /// Integer upper bound obtained by ceiling each inner square root. This is
    /// the value used by the fail-closed no-wrap check.
    std::uint64_t conservative_integer_upper = 0;
    /// A_l = sum_{i,h} |p[l,i,h]|. If soundness certifies only an
    /// individual bound |y[i,j]| <= B, then B*A_l is the exact elementary
    /// upper bound on every packed partial-decryption coefficient.
    std::uint64_t total_absolute_coefficient_weight = 0;
    long double cauchy_schwarz_upper = 0;
    long double coefficient_infinity_upper = 0;
};

/// Streaming row-weight computation. A target-size row can contain thousands
/// of dense degree-N mask polynomials, so the audit retains only one running
/// square sum per coefficient rather than all `r*N` coefficients.
class PackingRowWeightAccumulator {
  public:
    explicit PackingRowWeightAccumulator(std::size_t ring_degree);

    void add(std::span<const std::int64_t> centered_coefficients);
    PackingRowWeight finish() const;

    std::size_t ring_degree() const { return coefficient_square_sums_.size(); }
    std::size_t contribution_count() const { return contribution_count_; }

  private:
    std::vector<std::uint64_t> coefficient_square_sums_;
    long double squared_frobenius_ = 0;
    std::uint64_t maximum_coefficient_magnitude_ = 0;
    std::uint64_t total_absolute_coefficient_weight_ = 0;
    std::size_t contribution_count_ = 0;
};

PackingRowWeight compute_packing_row_weight(
    const PackingRowCoefficientLifts &row);

/// Budget consumed solely by the well-formedness slack and final
/// linear packing map. This excludes the encrypted GKR prover's earlier noise.
long double required_lazy_ternary_aligned_budget_bits(
    std::size_t aligned_ciphertext_count,
    std::uint64_t maximum_row_weight_upper);

/// Public inputs to the paper's fixed-list lazy-ternary theorem.
struct LazyTernaryCertificateInputs {
    std::uint64_t packing_modulus = 0;
    std::uint64_t plaintext_modulus = 0;
    std::uint64_t honest_partial_decryption_bound = 0;
    std::size_t ring_degree = 0;
    std::size_t ciphertext_count = 0;
    std::size_t repetitions = kPackingWellFormednessRepetitions;
    std::uint64_t maximum_row_weight_upper = 0;
};

/// Statistical bounds for one fixed-input well-formedness reduction.
/// The selected 120 tests give this fixed-list component a bad-acceptance
/// bound of at most 2^-120, leaving room for the protocol's at-least-110-bit
/// interactive integrity target before Fiat--Shamir composition.
struct LazyTernaryInteractiveProbabilityBounds {
    /// T independent tests miss a fixed violating column with probability at
    /// most 2^-T.
    std::size_t soundness_bits = 0;
    long double soundness_error_upper = 1;
    /// Conditional on every honest partial-decryption coefficient satisfying
    /// `|y[i,j]| <= P`, union-bound all T*N threshold checks.
    long double conditional_honest_rejection_probability_upper = 1;
    long double conditional_honest_completeness_bits_lower = 0;
};

/// Consequences of accepting all tests, outside the interactive soundness
/// error event.
struct LazyTernaryAcceptedInputBounds {
    /// Acceptance implies `|y[i,j]| <= 2*tau` for every input entry.
    std::uint64_t individual_partial_decryption_bound = 0;
    /// Canonical BGV error bound induced by the individual `y` bound.
    std::uint64_t individual_canonical_error_bound = 0;
    /// The theorem's strict real boundary `(111/2)*P*sqrt(r)` for each column.
    long double aggregate_column_l2_boundary = 0;
    /// Conservative integer upper `ceil((111/2)*P*ceil(sqrt(r)))`, when it
    /// fits u64. The no-wrap predicate uses these integer factors directly.
    std::optional<std::uint64_t> aggregate_column_l2_integer_upper;
};

/// Exact, fail-closed checks of conservative sufficient inequalities.
/// Passing this structure is not a sound-profile certificate by itself.
struct LazyTernaryCertificateAssessment {
    bool theorem_shape_supported = false;
    /// The direct toggle argument needs only tau < Q/4. The aggregate
    /// short-interval argument below uses the stronger 2*Q >= 333*P*r.
    bool individual_detection_premise = false;
    bool modular_detection_premise = false;
    bool packing_no_wrap = false;
    /// The fixed-commitment interactive detection statement is available.
    bool interactive_detection_guarantees_hold = false;
    /// Detection plus the selected packing operator's integer no-wrap bound.
    bool interactive_certificate_holds = false;
    std::uint64_t exact_test_threshold = 0;
    LazyTernaryAcceptedInputBounds accepted_input_bounds;
    LazyTernaryInteractiveProbabilityBounds interactive_probabilities;
    long double approximate_test_radius = 0;
    long double required_aligned_budget_bits = 0;
};

LazyTernaryCertificateAssessment assess_lazy_ternary_certificate(
    const LazyTernaryCertificateInputs &inputs);

/// No-wrap assessment when well-formedness supplies only a uniform
/// per-ciphertext coefficient bound rather than a columnwise l2 bound.
///
/// For a packing row with encoded masks p[l,i,h], the exact triangle
/// inequality is
///
///   |u[l,j]| <= B * sum_{i,h} |p[l,i,h]| = B*A_l.
///
/// The aggregate lazy-ternary certificate normally gives a substantially
/// tighter result, but retaining this comparison makes the role of the
/// direct O(sqrt(r)) soundness corollary auditable.
struct IndividualBoundPackingAssessment {
    std::uint64_t certified_input_bound = 0;
    std::uint64_t maximum_row_absolute_weight = 0;
    std::uint64_t maximum_admissible_input_bound = 0;
    bool packing_no_wrap = false;
};

IndividualBoundPackingAssessment assess_individual_bound_packing(
    std::uint64_t packing_modulus,
    std::uint64_t certified_input_bound,
    std::uint64_t maximum_row_absolute_weight);

/// Maximum honest-noise bounds admitted by a concrete one-limb packing
/// modulus and an already-computed operator row weight.
struct PackingModulusCapacity {
    /// Largest aggregate column norm B_pack for which
    /// `B_pack * W_upper < Q/2` is guaranteed by integer arithmetic.
    std::uint64_t maximum_safe_aggregate_input_norm = 0;
    /// Largest honest per-ciphertext partial-decryption bound P permitted by
    /// the lazy-ternary theorem's modular-detection premise.
    std::uint64_t
        maximum_honest_partial_decryption_bound_from_detection = 0;
    /// Largest honest P whose soundness certificate
    /// `(111/2) * P * sqrt(r)` fits inside `maximum_safe_aggregate_input_norm`.
    std::uint64_t
        maximum_honest_partial_decryption_bound_from_packing = 0;
    /// Minimum of the detection and packing capacities above.
    std::uint64_t maximum_honest_partial_decryption_bound = 0;
    bool admits_even_zero_error = false;
    std::uint64_t maximum_honest_error_bound = 0;
};

PackingModulusCapacity compute_packing_modulus_capacity(
    std::uint64_t packing_modulus,
    std::uint64_t plaintext_modulus,
    std::size_t aligned_ciphertext_count,
    std::uint64_t maximum_row_weight_upper);

} // namespace laminate::packing

#endif // LAMINATE_PACKING_EVALUATION_WELL_FORMEDNESS_HPP
