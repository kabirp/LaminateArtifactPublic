#ifndef LAMINATE_PACKING_ANALYSIS_OPERATOR_HPP
#define LAMINATE_PACKING_ANALYSIS_OPERATOR_HPP

/// @file operator.hpp
/// @brief Exact logical rows and encoded-mask weights for transcript packing.

#include "laminate/packing/alignment/layout.hpp"
#include "laminate/packing/evaluation/signed_digits.hpp"
#include "laminate/packing/evaluation/well_formedness.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace laminate::packing {

/// The linear map implemented after rotations and before final decryption.
///
/// The selected `FixedMessageCoset` layout never splits a round, so both count
/// fields equal the paper's `r`. The generic `Prefix` diagnostic may split a
/// round at a BGV-row or output boundary. Each such piece is a distinct
/// `AlignedCiphertext` because it has its own rotation and is an independent
/// input column of the final mask-and-sum map; that diagnostic geometry is not
/// the paper's transcript-packing profile.
struct PackingLinearOperator {
    struct AlignedCiphertext {
        std::size_t aligned_index = 0;
        std::size_t source_index = 0;
        PackingSlotPattern slot_pattern = PackingSlotPattern::Prefix;
        std::size_t source_begin = 0;
        std::size_t rotation_steps = 0;
        std::size_t destination_begin = 0;
        std::size_t length = 0;

        std::size_t destination_slot(std::size_t slot_count,
                                     std::size_t offset) const;

        /// Materialize the exact 0/1 position mask on demand. Keeping masks
        /// out of the schedule makes operator storage O(r), not O(rN).
        fhe::SlotVector position_mask(std::size_t slot_count) const;
    };

    struct OutputRow {
        std::size_t output_index = 0;
        std::vector<AlignedCiphertext> contributions;
    };

    std::size_t slot_count = 0;
    std::size_t source_ciphertext_count = 0;
    std::size_t aligned_ciphertext_count = 0;
    std::vector<OutputRow> rows;

    /// Reject malformed rows, overlapping masks, and inconsistent counts.
    void validate() const;
};

/// Convert the canonical 2 x (N/2) placement schedule into explicit rows.
PackingLinearOperator make_packing_linear_operator(
    const PackingLayout &layout);

/// Callback used to expose the real BGV encoder without coupling this module
/// to a particular FHE library. The result must contain exactly one centered
/// integer coefficient per ring coefficient.
using PlaintextCoefficientEncoder =
    std::function<SignedCoefficientMask(const fhe::SlotVector &)>;

struct PackingOperatorWeightAnalysis {
    struct OutputRow {
        std::size_t output_index = 0;
        std::size_t contribution_count = 0;
        PackingRowWeight weight;
    };

    std::size_t ring_degree = 0;
    std::size_t source_ciphertext_count = 0;
    std::size_t aligned_ciphertext_count = 0;
    std::uint64_t maximum_row_weight_upper = 0;
    std::uint64_t maximum_row_absolute_weight = 0;
    std::vector<OutputRow> rows;
};

/// Encode every actual position mask and compute the theorem's row weights.
///
/// This function does not certify honest ciphertext noise or packing
/// soundness. It supplies only the exact operator-specific input to the
/// separate lazy-ternary arithmetic assessment.
PackingOperatorWeightAnalysis analyze_packing_operator_weights(
    const PackingLinearOperator &packing_operator,
    const PlaintextCoefficientEncoder &encode_coefficients);

/// Row weights after coefficient-wise balanced-radix decomposition.
///
/// There is one physical ciphertext row for every
/// `(logical output, digit)` pair. The client recombines these rows after
/// decryption, so the large radix powers never enter an FHE noise bound.
struct SignedDigitPackingWeightAnalysis {
    struct DigitRow {
        std::size_t output_index = 0;
        std::size_t digit_index = 0;
        std::size_t contribution_count = 0;
        std::size_t mask_nonzero_coefficients = 0;
        PackingRowWeight weight;
    };

    BalancedRadix radix;
    std::size_t ring_degree = 0;
    std::size_t source_ciphertext_count = 0;
    std::size_t aligned_ciphertext_count = 0;
    std::size_t logical_output_count = 0;
    std::size_t total_mask_nonzero_coefficients = 0;
    std::uint64_t maximum_digit_row_weight_upper = 0;
    std::uint64_t maximum_digit_row_absolute_weight = 0;
    std::vector<DigitRow> rows;
};

/// Analyze the exact small coefficient polynomials used by signed-digit
/// packing, not the undecomposed position masks.
SignedDigitPackingWeightAnalysis analyze_signed_digit_packing_weights(
    const PackingLinearOperator &packing_operator,
    const PlaintextCoefficientEncoder &encode_coefficients,
    const BalancedRadix &radix);

/// Public parameters used to choose a coefficient-small packing profile.
struct SignedDigitFrontierInputs {
    std::uint64_t packing_modulus = 0;
    std::uint64_t plaintext_modulus = 0;
    std::uint64_t honest_error_bound = 0;
    std::size_t repetitions = kPackingWellFormednessRepetitions;
    /// Protocol-selected radix. The frontier still audits every canonical
    /// candidate, but it never silently substitutes a different profile.
    std::uint64_t selected_radix_base = 0;
};

struct SignedDigitRadixProfileAnalysis {
    SignedDigitPackingWeightAnalysis weights;
    PackingModulusCapacity capacity;
    LazyTernaryCertificateAssessment certificate;
    IndividualBoundPackingAssessment individual_bound_packing;
};

/// Exact analyses for canonical radices, ordered by ciphertext count.
/// `selected_index` names the configured radix only when it satisfies every
/// interactive theorem and operator inequality for the public error bound.
struct SignedDigitPackingFrontierAnalysis {
    SignedDigitFrontierInputs inputs;
    std::uint64_t honest_partial_decryption_bound = 0;
    std::vector<SignedDigitRadixProfileAnalysis> profiles;
    std::optional<std::size_t> selected_index;

    const SignedDigitRadixProfileAnalysis *selected_profile() const;
};

SignedDigitPackingFrontierAnalysis analyze_signed_digit_packing_frontier(
    const PackingLinearOperator &packing_operator,
    const PlaintextCoefficientEncoder &encode_coefficients,
    const SignedDigitFrontierInputs &inputs);

} // namespace laminate::packing

#endif // LAMINATE_PACKING_ANALYSIS_OPERATOR_HPP
