/// @file operator.cpp
/// @brief Construction and validation of transcript-packing operator rows.

#include "laminate/packing/analysis/operator.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace laminate::packing {
namespace {

PackingLinearOperator::AlignedCiphertext make_aligned_ciphertext(
    const PackingPlacement &placement, PackingSlotPattern slot_pattern,
    std::size_t aligned_index) {
    return PackingLinearOperator::AlignedCiphertext{
        .aligned_index = aligned_index,
        .source_index = placement.message_index,
        .slot_pattern = slot_pattern,
        .source_begin = placement.source_begin,
        .rotation_steps = placement.rotation_steps,
        .destination_begin = placement.destination_begin,
        .length = placement.length,
    };
}

void validate_row(const PackingLinearOperator &packing_operator,
                  const PackingLinearOperator::OutputRow &row,
                  std::vector<bool> &seen_aligned) {
    if (row.output_index >= packing_operator.rows.size() ||
        row.contributions.empty()) {
        throw std::invalid_argument(
            "packing operator: malformed output row");
    }

    std::vector<bool> occupied(packing_operator.slot_count, false);
    for (const auto &input : row.contributions) {
        if (input.aligned_index >= seen_aligned.size() ||
            seen_aligned[input.aligned_index] ||
            input.source_index >=
                packing_operator.source_ciphertext_count ||
            input.length == 0 ||
            input.destination_begin >= packing_operator.slot_count ||
            input.length >
                packing_operator.slot_count - input.destination_begin) {
            throw std::invalid_argument(
                "packing operator: malformed aligned ciphertext");
        }
        seen_aligned[input.aligned_index] = true;

        for (std::size_t offset = 0; offset < input.length; ++offset) {
            const std::size_t destination = input.destination_slot(
                packing_operator.slot_count, offset);
            if (destination >= packing_operator.slot_count ||
                occupied[destination]) {
                throw std::invalid_argument(
                    "packing operator: mask range mismatch or overlap");
            }
            occupied[destination] = true;
        }
    }
}

SignedCoefficientMask encode_checked(
    const PlaintextCoefficientEncoder &encode_coefficients,
    const fhe::SlotVector &mask, std::size_t expected_degree) {
    SignedCoefficientMask result = encode_coefficients(mask);
    if (result.empty() ||
        (expected_degree != 0 && result.size() != expected_degree)) {
        throw std::invalid_argument(
            "packing operator: coefficient encoder returned wrong degree");
    }
    return result;
}

PackingOperatorWeightAnalysis::OutputRow analyze_row(
    const PackingLinearOperator::OutputRow &row,
    std::size_t slot_count,
    const PlaintextCoefficientEncoder &encode_coefficients,
    std::size_t &ring_degree) {
    SignedCoefficientMask first = encode_checked(
        encode_coefficients,
        row.contributions.front().position_mask(slot_count),
        ring_degree);
    if (ring_degree == 0) {
        ring_degree = first.size();
    }
    PackingRowWeightAccumulator accumulator(ring_degree);
    accumulator.add(first);
    for (std::size_t index = 1; index < row.contributions.size(); ++index) {
        const SignedCoefficientMask lift = encode_checked(
            encode_coefficients,
            row.contributions[index].position_mask(slot_count), ring_degree);
        accumulator.add(lift);
    }
    return PackingOperatorWeightAnalysis::OutputRow{
        .output_index = row.output_index,
        .contribution_count = row.contributions.size(),
        .weight = accumulator.finish(),
    };
}

std::vector<SignedCoefficientMask> encode_digit_masks_checked(
    const PackingLinearOperator::AlignedCiphertext &contribution,
    std::size_t slot_count,
    const PlaintextCoefficientEncoder &encode_coefficients,
    const BalancedRadix &radix, std::size_t expected_degree) {
    const SignedCoefficientMask coefficients = encode_checked(
        encode_coefficients, contribution.position_mask(slot_count),
        expected_degree);
    return decompose_coefficient_mask(coefficients, radix);
}

std::vector<SignedDigitPackingWeightAnalysis::DigitRow>
analyze_signed_digit_row(
    const PackingLinearOperator::OutputRow &row, std::size_t slot_count,
    const PlaintextCoefficientEncoder &encode_coefficients,
    const BalancedRadix &radix, std::size_t &ring_degree) {
    std::vector<SignedCoefficientMask> first =
        encode_digit_masks_checked(row.contributions.front(), slot_count,
                                    encode_coefficients, radix, ring_degree);
    if (ring_degree == 0) {
        ring_degree = first.front().size();
    }

    std::vector<PackingRowWeightAccumulator> accumulators;
    std::vector<std::size_t> nonzero_coefficients(radix.digit_count, 0);
    accumulators.reserve(radix.digit_count);
    for (std::size_t digit = 0; digit < radix.digit_count; ++digit) {
        accumulators.emplace_back(ring_degree);
        accumulators.back().add(first[digit]);
        nonzero_coefficients[digit] +=
            static_cast<std::size_t>(std::count_if(
                first[digit].begin(), first[digit].end(),
                [](std::int64_t value) { return value != 0; }));
    }
    for (std::size_t contribution = 1;
         contribution < row.contributions.size(); ++contribution) {
        const auto masks = encode_digit_masks_checked(
            row.contributions[contribution], slot_count,
            encode_coefficients, radix, ring_degree);
        for (std::size_t digit = 0; digit < radix.digit_count; ++digit) {
            accumulators[digit].add(masks[digit]);
            nonzero_coefficients[digit] +=
                static_cast<std::size_t>(std::count_if(
                    masks[digit].begin(), masks[digit].end(),
                    [](std::int64_t value) { return value != 0; }));
        }
    }

    std::vector<SignedDigitPackingWeightAnalysis::DigitRow> result;
    result.reserve(radix.digit_count);
    for (std::size_t digit = 0; digit < radix.digit_count; ++digit) {
        result.push_back(SignedDigitPackingWeightAnalysis::DigitRow{
            .output_index = row.output_index,
            .digit_index = digit,
            .contribution_count = row.contributions.size(),
            .mask_nonzero_coefficients = nonzero_coefficients[digit],
            .weight = accumulators[digit].finish(),
        });
    }
    return result;
}

} // namespace

std::size_t PackingLinearOperator::AlignedCiphertext::destination_slot(
    std::size_t slot_count, std::size_t offset) const {
    if (offset >= length) {
        throw std::invalid_argument(
            "packing operator: destination offset is invalid");
    }
    if (slot_pattern == PackingSlotPattern::FixedMessageCoset) {
        return fhe::fixed_message_cell_slot(slot_count, offset) +
               destination_begin;
    }
    return destination_begin + offset;
}

fhe::SlotVector PackingLinearOperator::AlignedCiphertext::position_mask(
    std::size_t slot_count) const {
    if (slot_count == 0 || length == 0 || destination_begin >= slot_count ||
        length > slot_count - destination_begin) {
        throw std::invalid_argument(
            "packing operator: position mask range is invalid");
    }
    fhe::SlotVector result(slot_count, Fp::zero());
    for (std::size_t offset = 0; offset < length; ++offset) {
        const std::size_t destination = destination_slot(slot_count, offset);
        if (destination >= slot_count) {
            throw std::invalid_argument(
                "packing operator: destination slot is invalid");
        }
        result[destination] = Fp::one();
    }
    return result;
}

PackingLinearOperator make_packing_linear_operator(
    const PackingLayout &layout) {
    layout.validate();
    PackingLinearOperator result;
    result.slot_count = layout.slot_count;
    result.source_ciphertext_count = layout.message_active_slots.size();
    result.aligned_ciphertext_count = layout.placements.size();
    result.rows.resize(layout.packed_ciphertext_count);
    for (std::size_t row = 0; row < result.rows.size(); ++row) {
        result.rows[row].output_index = row;
    }
    for (std::size_t aligned = 0; aligned < layout.placements.size();
         ++aligned) {
        const PackingPlacement &placement = layout.placements[aligned];
        result.rows[placement.packed_index].contributions.push_back(
            make_aligned_ciphertext(placement, layout.slot_pattern, aligned));
    }
    result.validate();
    return result;
}

void PackingLinearOperator::validate() const {
    if (slot_count == 0 || source_ciphertext_count == 0 ||
        aligned_ciphertext_count == 0 || rows.empty()) {
        throw std::invalid_argument("packing operator: empty shape");
    }
    std::vector<bool> seen_aligned(aligned_ciphertext_count, false);
    for (std::size_t row_index = 0; row_index < rows.size(); ++row_index) {
        if (rows[row_index].output_index != row_index) {
            throw std::invalid_argument(
                "packing operator: noncanonical output order");
        }
        validate_row(*this, rows[row_index], seen_aligned);
    }
    if (!std::all_of(seen_aligned.begin(), seen_aligned.end(),
                     [](bool seen) { return seen; })) {
        throw std::invalid_argument(
            "packing operator: missing aligned ciphertext");
    }
}

PackingOperatorWeightAnalysis analyze_packing_operator_weights(
    const PackingLinearOperator &packing_operator,
    const PlaintextCoefficientEncoder &encode_coefficients) {
    packing_operator.validate();
    if (!encode_coefficients) {
        throw std::invalid_argument(
            "packing operator: coefficient encoder is absent");
    }

    PackingOperatorWeightAnalysis result;
    result.source_ciphertext_count =
        packing_operator.source_ciphertext_count;
    result.aligned_ciphertext_count =
        packing_operator.aligned_ciphertext_count;
    result.rows.reserve(packing_operator.rows.size());
    for (const auto &row : packing_operator.rows) {
        auto analysis = analyze_row(row, packing_operator.slot_count,
                                    encode_coefficients,
                                    result.ring_degree);
        result.maximum_row_weight_upper = std::max(
            result.maximum_row_weight_upper,
            analysis.weight.conservative_integer_upper);
        result.maximum_row_absolute_weight = std::max(
            result.maximum_row_absolute_weight,
            analysis.weight.total_absolute_coefficient_weight);
        result.rows.push_back(std::move(analysis));
    }
    if (result.ring_degree != packing_operator.slot_count) {
        throw std::invalid_argument(
            "packing operator: ring degree differs from slot count");
    }
    return result;
}

SignedDigitPackingWeightAnalysis analyze_signed_digit_packing_weights(
    const PackingLinearOperator &packing_operator,
    const PlaintextCoefficientEncoder &encode_coefficients,
    const BalancedRadix &radix) {
    packing_operator.validate();
    radix.validate();
    if (!encode_coefficients) {
        throw std::invalid_argument(
            "signed-digit packing: coefficient encoder is absent");
    }

    SignedDigitPackingWeightAnalysis result;
    result.radix = radix;
    result.source_ciphertext_count =
        packing_operator.source_ciphertext_count;
    result.aligned_ciphertext_count =
        packing_operator.aligned_ciphertext_count;
    result.logical_output_count = packing_operator.rows.size();
    result.rows.reserve(result.logical_output_count * radix.digit_count);
    for (const auto &row : packing_operator.rows) {
        auto digit_rows = analyze_signed_digit_row(
            row, packing_operator.slot_count, encode_coefficients, radix,
            result.ring_degree);
        for (auto &digit_row : digit_rows) {
            result.total_mask_nonzero_coefficients +=
                digit_row.mask_nonzero_coefficients;
            result.maximum_digit_row_weight_upper = std::max(
                result.maximum_digit_row_weight_upper,
                digit_row.weight.conservative_integer_upper);
            result.maximum_digit_row_absolute_weight = std::max(
                result.maximum_digit_row_absolute_weight,
                digit_row.weight.total_absolute_coefficient_weight);
            result.rows.push_back(std::move(digit_row));
        }
    }
    if (result.ring_degree != packing_operator.slot_count) {
        throw std::invalid_argument(
            "signed-digit packing: ring degree differs from slot count");
    }
    return result;
}

const SignedDigitRadixProfileAnalysis *
SignedDigitPackingFrontierAnalysis::selected_profile() const {
    if (!selected_index) {
        return nullptr;
    }
    if (*selected_index >= profiles.size()) {
        throw std::logic_error(
            "signed-digit frontier: selected profile is out of range");
    }
    return &profiles[*selected_index];
}

SignedDigitPackingFrontierAnalysis analyze_signed_digit_packing_frontier(
    const PackingLinearOperator &packing_operator,
    const PlaintextCoefficientEncoder &encode_coefficients,
    const SignedDigitFrontierInputs &inputs) {
    packing_operator.validate();
    if (inputs.packing_modulus < 3 || inputs.plaintext_modulus < 3 ||
        inputs.repetitions == 0 || inputs.selected_radix_base < 3) {
        throw std::invalid_argument(
            "signed-digit frontier: invalid public parameters");
    }

    SignedDigitPackingFrontierAnalysis result;
    result.inputs = inputs;
    result.honest_partial_decryption_bound =
        canonical_partial_decryption_bound(inputs.plaintext_modulus,
                                           inputs.honest_error_bound);
    bool found_selected_radix = false;
    for (const BalancedRadix &radix :
         canonical_balanced_radix_frontier(inputs.plaintext_modulus)) {
        found_selected_radix = found_selected_radix ||
                               radix.base == inputs.selected_radix_base;
        SignedDigitPackingWeightAnalysis weights =
            analyze_signed_digit_packing_weights(
                packing_operator, encode_coefficients, radix);
        const PackingModulusCapacity capacity =
            compute_packing_modulus_capacity(
                inputs.packing_modulus, inputs.plaintext_modulus,
                packing_operator.aligned_ciphertext_count,
                weights.maximum_digit_row_weight_upper);
        const LazyTernaryCertificateAssessment certificate =
            assess_lazy_ternary_certificate(
                LazyTernaryCertificateInputs{
                    .packing_modulus = inputs.packing_modulus,
                    .plaintext_modulus = inputs.plaintext_modulus,
                    .honest_partial_decryption_bound =
                        result.honest_partial_decryption_bound,
                    .ring_degree = packing_operator.slot_count,
                    .ciphertext_count =
                        packing_operator.aligned_ciphertext_count,
                    .repetitions = inputs.repetitions,
                    .maximum_row_weight_upper =
                        weights.maximum_digit_row_weight_upper,
                });
        const IndividualBoundPackingAssessment individual_bound_packing =
            assess_individual_bound_packing(
                inputs.packing_modulus,
                certificate.accepted_input_bounds
                    .individual_partial_decryption_bound,
                weights.maximum_digit_row_absolute_weight);
        result.profiles.push_back(SignedDigitRadixProfileAnalysis{
            .weights = std::move(weights),
            .capacity = capacity,
            .certificate = certificate,
            .individual_bound_packing = individual_bound_packing,
        });
        if (radix.base == inputs.selected_radix_base &&
            certificate.interactive_certificate_holds) {
            result.selected_index = result.profiles.size() - 1;
        }
    }
    if (!found_selected_radix) {
        throw std::invalid_argument(
            "signed-digit frontier: selected radix is not canonical");
    }
    return result;
}

} // namespace laminate::packing
