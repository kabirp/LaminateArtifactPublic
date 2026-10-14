/// @file packing_r1cs.cpp
/// @brief Bounded-memory fixed packing matrix generation.

#include "laminate/packing/outer_relation/packing_r1cs.hpp"

#include <algorithm>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

namespace laminate::packing {
namespace {

std::uint64_t checked_size(std::size_t value, const char *label) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds u64");
    }
    return static_cast<std::uint64_t>(value);
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows u64");
    }
    return left + right;
}

std::uint64_t checked_mul(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows u64");
    }
    return left * right;
}

OuterRelationR1csVariable constant_one() {
    return OuterRelationR1csVariable{
        .kind = OuterRelationR1csVariableKind::ConstantOne,
        .index = 0,
    };
}

OuterRelationR1csVariable public_input(std::uint64_t index) {
    return OuterRelationR1csVariable{
        .kind = OuterRelationR1csVariableKind::PublicInput,
        .index = index,
    };
}

OuterRelationR1csVariable witness(std::uint64_t index) {
    return OuterRelationR1csVariable{
        .kind = OuterRelationR1csVariableKind::Witness,
        .index = index,
    };
}

void validate_stream_shape(
    const OuterRelationPlan &plan,
    const PackingLinearOperator &packing_operator,
    const FixedPackingR1csEntryCursor::Encoders &encoders,
    const BalancedRadix &radix) {
    packing_operator.validate();
    radix.validate();
    if (!encoders.centered_coefficients || !encoders.native_ntt) {
        throw std::invalid_argument(
            "fixed packing R1CS stream: an encoder is absent");
    }
    if (packing_operator.slot_count != plan.shape.ring_degree ||
        packing_operator.aligned_ciphertext_count !=
            plan.shape.aligned_ciphertexts ||
        packing_operator.rows.size() !=
            plan.shape.logical_packed_outputs ||
        radix.digit_count != plan.shape.packing_digit_count) {
        throw std::invalid_argument(
            "fixed packing R1CS stream: operator does not match plan");
    }
}

void validate_centered_coefficients(
    std::span<const std::int64_t> coefficients,
    std::size_t ring_degree) {
    if (coefficients.size() != ring_degree) {
        throw std::invalid_argument(
            "fixed packing R1CS stream: centered encoder returned the "
            "wrong degree");
    }
}

void validate_native_coefficients(
    std::span<const std::uint64_t> coefficients,
    std::size_t ring_degree, std::uint64_t native_modulus) {
    if (coefficients.size() != ring_degree) {
        throw std::invalid_argument(
            "fixed packing R1CS stream: NTT encoder returned the wrong "
            "degree");
    }
    if (std::any_of(coefficients.begin(), coefficients.end(),
                    [=](std::uint64_t coefficient) {
                        return coefficient >= native_modulus;
                    })) {
        throw std::invalid_argument(
            "fixed packing R1CS stream: NTT encoder returned a "
            "noncanonical residue");
    }
}

} // namespace

FixedPackingR1csStorageEstimate estimate_fixed_packing_r1cs_storage(
    const OuterRelationPlan &plan) {
    const std::uint64_t degree =
        checked_size(plan.shape.ring_degree, "packing stream degree");
    const std::uint64_t aligned = checked_size(
        plan.shape.aligned_ciphertexts, "packing stream aligned count");
    const std::uint64_t digits = checked_size(
        plan.shape.packing_digit_count, "packing stream digit count");
    const std::uint64_t materialized_coordinates = checked_mul(
        checked_mul(aligned, digits,
                    "materialized packing multiplier coordinates"),
        degree, "materialized packing multiplier coordinates");
    const std::uint64_t streamed_coordinates = checked_mul(
        checked_add(digits, 1, "streamed packing coordinates"), degree,
        "streamed packing coordinates");
    return FixedPackingR1csStorageEstimate{
        .materialized_multiplier_coordinates = materialized_coordinates,
        .materialized_multiplier_bytes = checked_mul(
            materialized_coordinates, sizeof(std::uint64_t),
            "materialized packing multiplier bytes"),
        .streamed_digit_and_ntt_coordinates = streamed_coordinates,
        .streamed_digit_and_ntt_bytes = checked_mul(
            streamed_coordinates, sizeof(std::uint64_t),
            "streamed packing coordinate bytes"),
    };
}

FixedPackingR1csEntryCursor::FixedPackingR1csEntryCursor(
    const OuterRelationPlan &plan,
    const PackingLinearOperator &packing_operator,
    Encoders encoders, BalancedRadix radix)
    : plan_(&plan), packing_operator_(&packing_operator),
      encoders_(std::move(encoders)), radix_(std::move(radix)) {
    validate_stream_shape(plan, packing_operator, encoders_, radix_);

    contributions_.reserve(packing_operator.aligned_ciphertext_count);
    for (const PackingLinearOperator::OutputRow &row :
         packing_operator.rows) {
        for (const auto &aligned : row.contributions) {
            contributions_.push_back(ContributionReference{
                .logical_output = row.output_index,
                .aligned = &aligned,
            });
        }
    }
    std::sort(
        contributions_.begin(), contributions_.end(),
        [](const ContributionReference &left,
           const ContributionReference &right) {
            if (left.logical_output != right.logical_output) {
                return left.logical_output < right.logical_output;
            }
            return left.aligned->aligned_index <
                   right.aligned->aligned_index;
        });
}

bool FixedPackingR1csEntryCursor::empty() const {
    return stage_ == Stage::Done;
}

const FixedPackingR1csStreamStatistics &
FixedPackingR1csEntryCursor::statistics() const {
    return statistics_;
}

void FixedPackingR1csEntryCursor::load_contribution() {
    const auto &reference = contributions_.at(contribution_index_);
    const fhe::SlotVector mask = reference.aligned->position_mask(
        packing_operator_->slot_count);
    SignedCoefficientMask centered =
        encoders_.centered_coefficients(mask);
    validate_centered_coefficients(centered, plan_->shape.ring_degree);
    digit_masks_ = decompose_coefficient_mask(centered, radix_);
    if (digit_masks_.size() != radix_.digit_count ||
        std::any_of(digit_masks_.begin(), digit_masks_.end(),
                    [&](const SignedCoefficientMask &digit) {
                        return digit.size() != plan_->shape.ring_degree;
                    })) {
        throw std::logic_error(
            "fixed packing R1CS stream: digit decomposition has the "
            "wrong shape");
    }

    digit_index_ = 0;
    ntt_coordinate_ = 0;
    component_ = 0;
    contribution_loaded_ = true;
    digit_polynomial_loaded_ = false;
    const std::uint64_t coordinates_per_aligned =
        checked_mul(
            checked_size(plan_->shape.ciphertext_components,
                         "ciphertext component count"),
            checked_size(plan_->shape.ring_degree, "ring degree"),
            "coordinates per aligned ciphertext");
    aligned_witness_base_ = checked_add(
        plan_->variables.witness.aligned_ciphertext_coordinates.begin,
        checked_mul(checked_size(reference.aligned->aligned_index,
                                 "aligned input index"),
                    coordinates_per_aligned,
                    "aligned witness base"),
        "aligned witness base");
    ++statistics_.aligned_masks_encoded;
}

void FixedPackingR1csEntryCursor::load_digit_polynomial() {
    native_digit_polynomial_ =
        encoders_.native_ntt(digit_masks_.at(digit_index_));
    validate_native_coefficients(
        native_digit_polynomial_, plan_->shape.ring_degree,
        plan_->shape.native_modulus);
    ntt_coordinate_ = 0;
    component_ = 0;
    digit_polynomial_loaded_ = true;
    const ContributionReference &reference =
        contributions_[contribution_index_];
    const std::uint64_t physical = checked_add(
        checked_mul(checked_size(reference.logical_output,
                                 "logical output"),
                    checked_size(plan_->shape.packing_digit_count,
                                 "packing digit count"),
                    "physical packing output"),
        checked_size(digit_index_, "packing digit"),
        "physical packing output");
    digit_constraint_base_ = checked_add(
        plan_->constraints.revealed_packing_equalities.begin,
        checked_mul(
            checked_mul(
                physical,
                checked_size(plan_->shape.ciphertext_components,
                             "ciphertext component count"),
                "packing output component base"),
            checked_size(plan_->shape.ring_degree, "ring degree"),
            "packing output coordinate base"),
        "packing constraint base");
    ++statistics_.native_digit_polynomials_encoded;
}

std::optional<OuterRelationR1csMatrixEntry>
FixedPackingR1csEntryCursor::next_a_entry() {
    while (contribution_index_ < contributions_.size()) {
        if (!contribution_loaded_) {
            load_contribution();
        }
        if (digit_index_ == radix_.digit_count) {
            ++contribution_index_;
            contribution_loaded_ = false;
            digit_polynomial_loaded_ = false;
            continue;
        }
        if (!digit_polynomial_loaded_) {
            load_digit_polynomial();
        }

        while (ntt_coordinate_ < plan_->shape.ring_degree) {
            const std::size_t coordinate = ntt_coordinate_;
            const std::uint64_t coefficient =
                native_digit_polynomial_[coordinate];
            if (coefficient == 0) {
                ++ntt_coordinate_;
                component_ = 0;
                continue;
            }

            const std::size_t component = component_++;
            if (component_ == plan_->shape.ciphertext_components) {
                component_ = 0;
                ++ntt_coordinate_;
            }
            const std::uint64_t component_offset =
                static_cast<std::uint64_t>(component) *
                plan_->shape.ring_degree;
            ++statistics_.a_nonzero_entries;
            ++statistics_.total_nonzero_entries;
            return OuterRelationR1csMatrixEntry{
                .matrix = OuterRelationR1csMatrix::A,
                .constraint_index = digit_constraint_base_ +
                                    component_offset + coordinate,
                .variable = witness(aligned_witness_base_ +
                                    component_offset + coordinate),
                .coefficient = coefficient,
            };
        }

        ++digit_index_;
        digit_polynomial_loaded_ = false;
    }
    return std::nullopt;
}

OuterRelationR1csMatrixEntry
FixedPackingR1csEntryCursor::next_unit_entry(
    OuterRelationR1csMatrix matrix) {
    const std::uint64_t local = unit_row_offset_++;
    const std::uint64_t constraint = checked_add(
        plan_->constraints.revealed_packing_equalities.begin, local,
        "packing unit-entry row");
    if (matrix == OuterRelationR1csMatrix::B) {
        ++statistics_.b_nonzero_entries;
        ++statistics_.total_nonzero_entries;
        return OuterRelationR1csMatrixEntry{
            .matrix = matrix,
            .constraint_index = constraint,
            .variable = constant_one(),
            .coefficient = 1,
        };
    }
    ++statistics_.c_nonzero_entries;
    ++statistics_.total_nonzero_entries;
    return OuterRelationR1csMatrixEntry{
        .matrix = matrix,
        .constraint_index = constraint,
        .variable = public_input(checked_add(
            plan_->variables.public_inputs.revealed_packing_coordinates.begin,
            local, "packing public output")),
        .coefficient = 1,
    };
}

OuterRelationR1csMatrixEntry FixedPackingR1csEntryCursor::next() {
    while (true) {
        switch (stage_) {
        case Stage::PackingA:
            if (auto entry = next_a_entry()) {
                return *entry;
            }
            stage_ = Stage::PackingB;
            unit_row_offset_ = 0;
            break;
        case Stage::PackingB: {
            OuterRelationR1csMatrixEntry entry =
                next_unit_entry(OuterRelationR1csMatrix::B);
            if (unit_row_offset_ ==
                plan_->constraints.revealed_packing_equalities.count) {
                stage_ = Stage::PackingC;
                unit_row_offset_ = 0;
            }
            return entry;
        }
        case Stage::PackingC: {
            OuterRelationR1csMatrixEntry entry =
                next_unit_entry(OuterRelationR1csMatrix::C);
            if (unit_row_offset_ ==
                plan_->constraints.revealed_packing_equalities.count) {
                stage_ = Stage::Done;
                statistics_.complete = true;
            }
            return entry;
        }
        case Stage::Done:
            throw std::out_of_range(
                "fixed packing R1CS entry cursor is exhausted");
        }
    }
}

} // namespace laminate::packing
