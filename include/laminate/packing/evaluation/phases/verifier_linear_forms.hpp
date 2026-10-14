#ifndef LAMINATE_PACKING_EVALUATION_PHASES_VERIFIER_LINEAR_FORMS_HPP
#define LAMINATE_PACKING_EVALUATION_PHASES_VERIFIER_LINEAR_FORMS_HPP

/// @file verifier_linear_forms.hpp
/// @brief Key-free reconstruction of public lazy-ternary contributions.

namespace laminate::packing::lazy_ternary_detail {

inline fhe::PublicPlaintext rotate_public_plaintext(
    const fhe::PublicPlaintext &plaintext, std::size_t slot_count,
    std::size_t steps) {
    plaintext.validate_slot_count(slot_count, "verifier public rotation");
    if (plaintext.is_scalar() || steps % slot_count == 0) {
        return plaintext;
    }
    return fhe::PublicPlaintext::from_slots(
        fhe::grid_rotate(plaintext.slots(), steps));
}

inline void add_scaled_public_plaintext(
    fhe::PublicPlaintext &accumulator,
    const fhe::PublicPlaintext &term, int coefficient,
    std::size_t slot_count) {
    if (coefficient != 1 && coefficient != -1) {
        throw std::invalid_argument(
            "verifier public coefficient is not ternary");
    }
    accumulator.validate_slot_count(slot_count,
                                    "verifier public accumulator");
    term.validate_slot_count(slot_count, "verifier public term");
    const Fp scale = coefficient == 1
                         ? Fp::one()
                         : Fp::zero() - Fp::one();
    if (accumulator.is_scalar() && term.is_scalar()) {
        accumulator = fhe::PublicPlaintext::from_scalar(
            accumulator.scalar() + scale * term.scalar());
        return;
    }
    fhe::SlotVector sum = accumulator.materialize(slot_count);
    const fhe::SlotVector values = term.materialize(slot_count);
    for (std::size_t slot = 0; slot < slot_count; ++slot) {
        sum[slot] += scale * values[slot];
    }
    accumulator = fhe::PublicPlaintext::from_slots(std::move(sum));
}

inline fhe::PublicPlaintext multiply_public_plaintexts(
    const fhe::PublicPlaintext &left, const fhe::PublicPlaintext &right,
    std::size_t slot_count) {
    left.validate_slot_count(slot_count, "verifier public product");
    right.validate_slot_count(slot_count, "verifier public product");
    if (left.is_scalar() && right.is_scalar()) {
        return fhe::PublicPlaintext::from_scalar(left.scalar() *
                                                 right.scalar());
    }
    fhe::SlotVector result = left.materialize(slot_count);
    const fhe::SlotVector right_slots = right.materialize(slot_count);
    for (std::size_t slot = 0; slot < slot_count; ++slot) {
        result[slot] *= right_slots[slot];
    }
    return fhe::PublicPlaintext::from_slots(std::move(result));
}

template <PublicCoefficientEncodingBackend Backend, typename Context>
    requires PublicCoefficientVerifierContext<Backend, Context>
void validate_verifier_projection(
    const Context &context,
    const NormalizedAlignedTranscript<Backend> &projection) {
    projection.layout.validate();
    if (Backend::slot_count(context) != projection.layout.slot_count ||
        projection.values.size() != projection.layout.placements.size() ||
        projection.public_coordinates.size() != projection.values.size() ||
        projection.public_sources.size() != projection.values.size() ||
        projection.ciphertext_list_digest) {
        throw std::invalid_argument(
            "verifier public projection does not match its layout");
    }
    const std::size_t width = 2 * projection.layout.slot_count;
    for (std::size_t index = 0; index < projection.values.size(); ++index) {
        const fhe::FheValue<Backend> &value = projection.values[index];
        const auto &coordinates = projection.public_coordinates[index];
        if (!value.is_public()) {
            throw std::invalid_argument(
                "verifier public projection contains a ciphertext");
        }
        value.plaintext().validate_slot_count(projection.layout.slot_count,
                                              "verifier public projection");
        if (!projection.public_sources[index]) {
            if (!value.is_public_zero() || !coordinates.empty()) {
                throw std::invalid_argument(
                    "verifier encrypted-message placeholder is malformed");
            }
            continue;
        }
        if (value.is_public_zero()) {
            if (!coordinates.empty()) {
                throw std::invalid_argument(
                    "verifier public zero has materialized coordinates");
            }
            continue;
        }
        if (coordinates.size() != width ||
            coordinates != normalized_public_value_coordinates<Backend>(
                               context, value.plaintext())) {
            throw std::invalid_argument(
                "verifier public projection coordinates are not canonical");
        }
    }
}

template <PublicCoefficientEncodingBackend Backend>
MixedPackingValue<Backend> form_verifier_test_value(
    const NormalizedAlignedTranscript<Backend> &projection,
    std::span<const LazyTernaryChallenge> challenges) {
    if (projection.values.size() != challenges.size()) {
        throw std::invalid_argument(
            "verifier lazy-ternary challenge row is ragged");
    }
    MixedPackingValue<Backend> result;
    const std::size_t slot_count = projection.layout.slot_count;
    for (std::size_t index = 0; index < projection.values.size(); ++index) {
        const int coefficient = challenges[index].coefficient();
        if (coefficient == 0 || !projection.public_sources[index] ||
            projection.values[index].is_public_zero()) {
            continue;
        }
        ++result.public_term_count;
        add_scaled_public_plaintext(
            result.public_offset, projection.values[index].plaintext(),
            coefficient, slot_count);
        const auto coordinates =
            normalized_aligned_coordinates(projection, index);
        add_public_c0_scaled<Backend>(
            result.public_c0_coordinates, coordinates.first(slot_count),
            coefficient);
    }
    discard_exact_zero_coordinates(result.public_c0_coordinates);
    return result;
}

template <PublicCoefficientEncodingBackend Backend, typename Context>
    requires PublicCoefficientVerifierContext<Backend, Context>
std::vector<MixedPackingValue<Backend>> form_verifier_signed_digit_values(
    const Context &context,
    const NormalizedAlignedTranscript<Backend> &projection,
    const BalancedRadix &radix) {
    radix.validate();
    const std::size_t slot_count = projection.layout.slot_count;
    std::vector<MixedPackingValue<Backend>> result(
        projection.layout.packed_ciphertext_count * radix.digit_count);
    for (std::size_t index = 0; index < projection.values.size(); ++index) {
        if (!projection.public_sources[index] ||
            projection.values[index].is_public_zero()) {
            continue;
        }
        const PackingPlacement &placement =
            projection.layout.placements[index];
        const fhe::SlotVector position_mask =
            make_packing_destination_mask(projection.layout, placement);
        const SignedCoefficientMask coefficients =
            Backend::encode_centered_plaintext_coefficients(context,
                                                             position_mask);
        const auto digit_masks = decompose_coefficient_mask(coefficients,
                                                             radix);
        for (std::size_t digit = 0; digit < radix.digit_count; ++digit) {
            const fhe::SlotVector digit_slots =
                Backend::decode_centered_plaintext_coefficients(
                    context, digit_masks[digit]);
            if (std::all_of(digit_slots.begin(), digit_slots.end(),
                            [](const Fp &value) {
                                return value.is_zero();
                            })) {
                continue;
            }
            MixedPackingValue<Backend> &accumulator =
                result[placement.packed_index * radix.digit_count + digit];
            const fhe::PublicPlaintext term = multiply_public_plaintexts(
                projection.values[index].plaintext(),
                fhe::PublicPlaintext::from_slots(digit_slots), slot_count);
            add_scaled_public_plaintext(accumulator.public_offset, term, 1,
                                        slot_count);

            const auto source_coordinates =
                normalized_aligned_coordinates(projection, index);
            const std::vector<std::uint64_t> mask_coordinates =
                Backend::encode_lowest_plaintext_ntt_coordinates(
                    context, digit_masks[digit]);
            if (mask_coordinates.size() != slot_count) {
                throw std::logic_error(
                    "verifier signed-digit mask has the wrong NTT width");
            }
            if (accumulator.public_c0_coordinates.empty()) {
                accumulator.public_c0_coordinates.assign(slot_count, 0);
            }
            for (std::size_t coordinate = 0; coordinate < slot_count;
                 ++coordinate) {
                const std::uint64_t product = multiply_fq(
                    source_coordinates[coordinate],
                    mask_coordinates[coordinate]);
                std::uint64_t &sum =
                    accumulator.public_c0_coordinates[coordinate];
                sum = sum >= kOuterFieldOrder - product
                          ? sum - (kOuterFieldOrder - product)
                          : sum + product;
            }
        }
    }
    for (auto &value : result) {
        discard_exact_zero_coordinates(value.public_c0_coordinates);
    }
    return result;
}

} // namespace laminate::packing::lazy_ternary_detail

#endif // LAMINATE_PACKING_EVALUATION_PHASES_VERIFIER_LINEAR_FORMS_HPP
