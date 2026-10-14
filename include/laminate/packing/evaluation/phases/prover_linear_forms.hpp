#ifndef LAMINATE_PACKING_EVALUATION_PHASES_PROVER_LINEAR_FORMS_HPP
#define LAMINATE_PACKING_EVALUATION_PHASES_PROVER_LINEAR_FORMS_HPP

/// @file prover_linear_forms.hpp
/// @brief Server-side FHE evaluation of revealed tests and packed digits.

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <utility>

namespace laminate::packing::lazy_ternary_detail {

/// Add an integer multiple in the ciphertext ring. Plaintext multiplication
/// lifts a scalar from its centered representative modulo t, so larger
/// multiplicities must be split before using that operation.
template <PublicCoefficientEncodingBackend Backend>
void add_integer_ciphertext_multiple(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &ciphertext,
    std::int64_t multiplicity,
    ExactZeroCiphertextAccumulator<Backend> &accumulator) {
    const bool negative = multiplicity < 0;
    std::uint64_t remaining = negative
        ? std::uint64_t{0} - static_cast<std::uint64_t>(multiplicity)
        : static_cast<std::uint64_t>(multiplicity);
    constexpr std::uint64_t kMaximumChunk = (kBaseFieldOrder - 1) / 2;
    std::optional<fhe::FheValue<Backend>> full_chunk;
    while (remaining != 0) {
        const std::uint64_t chunk = std::min(remaining, kMaximumChunk);
        if (!full_chunk || chunk != kMaximumChunk) {
            auto term = fhe::FheValue<Backend>::from_ciphertext(ciphertext);
            if (chunk == 1) {
                if (negative) {
                    term = fhe::value_negate<Backend>(eval, term);
                }
            } else {
                const Fp scalar = negative ? Fp::zero() - Fp(chunk)
                                           : Fp(chunk);
                term = fhe::value_mul<Backend>(
                    eval, term, fhe::FheValue<Backend>::public_scalar(scalar));
            }
            if (chunk == kMaximumChunk) {
                full_chunk = std::move(term);
            } else {
                accumulator.add(eval, std::move(term));
            }
        }
        if (chunk == kMaximumChunk) {
            accumulator.add(eval, *full_chunk);
        }
        remaining -= chunk;
    }
}

template <PublicCoefficientEncodingBackend Backend>
MixedPackingValue<Backend> form_test_value(
    const typename Backend::EvalContext &eval,
    const NormalizedAlignedTranscript<Backend> &aligned,
    std::span<const LazyTernaryChallenge> challenges) {
    const auto &values = aligned.values;
    if (values.size() != challenges.size()) {
        throw std::invalid_argument(
            "lazy-ternary evaluation: ragged challenge row");
    }
    // A signed sum of at most values.size() ternary entries cannot overflow.
    if (!std::in_range<std::int64_t>(values.size())) {
        throw std::overflow_error(
            "lazy-ternary evaluation: multiplicity exceeds signed range");
    }

    // Equal ciphertexts are combined before FHE work. In particular, `+C-C`
    // becomes a known public zero without manufacturing or subtracting an
    // encrypted zero.
    struct CombinedTerm {
        const typename Backend::Ciphertext *ciphertext = nullptr;
        std::int64_t coefficient = 0;
    };
    std::map<std::vector<std::uint8_t>, CombinedTerm> combined;
    MixedPackingValue<Backend> result;
    ExactZeroCiphertextAccumulator<Backend> encrypted_accumulator;
    fhe::FheValue<Backend> public_offset =
        fhe::FheValue<Backend>::public_zero();
    std::vector<std::uint64_t> public_c0;
    for (std::size_t index = 0; index < values.size(); ++index) {
        const int coefficient = challenges[index].coefficient();
        if (coefficient == 0) {
            continue;
        }
        if (coefficient != 1 && coefficient != -1) {
            throw std::invalid_argument(
                "lazy-ternary evaluation: coefficient is not ternary");
        }
        if (values[index].is_public_zero()) {
            continue;
        }
        if (values[index].is_public()) {
            if (!aligned.public_sources[index]) {
                continue;
            }
            ++result.public_term_count;
            fhe::FheValue<Backend> term = values[index];
            if (coefficient == -1) {
                term = fhe::value_negate<Backend>(eval, term);
            }
            fhe::value_add_assign<Backend>(eval, public_offset,
                                           std::move(term));
            const auto coordinates =
                normalized_aligned_coordinates(aligned, index);
            add_public_c0_scaled<Backend>(
                public_c0, coordinates.first(aligned.layout.slot_count),
                coefficient);
            continue;
        }
        const std::vector<std::uint8_t> encoding =
            Backend::serialize(values[index].ciphertext());
        CombinedTerm &term = combined[encoding];
        if (term.ciphertext == nullptr) {
            term.ciphertext = &values[index].ciphertext();
        }
        term.coefficient += coefficient;
    }

    for (const auto &[encoding, combined_term] : combined) {
        (void)encoding;
        add_integer_ciphertext_multiple<Backend>(
            eval, *combined_term.ciphertext, combined_term.coefficient,
            encrypted_accumulator);
    }
    result.encrypted_contribution =
        std::move(encrypted_accumulator).finish();
    if (!public_offset.is_public()) {
        throw std::logic_error(
            "lazy-ternary public offset became encrypted");
    }
    result.public_offset = public_offset.plaintext();
    discard_exact_zero_coordinates(public_c0);
    result.public_c0_coordinates = std::move(public_c0);
    return result;
}

template <SignedDigitPackingBackend Backend>
std::vector<MixedPackingValue<Backend>> form_signed_digit_values(
    const typename Backend::EvalContext &eval,
    const NormalizedAlignedTranscript<Backend> &aligned,
    const BalancedRadix &radix)
    requires SignedDigitPackingBackend<Backend>
{
    radix.validate();
    std::vector<MixedPackingValue<Backend>> accumulators(
        aligned.layout.packed_ciphertext_count * radix.digit_count);
    std::vector<ExactZeroCiphertextAccumulator<Backend>>
        encrypted_accumulators(accumulators.size());
    for (std::size_t index = 0; index < aligned.values.size(); ++index) {
        if (aligned.values[index].is_public_zero()) {
            continue;
        }
        const PackingPlacement &placement = aligned.layout.placements[index];
        const fhe::SlotVector position_mask =
            make_packing_destination_mask(aligned.layout, placement);
        const SignedCoefficientMask coefficients =
            Backend::encode_centered_plaintext_coefficients(eval,
                                                             position_mask);
        const auto digit_masks = decompose_coefficient_mask(coefficients,
                                                             radix);
        for (std::size_t digit = 0; digit < radix.digit_count; ++digit) {
            const std::size_t accumulator_index =
                placement.packed_index * radix.digit_count + digit;
            MixedPackingValue<Backend> &accumulator =
                accumulators[accumulator_index];
            const fhe::SlotVector digit_plaintext =
                Backend::decode_centered_plaintext_coefficients(
                    eval, digit_masks[digit]);
            if (std::all_of(digit_plaintext.begin(), digit_plaintext.end(),
                            [](const Fp &value) {
                                return value.is_zero();
                            })) {
                continue;
            }
            const fhe::FheValue<Backend> mask =
                fhe::FheValue<Backend>::public_slots(digit_plaintext);
            if (aligned.values[index].is_public()) {
                auto term = fhe::value_mul<Backend>(
                    eval, aligned.values[index], mask);
                fhe::FheValue<Backend> current =
                    fhe::FheValue<Backend>::public_plaintext(
                        accumulator.public_offset);
                fhe::value_add_assign<Backend>(eval, current,
                                               std::move(term));
                accumulator.public_offset = current.plaintext();

                const auto aligned_coordinates =
                    normalized_aligned_coordinates(aligned, index);
                const std::vector<std::uint64_t> mask_coordinates =
                    Backend::encode_lowest_plaintext_ntt_coordinates(
                        eval, digit_masks[digit]);
                if (mask_coordinates.size() != aligned.layout.slot_count) {
                    throw std::logic_error(
                        "signed-digit public mask has the wrong NTT width");
                }
                if (accumulator.public_c0_coordinates.empty()) {
                    accumulator.public_c0_coordinates.assign(
                        aligned.layout.slot_count, 0);
                }
                for (std::size_t coordinate = 0;
                     coordinate < aligned.layout.slot_count; ++coordinate) {
                    const std::uint64_t product = multiply_fq(
                        aligned_coordinates[coordinate],
                        mask_coordinates[coordinate]);
                    std::uint64_t &sum =
                        accumulator.public_c0_coordinates[coordinate];
                    sum = sum >= kOuterFieldOrder - product
                              ? sum - (kOuterFieldOrder - product)
                              : sum + product;
                }
                continue;
            }

            // Backend boundary: one plaintext/ciphertext multiplication for
            // each nonzero signed-digit mask, followed by linear accumulation.
            fhe::FheValue<Backend> term = fhe::value_mul<Backend>(
                eval, aligned.values[index], mask);
            if (!term.is_encrypted()) {
                throw std::logic_error(
                    "signed-digit encrypted term became public");
            }
            encrypted_accumulators[accumulator_index].add(
                eval, std::move(term));
        }
    }
    for (std::size_t index = 0; index < accumulators.size(); ++index) {
        MixedPackingValue<Backend> &accumulator = accumulators[index];
        accumulator.encrypted_contribution =
            std::move(encrypted_accumulators[index]).finish();
        discard_exact_zero_coordinates(accumulator.public_c0_coordinates);
    }
    return accumulators;
}

} // namespace laminate::packing::lazy_ternary_detail

#endif // LAMINATE_PACKING_EVALUATION_PHASES_PROVER_LINEAR_FORMS_HPP
