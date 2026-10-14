#ifndef LAMINATE_PACKING_EVALUATION_PHASES_CANONICAL_COORDINATES_HPP
#define LAMINATE_PACKING_EVALUATION_PHASES_CANONICAL_COORDINATES_HPP

/// @file canonical_coordinates.hpp
/// @brief Canonical bottom-prime coordinates and aligned-input validation.

#include <algorithm>
#include <stdexcept>

namespace laminate::packing {

template <PublicCoefficientEncodingBackend Backend, typename Context>
    requires PublicCoefficientVerifierContext<Backend, Context>
std::vector<std::uint64_t> normalized_public_value_coordinates(
    const Context &context, const fhe::PublicPlaintext &plaintext) {
    const std::size_t slot_count = Backend::slot_count(context);
    const fhe::SlotVector slots = plaintext.materialize(slot_count);
    const std::vector<std::int64_t> coefficients =
        Backend::encode_centered_plaintext_coefficients(context, slots);
    std::vector<std::uint64_t> result =
        Backend::encode_lowest_plaintext_ntt_coordinates(context,
                                                          coefficients);
    if (result.size() != slot_count ||
        std::any_of(result.begin(), result.end(),
                    [](std::uint64_t coordinate) {
                        return coordinate >= kOuterFieldOrder;
                    })) {
        throw std::logic_error(
            "public aligned value has malformed bottom-prime coordinates");
    }

    // Public data occupies the formal BGV pair `(NTT(plaintext), 0)`.
    // Keeping the c1 half implicit everywhere else avoids encrypting zero.
    result.resize(2 * slot_count, 0);
    return result;
}

template <PublicCoefficientEncodingBackend Backend>
std::span<const std::uint64_t> normalized_aligned_coordinates(
    const NormalizedAlignedTranscript<Backend> &aligned,
    std::size_t index) {
    if (index >= aligned.values.size() ||
        aligned.public_coordinates.size() != aligned.values.size()) {
        throw std::out_of_range(
            "normalized_aligned_coordinates: aligned index is invalid");
    }
    const fhe::FheValue<Backend> &value = aligned.values[index];
    if (value.is_public()) {
        if (aligned.public_coordinates[index].empty()) {
            throw std::logic_error(
                "normalized_aligned_coordinates: implicit verifier zero "
                "has no materialized coordinates");
        }
        return aligned.public_coordinates[index];
    }
    if (!aligned.public_coordinates[index].empty()) {
        throw std::logic_error(
            "normalized_aligned_coordinates: encrypted value owns public "
            "coordinates");
    }
    return Backend::coefficient_commitment_ntt_coordinate_view(
        value.ciphertext());
}

template <PublicCoefficientEncodingBackend Backend, typename Context>
    requires PublicCoefficientVerifierContext<Backend, Context>
std::vector<std::uint64_t> normalized_mixed_value_coordinates(
    const Context &context, const MixedPackingValue<Backend> &value) {
    const std::size_t slot_count = Backend::slot_count(context);
    value.public_offset.validate_slot_count(
        slot_count, "normalized_mixed_value_coordinates");
    if (!value.public_c0_coordinates.empty() &&
        value.public_c0_coordinates.size() != slot_count) {
        throw std::invalid_argument(
            "mixed packing value has the wrong public c0 width");
    }

    std::vector<std::uint64_t> result(2 * slot_count, 0);
    if (value.encrypted_contribution) {
        const auto &ciphertext = *value.encrypted_contribution;
        if (Backend::rns_limb_count(context, ciphertext) != 1 ||
            !Backend::is_normalized_for_coefficient_commitment(ciphertext)) {
            throw std::invalid_argument(
                "mixed packing encrypted contribution is not normalized");
        }
        const auto coordinates =
            Backend::coefficient_commitment_ntt_coordinate_view(ciphertext);
        if (coordinates.size() != result.size()) {
            throw std::invalid_argument(
                "mixed packing encrypted contribution has the wrong width");
        }
        std::copy(coordinates.begin(), coordinates.end(), result.begin());
    }
    for (std::size_t coordinate = 0;
         coordinate < value.public_c0_coordinates.size(); ++coordinate) {
        const std::uint64_t public_coordinate =
            value.public_c0_coordinates[coordinate];
        if (public_coordinate >= kOuterFieldOrder) {
            throw std::invalid_argument(
                "mixed packing public coordinate is outside Fq");
        }
        std::uint64_t &sum = result[coordinate];
        sum = sum >= kOuterFieldOrder - public_coordinate
                  ? sum - (kOuterFieldOrder - public_coordinate)
                  : sum + public_coordinate;
    }
    return result;
}

} // namespace laminate::packing

namespace laminate::packing::lazy_ternary_detail {

template <CoefficientWellFormednessBackend Backend>
void validate_aligned_transcript(
    const typename Backend::EvalContext &eval,
    const NormalizedAlignedTranscript<Backend> &aligned) {
    aligned.layout.validate();
    if (aligned.values.size() != aligned.layout.placements.size() ||
        aligned.public_coordinates.size() != aligned.values.size() ||
        aligned.public_sources.size() != aligned.values.size()) {
        throw std::invalid_argument(
            "lazy-ternary evaluation: aligned value count mismatch");
    }
    const std::size_t width = 2 * aligned.layout.slot_count;
    for (std::size_t index = 0; index < aligned.values.size(); ++index) {
        const fhe::FheValue<Backend> &value = aligned.values[index];
        const auto &public_coordinates = aligned.public_coordinates[index];
        if (value.is_public()) {
            if constexpr (!PublicCoefficientEncodingBackend<Backend>) {
                throw std::invalid_argument(
                    "bound-only aligned transcript contains a public value");
            } else {
                value.plaintext().validate_slot_count(
                    aligned.layout.slot_count,
                    "lazy-ternary aligned public value");
                if (!aligned.public_sources[index]) {
                    if (!value.is_public_zero() ||
                        !public_coordinates.empty()) {
                        throw std::invalid_argument(
                            "lazy-ternary verifier placeholder is not "
                            "implicit public zero");
                    }
                    continue;
                }
                if (value.is_public_zero() && public_coordinates.empty()) {
                    continue;
                }
                if (public_coordinates.size() != width ||
                    public_coordinates !=
                        normalized_public_value_coordinates<Backend>(
                            eval, value.plaintext())) {
                    throw std::invalid_argument(
                        "lazy-ternary evaluation: public aligned "
                        "coordinates are not canonical");
                }
                continue;
            }
        }
        if (aligned.public_sources[index] || !public_coordinates.empty() ||
            Backend::rns_limb_count(eval, value.ciphertext()) != 1 ||
            !Backend::is_normalized_for_coefficient_commitment(
                value.ciphertext())) {
            throw std::invalid_argument(
                "lazy-ternary evaluation: input is not normalized at the "
                "single-prime bottom level");
        }
        if constexpr (PublicCoefficientEncodingBackend<Backend>) {
            const auto coordinates =
                Backend::coefficient_commitment_ntt_coordinate_view(
                    value.ciphertext());
            if (coordinates.size() != width ||
                std::any_of(coordinates.begin(), coordinates.end(),
                            [](std::uint64_t coordinate) {
                                return coordinate >= kOuterFieldOrder;
                            })) {
                throw std::invalid_argument(
                    "lazy-ternary evaluation: aligned coordinates are "
                    "malformed");
            }
        }
    }
    if (aligned.ciphertext_list_digest &&
        digest_aligned_values<Backend>(aligned.layout, aligned) !=
            *aligned.ciphertext_list_digest) {
        throw std::invalid_argument(
            "lazy-ternary evaluation: aligned-list digest mismatch");
    }
}

} // namespace laminate::packing::lazy_ternary_detail

#endif // LAMINATE_PACKING_EVALUATION_PHASES_CANONICAL_COORDINATES_HPP
