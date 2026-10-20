#ifndef LAMINATE_PACKING_EVALUATION_PHASES_ALIGNED_TRANSCRIPT_HPP
#define LAMINATE_PACKING_EVALUATION_PHASES_ALIGNED_TRANSCRIPT_HPP

/// @file aligned_transcript.hpp
/// @brief Alignment, bottom-level normalization, and public projection.

#include "laminate/packing/alignment/placement.hpp"

#include <stdexcept>
#include <utility>

namespace laminate::packing {

template <CoefficientWellFormednessBackend Backend>
NormalizedAlignedTranscript<Backend> prepare_normalized_aligned_transcript(
    const typename Backend::EvalContext &eval,
    std::span<const typename Backend::Ciphertext> round_ciphertexts,
    std::span<const std::size_t> message_active_slots) {
    if (round_ciphertexts.size() != message_active_slots.size()) {
        throw std::invalid_argument(
            "prepare_normalized_aligned_transcript: round-ciphertext and "
            "width counts differ");
    }
    return prepare_normalized_aligned_transcript<Backend>(
        eval, round_ciphertexts,
        make_prefix_packing_layout(Backend::slot_count(eval),
                                   message_active_slots));
}

template <CoefficientWellFormednessBackend Backend>
AlignedTranscriptDraft<Backend> materialize_aligned_transcript(
    const typename Backend::EvalContext &eval,
    std::span<const typename Backend::Ciphertext> round_ciphertexts,
    const PackingLayout &layout) {
    layout.validate();
    if (round_ciphertexts.size() != layout.message_active_slots.size() ||
        Backend::slot_count(eval) != layout.slot_count) {
        throw std::invalid_argument(
            "materialize_aligned_transcript: round ciphertexts do not match "
            "the layout");
    }
    std::vector<fhe::FheValue<Backend>> values;
    values.reserve(round_ciphertexts.size());
    for (const auto &ciphertext : round_ciphertexts) {
        values.push_back(fhe::FheValue<Backend>::from_ciphertext(ciphertext));
    }
    return materialize_aligned_transcript<Backend>(eval, values, layout);
}

template <CoefficientWellFormednessBackend Backend>
AlignedTranscriptDraft<Backend> materialize_aligned_transcript(
    const typename Backend::EvalContext &eval,
    std::span<const fhe::FheValue<Backend>> round_values,
    const PackingLayout &layout) {
    layout.validate();
    if (round_values.size() != layout.message_active_slots.size() ||
        Backend::slot_count(eval) != layout.slot_count) {
        throw std::invalid_argument(
            "materialize_aligned_transcript: round values do not match the "
            "layout");
    }
    AlignedTranscriptDraft<Backend> result;
    result.layout = layout;
    result.values.reserve(result.layout.placements.size());
    for (const PackingPlacement &placement : result.layout.placements) {
        result.values.push_back(fhe::value_rotate<Backend>(
            eval, round_values[placement.message_index],
            placement.rotation_steps));
    }
    return result;
}

template <CoefficientWellFormednessBackend Backend>
NormalizedAlignedTranscript<Backend> finalize_aligned_transcript(
    const typename Backend::EvalContext &eval,
    AlignedTranscriptDraft<Backend> draft) {
    draft.layout.validate();
    if (draft.values.size() != draft.layout.placements.size() ||
        Backend::slot_count(eval) != draft.layout.slot_count) {
        throw std::invalid_argument(
            "finalize_aligned_transcript: draft does not match its layout");
    }
    NormalizedAlignedTranscript<Backend> result;
    result.layout = std::move(draft.layout);
    result.values = std::move(draft.values);
    result.public_coordinates.resize(result.values.size());
    result.public_sources.resize(result.values.size(), false);

    // Choose the one-prime coefficient representation before any commitment
    // or challenge. Public zeros stay implicit; encrypted values are switched
    // and normalized exactly once here.
    for (std::size_t index = 0; index < result.values.size(); ++index) {
        fhe::FheValue<Backend> &value = result.values[index];
        if (value.is_public()) {
            if constexpr (PublicCoefficientEncodingBackend<Backend>) {
                result.public_sources[index] = true;
                if (!value.is_public_zero()) {
                    result.public_coordinates[index] =
                        normalized_public_value_coordinates<Backend>(
                            eval, value.plaintext());
                }
                continue;
            } else {
                throw std::invalid_argument(
                    "bound-only packing finalization cannot represent a "
                    "public value");
            }
        }
        Backend::mod_switch_to_lowest(eval, value.ciphertext());
        Backend::normalize_for_coefficient_commitment(eval,
                                                       value.ciphertext());
    }
    result.ciphertext_list_digest =
        lazy_ternary_detail::digest_aligned_values<Backend>(result.layout,
                                                            result);
    return result;
}

template <CoefficientWellFormednessBackend Backend>
NormalizedAlignedTranscript<Backend> prepare_normalized_aligned_transcript(
    const typename Backend::EvalContext &eval,
    std::span<const typename Backend::Ciphertext> round_ciphertexts,
    const PackingLayout &layout) {
    auto draft = materialize_aligned_transcript<Backend>(
        eval, round_ciphertexts, layout);
    return finalize_aligned_transcript<Backend>(eval, std::move(draft));
}

template <CoefficientWellFormednessBackend Backend>
NormalizedAlignedTranscript<Backend> prepare_normalized_aligned_transcript(
    const typename Backend::EvalContext &eval,
    std::span<const fhe::FheValue<Backend>> round_values,
    const PackingLayout &layout) {
    auto draft = materialize_aligned_transcript<Backend>(
        eval, round_values, layout);
    return finalize_aligned_transcript<Backend>(eval, std::move(draft));
}

template <PublicCoefficientEncodingBackend Backend, typename Context>
    requires PublicCoefficientVerifierContext<Backend, Context>
NormalizedAlignedTranscript<Backend> prepare_verifier_aligned_projection(
    const Context &context,
    std::span<const fhe::PublicPlaintext *const> round_public_values,
    const PackingLayout &layout) {
    layout.validate();
    if (round_public_values.size() != layout.message_active_slots.size() ||
        Backend::slot_count(context) != layout.slot_count) {
        throw std::invalid_argument(
            "verifier aligned projection does not match its layout");
    }
    NormalizedAlignedTranscript<Backend> result;
    result.layout = layout;
    result.values.reserve(layout.placements.size());
    result.public_coordinates.resize(layout.placements.size());
    result.public_sources.resize(layout.placements.size(), false);
    for (std::size_t index = 0; index < layout.placements.size(); ++index) {
        const PackingPlacement &placement = layout.placements[index];
        const fhe::PublicPlaintext *source =
            round_public_values[placement.message_index];
        if (source == nullptr) {
            result.values.push_back(fhe::FheValue<Backend>::public_zero());
            continue;
        }
        const fhe::PublicPlaintext aligned =
            lazy_ternary_detail::rotate_public_plaintext(
                *source, layout.slot_count, placement.rotation_steps);
        result.public_sources[index] = true;
        if (!aligned.is_zero()) {
            result.public_coordinates[index] =
                normalized_public_value_coordinates<Backend>(context,
                                                              aligned);
        }
        result.values.push_back(
            fhe::FheValue<Backend>::public_plaintext(aligned));
    }
    return result;
}

template <PublicCoefficientEncodingBackend Backend, typename Context>
    requires PublicCoefficientVerifierContext<Backend, Context>
NormalizedAlignedTranscript<Backend> prepare_verifier_aligned_projection(
    const Context &context,
    std::span<const std::optional<fhe::PublicPlaintext>> round_public_values,
    const PackingLayout &layout) {
    std::vector<const fhe::PublicPlaintext *> views;
    views.reserve(round_public_values.size());
    for (const auto &value : round_public_values) {
        views.push_back(value ? &*value : nullptr);
    }
    return prepare_verifier_aligned_projection<Backend>(
        context, std::span<const fhe::PublicPlaintext *const>(views), layout);
}

} // namespace laminate::packing

#endif // LAMINATE_PACKING_EVALUATION_PHASES_ALIGNED_TRANSCRIPT_HPP
