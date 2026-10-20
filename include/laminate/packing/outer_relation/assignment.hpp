#ifndef LAMINATE_PACKING_OUTER_RELATION_ASSIGNMENT_HPP
#define LAMINATE_PACKING_OUTER_RELATION_ASSIGNMENT_HPP

/// @file assignment.hpp
/// @brief Lazy target-scale assignment for the native-Q packing relation.

#include "laminate/packing/outer_relation/relation.hpp"
#include "laminate/packing/evaluation/lazy_ternary.hpp"
#include "laminate/storage/native_field_artifact.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

namespace laminate::packing {

/// One borrowed canonical ciphertext-coordinate array.
///
/// An absent lazy-ternary test is represented by `implicit_zero()` rather
/// than by allocating `2N` zero residues. A borrowed source must contain one
/// complete ciphertext in component-major NTT order.
class OuterRelationCiphertextCoordinateSlice {
  public:
    /// Borrow one concrete ciphertext. The span may not be empty and is
    /// validated against the relation width by the assignment constructor.
    static OuterRelationCiphertextCoordinateSlice borrowed(
        std::span<const std::uint64_t> coordinates);
    /// Borrow an optional encrypted coordinate vector plus an exact public c0
    /// overlay. `total_width` is `2N`; the public span is empty or length N.
    static OuterRelationCiphertextCoordinateSlice mixed(
        std::span<const std::uint64_t> encrypted_coordinates,
        std::span<const std::uint64_t> public_c0_coordinates,
        std::size_t total_width);
    /// Represent the protocol's absent optional test as public all-zero
    /// coordinates without allocating a zero buffer.
    static OuterRelationCiphertextCoordinateSlice implicit_zero();

    bool is_implicit_zero() const;
    std::size_t size() const;
    std::span<const std::uint64_t> coordinates() const;
    std::span<const std::uint64_t> public_c0_coordinates() const;
    std::uint64_t value(std::size_t coordinate) const;

  private:
    explicit OuterRelationCiphertextCoordinateSlice(
        std::span<const std::uint64_t> coordinates,
        std::span<const std::uint64_t> public_c0_coordinates,
        std::size_t logical_size, bool implicit_zero);

    std::span<const std::uint64_t> coordinates_;
    std::span<const std::uint64_t> public_c0_coordinates_;
    std::size_t logical_size_ = 0;
    bool implicit_zero_ = false;
};

/// Non-owning source layout for the lazy outer assignment.
///
/// Each vector contains one descriptor per logical ciphertext, not one field
/// element per coordinate. The underlying challenge words and ciphertexts
/// must outlive the assignment view and must not move or mutate while it is
/// being consumed.
struct OuterRelationR1csInputSlices {
    std::span<const std::uint64_t> packed_challenge_words;
    std::vector<OuterRelationCiphertextCoordinateSlice>
        revealed_test_ciphertexts;
    std::vector<OuterRelationCiphertextCoordinateSlice>
        revealed_packing_ciphertexts;
    std::vector<OuterRelationCiphertextCoordinateSlice>
        aligned_ciphertexts;
};

/// Byte ledger for the owning and lazy assignment representations.
///
/// Field-source fields count payload bytes. `borrowed_slice_descriptor_bytes`
/// additionally counts the concrete descriptor objects owned by the view.
/// The lazy view retains no derived challenge-bit or product vector.
struct OuterRelationR1csAssignmentStorage {
    std::uint64_t public_source_bytes = 0;
    std::uint64_t aligned_source_bytes = 0;
    std::uint64_t challenge_word_source_bytes = 0;
    std::uint64_t borrowed_ciphertext_coordinate_bytes = 0;
    std::uint64_t borrowed_slice_descriptor_bytes = 0;
    std::uint64_t flattened_coordinate_copy_bytes_avoided = 0;
    std::uint64_t eager_product_auxiliary_bytes = 0;
    std::uint64_t eager_flat_assignment_bytes = 0;
    std::uint64_t lazy_derived_witness_bytes = 0;
};

OuterRelationR1csAssignmentStorage
estimate_outer_relation_r1cs_assignment_storage(
    const OuterRelationPlan &plan);

/// Caller-owned resources for emitting the canonical outer assignment to
/// disk. The destination must be an existing empty private directory.
/// `max_working_field_bytes` bounds the Fq conversion buffer; reader and
/// writer objects, fixed hashing buffers, and allocator metadata are outside
/// that deterministic counter.
struct OuterRelationAssignmentArtifactOptions {
    std::filesystem::path directory;
    storage::NativeFieldArtifactOptions storage_limits;
    std::uint64_t max_working_field_bytes = 0;
    std::size_t block_elements = 0;
};

struct OuterRelationAssignmentArtifactReport {
    std::uint64_t public_input_elements = 0;
    std::uint64_t witness_elements = 0;
    std::uint64_t derived_product_elements = 0;
    std::uint64_t public_payload_bytes = 0;
    std::uint64_t witness_payload_bytes = 0;
    std::uint64_t physical_bytes = 0;
    std::uint64_t artifact_validation_bytes = 0;
    std::uint64_t sequential_write_payload_bytes = 0;
    std::uint64_t peak_working_field_bytes = 0;

    bool operator==(
        const OuterRelationAssignmentArtifactReport &) const = default;
};

struct OuterRelationAssignmentArtifact {
    std::shared_ptr<const storage::NativeFieldArtifact> artifact;
    OuterRelationAssignmentArtifactReport report;
};

/// Stable identity of the canonical public/witness order fixed by `plan`.
Digest outer_relation_assignment_artifact_identity(
    const OuterRelationPlan &plan);

/// Exact completed assignment-artifact size derived from `plan`, without
/// constructing the assignment or touching its future destination.
std::uint64_t outer_relation_assignment_artifact_physical_bytes(
    const OuterRelationPlan &plan);

/// Reopen and validate an assignment artifact against `plan`.
std::shared_ptr<const storage::NativeFieldArtifact>
open_outer_relation_assignment_artifact(
    const std::filesystem::path &directory,
    const OuterRelationPlan &plan);

/// Read-only assignment view that derives the enormous auxiliary witness.
///
/// Challenge bits are unpacked from public words and each well-formedness
/// product is computed as `(b_plus-b_minus) * C mod Q` only when requested.
/// Construction checks every source length and residue once. Random access
/// then performs no repeated whole-source scan.
class OuterRelationR1csAssignmentView {
  public:
    /// Diagnostic adapter over the existing flat input vectors.
    ///
    /// `plan`, `public_inputs`, and `witness_inputs` must outlive the view and
    /// must not move or mutate during traversal.
    OuterRelationR1csAssignmentView(
        const OuterRelationPlan &plan,
        const OuterRelationPublicInputs &public_inputs,
        const OuterRelationWitnessInputs &witness_inputs);

    /// Construct directly over normalized ciphertext storage.
    ///
    /// This is the target proof-adapter path. The view owns the small slice
    /// descriptor vectors but borrows every field element. `plan` and all
    /// buffers referenced by `input_slices` must outlive the view and remain
    /// fixed. Revealed test and packing slices may be implicit zero.
    OuterRelationR1csAssignmentView(
        const OuterRelationPlan &plan,
        OuterRelationR1csInputSlices input_slices);

    const OuterRelationPlan &plan() const;
    std::uint64_t public_value(std::uint64_t index) const;
    std::uint64_t witness_value(std::uint64_t index) const;

  private:
    friend class OuterRelationWitnessValueCursor;

    std::uint8_t challenge_bit(std::uint64_t local_bit) const;
    std::uint64_t ternary_coefficient(std::size_t test,
                                      std::size_t aligned) const;
    std::uint64_t product_value(std::uint64_t local_product) const;
    const OuterRelationCiphertextCoordinateSlice &aligned_ciphertext(
        std::size_t aligned) const;

    const OuterRelationPlan *plan_ = nullptr;
    OuterRelationR1csInputSlices input_slices_;
};

/// Emit `public-inputs` and `witness` as native-field arrays by walking the
/// lazy cursors. In particular, the `T*r*2N` product family is generated one
/// value at a time and is never retained as a vector. On failure, the empty
/// caller-owned destination is restored. The borrowed assignment sources
/// remain untouched and must outlive this call.
OuterRelationAssignmentArtifact write_outer_relation_assignment_artifact(
    const OuterRelationR1csAssignmentView &assignment,
    OuterRelationAssignmentArtifactOptions options);

/// Build a zero-copy assignment view from backend ciphertext containers.
///
/// `coordinates(ciphertext)` must return a borrowed span and should reject a
/// noncanonical ciphertext representation. An absent test ciphertext denotes
/// the public all-zero result of a lazy-ternary combination.
template <fhe::FheBackend Backend, typename CoordinateExtractor>
requires std::same_as<
    std::remove_cvref_t<std::invoke_result_t<
        CoordinateExtractor &, const typename Backend::Ciphertext &>>,
    std::span<const std::uint64_t>>
OuterRelationR1csAssignmentView borrow_outer_relation_r1cs_assignment(
    const OuterRelationPlan &plan,
    std::span<const std::uint64_t> packed_challenge_words,
    std::span<const fhe::FheValue<Backend>> revealed_tests,
    std::span<const fhe::FheValue<Backend>> revealed_packing,
    std::span<const typename Backend::Ciphertext> aligned,
    CoordinateExtractor coordinates) {
    OuterRelationR1csInputSlices slices;
    slices.packed_challenge_words = packed_challenge_words;
    slices.revealed_test_ciphertexts.reserve(revealed_tests.size());
    slices.revealed_packing_ciphertexts.reserve(revealed_packing.size());
    slices.aligned_ciphertexts.reserve(aligned.size());

    const auto append_reveal = [&](
                                   auto &destination,
                                   const fhe::FheValue<Backend> &value) {
        if (value.is_encrypted()) {
            destination.push_back(
                OuterRelationCiphertextCoordinateSlice::borrowed(
                    std::invoke(coordinates, value.ciphertext())));
            return;
        }
        if (!value.is_public_zero()) {
            throw std::invalid_argument(
                "outer relation reveal: public value must be zero");
        }
        destination.push_back(
            OuterRelationCiphertextCoordinateSlice::implicit_zero());
    };
    for (const fhe::FheValue<Backend> &value : revealed_tests) {
        append_reveal(slices.revealed_test_ciphertexts, value);
    }
    for (const fhe::FheValue<Backend> &value : revealed_packing) {
        append_reveal(slices.revealed_packing_ciphertexts, value);
    }
    for (const typename Backend::Ciphertext &ciphertext : aligned) {
        slices.aligned_ciphertexts.push_back(
            OuterRelationCiphertextCoordinateSlice::borrowed(
                std::invoke(coordinates, ciphertext)));
    }
    return OuterRelationR1csAssignmentView(plan, std::move(slices));
}

/// Mixed-value target path. Each reveal borrows an optional encrypted
/// coordinate vector and an exact public c0 overlay. The view adds them lazily
/// per coordinate; c1 is implicit zero for the public part.
template <PublicCoefficientEncodingBackend Backend,
          typename CoordinateExtractor>
requires std::same_as<
    std::remove_cvref_t<std::invoke_result_t<
        CoordinateExtractor &, const typename Backend::Ciphertext &>>,
    std::span<const std::uint64_t>>
OuterRelationR1csAssignmentView borrow_outer_relation_r1cs_assignment(
    const typename Backend::EvalContext &,
    const OuterRelationPlan &plan,
    std::span<const std::uint64_t> packed_challenge_words,
    std::span<const MixedPackingValue<Backend>> revealed_tests,
    std::span<const MixedPackingValue<Backend>> revealed_packing,
    const NormalizedAlignedTranscript<Backend> &aligned,
    CoordinateExtractor coordinates) {
    OuterRelationR1csInputSlices slices;
    slices.packed_challenge_words = packed_challenge_words;
    slices.revealed_test_ciphertexts.reserve(revealed_tests.size());
    slices.revealed_packing_ciphertexts.reserve(revealed_packing.size());
    slices.aligned_ciphertexts.reserve(aligned.values.size());

    const std::size_t width = plan.coordinates_per_ciphertext();
    const auto append_reveal = [&](auto &destination,
                                   const MixedPackingValue<Backend> &value) {
        if (!value.encrypted_contribution &&
            value.public_c0_coordinates.empty()) {
            destination.push_back(
                OuterRelationCiphertextCoordinateSlice::implicit_zero());
            return;
        }
        const std::span<const std::uint64_t> encrypted =
            value.encrypted_contribution
                ? std::invoke(coordinates,
                              *value.encrypted_contribution)
                : std::span<const std::uint64_t>{};
        destination.push_back(
            OuterRelationCiphertextCoordinateSlice::mixed(
                encrypted, value.public_c0_coordinates, width));
    };
    for (const MixedPackingValue<Backend> &value : revealed_tests) {
        append_reveal(slices.revealed_test_ciphertexts, value);
    }
    for (const MixedPackingValue<Backend> &value : revealed_packing) {
        append_reveal(slices.revealed_packing_ciphertexts, value);
    }
    for (std::size_t index = 0; index < aligned.values.size(); ++index) {
        if (aligned.values[index].is_public_zero()) {
            slices.aligned_ciphertexts.push_back(
                OuterRelationCiphertextCoordinateSlice::implicit_zero());
        } else {
            const auto aligned_coordinates =
                normalized_aligned_coordinates(aligned, index);
            slices.aligned_ciphertexts.push_back(
                OuterRelationCiphertextCoordinateSlice::borrowed(
                    aligned_coordinates));
        }
    }
    return OuterRelationR1csAssignmentView(plan, std::move(slices));
}

enum class OuterRelationPublicValueFamily : std::uint8_t {
    PackedChallengeWord,
    RevealedTestCoordinate,
    RevealedPackingCoordinate,
};

struct OuterRelationPublicValue {
    std::uint64_t index = 0;
    OuterRelationPublicValueFamily family =
        OuterRelationPublicValueFamily::PackedChallengeWord;
    std::uint64_t value = 0;
};

/// Forward cursor over canonical public-input order.
class OuterRelationPublicValueCursor {
  public:
    explicit OuterRelationPublicValueCursor(
        const OuterRelationR1csAssignmentView &assignment);
    OuterRelationPublicValueCursor(
        const OuterRelationR1csAssignmentView &assignment,
        std::uint64_t begin, std::uint64_t end);

    bool empty() const;
    std::uint64_t position() const;
    std::uint64_t remaining() const;
    OuterRelationPublicValue next();

  private:
    const OuterRelationR1csAssignmentView *assignment_ = nullptr;
    std::uint64_t cursor_ = 0;
    std::uint64_t end_ = 0;
};

enum class OuterRelationWitnessValueFamily : std::uint8_t {
    DerivedChallengeBit,
    AlignedCiphertextCoordinate,
    WellFormednessProduct,
};

struct OuterRelationWitnessValue {
    std::uint64_t index = 0;
    OuterRelationWitnessValueFamily family =
        OuterRelationWitnessValueFamily::DerivedChallengeBit;
    std::uint64_t value = 0;
};

/// Forward witness cursor with a cached lazy-ternary coefficient.
///
/// Product order is `(test, aligned, component, NTT coordinate)`. The cursor
/// decodes its starting point once, then reuses one challenge coefficient for
/// all `components * N` coordinates of that `(test, aligned)` pair.
class OuterRelationWitnessValueCursor {
  public:
    explicit OuterRelationWitnessValueCursor(
        const OuterRelationR1csAssignmentView &assignment);
    OuterRelationWitnessValueCursor(
        const OuterRelationR1csAssignmentView &assignment,
        std::uint64_t begin, std::uint64_t end);

    bool empty() const;
    std::uint64_t position() const;
    std::uint64_t remaining() const;
    OuterRelationWitnessValue next();

  private:
    void initialize_product_position();
    std::uint64_t next_product_value();
    void advance_product_position();

    const OuterRelationR1csAssignmentView *assignment_ = nullptr;
    std::uint64_t cursor_ = 0;
    std::uint64_t end_ = 0;
    bool product_position_initialized_ = false;
    std::size_t product_test_ = 0;
    std::size_t product_aligned_ = 0;
    std::size_t product_coordinate_ = 0;
    std::uint64_t product_coefficient_ = 0;
    const OuterRelationCiphertextCoordinateSlice *product_ciphertext_ =
        nullptr;
};

} // namespace laminate::packing

#endif // LAMINATE_PACKING_OUTER_RELATION_ASSIGNMENT_HPP
