#ifndef LAMINATE_PACKING_EVALUATION_PHASES_NATIVE_ACCUMULATOR_HPP
#define LAMINATE_PACKING_EVALUATION_PHASES_NATIVE_ACCUMULATOR_HPP

/// @file native_accumulator.hpp
/// @brief Mixed public/ciphertext accumulation without encrypted zero values.

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace laminate::packing::lazy_ternary_detail {

template <CoefficientWellFormednessBackend Backend>
void add_public_c0_scaled(
    std::vector<std::uint64_t> &accumulator,
    std::span<const std::uint64_t> coordinates, int coefficient) {
    if (coefficient == 0) {
        return;
    }
    if (coefficient != 1 && coefficient != -1) {
        throw std::invalid_argument(
            "public coefficient contribution is not ternary");
    }
    if (accumulator.empty()) {
        accumulator.assign(coordinates.size(), 0);
    }
    if (accumulator.size() != coordinates.size()) {
        throw std::invalid_argument(
            "public coefficient contribution has the wrong width");
    }
    for (std::size_t index = 0; index < coordinates.size(); ++index) {
        const std::uint64_t value = coordinates[index];
        if (value >= kOuterFieldOrder) {
            throw std::invalid_argument(
                "public coefficient contribution is outside Fq");
        }
        if (coefficient == 1) {
            accumulator[index] =
                accumulator[index] >= kOuterFieldOrder - value
                    ? accumulator[index] - (kOuterFieldOrder - value)
                    : accumulator[index] + value;
        } else {
            accumulator[index] = accumulator[index] >= value
                                     ? accumulator[index] - value
                                     : kOuterFieldOrder -
                                           (value - accumulator[index]);
        }
    }
}

inline void discard_exact_zero_coordinates(
    std::vector<std::uint64_t> &coordinates) {
    if (std::all_of(coordinates.begin(), coordinates.end(),
                    [](std::uint64_t value) { return value == 0; })) {
        coordinates.clear();
    }
}

inline std::uint64_t multiply_fq(std::uint64_t left,
                                 std::uint64_t right) {
    if (left >= kOuterFieldOrder || right >= kOuterFieldOrder) {
        throw std::invalid_argument(
            "public coefficient product is outside Fq");
    }
    return static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(left) * right) % kOuterFieldOrder);
}

inline bool add_native_coordinates(
    std::vector<std::uint64_t> &accumulator,
    std::span<const std::uint64_t> term, std::size_t expected_width) {
    if (term.size() != expected_width) {
        throw std::invalid_argument(
            "packing ciphertext has the wrong native-coordinate width");
    }
    if (std::any_of(term.begin(), term.end(),
                    [](std::uint64_t coordinate) {
                        return coordinate >= kOuterFieldOrder;
                    })) {
        throw std::invalid_argument(
            "packing ciphertext coordinate is outside Fq");
    }
    if (accumulator.empty()) {
        accumulator.assign(term.begin(), term.end());
    } else {
        for (std::size_t coordinate = 0; coordinate < term.size();
             ++coordinate) {
            const std::uint64_t left = accumulator[coordinate];
            const std::uint64_t right = term[coordinate];
            accumulator[coordinate] =
                left >= kOuterFieldOrder - right
                    ? left - (kOuterFieldOrder - right)
                    : left + right;
        }
    }
    return std::all_of(accumulator.begin(), accumulator.end(),
                       [](std::uint64_t value) { return value == 0; });
}

/// Accumulate normalized encrypted terms without manufacturing an encrypted
/// zero. The only FHE addition in the lazy-ternary flow is visible in `add`.
/// Exact `(c0,c1) = (0,0)` becomes an omitted reveal; a prover-derived public
/// nonzero is rejected because the proof wire has no representation for it.
template <PublicCoefficientEncodingBackend Backend>
class ExactZeroCiphertextAccumulator {
  public:
    void add(const typename Backend::EvalContext &eval,
             fhe::FheValue<Backend> term) {
        if (!term.is_encrypted()) {
            throw std::logic_error(
                "packing encrypted accumulator received a public term");
        }
        bool exact_zero = false;
        if constexpr (!kBackendReportsPublicSums) {
            const std::size_t width = 2 * Backend::slot_count(eval);
            exact_zero = add_native_coordinates(
                native_coordinates_,
                Backend::coefficient_commitment_ntt_coordinate_view(
                    term.ciphertext()),
                width);
        }

        // Backend boundary: one ciphertext addition for this linear term.
        fhe::value_add_assign<Backend>(eval, value_, std::move(term));
        if (value_.is_public()) {
            if (!value_.is_public_zero()) {
                throw std::logic_error(
                    "packing encrypted terms cancelled to a nonzero public "
                    "residue that the current proof wire cannot bind");
            }
            native_coordinates_.clear();
            return;
        }
        if constexpr (!kBackendReportsPublicSums) {
            if (exact_zero) {
                value_ = fhe::FheValue<Backend>::public_zero();
                native_coordinates_.clear();
            }
        }
    }

    std::optional<typename Backend::Ciphertext> finish() && {
        if (value_.is_public_zero()) {
            return std::nullopt;
        }
        if (!value_.is_encrypted()) {
            throw std::logic_error(
                "packing encrypted accumulator finished as public nonzero");
        }
        return std::move(value_).take_ciphertext();
    }

  private:
    static constexpr bool kBackendReportsPublicSums =
        requires(const typename Backend::EvalContext &context,
                 typename Backend::Ciphertext &accumulator,
                 const typename Backend::Ciphertext &term) {
            Backend::add_assign_or_public(context, accumulator, term);
        };

    fhe::FheValue<Backend> value_ = fhe::FheValue<Backend>::public_zero();
    std::vector<std::uint64_t> native_coordinates_;
};

} // namespace laminate::packing::lazy_ternary_detail

#endif // LAMINATE_PACKING_EVALUATION_PHASES_NATIVE_ACCUMULATOR_HPP
