/// @file test_fq_ntt.cpp
/// @brief Native-Fq NTT backend and tile-kernel correctness comparisons.

#include "test_helpers.hpp"

#include "laminate/field/fq_ntt.hpp"
#include "laminate/field/fq_transform_kernels.hpp"

#include <bit>
#include <cstddef>
#include <stdexcept>
#include <vector>

namespace {

using laminate::Fq;
using laminate::FqNttBackend;
using laminate::FqNttPlan;

template <typename Function> bool rejects_as(Function &&function) {
    try {
        function();
        return false;
    } catch (const std::invalid_argument &) {
        return true;
    }
}

std::vector<Fq> direct_ntt(const std::vector<Fq> &input, const Fq &root) {
    std::vector<Fq> result(input.size(), Fq::zero());
    for (std::size_t output = 0; output < input.size(); ++output) {
        Fq power = Fq::one();
        const Fq step = root.pow(output);
        for (const Fq &value : input) {
            result[output] += value * power;
            power *= step;
        }
    }
    return result;
}

void test_ntt_matches_direct_and_round_trips() {
    for (std::size_t log_size = 0; log_size <= 17; ++log_size) {
        const std::size_t size = std::size_t{1} << log_size;
        const Fq root = Fq::two_adic_generator(log_size);
        std::vector<Fq> input(size);
        for (std::size_t index = 0; index < size; ++index) {
            input[index] = Fq(31U * index * index + 17U * index + log_size);
        }
        FqNttPlan forward(size, root);
        std::vector<Fq> transformed = input;
        forward.apply(transformed);
        if (size <= 64) {
            CHECK(transformed == direct_ntt(input, root));
        }

        std::vector<Fq> scalar = input;
        forward.apply_scalar_reference(scalar);
        CHECK(transformed == scalar);
        if (laminate::fq_ntt_backend_available(FqNttBackend::IntelHexl) &&
            size >= 2) {
            std::vector<Fq> explicit_hexl = input;
            FqNttPlan hexl(size, root, FqNttBackend::IntelHexl);
            hexl.apply(explicit_hexl);
            CHECK(explicit_hexl == scalar);
        }
        const bool hexl_expected =
            laminate::fq_ntt_backend_available(FqNttBackend::IntelHexl) &&
            size >= (std::size_t{1} << 16U) &&
            size <= (std::size_t{1} << 17U);
        CHECK(forward.backend() ==
              (hexl_expected ? FqNttBackend::IntelHexl
                             : FqNttBackend::Scalar));

        std::vector<Fq> scalar_inverse = transformed;
        FqNttPlan inverse_scalar(size, root.inverse(),
                                 FqNttBackend::Scalar);
        inverse_scalar.apply(scalar_inverse);
        FqNttPlan inverse(size, root.inverse());
        inverse.apply(transformed);
        CHECK(transformed == scalar_inverse);
        const Fq inverse_size = Fq(size).inverse();
        for (Fq &value : transformed) {
            value *= inverse_size;
        }
        CHECK(transformed == input);
    }
}

void test_ntt_row_batches_match_individual_transforms() {
    constexpr std::size_t row_size = 16;
    constexpr std::size_t row_count = 7;
    std::vector<Fq> input(row_size * row_count);
    for (std::size_t index = 0; index < input.size(); ++index) {
        input[index] = Fq(43U * index + 19U);
    }
    FqNttPlan plan(row_size, Fq::two_adic_generator(4));
    std::vector<Fq> individual = input;
    for (std::size_t row = 0; row < row_count; ++row) {
        plan.apply(std::span<Fq>(individual).subspan(row * row_size,
                                                       row_size));
    }
    std::vector<Fq> batched = input;
    plan.apply_rows(batched);
    CHECK(batched == individual);
    CHECK(rejects_as([&] {
        plan.apply_rows(std::span<Fq>(batched).first(batched.size() - 1U));
    }));
}

void test_ntt_matches_scalar_for_alternate_roots() {
    for (std::size_t log_size = 1; log_size <= 12; ++log_size) {
        const std::size_t size = std::size_t{1} << log_size;
        const Fq generator = Fq::two_adic_generator(log_size);
        std::vector<Fq> input(size);
        for (std::size_t index = 0; index < size; ++index) {
            input[index] = Fq(101U * index + 29U * log_size + 7U);
        }
        for (const std::size_t exponent :
             {std::size_t{1}, std::size_t{3}, size - 1U}) {
            const Fq root = generator.pow(exponent);
            std::vector<Fq> production = input;
            std::vector<Fq> scalar = input;
            const FqNttBackend comparison_backend =
                laminate::fq_ntt_backend_available(
                    FqNttBackend::IntelHexl) &&
                        size >= 2
                    ? FqNttBackend::IntelHexl
                    : FqNttBackend::Automatic;
            FqNttPlan production_plan(size, root, comparison_backend);
            FqNttPlan scalar_plan(size, root, FqNttBackend::Scalar);
            production_plan.apply(production);
            scalar_plan.apply(scalar);
            CHECK(production == scalar);
        }
    }
}

void test_unavailable_backends_fail_cleanly() {
    CHECK(laminate::fq_ntt_backend_available(FqNttBackend::Automatic));
    CHECK(laminate::fq_ntt_backend_available(FqNttBackend::Scalar));
    CHECK(!laminate::fq_ntt_backend_available(FqNttBackend::Avx512Ifma));
    CHECK(laminate::kOuterFieldOrder >= (std::uint64_t{1} << 59U));
    CHECK(laminate::kOuterFieldOrder < (std::uint64_t{1} << 60U));
    if (laminate::fq_ntt_backend_available(FqNttBackend::IntelHexl)) {
        FqNttPlan plan(16, Fq::two_adic_generator(4),
                       FqNttBackend::IntelHexl);
        CHECK(plan.backend() == FqNttBackend::IntelHexl);
        CHECK(rejects_as([&] {
            (void)FqNttPlan(std::size_t{1} << 18U,
                            Fq::two_adic_generator(18),
                            FqNttBackend::IntelHexl);
        }));
    } else {
        CHECK(rejects_as([&] {
            (void)FqNttPlan(16, Fq::two_adic_generator(4),
                            FqNttBackend::IntelHexl);
        }));
    }
}

void test_transpose_and_twiddle_tiles() {
    constexpr std::size_t rows = 8;
    constexpr std::size_t columns = 4;
    std::vector<Fq> tile(rows * columns);
    for (std::size_t index = 0; index < tile.size(); ++index) {
        tile[index] = Fq(index + 1U);
    }
    std::vector<Fq> transposed(tile.size());
    laminate::transpose_fq_tile(tile, transposed, rows, columns);
    for (std::size_t row = 0; row < rows; ++row) {
        for (std::size_t column = 0; column < columns; ++column) {
            CHECK(transposed[column * rows + row] ==
                  tile[row * columns + column]);
        }
    }

    const Fq root = Fq::two_adic_generator(6);
    const std::vector<Fq> original = tile;
    laminate::apply_fq_twiddle_tile(tile, rows, columns, 7, 11, root);
    for (std::size_t row = 0; row < rows; ++row) {
        for (std::size_t column = 0; column < columns; ++column) {
            CHECK(tile[row * columns + column] ==
                  original[row * columns + column] *
                      root.pow((7U + row) * (11U + column)));
        }
    }
}

} // namespace

int main() {
    laminate::test::Runner runner("test_fq_ntt");
    runner.run("native Fq NTT matches direct evaluation and round trips",
               test_ntt_matches_direct_and_round_trips);
    runner.run("native Fq NTT matches scalar for alternate roots",
               test_ntt_matches_scalar_for_alternate_roots);
    runner.run("native Fq NTT row batches match individual transforms",
               test_ntt_row_batches_match_individual_transforms);
    runner.run("unavailable native Fq NTT backends fail cleanly",
               test_unavailable_backends_fail_cleanly);
    runner.run("native Fq transpose and twiddle tiles are exact",
               test_transpose_and_twiddle_tiles);
    return runner.summary();
}
