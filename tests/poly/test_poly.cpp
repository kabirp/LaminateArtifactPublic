/// @file test_poly.cpp
/// @brief MSB-first multilinear and BGV-grid predicate tests.

#include "test_helpers.hpp"

#include "laminate/fhe/layout/slot_grid.hpp"
#include "laminate/poly/eq.hpp"
#include "laminate/poly/multilinear.hpp"

#include <cstddef>
#include <stdexcept>
#include <vector>

using namespace laminate;
using namespace laminate::poly;

namespace {

Fpk extension_value(std::uint64_t seed) {
    Fpk::Coefficients coefficients{};
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        coefficients[index] = Fp(seed + 11 * index + index * index);
    }
    return Fpk(coefficients);
}

std::vector<Fpk> point(std::size_t size, std::uint64_t seed) {
    std::vector<Fpk> result;
    result.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        result.push_back(extension_value(seed + 17 * index));
    }
    return result;
}

std::vector<Fpk> vertex(std::size_t value, std::size_t num_vars) {
    std::vector<Fpk> result;
    result.reserve(num_vars);
    for (std::size_t bit = 0; bit < num_vars; ++bit) {
        const bool set = ((value >> (num_vars - 1 - bit)) & 1U) != 0;
        result.push_back(set ? Fpk::one() : Fpk::zero());
    }
    return result;
}

} // namespace

int main() {
    test::Runner runner("test_poly");

    runner.run("dense MLE binds the most-significant variable first", [] {
        std::vector<Fp> evaluations;
        for (std::size_t index = 0; index < 8; ++index) {
            evaluations.push_back(Fp(3 + index));
        }
        const Multilinear<Fp> polynomial(3, evaluations);

        const auto low = polynomial.fix_first_variable(Fpk::zero());
        const auto high = polynomial.fix_first_variable(Fpk::one());
        for (std::size_t index = 0; index < 4; ++index) {
            CHECK(low.on_hypercube(index) ==
                  Fpk::from_base(evaluations[index]));
            CHECK(high.on_hypercube(index) ==
                  Fpk::from_base(evaluations[index + 4]));
        }
        for (std::size_t index = 0; index < 8; ++index) {
            CHECK(polynomial.evaluate(vertex(index, 3)) ==
                  Fpk::from_base(evaluations[index]));
        }
    });

    runner.run("dense evaluation agrees with the equality-table formula", [] {
        std::vector<Fp> evaluations;
        for (std::size_t index = 0; index < 16; ++index) {
            evaluations.push_back(Fp(5 + index * index));
        }
        const Multilinear<Fp> polynomial(4, evaluations);
        const auto evaluation_point = point(4, 7);
        const auto weights = eq_evaluations(evaluation_point);
        Fpk direct = Fpk::zero();
        for (std::size_t index = 0; index < evaluations.size(); ++index) {
            direct += Fpk::from_base(evaluations[index]) * weights[index];
        }
        CHECK(polynomial.evaluate(evaluation_point) == direct);
    });

    runner.run("sparse MLE is canonical and agrees with its dense table", [] {
        const SparseMultilinear<Fp> sparse(
            4, {{12, Fp(9)}, {1, Fp(4)}, {7, Fp(13)}});
        CHECK(sparse.entries()[0].index == 1);
        CHECK(sparse.entries()[1].index == 7);
        CHECK(sparse.on_hypercube(2) == Fp::zero());
        CHECK(sparse.on_hypercube(7) == Fp(13));

        const auto evaluation_point = point(4, 29);
        CHECK(sparse.evaluate(evaluation_point) ==
              sparse.dense().evaluate(evaluation_point));

        bool duplicate_threw = false;
        try {
            (void)SparseMultilinear<Fp>(2, {{1, Fp(2)}, {1, Fp(3)}});
        } catch (const std::invalid_argument &) {
            duplicate_threw = true;
        }
        CHECK(duplicate_threw);

        bool zero_threw = false;
        try {
            (void)SparseMultilinear<Fp>(2, {{1, Fp::zero()}});
        } catch (const std::invalid_argument &) {
            zero_threw = true;
        }
        CHECK(zero_threw);
    });

    runner.run("equality tables use MSB-first hypercube order", [] {
        const auto evaluation_point = point(4, 41);
        const auto table = eq_evaluations(evaluation_point);
        Fpk sum = Fpk::zero();
        for (std::size_t index = 0; index < table.size(); ++index) {
            CHECK(table[index] ==
                  eq_eval(evaluation_point, vertex(index, 4)));
            sum += table[index];
        }
        CHECK(sum == Fpk::one());
        CHECK(eq_eval(std::vector<Fpk>{}, std::vector<Fpk>{}) == Fpk::one());
    });

    runner.run("cyclic-shift MLE agrees with exhaustive enumeration", [] {
        for (std::size_t num_vars = 0; num_vars <= 5; ++num_vars) {
            const std::size_t size = hypercube_size(num_vars);
            const auto input = point(num_vars, 53 + num_vars);
            const auto output = point(num_vars, 101 + num_vars);
            const auto input_eq = eq_evaluations(input);
            const auto output_eq = eq_evaluations(output);
            for (std::size_t shift = 0; shift < size; ++shift) {
                Fpk brute = Fpk::zero();
                for (std::size_t index = 0; index < size; ++index) {
                    brute += input_eq[index] *
                             output_eq[(index + shift) % size];
                }
                CHECK(cyclic_shift_eval(input, output, shift) == brute);
            }
        }
    });

    runner.run("grid-rotation MLE uses the shared two-row permutation", [] {
        for (std::size_t log_slots = 1; log_slots <= 5; ++log_slots) {
            const std::size_t slot_count = hypercube_size(log_slots);
            const auto input = point(log_slots, 151 + log_slots);
            const auto output = point(log_slots, 211 + log_slots);
            const auto input_eq = eq_evaluations(input);
            const auto output_eq = eq_evaluations(output);
            for (std::size_t step = 0; step < slot_count; ++step) {
                Fpk brute = Fpk::zero();
                for (std::size_t slot = 0; slot < slot_count; ++slot) {
                    brute += input_eq[slot] * output_eq[fhe::grid_source(
                                                   slot_count, step, slot)];
                }
                CHECK(grid_rotation_eval(input, output, step) == brute);
            }
        }
    });

    runner.run("BGV action MLE specializes to every fixed rotation", [] {
        for (std::size_t log_slots = 1; log_slots <= 5; ++log_slots) {
            const std::size_t slot_count = hypercube_size(log_slots);
            const auto destination = point(log_slots, 263 + log_slots);
            const auto source = point(log_slots, 307 + log_slots);
            for (std::size_t step = 0; step < slot_count; ++step) {
                CHECK(grid_action_eval(destination, source,
                                       vertex(step, log_slots)) ==
                      grid_rotation_eval(destination, source, step));
            }
        }
    });

    runner.run("BGV action MLE agrees with its full Boolean table", [] {
        for (std::size_t log_slots = 1; log_slots <= 4; ++log_slots) {
            const std::size_t slot_count = hypercube_size(log_slots);
            const auto destination = point(log_slots, 359 + log_slots);
            const auto source = point(log_slots, 401 + log_slots);
            const auto offset = point(log_slots, 449 + log_slots);
            const auto destination_eq = eq_evaluations(destination);
            const auto source_eq = eq_evaluations(source);
            const auto offset_eq = eq_evaluations(offset);

            Fpk brute = Fpk::zero();
            for (std::size_t destination_slot = 0;
                 destination_slot < slot_count; ++destination_slot) {
                for (std::size_t step = 0; step < slot_count; ++step) {
                    const std::size_t source_slot = fhe::grid_source(
                        slot_count, step, destination_slot);
                    brute += destination_eq[destination_slot] *
                             source_eq[source_slot] * offset_eq[step];
                }
            }
            CHECK(grid_action_eval(destination, source, offset) == brute);
        }
    });

    runner.run("BGV action MLE is exact on Boolean triples", [] {
        for (std::size_t log_slots = 1; log_slots <= 4; ++log_slots) {
            const std::size_t slot_count = hypercube_size(log_slots);
            for (std::size_t destination = 0; destination < slot_count;
                 ++destination) {
                for (std::size_t source = 0; source < slot_count; ++source) {
                    for (std::size_t step = 0; step < slot_count; ++step) {
                        const Fpk expected =
                            source == fhe::grid_source(slot_count, step,
                                                       destination)
                                ? Fpk::one()
                                : Fpk::zero();
                        CHECK(grid_action_eval(vertex(destination, log_slots),
                                               vertex(source, log_slots),
                                               vertex(step, log_slots)) ==
                              expected);
                    }
                }
            }
        }
    });

    runner.run("BGV action MLE rejects malformed points", [] {
        bool mismatch_threw = false;
        try {
            (void)grid_action_eval(point(2, 503), point(2, 521),
                                   point(1, 541));
        } catch (const std::invalid_argument &) {
            mismatch_threw = true;
        }
        CHECK(mismatch_threw);

        bool empty_threw = false;
        try {
            (void)grid_action_eval(std::vector<Fpk>{}, std::vector<Fpk>{},
                                   std::vector<Fpk>{});
        } catch (const std::invalid_argument &) {
            empty_threw = true;
        }
        CHECK(empty_threw);
    });

    runner.run("invalid polynomial dimensions are rejected", [] {
        bool table_threw = false;
        try {
            (void)Multilinear<Fp>(3, std::vector<Fp>(7, Fp::zero()));
        } catch (const std::invalid_argument &) {
            table_threw = true;
        }
        CHECK(table_threw);

        bool point_threw = false;
        try {
            const Multilinear<Fp> constant(0, {Fp(7)});
            (void)constant.evaluate(std::vector<Fpk>{Fpk::one()});
        } catch (const std::invalid_argument &) {
            point_threw = true;
        }
        CHECK(point_threw);
    });

    return runner.summary();
}
