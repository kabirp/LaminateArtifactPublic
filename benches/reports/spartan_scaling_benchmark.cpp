/// @file spartan_scaling_benchmark.cpp
/// @brief Single-thread Spartan-core packing-density calibration.

#include "benchmark_support.hpp"

#include "laminate/params.hpp"
#include "laminate/spartan/basefold_pcs.hpp"
#include "laminate/spartan/spartan.hpp"
#include "laminate/spartan/uniform.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
using laminate::Fq;
using laminate::Transcript;
using namespace laminate::spartan;

constexpr std::size_t kLocalConstraints = 64;
constexpr std::size_t kLocalNonzerosPerConstraint = 7;

struct BenchmarkOptions {
    std::size_t log_constraints = 20;
    std::size_t log_rate =
        laminate::kTranscriptPackingBaseFoldLogRate;
    std::size_t query_count =
        laminate::kTranscriptPackingBaseFoldQueries;
    std::size_t iterations = 1;
};

std::size_t parse_size(std::string_view text, const char *label) {
    std::size_t consumed = 0;
    const unsigned long long value =
        std::stoull(std::string(text), &consumed, 10);
    if (consumed != text.size() ||
        value > std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(std::string("invalid ") + label);
    }
    return static_cast<std::size_t>(value);
}

std::optional<BenchmarkOptions> parse_options(int argc, char **argv) {
    BenchmarkOptions result;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help" || argument == "-h") {
            std::cout
                << "Usage: laminate_spartan_scaling_bench [options]\n"
                << "  --log-constraints L --log-rate R\n"
                << "  --query-count Q --iterations I\n";
            return std::nullopt;
        }
        const auto next = [&](const char *label) {
            if (++index == argc) {
                throw std::invalid_argument(std::string("missing ") + label);
            }
            return parse_size(argv[index], label);
        };
        if (argument == "--log-constraints") {
            result.log_constraints = next("--log-constraints");
        } else if (argument == "--log-rate") {
            result.log_rate = next("--log-rate");
        } else if (argument == "--query-count") {
            result.query_count = next("--query-count");
        } else if (argument == "--iterations") {
            result.iterations = next("--iterations");
        } else {
            throw std::invalid_argument("unknown option: " +
                                        std::string(argument));
        }
    }
    if (result.log_constraints < 6 ||
        result.log_constraints >= std::numeric_limits<std::size_t>::digits ||
        result.iterations == 0 || result.query_count == 0) {
        throw std::invalid_argument("benchmark dimensions are invalid");
    }
    return result;
}

R1csInstance make_local_packing_circuit() {
    // Each row proves L_i(w) * 1 = L_i(w), where L_i has three terms.
    // The resulting seven A/B/C entries per row match the packing ledger's
    // approximately seven sparse entries per constraint without changing the
    // padded row-to-assignment-domain ratio.
    std::vector<R1csEntry> a;
    std::vector<R1csEntry> b;
    std::vector<R1csEntry> c;
    a.reserve(3 * kLocalConstraints);
    b.reserve(kLocalConstraints);
    c.reserve(3 * kLocalConstraints);
    for (std::size_t row = 0; row < kLocalConstraints; ++row) {
        const std::array<R1csEntry, 3> expression{
            R1csEntry{row, 1 + row, Fq::one()},
            R1csEntry{row, 1 + (row + 1) % kLocalConstraints, Fq(2)},
            R1csEntry{row, 1 + (row + 7) % kLocalConstraints, Fq(3)},
        };
        a.insert(a.end(), expression.begin(), expression.end());
        b.push_back(R1csEntry{row, 0, Fq::one()});
        c.insert(c.end(), expression.begin(), expression.end());
    }
    return R1csInstance(
        R1csShape{.constraints = kLocalConstraints,
                  .public_inputs = 0,
                  .witness_variables = kLocalConstraints},
        std::move(a), std::move(b), std::move(c));
}

double seconds(Clock::time_point begin, Clock::time_point end) {
    return std::chrono::duration<double>(end - begin).count();
}

} // namespace

int main(int argc, char **argv) {
    try {
        const std::optional<BenchmarkOptions> parsed =
            parse_options(argc, argv);
        if (!parsed) {
            return 0;
        }
        const BenchmarkOptions &options = *parsed;
        const std::size_t constraints =
            std::size_t{1} << options.log_constraints;
        const BaseFoldPcs pcs({
            .log_rate = options.log_rate,
            .query_count = options.query_count,
        });

        const Clock::time_point setup_begin = Clock::now();
        auto compiled = compile_uniform_r1cs(
            make_local_packing_circuit(), constraints / kLocalConstraints);
        const Setup keys = setup(
            std::move(compiled.circuit), pcs,
            Options{.matrix_evaluation = MatrixEvaluationMode::Uniform},
            compiled.matrix_oracle);
        const Clock::time_point setup_end = Clock::now();

        const Clock::time_point witness_begin = Clock::now();
        R1csAssignment assignment;
        assignment.witness.resize(constraints);
        for (std::size_t index = 0; index < constraints; ++index) {
            assignment.witness[index] = Fq(index + 1U);
        }
        const Clock::time_point witness_end = Clock::now();

        double prove_total = 0;
        double verify_total = 0;
        std::size_t proof_bytes = 0;
        bool accepted = true;
        for (std::size_t iteration = 0; iteration < options.iterations;
             ++iteration) {
            Transcript prover("laminate/benchmark/uniform-spartan/v2");
            const Clock::time_point prove_begin = Clock::now();
            const Proof proof = prove(
                keys.prover_key, assignment, pcs, prover);
            const Clock::time_point prove_end = Clock::now();
            Transcript verifier("laminate/benchmark/uniform-spartan/v2");
            accepted = accepted && verify(
                keys.verifier_key, {}, proof, pcs, verifier);
            const Clock::time_point verify_end = Clock::now();
            prove_total += seconds(prove_begin, prove_end);
            verify_total += seconds(prove_end, verify_end);
            proof_bytes = proof_size_bytes(proof);
        }

        std::cout << std::fixed << std::setprecision(6);
        std::cout << "format=laminate-uniform-spartan-benchmark-v4\n";
        std::cout << "classification="
                     "measured-single-thread-spartan-core-packing-density\n";
        std::cout << "piop=spartan\n";
        std::cout << "matrix_mode=uniform-reference\n";
        std::cout << "scope=core-excludes-factored-matrix-argument\n";
        std::cout << "fiat_shamir=sha256\n";
        std::cout << "pcs=basefold-blake2b-320\n";
        std::cout << "constraints=" << constraints << '\n';
        std::cout << "log_constraints=" << options.log_constraints << '\n';
        std::cout << "nonzeros_per_constraint="
                  << kLocalNonzerosPerConstraint << '\n';
        std::cout << "basefold_log_rate=" << options.log_rate << '\n';
        std::cout << "basefold_queries=" << options.query_count << '\n';
        std::cout << "iterations=" << options.iterations << '\n';
        const laminate::bench::Record record;
        laminate::bench::emit_benchmark_provenance(record, argc, argv);
        std::cout << "setup_seconds="
                  << seconds(setup_begin, setup_end) << '\n';
        std::cout << "witness_generation_seconds="
                  << seconds(witness_begin, witness_end) << '\n';
        std::cout << "prove_seconds_mean="
                  << prove_total / options.iterations << '\n';
        std::cout << "verify_seconds_mean="
                  << verify_total / options.iterations << '\n';
        std::cout << "proof_bytes=" << proof_bytes << '\n';
        std::cout << "accepted=" << (accepted ? "true" : "false") << '\n';
        return accepted ? 0 : 1;
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
