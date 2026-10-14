#include "test_helpers.hpp"

#include "laminate/spartan/basefold_pcs.hpp"
#include "laminate/spartan/spartan.hpp"
#include "laminate/spartan/uniform.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {

using laminate::Fq;
using laminate::Transcript;
using laminate::spartan::BaseFoldPcs;
using laminate::spartan::Matrix;
using laminate::spartan::MatrixEvaluationMode;
using laminate::spartan::Options;
using laminate::spartan::Proof;
using laminate::spartan::R1csAssignment;
using laminate::spartan::R1csEntry;
using laminate::spartan::R1csInstance;
using laminate::spartan::R1csShape;
using laminate::spartan::Setup;

R1csInstance make_cube_circuit() {
    // Public x and private (w0,w1,w2):
    //   x * 1   = w0
    //   w0 * w0 = w1
    //   w1 * w0 = w2
    return R1csInstance(
        R1csShape{.constraints = 3,
                  .public_inputs = 1,
                  .witness_variables = 3},
        std::vector<R1csEntry>{{0, 1, Fq::one()},
                               {1, 2, Fq::one()},
                               {2, 3, Fq::one()}},
        std::vector<R1csEntry>{{0, 0, Fq::one()},
                               {1, 2, Fq::one()},
                               {2, 2, Fq::one()}},
        std::vector<R1csEntry>{{0, 2, Fq::one()},
                               {1, 3, Fq::one()},
                               {2, 4, Fq::one()}});
}

R1csAssignment cube_assignment(std::uint64_t value) {
    const Fq x(value);
    return R1csAssignment{
        .public_inputs = {x},
        .witness = {x, x * x, x * x * x},
    };
}

void check_direct_proof_appender(const Proof &proof) {
    const std::vector<std::uint8_t> expected =
        laminate::spartan::encode_proof(proof);
    CHECK(expected.size() >=
          proof.witness_opening.bytes.size() + sizeof(std::uint64_t));
    const std::size_t witness_size_offset =
        expected.size() - proof.witness_opening.bytes.size() -
        sizeof(std::uint64_t);
    std::uint64_t framed_witness_size = 0;
    for (std::size_t byte = 0; byte < sizeof(std::uint64_t); ++byte) {
        framed_witness_size |=
            static_cast<std::uint64_t>(expected[witness_size_offset + byte])
            << (8U * byte);
    }
    CHECK(framed_witness_size == proof.witness_opening.bytes.size());
    std::vector<std::uint8_t> appended{0xa5U, 0x5aU, 0x17U};
    const std::size_t prefix = appended.size();
    laminate::spartan::append_encoded_proof(proof, appended);
    CHECK(appended.size() - prefix ==
          laminate::spartan::proof_size_bytes(proof));
    CHECK(std::equal(expected.begin(), expected.end(),
                     appended.begin() + static_cast<std::ptrdiff_t>(prefix)));
}

void test_r1cs_shape_and_evaluation() {
    const R1csInstance circuit = make_cube_circuit();
    CHECK(circuit.padded_constraints() == 4);
    CHECK(circuit.assignment_half_size() == 4);
    CHECK(circuit.padded_variables() == 8);
    CHECK(circuit.row_variables() == 2);
    CHECK(circuit.column_variables() == 3);
    CHECK(circuit.nonzero_entries() == 9);
    CHECK(circuit.padded_column(0) == 0);
    CHECK(circuit.padded_column(1) == 1);
    CHECK(circuit.padded_column(2) == 4);
    CHECK(circuit.padded_column(4) == 6);
    CHECK(circuit.is_satisfied(cube_assignment(3)));

    R1csAssignment bad = cube_assignment(3);
    bad.witness.back() += Fq::one();
    CHECK(!circuit.is_satisfied(bad));
}

void test_spartan_end_to_end() {
    BaseFoldPcs pcs;
    const Setup keys = laminate::spartan::setup(make_cube_circuit(), pcs);
    const R1csAssignment assignment = cube_assignment(3);

    Transcript prover("laminate/test/spartan/v1");
    const Proof proof = laminate::spartan::prove(
        keys.prover_key, assignment, pcs, prover);
    CHECK(proof.witness_commitment.log_rate == 3U);
    CHECK(proof.witness_commitment.query_count ==
          laminate::kTranscriptPackingBaseFoldQueries);
    CHECK(proof.witness_opening.bytes.size() <=
          laminate::spartan::basefold_opening_proof_max_size_bytes(
              std::bit_width(proof.witness_commitment.evaluation_count) - 1U,
              1U, pcs.parameters()));
    CHECK(laminate::spartan::proof_size_bytes(proof) > 0);
    CHECK(laminate::spartan::encode_proof(proof).size() ==
          laminate::spartan::proof_size_bytes(proof));
    check_direct_proof_appender(proof);

    Transcript verifier("laminate/test/spartan/v1");
    CHECK(laminate::spartan::verify(
        keys.verifier_key, assignment.public_inputs, proof, pcs,
        verifier));
    CHECK(prover.challenge_fq2() == verifier.challenge_fq2());
}

R1csInstance make_local_uniform_circuit() {
    // Per cycle: w0 * 1 = w0, w0 * w0 = w1, w1 * w0 = w2.
    return R1csInstance(
        R1csShape{.constraints = 3,
                  .public_inputs = 0,
                  .witness_variables = 3},
        std::vector<R1csEntry>{{0, 1, Fq::one()},
                               {1, 1, Fq::one()},
                               {2, 2, Fq::one()}},
        std::vector<R1csEntry>{{0, 0, Fq::one()},
                               {1, 1, Fq::one()},
                               {2, 1, Fq::one()}},
        std::vector<R1csEntry>{{0, 1, Fq::one()},
                               {1, 2, Fq::one()},
                               {2, 3, Fq::one()}});
}

R1csInstance make_expanded_uniform_circuit() {
    std::vector<R1csEntry> a;
    std::vector<R1csEntry> b;
    std::vector<R1csEntry> c;
    for (std::uint64_t cycle = 0; cycle < 4; ++cycle) {
        const std::uint64_t row = 4 * cycle;
        const std::uint64_t column = 1 + 4 * cycle;
        a.insert(a.end(), {{row, column, Fq::one()},
                           {row + 1, column, Fq::one()},
                           {row + 2, column + 1, Fq::one()}});
        b.insert(b.end(), {{row, 0, Fq::one()},
                           {row + 1, column, Fq::one()},
                           {row + 2, column, Fq::one()}});
        c.insert(c.end(), {{row, column, Fq::one()},
                           {row + 1, column + 1, Fq::one()},
                           {row + 2, column + 2, Fq::one()}});
    }
    return R1csInstance(
        R1csShape{.constraints = 16,
                  .public_inputs = 0,
                  .witness_variables = 16},
        std::move(a), std::move(b), std::move(c));
}

R1csInstance make_local_public_uniform_circuit() {
    // Per cycle, public x and private (w0,w1): x * 1 = w0, w0 * w0 = w1.
    return R1csInstance(
        R1csShape{.constraints = 2,
                  .public_inputs = 1,
                  .witness_variables = 2},
        std::vector<R1csEntry>{{0, 1, Fq::one()},
                               {1, 2, Fq::one()}},
        std::vector<R1csEntry>{{0, 0, Fq::one()},
                               {1, 2, Fq::one()}},
        std::vector<R1csEntry>{{0, 2, Fq::one()},
                               {1, 3, Fq::one()}});
}

R1csInstance make_expanded_public_uniform_circuit() {
    std::vector<R1csEntry> a;
    std::vector<R1csEntry> b;
    std::vector<R1csEntry> c;
    for (std::uint64_t cycle = 0; cycle < 3; ++cycle) {
        const std::uint64_t row = 2 * cycle;
        const std::uint64_t public_column = 2 * cycle + 1;
        const std::uint64_t witness_column = 8 + 2 * cycle;
        a.insert(a.end(), {{row, public_column, Fq::one()},
                           {row + 1, witness_column, Fq::one()}});
        b.insert(b.end(), {{row, 0, Fq::one()},
                           {row + 1, witness_column, Fq::one()}});
        c.insert(c.end(), {{row, witness_column, Fq::one()},
                           {row + 1, witness_column + 1, Fq::one()}});
    }
    return R1csInstance(
        R1csShape{.constraints = 6,
                  .public_inputs = 7,
                  .witness_variables = 8},
        std::move(a), std::move(b), std::move(c));
}

R1csAssignment public_uniform_assignment() {
    R1csAssignment assignment;
    assignment.public_inputs.resize(7, Fq::zero());
    assignment.witness.resize(8, Fq::zero());
    for (std::size_t cycle = 0; cycle < 3; ++cycle) {
        const Fq x(cycle + 3);
        assignment.public_inputs[2 * cycle] = x;
        assignment.witness[2 * cycle] = x;
        assignment.witness[2 * cycle + 1] = x * x;
    }
    return assignment;
}

void test_uniform_spartan_end_to_end() {
    BaseFoldPcs pcs({.log_rate = 2, .query_count = 24});
    auto compiled = laminate::spartan::compile_uniform_r1cs(
        make_local_uniform_circuit(), 4);
    CHECK(compiled.circuit.padded_constraints() == 16);
    CHECK(compiled.circuit.assignment_half_size() == 16);
    CHECK(compiled.circuit.nonzero_entries() == 36);
    CHECK(compiled.cycles == 4);
    CHECK(compiled.padded_cycles == 4);
    CHECK(compiled.public_stride == 0);
    CHECK(compiled.witness_stride == 4);
    const R1csInstance expanded = make_expanded_uniform_circuit();

    const std::vector<laminate::Fq2> row_point{
        laminate::Fq2::from_base(Fq(2)),
        laminate::Fq2::from_base(Fq(3)),
        laminate::Fq2::from_base(Fq(5)),
        laminate::Fq2::from_base(Fq(7))};
    const std::vector<laminate::Fq2> column_point{
        laminate::Fq2::from_base(Fq(11)),
        laminate::Fq2::from_base(Fq(13)),
        laminate::Fq2::from_base(Fq(17)),
        laminate::Fq2::from_base(Fq(19)),
        laminate::Fq2::from_base(Fq(23))};
    const auto structured = compiled.matrix_oracle->evaluate_matrices(
        row_point, column_point);
    for (std::size_t matrix = 0; matrix < 3; ++matrix) {
        CHECK(structured[matrix] == expanded.evaluate_matrix(
                                        static_cast<Matrix>(matrix),
                                        row_point, column_point));
    }

    const Setup keys = laminate::spartan::setup(
        std::move(compiled.circuit), pcs,
        Options{.matrix_evaluation = MatrixEvaluationMode::Uniform},
        compiled.matrix_oracle);
    R1csAssignment assignment;
    assignment.witness.resize(16, Fq::zero());
    for (std::size_t cycle = 0; cycle < 4; ++cycle) {
        const Fq x(cycle + 2);
        assignment.witness[4 * cycle] = x;
        assignment.witness[4 * cycle + 1] = x * x;
        assignment.witness[4 * cycle + 2] = x * x * x;
    }
    CHECK(keys.prover_key.matrix_oracle != nullptr);
    CHECK(keys.prover_key.circuit->is_satisfied(assignment));

    Transcript prover("laminate/test/spartan-uniform/v1");
    const Proof proof = laminate::spartan::prove(
        keys.prover_key, assignment, pcs, prover);
    Transcript verifier("laminate/test/spartan-uniform/v1");
    CHECK(laminate::spartan::verify(keys.verifier_key, {}, proof, pcs,
                                    verifier));
    CHECK(prover.challenge_fq2() == verifier.challenge_fq2());
}

void test_uniform_spartan_with_public_blocks() {
    BaseFoldPcs pcs({.log_rate = 2, .query_count = 16});
    auto compiled = laminate::spartan::compile_uniform_r1cs(
        make_local_public_uniform_circuit(), 3);
    CHECK(compiled.circuit.shape().public_inputs == 7);
    CHECK(compiled.circuit.shape().witness_variables == 8);
    CHECK(compiled.circuit.padded_constraints() == 8);
    CHECK(compiled.circuit.assignment_half_size() == 8);
    CHECK(compiled.cycles == 3);
    CHECK(compiled.padded_cycles == 4);
    CHECK(compiled.public_stride == 2);
    CHECK(compiled.witness_stride == 2);

    const R1csInstance expanded = make_expanded_public_uniform_circuit();
    const R1csAssignment assignment = public_uniform_assignment();
    CHECK(compiled.circuit.is_satisfied(assignment));
    CHECK(expanded.is_satisfied(assignment));

    const std::vector<laminate::Fq2> row_point{
        laminate::Fq2::from_base(Fq(2)),
        laminate::Fq2::from_base(Fq(3)),
        laminate::Fq2::from_base(Fq(5))};
    const std::vector<laminate::Fq2> column_point{
        laminate::Fq2::from_base(Fq(7)),
        laminate::Fq2::from_base(Fq(11)),
        laminate::Fq2::from_base(Fq(13)),
        laminate::Fq2::from_base(Fq(17))};
    const auto structured = compiled.matrix_oracle->evaluate_matrices(
        row_point, column_point);
    for (std::size_t matrix = 0; matrix < 3; ++matrix) {
        const auto kind = static_cast<Matrix>(matrix);
        CHECK(structured[matrix] == expanded.evaluate_matrix(
                                        kind, row_point, column_point));
        CHECK(compiled.circuit.multiply(
                  kind, compiled.circuit.padded_assignment(assignment)) ==
              expanded.multiply(kind, expanded.padded_assignment(assignment)));
    }
    const laminate::Fq2 gamma = laminate::Fq2::from_base(Fq(19));
    CHECK(compiled.circuit.batched_wiring_table(row_point, gamma) ==
          expanded.batched_wiring_table(row_point, gamma));

    const auto oracle = compiled.matrix_oracle;
    const Setup keys = laminate::spartan::setup(
        std::move(compiled.circuit), pcs,
        Options{.matrix_evaluation = MatrixEvaluationMode::Uniform}, oracle);
    Transcript prover("laminate/test/spartan-uniform-public/v1");
    const Proof proof = laminate::spartan::prove(
        keys.prover_key, assignment, pcs, prover);
    Transcript verifier("laminate/test/spartan-uniform-public/v1");
    CHECK(laminate::spartan::verify(
        keys.verifier_key, assignment.public_inputs, proof, pcs, verifier));
    CHECK(prover.challenge_fq2() == verifier.challenge_fq2());
}

void test_spartan_rejects_mutations() {
    BaseFoldPcs pcs;
    const Setup keys = laminate::spartan::setup(make_cube_circuit(), pcs);
    const R1csAssignment assignment = cube_assignment(5);
    Transcript prover("laminate/test/spartan-mutation/v1");
    const Proof honest = laminate::spartan::prove(
        keys.prover_key, assignment, pcs, prover);

    auto rejects = [&](const Proof &proof,
                       const std::vector<Fq> &public_inputs) {
        Transcript verifier("laminate/test/spartan-mutation/v1");
        return !laminate::spartan::verify(
            keys.verifier_key, public_inputs, proof, pcs, verifier);
    };

    Proof bad_terminal = honest;
    bad_terminal.az_evaluation += laminate::Fq2::one();
    CHECK(rejects(bad_terminal, assignment.public_inputs));

    Proof bad_round = honest;
    bad_round.constraint_sumcheck.rounds[0].at_two += laminate::Fq2::one();
    CHECK(rejects(bad_round, assignment.public_inputs));

    Proof bad_matrix = honest;
    bad_matrix.matrix_evaluation += laminate::Fq2::one();
    CHECK(rejects(bad_matrix, assignment.public_inputs));

    Proof bad_opening = honest;
    bad_opening.witness_opening
        .bytes[bad_opening.witness_opening.bytes.size() / 2] ^= 1U;
    CHECK(rejects(bad_opening, assignment.public_inputs));

    Proof bad_root = honest;
    bad_root.witness_commitment.root[0] ^= 1U;
    CHECK(rejects(bad_root, assignment.public_inputs));

    Proof bad_rate = honest;
    --bad_rate.witness_commitment.log_rate;
    CHECK(rejects(bad_rate, assignment.public_inputs));
    Proof bad_queries = honest;
    --bad_queries.witness_commitment.query_count;
    CHECK(rejects(bad_queries, assignment.public_inputs));
    std::vector<Fq> wrong_public = assignment.public_inputs;
    wrong_public[0] += Fq::one();
    CHECK(rejects(honest, wrong_public));
}

void test_spartan_rejects_false_witness() {
    BaseFoldPcs pcs({.log_rate = 2, .query_count = 8});
    const Setup keys = laminate::spartan::setup(make_cube_circuit(), pcs);
    R1csAssignment assignment = cube_assignment(7);
    assignment.witness[1] += Fq::one();
    bool threw = false;
    try {
        Transcript transcript("laminate/test/spartan-false/v1");
        (void)laminate::spartan::prove(
            keys.prover_key, assignment, pcs, transcript);
    } catch (const std::logic_error &) {
        threw = true;
    }
    CHECK(threw);
}

} // namespace

int main() {
    laminate::test::Runner runner("test_spartan");
    runner.run("R1CS shape and evaluation", test_r1cs_shape_and_evaluation);
    runner.run("Spartan plus BaseFold end to end", test_spartan_end_to_end);
    runner.run("uniform Spartan plus BaseFold end to end",
               test_uniform_spartan_end_to_end);
    runner.run("uniform Spartan with per-cycle public blocks",
               test_uniform_spartan_with_public_blocks);
    runner.run("Spartan mutation rejection", test_spartan_rejects_mutations);
    runner.run("Spartan false witness rejection",
               test_spartan_rejects_false_witness);
    return runner.summary();
}
