/// @file test_action_sumcheck.cpp
/// @brief Correctness and forgery tests for the Wide BGV-action sumcheck.

#include "test_helpers.hpp"

#include "laminate/fhe/layout/slot_grid.hpp"
#include "laminate/gates/action_sumcheck.hpp"
#include "laminate/poly/eq.hpp"
#include "laminate/transcript/transcript.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <vector>

using namespace laminate;

namespace {

constexpr std::string_view kTranscriptDomain =
    "Laminate/gates/wide-action/test/v1";

Fpk extension(std::uint64_t seed) {
    Fpk::Coefficients coefficients{};
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        coefficients[index] =
            Fp(seed + 19U * index + 5U * index * index);
    }
    return Fpk(coefficients);
}

std::vector<Fpk> point(std::size_t variables, std::uint64_t seed) {
    std::vector<Fpk> result;
    result.reserve(variables);
    for (std::size_t variable = 0; variable < variables; ++variable) {
        result.push_back(extension(seed + 31U * variable));
    }
    return result;
}

std::vector<Fpk> vertex(std::size_t address,
                        std::size_t variables) {
    std::vector<Fpk> result;
    result.reserve(variables);
    for (std::size_t variable = 0; variable < variables; ++variable) {
        const bool bit =
            ((address >> (variables - 1U - variable)) & 1U) != 0;
        result.push_back(bit ? Fpk::one() : Fpk::zero());
    }
    return result;
}

std::size_t address(std::size_t output_wire,
                    std::size_t source_wire, std::size_t offset,
                    std::size_t source_variables,
                    std::size_t offset_variables) {
    return (((output_wire << source_variables) | source_wire)
            << offset_variables) |
           offset;
}

std::vector<Fpk> concatenate(std::span<const Fpk> first,
                             std::span<const Fpk> second,
                             std::span<const Fpk> third = {}) {
    std::vector<Fpk> result;
    result.reserve(first.size() + second.size() + third.size());
    result.insert(result.end(), first.begin(), first.end());
    result.insert(result.end(), second.begin(), second.end());
    result.insert(result.end(), third.begin(), third.end());
    return result;
}

Fpk brute_full_coefficient(
    std::span<const gates::sparse::SparseEntry> entries,
    std::span<const Fpk> output_wire_point,
    std::span<const Fpk> output_slot_point,
    std::span<const Fpk> source_wire_point,
    std::span<const Fpk> source_slot_point) {
    const std::size_t offset_variables = output_slot_point.size();
    const std::size_t slot_count =
        std::size_t{1} << offset_variables;
    const std::size_t offset_mask = slot_count - 1U;
    const std::size_t source_mask =
        source_wire_point.empty()
            ? 0
            : (std::size_t{1} << source_wire_point.size()) - 1U;
    const std::vector<Fpk> output_wire_weights =
        poly::eq_evaluations(
            std::vector<Fpk>(output_wire_point.begin(),
                             output_wire_point.end()));
    const std::vector<Fpk> source_wire_weights =
        poly::eq_evaluations(
            std::vector<Fpk>(source_wire_point.begin(),
                             source_wire_point.end()));
    const std::vector<Fpk> output_slot_weights =
        poly::eq_evaluations(
            std::vector<Fpk>(output_slot_point.begin(),
                             output_slot_point.end()));
    const std::vector<Fpk> source_slot_weights =
        poly::eq_evaluations(
            std::vector<Fpk>(source_slot_point.begin(),
                             source_slot_point.end()));

    Fpk result = Fpk::zero();
    for (const gates::sparse::SparseEntry &entry : entries) {
        const std::size_t offset = entry.address & offset_mask;
        const std::size_t source_wire =
            (entry.address >> offset_variables) & source_mask;
        const std::size_t output_wire =
            entry.address >>
            (offset_variables + source_wire_point.size());
        for (std::size_t output_slot = 0;
             output_slot < slot_count; ++output_slot) {
            const std::size_t source_slot = fhe::grid_source(
                slot_count, offset, output_slot);
            result += Fpk::from_base(entry.value) *
                      output_wire_weights[output_wire] *
                      source_wire_weights[source_wire] *
                      output_slot_weights[output_slot] *
                      source_slot_weights[source_slot];
        }
    }
    return result;
}

Fpk interpolate(const Fpk &at_zero, const Fpk &at_one,
                const Fpk &at_two, const Fpk &value) {
    const Fpk one = Fpk::one();
    const Fpk two = Fpk::from_base(Fp(2));
    const Fpk half = Fpk::from_base(Fp(2).inverse());
    return at_zero * (value - one) * (value - two) * half -
           at_one * value * (value - two) +
           at_two * value * (value - one) * half;
}

Fpk dense_round_evaluation(
    std::span<const gates::sparse::SparseEntry> entries,
    std::span<const Fpk> output_wire_point,
    const std::vector<Fpk> &output_slot_point,
    std::span<const Fpk> source_wire_point,
    const std::vector<Fpk> &source_slot_point,
    std::span<const Fpk> prefix, const Fpk &round_value,
    std::size_t offset_variables) {
    const std::size_t suffix_variables =
        offset_variables - prefix.size() - 1U;
    const std::size_t suffix_count =
        std::size_t{1} << suffix_variables;
    Fpk result = Fpk::zero();
    for (std::size_t suffix = 0; suffix < suffix_count; ++suffix) {
        std::vector<Fpk> offset_point(prefix.begin(), prefix.end());
        offset_point.push_back(round_value);
        const std::vector<Fpk> suffix_point =
            vertex(suffix, suffix_variables);
        offset_point.insert(offset_point.end(), suffix_point.begin(),
                            suffix_point.end());
        const std::vector<Fpk> compact_point = concatenate(
            output_wire_point, source_wire_point, offset_point);
        const Fpk compact = gates::sparse::evaluate_sparse_entries(
            entries, compact_point.size(), compact_point);
        result += compact * poly::grid_action_eval(
                                output_slot_point, source_slot_point,
                                offset_point);
    }
    return result;
}

struct Fixture {
    std::vector<gates::sparse::SparseEntry> entries;
    std::vector<Fpk> output_wire;
    std::vector<Fpk> output_slot;
    std::vector<Fpk> source_wire;
    std::vector<Fpk> source_slot;
    Fpk claimed = Fpk::zero();
    gates::WideActionSumcheckProverOutput proved;
};

Fixture prove_fixture() {
    constexpr std::size_t output_variables = 2;
    constexpr std::size_t source_variables = 2;
    constexpr std::size_t offset_variables = 3;
    Fixture fixture;
    fixture.entries = {
        {address(0, 1, 0, source_variables, offset_variables), Fp(3)},
        {address(0, 2, 5, source_variables, offset_variables), Fp(7)},
        {address(1, 0, 3, source_variables, offset_variables), Fp(11)},
        {address(1, 3, 5, source_variables, offset_variables), Fp(13)},
        {address(2, 1, 7, source_variables, offset_variables), Fp(17)},
        {address(3, 2, 3, source_variables, offset_variables), Fp(19)},
    };
    fixture.output_wire = point(output_variables, 101);
    fixture.output_slot = point(offset_variables, 211);
    fixture.source_wire = point(source_variables, 307);
    fixture.source_slot = point(offset_variables, 401);
    fixture.claimed = brute_full_coefficient(
        fixture.entries, fixture.output_wire, fixture.output_slot,
        fixture.source_wire, fixture.source_slot);
    Transcript prover(kTranscriptDomain);
    fixture.proved = gates::prove_wide_action_sumcheck(
        fixture.entries, fixture.output_wire, fixture.output_slot,
        fixture.source_wire, fixture.source_slot, fixture.claimed,
        prover);
    return fixture;
}

std::optional<gates::WideActionSumcheckReduction> verify_proof(
    const gates::WideActionSumcheckProof &proof,
    std::span<const Fpk> output_wire,
    std::span<const Fpk> output_slot,
    std::span<const Fpk> source_wire,
    std::span<const Fpk> source_slot, const Fpk &claimed) {
    Transcript verifier(kTranscriptDomain);
    return gates::verify_wide_action_sumcheck(
        output_wire, output_slot, source_wire, source_slot, claimed,
        proof, verifier);
}

std::optional<gates::WideActionSumcheckReduction> verify(
    const Fixture &fixture,
    const gates::WideActionSumcheckProof &proof) {
    return verify_proof(proof, fixture.output_wire, fixture.output_slot,
                        fixture.source_wire, fixture.source_slot,
                        fixture.claimed);
}

} // namespace

int main() {
    test::Runner runner("test_action_sumcheck");

    runner.run("sparse action sumcheck proves the full Wide coefficient",
               [] {
                   const Fixture fixture = prove_fixture();
                   CHECK(fixture.proved.proof.rounds.size() ==
                         fixture.output_slot.size());
                   CHECK(fixture.proved.reduction.offset_point_msb.size() ==
                         fixture.output_slot.size());
                   CHECK(fixture.proved.proof.terminal_compact_weight ==
                         fixture.proved.reduction.compact_weight);

                   const std::vector<Fpk> terminal_point = concatenate(
                       fixture.output_wire, fixture.source_wire,
                       fixture.proved.reduction.offset_point_msb);
                   CHECK(fixture.proved.reduction.compact_weight ==
                         gates::sparse::evaluate_sparse_entries(
                             fixture.entries, terminal_point.size(),
                             terminal_point));

                   const auto checked = verify(
                       fixture, fixture.proved.proof);
                   CHECK(checked.has_value());
                   CHECK(*checked == fixture.proved.reduction);
               });

    runner.run("direct expansion and every round polynomial agree", [] {
        const Fixture fixture = prove_fixture();
        CHECK(gates::evaluate_wide_affine_coefficient(
                  fixture.entries, fixture.output_wire,
                  fixture.output_slot, fixture.source_wire,
                  fixture.source_slot) == fixture.claimed);

        Fpk running = fixture.claimed;
        std::vector<Fpk> prefix;
        for (std::size_t round = 0;
             round < fixture.proved.proof.rounds.size(); ++round) {
            const Fpk at_zero = dense_round_evaluation(
                fixture.entries, fixture.output_wire,
                fixture.output_slot, fixture.source_wire,
                fixture.source_slot, prefix, Fpk::zero(),
                fixture.output_slot.size());
            const Fpk at_one = dense_round_evaluation(
                fixture.entries, fixture.output_wire,
                fixture.output_slot, fixture.source_wire,
                fixture.source_slot, prefix, Fpk::one(),
                fixture.output_slot.size());
            const Fpk at_two = dense_round_evaluation(
                fixture.entries, fixture.output_wire,
                fixture.output_slot, fixture.source_wire,
                fixture.source_slot, prefix, Fpk::from_base(Fp(2)),
                fixture.output_slot.size());
            CHECK(at_zero + at_one == running);
            CHECK(fixture.proved.proof.rounds[round].at_one == at_one);
            CHECK(fixture.proved.proof.rounds[round].at_two == at_two);
            const Fpk challenge =
                fixture.proved.reduction.offset_point_msb[round];
            running = interpolate(at_zero, at_one, at_two, challenge);
            prefix.push_back(challenge);
        }
        CHECK(running == fixture.proved.reduction.compact_weight *
                             poly::grid_action_eval(
                                 fixture.output_slot,
                                 fixture.source_slot, prefix));
    });

    runner.run("one slot bit covers the BGV row-swap action", [] {
        const std::vector<gates::sparse::SparseEntry> entries = {
            {0, Fp(23)}, {1, Fp(41)}};
        const std::vector<Fpk> no_wires;
        const std::vector<Fpk> output_slot = point(1, 503);
        const std::vector<Fpk> source_slot = point(1, 601);
        const Fpk claimed = brute_full_coefficient(
            entries, no_wires, output_slot, no_wires, source_slot);
        CHECK(gates::evaluate_wide_affine_coefficient(
                  entries, no_wires, output_slot, no_wires,
                  source_slot) == claimed);

        Transcript prover("Laminate/gates/wide-action/row-swap/v1");
        const auto proved = gates::prove_wide_action_sumcheck(
            entries, no_wires, output_slot, no_wires, source_slot,
            claimed, prover);
        CHECK(proved.proof.rounds.size() == 1);
        Transcript verifier("Laminate/gates/wide-action/row-swap/v1");
        const auto checked = gates::verify_wide_action_sumcheck(
            no_wires, output_slot, no_wires, source_slot, claimed,
            proved.proof, verifier);
        CHECK(checked.has_value());
        CHECK(*checked == proved.reduction);
    });

    runner.run("round, terminal, and statement tampering is rejected", [] {
        const Fixture fixture = prove_fixture();

        gates::WideActionSumcheckProof bad_one = fixture.proved.proof;
        bad_one.rounds.front().at_one += Fpk::one();
        CHECK(!verify(fixture, bad_one).has_value());

        gates::WideActionSumcheckProof bad_two = fixture.proved.proof;
        bad_two.rounds.back().at_two += Fpk::one();
        CHECK(!verify(fixture, bad_two).has_value());

        gates::WideActionSumcheckProof bad_terminal =
            fixture.proved.proof;
        bad_terminal.terminal_compact_weight += Fpk::one();
        CHECK(!verify(fixture, bad_terminal).has_value());

        std::vector<Fpk> changed_output_wire = fixture.output_wire;
        changed_output_wire.front() += Fpk::one();
        CHECK(!verify_proof(fixture.proved.proof, changed_output_wire,
                      fixture.output_slot, fixture.source_wire,
                      fixture.source_slot, fixture.claimed)
                   .has_value());

        std::vector<Fpk> changed_output_slot = fixture.output_slot;
        changed_output_slot.front() += Fpk::one();
        CHECK(!verify_proof(fixture.proved.proof, fixture.output_wire,
                      changed_output_slot, fixture.source_wire,
                      fixture.source_slot, fixture.claimed)
                   .has_value());
        CHECK(!verify_proof(fixture.proved.proof, fixture.output_wire,
                      fixture.output_slot, fixture.source_wire,
                      fixture.source_slot, fixture.claimed + Fpk::one())
                   .has_value());
    });

    runner.run("malformed shapes fail before transcript mutation", [] {
        const Fixture fixture = prove_fixture();

        gates::WideActionSumcheckProof missing = fixture.proved.proof;
        missing.rounds.pop_back();
        Transcript rejected_missing(kTranscriptDomain);
        CHECK(!gates::verify_wide_action_sumcheck(
                   fixture.output_wire, fixture.output_slot,
                   fixture.source_wire, fixture.source_slot,
                   fixture.claimed, missing, rejected_missing)
                   .has_value());
        Transcript pristine_missing(kTranscriptDomain);
        CHECK(rejected_missing.challenge_fpk() ==
              pristine_missing.challenge_fpk());

        gates::WideActionSumcheckProof extra = fixture.proved.proof;
        extra.rounds.push_back({Fpk::one(), Fpk::one()});
        Transcript rejected_extra(kTranscriptDomain);
        CHECK(!gates::verify_wide_action_sumcheck(
                   fixture.output_wire, fixture.output_slot,
                   fixture.source_wire, fixture.source_slot,
                   fixture.claimed, extra, rejected_extra)
                   .has_value());
        Transcript pristine_extra(kTranscriptDomain);
        CHECK(rejected_extra.challenge_fpk() ==
              pristine_extra.challenge_fpk());

        std::vector<Fpk> short_source_slot = fixture.source_slot;
        short_source_slot.pop_back();
        Transcript rejected_shape(kTranscriptDomain);
        CHECK(!gates::verify_wide_action_sumcheck(
                   fixture.output_wire, fixture.output_slot,
                   fixture.source_wire, short_source_slot,
                   fixture.claimed, fixture.proved.proof,
                   rejected_shape)
                   .has_value());
        Transcript pristine_shape(kTranscriptDomain);
        CHECK(rejected_shape.challenge_fpk() ==
              pristine_shape.challenge_fpk());
    });

    runner.run("prover rejects false claims and noncanonical entries", [] {
        const Fixture fixture = prove_fixture();
        bool false_claim_rejected = false;
        Transcript rejected_claim(kTranscriptDomain);
        try {
            (void)gates::prove_wide_action_sumcheck(
                fixture.entries, fixture.output_wire,
                fixture.output_slot, fixture.source_wire,
                fixture.source_slot, fixture.claimed + Fpk::one(),
                rejected_claim);
        } catch (const std::invalid_argument &) {
            false_claim_rejected = true;
        }
        CHECK(false_claim_rejected);
        Transcript pristine_claim(kTranscriptDomain);
        CHECK(rejected_claim.challenge_fpk() ==
              pristine_claim.challenge_fpk());

        const std::size_t address_variables =
            fixture.output_wire.size() + fixture.source_wire.size() +
            fixture.output_slot.size();
        const std::size_t out_of_range =
            std::size_t{1} << address_variables;
        for (const std::vector<gates::sparse::SparseEntry> &bad : {
                 std::vector<gates::sparse::SparseEntry>{
                     {out_of_range, Fp::one()}},
                 std::vector<gates::sparse::SparseEntry>{
                     {0, Fp::zero()}},
                 std::vector<gates::sparse::SparseEntry>{
                     {1, Fp(3)}, {1, Fp(5)}},
                 std::vector<gates::sparse::SparseEntry>{
                     {2, Fp(3)}, {1, Fp(5)}}}) {
            bool rejected = false;
            try {
                (void)gates::evaluate_wide_affine_coefficient(
                    bad, fixture.output_wire, fixture.output_slot,
                    fixture.source_wire, fixture.source_slot);
            } catch (const std::invalid_argument &) {
                rejected = true;
            }
            CHECK(rejected);
        }

        bool empty_slots_rejected = false;
        try {
            const std::vector<Fpk> empty;
            (void)gates::evaluate_wide_affine_coefficient(
                fixture.entries, fixture.output_wire, empty,
                fixture.source_wire, empty);
        } catch (const std::invalid_argument &) {
            empty_slots_rejected = true;
        }
        CHECK(empty_slots_rejected);
    });

    return runner.summary();
}
