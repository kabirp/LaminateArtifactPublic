/// @file test_outsourced_gate_mle.cpp
/// @brief End-to-end and forgery tests for structured gate-MLE openings.

#include "test_helpers.hpp"

#include "laminate/basefold/common.hpp"
#include "laminate/bench/target_cost.hpp"
#include "laminate/gates/outsourced.hpp"
#include "laminate/gkr/detail/shared/reduction/gate_claims.hpp"
#include "laminate/payload/compiler.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace laminate;

namespace {

payload::PayloadCircuit make_wide_payload() {
    payload::PayloadBuilder builder(payload::PayloadShape::wide(8), 2);
    const std::size_t uniform =
        builder.add_scalar_plaintext(Fp(23));
    const std::size_t diagonal = builder.add_plaintext(
        {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
    const auto left = builder.add_plain(
        builder.mul_plain(builder.rotate(0, 3), diagonal), uniform);
    const auto right = builder.add_plain(1, diagonal);
    builder.set_outputs({builder.mul(left, right)});
    return builder.finish();
}

payload::PayloadCircuit make_laned_payload() {
    payload::PayloadBuilder builder(
        payload::PayloadShape::laned(4, 16), 2);
    const std::size_t uniform =
        builder.add_scalar_plaintext(Fp(29));
    const auto left = builder.add_plain(builder.add(0, 1), uniform);
    builder.set_outputs({builder.mul(left, 1)});
    return builder.finish();
}

Fpk value(std::uint64_t seed) {
    Fpk::Coefficients coefficients{};
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        coefficients[index] = Fp(seed + 23 * index + 5 * index * index);
    }
    return Fpk(coefficients);
}

std::vector<Fpk> point(std::size_t variables, std::uint64_t seed) {
    std::vector<Fpk> result;
    result.reserve(variables);
    for (std::size_t index = 0; index < variables; ++index) {
        result.push_back(value(seed + 41 * index));
    }
    return result;
}

std::size_t variables(std::size_t dimension) {
    return basefold::log2_exact(dimension);
}

struct QueryBatch {
    std::size_t affine_layer = 0;
    gates::GateTableSet table_set = gates::GateTableSet::Wide;
    std::size_t output_wire_variables = 0;
    std::vector<Fpk> affine_output;
    std::vector<Fpk> affine_source;
};

QueryBatch make_queries(const payload::LayeredCircuit &circuit,
                        const gates::GateTableLayout &layout,
                        bool require_split_constants) {
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        const gates::GateTableKind coefficient_kind =
            layout.table_set == gates::GateTableSet::Wide
                ? gates::GateTableKind::WideLocalUniformEdges
                : gates::GateTableKind::LanedAffineWire;
        if (gates::find_table_if(layout, layer, coefficient_kind) == nullptr ||
            gates::find_table_if(
                layout, layer,
                gates::GateTableKind::AffineConstantUniform) == nullptr ||
            (require_split_constants &&
             gates::find_table_if(
                 layout, layer,
                 gates::GateTableKind::AffineConstantSlot) == nullptr)) {
            continue;
        }

        const std::size_t output_wires =
            payload::layer_dimensions(circuit.layers[layer]).padded_size;
        const std::size_t source_wires = payload::layer_dimensions(
                                             circuit.layers[layer + 1])
                                             .padded_size;
        const std::size_t output_wire_variables = variables(output_wires);
        const std::size_t slot_variables =
            variables(circuit.shape.value_width());
        return QueryBatch{
            layer,
            layout.table_set,
            output_wire_variables,
            point(output_wire_variables + slot_variables, 101),
            point(variables(source_wires) +
                      (layout.table_set == gates::GateTableSet::Wide
                           ? slot_variables
                           : 0),
                  211)};
    }
    throw std::logic_error(
        "test fixture lacks the requested structured affine layer");
}

std::vector<Fpk> record_batch(gates::GateClaimProver &channel,
                              const QueryBatch &queries) {
    const Fpk constant = channel.evaluate_affine_constant(
        queries.affine_layer, queries.affine_output);
    if (queries.table_set == gates::GateTableSet::Wide) {
        return {
            constant,
            channel.evaluate(gates::GateMleQuery{gates::AffineQuery{
                queries.affine_layer, queries.affine_output,
                queries.affine_source}})};
    }
    return {
        constant,
        channel.evaluate(gates::GateMleQuery{
            gates::LanedAffineWireQuery{
                queries.affine_layer,
                std::span<const Fpk>(queries.affine_output)
                    .first(queries.output_wire_variables),
                queries.affine_source}})};
}

std::vector<Fpk> replay_batch(gates::GateClaimVerifier &channel,
                              const QueryBatch &queries) {
    const Fpk constant = channel.evaluate_affine_constant(
        queries.affine_layer, queries.affine_output);
    if (queries.table_set == gates::GateTableSet::Wide) {
        return {
            constant,
            channel.evaluate(gates::GateMleQuery{gates::AffineQuery{
                queries.affine_layer, queries.affine_output,
                queries.affine_source}})};
    }
    return {
        constant,
        channel.evaluate(gates::GateMleQuery{
            gates::LanedAffineWireQuery{
                queries.affine_layer,
                std::span<const Fpk>(queries.affine_output)
                    .first(queries.output_wire_variables),
                queries.affine_source}})};
}

struct Fixture {
    payload::LayeredCircuit circuit;
    gates::GateTableProverKey key;
    QueryBatch queries;
    std::vector<Fpk> values;
    gates::OutsourcedGateMleProof proof;
};

Fixture prove_fixture(const payload::PayloadCircuit &payload_circuit,
                      gates::GateTableSet table_set,
                      bool require_split_constants,
                      const basefold::Parameters parameters = {2, 10}) {
    payload::LayeredCircuit circuit = payload::compile(payload_circuit);
    gates::GateTableProverKey key = gates::preprocess_gate_tables(
        circuit, table_set,
        gates::GateTableBuildOptions{
            .basefold_parameters = parameters,
            .max_message_entries = std::size_t{1} << 22});
    QueryBatch queries = make_queries(
        circuit, key.verifier.layout, require_split_constants);
    Transcript transcript("Laminate/OutsourcedGate/Test/v2");
    gates::observe_gate_table_key(key.verifier, transcript);
    gates::GateClaimProver channel(circuit, key.verifier.layout, transcript);
    std::vector<Fpk> values = record_batch(channel, queries);
    gates::OutsourcedGateMleProof proof = channel.finish(key);
    return Fixture{std::move(circuit), std::move(key), std::move(queries),
                   std::move(values), std::move(proof)};
}

Fixture prove_wide_fixture() {
    return prove_fixture(make_wide_payload(), gates::GateTableSet::Wide,
                         true);
}

Fixture prove_laned_fixture() {
    return prove_fixture(make_laned_payload(), gates::GateTableSet::Laned,
                         false);
}

bool verify_fixture(const Fixture &fixture,
                    const gates::OutsourcedGateMleProof &proof,
                    const QueryBatch &queries) {
    Transcript transcript("Laminate/OutsourcedGate/Test/v2");
    gates::observe_gate_table_key(fixture.key.verifier, transcript);
    gates::GateClaimVerifier channel(fixture.key.verifier, proof, transcript);
    const std::vector<Fpk> values = replay_batch(channel, queries);
    return values == proof.claimed_values && channel.finish();
}

bool opening_for_kind(const Fixture &fixture,
                      gates::GateTableKind kind) {
    const gates::GateTableDescriptor *descriptor = gates::find_table_if(
        fixture.key.verifier.layout, fixture.queries.affine_layer, kind);
    if (descriptor == nullptr) {
        return false;
    }
    if (fixture.proof.wide) {
        for (const auto &opening : fixture.proof.wide->tables)
            if (opening.table_selector == descriptor->selector) return true;
        return false;
    }
    for (const gates::SparseTableOpeningProof &opening :
         fixture.proof.table_openings) {
        if (opening.table_selector == descriptor->selector) {
            return true;
        }
    }
    return false;
}

} // namespace

int main() {
    test::Runner runner("test_outsourced_gate_mle");

    runner.run("default rate-eight Wide and Laned openings bind parameters", [] {
        for (const bool wide : {false, true}) {
            Fixture fixture = prove_fixture(
                wide ? make_wide_payload() : make_laned_payload(),
                wide ? gates::GateTableSet::Wide
                     : gates::GateTableSet::Laned,
                wide, basefold::Parameters{});
            CHECK(fixture.key.verifier.basefold_parameters.log_rate == 3U);
            CHECK(fixture.key.verifier.basefold_parameters.num_queries ==
                  kGateMleBaseFoldQueries);
            CHECK(verify_fixture(fixture, fixture.proof, fixture.queries));

            gates::OutsourcedGateMleProof bad_merkle = fixture.proof;
            if (wide) bad_merkle.wide->public_opening.initial.values.front() += Fpk::one();
            else bad_merkle.table_openings.front().opening.queries.openings.front().base_lo.front() += Fp::one();
            CHECK(!verify_fixture(fixture, bad_merkle, fixture.queries));

            gates::OutsourcedGateMleProof missing = fixture.proof;
            if (wide) missing.wide->public_opening.initial.values.pop_back();
            else missing.table_openings.front().opening.queries.openings.pop_back();
            CHECK(!verify_fixture(fixture, missing, fixture.queries));
            gates::OutsourcedGateMleProof bad_terminal = fixture.proof;
            if (wide) bad_terminal.wide->public_opening.sumcheck.operand_evaluations.front() += Fpk::one();
            else bad_terminal.table_openings.front().opening.sumcheck.operand_evaluations.front() += Fpk::one();
            CHECK(!verify_fixture(fixture, bad_terminal, fixture.queries));
            const auto original_parameters =
                fixture.key.verifier.basefold_parameters;
            --fixture.key.verifier.basefold_parameters.log_rate;
            CHECK(!verify_fixture(fixture, fixture.proof, fixture.queries));
            fixture.key.verifier.basefold_parameters = original_parameters;
            --fixture.key.verifier.basefold_parameters.num_queries;
            CHECK(!verify_fixture(fixture, fixture.proof, fixture.queries));
        }
    });

    runner.run("rate-eight Laned tables retain RS sharding", [] {
        const basefold::Parameters parameters{};
        const gates::GateTableDescriptor descriptor{
            .layer_index = 0,
            .kind = gates::GateTableKind::LanedAffineWire,
            .selector = 0,
            .local_variables = 14,
            .support_size = 8193,
        };
        const gates::SparseTableCommitment sharded{
            .message_size = 16384,
            .shard_size = 8192,
            .shard_count = 2,
            .logical_width = 16,
            .physical_width = 32,
        };
        CHECK(gates::valid_sparse_table_commitment(
            descriptor, sharded, parameters));
        CHECK(basefold::valid_shape(8192, 32, parameters));
        CHECK(!basefold::valid_shape(16384, 16, parameters));

        gates::SparseTableCommitment old_geometry = sharded;
        old_geometry.shard_size = 16384;
        old_geometry.shard_count = 1;
        old_geometry.physical_width = 16;
        CHECK(!gates::valid_sparse_table_commitment(
            descriptor, old_geometry, parameters));

        gates::GateTableDescriptor boundary = descriptor;
        boundary.support_size = 8192;
        gates::SparseTableCommitment unsharded = sharded;
        unsharded.message_size = 8192;
        unsharded.shard_count = 1;
        unsharded.physical_width = 16;
        CHECK(gates::valid_sparse_table_commitment(
            boundary, unsharded, parameters));
    });

    runner.run("Wide reverse trace authenticates local mask and rotation tables", [] {
        const Fixture fixture = prove_wide_fixture();
        CHECK(fixture.values == fixture.proof.claimed_values);
        CHECK(fixture.proof.claimed_values.size() == 2);
        CHECK(fixture.proof.wide.has_value());
        CHECK(fixture.proof.wide->traces.size() == 1);
        CHECK(!fixture.proof.wide->traces[0].product.rounds.empty());
        CHECK(fixture.proof.wide->tables.size() == 5);
        CHECK(fixture.proof.action_sumchecks.empty());
        CHECK(fixture.proof.table_openings.empty());
        CHECK(opening_for_kind(
            fixture, gates::GateTableKind::WideLocalUniformEdges));
        CHECK(opening_for_kind(
            fixture, gates::GateTableKind::WideLocalMaskEdges));
        CHECK(opening_for_kind(
            fixture, gates::GateTableKind::AffineConstantUniform));
        CHECK(opening_for_kind(
            fixture, gates::GateTableKind::AffineConstantSlot));
        CHECK(!gates::encode_canonical(fixture.proof).empty());
        CHECK(verify_fixture(fixture, fixture.proof, fixture.queries));
    });

    runner.run("Laned wire and uniform constant claims are outsourced", [] {
        const Fixture fixture = prove_laned_fixture();
        CHECK(fixture.values == fixture.proof.claimed_values);
        CHECK(fixture.proof.claimed_values.size() == 2);
        CHECK(fixture.proof.action_sumchecks.empty());
        CHECK(fixture.proof.sparse_values.size() == 2);
        CHECK(fixture.proof.sparse_products.size() == 2);
        CHECK(fixture.proof.table_openings.size() == 2);
        CHECK(opening_for_kind(
            fixture, gates::GateTableKind::LanedAffineWire));
        CHECK(opening_for_kind(
            fixture, gates::GateTableKind::AffineConstantUniform));
        CHECK(verify_fixture(fixture, fixture.proof, fixture.queries));
    });

    runner.run("multi-shard physical columns open and bind every shard", [] {
        const Fixture fixture = prove_fixture(
            make_laned_payload(), gates::GateTableSet::Laned, false,
            basefold::Parameters{15, 1});
        CHECK(verify_fixture(fixture, fixture.proof, fixture.queries));

        std::optional<std::pair<std::size_t, std::size_t>> sharded_opening;
        for (std::size_t opening_index = 0;
             opening_index < fixture.proof.table_openings.size();
             ++opening_index) {
            const gates::SparseTableOpeningProof &opening =
                fixture.proof.table_openings[opening_index];
            const gates::SparseTableCommitment &table =
                fixture.key.verifier.tables.at(opening.table_selector);
            if (table.shard_count > 1) {
                CHECK(!opening.column_targets.empty());
                CHECK(opening.column_targets[0].size() ==
                      table.physical_width);
                sharded_opening =
                    std::pair{opening_index, table.logical_width};
                break;
            }
        }
        CHECK(sharded_opening.has_value());

        gates::OutsourcedGateMleProof tampered = fixture.proof;
        tampered
            .table_openings[sharded_opening->first]
            .column_targets[0][sharded_opening->second] += Fpk::one();
        CHECK(!verify_fixture(fixture, tampered, fixture.queries));
    });

    runner.run("action and sparse product forgeries are rejected", [] {
        const Fixture fixture = prove_wide_fixture();

        gates::OutsourcedGateMleProof bad_action = fixture.proof;
        bool changed_action = false;
        for (auto &local : bad_action.wide->traces[0].local_openings) {
            if (local.action && !local.action->rounds.empty()) {
                local.action->rounds[0].at_one += Fpk::one();
                changed_action = true;
                break;
            }
        }
        CHECK(changed_action);
        CHECK(!verify_fixture(fixture, bad_action, fixture.queries));

        gates::OutsourcedGateMleProof bad_product = fixture.proof;
        bool changed_product_round = false;
        for (auto &local : bad_product.wide->traces[0].local_openings) {
            for (auto &product : local.products) {
                if (!product.root_rounds.empty()) {
                    product.root_rounds[0] += Fpk::one();
                    changed_product_round = true;
                    break;
                }
            }
            if (changed_product_round) break;
        }
        CHECK(changed_product_round);
        CHECK(!verify_fixture(fixture, bad_product, fixture.queries));
    });

    runner.run("per-table target and Merkle forgeries are rejected", [] {
        const Fixture fixture = prove_wide_fixture();
        CHECK(!fixture.proof.wide->tables.empty());
        CHECK(!fixture.proof.wide->tables[0].column_targets.empty());
        CHECK(!fixture.proof.wide->tables[0].column_targets[0].empty());

        gates::OutsourcedGateMleProof bad_target = fixture.proof;
        bad_target.wide->tables[0].column_targets[0][0] += Fpk::one();
        CHECK(!verify_fixture(fixture, bad_target, fixture.queries));

        gates::OutsourcedGateMleProof bad_selector = fixture.proof;
        ++bad_selector.wide->tables[0].table_selector;
        CHECK(!verify_fixture(fixture, bad_selector, fixture.queries));

        gates::OutsourcedGateMleProof bad_merkle = fixture.proof;
        auto &queries = bad_merkle.wide->public_opening.initial.values;
        CHECK(!queries.empty());
        queries[0] += Fpk::one();
        CHECK(!verify_fixture(fixture, bad_merkle, fixture.queries));
    });

    runner.run("honest public columns bind every target and deduplicate row operands", [] {
        const auto fixture = prove_wide_fixture();
        const auto &meta = *fixture.key.verifier.wide_public_commitment;
        const auto &wide = *fixture.proof.wide;
        CHECK(meta.width > 1);
        CHECK(wide.public_opening.sumcheck.rounds.size() == basefold::log2_exact(meta.m));
        std::size_t expected_operands = 0;
        bool reused = false;
        for (const auto &opening : wide.tables) {
            const auto &table = fixture.key.verifier.tables[opening.table_selector];
            const auto per_request = gates::wide_public_operands_per_request(table, meta);
            expected_operands += per_request * opening.column_targets.size();
            reused |= per_request < table.physical_width;
        }
        CHECK(reused);
        CHECK(wide.public_column_targets.size() == expected_operands);
        CHECK(wide.public_opening.sumcheck.operand_evaluations.size() == expected_operands);
        for (const auto &row : wide.public_column_targets) CHECK(row.size() == meta.width);
        CHECK(verify_fixture(fixture, fixture.proof, fixture.queries));
        const auto reject = [&](auto mutate) {
            auto bad = fixture.proof;
            mutate(*bad.wide);
            CHECK(!verify_fixture(fixture, bad, fixture.queries));
        };
        reject([](auto &proof) { proof.public_column_targets.front().front() += Fpk::one(); });
        reject([](auto &proof) { proof.public_column_targets.front().back() += Fpk::one(); });
        reject([](auto &proof) { proof.public_column_targets.pop_back(); });
        reject([](auto &proof) { proof.public_column_targets.push_back(proof.public_column_targets.front()); });
        reject([](auto &proof) { proof.public_column_targets.front().pop_back(); });
        reject([](auto &proof) {
            std::swap(proof.public_column_targets.front(), proof.public_column_targets.back());
        });
    });

    runner.run("composable affine paths need only public-column openings", [] {
        payload::PayloadBuilder builder(payload::PayloadShape::wide(8), 2);
        const auto mask = builder.add_plaintext(
            {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
        const auto scalar = builder.add_scalar_plaintext(Fp(23));
        const auto sum = builder.add(0, 1);
        const auto left = builder.add_plain(builder.rotate(sum, 3), scalar);
        const auto right = builder.add_plain(builder.mul_plain(sum, mask), mask);
        builder.set_outputs({builder.mul(left, right)});
        const auto fixture = prove_fixture(builder.finish(), gates::GateTableSet::Wide, true);
        CHECK(!fixture.proof.wide->traces.front().has_adjoint);
        CHECK(fixture.proof.wide->adjoint_groups.empty());
        CHECK(!fixture.proof.wide->public_column_targets.empty());
        CHECK(verify_fixture(fixture, fixture.proof, fixture.queries));
        auto bad = fixture.proof;
        bad.claimed_values.front() += Fpk::one();
        CHECK(!verify_fixture(fixture, bad, fixture.queries));
        bad = fixture.proof;
        bad.wide->public_opening.initial.values.front() += Fpk::one();
        CHECK(!verify_fixture(fixture, bad, fixture.queries));
        auto changed = fixture.queries;
        changed.affine_source.front() += Fpk::one();
        CHECK(!verify_fixture(fixture, fixture.proof, changed));
    });

    runner.run("reverse constraint, witness root, and mask terminals reject tampering", [] {
        const auto fixture = prove_wide_fixture();
        auto reject_mutation = [&](auto mutate) {
            auto bad = fixture.proof;
            mutate(bad.wide->traces.front());
            CHECK(!verify_fixture(fixture, bad, fixture.queries));
        };
        reject_mutation([](auto &trace) { trace.residual_evaluation += Fpk::one(); });
        reject_mutation([](auto &trace) { trace.boundary_values.back() += Fpk::one(); });
        reject_mutation([](auto &trace) { trace.product.rounds.front()[1] += Fpk::one(); });
        reject_mutation([](auto &trace) { trace.terminal_values.back() += Fpk::one(); });
        auto bad_root = fixture.proof;
        bad_root.wide->adjoint_groups.front().root[0] ^= 1;
        CHECK(!verify_fixture(fixture, bad_root, fixture.queries));
        auto bad_opening = fixture.proof;
        bad_opening.wide->adjoint_groups.front().opening.initial.values.front() += Fpk::one();
        CHECK(!verify_fixture(fixture, bad_opening, fixture.queries));
        reject_mutation([](auto &trace) {
            for (auto &local : trace.local_openings) {
                if (local.masked) { local.masked->slots.left += Fpk::one(); return; }
            }
            CHECK(false);
        });
    });

    runner.run("online values and query coordinates are transcript-bound", [] {
        const Fixture fixture = prove_wide_fixture();
        gates::OutsourcedGateMleProof bad_value = fixture.proof;
        bad_value.claimed_values[1] += Fpk::one();
        CHECK(!verify_fixture(fixture, bad_value, fixture.queries));

        QueryBatch changed = fixture.queries;
        changed.affine_source[0] += Fpk::one();
        CHECK(!verify_fixture(fixture, fixture.proof, changed));
    });

    runner.run("Wide witness disk is admitted before allocating proof files", [] {
        auto fixture = prove_wide_fixture();
        const auto parent = fixture.key.wide_scratch_parent;
        const auto entries = [&]() {
            std::size_t count = 0;
            for (const auto &entry : std::filesystem::recursive_directory_iterator(parent)) {
                (void)entry;
                ++count;
            }
            return count;
        };
        const auto before = entries();
        fixture.key.wide_resources.max_disk_bytes = fixture.key.wide_retained_disk_bytes;
        Transcript transcript("Laminate/OutsourcedGate/Test/v2");
        gates::observe_gate_table_key(fixture.key.verifier, transcript);
        gates::GateClaimProver channel(fixture.circuit, fixture.key.verifier.layout, transcript);
        (void)record_batch(channel, fixture.queries);
        bool rejected = false;
        try { (void)channel.finish(fixture.key); }
        catch (const std::runtime_error &) { rejected = true; }
        CHECK(rejected);
        CHECK(entries() == before);
    });

    runner.run("paired verifier preserves outsourced claim transcript", [] {
        const payload::PayloadCircuit payload_circuit = make_wide_payload();
        const payload::LayeredCircuit circuit =
            payload::compile(payload_circuit);
        const gates::GateTableProverKey key =
            gates::preprocess_gate_tables(
                circuit, gates::GateTableSet::Wide,
                gates::GateTableBuildOptions{
                    .basefold_parameters = {},
                    .max_message_entries = std::size_t{1} << 22});
        const PublicSetup setup = make_outsourced_gate_setup(
            payload_circuit, circuit, key.verifier);
        const QueryBatch queries = make_queries(
            circuit, key.verifier.layout, true);
        const std::vector<Fpk> second_output = point(
            queries.affine_output.size(), 419);
        const Fpk second_weight = value(613);
        const auto prover_key =
            std::make_shared<const gates::GateTableProverKey>(key);

        Transcript prover_transcript(
            "Laminate/OutsourcedGate/PairProvider/v2");
        gates::observe_gate_mle_setup(setup, prover_transcript);
        gkr::detail::ProverGateClaims prover(
            circuit, setup, prover_transcript);
        const Fpk first_constant = prover.evaluate_affine_constant(
            queries.affine_layer, queries.affine_output);
        const Fpk second_constant = prover.evaluate_affine_constant(
            queries.affine_layer, second_output);
        const Fpk first_affine = prover.evaluate(
            gates::GateMleQuery{gates::AffineQuery{
                queries.affine_layer, queries.affine_output,
                queries.affine_source}});
        const Fpk second_affine = prover.evaluate(
            gates::GateMleQuery{gates::AffineQuery{
                queries.affine_layer, second_output,
                queries.affine_source}});
        const std::optional<gates::OutsourcedGateMleProof> proof =
            prover.finish(prover_key);
        CHECK(proof.has_value());

        Transcript paired_verifier_transcript(
            "Laminate/OutsourcedGate/PairProvider/v2");
        gates::observe_gate_mle_setup(setup, paired_verifier_transcript);
        gkr::detail::VerifierGateClaims paired_verifier(
            circuit, setup, proof, paired_verifier_transcript);
        CHECK(paired_verifier.evaluate_affine_constant_pair(
                  queries.affine_layer, queries.affine_output,
                  second_output, second_weight) ==
              first_constant + second_weight * second_constant);
        CHECK(paired_verifier.evaluate_affine_pair(
                  queries.affine_layer, queries.affine_output,
                  second_output, queries.affine_source,
                  second_weight) ==
              first_affine + second_weight * second_affine);
        CHECK(paired_verifier.finish());
        const Fpk paired_verifier_challenge =
            paired_verifier_transcript.challenge_fpk();

        Transcript manual_verifier_transcript(
            "Laminate/OutsourcedGate/PairProvider/v2");
        gates::observe_gate_mle_setup(setup, manual_verifier_transcript);
        gkr::detail::VerifierGateClaims manual_verifier(
            circuit, setup, proof, manual_verifier_transcript);
        CHECK(manual_verifier.evaluate_affine_constant(
                  queries.affine_layer, queries.affine_output) ==
              first_constant);
        CHECK(manual_verifier.evaluate_affine_constant(
                  queries.affine_layer, second_output) ==
              second_constant);
        CHECK(manual_verifier.evaluate(
                  gates::GateMleQuery{gates::AffineQuery{
                      queries.affine_layer, queries.affine_output,
                      queries.affine_source}}) == first_affine);
        CHECK(manual_verifier.evaluate(
                  gates::GateMleQuery{gates::AffineQuery{
                      queries.affine_layer, second_output,
                      queries.affine_source}}) == second_affine);
        CHECK(manual_verifier.finish());
        CHECK(paired_verifier_challenge ==
              manual_verifier_transcript.challenge_fpk());

        auto substituted = proof;
        CHECK(substituted->wide->traces.size() == 2);
        substituted->wide->traces[1] = substituted->wide->traces[0];
        Transcript bad_transcript("Laminate/OutsourcedGate/PairProvider/v2");
        gates::observe_gate_mle_setup(setup, bad_transcript);
        gkr::detail::VerifierGateClaims bad(circuit, setup, substituted, bad_transcript);
        (void)bad.evaluate_affine_constant_pair(queries.affine_layer,
            queries.affine_output, second_output, second_weight);
        (void)bad.evaluate_affine_pair(queries.affine_layer,
            queries.affine_output, second_output, queries.affine_source, second_weight);
        CHECK(!bad.finish());
    });

    runner.run("adjoint groups preserve blocks without adding witness padding", [] {
        const std::vector<std::size_t> balanced(9, std::size_t{1} << 30);
        const auto groups = gates::wide_adjoint_group_layout(balanced);
        CHECK(groups.size() == 3);
        CHECK(groups[0].trace_indices == (std::vector<std::size_t>{0, 1, 2, 3}));
        CHECK(groups[1].trace_indices == (std::vector<std::size_t>{4, 5, 6, 7}));
        CHECK(groups[2].trace_indices == (std::vector<std::size_t>{8}));
        CHECK(groups[0].message_size == (std::size_t{1} << 32));
        CHECK(groups[2].message_size == (std::size_t{1} << 30));
        const std::array<std::size_t, 5> mixed{0, 1U << 26, 0, 1U << 30, 1ULL << 31};
        const auto separate = gates::wide_adjoint_group_layout(mixed);
        CHECK(separate.size() == 3);
        for (const auto &group : separate) CHECK(group.trace_indices.size() == 1);
        const std::array<std::size_t, 3> odd{8, 8, 8};
        const auto unpadded = gates::wide_adjoint_group_layout(odd);
        CHECK(unpadded.size() == 2);
        CHECK(unpadded[0].message_size + unpadded[1].message_size == 24);
        bool rejected = false;
        try { (void)gates::wide_adjoint_group_layout(std::array<std::size_t, 1>{3}); }
        catch (const std::invalid_argument &) { rejected = true; }
        CHECK(rejected);
    });

    runner.run("nine adjoints share three proofs and reject group substitution", [] {
        const auto fixture = prove_wide_fixture();
        std::vector<QueryBatch> batches;
        for (std::size_t i = 0; i < 9; ++i) {
            auto batch = fixture.queries;
            batch.affine_output = point(batch.affine_output.size(), 101 + 1009 * i);
            batches.push_back(std::move(batch));
        }
        Transcript prover_transcript("Laminate/GroupedWide/Test/v1");
        gates::observe_gate_table_key(fixture.key.verifier, prover_transcript);
        gates::GateClaimProver prover(fixture.circuit, fixture.key.verifier.layout, prover_transcript);
        for (const auto &batch : batches) (void)record_batch(prover, batch);
        const auto proof = prover.finish(fixture.key);
        CHECK(proof.wide->traces.size() == 9);
        CHECK(proof.wide->adjoint_groups.size() == 3);
        CHECK(proof.wide->adjoint_groups[0].opening.sumcheck.operand_evaluations.size() == 8);
        CHECK(proof.wide->adjoint_groups[1].opening.sumcheck.operand_evaluations.size() == 8);
        CHECK(proof.wide->adjoint_groups[2].opening.sumcheck.operand_evaluations.size() == 2);
        CHECK(!proof.wide->public_opening.final_codeword.empty());
        const auto verify = [&](const gates::OutsourcedGateMleProof &candidate) {
            Transcript transcript("Laminate/GroupedWide/Test/v1");
            gates::observe_gate_table_key(fixture.key.verifier, transcript);
            gates::GateClaimVerifier verifier(fixture.key.verifier, candidate, transcript);
            for (const auto &batch : batches) (void)replay_batch(verifier, batch);
            return verifier.finish();
        };
        CHECK(verify(proof));
        auto bad = proof;
        std::swap(bad.wide->adjoint_groups[0], bad.wide->adjoint_groups[1]);
        CHECK(!verify(bad));
        bad = proof;
        bad.wide->adjoint_groups.pop_back();
        CHECK(!verify(bad));
        bad = proof;
        std::swap(bad.wide->traces[0], bad.wide->traces[1]);
        CHECK(!verify(bad));
        bad = proof;
        bad.wide->adjoint_groups[1].opening.sumcheck.operand_evaluations[0] += Fpk::one();
        CHECK(!verify(bad));
        bad = proof;
        bad.wide->traces[4].has_adjoint = false;
        CHECK(!verify(bad));
    });

    runner.run("boundary-only and grouped adjoint traces share one public check", [] {
        const auto fixture = prove_wide_fixture();
        std::vector<QueryBatch> batches;
        bool boundary_only = false, has_adjoint = false;
        for (const auto &layer : fixture.key.verifier.layout.wide_layers) {
            const auto &d = layer.dimensions;
            batches.push_back({layer.layer_index, gates::GateTableSet::Wide,
                variables(d.output_width), point(variables(d.output_width * d.slots), 809),
                point(variables(d.input_width * d.slots), 1201)});
            boundary_only |= layer.node_count == 0;
            has_adjoint |= layer.node_count != 0;
        }
        CHECK(boundary_only && has_adjoint);
        Transcript transcript("Laminate/MixedWide/Test/v1");
        gates::observe_gate_table_key(fixture.key.verifier, transcript);
        gates::GateClaimProver prover(fixture.circuit, fixture.key.verifier.layout, transcript);
        for (const auto &batch : batches) (void)record_batch(prover, batch);
        const auto proof = prover.finish(fixture.key);
        Transcript check("Laminate/MixedWide/Test/v1");
        gates::observe_gate_table_key(fixture.key.verifier, check);
        gates::GateClaimVerifier verifier(fixture.key.verifier, proof, check);
        for (const auto &batch : batches) (void)replay_batch(verifier, batch);
        CHECK(verifier.finish());
        const auto cap = bench::estimate_wide_gate_proof_size(
            fixture.circuit, fixture.key.verifier.foldable_parameters);
        CHECK(gates::encode_canonical(proof).size() <= cap.canonical_bytes_upper_bound);
    });

    runner.run("zero affine program has canonical empty public opening", [] {
        payload::LayeredCircuit circuit;
        circuit.shape = payload::PayloadShape::wide(8);
        circuit.payload_input_count = 1;
        circuit.payload_output_count = 1;
        payload::AffineLayer affine;
        affine.dimensions = {1, 1, 1, 0};
        affine.gates = {{{}, Fp::zero(), payload::GateOrigin::Payload}};
        circuit.layers = {affine, payload::InputLayer{{1, 1, 1, 0}}};
        circuit.validate();
        auto key = gates::preprocess_gate_tables(circuit, gates::GateTableSet::Wide);
        CHECK(key.tables.empty());
        CHECK(!key.wide_public_commitment);
        QueryBatch batch{0, gates::GateTableSet::Wide, 0, point(3, 7), point(3, 13)};
        Transcript transcript("Laminate/EmptyWide/Test/v1");
        gates::observe_gate_table_key(key.verifier, transcript);
        gates::GateClaimProver prover(circuit, key.verifier.layout, transcript);
        const auto values = record_batch(prover, batch);
        for (const auto &claim : values) CHECK(claim.is_zero());
        const auto proof = prover.finish(key);
        CHECK(proof.wide->tables.empty());
        CHECK(proof.wide->public_column_targets.empty());
        CHECK(proof.wide->public_opening.final_codeword.empty());
        const auto verify = [&](const gates::OutsourcedGateMleProof &candidate) {
            Transcript check("Laminate/EmptyWide/Test/v1");
            gates::observe_gate_table_key(key.verifier, check);
            gates::GateClaimVerifier verifier(key.verifier, candidate, check);
            (void)replay_batch(verifier, batch);
            return verifier.finish();
        };
        CHECK(verify(proof));
        auto bad = proof;
        bad.wide->public_opening.final_codeword.push_back(Fpk::zero());
        CHECK(!verify(bad));
        bool rejected = false;
        try { (void)gates::encode_canonical(bad); }
        catch (const std::invalid_argument &) { rejected = true; }
        CHECK(rejected);
        bad = proof;
        bad.wide->public_column_targets.push_back({Fpk::zero()});
        CHECK(!verify(bad));
        rejected = false;
        try { (void)gates::encode_canonical(bad); }
        catch (const std::invalid_argument &) { rejected = true; }
        CHECK(rejected);
    });

    return runner.summary();
}
