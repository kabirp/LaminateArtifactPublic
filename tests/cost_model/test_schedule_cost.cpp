/// @file test_schedule_cost.cpp
/// @brief Executable Folded/Laned schedule-formula tests.

#include "test_helpers.hpp"

#include "laminate/bench/schedule_cost.hpp"
#include "laminate/bench/payload_profile.hpp"
#include "laminate/bench/target_cost.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/field/serialization.hpp"
#include "laminate/gkr/detail/base/reference/prover.hpp"
#include "laminate/gkr/detail/folded/reference/prover.hpp"
#include "laminate/gkr/detail/laned/prover.hpp"
#include "laminate/gkr/detail/laned/reference/prover.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"
#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/laned.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"
#include "laminate/payload/fixtures/workloads.hpp"
#include "laminate/setup.hpp"
#include "laminate/spartan/basefold_pcs.hpp"
#include "laminate/spartan/spartan.hpp"

#include <algorithm>
#include <bit>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::bench;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;

namespace {

// Synthetic prices exercise the accounting independently of any benchmark.
constexpr TargetRuntimeCalibration kTestCalibration{
    .ntt_ready_plain_ms = 1,
    .online_plain_preparation_ms = 2,
    .ciphertext_product_ms = 3,
    .additive_ms = 4,
    .key_switch_ms = 5,
};

struct FormulaFixture {
    Workload workload;
    LayeredCircuit circuit;
    PlainTrace trace;

    explicit FormulaFixture(PayloadShape shape,
                            WorkloadKind kind = WorkloadKind::Diamond,
                            std::size_t depth = 1,
                            std::size_t width = 1,
                            bool terminal_nonuniform = false)
        : workload(make_workload(WorkloadSpec{
              .kind = kind,
              .shape = shape,
              .multiplicative_depth = depth,
              .width = width,
              .seed = 1,
              .terminal_nonuniform_plaintext_multiplication =
                  terminal_nonuniform,
          })),
          circuit(compile(workload.circuit)),
          trace(synthesize_trace(workload.circuit, circuit,
                                 workload.inputs)) {}
};

bool is_fully_live(const LayeredCircuit &circuit) {
    const std::vector<LayerWireSupport> support =
        canonical_trace_wire_support(circuit);
    return std::all_of(
        support.begin(), support.end(), [](const LayerWireSupport &layer) {
            return layer.live_wire_count == layer.padded_wire_count;
        });
}

Fpk dense_claim_coordinate() {
    Fpk::Coefficients coefficients{};
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        coefficients[index] = Fp(19U + index);
    }
    return Fpk(coefficients);
}

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100U; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-schedule-cost-" + std::to_string(stamp) +
                     "-" + std::to_string(attempt));
            if (std::filesystem::create_directory(path_)) {
                return;
            }
        }
        throw std::runtime_error(
            "failed to create schedule-cost temporary directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    std::filesystem::path make_child(const std::string &name) const {
        const std::filesystem::path child = path_ / name;
        if (!std::filesystem::create_directory(child)) {
            throw std::runtime_error(
                "failed to create schedule-cost child directory");
        }
        return child;
    }

  private:
    std::filesystem::path path_;
};

FileTraceStoreOptions file_store_limits() {
    return FileTraceStoreOptions{
        .max_total_bytes = std::uint64_t{1} << 30U,
        .min_free_bytes = 1,
    };
}

OperationCounts measured_base_counts(FormulaFixture &fixture) {
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = fixture.circuit.shape.slot_count,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 1000,
    });
    const PublicSetup public_setup =
        make_direct_setup(fixture.workload.circuit, fixture.circuit);
    const auto encrypted = encrypt_compact_synthetic_trace<MockBackend>(
        contexts.eval, contexts.client, fixture.workload.circuit,
        fixture.circuit, fixture.trace,
        TraceEncryptionPlan::uniform(fixture.circuit, 10));
    const SingleClaim claim = make_layer_claim(
        fixture.trace.layers.front(),
        std::vector<Fpk>(base_detail::layer_vars(fixture.circuit, 0),
                         dense_claim_coordinate()));
    const auto evaluation = make_packed_evaluation_setup<MockBackend>(
        public_setup, contexts.eval);
    MockBackend::reset_counts(contexts.eval);
    Transcript transcript("test/schedule/base/v1");
    (void)base_detail::prove_resident_synthetic_reference<MockBackend>(
        fixture.workload.circuit, fixture.circuit, encrypted,
        evaluation, claim.point, transcript);
    return MockBackend::counts(contexts.eval);
}

void add_concrete(ConcretePrimitiveUpperBound &destination,
                  const ConcretePrimitiveUpperBound &source) {
#define LAMINATE_TEST_ADD(field) destination.field += source.field
    LAMINATE_TEST_ADD(plain_multiplications);
    LAMINATE_TEST_ADD(online_vector_plain_multiplications);
    LAMINATE_TEST_ADD(online_vector_plaintext_preparations);
    LAMINATE_TEST_ADD(ciphertext_multiplications_no_relinearization);
    LAMINATE_TEST_ADD(relinearizations);
    LAMINATE_TEST_ADD(negations);
    LAMINATE_TEST_ADD(additions);
    LAMINATE_TEST_ADD(subtractions);
    LAMINATE_TEST_ADD(rotations);
#undef LAMINATE_TEST_ADD
}

OperationCounts measured_folded_counts(FormulaFixture &fixture) {
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = fixture.circuit.shape.slot_count,
        .fresh_rns_limbs = 10,
        .bits_per_limb = 60,
    });
    const PublicSetup public_setup =
        make_direct_setup(fixture.workload.circuit, fixture.circuit);
    const auto encrypted = encrypt_compact_synthetic_trace<MockBackend>(
        contexts.eval, contexts.client, fixture.workload.circuit,
        fixture.circuit, fixture.trace,
        TraceEncryptionPlan::uniform(fixture.circuit, 7));
    const std::size_t variables =
        (std::bit_width(layer_dimensions(fixture.circuit.layers.front())
                            .padded_size) -
         1U) +
        (std::bit_width(fixture.circuit.shape.slot_count) - 1U);
    const SingleClaim claim = make_layer_claim(
        fixture.trace.layers.front(),
        std::vector<Fpk>(variables, dense_claim_coordinate()));
    const auto evaluation = make_packed_evaluation_setup<MockBackend>(
        public_setup, contexts.eval);
    MockBackend::reset_counts(contexts.eval);
    Transcript transcript("test/schedule/folded/v1");
    (void)folded_detail::prove_folded_gkr_resident<MockBackend>(
        fixture.workload.circuit, fixture.circuit, encrypted,
        evaluation, claim.point, transcript,
        std::vector<std::size_t>(fixture.circuit.layers.size(), 8));
    return MockBackend::counts(contexts.eval);
}

OperationCounts measured_laned_counts(FormulaFixture &fixture) {
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = fixture.circuit.shape.slot_count,
        .fresh_rns_limbs = 12,
        .bits_per_limb = 60,
    });
    const PublicSetup public_setup =
        make_direct_setup(fixture.workload.circuit, fixture.circuit);
    const auto encrypted = encrypt_compact_synthetic_trace<MockBackend>(
        contexts.eval, contexts.client, fixture.workload.circuit,
        fixture.circuit, fixture.trace,
        TraceEncryptionPlan::uniform(fixture.circuit, 9));
    const SingleClaim claim = make_packed_laned_claim(
        fixture.trace.layers.front(), laned_layout(fixture.circuit, 0),
        std::vector<Fpk>(laned_layer_variables(fixture.circuit, 0),
                         dense_claim_coordinate()));
    const auto evaluation = make_packed_evaluation_setup<MockBackend>(
        public_setup, contexts.eval);
    std::vector<std::size_t> ingress_rns_limbs;
    ingress_rns_limbs.reserve(encrypted.layers.size());
    for (const auto &layer : encrypted.layers) {
        CHECK(layer.wires.front().is_encrypted());
        ingress_rns_limbs.push_back(
            MockBackend::rns_limb_count(contexts.eval,
                                        layer.wires.front().ciphertext()));
    }
    TemporaryDirectory temporary;
    const std::filesystem::path trace_directory =
        temporary.make_child("trace");
    (void)write_file_encrypted_trace(
        contexts.eval, trace_directory, file_store_limits(),
        fixture.circuit, encrypted);
    const auto trace = FileEncryptedTraceStore<MockBackend>::open(
        contexts.eval, trace_directory, fixture.workload.circuit,
        fixture.circuit, encrypted.provenance, encrypted.trace_id);
    laned_detail::FileLanedGkrOptions options;
    for (std::size_t layer = 0;
         layer + 1U < fixture.circuit.layers.size(); ++layer) {
        if (layer_kind(fixture.circuit.layers[layer]) !=
            LayerKind::Multiplication) {
            continue;
        }
        options.multiplication_scratch.push_back(
            laned_detail::FileLanedMultiplicationScratch{
                layer,
                temporary.make_child("multiplication-" +
                                     std::to_string(layer)),
                file_store_limits(),
            });
    }

    MockBackend::reset_counts(contexts.eval);
    Transcript transcript("test/schedule/laned/v1");
    (void)laned_detail::prove_laned_gkr<MockBackend>(
        fixture.workload.circuit, fixture.circuit, trace, evaluation,
        ingress_rns_limbs, claim.point, transcript, std::move(options));
    return MockBackend::counts(contexts.eval);
}

void check_measured_within_formula(
    const OperationCounts &measured, const ScheduleFormula &formula,
    std::size_t slot_count) {
    const ConcretePrimitiveUpperBound concrete =
        concrete_primitive_upper_bound(formula.operations, slot_count);
    // MockBackend's logical extension-add counter includes both general
    // extension accumulations and the coefficientwise accumulation of
    // weighted base terms. The public formula intentionally separates them.
    CHECK(measured.logical_ext_add <=
          formula.operations.extension_additions +
              formula.operations.weighted_base_accumulations);
    CHECK(measured.logical_ext_sub <=
          formula.operations.extension_subtractions);
    CHECK(measured.logical_ext_mul <=
          formula.operations.extension_ciphertext_multiplications);
    const std::uint64_t emitted_plain_products =
        measured.logical_ext_mul_plain +
        measured.prepared_extension_promotion_api_calls;
    CHECK(emitted_plain_products <=
          formula.operations.extension_plain_multiplications +
              formula.operations
                  .prepared_base_slot_extension_multiplications);
    // Dense extension products are conservative: a test transcript can make
    // a coefficient zero, allowing the backend to omit its base product and
    // the associated reduction arithmetic.
    CHECK(measured.mul_plain_scalar + measured.mul_plain_vector <=
          concrete.plain_multiplications);
    CHECK(measured.mul_no_relin <=
          concrete.ciphertext_multiplications_no_relinearization);
    CHECK(measured.relinearize <= concrete.relinearizations);
    CHECK(measured.negate <= concrete.negations);
    CHECK(measured.add <= concrete.additions);
    // The formula expands every logical extension coordinate. Runtime
    // rotation skips coordinates that are known public zeros, so the dense
    // expansion is an upper bound even though the logical schedule is exact.
    CHECK(measured.rotate <= concrete.rotations);
}

std::uint64_t modeled_logical_plain_products(
    const ScheduleOperations &operations) {
    return operations.extension_plain_multiplications +
           operations.prepared_base_slot_extension_multiplications;
}

std::uint64_t emitted_logical_plain_products(
    const OperationCounts &operations) {
    return operations.logical_ext_mul_plain +
           operations.prepared_extension_promotion_api_calls;
}

std::uint64_t emitted_ciphertext_products(
    const ScheduleOperations &operations,
    std::uint64_t emitted_extension_products) {
    return operations.base_ciphertext_multiplications +
           emitted_extension_products * kExtensionDegree *
               kExtensionDegree;
}

} // namespace

int main() {
    laminate::test::Runner runner("schedule cost formulas");

    runner.run("mixed schedules match emitted core operation counts", [] {
        FormulaFixture base(PayloadShape::wide(16),
                            WorkloadKind::Diamond, 2, 4, true);
        const ScheduleFormula base_formula =
            base_schedule_formula(base.circuit);
        const ConcretePrimitiveUpperBound base_concrete =
            concrete_primitive_upper_bound(base_formula.operations, 16);
        const OperationCounts base_measured = measured_base_counts(base);
        CHECK(base_formula.operations.extension_ciphertext_multiplications >
              0);
        CHECK(base_formula.operations
                  .prepared_base_slot_extension_multiplications == 0);
        CHECK(base_measured.logical_ext_mul ==
              base_formula.operations.extension_ciphertext_multiplications);
        // A deterministic transcript can make a challenge-derived suffix
        // weight zero. The circuit-only formula deliberately keeps that
        // product as a conservative upper bound.
        CHECK(emitted_logical_plain_products(base_measured) <=
              modeled_logical_plain_products(base_formula.operations));
        CHECK(base_measured.logical_ext_sub ==
              base_formula.operations.extension_subtractions);
        CHECK(base_measured.mul_no_relin ==
              emitted_ciphertext_products(
                  base_formula.operations,
                  base_measured.logical_ext_mul));
        CHECK(base_measured.relinearize == base_concrete.relinearizations);
        CHECK(base_measured.rotate == base_concrete.rotations);

        FormulaFixture folded(PayloadShape::wide(16),
                              WorkloadKind::Diamond, 2, 4, true);
        const ScheduleFormula folded_formula =
            folded_schedule_formula(folded.circuit);
        const ConcretePrimitiveUpperBound folded_concrete =
            concrete_primitive_upper_bound(folded_formula.operations, 16);
        const OperationCounts folded_measured =
            measured_folded_counts(folded);
        // The circuit-only formula retains challenge-derived plaintext
        // products whose scalar happens to be zero in this deterministic
        // transcript. Ciphertext products and relinearizations remain exact.
        CHECK(folded_measured.logical_ext_mul ==
              folded_formula.operations
                  .extension_ciphertext_multiplications);
        CHECK(emitted_logical_plain_products(folded_measured) <=
              modeled_logical_plain_products(folded_formula.operations));
        CHECK(folded_measured.logical_ext_sub ==
              folded_formula.operations.extension_subtractions);
        CHECK(folded_measured.mul_no_relin ==
              emitted_ciphertext_products(
                  folded_formula.operations,
                  folded_measured.logical_ext_mul));
        CHECK(folded_measured.relinearize ==
              folded_concrete.relinearizations);
        CHECK(folded_measured.rotate <= folded_concrete.rotations);

        FormulaFixture laned(PayloadShape::laned(4, 16),
                             WorkloadKind::Diamond, 2, 4);
        const ScheduleFormula laned_formula =
            laned_schedule_formula(laned.circuit);
        const ConcretePrimitiveUpperBound laned_concrete =
            concrete_primitive_upper_bound(laned_formula.operations, 16);
        const OperationCounts laned_measured = measured_laned_counts(laned);
        CHECK(laned_measured.logical_ext_add ==
              laned_formula.operations.extension_additions +
                  laned_formula.operations.weighted_base_accumulations);
        CHECK(laned_measured.logical_ext_sub ==
              laned_formula.operations.extension_subtractions);
        CHECK(laned_measured.logical_ext_mul ==
              laned_formula.operations.extension_ciphertext_multiplications);
        CHECK(emitted_logical_plain_products(laned_measured) ==
              modeled_logical_plain_products(laned_formula.operations));
        CHECK(laned_measured.mul_no_relin != 0);
        CHECK(laned_measured.mul_no_relin <
              emitted_ciphertext_products(
                  laned_formula.operations,
                  laned_measured.logical_ext_mul));
        CHECK(laned_measured.relinearize <=
              laned_concrete.relinearizations);
        CHECK(laned_measured.rotate < laned_concrete.rotations);
    });

    runner.run("Base sparse formula selects the streamed schedule", [] {
        FormulaFixture fixture(PayloadShape::wide(16),
                               WorkloadKind::Diamond, 1, 4);
        const ScheduleFormula formula = base_schedule_formula(fixture.circuit);
        CHECK(formula.protocol == ScheduleProtocol::Base);
        CHECK(formula.layers.size() == 3);
        CHECK(formula.operations.logical_rounds == 6);
        CHECK(formula.operations.terminal_messages == 3);
        CHECK(formula.operations.extension_ciphertext_multiplications != 0);
        CHECK(formula.operations.extension_folds == 0);
        CHECK(formula.operations.extension_rotations == 0);
    });

    runner.run("Base first multiplication rounds stay in the base field", [] {
        const Workload workload = make_workload(WorkloadSpec{
            .kind = WorkloadKind::Diamond,
            .shape = PayloadShape::wide(1U << 14U),
            .multiplicative_depth = 7,
            .width = 7,
            .seed = 1,
        });
        const LayeredCircuit circuit = compile(workload.circuit);
        const ScheduleFormula formula = base_schedule_formula(circuit);
        const ConcretePrimitiveUpperBound concrete =
            concrete_primitive_upper_bound(formula.operations,
                                           circuit.shape.slot_count);
        // Each of the seven layers performs eight first-round products in the
        // base field. Its two later ciphertext-index rounds require six
        // grouped extension products in total.
        CHECK(formula.operations.base_ciphertext_multiplications == 56);
        CHECK(formula.operations.extension_ciphertext_multiplications == 42);
        CHECK(concrete.ciphertext_multiplications_no_relinearization == 2744);
    });

    runner.run("Folded formula counts multiplication slot rounds", [] {
        FormulaFixture fixture(PayloadShape::wide(16));
        const ScheduleFormula formula =
            folded_schedule_formula(fixture.circuit);
        CHECK(formula.protocol == ScheduleProtocol::Folded);
        CHECK(formula.layers.size() == 3);
        const ScheduleLayerFormula &multiplication = formula.layers[1];
        CHECK(multiplication.kind == LayerKind::Multiplication);

        const ScheduleOperations &slot_rounds =
            multiplication.multiplication_slot_rounds;
        CHECK(slot_rounds.logical_rounds == 4);
        CHECK(slot_rounds.extension_ciphertext_multiplications == 8);
        CHECK(slot_rounds.extension_plain_multiplications == 14);
        CHECK(slot_rounds.extension_rotations == 20);
        CHECK(slot_rounds.extension_additions == 20);
        CHECK(slot_rounds.extension_subtractions == 8);
        CHECK(slot_rounds.extension_folds == 8);
        CHECK(slot_rounds.round_extension_values == 8);

        const ScheduleOperations &total = formula.operations;
        CHECK(total.weighted_base_terms == 4);
        CHECK(total.weighted_base_accumulations == 0);
        CHECK(total.base_ciphertext_multiplications == 0);
        CHECK(total.base_additions == 0);
        CHECK(total.base_subtractions == 0);
        CHECK(total.extension_plain_multiplications == 40);
        CHECK(total.extension_ciphertext_multiplications == 8);
        CHECK(total.extension_additions == 56);
        CHECK(total.extension_subtractions == 16);
        CHECK(total.extension_rotations == 56);
        CHECK(total.extension_folds == 24);
        CHECK(total.extension_relinearizations == 8);
        CHECK(total.round_extension_values == 28);
        CHECK(total.aligned_round_ciphertexts == 15);
        CHECK(total.logical_rounds == 12);
        CHECK(total.terminal_messages == 3);
        const ConcretePrimitiveUpperBound concrete =
            concrete_primitive_upper_bound(total, 16);
        CHECK(concrete.plain_multiplications == 2816);
        CHECK(concrete.ciphertext_multiplications_no_relinearization ==
              512);
        CHECK(concrete.relinearizations == 64);
        CHECK(concrete.negations == 672);
        CHECK(concrete.additions == 4449);
        CHECK(concrete.subtractions == 0);
        CHECK(concrete.rotations == 1216);
        check_measured_within_formula(measured_folded_counts(fixture),
                                      formula, 16);
    });

    runner.run("Laned formula counts multiplication slot rounds", [] {
        FormulaFixture fixture(PayloadShape::laned(4, 16));
        const ScheduleFormula formula =
            laned_schedule_formula(fixture.circuit);
        CHECK(formula.protocol == ScheduleProtocol::Laned);
        CHECK(formula.layers.size() == 3);
        const ScheduleLayerFormula &multiplication = formula.layers[1];
        CHECK(multiplication.kind == LayerKind::Multiplication);
        const LayerWireSupport source_support =
            canonical_layer_wire_support(fixture.circuit, 2);
        CHECK(source_support.live_ranges.size() == 2);
        CHECK(source_support.live_ranges.front().padded_end() <
              source_support.live_ranges.back().padded_begin);
        CHECK(source_support.live_wire_count <
              source_support.padded_wire_count);
        CHECK(multiplication.source_stored_values ==
              source_support.live_wire_count);
        CHECK(multiplication.source_virtual_wire_positions ==
              source_support.padded_wire_count);
        CHECK(multiplication.source_materialized_packed_ciphertexts == 2);
        CHECK(multiplication.source_virtual_packed_positions == 2);
        CHECK(multiplication.operations.witness_base_plain_multiplications ==
              source_support.live_wire_count);

        const ScheduleOperations &slot_rounds =
            multiplication.multiplication_slot_rounds;
        CHECK(slot_rounds.logical_rounds == 4);
        CHECK(slot_rounds.extension_ciphertext_multiplications == 8);
        CHECK(slot_rounds.extension_plain_multiplications == 14);
        CHECK(slot_rounds.extension_rotations == 20);
        CHECK(slot_rounds.extension_additions == 20);
        CHECK(slot_rounds.extension_subtractions == 8);
        CHECK(slot_rounds.extension_folds == 8);
        CHECK(slot_rounds.round_extension_values == 8);

        const ScheduleOperations &total = formula.operations;
        CHECK(total.weighted_base_terms == 4);
        CHECK(total.weighted_base_accumulations == 0);
        CHECK(total.base_ciphertext_multiplications == 0);
        CHECK(total.extension_plain_multiplications == 40);
        CHECK(total.extension_ciphertext_multiplications == 8);
        CHECK(total.extension_additions == 48);
        CHECK(total.extension_subtractions == 16);
        CHECK(total.extension_rotations == 48);
        CHECK(total.extension_folds == 26);
        CHECK(total.extension_relinearizations == 8);
        CHECK(total.witness_base_plain_multiplications == 4);
        CHECK(total.witness_base_additions == 0);
        CHECK(total.round_extension_values == 28);
        CHECK(total.aligned_round_ciphertexts == 15);
        CHECK(total.logical_rounds == 12);
        CHECK(total.terminal_messages == 3);

        const ConcretePrimitiveUpperBound concrete =
            concrete_primitive_upper_bound(total, 16);
        CHECK(concrete.plain_multiplications == 2820);
        CHECK(concrete.ciphertext_multiplications_no_relinearization ==
              512);
        CHECK(concrete.relinearizations == 64);
        CHECK(concrete.negations == 672);
        CHECK(concrete.additions == 4449);
        CHECK(concrete.subtractions == 0);
        CHECK(concrete.rotations == 1216);
        CHECK(!is_fully_live(fixture.circuit));
        FormulaFixture measured(PayloadShape::laned(4, 16),
                                WorkloadKind::Diamond, 1, 4);
        CHECK(is_fully_live(measured.circuit));
        check_measured_within_formula(
            measured_laned_counts(measured),
            laned_schedule_formula(measured.circuit), 16);
    });

    runner.run("Laned affine checkpoints and base-first products scale", [] {
        FormulaFixture fixture(PayloadShape::laned(16, 16),
                               WorkloadKind::Diamond, 1, 4);
        const ScheduleFormula formula =
            laned_schedule_formula(fixture.circuit);
        CHECK(formula.operations.weighted_base_terms == 56);
        CHECK(formula.operations.weighted_base_accumulations == 38);
        CHECK(formula.operations.base_ciphertext_multiplications == 4);
        CHECK(formula.operations.base_additions == 4);
        CHECK(formula.operations.base_subtractions == 4);
        CHECK(formula.operations.extension_plain_multiplications == 46);
        CHECK(formula.operations.extension_ciphertext_multiplications == 10);
        CHECK(formula.layers.front().operations.weighted_base_terms == 16);
        CHECK(formula.layers.front()
                  .operations.extension_plain_multiplications == 12);
        check_measured_within_formula(measured_laned_counts(fixture), formula,
                                      16);
    });

    runner.run("dense multiplication padding is absent from the schedule", [] {
        // Three payload products pad to a four-pair proof domain. The fourth
        // pair is structural public zero and must not be stored or visited.
        FormulaFixture fixture(PayloadShape::wide(16),
                               WorkloadKind::Diamond, 1, 3);
        const auto multiplication = std::find_if(
            fixture.circuit.layers.begin(), fixture.circuit.layers.end(),
            [](const Layer &layer) {
                return layer_kind(layer) == LayerKind::Multiplication;
            });
        CHECK(multiplication != fixture.circuit.layers.end());
        const std::size_t layer = static_cast<std::size_t>(
            multiplication - fixture.circuit.layers.begin());
        const gkr::detail::DenseMultiplicationAliasPlan aliases =
            gkr::detail::make_dense_multiplication_alias_plan(
                fixture.circuit, layer);
        CHECK(aliases.pair_count == 4);
        CHECK(aliases.live_pair_count == 3);

        const ScheduleFormula base =
            base_schedule_formula(fixture.circuit);
        const ScheduleFormula folded =
            folded_schedule_formula(fixture.circuit);
        CHECK(!is_fully_live(fixture.circuit));
    });

    runner.run("RNS ledger separates core, alignment, and bottom packing", [] {
        FormulaFixture fixture(PayloadShape::wide(32));
        const ScheduleFormula formula =
            folded_schedule_formula(fixture.circuit);
        const ProverOperationLedger ledger =
            packed_operation_ledger(formula, 32, 6);
        CHECK(ledger.core_rns_limbs == 6);
        CHECK(ledger.aligned_ciphertexts ==
              formula.operations.aligned_round_ciphertexts);
        CHECK(ledger.paper_raw_ciphertext_footprint ==
              fhe::kFixedMessageCellCount * ledger.aligned_ciphertexts);
        CHECK(ledger.direct_transcript_ciphertexts == 0);
        CHECK(ledger.logical_packed_outputs > 0);
        CHECK(ledger.levels.size() == 6);
        for (const RnsLevelOperations &row : ledger.levels) {
            if (row.rns_limbs >= 2) {
                CHECK(row.modulus_switches ==
                      ledger.aligned_ciphertexts);
            } else {
                CHECK(row.modulus_switches == 0);
                CHECK(row.primitives.plain_multiplications ==
                      4 * ledger.aligned_ciphertexts);
                CHECK(row.primitives.negations ==
                      kPackingWellFormednessRepetitions);
            }
        }
        const TargetRuntimeEstimate runtime =
            estimate_target_runtime(ledger, kTestCalibration);
        CHECK(runtime.all_plain_ntt_ready_hours > 0);
        CHECK(runtime.preprocessing_aware_hours >=
              runtime.all_plain_ntt_ready_hours);
        CHECK(runtime.all_plain_ntt_ready_with_modswitch_proxy_hours >
              runtime.all_plain_ntt_ready_hours);

        const PackedProverRuntimeBreakdown breakdown =
            packed_prover_runtime_breakdown(ledger, kTestCalibration);
        CHECK(breakdown.gkr_and_alignment_hours > 0);
        CHECK(breakdown.transcript_packing_fhe_seconds > 0);
        const double recomposed_hours =
            breakdown.gkr_and_alignment_hours +
            breakdown.transcript_packing_fhe_seconds / 3'600.0;
        CHECK(std::abs(recomposed_hours -
                       runtime.preprocessing_aware_hours) < 1e-12);
    });

    runner.run("Base formula ledger labels a uniform proof ingress", [] {
        FormulaFixture fixture(PayloadShape::wide(32));
        const ScheduleFormula formula =
            base_schedule_formula(fixture.circuit);
        const ProverOperationLedger ledger =
            base_operation_ledger(formula, 32, 3);

        CHECK(!ledger.base_proof_ingress_normalization_modeled);
        CHECK(ledger.base_proof_ingress_switch_events == 0);
        CHECK(ledger.base_reductions.size() == formula.layers.size());
        CHECK(ledger.levels.front().rns_limbs == 3);
        CHECK(ledger.levels.front().primitives ==
              concrete_primitive_upper_bound(formula.operations, 32));
        std::uint64_t proof_switches = 0;
        std::size_t proof_ciphertexts = 0;
        for (const BaseReductionRnsOperations &reduction :
             ledger.base_reductions) {
            CHECK(reduction.natural_source_rns_limbs == 0);
            CHECK(reduction.proof_ingress_rns_limbs == 3);
            CHECK(reduction.ingress_switch_events == 0);
            proof_switches += reduction.proof_message_switch_events;
            proof_ciphertexts += reduction.proof_message_ciphertexts;
        }
        CHECK(proof_switches == ledger.base_proof_message_switch_events);
        CHECK(proof_ciphertexts == ledger.direct_transcript_ciphertexts);
        CHECK(ledger.direct_transcript_extension_messages *
                  kExtensionDegree ==
              ledger.direct_transcript_ciphertexts);
        CHECK(ledger.direct_transcript_public_zero_extension_messages == 0);
        CHECK(proof_switches == 2 * proof_ciphertexts);
        for (const RnsLevelOperations &row : ledger.levels) {
            CHECK(row.base_proof_ingress_switches == 0);
            CHECK(row.base_proof_message_switches ==
                  (row.rns_limbs > 1 ? proof_ciphertexts : 0));
        }
    });

    runner.run("Base schedule ledger normalizes each source once", [] {
        FormulaFixture fixture(PayloadShape::wide(32),
                               WorkloadKind::Diamond, 2, 2);
        const ScheduleFormula formula =
            base_schedule_formula(fixture.circuit);
        FheEvaluationPlan evaluation =
            FheEvaluationPlan::without_payload_switches(fixture.circuit, 4);
        for (std::size_t layer = 1; layer < fixture.circuit.layers.size();
             ++layer) {
            evaluation.proof_ingress_mult_depth_by_layer[layer] =
                1U + layer % 2U;
        }
        const HonestBaseProofNormalizationPlan plan =
            derive_honest_base_proof_normalization_plan(
                fixture.circuit, evaluation);

        const ProverOperationLedger ledger =
            base_operation_ledger(formula, 32, plan);
        CHECK(ledger.base_proof_ingress_normalization_modeled);
        CHECK(ledger.base_proof_ingress_switch_events ==
              plan.ingress_switch_events);
        CHECK(ledger.base_proof_message_switch_events ==
              plan.proof_message_switch_events);
        CHECK(ledger.base_reductions.size() == plan.reductions.size());

        for (std::size_t index = 0; index < formula.layers.size(); ++index) {
            const auto &placed = ledger.base_reductions[index];
            const auto &approved = plan.reductions[index];
            CHECK(placed.natural_source_rns_limbs ==
                  approved.natural_source_rns_limb_count);
            CHECK(placed.proof_ingress_rns_limbs ==
                  approved.proof_ingress_rns_limb_count);
            CHECK(placed.ingress_switch_events ==
                  approved.ingress_switch_events);
            CHECK(placed.proof_message_switch_events ==
                  approved.proof_message_switch_events);
        }

        std::uint64_t per_level_ingress_switches = 0;
        std::uint64_t per_level_proof_switches = 0;
        ConcretePrimitiveUpperBound expected_at_two;
        ConcretePrimitiveUpperBound expected_at_three;
        for (std::size_t index = 0; index < formula.layers.size(); ++index) {
            ConcretePrimitiveUpperBound &expected =
                plan.reductions[index].proof_ingress_rns_limb_count == 2
                    ? expected_at_two
                    : expected_at_three;
            add_concrete(expected, concrete_primitive_upper_bound(
                                       formula.layers[index].operations, 32));
        }
        for (const RnsLevelOperations &row : ledger.levels) {
            CHECK(row.modulus_switches ==
                  row.base_proof_ingress_switches +
                      row.base_proof_message_switches);
            per_level_ingress_switches +=
                row.base_proof_ingress_switches;
            per_level_proof_switches +=
                row.base_proof_message_switches;
            const ConcretePrimitiveUpperBound expected =
                row.rns_limbs == 2
                    ? expected_at_two
                    : row.rns_limbs == 3
                          ? expected_at_three
                          : ConcretePrimitiveUpperBound{};
            CHECK(row.primitives == expected);
        }
        CHECK(per_level_ingress_switches == plan.ingress_switch_events);
        CHECK(per_level_proof_switches ==
              plan.proof_message_switch_events);

        // The source normalization count is independent of how many scans a
        // reduction performs: one copy per live source and dropped limb.
        for (const auto &reduction : plan.reductions) {
            CHECK(reduction.ingress_switch_events ==
                  reduction.live_source_ciphertext_count *
                      (reduction.natural_source_rns_limb_count -
                       reduction.proof_ingress_rns_limb_count));
        }
    });

    runner.run("Base source accounting distinguishes public stored values",
               [] {
        PayloadBuilder builder(PayloadShape::wide(16), 2);
        const std::size_t zero = builder.add_scalar_plaintext(Fp::zero());
        const WireId killed = builder.mul_plain(0, zero);
        const WireId output = builder.mul(killed, 1);
        builder.set_outputs({output});
        const PayloadCircuit payload = builder.finish();
        const LayeredCircuit circuit = compile(payload);

        const std::vector<LayerTraceValueCounts> counts =
            canonical_trace_value_counts(circuit);
        CHECK(counts.size() == 4);
        CHECK(counts[3].logical_live_wires == 2);
        CHECK(counts[3].stored_values == 2);
        CHECK(counts[3].encrypted_ciphertexts == 2);
        CHECK(counts[2].stored_values == 2);
        CHECK(counts[2].encrypted_ciphertexts == 1);
        // The ordinary multiplication is public zero, not an encrypted
        // dependency: FheValue short-circuits zero * ciphertext.
        CHECK(counts[1].stored_values == 1);
        CHECK(counts[1].encrypted_ciphertexts == 0);
        CHECK(counts[0].stored_values == 1);
        CHECK(counts[0].encrypted_ciphertexts == 0);

        const ScheduleFormula formula = base_schedule_formula(circuit);
        for (const ScheduleLayerFormula &layer : formula.layers) {
            const LayerTraceValueCounts &source = counts[layer.layer + 1U];
            CHECK(layer.source_logical_live_wires ==
                  source.logical_live_wires);
            CHECK(layer.source_stored_values == source.stored_values);
            CHECK(layer.source_encrypted_ciphertexts ==
                  source.encrypted_ciphertexts);
        }

        FheEvaluationPlan evaluation =
            FheEvaluationPlan::without_payload_switches(circuit, 4);
        for (std::size_t layer = 1; layer < circuit.layers.size(); ++layer) {
            evaluation.proof_ingress_mult_depth_by_layer[layer] = 1;
        }
        const HonestBaseProofNormalizationPlan normalization =
            derive_honest_base_proof_normalization_plan(circuit,
                                                        evaluation);
        const ProverOperationLedger ledger =
            base_operation_ledger(formula, 16, normalization);
        CHECK(ledger.base_reductions.size() == formula.layers.size());
        for (std::size_t index = 0; index < formula.layers.size(); ++index) {
            CHECK(ledger.base_reductions[index].live_source_ciphertexts ==
                  counts[index + 1U].encrypted_ciphertexts);
        }
    });

    runner.run("online plaintext preparation is counted once per vector", [] {
        ScheduleOperations logical;
        logical.weighted_base_terms = 1;
        logical.online_vector_weighted_base_terms = 1;
        logical.extension_plain_multiplications = 1;
        logical.online_vector_extension_plain_multiplications = 1;
        const ConcretePrimitiveUpperBound concrete =
            concrete_primitive_upper_bound(logical, 16);
        CHECK(concrete.plain_multiplications == 8 + 64);
        CHECK(concrete.online_vector_plain_multiplications == 8 + 64);
        CHECK(concrete.online_vector_plaintext_preparations == 8 + 8);

        ProverOperationLedger ledger;
        ledger.levels.push_back(RnsLevelOperations{
            .rns_limbs = 2,
            .primitives = ConcretePrimitiveUpperBound{
                .plain_multiplications = 10,
                .online_vector_plain_multiplications = 8,
                .online_vector_plaintext_preparations = 3,
            },
        });
        const TargetRuntimeEstimate runtime =
            estimate_target_runtime(ledger, kTestCalibration);
        constexpr double milliseconds_per_hour = 3'600'000.0;
        const double expected_ready = 2.0 * 10.0 * kTestCalibration.ntt_ready_plain_ms /
                                      milliseconds_per_hour;
        const double expected_online_delta = 2.0 * 3.0 * kTestCalibration.online_plain_preparation_ms /
                                             milliseconds_per_hour;
        CHECK(std::abs(runtime.all_plain_ntt_ready_hours - expected_ready) <
              1e-15);
        CHECK(std::abs(runtime.preprocessing_aware_hours - expected_ready -
                       expected_online_delta) < 1e-15);
    });

    runner.run("Laned ledger charges witness packing before its level drop", [] {
        FormulaFixture partial(PayloadShape::laned(4, 32));
        const ScheduleFormula partial_formula =
            laned_schedule_formula(partial.circuit);
        const ProverOperationLedger partial_ledger =
            packed_operation_ledger(partial_formula, 32, 6);
        const auto at = [&](std::size_t limbs) -> const RnsLevelOperations & {
            const auto found = std::find_if(
                partial_ledger.levels.begin(), partial_ledger.levels.end(),
                [&](const auto &row) { return row.rns_limbs == limbs; });
            CHECK(found != partial_ledger.levels.end());
            return *found;
        };
        CHECK(at(6).primitives.plain_multiplications > 0);
        CHECK(at(5).primitives.ciphertext_multiplications_no_relinearization >
              0);
        CHECK(at(6).modulus_switches > 0);

        FormulaFixture full(PayloadShape::laned(32, 32));
        const ScheduleFormula full_formula =
            laned_schedule_formula(full.circuit);
        const ProverOperationLedger full_ledger =
            packed_operation_ledger(full_formula, 32, 6);
        const auto five = std::find_if(
            full_ledger.levels.begin(), full_ledger.levels.end(),
            [](const auto &row) { return row.rns_limbs == 5; });
        CHECK(five != full_ledger.levels.end());
        CHECK(five->primitives == ConcretePrimitiveUpperBound{});
    });

    runner.run("both Folded target proof caps stay below 70 decimal MB", [] {
        for (const auto name : {"target-mulHeavyPyramid", "target-balancedLaned"}) {
            const auto profile = benchmark_payload_profile(name);
            const auto spec = benchmark_payload_workload_spec(profile,
                PayloadShape::wide(kDefaultPolyModulusDegree), 1);
            const auto circuit = compile(make_payload_circuit(spec));
            const auto ledger = packed_operation_ledger(
                folded_schedule_formula(circuit), circuit.shape.slot_count, 6);
            const auto core = estimate_packed_proof_size(circuit, ledger);
            const auto packing = estimate_spartan_packing(circuit, ledger);
            const auto gates = estimate_wide_gate_proof_size(circuit);
            CHECK(core.public_message_overhead_bytes ==
                  ledger.aligned_ciphertexts * (274 - 1 - PoseidonDigest{}.size()));
            const auto layout = gates::make_gate_table_layout(
                circuit, gates::GateTableSet::Wide);
            const auto public_shape = gates::plan_wide_public_commitment(layout);
            CHECK(gates.public_message_size == public_shape.m);
            CHECK(public_shape.width > 1);
            CHECK(public_shape.width <= 256);
            CHECK(std::all_of(layout.wide_layers.begin(), layout.wide_layers.end(),
                [](const auto &layer) { return layer.node_count == 0; }));
            CHECK(gates.adjoint_groups == 0);
            CHECK(gates.public_operands > 0);
            CHECK(gates.canonical_bytes_upper_bound ==
                  gates.outer_bytes + gates.pcs_bytes_upper_bound);
            static_assert(PoseidonDigest{}.size() == 6 * sizeof(std::uint64_t));
            const auto complete_cap =
                core.canonical_bytes_excluding_packing_argument +
                packing.proof_max_bytes + gates.canonical_bytes_upper_bound +
                8; // Outsourced opening length.
            std::cout << "[INFO] " << name << " public rows=" << public_shape.m
                      << " width=" << public_shape.width << " operands="
                      << gates.public_operands << " gate outer bytes=" << gates.outer_bytes
                      << " complete proof cap=" << complete_cap << '\n';
            CHECK(complete_cap < 70'000'000);
            CHECK(estimate_wide_gate_proof_size(circuit, {.num_queries = 350})
                .canonical_bytes_upper_bound > gates.canonical_bytes_upper_bound);
        }
    });

    runner.run("wire-size formulas expose the selected proof boundary", [] {
        FormulaFixture base_fixture(PayloadShape::wide(32));
        const ScheduleFormula base_formula =
            base_schedule_formula(base_fixture.circuit);
        const ProverOperationLedger base_ledger =
            base_operation_ledger(base_formula, 32, 3);
        const ProofSizeEstimate base_size =
            estimate_base_proof_size(base_fixture.circuit, base_formula);
        CHECK(base_size.one_prime_ciphertexts ==
              base_ledger.direct_transcript_ciphertexts);
        CHECK(base_ledger.paper_raw_ciphertext_footprint == 0);
        CHECK(base_ledger.aligned_ciphertexts == 0);
        CHECK(base_ledger.logical_packed_outputs == 0);
        CHECK(base_size.partial_gate_mle_bytes ==
              2 * (8 + 32 * kSerializedFpkBytes));

        const ScheduleFormula folded_formula =
            folded_schedule_formula(base_fixture.circuit);
        const ProverOperationLedger folded_ledger =
            packed_operation_ledger(folded_formula, 32, 6);
        const ProofSizeEstimate folded_size =
            estimate_packed_proof_size(base_fixture.circuit, folded_ledger);
        CHECK(folded_size.one_prime_ciphertexts ==
              kPackingWellFormednessRepetitions +
                  4 * folded_ledger.logical_packed_outputs);
        // The depth-one Diamond has two affine layers. Each receives one
        // selector-interpolated claim and opens its constant and gate MLE.
        CHECK(std::count_if(base_fixture.circuit.layers.begin(),
                            base_fixture.circuit.layers.end(),
                            [](const auto &layer) {
                                return layer_kind(layer) == LayerKind::Affine;
                            }) == 2);
        CHECK(estimate_verifier_crypto(base_fixture.circuit, base_ledger)
                  .direct_gate_mle_queries == 4);
        CHECK(estimate_verifier_crypto(base_fixture.circuit, base_ledger)
                  .base_partial_gate_mle_vectors == 2);
        CHECK(estimate_verifier_crypto(base_fixture.circuit, folded_ledger)
                  .direct_gate_mle_queries == 4);
        const SpartanPackingEstimate folded_spartan =
            estimate_spartan_packing(base_fixture.circuit, folded_ledger);
        CHECK(folded_spartan.r1cs_constraints > 0);
        CHECK(folded_spartan.r1cs_matrix_rows >=
              folded_spartan.r1cs_constraints);
        CHECK(folded_spartan.r1cs_logical_inputs ==
              folded_spartan.r1cs_public_inputs);
        CHECK(folded_spartan.r1cs_public_inputs >
              kPoseidonDigestElements);
        CHECK(std::has_single_bit(folded_spartan.padded_constraints));
        CHECK(folded_spartan.padded_constraints >=
              folded_spartan.r1cs_matrix_rows);
        CHECK(std::has_single_bit(folded_spartan.assignment_half_size));
        CHECK(folded_spartan.assignment_half_size >=
              folded_spartan.r1cs_witness_variables);
        CHECK(folded_spartan.r1cs_nonzero_entries_upper_bound >=
              folded_spartan.r1cs_constraints);
        CHECK(folded_spartan.factored_output_live_owners.size() ==
              folded_ledger.logical_packed_outputs);
        CHECK(folded_spartan.factored_output_padded_owners.size() ==
              folded_ledger.logical_packed_outputs);
        std::uint64_t live_owners = 0;
        for (std::size_t output = 0;
             output < folded_spartan.factored_output_live_owners.size();
             ++output) {
            const std::uint64_t live =
                folded_spartan.factored_output_live_owners[output];
            const std::uint64_t padded =
                folded_spartan.factored_output_padded_owners[output];
            live_owners += live;
            CHECK(live > 0);
            CHECK(std::has_single_bit(padded));
            CHECK(padded >= live);
        }
        CHECK(live_owners == folded_ledger.aligned_ciphertexts);
        CHECK(folded_spartan.factored_tensor_live_elements ==
              live_owners * base_fixture.circuit.shape.slot_count *
                  folded_ledger.signed_digits_per_output);
        CHECK(folded_spartan.factored_tensor_padded_elements >=
              folded_spartan.factored_tensor_live_elements);
        CHECK(folded_spartan.factored_tensor_live_bytes ==
              folded_spartan.factored_tensor_live_elements * sizeof(Fq));
        CHECK(folded_spartan.factored_tensor_padded_bytes ==
              folded_spartan.factored_tensor_padded_elements * sizeof(Fq));
        CHECK(folded_spartan.factored_retained_raw_tensor_bytes ==
              folded_spartan.factored_tensor_padded_bytes);
        CHECK(folded_spartan.factored_retained_basefold_message_bytes ==
              folded_spartan.factored_tensor_padded_bytes);
        CHECK(folded_spartan.factored_retained_basefold_codeword_bytes ==
              (std::uint64_t{1}
               << kTranscriptPackingBaseFoldLogRate) *
                  folded_spartan.factored_tensor_padded_bytes);
        CHECK(folded_spartan.factored_retained_basefold_merkle_bytes > 0);
        CHECK(folded_spartan.factored_retained_preprocessing_bytes_model ==
              folded_spartan.factored_retained_raw_tensor_bytes +
                  folded_spartan
                      .factored_retained_basefold_message_bytes +
                  folded_spartan
                      .factored_retained_basefold_codeword_bytes +
                  folded_spartan.factored_retained_basefold_merkle_bytes);
        CHECK(folded_spartan.factored_opening_peak_bytes_model ==
              folded_spartan
                      .factored_retained_preprocessing_bytes_model +
                  (2 + (std::uint64_t{1}
                        << kTranscriptPackingBaseFoldLogRate)) *
                      folded_spartan
                          .factored_largest_tensor_evaluations *
                      sizeof(Fq2));
        CHECK(folded_spartan.regular_poseidon_segments > 0);
        CHECK(folded_spartan.regular_poseidon_ciphertext_segment_visits ==
              folded_ledger.aligned_ciphertexts *
                  folded_spartan.regular_poseidon_segments);
        CHECK(folded_spartan.regular_poseidon_rate_interval_evaluations ==
              kPoseidonRate *
                  folded_spartan
                      .regular_poseidon_ciphertext_segment_visits);
        CHECK(folded_spartan.regular_poseidon_boundary_segment_visits ==
              (folded_ledger.aligned_ciphertexts - 1) *
                  folded_spartan.regular_poseidon_segments);
        CHECK(folded_spartan.regular_poseidon_digest_terms ==
              kPoseidonDigestElements *
                  folded_ledger.aligned_ciphertexts);
        CHECK(folded_spartan.regular_challenge_bit_visits > 0);
        CHECK(folded_spartan.regular_test_ciphertext_pair_visits ==
              3 * folded_ledger.well_formedness_repetitions *
                  folded_ledger.aligned_ciphertexts);
        CHECK(folded_spartan.regular_owner_affine_segment_visits > 0);
        CHECK(folded_spartan.regular_public_affine_range_evaluations ==
              folded_ledger.well_formedness_repetitions +
                  folded_ledger.logical_packed_outputs *
                      folded_ledger.signed_digits_per_output);
        CHECK(folded_spartan.regular_high_equality_table_elements > 0);
        CHECK(folded_spartan.factored_sumcheck_rounds > 0);
        CHECK(folded_spartan.factored_digit_weight_terms ==
              folded_ledger.logical_packed_outputs *
                  folded_ledger.signed_digits_per_output);
        CHECK(folded_spartan.factored_terminal_owner_terms ==
              folded_ledger.aligned_ciphertexts);
        CHECK(folded_spartan.factored_terminal_affine_segment_visits ==
              folded_spartan.regular_owner_affine_segment_visits);
        CHECK(folded_spartan.factored_basefold_openings ==
              folded_ledger.logical_packed_outputs);
        CHECK(folded_spartan.factored_basefold_queries ==
              kTranscriptPackingBaseFoldQueries *
                  folded_ledger.logical_packed_outputs);
        CHECK(folded_spartan.factored_basefold_query_fold_steps ==
              kTranscriptPackingBaseFoldQueries *
                  folded_spartan.factored_sumcheck_rounds);
        CHECK(folded_spartan.factored_basefold_merkle_hashes > 0);
        CHECK(folded_spartan.core_proof_max_bytes > 0);
        CHECK(folded_spartan.factored_proof_max_bytes > 0);
        CHECK(folded_spartan.proof_max_bytes ==
              folded_spartan.core_proof_max_bytes +
                  folded_spartan.factored_proof_max_bytes);
        CHECK(folded_spartan.proof_max_bytes > 0);
        const std::uint64_t h = folded_spartan.assignment_half_size;
        const std::uint64_t m = folded_spartan.padded_constraints;
        const std::uint64_t basefold_rate =
            std::uint64_t{1} << kTranscriptPackingBaseFoldLogRate;
        const std::uint64_t retained_witness_pcs =
            (37 * basefold_rate + 32) * h / 4 - 40;
        const std::uint64_t assignment_and_witness_pcs =
            retained_witness_pcs + 16 * h;
        const std::uint64_t assignment_commitment =
            assignment_and_witness_pcs +
            std::min<std::uint64_t>(basefold_rate * h, 64) * sizeof(Fq);
        const std::uint64_t constraint_peak =
            assignment_and_witness_pcs + 34 * m;
        const std::uint64_t wiring_peak =
            assignment_and_witness_pcs + 40 * h;
        const std::uint64_t witness_opening_peak =
            retained_witness_pcs +
            std::max<std::uint64_t>(2 + basefold_rate,
                                    2 * basefold_rate) *
                h * sizeof(Fq2);
        CHECK(folded_spartan.core_retained_witness_pcs_bytes_model ==
              retained_witness_pcs);
        CHECK(folded_spartan
                  .core_assignment_commitment_peak_bytes_model ==
              assignment_commitment);
        CHECK(folded_spartan.core_constraint_peak_memory_bytes_model ==
              constraint_peak);
        CHECK(folded_spartan.core_wiring_peak_memory_bytes_model ==
              wiring_peak);
        CHECK(folded_spartan
                  .core_witness_opening_peak_memory_bytes_model ==
              witness_opening_peak);
        CHECK(folded_spartan.core_peak_memory_bytes_model ==
              std::max({assignment_commitment, constraint_peak,
                        wiring_peak, witness_opening_peak}));

        const std::size_t row_variables =
            std::bit_width(folded_spartan.padded_constraints) - 1U;
        const std::size_t assignment_variables =
            std::bit_width(folded_spartan.assignment_half_size) - 1U;
        spartan::Proof proof_shape;
        proof_shape.constraint_sumcheck.rounds.resize(row_variables);
        proof_shape.wiring_sumcheck.rounds.resize(
            assignment_variables + 1U);
        proof_shape.witness_opening.bytes.resize(
            spartan::basefold_opening_proof_max_size_bytes(
                assignment_variables, 1U,
                {.log_rate = kTranscriptPackingBaseFoldLogRate,
                 .query_count = kTranscriptPackingBaseFoldQueries}));
        CHECK(spartan::proof_size_bytes(proof_shape) ==
              folded_spartan.core_proof_max_bytes);
        spartan::FactoredMatrixEvaluationProof factored_shape;
        factored_shape.tensors.resize(
            folded_spartan.factored_output_padded_owners.size());
        for (std::size_t output = 0;
             output < factored_shape.tensors.size(); ++output) {
            const std::uint64_t evaluations =
                folded_spartan.factored_output_padded_owners[output] *
                base_fixture.circuit.shape.slot_count;
            const std::size_t tensor_variables =
                std::bit_width(evaluations) - 1U;
            factored_shape.tensors[output].rounds.resize(tensor_variables);
            factored_shape.tensors[output].opening.bytes.resize(
                spartan::basefold_opening_proof_max_size_bytes(
                    tensor_variables,
                    folded_ledger.signed_digits_per_output,
                    {.log_rate = kTranscriptPackingBaseFoldLogRate,
                     .query_count =
                         kTranscriptPackingBaseFoldQueries}));
        }
        proof_shape.factored_evaluation = std::move(factored_shape);
        CHECK(spartan::proof_size_bytes(proof_shape) ==
              folded_spartan.proof_max_bytes);

        FormulaFixture laned_fixture(PayloadShape::laned(4, 32));
        const ScheduleFormula laned_formula =
            laned_schedule_formula(laned_fixture.circuit);
        const ProverOperationLedger laned_ledger =
            packed_operation_ledger(laned_formula, 32, 6);
        CHECK(estimate_verifier_crypto(laned_fixture.circuit, laned_ledger)
                  .direct_gate_mle_queries == 4);
        CHECK(one_prime_seal_ciphertext_bytes(1024) == 16'497);
        CHECK(one_prime_seal_ciphertext_bytes(16'384) == 262'257);
    });

    runner.run("Base large Diamond reference topology is circuit exact", [] {
        const Workload workload = make_workload(WorkloadSpec{
            .kind = WorkloadKind::Diamond,
            .shape = PayloadShape::wide(1U << 14U),
            .multiplicative_depth = 8,
            .width = 61'681,
            .seed = 1,
        });
        const LayeredCircuit circuit = compile(workload.circuit);
        const ScheduleFormula formula = base_schedule_formula(circuit);
        const ProverOperationLedger dense =
            base_operation_ledger(formula, 1U << 14U, 3);
        const ProverOperationLedger exact =
            base_operation_ledger(circuit, formula, 1U << 14U, 3);

        CHECK(formula.operations.logical_rounds == 262);
        CHECK(formula.operations.terminal_messages == 17);
        CHECK(exact.direct_transcript_extension_messages == 549);
        CHECK(exact.direct_transcript_public_zero_extension_messages == 0);
        CHECK(exact.direct_transcript_ciphertexts == 4'392);
        CHECK(dense.direct_transcript_ciphertexts == 4'392);
        CHECK(exact.base_proof_message_switch_events == 2U * 4'392U);

        std::size_t multiplication_layers = 0;
        std::uint64_t base_multiplication_rounds = 0;
        for (std::size_t layer = 0; layer + 1U < circuit.layers.size();
             ++layer) {
            if (layer_kind(circuit.layers[layer]) !=
                LayerKind::Multiplication) {
                continue;
            }
            base_multiplication_rounds +=
                formula.layers[layer].operations.logical_rounds;
            if (++multiplication_layers == 8U) {
                // Original AddPlain nodes remain distinct in the local DAG.
                // Only the 64 direct-input operands share output records.
                CHECK(formula.layers[layer].source_stored_values == 61'745U);
                CHECK(formula.layers[layer]
                          .source_virtual_wire_positions == 131'072U);
                CHECK(formula.layers[layer]
                          .source_materialized_packed_ciphertexts == 61'745U);
                CHECK(formula.layers[layer]
                          .source_reused_packed_ciphertexts == 64U);
            } else {
                CHECK(formula.layers[layer].source_stored_values ==
                      123'362U);
                CHECK(formula.layers[layer]
                          .source_virtual_wire_positions == 131'072U);
                CHECK(formula.layers[layer]
                          .source_materialized_packed_ciphertexts ==
                      123'362U);
                CHECK(formula.layers[layer]
                          .source_reused_packed_ciphertexts == 0U);
            }
        }
        CHECK(multiplication_layers == 8U);
        CHECK(base_multiplication_rounds == 128U);

        const ScheduleFormula folded_formula =
            folded_schedule_formula(circuit);
        std::uint64_t folded_multiplication_rounds = 0;
        for (const ScheduleLayerFormula &layer : folded_formula.layers) {
            if (layer.kind == LayerKind::Multiplication) {
                folded_multiplication_rounds +=
                    layer.operations.logical_rounds;
            }
        }
        CHECK(folded_multiplication_rounds == 240U);
        CHECK(folded_formula.operations.logical_rounds == 500U);
        CHECK(folded_formula.operations.terminal_messages == 17U);
        CHECK(folded_formula.operations.aligned_round_ciphertexts == 517U);

        const ProverOperationLedger folded_ledger =
            packed_operation_ledger(folded_formula, 1U << 14U, 6);
        const ProofSizeEstimate folded_size =
            estimate_packed_proof_size(circuit, folded_ledger);
        CHECK(folded_size.one_prime_ciphertexts == 124U);
        CHECK(folded_size.fhe_message_bytes == 32'520'984ULL);
        CHECK(folded_size.gkr_commitment_bytes == 24'816ULL);
        CHECK(folded_size.public_message_overhead_bytes == 116'325ULL);
        CHECK(folded_size.statement_and_metadata_bytes == 117'233ULL);
        CHECK(folded_size.canonical_bytes_excluding_packing_argument ==
              32'663'033ULL);

        const ProofSizeEstimate exact_size =
            estimate_base_proof_size(circuit, formula, exact);
        CHECK(exact_size.one_prime_ciphertexts == 4'392);
        CHECK(exact_size.fhe_message_bytes == 1'151'879'958ULL);
        CHECK(exact_size.partial_gate_mle_bytes == 3'539'016ULL);
        CHECK(exact_size.statement_and_metadata_bytes == 333);
        CHECK(exact_size.canonical_bytes_excluding_packing_argument ==
              1'155'419'307ULL);
        CHECK(exact_size.persistent_base.has_value());
        const PersistentBaseProofSizeEstimate &persistent =
            exact_size.persistent_base.value();
        CHECK(persistent.fhe_message_bytes == 1'151'872'821ULL);
        CHECK(persistent.partial_gate_mle_bytes == 3'539'016ULL);
        CHECK(persistent.statement_and_metadata_bytes == 370);
        CHECK(persistent.inner_transport_bytes == 1'155'412'207ULL);
        CHECK(persistent.response_envelope_header_bytes == 43);
        CHECK(persistent.response_public_bindings_bytes == 128);
        CHECK(persistent.response_output_dimensions_bytes == 32);
        CHECK(persistent.response_output_fhe_values_bytes == 262'306);
        CHECK(persistent.response_output_statement_bytes == 262'338);
        CHECK(persistent.response_proof_length_prefix_bytes == 8);
        CHECK(persistent.response_envelope_bytes == 262'517);
        CHECK(persistent.response_envelope_bytes ==
              persistent.response_envelope_header_bytes +
                  persistent.response_public_bindings_bytes +
                  persistent.response_output_statement_bytes +
                  persistent.response_proof_length_prefix_bytes);
        CHECK(persistent.response_bytes == 1'155'674'724ULL);
        CHECK(persistent.response_bytes ==
              persistent.response_envelope_bytes +
                  persistent.inner_transport_bytes);
        const VerifierCryptoLedger verifier =
            estimate_verifier_crypto(circuit, exact);
        CHECK(verifier.one_prime_decryptions == 4'392);
        CHECK(verifier.recovered_gkr_messages == 549);
    });

    runner.run("Base PT-CT execution uses an affine relation", [] {
        PayloadBuilder builder(PayloadShape::wide(32), 1);
        SlotVector diagonal_values;
        diagonal_values.reserve(32);
        for (std::size_t slot = 0; slot < 32; ++slot) {
            diagonal_values.emplace_back(slot + 7);
        }
        const std::size_t diagonal =
            builder.add_plaintext(std::move(diagonal_values));
        builder.set_outputs({builder.mul_plain(0, diagonal)});
        const PayloadCircuit payload = builder.finish();
        const LayeredCircuit circuit = compile(payload);
        const ScheduleFormula formula = base_schedule_formula(circuit);
        const ProverOperationLedger ledger =
            base_operation_ledger(formula, 32, 3);
        const VerifierCryptoLedger verifier =
            estimate_verifier_crypto(circuit, ledger);

        std::uint64_t expected_vectors = 0;
        CHECK(circuit.proof_multiplication_depth == 0);
        for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
            CHECK(layer_kind(circuit.layers[layer]) == LayerKind::Affine);
            ++expected_vectors;
        }
        CHECK(verifier.base_partial_gate_mle_vectors == expected_vectors);
        CHECK(verifier.direct_gate_mle_queries < 32);
    });

    runner.run("comparison statuses are explicit", [] {
        CHECK(compare_measured_to_upper_bound(8, 8) ==
              FormulaComparisonStatus::Match);
        CHECK(compare_measured_to_upper_bound(7, 8) ==
              FormulaComparisonStatus::ExpectedDelta);
        CHECK(compare_measured_to_upper_bound(9, 8) ==
              FormulaComparisonStatus::Investigate);

    });

    runner.run("bounds cover varied small schedules", [] {
        for (const WorkloadKind kind :
             {WorkloadKind::Diamond, WorkloadKind::DeepSnake,
              WorkloadKind::FanoutHeavy, WorkloadKind::RotationHeavy}) {
            FormulaFixture folded(PayloadShape::wide(16), kind, 2, 2);
            const ScheduleFormula formula =
                folded_schedule_formula(folded.circuit);
            if (is_fully_live(folded.circuit)) {
                check_measured_within_formula(
                    measured_folded_counts(folded), formula, 16);
            } else {
                CHECK(formula.operations.logical_rounds > 0);
            }
        }
        for (const std::size_t lanes : {std::size_t{1}, std::size_t{4},
                                        std::size_t{16}}) {
            FormulaFixture laned(PayloadShape::laned(lanes, 16),
                                 WorkloadKind::FanoutHeavy, 2, 2);
            const ScheduleFormula formula =
                laned_schedule_formula(laned.circuit);
            CHECK(!is_fully_live(laned.circuit));
            CHECK(formula.operations.logical_rounds > 0);

            const std::size_t full_live_width = 16 / lanes;
            FormulaFixture measured(PayloadShape::laned(lanes, 16),
                                    WorkloadKind::Diamond, 2,
                                    full_live_width);
            CHECK(is_fully_live(measured.circuit));
            check_measured_within_formula(
                measured_laned_counts(measured),
                laned_schedule_formula(measured.circuit), 16);
        }
    });

    return runner.summary();
}
