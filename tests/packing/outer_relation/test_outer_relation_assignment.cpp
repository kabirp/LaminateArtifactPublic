/// @file test_outer_relation_assignment.cpp
/// @brief Lazy outer-assignment equivalence and range tests.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/packing/outer_relation/assignment.hpp"
#include "laminate/packing/outer_relation/r1cs.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace laminate;
using namespace laminate::packing;

namespace {

constexpr std::uint64_t kPrime = 257;

class TemporaryDirectory {
  public:
    explicit TemporaryDirectory(std::string_view label) {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-outer-assignment-" + std::string(label) +
                     "-" + std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(path_)) {
                return;
            }
        }
        throw std::runtime_error("failed to create temporary directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

OuterRelationAssignmentArtifactOptions artifact_options(
    const std::filesystem::path &directory,
    std::uint64_t max_total_bytes = 1ULL << 20U,
    std::uint64_t max_working_field_bytes = 64,
    std::size_t block_elements = 7) {
    return {
        .directory = directory,
        .storage_limits = {
            .max_total_bytes = max_total_bytes,
            .min_free_bytes = 1,
        },
        .max_working_field_bytes = max_working_field_bytes,
        .block_elements = block_elements,
    };
}

NativePackingContribution contribution(std::size_t aligned,
                                       std::uint64_t seed) {
    return NativePackingContribution{
        .aligned_ciphertext = aligned,
        .multiplier_ntt_coordinates = {
            seed, seed + 1, seed + 2, seed + 3},
    };
}

NativePackingOperator packing_operator() {
    return NativePackingOperator{
        .native_modulus = kPrime,
        .ring_degree = 4,
        .aligned_ciphertexts = 3,
        .logical_outputs = 2,
        .digit_count = 2,
        .rows = {
            NativePackingRow{0, 0,
                             {contribution(0, 1), contribution(1, 11)}},
            NativePackingRow{0, 1,
                             {contribution(0, 21), contribution(1, 31)}},
            NativePackingRow{1, 0, {contribution(2, 41)}},
            NativePackingRow{1, 1, {contribution(2, 51)}},
        },
    };
}

LazyTernaryChallengeMatrix challenges() {
    return {
        {{false, false}, {true, true}, {true, false}},
        {{false, true}, {true, false}, {true, true}},
    };
}

struct Fixture {
    NativePackingOperator packing = packing_operator();
    OuterRelationPlan plan = make_outer_relation_plan(packing, 2, 2, 8);
    OuterRelationWitnessInputs witness_inputs;
    OuterRelationPublicInputs public_inputs;
    OuterRelationAuxiliaryWitness auxiliary;
    OuterRelationR1csAssignment owning;

    Fixture() {
        witness_inputs.aligned_ciphertext_coordinates.resize(24);
        for (std::size_t index = 0;
             index < witness_inputs.aligned_ciphertext_coordinates.size();
             ++index) {
            witness_inputs.aligned_ciphertext_coordinates[index] = index + 1;
        }
        public_inputs.packed_challenge_words =
            pack_outer_relation_challenge_bits(plan, challenges());
        const OuterRelationExpectedOutputs outputs =
            compute_outer_relation_expected_outputs(
                plan, public_inputs.packed_challenge_words,
                witness_inputs, packing);
        public_inputs.revealed_test_coordinates =
            outputs.revealed_test_coordinates;
        public_inputs.revealed_packing_coordinates =
            outputs.revealed_packing_coordinates;
        auxiliary = build_outer_relation_auxiliary_witness(
            plan, public_inputs.packed_challenge_words, witness_inputs);
        owning = make_outer_relation_r1cs_assignment(
            plan, public_inputs, witness_inputs, auxiliary);
    }

    OuterRelationR1csAssignmentView view() const {
        return OuterRelationR1csAssignmentView(
            plan, public_inputs, witness_inputs);
    }
};

void append_slices(
    std::vector<OuterRelationCiphertextCoordinateSlice> &destination,
    std::span<const std::uint64_t> coordinates,
    std::size_t ciphertext_count, std::size_t width) {
    for (std::size_t ciphertext = 0; ciphertext < ciphertext_count;
         ++ciphertext) {
        destination.push_back(
            OuterRelationCiphertextCoordinateSlice::borrowed(
                coordinates.subspan(ciphertext * width, width)));
    }
}

OuterRelationR1csInputSlices sliced_inputs(const Fixture &fixture) {
    OuterRelationR1csInputSlices result;
    result.packed_challenge_words =
        fixture.public_inputs.packed_challenge_words;
    const std::size_t width = fixture.plan.coordinates_per_ciphertext();
    append_slices(
        result.revealed_test_ciphertexts,
        fixture.public_inputs.revealed_test_coordinates,
        fixture.plan.shape.repetitions, width);
    append_slices(
        result.revealed_packing_ciphertexts,
        fixture.public_inputs.revealed_packing_coordinates,
        fixture.plan.physical_packed_ciphertexts(), width);
    append_slices(
        result.aligned_ciphertexts,
        fixture.witness_inputs.aligned_ciphertext_coordinates,
        fixture.plan.shape.aligned_ciphertexts, width);
    return result;
}

template <typename Exception, typename Action>
bool rejects_as(Action action) {
    try {
        action();
    } catch (const Exception &) {
        return true;
    }
    return false;
}

} // namespace

int main() {
    test::Runner runner("test_outer_relation_assignment");

    runner.run("lazy random access equals the owning assignment", [] {
        const Fixture fixture;
        const OuterRelationR1csAssignmentView view = fixture.view();
        for (std::uint64_t index = 0;
             index < fixture.plan.variables.public_inputs.total; ++index) {
            CHECK(view.public_value(index) ==
                  fixture.owning.public_inputs[index]);
        }
        for (std::uint64_t index = 0;
             index < fixture.plan.variables.witness.total; ++index) {
            CHECK(view.witness_value(index) == fixture.owning.witness[index]);
        }
        CHECK(rejects_as<std::out_of_range>([&] {
            (void)view.public_value(
                fixture.plan.variables.public_inputs.total);
        }));
        CHECK(rejects_as<std::out_of_range>([&] {
            (void)view.witness_value(
                fixture.plan.variables.witness.total);
        }));
    });

    runner.run("lazy assignment streams to a bounded native-field artifact",
               [] {
        const Fixture fixture;
        const OuterRelationR1csAssignmentView view = fixture.view();
        TemporaryDirectory directory("parity");
        const OuterRelationAssignmentArtifact written =
            write_outer_relation_assignment_artifact(
                view, artifact_options(directory.path()));
        CHECK(written.artifact != nullptr);
        CHECK(written.artifact->identity() ==
              outer_relation_assignment_artifact_identity(fixture.plan));
        CHECK(written.report.public_input_elements ==
              fixture.owning.public_inputs.size());
        CHECK(written.report.witness_elements ==
              fixture.owning.witness.size());
        CHECK(written.report.derived_product_elements ==
              fixture.plan.variables.witness
                  .well_formedness_products.count);
        CHECK(written.report.public_payload_bytes ==
              fixture.owning.public_inputs.size() * sizeof(Fq));
        CHECK(written.report.witness_payload_bytes ==
              fixture.owning.witness.size() * sizeof(Fq));
        CHECK(written.report.physical_bytes ==
              written.artifact->physical_bytes());
        CHECK(written.report.artifact_validation_bytes ==
              written.report.physical_bytes);
        CHECK(written.report.sequential_write_payload_bytes ==
              written.report.public_payload_bytes +
                  written.report.witness_payload_bytes);
        CHECK(written.report.peak_working_field_bytes == 7 * sizeof(Fq));

        auto public_reader =
            written.artifact->open_array("public-inputs");
        std::vector<Fq> public_values(fixture.owning.public_inputs.size());
        CHECK(public_reader.read(public_values) == public_values.size());
        for (std::size_t index = 0; index < public_values.size(); ++index) {
            CHECK(public_values[index] ==
                  Fq(fixture.owning.public_inputs[index]));
        }

        auto witness_reader = written.artifact->open_array("witness");
        std::vector<Fq> witness_values(fixture.owning.witness.size());
        CHECK(witness_reader.read(witness_values) == witness_values.size());
        for (std::size_t index = 0; index < witness_values.size(); ++index) {
            CHECK(witness_values[index] == Fq(fixture.owning.witness[index]));
        }

        const auto reopened = open_outer_relation_assignment_artifact(
            directory.path(), fixture.plan);
        CHECK(reopened->arrays() == written.artifact->arrays());
        CHECK(reopened->physical_bytes() == written.report.physical_bytes);
    });

    runner.run("assignment artifact limits fail before publication", [] {
        const Fixture fixture;
        const OuterRelationR1csAssignmentView view = fixture.view();
        std::uint64_t exact_bytes = 0;
        {
            TemporaryDirectory baseline("baseline");
            exact_bytes = write_outer_relation_assignment_artifact(
                              view, artifact_options(baseline.path()))
                              .report.physical_bytes;
        }

        {
            TemporaryDirectory directory("quota");
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)write_outer_relation_assignment_artifact(
                    view, artifact_options(directory.path(),
                                           exact_bytes - 1));
            }));
            CHECK(std::filesystem::is_empty(directory.path()));
        }
        {
            TemporaryDirectory directory("memory");
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)write_outer_relation_assignment_artifact(
                    view, artifact_options(directory.path(), 1ULL << 20U,
                                           sizeof(Fq) - 1));
            }));
            CHECK(std::filesystem::is_empty(directory.path()));
        }
        {
            TemporaryDirectory directory("occupied");
            const std::filesystem::path marker = directory.path() / "keep";
            std::ofstream output(marker);
            output << "keep";
            output.close();
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)write_outer_relation_assignment_artifact(
                    view, artifact_options(directory.path()));
            }));
            CHECK(std::filesystem::exists(marker));
        }
        {
            TemporaryDirectory directory("late-failure");
            OuterRelationPlan oversized_modulus = fixture.plan;
            oversized_modulus.shape.native_modulus =
                std::numeric_limits<std::uint64_t>::max();
            OuterRelationWitnessInputs malformed = fixture.witness_inputs;
            malformed.aligned_ciphertext_coordinates.front() = Fq::modulus();
            const OuterRelationR1csAssignmentView malformed_view(
                oversized_modulus, fixture.public_inputs, malformed);
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)write_outer_relation_assignment_artifact(
                    malformed_view, artifact_options(directory.path()));
            }));
            CHECK(std::filesystem::is_empty(directory.path()));
        }
        {
            TemporaryDirectory directory("identity");
            (void)write_outer_relation_assignment_artifact(
                view, artifact_options(directory.path()));
            OuterRelationShape changed_shape = fixture.plan.shape;
            ++changed_shape.repetitions;
            const OuterRelationPlan changed =
                make_outer_relation_plan(changed_shape);
            CHECK(rejects_as<std::runtime_error>([&] {
                (void)open_outer_relation_assignment_artifact(
                    directory.path(), changed);
            }));
        }
    });

    runner.run("forward cursor crosses product blocks without allocation", [] {
        const Fixture fixture;
        const OuterRelationR1csAssignmentView view = fixture.view();
        OuterRelationWitnessValueCursor full(view);
        while (!full.empty()) {
            const std::uint64_t index = full.position();
            const OuterRelationWitnessValue value = full.next();
            CHECK(value.index == index);
            CHECK(value.value == fixture.owning.witness[index]);
        }
        CHECK(rejects_as<std::out_of_range>([&] {
            (void)full.next();
        }));

        const OuterRelationRange products =
            fixture.plan.variables.witness.well_formedness_products;
        OuterRelationWitnessValueCursor ranged(
            view, products.begin + 7, products.begin + 19);
        while (!ranged.empty()) {
            const OuterRelationWitnessValue value = ranged.next();
            CHECK(value.family ==
                  OuterRelationWitnessValueFamily::WellFormednessProduct);
            CHECK(value.value == fixture.owning.witness[value.index]);
        }
        CHECK(rejects_as<std::out_of_range>([&] {
            OuterRelationWitnessValueCursor invalid(
                view, 1, fixture.plan.variables.witness.total + 1);
            (void)invalid;
        }));
    });

    runner.run("public cursor preserves canonical family order", [] {
        const Fixture fixture;
        const OuterRelationR1csAssignmentView view = fixture.view();
        OuterRelationPublicValueCursor cursor(view);
        while (!cursor.empty()) {
            const std::uint64_t index = cursor.position();
            const OuterRelationPublicValue value = cursor.next();
            CHECK(value.index == index);
            CHECK(value.value == fixture.owning.public_inputs[index]);
            if (index < fixture.plan.variables.public_inputs
                            .packed_challenge_words.end()) {
                CHECK(value.family ==
                      OuterRelationPublicValueFamily::PackedChallengeWord);
            } else if (
                index < fixture.plan.variables.public_inputs
                            .revealed_test_coordinates.end()) {
                CHECK(value.family == OuterRelationPublicValueFamily::
                                          RevealedTestCoordinate);
            } else {
                CHECK(value.family == OuterRelationPublicValueFamily::
                                          RevealedPackingCoordinate);
            }
        }
        CHECK(rejects_as<std::out_of_range>([&] {
            (void)cursor.next();
        }));
        CHECK(rejects_as<std::out_of_range>([&] {
            OuterRelationPublicValueCursor invalid(
                view, 2,
                fixture.plan.variables.public_inputs.total + 1);
            (void)invalid;
        }));
    });

    runner.run("segmented inputs equal flat inputs without coordinate copies",
               [] {
        const Fixture fixture;
        const OuterRelationR1csAssignmentView segmented(
            fixture.plan, sliced_inputs(fixture));
        for (std::uint64_t index = 0;
             index < fixture.plan.variables.public_inputs.total; ++index) {
            CHECK(segmented.public_value(index) ==
                  fixture.owning.public_inputs[index]);
        }
        for (std::uint64_t index = 0;
             index < fixture.plan.variables.witness.total; ++index) {
            CHECK(segmented.witness_value(index) ==
                  fixture.owning.witness[index]);
        }

        OuterRelationR1csCursor rows(fixture.plan, fixture.packing);
        while (!rows.empty()) {
            CHECK(evaluate_outer_relation_r1cs_row(
                fixture.plan, rows.next(), segmented));
        }
    });

    runner.run("implicit-zero test slices need no 2N allocation", [] {
        const Fixture fixture;
        OuterRelationR1csInputSlices slices = sliced_inputs(fixture);
        slices.revealed_test_ciphertexts.front() =
            OuterRelationCiphertextCoordinateSlice::implicit_zero();
        const OuterRelationR1csAssignmentView segmented(
            fixture.plan, std::move(slices));

        const OuterRelationRange tests =
            fixture.plan.variables.public_inputs.revealed_test_coordinates;
        const std::size_t width = fixture.plan.coordinates_per_ciphertext();
        for (std::size_t coordinate = 0; coordinate < width; ++coordinate) {
            CHECK(segmented.public_value(tests.begin + coordinate) == 0);
        }
        CHECK(segmented.public_value(tests.begin + width) ==
              fixture.owning.public_inputs[tests.begin + width]);
    });

    runner.run("mixed assignment recognizes implicit aligned zeros", [] {
        const Fixture fixture;
        auto contexts = fhe::MockBackend::create(
            fhe::MockParameters{.slot_count = 4});
        std::vector<MixedPackingValue<fhe::MockBackend>> tests(
            fixture.plan.shape.repetitions);
        std::vector<MixedPackingValue<fhe::MockBackend>> packing(
            fixture.plan.physical_packed_ciphertexts());
        NormalizedAlignedTranscript<fhe::MockBackend> aligned;
        aligned.values.resize(fixture.plan.shape.aligned_ciphertexts);
        aligned.public_coordinates.resize(
            fixture.plan.shape.aligned_ciphertexts);
        aligned.public_sources.resize(
            fixture.plan.shape.aligned_ciphertexts, false);

        std::size_t coordinate_extractions = 0;
        const auto view =
            borrow_outer_relation_r1cs_assignment<fhe::MockBackend>(
                contexts.eval, fixture.plan,
                fixture.public_inputs.packed_challenge_words, tests,
                packing, aligned,
                [&](const fhe::MockBackend::Ciphertext &)
                    -> std::span<const std::uint64_t> {
                    ++coordinate_extractions;
                    return {};
                });
        CHECK(coordinate_extractions == 0);
        const OuterRelationRange coordinates =
            fixture.plan.variables.witness
                .aligned_ciphertext_coordinates;
        for (std::uint64_t index = coordinates.begin;
             index < coordinates.end(); ++index) {
            CHECK(view.witness_value(index) == 0);
        }
    });

    runner.run("every R1CS row accepts the same lazy values", [] {
        const Fixture fixture;
        const OuterRelationR1csAssignmentView view = fixture.view();
        OuterRelationR1csCursor cursor(fixture.plan, fixture.packing);
        while (!cursor.empty()) {
            const OuterRelationR1csRow &row = cursor.next();
            CHECK(evaluate_outer_relation_r1cs_row(
                fixture.plan, row, fixture.owning));
            CHECK(evaluate_outer_relation_r1cs_row(
                fixture.plan, row, view));
        }

        OuterRelationPlan copied_plan = fixture.plan;
        CHECK(rejects_as<std::invalid_argument>([&] {
            const OuterRelationR1csBuilder builder(copied_plan,
                                                   fixture.packing);
            (void)evaluate_outer_relation_r1cs_row(
                copied_plan, builder.row(0), view);
        }));
    });

    runner.run("public mutations remain visible to relation rows", [] {
        const Fixture fixture;
        OuterRelationPublicInputs changed = fixture.public_inputs;
        changed.revealed_test_coordinates.front() ^= 1;
        const OuterRelationR1csAssignmentView wrong_test(
            fixture.plan, changed, fixture.witness_inputs);
        const OuterRelationR1csBuilder builder(
            fixture.plan, fixture.packing);
        CHECK(!evaluate_outer_relation_r1cs_row(
            fixture.plan,
            builder.row(
                fixture.plan.constraints.revealed_test_equalities.begin),
            wrong_test));

        changed = fixture.public_inputs;
        changed.packed_challenge_words.back() |= std::uint64_t{1} << 7U;
        const OuterRelationR1csAssignmentView noncanonical_padding(
            fixture.plan, changed, fixture.witness_inputs);
        CHECK(!evaluate_outer_relation_r1cs_row(
            fixture.plan,
            builder.row(
                fixture.plan.constraints.challenge_word_recomposition.end() -
                1),
            noncanonical_padding));
    });

    runner.run("malformed source shapes and residues fail closed", [] {
        const Fixture fixture;
        OuterRelationPublicInputs malformed_public = fixture.public_inputs;
        malformed_public.revealed_packing_coordinates.pop_back();
        CHECK(rejects_as<std::invalid_argument>([&] {
            OuterRelationR1csAssignmentView view(
                fixture.plan, malformed_public, fixture.witness_inputs);
            (void)view;
        }));

        OuterRelationWitnessInputs malformed_witness = fixture.witness_inputs;
        malformed_witness.aligned_ciphertext_coordinates.front() = kPrime;
        CHECK(rejects_as<std::invalid_argument>([&] {
            OuterRelationR1csAssignmentView view(
                fixture.plan, fixture.public_inputs, malformed_witness);
            (void)view;
        }));

        OuterRelationR1csInputSlices wrong_count = sliced_inputs(fixture);
        wrong_count.aligned_ciphertexts.pop_back();
        CHECK(rejects_as<std::invalid_argument>([&] {
            OuterRelationR1csAssignmentView view(
                fixture.plan, std::move(wrong_count));
            (void)view;
        }));

        OuterRelationR1csInputSlices wrong_width = sliced_inputs(fixture);
        wrong_width.revealed_packing_ciphertexts.front() =
            OuterRelationCiphertextCoordinateSlice::borrowed(
                std::span<const std::uint64_t>(
                    fixture.public_inputs.revealed_packing_coordinates)
                    .first(
                        fixture.plan.coordinates_per_ciphertext() - 1));
        CHECK(rejects_as<std::invalid_argument>([&] {
            OuterRelationR1csAssignmentView view(
                fixture.plan, std::move(wrong_width));
            (void)view;
        }));

        OuterRelationR1csInputSlices missing_witness =
            sliced_inputs(fixture);
        missing_witness.aligned_ciphertexts.front() =
            OuterRelationCiphertextCoordinateSlice::implicit_zero();
        OuterRelationR1csAssignmentView public_zero_aligned(
            fixture.plan, std::move(missing_witness));
        CHECK(public_zero_aligned.witness_value(
                  fixture.plan.variables.witness
                      .aligned_ciphertext_coordinates.begin) == 0);
    });

    runner.run("target storage ledger removes the 2NTf vector", [] {
        const OuterRelationPlan plan = make_outer_relation_plan(
            OuterRelationShape{
                .native_modulus = kOuterFieldOrder,
                .ring_degree = 16'384,
                .aligned_ciphertexts = 517,
                .repetitions = kPackingWellFormednessRepetitions,
                .logical_packed_outputs = 1,
                .packing_digit_count = 4,
                .ciphertext_components = 2,
                .public_input_capacity_bits = 59,
            });
        const OuterRelationR1csAssignmentStorage storage =
            estimate_outer_relation_r1cs_assignment_storage(plan);
        CHECK(storage.public_source_bytes == 32'522'688);
        CHECK(storage.aligned_source_bytes == 135'528'448);
        CHECK(storage.challenge_word_source_bytes == 16'832);
        CHECK(storage.borrowed_ciphertext_coordinate_bytes ==
              168'034'304);
        CHECK(storage.borrowed_slice_descriptor_bytes ==
              641 * sizeof(OuterRelationCiphertextCoordinateSlice));
        CHECK(storage.flattened_coordinate_copy_bytes_avoided ==
              storage.borrowed_ciphertext_coordinate_bytes);
        CHECK(storage.challenge_word_source_bytes +
                  storage.borrowed_ciphertext_coordinate_bytes ==
              storage.public_source_bytes + storage.aligned_source_bytes);
        CHECK(storage.eager_product_auxiliary_bytes == 16'263'413'760ULL);
        CHECK(storage.eager_flat_assignment_bytes == 16'432'457'536ULL);
        CHECK(storage.lazy_derived_witness_bytes == 0);
    });

    return runner.summary();
}
