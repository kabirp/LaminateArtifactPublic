/// @file test_r1cs.cpp
/// @brief Complete ciphertext-commitment-plus-packing Spartan circuit tests.

#include "test_helpers.hpp"

#include "laminate/packing/proof/matrix/oracle.hpp"
#include "laminate/packing/proof/r1cs.hpp"
#include "laminate/packing/proof/reference/materialized_assignment.hpp"
#include "laminate/packing/proof/matrix/metadata.hpp"
#include "laminate/packing/alignment/layout.hpp"

#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace laminate;
using namespace laminate::packing;

namespace {

SignedCoefficientMask identity_coefficients(const fhe::SlotVector &slots) {
    SignedCoefficientMask result;
    result.reserve(slots.size());
    for (const Fp value : slots) {
        result.push_back(static_cast<std::int64_t>(value.value()));
    }
    return result;
}

std::vector<std::uint64_t> identity_native_ntt(
    std::span<const std::int64_t> coefficients) {
    std::vector<std::uint64_t> result;
    result.reserve(coefficients.size());
    for (const std::int64_t coefficient : coefficients) {
        const std::uint64_t magnitude =
            coefficient >= 0
                ? static_cast<std::uint64_t>(coefficient)
                : std::uint64_t{0} -
                      static_cast<std::uint64_t>(coefficient);
        result.push_back(
            coefficient >= 0 || magnitude == 0
                ? magnitude % kOuterFieldOrder
                : (kOuterFieldOrder - magnitude % kOuterFieldOrder) %
                      kOuterFieldOrder);
    }
    return result;
}

LazyTernaryChallengeMatrix challenges() {
    return {
        {{false, false}, {true, true}, {true, false}},
        {{false, true}, {true, false}, {true, true}},
    };
}

OuterRelationPlan make_test_plan(
    const NativePackingOperator &native,
    gkr::CiphertextCommitmentPolicy policy) {
    OuterRelationPlan result = make_outer_relation_plan(native, 2, 2, 59);
    result.shape.ciphertext_commitment_policy = policy;
    return result;
}

class TemporaryDirectory {
  public:
    explicit TemporaryDirectory(std::string_view label) {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-packing-assignment-" +
                     std::string(label) + "-" + std::to_string(stamp) +
                     "-" + std::to_string(attempt));
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

OuterRelationAssignmentArtifactOptions outer_artifact_options(
    const std::filesystem::path &directory) {
    return {
        .directory = directory,
        .storage_limits = {
            .max_total_bytes = 1ULL << 24U,
            .min_free_bytes = 1,
        },
        .max_working_field_bytes = 128,
        .block_elements = 11,
    };
}

ProofOfPackingAssignmentArtifactOptions assignment_artifact_options(
    const std::filesystem::path &directory,
    std::uint64_t max_total_bytes = 1ULL << 28U,
    std::uint64_t max_working_bytes = 1ULL << 24U,
    std::size_t block_elements = 13) {
    return {
        .directory = directory,
        .storage_limits = {
            .max_total_bytes = max_total_bytes,
            .min_free_bytes = 1,
        },
        .max_working_bytes = max_working_bytes,
        .block_elements = block_elements,
    };
}

struct Fixture {
    BalancedRadix radix =
        make_minimal_balanced_radix(kBaseFieldOrder, 17);
    PackingLayout alignment_layout = make_prefix_packing_layout(
        16, std::vector<std::size_t>{4, 4, 4});
    PackingLinearOperator logical =
        make_packing_linear_operator(alignment_layout);
    LazyTernaryParameters parameters{
        .repetitions = 2,
        .honest_error_bound = 23,
        .packing_radix = radix,
    };
    NativePackingOperator native =
        make_native_signed_digit_packing_operator(
            logical, identity_coefficients, identity_native_ntt,
            kOuterFieldOrder, radix);
    OuterRelationPlan plan;
    OuterRelationWitnessInputs witness_inputs;
    OuterRelationPublicInputs public_inputs;
    OuterRelationR1csAssignment packing_assignment;
    std::vector<gkr::HashCommitCT> commitments;
    CompiledProofOfPackingR1cs compiled;
    spartan::R1csAssignment assignment;

    explicit Fixture(
        gkr::CiphertextCommitmentPolicy commitment_policy =
            gkr::CiphertextCommitmentPolicy::poseidon_v2())
        : plan(make_test_plan(native, commitment_policy)),
          compiled(compile_proof_of_packing_r1cs(
              plan, logical,
              {.centered_coefficients = identity_coefficients,
               .native_ntt = identity_native_ntt},
              radix)) {
        witness_inputs.aligned_ciphertext_coordinates.resize(
            plan.shape.aligned_ciphertexts *
            plan.shape.ciphertext_components * plan.shape.ring_degree);
        for (std::size_t index = 0;
             index < witness_inputs.aligned_ciphertext_coordinates.size();
             ++index) {
            witness_inputs.aligned_ciphertext_coordinates[index] = index + 1;
        }

        public_inputs.packed_challenge_words =
            pack_outer_relation_challenge_bits(plan, challenges());
        const OuterRelationExpectedOutputs expected =
            compute_outer_relation_expected_outputs(
                plan, public_inputs.packed_challenge_words, witness_inputs,
                native);
        public_inputs.revealed_test_coordinates =
            expected.revealed_test_coordinates;
        public_inputs.revealed_packing_coordinates =
            expected.revealed_packing_coordinates;
        const OuterRelationAuxiliaryWitness auxiliary =
            build_outer_relation_auxiliary_witness(
                plan, public_inputs.packed_challenge_words, witness_inputs);
        packing_assignment = make_outer_relation_r1cs_assignment(
            plan, public_inputs, witness_inputs, auxiliary);

        const std::size_t coordinates_per_ciphertext =
            plan.shape.ciphertext_components * plan.shape.ring_degree;
        commitments.reserve(plan.shape.aligned_ciphertexts);
        for (std::size_t ciphertext = 0;
             ciphertext < plan.shape.aligned_ciphertexts; ++ciphertext) {
            const auto coordinates = std::span(
                witness_inputs.aligned_ciphertext_coordinates)
                                         .subspan(
                                             ciphertext *
                                                 coordinates_per_ciphertext,
                                             coordinates_per_ciphertext);
            commitments.push_back(
                gkr::hash_commit_normalized_ciphertext_coordinates(
                    plan.shape.ring_degree, coordinates,
                    plan.shape.ciphertext_commitment_policy));
        }
        assignment = reference::make_materialized_proof_of_packing_assignment(
            plan, commitments, packing_assignment);
    }

    OuterRelationR1csAssignmentView outer_view() const {
        return OuterRelationR1csAssignmentView(
            plan, public_inputs, witness_inputs);
    }
};

template <typename Exception, typename Action>
bool rejects_as(Action action) {
    try {
        action();
    } catch (const Exception &) {
        return true;
    }
    return false;
}

template <typename Action>
bool rejects_invalid_argument(Action action) {
    return rejects_as<std::invalid_argument>(std::move(action));
}

template <typename Action>
bool rejects_logic_error(Action action) {
    return rejects_as<std::logic_error>(std::move(action));
}

std::vector<Fq2> matrix_point(std::size_t variables,
                              std::uint64_t seed) {
    std::vector<Fq2> result;
    result.reserve(variables);
    for (std::size_t bit = 0; bit < variables; ++bit) {
        result.push_back(Fq2{
            {Fq(seed + 5 * bit + 1), Fq(seed + 7 * bit + 3)}});
    }
    return result;
}

Fq2 evaluate_mle(std::span<const Fq2> evaluations,
                 std::span<const Fq2> point) {
    if (point.size() >= std::numeric_limits<std::size_t>::digits ||
        evaluations.size() != (std::size_t{1} << point.size())) {
        throw std::invalid_argument("test MLE has inconsistent dimensions");
    }
    std::vector<Fq2> folded(evaluations.begin(), evaluations.end());
    for (std::size_t round = 0; round < point.size(); ++round) {
        const Fq2 &challenge = point[point.size() - 1U - round];
        for (std::size_t index = 0; index < folded.size() / 2U; ++index) {
            const Fq2 lo = folded[2U * index];
            const Fq2 hi = folded[2U * index + 1U];
            folded[index] = lo + challenge * (hi - lo);
        }
        folded.resize(folded.size() / 2U);
    }
    return folded.front();
}

} // namespace

int main() {
    test::Runner runner("test_proof_of_packing_r1cs");

    runner.run("complete generated A B C matrices accept the honest witness",
               [] {
                   const Fixture fixture;
                   CHECK(fixture.compiled.circuit.shape().constraints ==
                         fixture.compiled.ledger.matrix_rows);
                   CHECK(fixture.compiled.ledger.matrix_rows >=
                         fixture.compiled.ledger.total_constraints);
                   CHECK(fixture.compiled.circuit.shape().public_inputs ==
                         fixture.compiled.ledger.total_public_inputs);
                   CHECK(fixture.compiled.ledger.total_public_inputs ==
                         fixture.compiled.ledger.total_logical_inputs);
                   CHECK(fixture.assignment.public_inputs.size() ==
                         fixture.compiled.ledger.total_logical_inputs);
                   CHECK(fixture.assignment.public_inputs ==
                         make_proof_of_packing_public_inputs(
                             fixture.plan, fixture.commitments,
                             fixture.public_inputs));
                   const std::vector<Fq> commitment_inputs =
                       proof_of_packing_commitment_logical_inputs(
                           fixture.commitments);
                   for (std::size_t index = 0;
                        index < commitment_inputs.size(); ++index) {
                       CHECK(fixture.assignment.public_inputs[index] ==
                             commitment_inputs[index]);
                   }
                   for (std::size_t index = 0;
                        index < fixture.packing_assignment.public_inputs.size();
                        ++index) {
                       CHECK(fixture.assignment.public_inputs[
                                 commitment_inputs.size() + index] ==
                             Fq(fixture.packing_assignment
                                    .public_inputs[index]));
                   }
                   CHECK(fixture.compiled.circuit.shape().witness_variables ==
                         fixture.compiled.ledger.total_witness_variables);
                   CHECK(fixture.compiled.circuit.nonzero_entries() <=
                         fixture.compiled.ledger
                             .total_nonzero_entries_upper_bound);
                   CHECK(fixture.compiled.layout.ciphertext_segments.size() >
                         1);
                   CHECK(fixture.compiled.layout.rows.ciphertext_poseidon
                             .extent ==
                         fixture.compiled.layout.rows.ciphertext_poseidon
                             .live);
                   CHECK(fixture.compiled.fixed_packing_statistics.complete);
                   CHECK(fixture.compiled.circuit.is_satisfied(
                       fixture.assignment));
                   const auto borrowed_assignment =
                       make_proof_of_packing_r1cs_assignment(
                           fixture.plan, fixture.commitments,
                           fixture.outer_view());
                   CHECK(borrowed_assignment.public_inputs ==
                         fixture.assignment.public_inputs);
                   CHECK(borrowed_assignment.witness ==
                         fixture.assignment.witness);
               });

    runner.run("diagnostic simpleCTHash has the exact sparse relation and "
               "preserves the six-field statement",
               [] {
                   const auto policy = gkr::CiphertextCommitmentPolicy::
                       diagnostic_simple_ct_hash_v2();
                   const Fixture fixture(policy);
                   const std::uint64_t coordinates =
                       fixture.plan.coordinates_per_ciphertext();
                   const std::uint64_t per_ciphertext =
                       coordinates + kPoseidonDigestElements;
                   CHECK(fixture.compiled.ledger
                             .ciphertext_commitment_constraints_per_ciphertext ==
                         per_ciphertext);
                   CHECK(fixture.compiled.ledger
                             .ciphertext_commitment_constraints ==
                         fixture.plan.shape.aligned_ciphertexts *
                             per_ciphertext);
                   CHECK(fixture.compiled.ledger
                             .ciphertext_commitment_nonzero_entries ==
                         4 * fixture.compiled.ledger
                                 .ciphertext_commitment_constraints);
                   CHECK(fixture.compiled.ledger
                             .ciphertext_commitment_auxiliary_witness_variables ==
                         fixture.plan.shape.aligned_ciphertexts *
                             coordinates);
                   CHECK(fixture.compiled.ledger
                             .ciphertext_poseidon_constraints == 0);
                   CHECK(fixture.compiled.ledger
                             .ciphertext_poseidon_auxiliary_witness_variables ==
                         0);
                   CHECK(fixture.compiled.circuit.is_satisfied(
                       fixture.assignment));
                   CHECK(fixture.commitments.front().digest.size() == 48);

                   const std::size_t q =
                       fixture.plan.coordinates_per_ciphertext();
                   const auto first_coordinates = std::span(
                       fixture.witness_inputs
                           .aligned_ciphertext_coordinates)
                                                      .first(q);
                   const auto poseidon =
                       gkr::hash_commit_normalized_ciphertext_coordinates(
                           fixture.plan.shape.ring_degree,
                           first_coordinates,
                           gkr::CiphertextCommitmentPolicy::poseidon_v2());
                   CHECK(poseidon != fixture.commitments.front());
                   std::vector<std::uint64_t> changed(
                       first_coordinates.begin(), first_coordinates.end());
                   ++changed.back();
                   CHECK(gkr::hash_commit_normalized_ciphertext_coordinates(
                             fixture.plan.shape.ring_degree, changed,
                             policy) != fixture.commitments.front());

                   const auto simple_metadata =
                       make_proof_of_packing_structured_metadata(
                           fixture.alignment_layout,
                           fixture.parameters, policy);
                   const auto poseidon_metadata =
                       make_proof_of_packing_structured_metadata(
                           fixture.alignment_layout,
                           fixture.parameters);
                   CHECK(simple_metadata.relation_plan.shape
                             .ciphertext_commitment_policy == policy);
                   CHECK(simple_metadata.semantic_circuit_digest !=
                         poseidon_metadata.semantic_circuit_digest);
                   CHECK(simple_metadata
                             .ciphertext_commitment_gadget_digest !=
                         poseidon_metadata
                             .ciphertext_commitment_gadget_digest);
               });

    runner.run("structured metadata matches materialized shape without "
               "coefficient setup",
               [] {
                   const Fixture fixture;
                   const ProofOfPackingStructuredMetadata structured =
                       make_proof_of_packing_structured_metadata(
                           fixture.alignment_layout, fixture.parameters);
                   structured.validate();

                   const spartan::R1csMetadata materialized =
                       fixture.compiled.circuit.metadata();
                   CHECK(structured.relation_plan.shape.native_modulus ==
                         fixture.plan.shape.native_modulus);
                   CHECK(structured.relation_plan.shape.ring_degree ==
                         fixture.plan.shape.ring_degree);
                   CHECK(structured.relation_plan.shape.aligned_ciphertexts ==
                         fixture.plan.shape.aligned_ciphertexts);
                   CHECK(structured.relation_plan.shape.repetitions ==
                         fixture.plan.shape.repetitions);
                   CHECK(
                       structured.relation_plan.shape.logical_packed_outputs ==
                       fixture.plan.shape.logical_packed_outputs);
                   CHECK(structured.relation_plan.shape.packing_digit_count ==
                         fixture.plan.shape.packing_digit_count);
                   CHECK(structured.r1cs_ledger == fixture.compiled.ledger);
                   CHECK(structured.circuit_metadata.shape() ==
                         materialized.shape());
                   CHECK(structured.circuit_metadata.padded_constraints() ==
                         materialized.padded_constraints());
                   CHECK(
                       structured.circuit_metadata.assignment_half_size() ==
                       materialized.assignment_half_size());
                   CHECK(structured.circuit_metadata.row_variables() ==
                         materialized.row_variables());
                   CHECK(structured.circuit_metadata.column_variables() ==
                         materialized.column_variables());
                   CHECK(structured.circuit_metadata.digest() ==
                         structured.semantic_circuit_digest);
                   CHECK(structured.recompute_semantic_circuit_digest() ==
                         structured.semantic_circuit_digest);

                   const std::vector<PackingTensor> tensors =
                       compile_packing_tensors(
                           fixture.plan,
                           fixture.compiled.native_packing_operator);
                   std::vector<PackingTensorMapping> materialized_mappings;
                   for (const PackingTensor &tensor : tensors) {
                       materialized_mappings.push_back({
                           .descriptor = tensor.descriptor,
                           .global_owners = tensor.global_owners,
                       });
                   }
                   CHECK(structured.tensor_mappings ==
                         materialized_mappings);
               });

    runner.run("structured identity rejects layout plan and Poseidon "
               "mutations",
               [] {
                   const Fixture fixture;
                   const ProofOfPackingStructuredMetadata original =
                       make_proof_of_packing_structured_metadata(
                           fixture.alignment_layout, fixture.parameters);
                   // Binds the complete v2 sponge profile and local R1CS template.
                   const Digest expected_poseidon_gadget{
                       0x7e, 0xc3, 0x99, 0xfa, 0x15, 0x0d, 0xe1, 0x77,
                       0xc1, 0xc5, 0xb2, 0xe1, 0x0e, 0x74, 0x97, 0x87,
                       0x15, 0xbf, 0x76, 0xf0, 0xec, 0xfa, 0x23, 0xdc,
                       0xce, 0x77, 0x05, 0xd7, 0x1e, 0x56, 0xc3, 0x9a};
                   CHECK(original.ciphertext_commitment_gadget_digest ==
                         expected_poseidon_gadget);

                   auto changed_plan = original;
                   ++changed_plan.relation_plan.constraints.total;
                   CHECK(changed_plan.recompute_semantic_circuit_digest() !=
                         original.semantic_circuit_digest);
                   CHECK(rejects_invalid_argument(
                       [&] { changed_plan.validate(); }));

                   auto changed_layout = original;
                   ++changed_layout.alignment_layout
                         .placements.front()
                         .rotation_steps;
                   CHECK(changed_layout.recompute_semantic_circuit_digest() !=
                         original.semantic_circuit_digest);
                   CHECK(rejects_invalid_argument(
                       [&] { changed_layout.validate(); }));

                   auto changed_poseidon = original;
                   changed_poseidon.ciphertext_commitment_gadget_digest
                       .front() ^= 1U;
                   CHECK(
                       changed_poseidon.recompute_semantic_circuit_digest() !=
                       original.semantic_circuit_digest);
                   CHECK(rejects_invalid_argument(
                       [&] { changed_poseidon.validate(); }));

                   auto changed_parameters = fixture.parameters;
                   ++changed_parameters.honest_error_bound;
                   const ProofOfPackingStructuredMetadata other_policy =
                       make_proof_of_packing_structured_metadata(
                           fixture.alignment_layout, changed_parameters);
                   CHECK(other_policy.semantic_circuit_digest !=
                         original.semantic_circuit_digest);
               });

    runner.run("implicit aligned zeros synthesize the formal Poseidon witness",
               [] {
        const Fixture fixture;
        OuterRelationR1csInputSlices slices;
        slices.packed_challenge_words =
            fixture.public_inputs.packed_challenge_words;
        slices.revealed_test_ciphertexts.assign(
            fixture.plan.shape.repetitions,
            OuterRelationCiphertextCoordinateSlice::implicit_zero());
        slices.revealed_packing_ciphertexts.assign(
            fixture.plan.physical_packed_ciphertexts(),
            OuterRelationCiphertextCoordinateSlice::implicit_zero());
        slices.aligned_ciphertexts.assign(
            fixture.plan.shape.aligned_ciphertexts,
            OuterRelationCiphertextCoordinateSlice::implicit_zero());
        const OuterRelationR1csAssignmentView view(
            fixture.plan, std::move(slices));

        const std::vector<std::uint64_t> formal_zero(
            fixture.plan.coordinates_per_ciphertext(), 0);
        const gkr::HashCommitCT zero_commitment =
            gkr::hash_commit_normalized_ciphertext_coordinates(
                fixture.plan.shape.ring_degree, formal_zero);
        const std::vector<gkr::HashCommitCT> commitments(
            fixture.plan.shape.aligned_ciphertexts, zero_commitment);
        const spartan::R1csAssignment assignment =
            make_proof_of_packing_r1cs_assignment(
                fixture.plan, commitments, view);

        CHECK(fixture.compiled.circuit.is_satisfied(assignment));
        const OuterRelationRange aligned =
            fixture.plan.variables.witness
                .aligned_ciphertext_coordinates;
        for (std::uint64_t index = aligned.begin;
             index < aligned.end(); ++index) {
            CHECK(assignment.witness.at(static_cast<std::size_t>(
                      fixture.compiled.layout.outer_witness_index(
                          fixture.plan, index))) == Fq::zero());
        }
    });

    runner.run("complete assignment keeps Spartan padding virtual",
               [] {
                   const Fixture fixture;
                   TemporaryDirectory source_directory("source-parity");
                   const OuterRelationAssignmentArtifact source =
                       write_outer_relation_assignment_artifact(
                           fixture.outer_view(),
                           outer_artifact_options(source_directory.path()));
                   TemporaryDirectory destination("complete-parity");
                   const auto options = assignment_artifact_options(
                       destination.path());
                   const spartan::R1csMetadata metadata =
                       fixture.compiled.circuit.metadata();
                   const ProofOfPackingAssignmentArtifact written =
                       write_proof_of_packing_assignment_artifact(
                           fixture.plan, metadata, *source.artifact,
                           fixture.commitments, options);

                   CHECK(fixture.commitments.size() == 3);
                   CHECK(fixture.compiled.layout.ciphertext_segments.size() >
                         1);
                   CHECK(fixture.compiled.layout
                             .ciphertext_segment(0)
                             .permutation_begin !=
                         fixture.compiled.layout
                             .ciphertext_segment(
                                 2 * fixture.compiled.layout
                                         .ciphertext_permutations_per_hash)
                             .permutation_begin);
                   CHECK(written.artifact != nullptr);
                   CHECK(written.artifact->identity() ==
                         proof_of_packing_assignment_artifact_identity(
                             fixture.plan, metadata, *source.artifact,
                             fixture.commitments));
                   CHECK(written.report.public_input_elements ==
                         fixture.assignment.public_inputs.size());
                   CHECK(written.report.witness_half_elements ==
                         fixture.compiled.circuit.assignment_half_size());
                   CHECK(written.report.stored_witness_elements ==
                         written.report.active_outer_witness_elements +
                             written.report
                                 .ciphertext_commitment_auxiliary_elements);
                   CHECK(written.report.active_outer_witness_elements ==
                         fixture.plan.variables.witness.total);
                   CHECK(written.report
                             .ciphertext_commitment_auxiliary_elements ==
                         fixture.compiled.layout.witness
                             .ciphertext_poseidon_auxiliary.live);
                   CHECK(written.report.zero_witness_elements ==
                         written.report.witness_half_elements -
                             written.report.stored_witness_elements);
                   CHECK(written.report.public_payload_bytes ==
                         written.report.public_input_elements * sizeof(Fq));
                   CHECK(written.report.logical_witness_payload_bytes ==
                         written.report.witness_half_elements * sizeof(Fq));
                   CHECK(written.report.stored_witness_payload_bytes ==
                         written.report.stored_witness_elements *
                             sizeof(Fq));
                   CHECK(written.report.stored_witness_payload_bytes <
                         written.report.logical_witness_payload_bytes);
                   CHECK(written.report.physical_bytes ==
                         written.artifact->physical_bytes());
                   CHECK(written.report.source_read_payload_bytes ==
                         (fixture.plan.variables.public_inputs.total +
                          fixture.plan.variables.witness.total) *
                             sizeof(Fq));
                   CHECK(written.report.source_seek_operations == 0);
                   CHECK(written.report.sequential_output_payload_bytes ==
                         written.report.public_payload_bytes);
                   CHECK(written.report.positional_output_payload_bytes ==
                         written.report.stored_witness_payload_bytes);
                   CHECK(written.report.positional_output_write_operations >
                         0);
                   CHECK(written.report.positional_publication_read_bytes >
                         written.report.stored_witness_payload_bytes);
                   CHECK(written.report
                             .positional_publication_read_operations > 0);
                   CHECK(written.report.artifact_validation_bytes ==
                         written.report.physical_bytes);
                   CHECK(written.report.peak_working_bytes <=
                         options.max_working_bytes);

                   auto public_reader =
                       written.artifact->open_array("public-inputs");
                   std::vector<Fq> public_inputs(
                       fixture.assignment.public_inputs.size());
                   CHECK(public_reader.read(public_inputs) ==
                         public_inputs.size());
                   CHECK(public_inputs == fixture.assignment.public_inputs);

                   const auto &stored_witness = written.artifact->array(
                       kProofOfPackingAssignmentWitnessValues);
                   CHECK(stored_witness.element_count ==
                         written.report.stored_witness_elements);
                   const ProofOfPackingWitnessStorageLayout storage_layout =
                       proof_of_packing_witness_storage_layout(
                           fixture.plan, metadata);
                   CHECK(storage_layout.logical_elements ==
                         written.report.witness_half_elements);
                   CHECK(storage_layout.stored_elements ==
                         written.report.stored_witness_elements);
                   CHECK(!storage_layout.segments.empty());

                   ProofOfPackingWitnessReader witness_reader(
                       fixture.plan, metadata, *written.artifact);
                   std::vector<Fq> witness_half(
                       fixture.compiled.circuit.assignment_half_size());
                   const ProofOfPackingWitnessReadReport full_read =
                       witness_reader.read_at(0, witness_half);
                   CHECK(full_read.stored_elements ==
                         written.report.stored_witness_elements);
                   CHECK(witness_half ==
                         fixture.compiled.circuit.padded_witness(
                             fixture.assignment));

                   bool checked_internal_gap = false;
                   for (std::size_t segment = 1;
                        segment < storage_layout.segments.size();
                        ++segment) {
                       const auto &previous =
                           storage_layout.segments[segment - 1];
                       const auto &next =
                           storage_layout.segments[segment];
                       const std::uint64_t gap_begin =
                           previous.logical_begin +
                           previous.element_count;
                       if (gap_begin >= next.logical_begin) {
                           continue;
                       }
                       const std::size_t gap_size =
                           static_cast<std::size_t>(std::min<std::uint64_t>(
                               17, next.logical_begin - gap_begin));
                       std::vector<Fq> zero_gap(gap_size);
                       const ProofOfPackingWitnessReadReport gap_read =
                           witness_reader.read_at(gap_begin, zero_gap);
                       CHECK(gap_read ==
                             ProofOfPackingWitnessReadReport{});
                       CHECK(std::all_of(
                           zero_gap.begin(), zero_gap.end(),
                           [](const Fq &value) {
                               return value.is_zero();
                           }));
                       checked_internal_gap = true;
                       break;
                   }
                   CHECK(checked_internal_gap);

                   const std::uint64_t tail_begin =
                       fixture.compiled.layout.witness.total;
                   CHECK(tail_begin < storage_layout.logical_elements);
                   std::vector<Fq> zero_tail(static_cast<std::size_t>(
                       storage_layout.logical_elements - tail_begin));
                   const ProofOfPackingWitnessReadReport tail_read =
                       witness_reader.read_at(tail_begin, zero_tail);
                   CHECK(tail_read == ProofOfPackingWitnessReadReport{});
                   CHECK(std::all_of(
                       zero_tail.begin(), zero_tail.end(),
                       [](const Fq &value) { return value.is_zero(); }));

                   const auto reopened =
                       open_proof_of_packing_assignment_artifact(
                           destination.path(), fixture.plan, metadata,
                           *source.artifact, fixture.commitments);
                   CHECK(reopened->arrays() == written.artifact->arrays());
                   CHECK(reopened->physical_bytes() ==
                         written.report.physical_bytes);
               });

    runner.run("complete assignment budgets and identities fail closed", [] {
        const Fixture fixture;
        TemporaryDirectory source_directory("source-limits");
        const OuterRelationAssignmentArtifact source =
            write_outer_relation_assignment_artifact(
                fixture.outer_view(),
                outer_artifact_options(source_directory.path()));
        const spartan::R1csMetadata metadata =
            fixture.compiled.circuit.metadata();

        std::uint64_t exact_bytes = 0;
        {
            TemporaryDirectory baseline("baseline");
            exact_bytes = write_proof_of_packing_assignment_artifact(
                              fixture.plan, metadata, *source.artifact,
                              fixture.commitments,
                              assignment_artifact_options(baseline.path()))
                              .report.physical_bytes;
        }
        {
            TemporaryDirectory destination("quota");
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)write_proof_of_packing_assignment_artifact(
                    fixture.plan, metadata, *source.artifact,
                    fixture.commitments,
                    assignment_artifact_options(destination.path(),
                                                exact_bytes - 1));
            }));
            CHECK(std::filesystem::is_empty(destination.path()));
        }
        {
            TemporaryDirectory destination("memory");
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)write_proof_of_packing_assignment_artifact(
                    fixture.plan, metadata, *source.artifact,
                    fixture.commitments,
                    assignment_artifact_options(destination.path(),
                                                1ULL << 28U,
                                                sizeof(Fq)));
            }));
            CHECK(std::filesystem::is_empty(destination.path()));
        }
        {
            TemporaryDirectory destination("free-space");
            auto options = assignment_artifact_options(destination.path());
            options.storage_limits.min_free_bytes =
                std::numeric_limits<std::uint64_t>::max();
            CHECK(rejects_as<std::overflow_error>([&] {
                (void)write_proof_of_packing_assignment_artifact(
                    fixture.plan, metadata, *source.artifact,
                    fixture.commitments, options);
            }));
            CHECK(std::filesystem::is_empty(destination.path()));
        }
        {
            TemporaryDirectory destination("occupied");
            const std::filesystem::path marker =
                destination.path() / "keep";
            std::ofstream output(marker);
            output << "keep";
            output.close();
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)write_proof_of_packing_assignment_artifact(
                    fixture.plan, metadata, *source.artifact,
                    fixture.commitments,
                    assignment_artifact_options(destination.path()));
            }));
            CHECK(std::filesystem::exists(marker));
        }
        {
            TemporaryDirectory destination("late-failure");
            auto wrong_commitments = fixture.commitments;
            wrong_commitments.front().digest.front() ^= 1U;
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)write_proof_of_packing_assignment_artifact(
                    fixture.plan, metadata, *source.artifact,
                    wrong_commitments,
                    assignment_artifact_options(destination.path()));
            }));
            CHECK(std::filesystem::is_empty(destination.path()));
        }
        {
            TemporaryDirectory destination("identity");
            (void)write_proof_of_packing_assignment_artifact(
                fixture.plan, metadata, *source.artifact,
                fixture.commitments,
                assignment_artifact_options(destination.path()));
            auto wrong_commitments = fixture.commitments;
            wrong_commitments.back().digest.back() ^= 1U;
            CHECK(rejects_as<std::runtime_error>([&] {
                (void)open_proof_of_packing_assignment_artifact(
                    destination.path(), fixture.plan, metadata,
                    *source.artifact, wrong_commitments);
            }));
        }
    });

    runner.run("public statement and private witness mutations fail closed", [] {
        const Fixture fixture;

        auto changed_commitment = fixture.assignment;
        changed_commitment.public_inputs.front() += Fq::one();
        CHECK(!fixture.compiled.circuit.is_satisfied(
            changed_commitment));

        auto changed_packing_input = fixture.assignment;
        changed_packing_input.public_inputs.at(static_cast<std::size_t>(
            fixture.compiled.ledger.commitment_logical_inputs)) +=
            Fq::one();
        CHECK(!fixture.compiled.circuit.is_satisfied(
            changed_packing_input));

        auto changed_witness = fixture.assignment;
        const std::uint64_t aligned_begin =
            fixture.compiled.layout.outer_witness_index(
                fixture.plan,
                fixture.plan.variables.witness
                    .aligned_ciphertext_coordinates.begin);
        changed_witness.witness.at(
            static_cast<std::size_t>(aligned_begin)) += Fq::one();
        CHECK(!fixture.compiled.circuit.is_satisfied(changed_witness));

        auto wrong_commitments = fixture.commitments;
        wrong_commitments.front().digest.front() ^= 1U;
        CHECK(rejects_invalid_argument([&] {
            (void)reference::make_materialized_proof_of_packing_assignment(
                fixture.plan, wrong_commitments,
                fixture.packing_assignment);
        }));
    });

    runner.run("both structured commitment policies match every direct A B "
               "C MLE",
               [] {
                   for (const auto policy : {
                            gkr::CiphertextCommitmentPolicy::poseidon_v2(),
                            gkr::CiphertextCommitmentPolicy::
                                diagnostic_simple_ct_hash_v2()}) {
                       const Fixture fixture(policy);
                       const auto reference =
                           std::make_shared<const spartan::R1csInstance>(
                               fixture.compiled.circuit);
                       const auto oracle =
                           make_proof_of_packing_matrix_oracle(
                               fixture.plan, fixture.compiled.layout,
                               fixture.compiled.native_packing_operator,
                               reference);
                       for (const std::uint64_t seed :
                            {3U, 101U, 1'009U}) {
                           const std::vector<Fq2> row_point = matrix_point(
                               reference->row_variables(), seed);
                           const std::vector<Fq2> column_point = matrix_point(
                               reference->column_variables(), seed + 10'007);
                           const auto structured =
                               oracle->evaluate_matrices(
                                   row_point, column_point);
                           for (std::size_t matrix = 0; matrix < 3;
                                ++matrix) {
                               CHECK(structured[matrix] ==
                                     reference->evaluate_matrix(
                                         static_cast<spartan::Matrix>(matrix),
                                         row_point, column_point));
                           }
                       }
                   }
               });

    runner.run("factored prover oracle retains products but not coefficients",
               [] {
                   const Fixture fixture;
                   const auto reference =
                       std::make_shared<const spartan::R1csInstance>(
                           fixture.compiled.circuit);
                   const auto oracle =
                       make_proof_of_packing_factored_prover_oracle(
                           fixture.plan, fixture.compiled.layout, reference);
                   CHECK(oracle->circuit_digest() == reference->digest());
                   CHECK(oracle->row_variables() ==
                         reference->row_variables());
                   CHECK(oracle->column_variables() ==
                         reference->column_variables());

                   const std::vector<Fq> assignment =
                       reference->padded_assignment(fixture.assignment);
                   for (std::size_t matrix = 0; matrix < 3; ++matrix) {
                       const auto kind =
                           static_cast<spartan::Matrix>(matrix);
                       CHECK(oracle->multiply(kind, assignment) ==
                             reference->multiply(kind, assignment));
                   }

                   const std::vector<Fq2> row_point = matrix_point(
                       reference->row_variables(), 37U);
                   const std::vector<Fq2> column_point = matrix_point(
                       reference->column_variables(), 71U);
                   const Fq2 gamma{{Fq(101), Fq(103)}};
                   CHECK(oracle->batched_wiring_table(row_point, gamma) ==
                         reference->batched_wiring_table(row_point, gamma));
                   CHECK(rejects_logic_error([&] {
                       (void)oracle->evaluate_matrices(
                           row_point, column_point);
                   }));
               });

    runner.run("factored regular matrices and K tensors match direct MLEs",
               [] {
                   const Fixture fixture;
                   const auto reference =
                       std::make_shared<const spartan::R1csInstance>(
                           fixture.compiled.circuit);
                   const std::vector<PackingTensor> tensors =
                       compile_packing_tensors(
                           fixture.plan,
                           fixture.compiled.native_packing_operator);
                   const auto materialized_structure =
                       make_proof_of_packing_factored_structure(
                           fixture.plan, fixture.compiled.layout, tensors,
                           reference->metadata());
                   const std::vector<PackingTensorMapping> mappings =
                       packing_tensor_mappings(
                           fixture.logical, fixture.radix.digit_count);
                   const auto structure =
                       make_proof_of_packing_factored_structure(
                           fixture.plan, fixture.compiled.layout, mappings,
                           reference->metadata());
                   CHECK(structure->structure_digest() ==
                         materialized_structure->structure_digest());
                   CHECK(proof_of_packing_factored_tensor_mappings(
                             *structure) == mappings);

                   for (const std::uint64_t seed : {7U, 313U}) {
                       const std::vector<Fq2> row_point = matrix_point(
                           reference->row_variables(), seed);
                       const std::vector<Fq2> column_point = matrix_point(
                           reference->column_variables(), seed + 2'003U);
                       const Fq2 gamma{
                           {Fq(seed + 41U), Fq(seed + 43U)}};
                       const auto regular =
                           structure->regular_matrix_evaluations(
                               row_point, column_point);
                       CHECK(regular ==
                             materialized_structure
                                 ->regular_matrix_evaluations(
                                     row_point, column_point));
                       Fq2 residual = Fq2::zero();
                       for (std::size_t output = 0;
                            output < tensors.size(); ++output) {
                           const std::vector<Fq2> weights =
                               structure->tensor_column_weights(
                                   output, row_point, column_point, gamma);
                           const std::vector<Fq2> operand =
                               structure->materialize_tensor_operand(
                                   output, row_point, column_point, gamma);
                           CHECK(weights.size() ==
                                 tensors[output].digit_columns.size());
                           CHECK(operand.size() ==
                                 tensors[output].digit_columns.front().size());
                           for (std::size_t index = 0;
                                index < operand.size(); ++index) {
                               Fq2 coefficient = Fq2::zero();
                               for (std::size_t digit = 0;
                                    digit < weights.size(); ++digit) {
                                   coefficient +=
                                       weights[digit] *
                                       tensors[output]
                                           .digit_columns[digit][index];
                               }
                               residual += coefficient * operand[index];
                           }

                           const std::size_t tensor_variables =
                               std::bit_width(operand.size()) - 1U;
                           const std::vector<Fq2> tensor_point =
                               matrix_point(tensor_variables,
                                            seed + 4'009U + output);
                           CHECK(structure->evaluate_tensor_operand(
                                     output, row_point, column_point, gamma,
                                     tensor_point) ==
                                 evaluate_mle(operand, tensor_point));
                       }
                       const Fq2 direct_a = reference->evaluate_matrix(
                           spartan::Matrix::A, row_point, column_point);
                       const Fq2 direct_b = reference->evaluate_matrix(
                           spartan::Matrix::B, row_point, column_point);
                       const Fq2 direct_c = reference->evaluate_matrix(
                           spartan::Matrix::C, row_point, column_point);
                       CHECK(direct_a == regular[0] + residual);
                       CHECK(direct_b == regular[1]);
                       CHECK(direct_c == regular[2]);
                   }
               });

    runner.run("target structured metadata is formula only", [] {
        constexpr std::size_t kRingDegree = 1U << 14U;
        constexpr std::size_t kAlignedCiphertexts = 517;
        const PackingLayout layout =
            make_fixed_message_coset_packing_layout(
                kRingDegree, kAlignedCiphertexts,
                kRingDegree / fhe::kFixedMessageCellCount);

        // This target-scale call has no encoder, NTT, native packing
        // operator, expanded R1CS, or coefficient-tensor input to invoke.
        const ProofOfPackingStructuredMetadata metadata =
            make_proof_of_packing_structured_metadata(
                layout, selected_lazy_ternary_parameters());
        CHECK(metadata.r1cs_ledger.total_constraints == 3'167'501'480ULL);
        CHECK(metadata.r1cs_ledger.matrix_rows == 3'167'518'720ULL);
        CHECK(metadata.circuit_metadata.padded_constraints() ==
              (std::size_t{1} << 32U));
        CHECK(metadata.circuit_metadata.assignment_half_size() ==
              (std::size_t{1} << 32U));
        CHECK(metadata.tensor_mappings.size() == 1);
        CHECK(metadata.tensor_mappings.front().global_owners.size() ==
              kAlignedCiphertexts);
        CHECK(metadata.tensor_mappings.front().descriptor.live_owner_count ==
              kAlignedCiphertexts);
        CHECK(
            metadata.tensor_mappings.front().descriptor.padded_owner_count ==
            1'024);
        CHECK(metadata.tensor_mappings.front().descriptor.digit_count == 4);
        CHECK(metadata.tensor_mappings.front().descriptor.field_element_bytes ==
              kSerializedFqBytes);
    });

    runner.run("N equals 2 to 14 ciphertext hashing has the expected constraint ledger",
               [] {
                   const OuterRelationPlan target =
                       make_outer_relation_plan(OuterRelationShape{
                           .native_modulus = kOuterFieldOrder,
                           .ring_degree = 1U << 14U,
                           .aligned_ciphertexts = 1,
                           .repetitions = 1,
                           .logical_packed_outputs = 1,
                           .packing_digit_count = 4,
                           .ciphertext_components = 2,
                           .public_input_capacity_bits = 59,
                       });
                   const ProofOfPackingR1csLedger ledger =
                       proof_of_packing_r1cs_ledger(target);
                   CHECK(ledger.nonzero_entry_counts_available);
                   CHECK(ledger.ciphertext_preimage_field_elements ==
                         2 * (1U << 14U) + 4);
                   CHECK(ledger.poseidon_sbox_constraints_per_ciphertext ==
                         1'504'602);
                   CHECK(
                       ledger.poseidon_checkpoint_constraints_per_ciphertext ==
                       681'824);
                   CHECK(ledger.poseidon_output_constraints_per_ciphertext ==
                         kPoseidonDigestElements);
                   CHECK(ledger.ciphertext_poseidon_constraints ==
                         2'186'432);
                   CHECK(ledger.ciphertext_poseidon_constraints <
                         2'200'000);
                   CHECK(
                       ledger
                           .ciphertext_poseidon_nonzero_entries_per_ciphertext ==
                         22'945'934);
                   CHECK(ledger.ciphertext_poseidon_nonzero_entries ==
                         ledger
                             .ciphertext_poseidon_nonzero_entries_per_ciphertext);
                   CHECK(ledger.total_nonzero_entries_upper_bound >=
                         ledger.ciphertext_poseidon_nonzero_entries);
                   CHECK(
                       ledger
                           .ciphertext_poseidon_auxiliary_witness_variables ==
                         ledger.poseidon_sbox_constraints_per_ciphertext +
                             ledger
                                 .poseidon_checkpoint_constraints_per_ciphertext);
                   CHECK(ledger.total_public_inputs ==
                         ledger.total_logical_inputs);
                   CHECK(ledger.total_poseidon_constraints ==
                         ledger.ciphertext_poseidon_constraints);
                   CHECK(ledger.active_witness_variables ==
                         ledger.packing_witness_variables +
                             ledger
                                 .ciphertext_poseidon_auxiliary_witness_variables);
               });

    return runner.summary();
}
