/// @file test_tensor_staging.cpp
/// @brief Formula admission, byte parity, and cleanup tests.

#include "test_helpers.hpp"

#include "laminate/packing/proof/matrix/tensor_staging.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::packing;

namespace {

class TemporaryDirectory {
  public:
    explicit TemporaryDirectory(std::string_view label) {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-tensor-staging-" + std::string(label) +
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

    TemporaryDirectory(const TemporaryDirectory &) = delete;
    TemporaryDirectory &operator=(const TemporaryDirectory &) = delete;

  private:
    std::filesystem::path path_;
};

SignedCoefficientMask test_centered_coefficients(
    const fhe::SlotVector &slots) {
    static constexpr std::int64_t kValues[] = {-8, -1, 1, 8};
    SignedCoefficientMask result(slots.size(), 0);
    for (std::size_t index = 0; index < slots.size(); ++index) {
        if (!slots[index].is_zero()) {
            result[index] = kValues[index % 4U];
        }
    }
    return result;
}

std::vector<std::uint64_t> test_native_ntt(
    std::span<const std::int64_t> coefficients) {
    std::vector<std::uint64_t> result(coefficients.size());
    for (std::size_t coordinate = 0; coordinate < coefficients.size();
         ++coordinate) {
        const std::int64_t coefficient =
            coefficients[(5U * coordinate) % coefficients.size()];
        const std::uint64_t magnitude =
            coefficient >= 0
                ? static_cast<std::uint64_t>(coefficient)
                : std::uint64_t{0} -
                      static_cast<std::uint64_t>(coefficient);
        result[coordinate] =
            coefficient >= 0 || magnitude == 0
                ? magnitude % kOuterFieldOrder
                : (kOuterFieldOrder - magnitude % kOuterFieldOrder) %
                      kOuterFieldOrder;
    }
    return result;
}

struct Fixture {
    PackingLayout layout = make_prefix_packing_layout(
        16, std::vector<std::size_t>{4, 4, 4});
    PackingLinearOperator packing_operator =
        make_packing_linear_operator(layout);
    LazyTernaryParameters parameters{
        .repetitions = 2,
        .honest_error_bound = 23,
        .packing_radix =
            make_minimal_balanced_radix(kBaseFieldOrder, 17),
    };
    ProofOfPackingStructuredMetadata metadata =
        make_proof_of_packing_structured_metadata(layout, parameters);

    ProofOfPackingR1csEncoders encoders() const {
        return {
            .centered_coefficients = test_centered_coefficients,
            .native_ntt = test_native_ntt,
        };
    }

    std::vector<PackingTensor> materialized_tensors() const {
        const NativePackingOperator native =
            make_native_signed_digit_packing_operator(
                packing_operator, test_centered_coefficients,
                test_native_ntt, kOuterFieldOrder,
                parameters.packing_radix);
        return compile_packing_tensors(metadata.relation_plan, native);
    }
};

template <typename Exception = std::exception, typename Action>
bool rejects_as(Action action) {
    try {
        action();
    } catch (const Exception &) {
        return true;
    }
    return false;
}

ProofOfPackingTensorStagingOptions options_for(
    const std::filesystem::path &directory,
    const ProofOfPackingTensorStagingPlan &plan) {
    return {
        .directory = directory,
        .storage_limits = {
            .max_total_bytes = plan.artifact_physical_bytes,
            .min_free_bytes = 1,
        },
        .max_working_bytes = plan.peak_working_bytes,
        .block_elements = plan.block_elements,
    };
}

std::vector<Fq> read_array(
    const storage::NativeFieldArtifact &artifact,
    std::string_view name) {
    storage::NativeFieldArrayReader reader = artifact.open_array(name);
    std::vector<Fq> result(reader.size());
    std::size_t written = 0;
    while (written < result.size()) {
        const std::size_t count = reader.read(
            std::span<Fq>(result).subspan(written));
        if (count == 0) {
            throw std::runtime_error("test artifact reader ended early");
        }
        written += count;
    }
    return result;
}

void write_materialized_reference(
    const std::filesystem::path &directory,
    const spartan::FactoredMatrixStructure &structure,
    std::span<const PackingTensor> tensors,
    std::uint64_t physical_bytes) {
    storage::NativeFieldArtifactWriter writer(
        directory,
        {.max_total_bytes = physical_bytes, .min_free_bytes = 1},
        spartan::factored_matrix_staging_artifact_identity(structure));
    for (std::size_t tensor = 0; tensor < tensors.size(); ++tensor) {
        for (std::size_t digit = 0;
             digit < tensors[tensor].digit_columns.size(); ++digit) {
            const std::vector<Fq> &column =
                tensors[tensor].digit_columns[digit];
            writer.begin_array(
                spartan::factored_matrix_tensor_column_array_name(tensor,
                                                                    digit),
                storage::NativeFieldElementKind::Fq, column.size());
            writer.append(column);
            writer.finish_array();
        }
    }
    (void)writer.finish();
}

std::vector<std::pair<std::string, std::vector<std::uint8_t>>>
directory_bytes(const std::filesystem::path &directory) {
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> result;
    for (const auto &entry : std::filesystem::directory_iterator(directory)) {
        std::ifstream input(entry.path(), std::ios::binary);
        if (!input) {
            throw std::runtime_error("failed to open test artifact file");
        }
        result.emplace_back(
            entry.path().filename().string(),
            std::vector<std::uint8_t>(
                std::istreambuf_iterator<char>(input),
                std::istreambuf_iterator<char>()));
    }
    std::sort(result.begin(), result.end(),
              [](const auto &left, const auto &right) {
                  return left.first < right.first;
              });
    return result;
}

} // namespace

int main() {
    test::Runner runner("test_proof_of_packing_tensor_staging");

    runner.run("streamed artifact has materialized byte and value parity",
               [] {
                   const Fixture fixture;
                   const ProofOfPackingTensorStagingPlan plan =
                       plan_proof_of_packing_tensor_staging(
                           fixture.metadata, fixture.packing_operator,
                           fixture.parameters.packing_radix, 3);
                   TemporaryDirectory streamed_directory("streamed");
                   ProofOfPackingTensorStaging streamed =
                       write_proof_of_packing_tensor_staging(
                           fixture.metadata, fixture.packing_operator,
                           fixture.encoders(),
                           fixture.parameters.packing_radix,
                           options_for(streamed_directory.path(), plan));

                   const std::vector<PackingTensor> materialized =
                       fixture.materialized_tensors();
                   CHECK(materialized.size() ==
                         streamed.structure->tensor_count());
                   for (std::size_t tensor = 0; tensor < materialized.size();
                        ++tensor) {
                       for (std::size_t digit = 0;
                            digit < materialized[tensor].digit_columns.size();
                            ++digit) {
                           CHECK(read_array(
                                     *streamed.artifact,
                                     spartan::
                                         factored_matrix_tensor_column_array_name(
                                             tensor, digit)) ==
                                 materialized[tensor].digit_columns[digit]);
                       }
                   }

                   TemporaryDirectory reference_directory("reference");
                   write_materialized_reference(
                       reference_directory.path(), *streamed.structure,
                       materialized, plan.artifact_physical_bytes);
                   CHECK(directory_bytes(streamed_directory.path()) ==
                         directory_bytes(reference_directory.path()));
               });

    runner.run("report exactly realizes the formula-only plan", [] {
        const Fixture fixture;
        const ProofOfPackingTensorStagingPlan plan =
            plan_proof_of_packing_tensor_staging(
                fixture.metadata, fixture.packing_operator,
                fixture.parameters.packing_radix, 5);
        TemporaryDirectory directory("report");
        const ProofOfPackingTensorStaging staged =
            write_proof_of_packing_tensor_staging(
                fixture.metadata, fixture.packing_operator,
                fixture.encoders(), fixture.parameters.packing_radix,
                options_for(directory.path(), plan));
        CHECK(staged.report.plan == plan);
        CHECK(staged.report.centered_masks_encoded ==
              plan.encoder_invocations);
        CHECK(staged.report.signed_digit_masks_derived ==
              plan.encoder_invocations);
        CHECK(staged.report.native_digit_polynomials_encoded ==
              plan.encoder_invocations);
        CHECK(staged.report.live_coordinates_written ==
              plan.live_coordinates);
        CHECK(staged.report.padded_zero_coordinates_written ==
              plan.padded_zero_coordinates);
        CHECK(staged.report.append_operations == plan.append_operations);
        CHECK(staged.report.artifact_physical_bytes ==
              plan.artifact_physical_bytes);
        CHECK(staged.report.artifact_validation_bytes ==
              plan.artifact_physical_bytes);
        CHECK(staged.artifact->physical_bytes() ==
              plan.artifact_physical_bytes);
        CHECK(plan.peak_working_bytes < plan.artifact_payload_bytes);
    });

    runner.run("target tensor setup is admitted by formulas only", [] {
        constexpr std::size_t kRingDegree = 1U << 14U;
        constexpr std::size_t kAlignedCiphertexts = 517;
        const PackingLayout layout =
            make_fixed_message_coset_packing_layout(
                kRingDegree, kAlignedCiphertexts,
                kRingDegree / fhe::kFixedMessageCellCount);
        const ProofOfPackingStructuredMetadata metadata =
            make_proof_of_packing_structured_metadata(
                layout, selected_lazy_ternary_parameters());

        // No encoder is supplied and no destination exists: this call can
        // only derive compact mappings and exact formulas.
        const ProofOfPackingTensorStagingPlan plan =
            plan_proof_of_packing_tensor_staging(
                metadata, metadata.packing_operator,
                metadata.parameters.packing_radix, 4'096);
        CHECK(plan.array_count == 4);
        CHECK(plan.geometry.total_live_elements == 33'882'112ULL);
        CHECK(plan.geometry.total_padded_elements == 67'108'864ULL);
        CHECK(plan.artifact_payload_bytes == 536'870'912ULL);
        CHECK(plan.artifact_physical_bytes == 536'871'816ULL);
        CHECK(plan.output_buffer_bytes == 32'768ULL);
        CHECK(plan.peak_working_bytes == 688'128ULL);
        CHECK(plan.encoder_invocations == 2'068ULL);
        CHECK(plan.live_coordinates == 33'882'112ULL);
        CHECK(plan.padded_zero_coordinates == 33'226'752ULL);
        CHECK(plan.append_operations == 16'384ULL);
    });

    runner.run("storage cap minus one rejects before encoding or writing",
               [] {
                   const Fixture fixture;
                   const ProofOfPackingTensorStagingPlan plan =
                       plan_proof_of_packing_tensor_staging(
                           fixture.metadata, fixture.packing_operator,
                           fixture.parameters.packing_radix, 3);
                   TemporaryDirectory directory("storage-cap");
                   auto encoder_calls = std::make_shared<std::size_t>(0);
                   ProofOfPackingR1csEncoders encoders{
                       .centered_coefficients =
                           [encoder_calls](const fhe::SlotVector &slots) {
                               ++*encoder_calls;
                               return test_centered_coefficients(slots);
                           },
                       .native_ntt =
                           [encoder_calls](
                               std::span<const std::int64_t> coefficients) {
                               ++*encoder_calls;
                               return test_native_ntt(coefficients);
                           },
                   };
                   auto options = options_for(directory.path(), plan);
                   --options.storage_limits.max_total_bytes;
                   CHECK(rejects_as([&] {
                       (void)write_proof_of_packing_tensor_staging(
                           fixture.metadata, fixture.packing_operator,
                           encoders, fixture.parameters.packing_radix,
                           options);
                   }));
                   CHECK(*encoder_calls == 0);
                   CHECK(std::filesystem::is_empty(directory.path()));
               });

    runner.run("working cap is exact and rejects before encoding", [] {
        const Fixture fixture;
        const ProofOfPackingTensorStagingPlan plan =
            plan_proof_of_packing_tensor_staging(
                fixture.metadata, fixture.packing_operator,
                fixture.parameters.packing_radix, 3);
        TemporaryDirectory directory("working-cap");
        auto encoder_calls = std::make_shared<std::size_t>(0);
        ProofOfPackingR1csEncoders encoders{
            .centered_coefficients =
                [encoder_calls](const fhe::SlotVector &slots) {
                    ++*encoder_calls;
                    return test_centered_coefficients(slots);
                },
            .native_ntt =
                [encoder_calls](
                    std::span<const std::int64_t> coefficients) {
                    ++*encoder_calls;
                    return test_native_ntt(coefficients);
                },
        };
        auto options = options_for(directory.path(), plan);
        --options.max_working_bytes;
        CHECK(rejects_as([&] {
            (void)write_proof_of_packing_tensor_staging(
                fixture.metadata, fixture.packing_operator, encoders,
                fixture.parameters.packing_radix, options);
        }));
        CHECK(*encoder_calls == 0);
        CHECK(std::filesystem::is_empty(directory.path()));
    });

    runner.run("encoder failure restores destination to empty", [] {
        const Fixture fixture;
        const ProofOfPackingTensorStagingPlan plan =
            plan_proof_of_packing_tensor_staging(
                fixture.metadata, fixture.packing_operator,
                fixture.parameters.packing_radix, 3);
        TemporaryDirectory directory("encoder-failure");
        auto native_calls = std::make_shared<std::size_t>(0);
        ProofOfPackingR1csEncoders encoders{
            .centered_coefficients = test_centered_coefficients,
            .native_ntt =
                [native_calls](
                    std::span<const std::int64_t> coefficients) {
                    ++*native_calls;
                    if (*native_calls == 4) {
                        throw std::runtime_error(
                            "injected NTT encoder failure");
                    }
                    return test_native_ntt(coefficients);
                },
        };
        CHECK(rejects_as<std::runtime_error>([&] {
            (void)write_proof_of_packing_tensor_staging(
                fixture.metadata, fixture.packing_operator, encoders,
                fixture.parameters.packing_radix,
                options_for(directory.path(), plan));
        }));
        CHECK(*native_calls == 4);
        CHECK(std::filesystem::is_empty(directory.path()));
    });

    runner.run("noncanonical native residue is rejected transactionally",
               [] {
                   const Fixture fixture;
                   const ProofOfPackingTensorStagingPlan plan =
                       plan_proof_of_packing_tensor_staging(
                           fixture.metadata, fixture.packing_operator,
                           fixture.parameters.packing_radix, 3);
                   TemporaryDirectory directory("noncanonical-native");
                   auto native_calls = std::make_shared<std::size_t>(0);
                   ProofOfPackingR1csEncoders encoders{
                       .centered_coefficients = test_centered_coefficients,
                       .native_ntt =
                           [native_calls](std::span<const std::int64_t>
                                              coefficients) {
                               ++*native_calls;
                               std::vector<std::uint64_t> result =
                                   test_native_ntt(coefficients);
                               if (*native_calls == 4) {
                                   result.front() = kOuterFieldOrder;
                               }
                               return result;
                           },
                   };
                   CHECK(rejects_as<std::invalid_argument>([&] {
                       (void)write_proof_of_packing_tensor_staging(
                           fixture.metadata, fixture.packing_operator,
                           encoders, fixture.parameters.packing_radix,
                           options_for(directory.path(), plan));
                   }));
                   CHECK(*native_calls == 4);
                   CHECK(std::filesystem::is_empty(directory.path()));
               });

    return runner.summary();
}
