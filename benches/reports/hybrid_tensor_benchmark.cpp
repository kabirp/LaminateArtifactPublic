/// @file hybrid_tensor_benchmark.cpp
/// @brief Hybrid tensor verifier calibration and prover resource projection.

#include "benchmark_support.hpp"

#include "laminate/bench/schedule_cost.hpp"
#include "laminate/field/serialization.hpp"
#include "laminate/packing/evaluation/lazy_ternary.hpp"
#include "laminate/packing/analysis/operator.hpp"
#include "laminate/packing/outer_relation/tensor.hpp"
#include "laminate/packing/proof/r1cs/layout.hpp"
#include "laminate/packing/proof/matrix/oracle.hpp"
#include "laminate/packing/proof/r1cs.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/fixtures/workloads.hpp"
#include "laminate/spartan/factored.hpp"
#include "laminate/transcript/transcript.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef LAMINATE_GIT_COMMIT
#define LAMINATE_GIT_COMMIT "unknown"
#endif
#ifndef LAMINATE_GIT_DIRTY
#define LAMINATE_GIT_DIRTY "unknown"
#endif
#ifndef LAMINATE_BUILD_TYPE
#define LAMINATE_BUILD_TYPE "unknown"
#endif
#ifndef LAMINATE_COMPILER
#define LAMINATE_COMPILER "unknown"
#endif

namespace {

using laminate::Digest;
using laminate::Fq;
using laminate::Fq2;
using laminate::Transcript;
using laminate::bench::Record;
using laminate::bench::ScheduleFormula;
using laminate::bench::ScheduleProtocol;
using laminate::bench::Timing;
using laminate::bench::emit_samples;
using laminate::bench::exact_command;
using laminate::bench::parse_size;
using laminate::bench::system_info;
using laminate::bench::timed;
using laminate::bench::timed_void;
using namespace laminate::packing;
using namespace laminate::payload;
using namespace laminate::spartan;

constexpr std::string_view kTranscriptDomain =
    "laminate/benchmark/hybrid-tensor/v1";

struct Options {
    ScheduleProtocol protocol = ScheduleProtocol::Folded;
    std::size_t slots = 1U << 14U;
    std::size_t lanes = 1U << 12U;
    std::size_t depth = laminate::kMaximumPayloadMultiplicativeDepth;
    std::size_t width = laminate::kBenchmarkDiamondMiddleWidth;
    std::size_t sample_entry_log = 20;
    std::size_t log_rate =
        laminate::kTranscriptPackingBaseFoldLogRate;
    std::size_t query_count =
        laminate::kTranscriptPackingBaseFoldQueries;
    std::size_t iterations = 3;
};

ScheduleProtocol parse_protocol(std::string_view value) {
    if (value == "folded") {
        return ScheduleProtocol::Folded;
    }
    if (value == "laned") {
        return ScheduleProtocol::Laned;
    }
    throw std::invalid_argument("--protocol must be folded or laned");
}

std::optional<Options> parse_options(int argc, char **argv) {
    Options result;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help" || argument == "-h") {
            std::cout
                << "Usage: laminate_hybrid_tensor_bench [options]\n"
                << "  --protocol folded|laned\n"
                << "  --slots N --lanes B --depth d --width W\n"
                << "  --sample-entry-log S --log-rate R\n"
                << "  --query-count Q --iterations I\n";
            return std::nullopt;
        }
        if (++index == argc) {
            throw std::invalid_argument(std::string(argument) +
                                        " requires a value");
        }
        const std::string_view value(argv[index]);
        if (argument == "--protocol") {
            result.protocol = parse_protocol(value);
        } else if (argument == "--slots") {
            result.slots = parse_size(value, argument);
        } else if (argument == "--lanes") {
            result.lanes = parse_size(value, argument);
        } else if (argument == "--depth") {
            result.depth = parse_size(value, argument);
        } else if (argument == "--width") {
            result.width = parse_size(value, argument);
        } else if (argument == "--sample-entry-log") {
            result.sample_entry_log = parse_size(value, argument);
        } else if (argument == "--log-rate") {
            result.log_rate = parse_size(value, argument);
        } else if (argument == "--query-count") {
            result.query_count = parse_size(value, argument);
        } else if (argument == "--iterations") {
            result.iterations = parse_size(value, argument);
        } else {
            throw std::invalid_argument("unknown option: " +
                                        std::string(argument));
        }
    }

    const std::size_t bits = std::numeric_limits<std::size_t>::digits;
    if (!std::has_single_bit(result.slots) || result.slots < 32 ||
        result.depth == 0 ||
        result.depth > laminate::kMaximumPayloadMultiplicativeDepth ||
        result.width == 0 ||
        result.sample_entry_log >= bits || result.log_rate == 0 ||
        result.log_rate >= bits || result.query_count == 0 ||
        result.query_count > std::numeric_limits<std::uint32_t>::max() ||
        result.iterations == 0 ||
        result.sample_entry_log + result.log_rate >
            laminate::kOuterFieldTwoAdicity) {
        throw std::invalid_argument("invalid hybrid calibration dimensions");
    }
    if (result.protocol == ScheduleProtocol::Laned &&
        (!std::has_single_bit(result.lanes) ||
         result.lanes > result.slots)) {
        throw std::invalid_argument(
            "Laned requires a power-of-two 1 <= B <= N");
    }
    return result;
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(label);
    }
    return left + right;
}

std::uint64_t checked_mul(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(label);
    }
    return left * right;
}

std::size_t as_size(std::uint64_t value, const char *label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(label);
    }
    return static_cast<std::size_t>(value);
}

std::size_t next_power_of_two(std::uint64_t value, const char *label) {
    const std::size_t size = as_size(value, label);
    if (size == 0 ||
        size > (std::numeric_limits<std::size_t>::max() >> 1U) + 1U) {
        throw std::overflow_error(label);
    }
    return std::bit_ceil(size);
}

std::size_t log2_exact(std::uint64_t value) {
    if (value == 0 || !std::has_single_bit(value)) {
        throw std::invalid_argument("tensor size is not a power of two");
    }
    return static_cast<std::size_t>(std::bit_width(value) - 1U);
}

std::vector<Fq2> point(std::size_t variables, std::uint64_t seed) {
    std::vector<Fq2> result;
    result.reserve(variables);
    for (std::size_t index = 0; index < variables; ++index) {
        result.push_back(Fq2({Fq(seed + 5U * index + 1U),
                             Fq(seed + 7U * index + 3U)}));
    }
    return result;
}

ScheduleFormula make_schedule(ScheduleProtocol protocol,
                              const LayeredCircuit &circuit) {
    return protocol == ScheduleProtocol::Folded
               ? laminate::bench::folded_schedule_formula(circuit)
               : laminate::bench::laned_schedule_formula(circuit);
}

std::size_t aligned_ciphertext_count(const Options &options) {
    const PayloadShape shape =
        options.protocol == ScheduleProtocol::Laned
            ? PayloadShape::laned(options.lanes, options.slots)
            : PayloadShape::wide(options.slots);
    const Workload workload = make_workload(WorkloadSpec{
        WorkloadKind::Diamond, shape, options.depth, options.width, 1});
    const LayeredCircuit circuit = compile(workload.circuit);
    const ScheduleFormula schedule = make_schedule(options.protocol, circuit);
    return as_size(schedule.operations.aligned_round_ciphertexts,
                   "aligned ciphertext count exceeds size_t");
}

struct TargetCase {
    std::size_t aligned_ciphertexts = 0;
    PackingLayout packing_layout;
    PackingLinearOperator packing_operator;
    OuterRelationPlan relation_plan;
    ProofOfPackingR1csLayout r1cs_layout;
    ProofOfPackingR1csLedger ledger;
    R1csMetadata metadata;
    PackingTensorGeometry geometry;
    std::vector<PackingTensor> descriptors;
    std::shared_ptr<const FactoredMatrixStructure> structure;
};

TargetCase make_target_case(const Options &options) {
    TargetCase result;
    result.aligned_ciphertexts = aligned_ciphertext_count(options);
    result.packing_layout = make_fixed_message_coset_packing_layout(
        options.slots, result.aligned_ciphertexts,
        options.slots / laminate::fhe::kFixedMessageCellCount);
    result.packing_operator =
        make_packing_linear_operator(result.packing_layout);
    const LazyTernaryParameters parameters =
        selected_lazy_ternary_parameters();
    result.relation_plan = make_outer_relation_plan(OuterRelationShape{
        .native_modulus = laminate::kOuterFieldOrder,
        .ring_degree = options.slots,
        .aligned_ciphertexts =
            result.packing_operator.aligned_ciphertext_count,
        .repetitions = parameters.repetitions,
        .logical_packed_outputs = result.packing_layout.packed_ciphertext_count,
        .packing_digit_count = parameters.packing_radix.digit_count,
        .ciphertext_components = 2,
        .public_input_capacity_bits = 59,
    });
    result.r1cs_layout =
        make_proof_of_packing_r1cs_layout(result.relation_plan);
    result.ledger = proof_of_packing_r1cs_ledger(result.relation_plan);

    const R1csShape shape{
        .constraints = result.ledger.matrix_rows,
        .public_inputs = result.ledger.total_public_inputs,
        .witness_variables = result.ledger.total_witness_variables,
    };
    const std::size_t padded_constraints = next_power_of_two(
        shape.constraints, "padded constraint count overflows");
    const std::uint64_t public_side = checked_add(
        shape.public_inputs, 1U, "public assignment side overflows");
    const std::size_t assignment_half = next_power_of_two(
        std::max(public_side, shape.witness_variables),
        "padded assignment side overflows");
    result.metadata = R1csMetadata(
        shape, padded_constraints, assignment_half, Digest{});

    std::vector<std::size_t> owner_counts;
    owner_counts.reserve(result.packing_operator.rows.size());
    for (const PackingLinearOperator::OutputRow &row :
         result.packing_operator.rows) {
        owner_counts.push_back(row.contributions.size());
    }
    result.geometry = packing_tensor_geometry(
        owner_counts, options.slots, parameters.packing_radix.digit_count,
        laminate::kSerializedFqBytes);
    result.descriptors.reserve(result.geometry.outputs.size());
    for (std::size_t output = 0; output < result.geometry.outputs.size();
         ++output) {
        PackingTensor tensor;
        tensor.descriptor = result.geometry.outputs[output];
        for (const PackingLinearOperator::AlignedCiphertext &contribution :
             result.packing_operator.rows[output].contributions) {
            tensor.global_owners.push_back(contribution.aligned_index);
        }
        result.descriptors.push_back(std::move(tensor));
    }
    result.structure = make_proof_of_packing_factored_structure(
        result.relation_plan, result.r1cs_layout, result.descriptors,
        result.metadata);
    return result;
}

class CalibrationStructure final : public FactoredMatrixStructure {
  public:
    CalibrationStructure(std::uint64_t row_variables,
                         std::uint64_t column_variables,
                         std::vector<FactoredTensorShape> shapes)
        : row_variables_(row_variables),
          column_variables_(column_variables), shapes_(std::move(shapes)) {
        structure_digest_[0] = 0xc1;
        structure_digest_[1] = static_cast<std::uint8_t>(shapes_.size());
        for (const FactoredTensorShape &shape : shapes_) {
            structure_digest_[2] ^=
                static_cast<std::uint8_t>(shape.evaluation_count);
            structure_digest_[3] ^=
                static_cast<std::uint8_t>(shape.column_count);
        }
    }

    Digest circuit_digest() const override { return {}; }
    Digest structure_digest() const override { return structure_digest_; }
    std::uint64_t row_variables() const override { return row_variables_; }
    std::uint64_t column_variables() const override {
        return column_variables_;
    }
    std::size_t tensor_count() const override { return shapes_.size(); }
    FactoredTensorShape tensor_shape(
        std::size_t tensor_index) const override {
        return shapes_.at(tensor_index);
    }

    laminate::spartan::FactoredTensorOperandWorkingSet
    tensor_operand_working_set(
        std::size_t tensor_index) const override {
        const FactoredTensorShape shape = shapes_.at(tensor_index);
        const std::uint64_t variables =
            std::bit_width(shape.evaluation_count) - 1U;
        const std::uint64_t factor_fields = 2U * variables;
        return {
            .materialization_peak_field_bytes =
                (shape.evaluation_count + factor_fields) * sizeof(Fq2),
            .compact_evaluation_peak_field_bytes =
                factor_fields * sizeof(Fq2),
        };
    }

    std::array<Fq2, 3> regular_matrix_evaluations(
        std::span<const Fq2> row_point,
        std::span<const Fq2> column_point) const override {
        validate_points(row_point, column_point);
        return {};
    }

    std::vector<Fq2> tensor_column_weights(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point,
        const Fq2 &gamma) const override {
        validate_points(row_point, column_point);
        const std::size_t width = as_size(
            shapes_.at(tensor_index).column_count,
            "calibration tensor width exceeds size_t");
        std::vector<Fq2> result;
        result.reserve(width);
        for (std::size_t column = 0; column < width; ++column) {
            result.push_back(
                gamma + row_point[(tensor_index + column) %
                                  row_point.size()] +
                column_point[(2U * tensor_index + column) %
                             column_point.size()] +
                Fq(static_cast<std::uint64_t>(column + 1U)));
        }
        return result;
    }

    std::vector<Fq2> materialize_tensor_operand(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point,
        const Fq2 &gamma) const override {
        validate_points(row_point, column_point);
        const auto factors = bit_factors(
            tensor_index, row_point, column_point, gamma);
        const std::size_t count = as_size(
            shapes_.at(tensor_index).evaluation_count,
            "calibration tensor size exceeds size_t");
        std::vector<Fq2> result(count, Fq2::zero());
        result[0] = scale(tensor_index, gamma);
        std::size_t active = 1;
        for (const auto &factor : factors) {
            for (std::size_t index = active; index-- > 0;) {
                const Fq2 previous = result[index];
                result[2U * index] = previous * factor[0];
                result[2U * index + 1U] = previous * factor[1];
            }
            active *= 2U;
        }
        return result;
    }

    Fq2 evaluate_tensor_operand(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point, const Fq2 &gamma,
        std::span<const Fq2> tensor_point) const override {
        validate_points(row_point, column_point);
        const auto factors = bit_factors(
            tensor_index, row_point, column_point, gamma);
        if (tensor_point.size() != factors.size()) {
            throw std::invalid_argument(
                "calibration tensor point has wrong dimension");
        }
        Fq2 result = scale(tensor_index, gamma);
        for (std::size_t bit = 0; bit < factors.size(); ++bit) {
            result *= (Fq2::one() - tensor_point[bit]) * factors[bit][0] +
                      tensor_point[bit] * factors[bit][1];
        }
        return result;
    }

  private:
    using Factor = std::array<Fq2, 2>;

    void validate_points(std::span<const Fq2> row_point,
                         std::span<const Fq2> column_point) const {
        if (row_point.size() != row_variables_ || row_point.empty() ||
            column_point.size() != column_variables_ ||
            column_point.empty()) {
            throw std::invalid_argument(
                "calibration matrix point has wrong dimension");
        }
    }

    std::vector<Factor> bit_factors(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point, const Fq2 &gamma) const {
        const std::size_t variables =
            log2_exact(shapes_.at(tensor_index).evaluation_count);
        std::vector<Factor> result;
        result.reserve(variables);
        for (std::size_t bit = 0; bit < variables; ++bit) {
            const Fq2 left = row_point[(tensor_index + bit) %
                                       row_point.size()];
            const Fq2 right = column_point[(tensor_index + bit) %
                                           column_point.size()];
            result.push_back(
                {Fq2::one() - left, right + gamma + Fq(bit + 1U)});
        }
        return result;
    }

    static Fq2 scale(std::size_t tensor_index, const Fq2 &gamma) {
        return gamma + Fq(static_cast<std::uint64_t>(tensor_index + 1U));
    }

    std::uint64_t row_variables_ = 0;
    std::uint64_t column_variables_ = 0;
    std::vector<FactoredTensorShape> shapes_;
    Digest structure_digest_{};
};

std::vector<std::vector<std::vector<Fq>>> sample_columns(
    std::span<const FactoredTensorShape> shapes) {
    std::vector<std::vector<std::vector<Fq>>> result;
    result.resize(shapes.size());
    for (std::size_t tensor_index = 0; tensor_index < shapes.size();
         ++tensor_index) {
        const std::size_t width = as_size(
            shapes[tensor_index].column_count,
            "sample tensor width exceeds size_t");
        const std::size_t count = as_size(
            shapes[tensor_index].evaluation_count,
            "sample tensor size exceeds size_t");
        result[tensor_index].resize(width);
        for (std::size_t column = 0; column < width; ++column) {
            result[tensor_index][column].resize(count);
            for (std::size_t index = 0; index < count; ++index) {
                result[tensor_index][column][index] = Fq(
                    7U + 17U * tensor_index + 11U * column +
                    5U * index + 3U * column * index);
            }
        }
    }
    return result;
}

Fq2 direct_sample_claim(
    const CalibrationStructure &structure,
    const std::vector<std::vector<std::vector<Fq>>> &columns,
    std::span<const Fq2> row_point,
    std::span<const Fq2> column_point, const Fq2 &gamma) {
    Fq2 result = Fq2::zero();
    for (std::size_t tensor_index = 0;
         tensor_index < columns.size(); ++tensor_index) {
        const std::vector<Fq2> weights =
            structure.tensor_column_weights(
                tensor_index, row_point, column_point, gamma);
        const std::vector<Fq2> operand =
            structure.materialize_tensor_operand(
                tensor_index, row_point, column_point, gamma);
        for (std::size_t index = 0; index < operand.size(); ++index) {
            Fq2 tensor_value = Fq2::zero();
            for (std::size_t column = 0; column < weights.size(); ++column) {
                tensor_value += weights[column] *
                                columns[tensor_index][column][index];
            }
            result += tensor_value * operand[index];
        }
    }
    return result;
}

FactoredMatrixCommitment target_commitment(
    const TargetCase &target, const BaseFoldPcsParameters &parameters) {
    FactoredMatrixCommitment result{
        .profile = kFactoredMatrixProfileIdentifier,
        .circuit_digest = target.structure->circuit_digest(),
        .structure_digest = target.structure->structure_digest(),
        .row_variables = target.structure->row_variables(),
        .column_variables = target.structure->column_variables(),
    };
    result.tensors.reserve(target.structure->tensor_count());
    for (std::size_t tensor_index = 0;
         tensor_index < target.structure->tensor_count(); ++tensor_index) {
        const FactoredTensorShape shape =
            target.structure->tensor_shape(tensor_index);
        result.tensors.push_back(FactoredTensorCommitment{
            .shape = shape,
            .columns = PcsCommitment{
                .scheme = BaseFoldPcs::kSchemeIdentifier,
                .root = {},
                .evaluation_count = shape.evaluation_count,
                .width = shape.column_count,
                .log_rate = static_cast<std::uint32_t>(parameters.log_rate),
                .query_count =
                    static_cast<std::uint32_t>(parameters.query_count),
            },
        });
    }
    return result;
}

struct ResourceProjection {
    std::uint64_t rate = 0;
    std::uint64_t retained_field_bytes = 0;
    std::uint64_t retained_merkle_bytes = 0;
    std::uint64_t retained_payload_bytes = 0;
    std::uint64_t online_peak_transient_bytes = 0;
    std::uint64_t online_peak_payload_bytes = 0;
    std::uint64_t committed_field_reads = 0;
    std::uint64_t operand_fq2_materializations = 0;
    long double preprocessing_work_units = 0;
};

ResourceProjection resources(
    std::span<const FactoredTensorShape> shapes,
    std::uint64_t padded_bytes, std::size_t log_rate) {
    ResourceProjection result;
    result.rate = std::uint64_t{1} << log_rate;
    result.retained_field_bytes = checked_mul(
        padded_bytes, 2U + result.rate,
        "retained tensor field state overflows");

    std::uint64_t maximum_transient = 0;
    std::uint64_t total_evaluations = 0;
    std::uint64_t padded_elements = 0;
    for (const FactoredTensorShape &shape : shapes) {
        const std::uint64_t codeword = checked_mul(
            shape.evaluation_count, result.rate,
            "BaseFold codeword size overflows");
        const std::uint64_t leaf_size = std::min<std::uint64_t>(codeword, 64);
        const std::uint64_t leaves = codeword / leaf_size;
        const std::uint64_t nodes = 2U * leaves - 1U;
        result.retained_merkle_bytes = checked_add(
            result.retained_merkle_bytes,
            checked_mul(nodes, 40U, "Merkle state size overflows"),
            "Merkle state size overflows");
        total_evaluations = checked_add(
            total_evaluations, shape.evaluation_count,
            "tensor evaluation count overflows");
        padded_elements = checked_add(
            padded_elements,
            checked_mul(shape.evaluation_count, shape.column_count,
                        "padded tensor element count overflows"),
            "padded tensor element count overflows");

        const std::uint64_t product_tables = checked_mul(
            checked_mul(2U, shape.evaluation_count,
                        "product table memory overflows"),
            sizeof(Fq2), "product table memory overflows");
        // Opening starts with a weighted message, equality operand, and
        // rate-expanded weighted codeword. The two fold tables then share one
        // allocation, and the weighted base codeword is released before
        // folded Merkle state accumulates.
        const std::uint64_t opening_fq2_per_entry =
            std::max(result.rate + 2U, 2U * result.rate);
        const std::uint64_t opening_tables = checked_mul(
            checked_mul(opening_fq2_per_entry, shape.evaluation_count,
                        "opening table memory overflows"),
            sizeof(Fq2), "opening table memory overflows");
        maximum_transient = std::max(
            maximum_transient, std::max(product_tables, opening_tables));

        const std::uint64_t codeword_log = log2_exact(codeword);
        result.preprocessing_work_units +=
            static_cast<long double>(shape.column_count) *
            (static_cast<long double>(codeword) +
             static_cast<long double>(codeword / 2U) * codeword_log);
    }
    result.retained_payload_bytes = checked_add(
        result.retained_field_bytes, result.retained_merkle_bytes,
        "retained tensor payload overflows");
    result.online_peak_transient_bytes = maximum_transient;
    result.online_peak_payload_bytes = checked_add(
        result.retained_payload_bytes, maximum_transient,
        "online peak tensor payload overflows");
    result.committed_field_reads = checked_mul(
        3U + result.rate, padded_elements,
        "online committed field reads overflow");
    result.operand_fq2_materializations = checked_mul(
        3U, total_evaluations,
        "operand materialization count overflows");
    return result;
}

std::string memory_assessment(std::uint64_t bytes) {
    constexpr std::uint64_t kComfortable = 8ULL << 30U;
    constexpr std::uint64_t kReassess = 16ULL << 30U;
    if (bytes <= kComfortable) {
        return "single-digit-gib-hybrid-layer";
    }
    if (bytes <= kReassess) {
        return "material-but-below-reassessment-threshold";
    }
    return "reassess-hybrid-layer-memory";
}

std::string time_assessment(double milliseconds) {
    if (milliseconds <= 60'000.0) {
        return "under-one-minute-projection";
    }
    if (milliseconds <= 600'000.0) {
        return "material-one-to-ten-minute-projection";
    }
    return "reassess-hybrid-layer-time";
}

int run(const Options &options, int argc, char **argv) {
    const auto [target, geometry_timing] =
        timed([&] { return make_target_case(options); });
    const BaseFoldPcsParameters parameters{
        .log_rate = options.log_rate,
        .query_count = options.query_count,
    };
    const BaseFoldPcs pcs(parameters);

    std::vector<FactoredTensorShape> target_shapes;
    std::vector<FactoredTensorShape> sample_shapes;
    target_shapes.reserve(target.structure->tensor_count());
    sample_shapes.reserve(target.structure->tensor_count());
    for (std::size_t tensor_index = 0;
         tensor_index < target.structure->tensor_count(); ++tensor_index) {
        const FactoredTensorShape shape =
            target.structure->tensor_shape(tensor_index);
        const std::size_t target_log = log2_exact(shape.evaluation_count);
        if (target_log + options.log_rate >
            laminate::kOuterFieldTwoAdicity) {
            throw std::invalid_argument(
                "target tensor exceeds BaseFold two-adicity");
        }
        target_shapes.push_back(shape);
        const std::size_t sample_log =
            std::min(options.sample_entry_log, target_log);
        sample_shapes.push_back(FactoredTensorShape{
            .evaluation_count = std::uint64_t{1} << sample_log,
            .column_count = shape.column_count,
        });
    }

    std::vector<Fq2> target_row =
        point(as_size(target.structure->row_variables(),
                      "target row variables exceed size_t"),
              101U);
    std::vector<Fq2> target_column =
        point(as_size(target.structure->column_variables(),
                      "target column variables exceed size_t"),
              503U);
    const Fq2 gamma({Fq(809U), Fq(811U)});

    std::vector<double> regular_samples;
    regular_samples.reserve(options.iterations);
    std::array<Fq2, 3> regular_checksum{};
    for (std::size_t iteration = 0; iteration < options.iterations;
         ++iteration) {
        const Timing timing = timed_void([&] {
            const auto values = target.structure->regular_matrix_evaluations(
                target_row, target_column);
            for (std::size_t matrix = 0; matrix < values.size(); ++matrix) {
                regular_checksum[matrix] += values[matrix];
            }
        });
        regular_samples.push_back(timing.wall_ms);
        target_row[0] += Fq2::from_base(Fq(iteration + 1U));
    }

    std::vector<std::vector<Fq2>> target_tensor_points;
    target_tensor_points.reserve(target_shapes.size());
    for (std::size_t tensor_index = 0;
         tensor_index < target_shapes.size(); ++tensor_index) {
        target_tensor_points.push_back(point(
            log2_exact(target_shapes[tensor_index].evaluation_count),
            1'001U + 101U * tensor_index));
    }
    std::vector<double> operand_samples;
    operand_samples.reserve(options.iterations);
    Fq2 operand_checksum = Fq2::zero();
    for (std::size_t iteration = 0; iteration < options.iterations;
         ++iteration) {
        const Timing timing = timed_void([&] {
            for (std::size_t tensor_index = 0;
                 tensor_index < target_shapes.size(); ++tensor_index) {
                operand_checksum += target.structure->evaluate_tensor_operand(
                    tensor_index, target_row, target_column, gamma,
                    target_tensor_points[tensor_index]);
            }
        });
        operand_samples.push_back(timing.wall_ms);
        target_column[0] += Fq2::from_base(Fq(iteration + 17U));
    }

    auto sample_structure = std::make_shared<const CalibrationStructure>(
        target.structure->row_variables(),
        target.structure->column_variables(), sample_shapes);
    std::vector<std::vector<std::vector<Fq>>> columns =
        sample_columns(sample_shapes);
    const std::vector<Fq2> sample_row =
        point(as_size(sample_structure->row_variables(),
                      "sample row variables exceed size_t"),
              2'003U);
    const std::vector<Fq2> sample_column =
        point(as_size(sample_structure->column_variables(),
                      "sample column variables exceed size_t"),
              3'007U);
    const Fq2 sample_claim = direct_sample_claim(
        *sample_structure, columns, sample_row, sample_column, gamma);
    const auto [sample_setup, preprocess_timing] = timed([&] {
        return preprocess_factored_matrix(
            sample_structure, std::move(columns), pcs);
    });
    Transcript prover(kTranscriptDomain);
    const auto [proof, prove_timing] = timed([&] {
        return prove_factored_matrix_evaluation(
            sample_setup.prover_key, sample_row, sample_column, gamma,
            sample_claim, pcs, prover);
    });
    const std::size_t sample_proof_bytes =
        factored_matrix_evaluation_proof_size_bytes(proof);
    const std::size_t sample_proof_max_bytes =
        factored_matrix_evaluation_proof_max_size_bytes(
            sample_setup.verifier_key.commitment, parameters);
    if (sample_proof_bytes > sample_proof_max_bytes) {
        throw std::logic_error(
            "sample factored proof exceeds its setup-derived maximum");
    }

    std::vector<double> verify_samples;
    verify_samples.reserve(options.iterations);
    for (std::size_t iteration = 0; iteration < options.iterations;
         ++iteration) {
        Transcript verifier(kTranscriptDomain);
        bool accepted = false;
        const Timing timing = timed_void([&] {
            accepted = verify_factored_matrix_evaluation(
                sample_setup.verifier_key, sample_row, sample_column,
                gamma, sample_claim, proof, pcs, verifier);
        });
        if (!accepted) {
            throw std::logic_error(
                "factored verifier rejected the calibration proof");
        }
        verify_samples.push_back(timing.wall_ms);
    }

    const FactoredMatrixCommitment projected_commitment =
        target_commitment(target, parameters);
    const std::size_t target_proof_max_bytes =
        factored_matrix_evaluation_proof_max_size_bytes(
            projected_commitment, parameters);
    const ResourceProjection target_resources = resources(
        target_shapes, target.geometry.total_padded_bytes,
        options.log_rate);
    std::uint64_t sample_padded_bytes = 0;
    for (const FactoredTensorShape &shape : sample_shapes) {
        sample_padded_bytes = checked_add(
            sample_padded_bytes,
            checked_mul(
                checked_mul(shape.evaluation_count, shape.column_count,
                            "sample padded element count overflows"),
                laminate::kSerializedFqBytes,
                "sample padded byte count overflows"),
            "sample padded byte count overflows");
    }
    const ResourceProjection sample_resources = resources(
        sample_shapes, sample_padded_bytes, options.log_rate);
    const std::uint64_t target_peak_payload_bytes = checked_add(
        target_resources.online_peak_payload_bytes,
        checked_mul(2U, target_proof_max_bytes,
                    "target proof working set overflows"),
        "target hybrid peak payload overflows");

    const auto regular_summary =
        laminate::bench::summarize(regular_samples);
    const auto operand_summary =
        laminate::bench::summarize(operand_samples);
    const auto verify_summary =
        laminate::bench::summarize(verify_samples);
    const double basefold_verify_upper_sensitivity =
        verify_summary.mean * static_cast<double>(target_proof_max_bytes) /
        static_cast<double>(sample_proof_bytes);
    const double hybrid_verify_upper_sensitivity =
        regular_summary.mean + operand_summary.mean +
        basefold_verify_upper_sensitivity;
    const double prove_projection =
        prove_timing.wall_ms *
        static_cast<double>(target_resources.committed_field_reads) /
        static_cast<double>(sample_resources.committed_field_reads);
    const double preprocess_projection =
        preprocess_timing.wall_ms *
        static_cast<double>(target_resources.preprocessing_work_units /
                            sample_resources.preprocessing_work_units);
    const double verify_upper_sensitivity_ratio =
        static_cast<double>(target_proof_max_bytes) /
        static_cast<double>(sample_proof_bytes);
    const double prove_projection_ratio =
        static_cast<double>(target_resources.committed_field_reads) /
        static_cast<double>(sample_resources.committed_field_reads);
    const double preprocess_projection_ratio =
        static_cast<double>(target_resources.preprocessing_work_units /
                            sample_resources.preprocessing_work_units);

    const Record record;
    record.text("format", "laminate-hybrid-tensor-benchmark-v4");
    record.text("classification.result_kind",
                "full-target-algebra-measurement-and-sampled-basefold-projection");
    record.text("classification.execution", "single-thread");
    record.text("classification.protocol",
                std::string(laminate::bench::schedule_protocol_name(
                    options.protocol)));
    record.text("classification.target_regular_matrix",
                "measured-single-thread-full-target-without-expanded-r1cs-or-coefficient-tensor");
    record.text("classification.target_terminal_operand",
                "measured-single-thread-full-target-compact-formula");
    record.text("classification.sample_factored",
                "measured-single-thread-bounded-entry-domain");
    record.text("classification.sample_operand",
                "synthetic-dense-tensor-product-not-real-segmented-packing-operand");
    record.text("classification.target_verify_upper_sensitivity",
                "single-thread-target-algebra-plus-upper-sensitivity-from-"
                "actual-sample-scaled-by-target-maximum-canonical-proof-"
                "bytes");
    record.text("classification.target_prove_projection",
                "model-projection-from-single-thread-synthetic-operand-sample-scaled-by-committed-field-reads-not-end-to-end-measurement");
    record.text("classification.target_preprocess_projection",
                "single-thread-sample-setup-scaled-by-codeword-and-ntt-work-units");
    record.text("classification.command", exact_command(argc, argv));

    const auto environment = system_info();
    record.text("environment.os", environment.os);
    record.text("environment.cpu", environment.cpu);
    record.integer("environment.ram_bytes", environment.ram_bytes);
    record.integer("environment.peak_rss_bytes", environment.peak_rss_bytes);
    record.text("environment.git_commit", LAMINATE_GIT_COMMIT);
    record.text("environment.git_dirty", LAMINATE_GIT_DIRTY);
    record.text("environment.build_type", LAMINATE_BUILD_TYPE);
    record.text("environment.compiler", LAMINATE_COMPILER);

    record.integer("parameters.N", options.slots);
    if (options.protocol == ScheduleProtocol::Laned) {
        record.integer("parameters.B", options.lanes);
    } else {
        record.text("parameters.B", "not-applicable");
    }
    record.integer("parameters.depth", options.depth);
    record.integer("parameters.width", options.width);
    record.integer("parameters.sample_entry_log", options.sample_entry_log);
    record.integer("parameters.basefold_log_rate", options.log_rate);
    record.integer("parameters.basefold_query_count", options.query_count);
    record.integer("parameters.iterations", options.iterations);
    record.integer("parameters.threads", 1);

    record.integer("geometry.r", target.aligned_ciphertexts);
    record.integer("geometry.aligned_ciphertexts",
                   target.relation_plan.shape.aligned_ciphertexts);
    record.integer("geometry.logical_outputs",
                   target.relation_plan.shape.logical_packed_outputs);
    record.integer("geometry.row_variables",
                   target.structure->row_variables());
    record.integer("geometry.column_variables",
                   target.structure->column_variables());
    record.integer("geometry.tensor_count", target_shapes.size());
    record.integer("geometry.tensor_live_elements",
                   target.geometry.total_live_elements);
    record.integer("geometry.tensor_padded_elements",
                   target.geometry.total_padded_elements);
    record.integer("geometry.tensor_live_bytes",
                   target.geometry.total_live_bytes);
    record.integer("geometry.tensor_padded_bytes",
                   target.geometry.total_padded_bytes);
    record.integer("geometry.sample_tensor_padded_elements",
                   sample_padded_bytes / laminate::kSerializedFqBytes);
    record.integer("geometry.sample_tensor_padded_bytes",
                   sample_padded_bytes);
    for (std::size_t tensor_index = 0;
         tensor_index < target.geometry.outputs.size(); ++tensor_index) {
        const PackingTensorDescriptor &descriptor =
            target.geometry.outputs[tensor_index];
        const std::string prefix =
            "geometry.tensor." + std::to_string(tensor_index);
        record.integer(prefix + ".live_owners",
                       descriptor.live_owner_count);
        record.integer(prefix + ".padded_owners",
                       descriptor.padded_owner_count);
        record.integer(prefix + ".evaluation_count",
                       target_shapes[tensor_index].evaluation_count);
        record.integer(prefix + ".column_count",
                       target_shapes[tensor_index].column_count);
        record.integer(prefix + ".live_bytes", descriptor.live_bytes);
        record.integer(prefix + ".padded_bytes",
                       descriptor.padded_bytes);
    }

    record.integer("memory.target.retained_field_state_bytes_formula",
                   target_resources.retained_field_bytes);
    record.integer("memory.target.retained_merkle_digest_bytes_formula",
                   target_resources.retained_merkle_bytes);
    record.integer("memory.target.retained_payload_bytes_formula",
                   target_resources.retained_payload_bytes);
    record.integer("memory.target.online_peak_transient_bytes_upper_bound",
                   target_resources.online_peak_transient_bytes);
    record.integer("memory.target.online_peak_payload_bytes_upper_bound",
                   target_peak_payload_bytes);
    record.text("memory.target.scope",
                "hybrid-tensor-only-includes-two-proof-copies-excludes-spartan-core-and-container-overhead");

    record.integer("proof.sample_bytes", sample_proof_bytes);
    record.integer("proof.sample_max_bytes", sample_proof_max_bytes);
    record.integer("proof.target_max_bytes_formula",
                   target_proof_max_bytes);
    record.real("timing.geometry_derivation_ms.measured",
                geometry_timing.wall_ms);
    emit_samples(record, "timing.target.regular_matrix_ms.measured",
                 regular_samples);
    emit_samples(record, "timing.target.terminal_operand_ms.measured",
                 operand_samples);
    record.real("timing.sample.preprocess_ms.measured",
                preprocess_timing.wall_ms);
    record.real("timing.sample.prove_ms.measured", prove_timing.wall_ms);
    emit_samples(record, "timing.sample.verify_ms.measured",
                 verify_samples);
    record.real(
        "timing.target.basefold_factored_verify_ms.upper_sensitivity",
        basefold_verify_upper_sensitivity);
    record.real("timing.target.hybrid_verify_ms.upper_sensitivity",
                hybrid_verify_upper_sensitivity);
    record.real("timing.target.preprocess_ms.projected",
                preprocess_projection);
    record.real("timing.target.prove_ms.model_projected", prove_projection);
    record.real("projection.verify.maximum_to_actual_proof_byte_ratio",
                verify_upper_sensitivity_ratio);
    record.real("projection.prove.committed_field_read_ratio",
                prove_projection_ratio);
    record.real("projection.preprocess.work_unit_ratio",
                preprocess_projection_ratio);

    record.integer("work.prover.online_pass_count", 3);
    record.text("work.prover.online_pass_schedule",
                "all-component-claims;product-sumcheck;pcs-opening");
    record.integer("work.prover.raw_payload_pass_equivalents",
                   3U + target_resources.rate);
    record.integer("work.prover.committed_field_reads_formula",
                   target_resources.committed_field_reads);
    record.integer("work.prover.operand_fq2_materializations_formula",
                   target_resources.operand_fq2_materializations);
    record.real("work.prover.preprocessing_work_units_formula",
                static_cast<double>(
                    target_resources.preprocessing_work_units));

    record.integer("checksum.regular.a0",
                   regular_checksum[0].coefficients()[0].value());
    record.integer("checksum.regular.b0",
                   regular_checksum[1].coefficients()[0].value());
    record.integer("checksum.regular.c0",
                   regular_checksum[2].coefficients()[0].value());
    record.integer("checksum.operand.c0",
                   operand_checksum.coefficients()[0].value());
    record.text("assessment.hybrid_memory",
                memory_assessment(
                    target_peak_payload_bytes));
    record.text("assessment.hybrid_prove_time",
                time_assessment(prove_projection));
    return 0;
}

} // namespace

int main(int argc, char **argv) {
    try {
        const std::optional<Options> options = parse_options(argc, argv);
        return options.has_value() ? run(*options, argc, argv) : 0;
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
