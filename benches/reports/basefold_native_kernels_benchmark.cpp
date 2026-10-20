/// @file basefold_native_kernels_benchmark.cpp
/// @brief Single-thread native-Fq commitment-kernel measurements.

#include "benchmark_support.hpp"

#include "laminate/field/fq_ntt.hpp"
#include "laminate/field/fq_transform_kernels.hpp"
#include "laminate/field/serialization.hpp"
#include "laminate/storage/native_field_artifact.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using laminate::Fq;
using laminate::FqNttBackend;
using laminate::FqNttPlan;
using laminate::SerializedFq;
using laminate::bench::Record;
using laminate::bench::Timing;
using laminate::storage::NativeFieldArtifact;
using laminate::storage::NativeFieldArtifactOptions;
using laminate::storage::NativeFieldArtifactWriter;
using laminate::storage::NativeFieldElementKind;

struct Options {
    std::size_t log_elements = 20;
    std::size_t max_log_ntt = 17;
    std::size_t iterations = 3;
    std::filesystem::path working_directory;
};

struct Samples {
    std::vector<double> wall_ms;
    std::vector<double> cpu_ms;
    std::uint64_t checksum = 0;
};

struct NttSamples {
    Samples scalar;
    Samples production;
    Samples fused_pass_scalar;
    Samples fused_pass_production;
    FqNttBackend production_backend = FqNttBackend::Scalar;
};

class TemporaryDirectory {
  public:
    explicit TemporaryDirectory(std::filesystem::path parent) {
        if (parent.empty()) {
            parent = std::filesystem::temp_directory_path();
        } else if (!std::filesystem::is_directory(parent)) {
            throw std::invalid_argument(
                "benchmark working directory does not exist");
        }
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = parent /
                    ("laminate-fq-kernels-" + std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(path_)) {
                return;
            }
        }
        throw std::runtime_error("cannot create benchmark directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

std::optional<Options> parse_options(int argc, char **argv) {
    Options result;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help" || argument == "-h") {
            std::cout
                << "Usage: laminate_basefold_native_kernels_bench [options]\n"
                << "  --log-elements L  bounded I/O/tile working set\n"
                << "  --max-log-ntt L   largest local NTT (16 or 17 typical)\n"
                << "  --iterations I    repeated single-thread samples\n"
                << "  --working-directory PATH  artifact I/O parent\n";
            return std::nullopt;
        }
        if (++index == argc) {
            throw std::invalid_argument("missing value after " +
                                        std::string(argument));
        }
        if (argument == "--working-directory") {
            result.working_directory = argv[index];
            continue;
        }
        const std::size_t value =
            laminate::bench::parse_size(argv[index], argument);
        if (argument == "--log-elements") {
            result.log_elements = value;
        } else if (argument == "--max-log-ntt") {
            result.max_log_ntt = value;
        } else if (argument == "--iterations") {
            result.iterations = value;
        } else {
            throw std::invalid_argument("unknown option: " +
                                        std::string(argument));
        }
    }
    if (result.log_elements < 2 ||
        result.log_elements >= std::numeric_limits<std::size_t>::digits ||
        result.max_log_ntt < 2 ||
        result.max_log_ntt > result.log_elements ||
        result.max_log_ntt > laminate::kOuterFieldTwoAdicity ||
        result.iterations == 0) {
        throw std::invalid_argument("invalid native-kernel dimensions");
    }
    return result;
}

std::vector<Fq> make_values(std::size_t count) {
    std::vector<Fq> result(count);
    for (std::size_t index = 0; index < count; ++index) {
        result[index] = Fq(
            static_cast<std::uint64_t>(index) * 1'000'003ULL + 97'531ULL);
    }
    return result;
}

std::uint64_t checksum(std::span<const Fq> values) {
    std::uint64_t result = 0;
    for (std::size_t index = 0; index < values.size(); ++index) {
        result = std::rotl(result, 7) ^ values[index].value();
    }
    return result;
}

std::uint64_t checksum(std::span<const SerializedFq> values) {
    std::uint64_t result = 0;
    for (std::size_t index = 0; index < values.size(); ++index) {
        for (const std::uint8_t byte : values[index]) {
            result = std::rotl(result, 7) ^ byte;
        }
    }
    return result;
}

void retain_sample(Samples &samples, const Timing &timing,
                   std::uint64_t checksum_value) {
    if (!samples.wall_ms.empty() && samples.checksum != checksum_value) {
        throw std::runtime_error("benchmark kernel changed its output");
    }
    samples.wall_ms.push_back(timing.wall_ms);
    samples.cpu_ms.push_back(timing.cpu_ms);
    samples.checksum = checksum_value;
}

void emit_samples(const Record &record, std::string_view name,
                  const Samples &samples, std::string_view work_unit,
                  std::uint64_t work_units,
                  std::uint64_t bytes = 0) {
    const auto wall = laminate::bench::summarize(samples.wall_ms);
    const auto cpu = laminate::bench::summarize(samples.cpu_ms);
    const std::string prefix = "kernel." + std::string(name);
    const std::string work_name = std::string(work_unit);
    record.integer(prefix + "." + work_name, work_units);
    if (bytes != 0) {
        record.integer(prefix + ".bytes", bytes);
    }
    record.real(prefix + ".wall_ms_median", wall.median);
    record.real(prefix + ".cpu_ms_median", cpu.median);
    record.real(prefix + "." + work_name + "_per_second",
                1000.0 * static_cast<double>(work_units) / wall.median);
    if (bytes != 0) {
        record.real(prefix + ".bytes_per_second",
                    1000.0 * static_cast<double>(bytes) / wall.median);
    }
    record.real(prefix + ".cpu_to_wall_ratio", cpu.median / wall.median);
    record.integer(prefix + ".checksum", samples.checksum);
}

double scaled_seconds(const Samples &samples, std::uint64_t measured_work,
                      std::uint64_t projected_work) {
    return laminate::bench::summarize(samples.wall_ms).median / 1000.0 *
           static_cast<double>(projected_work) /
           static_cast<double>(measured_work);
}

void emit_target_ntt_models(
    const Record &record, std::size_t measured_elements,
    const Samples &artifact_read, const Samples &artifact_write,
    const Samples &transpose, const Samples &twiddle_transpose,
    const std::map<std::size_t, NttSamples> &ntt) {
    constexpr std::uint64_t kRateFourElements = std::uint64_t{1} << 34U;
    constexpr std::uint64_t kRateTwoElements = std::uint64_t{1} << 33U;
    const auto io_seconds = [&](std::uint64_t elements) {
        return scaled_seconds(artifact_read, measured_elements, elements) +
               scaled_seconds(artifact_write, measured_elements, elements);
    };
    const auto transpose_seconds = [&](std::uint64_t elements) {
        return scaled_seconds(transpose, measured_elements, elements);
    };
    const auto twiddle_seconds = [&](std::uint64_t elements) {
        return scaled_seconds(twiddle_transpose, measured_elements, elements);
    };
    const auto local_seconds = [&](std::size_t log_size,
                                   std::uint64_t elements,
                                   bool production) {
        const std::uint64_t measured_butterflies =
            static_cast<std::uint64_t>(measured_elements / 2U) * log_size;
        const std::uint64_t projected_butterflies =
            elements / 2U * log_size;
        const NttSamples &samples = ntt.at(log_size);
        return scaled_seconds(production ? samples.production : samples.scalar,
                              measured_butterflies,
                              projected_butterflies);
    };
    const auto fused_local_pass_seconds = [&](std::size_t log_size,
                                               std::uint64_t elements,
                                               bool production) {
        const NttSamples &samples = ntt.at(log_size);
        return scaled_seconds(
            production ? samples.fused_pass_production
                       : samples.fused_pass_scalar,
            measured_elements, elements);
    };
    const auto emit_model = [&](std::string_view name, std::uint64_t elements,
                                std::size_t first_local_log,
                                std::size_t second_local_log,
                                bool production) {
        const double io = io_seconds(elements);
        const double ordinary_transpose = transpose_seconds(elements);
        const double twiddle = twiddle_seconds(elements);
        const double first_local =
            local_seconds(first_local_log, elements, production);
        const double second_local =
            local_seconds(second_local_log, elements, production);
        const std::string prefix = "projection." + std::string(name);
        record.integer(prefix + ".external_passes", 5);
        record.real(prefix + ".artifact_io_seconds", 5.0 * io);
        record.real(prefix + ".ordinary_transpose_compute_seconds",
                    2.0 * ordinary_transpose);
        record.real(prefix + ".twiddle_transpose_compute_seconds", twiddle);
        record.real(prefix + ".local_ntt_compute_seconds",
                    first_local + second_local);
        record.real(prefix + ".total_seconds",
                    5.0 * io + 2.0 * ordinary_transpose + twiddle +
                        first_local + second_local);
    };

    record.text(
        "projection.model",
        "additive-scaled-components-not-an-end-to-end-target-measurement");
    emit_model("rate_four_balanced_scalar", kRateFourElements, 17, 17,
               false);
    emit_model("rate_four_balanced_production", kRateFourElements, 17, 17,
               true);
    emit_model("rate_two_balanced_scalar", kRateTwoElements, 16, 17, false);
    emit_model("rate_two_balanced_production", kRateTwoElements, 16, 17,
               true);

    // A transpose artifact is written positionally and therefore needs one
    // publication reread for its digest. The ordinary artifact read rate is
    // a conservative proxy because it also decodes canonical Fq values. The
    // fused local-pass sample below measures the exact row-granular read,
    // transform, canonical write, and inline digest path together.
    const auto emit_execution_shape_model =
        [&](std::string_view name, std::uint64_t elements,
            std::size_t first_local_log, std::size_t second_local_log,
            bool production) {
            const double io = io_seconds(elements);
            const double positional_publication =
                scaled_seconds(artifact_read, measured_elements, elements);
            const double ordinary = io + positional_publication +
                                    transpose_seconds(elements);
            const double twiddle = io + positional_publication +
                                   twiddle_seconds(elements);
            const double local = fused_local_pass_seconds(
                                     first_local_log, elements, production) +
                                 fused_local_pass_seconds(
                                     second_local_log, elements, production);
            const std::string prefix =
                "projection." + std::string(name) + ".execution_shape";
            record.real(prefix + ".ordinary_transpose_seconds",
                        2.0 * ordinary);
            record.real(prefix + ".twiddle_transpose_seconds", twiddle);
            record.real(prefix + ".fused_local_ntt_pass_seconds", local);
            record.real(prefix + ".total_seconds",
                        2.0 * ordinary + twiddle + local);
        };
    record.text("projection.execution_shape_model",
                "fused-local-pass-plus-positional-publication-proxy");
    emit_execution_shape_model("rate_four_balanced_scalar",
                               kRateFourElements, 17, 17, false);
    emit_execution_shape_model("rate_four_balanced_production",
                               kRateFourElements, 17, 17, true);
    emit_execution_shape_model("rate_two_balanced_scalar", kRateTwoElements,
                               16, 17, false);
    emit_execution_shape_model("rate_two_balanced_production",
                               kRateTwoElements, 16, 17, true);

    const double old_io = io_seconds(kRateFourElements);
    const double old_transpose = transpose_seconds(kRateFourElements);
    const double old_twiddle = twiddle_seconds(kRateFourElements);
    const double old_local =
        local_seconds(2, kRateFourElements, false) +
        2.0 * local_seconds(16, kRateFourElements, false);
    record.integer("projection.rate_four_radix_16_scalar.external_passes", 9);
    record.real("projection.rate_four_radix_16_scalar.artifact_io_seconds",
                9.0 * old_io);
    record.real(
        "projection.rate_four_radix_16_scalar.ordinary_transpose_compute_seconds",
        4.0 * old_transpose);
    record.real(
        "projection.rate_four_radix_16_scalar.twiddle_transpose_compute_seconds",
        2.0 * old_twiddle);
    record.real("projection.rate_four_radix_16_scalar.local_ntt_compute_seconds",
                old_local);
    record.real("projection.rate_four_radix_16_scalar.total_seconds",
                9.0 * old_io + 4.0 * old_transpose + 2.0 * old_twiddle +
                    old_local);
}

Samples measure_serialization(std::span<const Fq> source,
                              std::vector<SerializedFq> &encoded,
                              std::size_t iterations, bool decode) {
    Samples samples;
    std::vector<Fq> decoded(source.size());
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        const Timing timing = laminate::bench::timed_void([&] {
            if (decode) {
                for (std::size_t index = 0; index < encoded.size(); ++index) {
                    decoded[index] = laminate::deserialize_fq(encoded[index]);
                }
            } else {
                for (std::size_t index = 0; index < source.size(); ++index) {
                    encoded[index] = laminate::serialize(source[index]);
                }
            }
        });
        retain_sample(samples, timing,
                      decode ? checksum(decoded)
                             : checksum(std::span<const SerializedFq>(encoded)));
    }
    return samples;
}

std::pair<Samples, Samples> measure_artifact_io(
    const std::filesystem::path &root, std::span<const Fq> source,
    std::size_t iterations) {
    Samples writes;
    Samples reads;
    constexpr std::string_view kIdentityDomain =
        "laminate/benchmark/native-fq-kernels/v1";
    const std::vector<std::uint8_t> identity_input(
        kIdentityDomain.begin(), kIdentityDomain.end());
    const laminate::Digest identity = laminate::sha256(identity_input);
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        const std::filesystem::path directory =
            root / ("artifact-" + std::to_string(iteration));
        if (!std::filesystem::create_directory(directory)) {
            throw std::runtime_error("cannot create artifact sample");
        }
        std::optional<NativeFieldArtifact> artifact;
        const Timing write_timing = laminate::bench::timed_void([&] {
            NativeFieldArtifactWriter writer(
                directory,
                NativeFieldArtifactOptions{
                    .max_total_bytes =
                        static_cast<std::uint64_t>(source.size()) * 8U +
                        (1U << 20U),
                    .min_free_bytes = 1,
                },
                identity);
            writer.begin_array("values", NativeFieldElementKind::Fq,
                               source.size());
            writer.append(source);
            writer.finish_array();
            (void)writer.finish();
            artifact.emplace(writer.trusted_finished_artifact());
        });
        retain_sample(writes, write_timing, checksum(source));
        std::vector<Fq> restored(source.size());
        const Timing read_timing = laminate::bench::timed_void([&] {
            auto reader = artifact->open_array("values");
            if (reader.read(restored) != restored.size()) {
                throw std::runtime_error("artifact benchmark truncated");
            }
        });
        retain_sample(reads, read_timing, checksum(restored));
        artifact.reset();
        std::filesystem::remove_all(directory);
    }
    return {std::move(writes), std::move(reads)};
}

Samples measure_transpose(std::span<const Fq> source, std::size_t rows,
                          std::size_t columns, std::size_t iterations,
                          bool with_twiddles) {
    Samples samples;
    std::vector<Fq> tile(source.begin(), source.end());
    std::vector<Fq> output(source.size());
    const Fq root =
        Fq::two_adic_generator(std::bit_width(source.size()) - 1U);
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        std::copy(source.begin(), source.end(), tile.begin());
        const Timing timing = laminate::bench::timed_void([&] {
            if (with_twiddles) {
                laminate::apply_fq_twiddle_tile(tile, rows, columns, 0, 0,
                                                root);
            }
            laminate::transpose_fq_tile(tile, output, rows, columns);
        });
        retain_sample(samples, timing, checksum(output));
    }
    return samples;
}

Samples measure_ntt(std::span<const Fq> source, std::size_t row_size,
                    std::size_t iterations, FqNttBackend backend) {
    Samples samples;
    const Fq root =
        Fq::two_adic_generator(std::bit_width(row_size) - 1U);
    FqNttPlan plan(row_size, root, backend);
    std::vector<Fq> values(source.begin(), source.end());
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        std::copy(source.begin(), source.end(), values.begin());
        const Timing timing =
            laminate::bench::timed_void([&] { plan.apply_rows(values); });
        retain_sample(samples, timing, checksum(values));
    }
    return samples;
}

std::uint64_t digest_checksum(const laminate::Digest &digest) {
    std::uint64_t result = 0;
    for (const std::uint8_t byte : digest) {
        result = std::rotl(result, 7) ^ byte;
    }
    return result;
}

Samples measure_fused_artifact_ntt_pass(
    const std::filesystem::path &root, std::span<const Fq> source,
    std::size_t row_size, std::size_t iterations, FqNttBackend backend,
    std::string_view sample_name) {
    constexpr std::string_view kIdentityDomain =
        "laminate/benchmark/native-fq-fused-pass/v1";
    const std::vector<std::uint8_t> identity_input(
        kIdentityDomain.begin(), kIdentityDomain.end());
    const laminate::Digest identity = laminate::sha256(identity_input);
    const std::uint64_t maximum_bytes =
        static_cast<std::uint64_t>(source.size()) *
            laminate::kSerializedFqBytes +
        (1U << 20U);
    const std::filesystem::path input_directory =
        root / ("fused-input-" + std::string(sample_name));
    if (!std::filesystem::create_directory(input_directory)) {
        throw std::runtime_error("cannot create fused-pass input artifact");
    }
    NativeFieldArtifactWriter input_writer(
        input_directory,
        NativeFieldArtifactOptions{
            .max_total_bytes = maximum_bytes,
            .min_free_bytes = 1,
        },
        identity);
    input_writer.begin_array("values", NativeFieldElementKind::Fq,
                             source.size());
    input_writer.append(source);
    input_writer.finish_array();
    (void)input_writer.finish();
    const NativeFieldArtifact input =
        input_writer.trusted_finished_artifact();

    Samples samples;
    const Fq root_of_unity =
        Fq::two_adic_generator(std::bit_width(row_size) - 1U);
    FqNttPlan plan(row_size, root_of_unity, backend);
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        const std::filesystem::path output_directory =
            root / ("fused-output-" + std::string(sample_name) + "-" +
                    std::to_string(iteration));
        if (!std::filesystem::create_directory(output_directory)) {
            throw std::runtime_error(
                "cannot create fused-pass output artifact");
        }
        laminate::Digest output_digest{};
        const Timing timing = laminate::bench::timed_void([&] {
            auto reader = input.open_array("values");
            NativeFieldArtifactWriter writer(
                output_directory,
                NativeFieldArtifactOptions{
                    .max_total_bytes = maximum_bytes,
                    .min_free_bytes = 1,
                },
                identity);
            writer.begin_array("values", NativeFieldElementKind::Fq,
                               source.size());
            constexpr std::size_t kMinimumTransferElements =
                std::size_t{1} << 16U;
            const std::size_t transfer_elements =
                std::min(source.size(),
                         std::max(row_size, kMinimumTransferElements));
            std::vector<Fq> rows(transfer_elements);
            for (std::size_t offset = 0; offset < source.size();
                 offset += transfer_elements) {
                const std::size_t active_count =
                    std::min(transfer_elements, source.size() - offset);
                std::span<Fq> active =
                    std::span<Fq>(rows).first(active_count);
                if (reader.read(active) != active.size()) {
                    throw std::runtime_error(
                        "fused artifact NTT pass was truncated");
                }
                plan.apply_rows(active);
                writer.append(active);
            }
            writer.finish_array();
            const auto written = writer.finish();
            output_digest = written.arrays.front().file_digest;
        });
        retain_sample(samples, timing, digest_checksum(output_digest));
        std::filesystem::remove_all(output_directory);
    }
    std::filesystem::remove_all(input_directory);
    return samples;
}

void emit_fused_pass_samples(const Record &record, std::string_view name,
                             const Samples &samples,
                             std::size_t element_count,
                             std::size_t log_ntt) {
    const std::uint64_t butterflies =
        static_cast<std::uint64_t>(element_count / 2U) * log_ntt;
    const std::uint64_t bytes =
        2U * static_cast<std::uint64_t>(element_count) *
        laminate::kSerializedFqBytes;
    emit_samples(record, name, samples, "elements", element_count, bytes);
    const auto wall = laminate::bench::summarize(samples.wall_ms);
    const std::string prefix = "kernel." + std::string(name);
    constexpr std::size_t kMinimumTransferElements =
        std::size_t{1} << 16U;
    const std::size_t row_size = std::size_t{1} << log_ntt;
    const std::size_t transfer_elements =
        std::min(element_count,
                 std::max(row_size, kMinimumTransferElements));
    record.integer(prefix + ".row_elements", row_size);
    record.integer(prefix + ".transfer_elements", transfer_elements);
    record.integer(prefix + ".rows_per_transfer",
                   transfer_elements / row_size);
    record.integer(prefix + ".transfer_count",
                   element_count / transfer_elements);
    record.integer(prefix + ".butterflies", butterflies);
    record.real(prefix + ".butterflies_per_second",
                1000.0 * static_cast<double>(butterflies) / wall.median);
}

} // namespace

int main(int argc, char **argv) {
    try {
        const std::optional<Options> parsed = parse_options(argc, argv);
        if (!parsed) {
            return 0;
        }
        const Options &options = *parsed;
        const std::size_t element_count =
            std::size_t{1} << options.log_elements;
        const std::vector<Fq> source = make_values(element_count);
        std::vector<SerializedFq> encoded(element_count);
        TemporaryDirectory temporary(options.working_directory);

        const Samples serialization_write = measure_serialization(
            source, encoded, options.iterations, false);
        const Samples serialization_read = measure_serialization(
            source, encoded, options.iterations, true);
        auto [artifact_write, artifact_read] = measure_artifact_io(
            temporary.path(), source, options.iterations);

        const std::size_t row_bits = options.log_elements / 2U;
        const std::size_t rows = std::size_t{1} << row_bits;
        const std::size_t columns = element_count / rows;
        const Samples transpose = measure_transpose(
            source, rows, columns, options.iterations, false);
        const Samples twiddle_transpose = measure_transpose(
            source, rows, columns, options.iterations, true);

        const Record record;
        record.text("format", "laminate-basefold-native-kernels-v3");
        record.text("classification", "measured-single-thread-native-fq");
        record.integer("threads", 1);
        record.integer("iterations", options.iterations);
        record.integer("working_set_elements", element_count);
        record.integer("working_set_bytes", element_count * sizeof(Fq));
        record.text("artifact_working_directory",
                    temporary.path().parent_path().string());
        record.integer("fq_modulus", laminate::kOuterFieldOrder);
        record.integer("fq_modulus_bits", 60);
        record.text("fq_representation", "montgomery-64");
        record.text("fq_avx512_ifma_compatible",
                    "no-forward-ntt-modulus-exceeds-2^50");
        record.text(
            "fq_intel_hexl_available",
            laminate::fq_ntt_backend_available(FqNttBackend::IntelHexl)
                ? "yes"
                : "no");
        record.integer("fq_intel_hexl_automatic_min_log_ntt", 16);
        record.text("fq_ntt_backend",
                    std::string(laminate::fq_ntt_backend_name(
                        FqNttPlan(4, Fq::two_adic_generator(2)).backend())));

        const std::uint64_t payload_bytes =
            static_cast<std::uint64_t>(element_count) *
            laminate::kSerializedFqBytes;
        emit_samples(record, "serialization.encode", serialization_write,
                     "elements", element_count, payload_bytes);
        emit_samples(record, "serialization.decode", serialization_read,
                     "elements", element_count, payload_bytes);
        emit_samples(record, "artifact.write", artifact_write, "elements",
                     element_count, payload_bytes);
        emit_samples(record, "artifact.read", artifact_read, "elements",
                     element_count, payload_bytes);
        emit_samples(record, "transpose", transpose, "elements",
                     element_count, 2U * payload_bytes);
        emit_samples(record, "twiddle_transpose", twiddle_transpose,
                     "elements", element_count, 2U * payload_bytes);

        std::vector<std::size_t> ntt_logs{2, options.max_log_ntt};
        if (options.max_log_ntt >= 16) {
            ntt_logs.push_back(16);
        }
        if (options.max_log_ntt >= 17) {
            ntt_logs.push_back(17);
        }
        std::sort(ntt_logs.begin(), ntt_logs.end());
        ntt_logs.erase(std::unique(ntt_logs.begin(), ntt_logs.end()),
                       ntt_logs.end());
        std::map<std::size_t, NttSamples> ntt_measurements;
        for (const std::size_t log_ntt : ntt_logs) {
            const std::size_t row_size = std::size_t{1} << log_ntt;
            const std::uint64_t butterflies =
                static_cast<std::uint64_t>(element_count / 2U) * log_ntt;
            const std::string prefix =
                "ntt.log_" + std::to_string(log_ntt);
            const Samples scalar = measure_ntt(
                source, row_size, options.iterations, FqNttBackend::Scalar);
            emit_samples(record, prefix + ".scalar", scalar, "butterflies",
                         butterflies);

            FqNttPlan production_plan(
                row_size, Fq::two_adic_generator(log_ntt));
            const FqNttBackend production_backend =
                production_plan.backend();
            const Samples fused_scalar = measure_fused_artifact_ntt_pass(
                temporary.path(), source, row_size, options.iterations,
                FqNttBackend::Scalar,
                "log-" + std::to_string(log_ntt) + "-scalar");
            emit_fused_pass_samples(record, prefix + ".fused_pass.scalar",
                                    fused_scalar, element_count, log_ntt);
            record.text("kernel." + prefix + ".production_backend",
                        std::string(laminate::fq_ntt_backend_name(
                            production_backend)));
            if (production_backend == FqNttBackend::Scalar) {
                record.text("kernel." + prefix +
                                ".production_samples_reused",
                            "yes");
                emit_samples(record, prefix + ".production", scalar,
                             "butterflies", butterflies);
                record.real("kernel." + prefix +
                                ".production_vs_scalar_speedup",
                            1.0);
                record.text("kernel." + prefix +
                                ".fused_pass.production_samples_reused",
                            "yes");
                emit_fused_pass_samples(
                    record, prefix + ".fused_pass.production",
                    fused_scalar, element_count, log_ntt);
                ntt_measurements.emplace(
                    log_ntt,
                    NttSamples{scalar, scalar, fused_scalar, fused_scalar,
                               production_backend});
            } else {
                const Samples production = measure_ntt(
                    source, row_size, options.iterations,
                    FqNttBackend::Automatic);
                const Samples fused_production =
                    measure_fused_artifact_ntt_pass(
                        temporary.path(), source, row_size,
                        options.iterations, FqNttBackend::Automatic,
                        "log-" + std::to_string(log_ntt) + "-production");
                emit_samples(record, prefix + ".production", production,
                             "butterflies", butterflies);
                emit_fused_pass_samples(
                    record, prefix + ".fused_pass.production",
                    fused_production, element_count, log_ntt);
                const double scalar_wall =
                    laminate::bench::summarize(scalar.wall_ms).median;
                const double production_wall =
                    laminate::bench::summarize(production.wall_ms).median;
                record.real("kernel." + prefix +
                                ".production_vs_scalar_speedup",
                            scalar_wall / production_wall);
                ntt_measurements.emplace(
                    log_ntt,
                    NttSamples{scalar, production, fused_scalar,
                               fused_production, production_backend});
            }
        }
        if (ntt_measurements.contains(2) && ntt_measurements.contains(16) &&
            ntt_measurements.contains(17)) {
            emit_target_ntt_models(record, element_count, artifact_read,
                                   artifact_write, transpose,
                                   twiddle_transpose, ntt_measurements);
        }
        laminate::bench::emit_benchmark_provenance(record, argc, argv);
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
