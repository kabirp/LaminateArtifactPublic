/// @file file_trace_store_duplex_benchmark.cpp
/// @brief Sustained cold-read plus canonical-write trace-store diagnostic.

#include "laminate/payload/storage/file_trace_store.hpp"

#include "benchmark_support.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <system_error>
#include <unistd.h>
#endif

namespace {

using namespace laminate;
using namespace laminate::payload;
using namespace laminate::payload::trace_storage;

constexpr std::uint64_t kKiB = 1024ULL;
constexpr std::uint64_t kMiB = 1024ULL * kKiB;
constexpr std::size_t kSourceValidationSamples = 64;

std::uint64_t parse_u64(std::string_view text, const char *name,
                        bool allow_zero = false) {
    std::size_t consumed = 0;
    const unsigned long long parsed =
        std::stoull(std::string(text), &consumed);
    if (consumed != text.size() || (!allow_zero && parsed == 0)) {
        throw std::invalid_argument(
            std::string(name) +
            (allow_zero ? " must be a nonnegative integer"
                        : " must be a positive integer"));
    }
    return static_cast<std::uint64_t>(parsed);
}

std::uint64_t multiply(std::uint64_t left, std::uint64_t right,
                       const char *name) {
    if (left != 0 && right >
                         std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(name) + " overflows");
    }
    return left * right;
}

std::uint64_t add(std::uint64_t left, std::uint64_t right,
                  const char *name) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(name) + " overflows");
    }
    return left + right;
}

void force_file_to_storage(const std::filesystem::path &path) {
#ifndef _WIN32
    const int descriptor = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
    if (descriptor < 0) {
        throw std::runtime_error(
            "failed to open sustained diagnostic artifact for sync: " +
            std::error_code(errno, std::generic_category()).message());
    }
    int result = 0;
    do {
        result = ::fsync(descriptor);
    } while (result != 0 && errno == EINTR);
    const int sync_error = result == 0 ? 0 : errno;
    const int close_result = ::close(descriptor);
    if (sync_error != 0) {
        throw std::runtime_error(
            "failed to sync sustained diagnostic artifact: " +
            std::error_code(sync_error, std::generic_category()).message());
    }
    if (close_result != 0) {
        throw std::runtime_error(
            "failed to close sustained diagnostic artifact");
    }
#else
    (void)path;
#endif
}

struct CacheDropResult {
    bool supported = false;
    bool succeeded = false;
    int error = 0;
};

CacheDropResult drop_file_from_page_cache(
    const std::filesystem::path &path) {
#if !defined(_WIN32) && defined(POSIX_FADV_DONTNEED)
    CacheDropResult result{.supported = true};
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        result.error = errno;
        return result;
    }
    result.error = ::posix_fadvise(descriptor, 0, 0, POSIX_FADV_DONTNEED);
    result.succeeded = result.error == 0;
    if (::close(descriptor) != 0 && result.succeeded) {
        result.succeeded = false;
        result.error = errno;
    }
    return result;
#else
    (void)path;
    return {};
#endif
}

std::uint64_t physical_memory_bytes() {
#ifndef _WIN32
    const long pages = ::sysconf(_SC_PHYS_PAGES);
    const long page_bytes = ::sysconf(_SC_PAGESIZE);
    if (pages <= 0 || page_bytes <= 0) {
        return 0;
    }
    const std::uint64_t count = static_cast<std::uint64_t>(pages);
    const std::uint64_t size = static_cast<std::uint64_t>(page_bytes);
    if (count > std::numeric_limits<std::uint64_t>::max() / size) {
        return 0;
    }
    return count * size;
#else
    return 0;
#endif
}

struct ProcessIo {
    bool available = false;
    std::uint64_t read_bytes = 0;
    std::uint64_t write_bytes = 0;
    std::uint64_t cancelled_write_bytes = 0;
};

ProcessIo process_io() {
#if defined(__linux__)
    std::ifstream input("/proc/self/io");
    if (!input) {
        return {};
    }
    ProcessIo result{.available = true};
    std::string key;
    std::uint64_t value = 0;
    while (input >> key >> value) {
        if (key == "read_bytes:") {
            result.read_bytes = value;
        } else if (key == "write_bytes:") {
            result.write_bytes = value;
        } else if (key == "cancelled_write_bytes:") {
            result.cancelled_write_bytes = value;
        }
    }
    return result;
#else
    return {};
#endif
}

std::uint64_t counter_delta(std::uint64_t after, std::uint64_t before) {
    return after >= before ? after - before : 0;
}

SerializedTraceStore write_source(
    const std::filesystem::path &directory,
    const FileTraceStoreOptions &options,
    std::span<const std::uint8_t> left_record,
    std::span<const std::uint8_t> right_record, std::size_t records,
    const Digest &context_id, const Digest &circuit_id,
    const Digest &trace_id) {
    if ((records & 1U) != 0 || left_record.size() != right_record.size()) {
        throw std::invalid_argument(
            "sustained diagnostic source must have two equal ranges");
    }
    SerializedTraceWriter writer(directory, options, context_id);
    writer.begin_trace(PayloadShape::wide(2),
                       TraceProvenance::SyntheticTrace,
                       circuit_id, trace_id, 1);
    writer.begin_layer(
        0, TraceLayerLayout::Wide,
        LayerDimensions{records, records, records, 0}, 0, records);
    for (std::size_t index = 0; index < records; ++index) {
        const std::span<const std::uint8_t> record =
            index < records / 2U ? left_record : right_record;
        writer.append_serialized_direct(
            record.size(), [&](std::vector<std::uint8_t> &output) {
                output.insert(output.end(), record.begin(), record.end());
            });
    }
    writer.finish_layer();
    return std::move(writer).finish_private_single_layer_store();
}

void emit_timing(std::string_view prefix,
                 const FileTraceStoreOperationTiming &timing) {
    std::cout << prefix << ".wall_ms=" << timing.wall_ms << '\n'
              << prefix << ".cpu_ms=" << timing.cpu_ms << '\n';
}

} // namespace

int main(int argc, char **argv) {
    try {
        if (argc != 11 ||
            std::string_view(argv[1]) != "--directory" ||
            std::string_view(argv[3]) != "--transfer-mib" ||
            std::string_view(argv[5]) != "--source-mib" ||
            std::string_view(argv[7]) != "--record-kib" ||
            std::string_view(argv[9]) != "--writeback-mib") {
            throw std::invalid_argument(
                "expected --directory ABSENT_PATH --transfer-mib N "
                "--source-mib N --record-kib N --writeback-mib N");
        }

        const std::filesystem::path root = argv[2];
        if (!root.is_absolute() || root == root.root_path() ||
            std::filesystem::exists(root)) {
            throw std::invalid_argument(
                "--directory must be an absent absolute child path");
        }
        const std::uint64_t transfer_bytes = multiply(
            parse_u64(argv[4], "transfer MiB"), kMiB,
            "transfer bytes");
        const std::uint64_t total_bytes = multiply(
            parse_u64(argv[6], "source MiB"), kMiB, "source bytes");
        const std::uint64_t record_bytes = multiply(
            parse_u64(argv[8], "record KiB"), kKiB, "record bytes");
        const std::uint64_t writeback_bytes = multiply(
            parse_u64(argv[10], "writeback MiB", true), kMiB,
            "writeback bytes");
        if (total_bytes % record_bytes != 0 ||
            total_bytes / record_bytes >
                std::numeric_limits<std::size_t>::max()) {
            throw std::invalid_argument(
                "source MiB must contain an integral size_t record count");
        }
        const std::size_t records =
            static_cast<std::size_t>(total_bytes / record_bytes);
        if (records < 2 || (records & (records - 1U)) != 0) {
            throw std::invalid_argument(
                "the sustained diagnostic source record count must be a "
                "power of two of at least two");
        }
        const std::size_t output_records = records / 2U;
        const std::uint64_t output_bytes = total_bytes / 2U;

        if (!std::filesystem::create_directory(root)) {
            throw std::runtime_error(
                "failed to create sustained diagnostic root");
        }
        const std::filesystem::path source_directory = root / "source";
        const std::filesystem::path output_directory = root / "output";
        const std::filesystem::path source_layer =
            source_directory / "layer-0000000000000000.bin";
        const std::filesystem::path output_layer =
            output_directory / "layer-0000000000000000.bin";

        std::vector<std::uint8_t> left_record(
            static_cast<std::size_t>(record_bytes));
        std::vector<std::uint8_t> right_record(
            static_cast<std::size_t>(record_bytes));
        for (std::size_t index = 0; index < left_record.size(); ++index) {
            left_record[index] = static_cast<std::uint8_t>(
                (index * 131U + 17U) & 0xffU);
            right_record[index] = static_cast<std::uint8_t>(
                (index * 193U + 71U) & 0xffU);
        }
        Digest context_id{};
        context_id.front() = 1;
        Digest circuit_id{};
        circuit_id.front() = 2;
        Digest source_trace_id{};
        source_trace_id.front() = 3;
        Digest output_trace_id{};
        output_trace_id.front() = 4;

        const FileTraceStoreOptions source_storage_options{
            .max_total_bytes = add(total_bytes, 32ULL * kMiB,
                                   "source diagnostic artifact limit"),
            .min_free_bytes = 1,
            .transfer_buffer_bytes = transfer_bytes,
            .writeback_window_bytes = writeback_bytes,
            .integrity_mode =
                FileTraceStoreIntegrityMode::SameProcessEphemeral,
        };
        const FileTraceStoreOptions output_storage_options{
            .max_total_bytes = add(output_bytes, 32ULL * kMiB,
                                   "output diagnostic artifact limit"),
            .min_free_bytes = 1,
            .transfer_buffer_bytes = transfer_bytes,
            .writeback_window_bytes = writeback_bytes,
            .integrity_mode =
                FileTraceStoreIntegrityMode::SameProcessEphemeral,
        };

        laminate::bench::Stopwatch source_stopwatch;
        SerializedTraceStore source = write_source(
            source_directory, source_storage_options, left_record,
            right_record, records, context_id, circuit_id, source_trace_id);
        force_file_to_storage(source_layer);
        force_file_to_storage(source_directory / "manifest.bin");
        const laminate::bench::Timing source_timing =
            source_stopwatch.stop();
        const CacheDropResult cache_drop =
            drop_file_from_page_cache(source_layer);

        FileTraceStoreReadDiagnostics left_reads;
        FileTraceStoreReadDiagnostics right_reads;
        const ProcessIo io_before = process_io();
        laminate::bench::Stopwatch pipeline_stopwatch;
        SerializedTraceWriter output_writer(
            output_directory, output_storage_options, context_id);
        output_writer.begin_trace(
            PayloadShape::wide(2), TraceProvenance::SyntheticTrace,
            circuit_id, output_trace_id, 1);
        output_writer.begin_layer(
            0, TraceLayerLayout::Wide,
            LayerDimensions{output_records, output_records, output_records,
                            0},
            0, output_records);
        // A full comparison here adds a second source-sized memory scan to the
        // timed device pipeline. Keep smoke-sized runs exhaustive, but bound
        // target-scale validation to uniformly spaced complete record pairs
        // plus the terminal pair. Record sizes and range termination remain
        // checked for every pair.
        const std::size_t source_validation_stride =
            std::max<std::size_t>(
                1, 1U + (output_records - 1U) /
                            kSourceValidationSamples);
        std::size_t validated_source_pairs = 0;
        std::size_t observed = 0;
        {
            auto left_reader = source.layer_range(
                0, 0, output_records, &left_reads);
            auto right_reader = source.layer_range(
                0, output_records, records, &right_reads);
            while (true) {
                const auto left = left_reader.next_view();
                const auto right = right_reader.next_view();
                if (!left || !right) {
                    if (left || right) {
                        throw std::runtime_error(
                            "sustained diagnostic reader ranges ended at "
                            "different records");
                    }
                    break;
                }
                if (left->size() != left_record.size() ||
                    right->size() != right_record.size()) {
                    throw std::runtime_error(
                        "sustained diagnostic source record size mismatch");
                }
                const bool validate_source_pair =
                    observed % source_validation_stride == 0 ||
                    observed + 1U == output_records;
                if (validate_source_pair &&
                    (!std::equal(left->begin(), left->end(),
                                 left_record.begin()) ||
                     !std::equal(right->begin(), right->end(),
                                 right_record.begin()))) {
                    throw std::runtime_error(
                        "sustained diagnostic sampled source record "
                        "mismatch");
                }
                if (validate_source_pair) {
                    ++validated_source_pairs;
                }
                output_writer.append_serialized_direct(
                    left->size(),
                    [&](std::vector<std::uint8_t> &output) {
                        output.insert(output.end(), left->begin(),
                                      left->end());
                    });
                ++observed;
            }
        }
        if (observed != output_records) {
            throw std::runtime_error(
                "sustained diagnostic source record count mismatch");
        }
        output_writer.finish_layer();
        SerializedTraceStore output =
            std::move(output_writer).finish_private_single_layer_store();
        const laminate::bench::Timing pipeline_timing =
            pipeline_stopwatch.stop();
        const ProcessIo io_after_pipeline = process_io();

        laminate::bench::Stopwatch drain_stopwatch;
        force_file_to_storage(output_layer);
        force_file_to_storage(output_directory / "manifest.bin");
        const laminate::bench::Timing drain_timing = drain_stopwatch.stop();
        const ProcessIo io_after_drain = process_io();

        // Sample both ends without turning verification into another complete
        // cold scan. Byte identity of the buffered/direct writers is covered
        // exhaustively by the storage tests; this diagnostic's job is the
        // sustained device path.
        {
            auto first = output.layer_range(0, 0, 1);
            const auto encoded = first.next_view();
            if (!encoded || encoded->size() != left_record.size() ||
                !std::equal(encoded->begin(), encoded->end(),
                            left_record.begin())) {
                throw std::runtime_error(
                    "sustained diagnostic first output record mismatch");
            }
            auto last = output.layer_range(
                0, output_records - 1U, output_records);
            const auto final = last.next_view();
            if (!final || final->size() != left_record.size() ||
                !std::equal(final->begin(), final->end(),
                            left_record.begin())) {
                throw std::runtime_error(
                    "sustained diagnostic final output record mismatch");
            }
        }

        const FileTraceStoreWriteDiagnostics writes =
            output.write_diagnostics();
        const std::uint64_t source_physical = source.report().physical_bytes;
        const std::uint64_t output_physical = output.report().physical_bytes;
        const std::uint64_t removed_output = output.remove_validated_files();
        const std::uint64_t removed_source = source.remove_validated_files();
        if (removed_output != output_physical ||
            removed_source != source_physical ||
            !std::filesystem::remove(output_directory) ||
            !std::filesystem::remove(source_directory) ||
            !std::filesystem::remove(root)) {
            throw std::runtime_error(
                "sustained diagnostic cleanup failed");
        }

        const std::uint64_t host_ram = physical_memory_bytes();
        const bool source_exceeds_ram =
            host_ram != 0 && source_physical > host_ram;
        const bool kernel_io_available =
            io_before.available && io_after_pipeline.available &&
            io_after_drain.available;
        const std::uint64_t pipeline_kernel_read_bytes =
            kernel_io_available
                ? counter_delta(io_after_pipeline.read_bytes,
                                io_before.read_bytes)
                : 0;
        const std::uint64_t pipeline_kernel_write_bytes =
            kernel_io_available
                ? counter_delta(io_after_pipeline.write_bytes,
                                io_before.write_bytes)
                : 0;
        const std::uint64_t pipeline_kernel_cancelled_write_bytes =
            kernel_io_available
                ? counter_delta(io_after_pipeline.cancelled_write_bytes,
                                io_before.cancelled_write_bytes)
                : 0;
        const std::uint64_t final_kernel_write_bytes =
            kernel_io_available
                ? counter_delta(io_after_drain.write_bytes,
                                io_before.write_bytes)
                : 0;
        const std::uint64_t final_kernel_cancelled_write_bytes =
            kernel_io_available
                ? counter_delta(io_after_drain.cancelled_write_bytes,
                                io_before.cancelled_write_bytes)
                : 0;
        const std::uint64_t drain_kernel_write_bytes =
            kernel_io_available
                ? counter_delta(io_after_drain.write_bytes,
                                io_after_pipeline.write_bytes)
                : 0;
        const std::uint64_t drain_kernel_cancelled_write_bytes =
            kernel_io_available
                ? counter_delta(io_after_drain.cancelled_write_bytes,
                                io_after_pipeline.cancelled_write_bytes)
                : 0;
        const std::uint64_t pipeline_effective_kernel_write_bytes =
            pipeline_kernel_write_bytes >=
                    pipeline_kernel_cancelled_write_bytes
                ? pipeline_kernel_write_bytes -
                      pipeline_kernel_cancelled_write_bytes
                : 0;
        const std::uint64_t final_effective_kernel_write_bytes =
            final_kernel_write_bytes >= final_kernel_cancelled_write_bytes
                ? final_kernel_write_bytes -
                      final_kernel_cancelled_write_bytes
                : 0;
        const bool cold_read_confirmed =
            kernel_io_available && cache_drop.succeeded &&
            pipeline_kernel_read_bytes >= total_bytes - total_bytes / 20U;
        const bool final_output_write_confirmed =
            kernel_io_available &&
            final_effective_kernel_write_bytes >=
                output_physical - output_physical / 20U;
        const bool sustained_qualification =
            source_exceeds_ram && cold_read_confirmed &&
            final_output_write_confirmed;
        const double pipeline_wall_ms = pipeline_timing.wall_ms;
        const double application_bytes =
            static_cast<double>(total_bytes) +
            static_cast<double>(output_bytes);
        const std::uint64_t read_application_bytes =
            add(left_reads.bytes_transferred, right_reads.bytes_transferred,
                "duplex application read bytes");
        const std::uint64_t read_batches =
            add(left_reads.read_batches, right_reads.read_batches,
                "duplex read batches");
        const std::uint64_t read_syscalls =
            add(left_reads.read_syscalls, right_reads.read_syscalls,
                "duplex read syscalls");
        const std::uint64_t prefetch_requests =
            add(left_reads.prefetch_requests, right_reads.prefetch_requests,
                "duplex prefetch requests");
        const std::uint64_t prefetch_bytes_requested = add(
            left_reads.prefetch_bytes_requested,
            right_reads.prefetch_bytes_requested,
            "duplex requested prefetch bytes");
        const std::uint64_t prefetch_fallbacks =
            add(left_reads.prefetch_fallbacks, right_reads.prefetch_fallbacks,
                "duplex prefetch fallbacks");
        const std::uint64_t prefetch_seek_disables = add(
            left_reads.prefetch_seek_disables,
            right_reads.prefetch_seek_disables,
            "duplex seek-disabled prefetch readers");
        FileTraceStoreOperationTiming aggregate_read_storage =
            left_reads.storage_read;
        aggregate_read_storage += right_reads.storage_read;
        FileTraceStoreOperationTiming aggregate_read_prefetch =
            left_reads.prefetch;
        aggregate_read_prefetch += right_reads.prefetch;

        std::cout << std::fixed << std::setprecision(3)
                  << "format=laminate-payload-storage-duplex-v1\n"
                  << "classification=measured-single-thread\n";
        const laminate::bench::Record provenance;
        laminate::bench::emit_benchmark_provenance(provenance, argc, argv);
        provenance.text("environment.threading", "single-threaded");
        std::cout
            << "environment.physical_memory_bytes=" << host_ram << '\n'
            << "parameters.transfer_buffer_bytes=" << transfer_bytes << '\n'
            << "parameters.writeback_window_bytes=" << writeback_bytes << '\n'
            << "parameters.record_bytes=" << record_bytes << '\n'
            << "parameters.source_records=" << records << '\n'
            << "parameters.output_records=" << output_records << '\n'
            << "parameters.validated_source_record_pairs="
            << validated_source_pairs << '\n'
            << "parameters.readers=2\n"
            << "parameters.reads_per_output=2\n"
            << "parameters.source_logical_record_bytes=" << total_bytes
            << '\n'
            << "parameters.output_logical_record_bytes=" << output_bytes
            << '\n'
            << "parameters.integrity=ephemeral\n"
            << "parameters.record_path=direct\n"
            << "source.physical_bytes=" << source_physical << '\n'
            << "output.physical_bytes=" << output_physical << '\n'
            << "source.exceeds_physical_memory="
            << (source_exceeds_ram ? "true" : "false") << '\n'
            << "source.cache_drop_supported="
            << (cache_drop.supported ? "true" : "false") << '\n'
            << "source.cache_drop_succeeded="
            << (cache_drop.succeeded ? "true" : "false") << '\n'
            << "source.cache_drop_error=" << cache_drop.error << '\n'
            << "source.preparation_wall_ms=" << source_timing.wall_ms << '\n'
            << "source.preparation_cpu_ms=" << source_timing.cpu_ms << '\n'
            << "pipeline.wall_ms=" << pipeline_wall_ms << '\n'
            << "pipeline.cpu_ms=" << pipeline_timing.cpu_ms << '\n'
            << "pipeline.cpu_utilization_percent="
            << (pipeline_wall_ms == 0.0
                    ? 0.0
                    : 100.0 * pipeline_timing.cpu_ms / pipeline_wall_ms)
            << '\n'
            << "pipeline.application_mib_per_second="
            << (pipeline_wall_ms == 0.0
                    ? 0.0
                    : 1000.0 * application_bytes /
                          static_cast<double>(kMiB) / pipeline_wall_ms)
            << '\n'
            << "pipeline.kernel_io_available="
            << (kernel_io_available ? "true" : "false")
            << '\n'
            << "pipeline.kernel_read_bytes="
            << pipeline_kernel_read_bytes << '\n'
            << "pipeline.kernel_write_bytes="
            << pipeline_kernel_write_bytes << '\n'
            << "pipeline.kernel_cancelled_write_bytes="
            << pipeline_kernel_cancelled_write_bytes << '\n'
            << "pipeline.effective_kernel_write_bytes="
            << pipeline_effective_kernel_write_bytes << '\n'
            << "pipeline.cold_source_read_confirmed="
            << (cold_read_confirmed ? "true" : "false") << '\n'
            << "post_pipeline_drain.wall_ms=" << drain_timing.wall_ms << '\n'
            << "post_pipeline_drain.cpu_ms=" << drain_timing.cpu_ms << '\n'
            << "post_pipeline_drain.kernel_write_bytes="
            << drain_kernel_write_bytes << '\n'
            << "post_pipeline_drain.kernel_cancelled_write_bytes="
            << drain_kernel_cancelled_write_bytes << '\n'
            << "post_pipeline_drain.final_kernel_write_bytes="
            << final_kernel_write_bytes << '\n'
            << "post_pipeline_drain.final_kernel_cancelled_write_bytes="
            << final_kernel_cancelled_write_bytes << '\n'
            << "post_pipeline_drain.final_effective_kernel_write_bytes="
            << final_effective_kernel_write_bytes << '\n'
            << "post_pipeline_drain.output_write_confirmed="
            << (final_output_write_confirmed ? "true" : "false") << '\n'
            << "read.application_bytes=" << read_application_bytes << '\n'
            << "read.left.application_bytes="
            << left_reads.bytes_transferred << '\n'
            << "read.right.application_bytes="
            << right_reads.bytes_transferred << '\n'
            << "read.batches=" << read_batches << '\n'
            << "read.syscalls=" << read_syscalls << '\n'
            << "read.prefetch_requests=" << prefetch_requests << '\n'
            << "read.prefetch_bytes_requested="
            << prefetch_bytes_requested << '\n'
            << "read.prefetch_fallbacks=" << prefetch_fallbacks << '\n'
            << "read.prefetch_seek_disables=" << prefetch_seek_disables
            << '\n'
            << "read.prefetch_window_bytes="
            << std::max(left_reads.prefetch_window_bytes,
                        right_reads.prefetch_window_bytes)
            << '\n'
            << "read.maximum_prefetch_request_bytes="
            << std::max(left_reads.maximum_prefetch_request_bytes,
                        right_reads.maximum_prefetch_request_bytes)
            << '\n'
            << "read.maximum_batch_bytes="
            << std::max(left_reads.maximum_batch_bytes,
                        right_reads.maximum_batch_bytes)
            << '\n'
            << "write.application_bytes=" << writes.bytes_submitted << '\n'
            << "write.batches=" << writes.write_batches << '\n'
            << "write.syscalls=" << writes.write_syscalls << '\n'
            << "write.maximum_batch_bytes=" << writes.maximum_batch_bytes
            << '\n'
            << "write.writeback_files_enabled="
            << writes.writeback_files_enabled << '\n'
            << "write.writeback_files_fallback="
            << writes.writeback_files_fallback << '\n'
            << "write.writeback_files_submit_only="
            << writes.writeback_files_submit_only << '\n'
            << "write.writeback_submission_attempts="
            << writes.writeback_submission_attempts
            << '\n'
            << "write.writeback_submission_successes="
            << writes.writeback_submission_successes << '\n'
            << "write.writeback_wait_attempts="
            << writes.writeback_wait_attempts << '\n'
            << "write.writeback_wait_successes="
            << writes.writeback_wait_successes << '\n'
            << "write.writeback_range_bytes_submitted="
            << writes.writeback_range_bytes_submitted << '\n'
            << "write.writeback_range_bytes_waited="
            << writes.writeback_range_bytes_waited << '\n'
            << "write.maximum_writeback_submission_bytes="
            << writes.maximum_writeback_submission_bytes << '\n'
            << "write.writeback_window_bytes="
            << writes.writeback_window_bytes << '\n'
            << "write.maximum_unwaited_writeback_range_bytes="
            << writes.maximum_unwaited_writeback_range_bytes << '\n'
            << "write.writeback_drains=" << writes.writeback_drains << '\n'
            << "write.writeback_drain_range_bytes="
            << writes.writeback_drain_range_bytes << '\n'
            << "write.writeback_drains_skipped="
            << writes.writeback_drains_skipped << '\n'
            << "write.writeback_range_bytes_without_explicit_wait="
            << writes.writeback_range_bytes_without_explicit_wait << '\n'
            << "write.positional_write_calls="
            << writes.positional_write_calls << '\n'
            << "write.positional_write_bytes="
            << writes.positional_write_bytes << '\n';
        emit_timing("timing.read.storage", aggregate_read_storage);
        emit_timing("timing.read.prefetch", aggregate_read_prefetch);
        emit_timing("timing.write.serialization", writes.serialization);
        emit_timing("timing.write.storage", writes.storage_write);
        emit_timing("timing.write.writeback_submission",
                    writes.writeback_submission);
        emit_timing("timing.write.writeback_wait",
                    writes.writeback_wait);
        emit_timing("timing.write.finalization",
                    writes.drain_close_and_publication);
        std::cout << "diagnostic.sustained_qualification="
                  << (sustained_qualification ? "PASS" : "NOT_PUBLISHABLE")
                  << '\n'
                  << "diagnostic.result=PASS\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
