/// @file file_trace_store_benchmark.cpp
/// @brief Single-threaded canonical trace-store transfer diagnostic.

#include "laminate/payload/storage/file_trace_store.hpp"

#include "benchmark_support.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
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

void emit_timing(std::string_view prefix,
                 const FileTraceStoreOperationTiming &timing) {
    std::cout << prefix << ".wall_ms=" << timing.wall_ms << '\n'
              << prefix << ".cpu_ms=" << timing.cpu_ms << '\n';
}

void force_file_to_storage(const std::filesystem::path &path) {
#ifndef _WIN32
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        throw std::runtime_error(
            "failed to open diagnostic artifact for final sync: " +
            std::error_code(errno, std::generic_category()).message());
    }
    int sync_result = 0;
    do {
        sync_result = ::fsync(descriptor);
    } while (sync_result != 0 && errno == EINTR);
    const int sync_error = sync_result == 0 ? 0 : errno;
    const int close_result = ::close(descriptor);
    if (sync_error != 0) {
        throw std::runtime_error(
            "failed to sync diagnostic artifact: " +
            std::error_code(sync_error, std::generic_category()).message());
    }
    if (close_result != 0) {
        throw std::runtime_error("failed to close diagnostic artifact");
    }
#else
    (void)path;
#endif
}

} // namespace

int main(int argc, char **argv) {
    try {
        if (argc < 9 || argc % 2 == 0 ||
            std::string_view(argv[1]) != "--directory" ||
            std::string_view(argv[3]) != "--transfer-mib" ||
            std::string_view(argv[5]) != "--total-mib" ||
            std::string_view(argv[7]) != "--record-kib") {
            throw std::invalid_argument(
                "expected --directory ABSENT_PATH --transfer-mib N "
                "--total-mib N --record-kib N [--writeback-mib N] "
                "[--integrity authenticated|ephemeral] "
                "[--record-path staged|direct]");
        }
        const std::filesystem::path directory = argv[2];
        if (!directory.is_absolute() ||
            directory == directory.root_path() ||
            std::filesystem::exists(directory)) {
            throw std::invalid_argument(
                "--directory must be an absent absolute child path");
        }
        constexpr std::uint64_t kMiB = 1024ULL * 1024ULL;
        constexpr std::uint64_t kKiB = 1024ULL;
        const std::uint64_t transfer_bytes = multiply(
            parse_u64(argv[4], "transfer MiB"), kMiB,
            "transfer bytes");
        const std::uint64_t total_bytes = multiply(
            parse_u64(argv[6], "total MiB"), kMiB, "total bytes");
        const std::uint64_t record_bytes = multiply(
            parse_u64(argv[8], "record KiB"), kKiB, "record bytes");
        std::uint64_t writeback_bytes =
            kFileTraceStoreWritebackWindowBytes;
        FileTraceStoreIntegrityMode integrity_mode =
            FileTraceStoreIntegrityMode::ReopenableAuthenticated;
        std::string_view integrity_name = "authenticated";
        bool direct_record_path = false;
        std::string_view record_path_name = "staged";
        for (int argument = 9; argument < argc; argument += 2) {
            const std::string_view option = argv[argument];
            const std::string_view value = argv[argument + 1];
            if (option == "--writeback-mib") {
                writeback_bytes = multiply(
                    parse_u64(value, "writeback MiB", true), kMiB,
                    "writeback bytes");
            } else if (option == "--integrity") {
                if (value == "authenticated") {
                    integrity_mode = FileTraceStoreIntegrityMode::
                        ReopenableAuthenticated;
                } else if (value == "ephemeral") {
                    integrity_mode = FileTraceStoreIntegrityMode::
                        SameProcessEphemeral;
                } else {
                    throw std::invalid_argument(
                        "--integrity must be authenticated or ephemeral");
                }
                integrity_name = value;
            } else if (option == "--record-path") {
                if (value != "staged" && value != "direct") {
                    throw std::invalid_argument(
                        "--record-path must be staged or direct");
                }
                direct_record_path = value == "direct";
                record_path_name = value;
            } else {
                throw std::invalid_argument("unknown diagnostic option: " +
                                            std::string(option));
            }
        }
        if (total_bytes % record_bytes != 0 ||
            total_bytes / record_bytes >
                std::numeric_limits<std::size_t>::max()) {
            throw std::invalid_argument(
                "total MiB must contain an integral size_t record count");
        }
        const std::size_t records =
            static_cast<std::size_t>(total_bytes / record_bytes);
        if (records == 0 || (records & (records - 1U)) != 0) {
            throw std::invalid_argument(
                "the diagnostic record count must be a power of two");
        }
        std::vector<std::uint8_t> record(
            static_cast<std::size_t>(record_bytes));
        for (std::size_t index = 0; index < record.size(); ++index) {
            record[index] = static_cast<std::uint8_t>(
                (index * 131U + 17U) & 0xffU);
        }
        Digest context_id{};
        context_id.front() = 1;
        Digest circuit_id{};
        circuit_id.front() = 2;
        Digest trace_id{};
        trace_id.front() = 3;
        const std::uint64_t maximum = total_bytes + 32ULL * kMiB;
        const FileTraceStoreOptions storage_options{
            .max_total_bytes = maximum,
            .min_free_bytes = 1,
            .transfer_buffer_bytes = transfer_bytes,
            .writeback_window_bytes = writeback_bytes,
            .integrity_mode = integrity_mode,
        };
        SerializedTraceWriter writer(directory, storage_options, context_id);
        laminate::bench::Stopwatch write_stopwatch;
        writer.begin_trace(PayloadShape::wide(2),
                           TraceProvenance::SyntheticTrace,
                           circuit_id, trace_id, 1);
        writer.begin_layer(
            0, TraceLayerLayout::Wide,
            LayerDimensions{records, records, records, 0}, 0, records);
        std::vector<std::uint8_t> staged_record(record.size());
        for (std::size_t index = 0; index < records; ++index) {
            if (direct_record_path) {
                writer.append_serialized_direct(
                    record_bytes,
                    [&](std::vector<std::uint8_t> &output) {
                        output.insert(output.end(), record.begin(),
                                      record.end());
                    });
            } else {
                laminate::bench::Stopwatch serialization_stopwatch;
                std::copy(record.begin(), record.end(),
                          staged_record.begin());
                const laminate::bench::Timing serialization =
                    serialization_stopwatch.stop();
                writer.append_serialized(
                    staged_record,
                    FileTraceStoreOperationTiming{
                        serialization.wall_ms, serialization.cpu_ms});
            }
        }
        writer.finish_layer();
        auto store =
            std::move(writer).finish_private_single_layer_store();
        laminate::bench::Stopwatch final_sync_stopwatch;
        force_file_to_storage(directory / "layer-0000000000000000.bin");
        force_file_to_storage(directory / "manifest.bin");
        const laminate::bench::Timing final_sync_timing =
            final_sync_stopwatch.stop();
        const laminate::bench::Timing write_timing =
            write_stopwatch.stop();

        FileTraceStoreReadDiagnostics reads;
        laminate::bench::Stopwatch read_stopwatch;
        {
            auto reader = store.layer_range(0, 0, records, &reads);
            std::size_t observed = 0;
            while (const auto encoded = reader.next_view()) {
                if (encoded->size() != record.size() ||
                    encoded->front() != record.front() ||
                    encoded->back() != record.back()) {
                    throw std::runtime_error(
                        "trace-store diagnostic record mismatch");
                }
                ++observed;
            }
            if (observed != records) {
                throw std::runtime_error(
                    "trace-store diagnostic record count mismatch");
            }
        }
        const laminate::bench::Timing read_timing = read_stopwatch.stop();
        const FileTraceStoreWriteDiagnostics writes =
            store.write_diagnostics();
        const std::uint64_t physical = store.report().physical_bytes;
        if (store.remove_validated_files() != physical ||
            !std::filesystem::remove(directory)) {
            throw std::runtime_error(
                "trace-store diagnostic cleanup failed");
        }

        const double write_ms = write_timing.wall_ms;
        const double read_ms = read_timing.wall_ms;
        std::cout << std::fixed << std::setprecision(3)
                  << "format=laminate-payload-storage-v1\n"
                  << "classification=measured-single-thread\n";
        const laminate::bench::Record provenance;
        laminate::bench::emit_benchmark_provenance(provenance, argc, argv);
        provenance.text("environment.threading", "single-threaded");
        std::cout << "parameters.transfer_buffer_bytes=" << transfer_bytes
                  << '\n'
                  << "parameters.writeback_window_bytes="
                  << writeback_bytes << '\n'
                  << "parameters.record_bytes=" << record_bytes << '\n'
                  << "parameters.records=" << records << '\n'
                  << "parameters.integrity=" << integrity_name << '\n'
                  << "parameters.record_path=" << record_path_name << '\n'
                  << "storage.physical_bytes=" << physical << '\n'
                  << "write.wall_ms=" << write_ms << '\n'
                  << "write.cpu_ms=" << write_timing.cpu_ms << '\n'
                  << "write.cpu_utilization_percent="
                  << (write_ms == 0.0
                          ? 0.0
                          : 100.0 * write_timing.cpu_ms / write_ms)
                  << '\n'
                  << "write.effective_mib_per_second="
                  << (1000.0 * static_cast<double>(physical) /
                      static_cast<double>(kMiB) / write_ms)
                  << '\n'
                  << "write.capacity_probes=" << writes.capacity_probes
                  << '\n'
                  << "write.batches=" << writes.write_batches << '\n'
                  << "write.syscalls=" << writes.write_syscalls << '\n'
                  << "write.maximum_batch_bytes="
                  << writes.maximum_batch_bytes << '\n'
                  << "write.authenticated_record_bytes="
                  << writes.authenticated_record_bytes << '\n'
                  << "write.same_process_unhashed_record_bytes="
                  << writes.same_process_unhashed_record_bytes << '\n'
                  << "write.record_copy_bytes="
                  << writes.record_copy_bytes << '\n'
                  << "write.writeback_files_enabled="
                  << writes.writeback_files_enabled << '\n'
                  << "write.writeback_files_fallback="
                  << writes.writeback_files_fallback << '\n'
                  << "write.writeback_files_submit_only="
                  << writes.writeback_files_submit_only << '\n'
                  << "write.writeback_submission_attempts="
                  << writes.writeback_submission_attempts << '\n'
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
                  << "write.writeback_drains="
                  << writes.writeback_drains << '\n'
                  << "write.writeback_drain_range_bytes="
                  << writes.writeback_drain_range_bytes << '\n'
                  << "write.writeback_drains_skipped="
                  << writes.writeback_drains_skipped << '\n'
                  << "write.writeback_range_bytes_without_explicit_wait="
                  << writes.writeback_range_bytes_without_explicit_wait << '\n'
                  << "write.positional_write_calls="
                  << writes.positional_write_calls << '\n'
                  << "write.positional_write_bytes="
                  << writes.positional_write_bytes << '\n'
                  << "write.final_sync_wall_ms="
                  << final_sync_timing.wall_ms << '\n'
                  << "write.final_sync_cpu_ms="
                  << final_sync_timing.cpu_ms << '\n'
                  << "read.wall_ms=" << read_ms << '\n'
                  << "read.cpu_ms=" << read_timing.cpu_ms << '\n'
                  << "read.cpu_utilization_percent="
                  << (read_ms == 0.0
                          ? 0.0
                          : 100.0 * read_timing.cpu_ms / read_ms)
                  << '\n'
                  << "read.effective_mib_per_second="
                  << (1000.0 * static_cast<double>(reads.bytes_transferred) /
                      static_cast<double>(kMiB) / read_ms)
                  << '\n'
                  << "read.batches=" << reads.read_batches << '\n'
                  << "read.syscalls=" << reads.read_syscalls << '\n'
                  << "read.prefetch_requests="
                  << reads.prefetch_requests << '\n'
                  << "read.prefetch_bytes_requested="
                  << reads.prefetch_bytes_requested << '\n'
                  << "read.prefetch_fallbacks="
                  << reads.prefetch_fallbacks << '\n'
                  << "read.prefetch_seek_disables="
                  << reads.prefetch_seek_disables << '\n'
                  << "read.prefetch_window_bytes="
                  << reads.prefetch_window_bytes << '\n'
                  << "read.maximum_prefetch_request_bytes="
                  << reads.maximum_prefetch_request_bytes << '\n'
                  << "read.maximum_batch_bytes="
                  << reads.maximum_batch_bytes << '\n';
        emit_timing("timing.write.serialization", writes.serialization);
        emit_timing("timing.write.buffer_assembly",
                    writes.buffer_assembly);
        emit_timing("timing.write.hashing", writes.hashing);
        emit_timing("timing.write.capacity_admission",
                    writes.capacity_admission);
        emit_timing("timing.write.storage", writes.storage_write);
        emit_timing("timing.write.writeback_submission",
                    writes.writeback_submission);
        emit_timing("timing.write.writeback_wait",
                    writes.writeback_wait);
        emit_timing("timing.read.storage", reads.storage_read);
        emit_timing("timing.read.prefetch", reads.prefetch);
        std::cout << "diagnostic.result=PASS\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
