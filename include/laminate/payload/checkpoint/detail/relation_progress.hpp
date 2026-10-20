#ifndef LAMINATE_PAYLOAD_CHECKPOINT_DETAIL_RELATION_PROGRESS_HPP
#define LAMINATE_PAYLOAD_CHECKPOINT_DETAIL_RELATION_PROGRESS_HPP

/// @file relation_progress.hpp
/// @brief Phase-local telemetry attribution for one payload relation.

#include "laminate/payload/checkpoint/artifact_io.hpp"

#include <algorithm>
#include <cstdint>

namespace laminate::payload::checkpoint_replay_execution_detail {

/// Composes an honest progress snapshot from one relation's local read/write
/// ledgers and the aggregate FHE ledger. Completed writers have already been
/// merged into `phase_writes`; the currently open writer remains handle-local
/// and is supplied to `populate` without mutating either accounting ledger.
class RelationProgressAttribution {
  public:
    RelationProgressAttribution(
        const PayloadCheckpointReplayIoReport &aggregate,
        const FileTraceStoreReadDiagnostics &phase_reads,
        const FileTraceStoreWriteDiagnostics &phase_writes)
        : aggregate_(aggregate), phase_begin_(aggregate),
          phase_reads_(phase_reads), phase_writes_(phase_writes) {}

    void populate(
        RuntimeProgressEvent &event,
        const FileTraceStoreWriteDiagnostics &active_writes,
        FileTraceStoreOperationTiming phase_timing) const {
        event.phase_wall_ms = phase_timing.wall_ms;
        event.phase_cpu_ms = phase_timing.cpu_ms;
        event.fhe_wall_ms = elapsed(aggregate_.fhe_evaluation.wall_ms,
                                    phase_begin_.fhe_evaluation.wall_ms);
        event.fhe_cpu_ms = elapsed(aggregate_.fhe_evaluation.cpu_ms,
                                   phase_begin_.fhe_evaluation.cpu_ms);
        event.modulus_switch_wall_ms = elapsed(
            aggregate_.modulus_switching.wall_ms,
            phase_begin_.modulus_switching.wall_ms);
        event.modulus_switch_cpu_ms = elapsed(
            aggregate_.modulus_switching.cpu_ms,
            phase_begin_.modulus_switching.cpu_ms);
        event.deserialization_wall_ms = elapsed(
            aggregate_.deserialization.wall_ms,
            phase_begin_.deserialization.wall_ms);
        event.deserialization_cpu_ms = elapsed(
            aggregate_.deserialization.cpu_ms,
            phase_begin_.deserialization.cpu_ms);

        assign_timing(event.serialization_wall_ms,
                      event.serialization_cpu_ms,
                      phase_writes_.serialization,
                      active_writes.serialization);
        assign_timing(event.buffer_assembly_wall_ms,
                      event.buffer_assembly_cpu_ms,
                      phase_writes_.buffer_assembly,
                      active_writes.buffer_assembly);
        assign_timing(event.hashing_wall_ms, event.hashing_cpu_ms,
                      phase_writes_.hashing, active_writes.hashing);

        event.storage_read_wall_ms = phase_reads_.storage_read.wall_ms;
        event.storage_read_cpu_ms = phase_reads_.storage_read.cpu_ms;
        assign_timing(event.storage_write_wall_ms,
                      event.storage_write_cpu_ms,
                      phase_writes_.storage_write,
                      active_writes.storage_write);
        event.prefetch_wall_ms = phase_reads_.prefetch.wall_ms;
        event.prefetch_cpu_ms = phase_reads_.prefetch.cpu_ms;
        assign_timing(event.writeback_submission_wall_ms,
                      event.writeback_submission_cpu_ms,
                      phase_writes_.writeback_submission,
                      active_writes.writeback_submission);
        assign_timing(event.writeback_wait_wall_ms,
                      event.writeback_wait_cpu_ms,
                      phase_writes_.writeback_wait,
                      active_writes.writeback_wait);

        // Time spent inside storage APIs includes both CPU work and I/O waits.
        event.storage_wait_wall_ms =
            event.storage_read_wall_ms + event.storage_write_wall_ms +
            event.prefetch_wall_ms + event.writeback_submission_wall_ms +
            event.writeback_wait_wall_ms;
        event.storage_wait_cpu_ms =
            event.storage_read_cpu_ms + event.storage_write_cpu_ms +
            event.prefetch_cpu_ms + event.writeback_submission_cpu_ms +
            event.writeback_wait_cpu_ms;

        event.capacity_probes = write_count(
            phase_writes_.capacity_probes, active_writes.capacity_probes,
            "phase-local capacity probes");
        event.read_batches = phase_reads_.read_batches;
        event.read_syscalls = phase_reads_.read_syscalls;
        event.application_read_bytes = phase_reads_.bytes_transferred;
        event.prefetch_requests = phase_reads_.prefetch_requests;
        event.prefetch_bytes_requested =
            phase_reads_.prefetch_bytes_requested;
        event.prefetch_fallbacks = phase_reads_.prefetch_fallbacks;
        event.prefetch_seek_disables = phase_reads_.prefetch_seek_disables;
        event.prefetch_window_bytes = phase_reads_.prefetch_requests == 0
                                          ? 0
                                          : phase_reads_.prefetch_window_bytes;
        event.maximum_prefetch_request_bytes =
            phase_reads_.maximum_prefetch_request_bytes;

        event.write_batches = write_count(phase_writes_.write_batches,
                                          active_writes.write_batches);
        event.write_syscalls = write_count(phase_writes_.write_syscalls,
                                           active_writes.write_syscalls);
        event.application_write_bytes = write_count(
            phase_writes_.bytes_submitted, active_writes.bytes_submitted);
        event.authenticated_record_bytes = write_count(
            phase_writes_.authenticated_record_bytes,
            active_writes.authenticated_record_bytes);
        event.same_process_unhashed_record_bytes = write_count(
            phase_writes_.same_process_unhashed_record_bytes,
            active_writes.same_process_unhashed_record_bytes);
        event.record_copy_bytes = write_count(
            phase_writes_.record_copy_bytes,
            active_writes.record_copy_bytes);
        event.writeback_submission_attempts = write_count(
            phase_writes_.writeback_submission_attempts,
            active_writes.writeback_submission_attempts);
        event.writeback_submission_successes = write_count(
            phase_writes_.writeback_submission_successes,
            active_writes.writeback_submission_successes);
        event.writeback_wait_attempts = write_count(
            phase_writes_.writeback_wait_attempts,
            active_writes.writeback_wait_attempts);
        event.writeback_wait_successes = write_count(
            phase_writes_.writeback_wait_successes,
            active_writes.writeback_wait_successes);
        event.writeback_range_bytes_submitted = write_count(
            phase_writes_.writeback_range_bytes_submitted,
            active_writes.writeback_range_bytes_submitted);
        event.writeback_range_bytes_waited = write_count(
            phase_writes_.writeback_range_bytes_waited,
            active_writes.writeback_range_bytes_waited);
        event.maximum_writeback_submission_bytes = std::max(
            phase_writes_.maximum_writeback_submission_bytes,
            active_writes.maximum_writeback_submission_bytes);
        event.writeback_window_bytes =
            event.writeback_submission_attempts == 0
                ? 0
                : std::max(phase_writes_.writeback_window_bytes,
                           active_writes.writeback_window_bytes);
        event.maximum_unwaited_writeback_range_bytes = std::max(
            phase_writes_.maximum_unwaited_writeback_range_bytes,
            active_writes.maximum_unwaited_writeback_range_bytes);
        event.writeback_files_submit_only = write_count(
            phase_writes_.writeback_files_submit_only,
            active_writes.writeback_files_submit_only);
        event.writeback_drains = write_count(
            phase_writes_.writeback_drains, active_writes.writeback_drains);
        event.writeback_drain_range_bytes = write_count(
            phase_writes_.writeback_drain_range_bytes,
            active_writes.writeback_drain_range_bytes);
        event.writeback_drains_skipped = write_count(
            phase_writes_.writeback_drains_skipped,
            active_writes.writeback_drains_skipped);
        event.writeback_range_bytes_without_explicit_wait = write_count(
            phase_writes_.writeback_range_bytes_without_explicit_wait,
            active_writes.writeback_range_bytes_without_explicit_wait);
        event.positional_write_calls = write_count(
            phase_writes_.positional_write_calls,
            active_writes.positional_write_calls);
        event.positional_write_bytes = write_count(
            phase_writes_.positional_write_bytes,
            active_writes.positional_write_bytes);
        event.maximum_read_batch_bytes = phase_reads_.maximum_batch_bytes;
        event.maximum_write_batch_bytes = std::max(
            phase_writes_.maximum_batch_bytes,
            active_writes.maximum_batch_bytes);

        event.identity_affine_alias_relations = delta(
            aggregate_.identity_affine_alias_relations,
            phase_begin_.identity_affine_alias_relations);
        event.identity_affine_alias_fallbacks = delta(
            aggregate_.identity_affine_alias_fallbacks,
            phase_begin_.identity_affine_alias_fallbacks);
        event.identity_affine_alias_records_reused = delta(
            aggregate_.identity_affine_alias_records_reused,
            phase_begin_.identity_affine_alias_records_reused);
        event.identity_affine_alias_layer_bytes_reused = delta(
            aggregate_.identity_affine_alias_layer_bytes_reused,
            phase_begin_.identity_affine_alias_layer_bytes_reused);
        event.identity_affine_alias_unique_bytes_written = delta(
            aggregate_.identity_affine_alias_unique_bytes_written,
            phase_begin_.identity_affine_alias_unique_bytes_written);
    }

    FileTraceStoreOperationTiming completed_relation_timing() const {
        return {
            elapsed(aggregate_.relation.wall_ms,
                    phase_begin_.relation.wall_ms),
            elapsed(aggregate_.relation.cpu_ms,
                    phase_begin_.relation.cpu_ms),
        };
    }

  private:
    static double elapsed(double after, double before) {
        return std::max(0.0, after - before);
    }

    static std::uint64_t delta(std::uint64_t after,
                               std::uint64_t before) {
        return after >= before ? after - before : 0U;
    }

    static void assign_timing(
        double &wall_ms, double &cpu_ms,
        const FileTraceStoreOperationTiming &completed,
        const FileTraceStoreOperationTiming &active) {
        wall_ms = completed.wall_ms + active.wall_ms;
        cpu_ms = completed.cpu_ms + active.cpu_ms;
    }

    static std::uint64_t write_count(
        std::uint64_t completed, std::uint64_t active,
        const char *label = "phase-local storage diagnostic counter") {
        return checked_add(completed, active, label);
    }

    const PayloadCheckpointReplayIoReport &aggregate_;
    PayloadCheckpointReplayIoReport phase_begin_;
    const FileTraceStoreReadDiagnostics &phase_reads_;
    const FileTraceStoreWriteDiagnostics &phase_writes_;
};

} // namespace laminate::payload::checkpoint_replay_execution_detail

#endif // LAMINATE_PAYLOAD_CHECKPOINT_DETAIL_RELATION_PROGRESS_HPP
