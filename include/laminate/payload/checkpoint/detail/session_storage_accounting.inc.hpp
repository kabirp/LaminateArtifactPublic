// Internal member-definition fragment for PayloadCheckpointReplayTrace.
// Include only from checkpoint/session_engine.hpp.
// Level validation, residency ledgers, and artifact retirement.

    void validate_value_level(const fhe::FheValue<Backend> &value,
                              std::size_t layer) const {
        if (value.is_encrypted() &&
            Backend::rns_limb_count(*eval_, value.ciphertext()) !=
            problem_->layers[layer].rns_limb_count) {
            throw std::invalid_argument(
                "checkpoint replay ciphertext level disagrees with the "
                "admitted plan");
        }
    }

    void update_resident_peak(std::size_t source_layer,
                              std::size_t source_count,
                              std::size_t extra_source_resident_count,
                              std::size_t output_layer,
                              std::size_t output_count) {
        const PayloadReplayLayer &source = problem_->layers[source_layer];
        const PayloadReplayLayer &output = problem_->layers[output_layer];
        std::uint64_t bytes = checkpoint_replay_execution_detail::checked_add(
            budgets_->reserved_resident_bytes,
            source_layer == output_layer ? 0 : output.affine_workspace_bytes,
            "affine DAG workspace");
        bytes = checkpoint_replay_execution_detail::checked_add(
            bytes,
            checkpoint_replay_execution_detail::checked_mul(
                checkpoint_replay_execution_detail::checked_count(
                    source_count, "resident source count"),
                checkpoint_replay_execution_detail::checked_add(
                    source.serialized_ciphertext_bytes,
                    source.resident_ciphertext_bytes,
                    "resident source per ciphertext"),
                "resident source bytes"),
            "resident source ledger");
        bytes = checkpoint_replay_execution_detail::checked_add(
            bytes,
            checkpoint_replay_execution_detail::checked_mul(
                checkpoint_replay_execution_detail::checked_count(
                    extra_source_resident_count,
                    "extra resident source count"),
                source.resident_ciphertext_bytes,
                "extra resident source bytes"),
            "extra resident source ledger");
        bytes = checkpoint_replay_execution_detail::checked_add(
            bytes,
            checkpoint_replay_execution_detail::checked_mul(
                checkpoint_replay_execution_detail::checked_count(
                    output_count, "resident output count"),
                checkpoint_replay_execution_detail::checked_add(
                    output.serialized_ciphertext_bytes,
                    output.resident_ciphertext_bytes,
                    "resident output per ciphertext"),
                "resident output bytes"),
            "resident output ledger");
        if (bytes > budgets_->max_resident_ciphertext_bytes ||
            bytes > plan_->selected.peak_resident_bytes) {
            throw std::runtime_error(
                "checkpoint replay exceeded the admitted resident bound");
        }
        report_.peak_controlled_resident_bytes =
            std::max(report_.peak_controlled_resident_bytes, bytes);
    }

    void update_proof_ingress_resident_peak(std::size_t layer) {
        const PayloadReplayLayer &resource = problem_->layers[layer];
        std::uint64_t bytes = budgets_->reserved_resident_bytes;
        bytes = checkpoint_replay_execution_detail::checked_add(
            bytes,
            checkpoint_replay_execution_detail::checked_add(
                resource.serialized_ciphertext_bytes,
                resource.resident_ciphertext_bytes,
                "natural proof-ingress input ciphertext"),
            "proof-ingress resident ledger");
        bytes = checkpoint_replay_execution_detail::checked_add(
            bytes,
            checkpoint_replay_execution_detail::checked_add(
                resource.proof_ingress_serialized_ciphertext_bytes == 0
                    ? resource.serialized_ciphertext_bytes
                    : resource
                          .proof_ingress_serialized_ciphertext_bytes,
                resource.proof_ingress_resident_ciphertext_bytes == 0
                    ? resource.resident_ciphertext_bytes
                    : resource.proof_ingress_resident_ciphertext_bytes,
                "reduced proof-ingress output value"),
            "proof-ingress resident ledger");
        const PayloadReplaySegment &segment =
            plan_->reverse_gkr_segments.at(layer - 1U);
        if (bytes != segment.proof_ingress_peak_resident_bytes ||
            bytes > budgets_->max_resident_ciphertext_bytes) {
            throw std::runtime_error(
                "proof-ingress exceeded its admitted resident bound");
        }
        report_.peak_controlled_resident_bytes =
            std::max(report_.peak_controlled_resident_bytes, bytes);
    }

    void require_live_capacity(std::uint64_t additional) const {
        const std::uint64_t projected =
            checkpoint_replay_execution_detail::checked_add(
                checkpoint_replay_execution_detail::checked_add(
                    budgets_->reserved_live_scratch_bytes,
                    report_.live_physical_bytes,
                    "checkpoint live reserve"),
                additional, "checkpoint live artifact");
        if (projected > budgets_->max_live_scratch_bytes) {
            throw std::runtime_error(
                "checkpoint replay exceeded the admitted live-storage "
                "bound before publication");
        }
    }

    void add_live_bytes(std::uint64_t bytes, bool layer_artifact) {
        report_.live_physical_bytes =
            checkpoint_replay_execution_detail::checked_add(
                report_.live_physical_bytes, bytes,
                "checkpoint live physical bytes");
        report_.peak_live_physical_bytes = std::max(
            report_.peak_live_physical_bytes,
            report_.live_physical_bytes);
        report_.peak_live_scratch_bytes = std::max(
            report_.peak_live_scratch_bytes,
            checkpoint_replay_execution_detail::checked_add(
                budgets_->reserved_live_scratch_bytes,
                report_.live_physical_bytes,
                "checkpoint peak live scratch"));
        if (report_.peak_live_scratch_bytes >
            budgets_->max_live_scratch_bytes) {
            throw std::runtime_error(
                "checkpoint replay live-storage ledger exceeded its cap");
        }
        if (layer_artifact) {
            ++live_layer_artifacts_;
            report_.peak_live_layer_artifacts = std::max(
                report_.peak_live_layer_artifacts,
                live_layer_artifacts_);
        }
    }

    void subtract_live_bytes(std::uint64_t bytes) {
        if (bytes > report_.live_physical_bytes) {
            throw std::logic_error(
                "checkpoint live physical-byte ledger underflows");
        }
        report_.live_physical_bytes -= bytes;
    }

    std::uint64_t remove_artifact(
        std::size_t layer, bool checkpoint,
        PayloadCheckpointReplayIoReport *io) {
        if (!artifacts_.at(layer)) {
            throw std::logic_error(
                "checkpoint replay artifact was already removed");
        }
        LayerArtifact &artifact = *artifacts_[layer];
        if (artifact.checkpoint != checkpoint) {
            throw std::logic_error(
                "checkpoint replay artifact ownership mismatch");
        }
        const std::uint64_t expected = artifact.report.physical_bytes;
        const FileTraceStoreRemovalReport removal =
            artifact.store.remove_validated_files_detailed();
        if (removal.namespace_physical_bytes_removed != expected) {
            throw std::logic_error(
                "checkpoint replay artifact removal ledger drifted");
        }
        const std::uint64_t removed =
            removal.unique_physical_bytes_reclaimed;
        artifacts_[layer].reset();
        subtract_live_bytes(removed);
        if (live_layer_artifacts_ == 0) {
            throw std::logic_error(
                "checkpoint live artifact count underflows");
        }
        --live_layer_artifacts_;
        if (io != nullptr) {
            checkpoint_replay_execution_detail::accumulate(
                io->physical_bytes_deleted, removed,
                "checkpoint phase deletions");
        }
        checkpoint_replay_execution_detail::accumulate(
            report_.total_reclaimed_physical_bytes, removed,
            "checkpoint total reclaimed bytes");
        if (checkpoint) {
            checkpoint_replay_execution_detail::accumulate(
                report_.checkpoint_layer_bytes_retired, removed,
                "checkpoint retained bytes retired");
        } else {
            checkpoint_replay_execution_detail::accumulate(
                report_.transient_layer_bytes_retired, removed,
                "checkpoint transient bytes retired");
        }
        return removed;
    }

    std::uint64_t remove_proof_ingress_artifact(
        std::size_t layer, PayloadCheckpointReplayIoReport *io) {
        if (!proof_ingress_artifacts_.at(layer)) {
            throw std::logic_error(
                "proof-ingress artifact was already removed");
        }
        LayerArtifact &artifact = *proof_ingress_artifacts_[layer];
        const std::uint64_t expected = artifact.report.physical_bytes;
        const FileTraceStoreRemovalReport removal =
            artifact.store.remove_validated_files_detailed();
        if (removal.namespace_physical_bytes_removed != expected) {
            throw std::logic_error(
                "proof-ingress artifact removal ledger drifted");
        }
        const std::uint64_t removed =
            removal.unique_physical_bytes_reclaimed;
        proof_ingress_artifacts_[layer].reset();
        subtract_live_bytes(removed);
        if (live_layer_artifacts_ == 0) {
            throw std::logic_error(
                "proof-ingress live artifact count underflows");
        }
        --live_layer_artifacts_;
        if (io != nullptr) {
            checkpoint_replay_execution_detail::accumulate(
                io->physical_bytes_deleted, removed,
                "proof-ingress phase deletions");
        }
        checkpoint_replay_execution_detail::accumulate(
            report_.total_reclaimed_physical_bytes, removed,
            "proof-ingress total reclaimed bytes");
        checkpoint_replay_execution_detail::accumulate(
            report_.proof_ingress_physical_bytes_retired, removed,
            "proof-ingress physical bytes retired");
        return removed;
    }

    std::uint64_t remove_eager_laned_packed_artifact(
        std::size_t layer, PayloadCheckpointReplayIoReport *io) {
        if (!eager_laned_packed_artifacts_.at(layer)) {
            throw std::logic_error(
                "Laned packed witness artifact was already removed");
        }
        LayerArtifact &artifact = *eager_laned_packed_artifacts_[layer];
        const std::uint64_t expected = artifact.report.physical_bytes;
        const FileTraceStoreRemovalReport removal =
            artifact.store.remove_validated_files_detailed();
        if (removal.namespace_physical_bytes_removed != expected) {
            throw std::logic_error(
                "Laned packed witness removal ledger drifted");
        }
        const std::uint64_t removed =
            removal.unique_physical_bytes_reclaimed;
        eager_laned_packed_artifacts_[layer].reset();
        subtract_live_bytes(removed);
        if (live_layer_artifacts_ == 0) {
            throw std::logic_error(
                "Laned packed witness artifact count underflows");
        }
        --live_layer_artifacts_;
        if (io != nullptr) {
            checkpoint_replay_execution_detail::accumulate(
                io->physical_bytes_deleted, removed,
                "Laned packed witness deletions");
        }
        checkpoint_replay_execution_detail::accumulate(
            report_.total_reclaimed_physical_bytes, removed,
            "Laned packed witness total reclaimed bytes");
        checkpoint_replay_execution_detail::accumulate(
            report_.laned_witness_physical_bytes_retired, removed,
            "Laned packed witness retired bytes");
        return removed;
    }

    static void merge_storage_read(
        FileTraceStoreReadDiagnostics &destination,
        const FileTraceStoreReadDiagnostics &source) {
        checkpoint_replay_execution_detail::accumulate(
            destination.read_batches, source.read_batches,
            "checkpoint merged storage read batches");
        checkpoint_replay_execution_detail::accumulate(
            destination.read_syscalls, source.read_syscalls,
            "checkpoint merged storage read syscalls");
        checkpoint_replay_execution_detail::accumulate(
            destination.bytes_transferred, source.bytes_transferred,
            "checkpoint merged physical read bytes");
        checkpoint_replay_execution_detail::accumulate(
            destination.prefetch_requests, source.prefetch_requests,
            "checkpoint merged prefetch requests");
        checkpoint_replay_execution_detail::accumulate(
            destination.prefetch_bytes_requested,
            source.prefetch_bytes_requested,
            "checkpoint merged requested prefetch bytes");
        checkpoint_replay_execution_detail::accumulate(
            destination.prefetch_fallbacks, source.prefetch_fallbacks,
            "checkpoint merged prefetch fallbacks");
        checkpoint_replay_execution_detail::accumulate(
            destination.prefetch_seek_disables,
            source.prefetch_seek_disables,
            "checkpoint merged seek-disabled prefetch readers");
        destination.prefetch_window_bytes = std::max(
            destination.prefetch_window_bytes,
            source.prefetch_window_bytes);
        destination.maximum_prefetch_request_bytes = std::max(
            destination.maximum_prefetch_request_bytes,
            source.maximum_prefetch_request_bytes);
        destination.maximum_batch_bytes = std::max(
            destination.maximum_batch_bytes, source.maximum_batch_bytes);
        destination.transfer_buffer_bytes = std::max(
            destination.transfer_buffer_bytes, source.transfer_buffer_bytes);
        destination.storage_read += source.storage_read;
        destination.prefetch += source.prefetch;
    }

    static void merge_storage_write(
        FileTraceStoreWriteDiagnostics &destination,
        const FileTraceStoreWriteDiagnostics &source) {
        const auto add = [](std::uint64_t &target, std::uint64_t value,
                            const char *description) {
            checkpoint_replay_execution_detail::accumulate(
                target, value, description);
        };
        add(destination.records, source.records,
            "checkpoint merged storage records");
        add(destination.authenticated_records, source.authenticated_records,
            "checkpoint merged authenticated records");
        add(destination.authenticated_record_bytes,
            source.authenticated_record_bytes,
            "checkpoint merged authenticated record bytes");
        add(destination.same_process_unhashed_records,
            source.same_process_unhashed_records,
            "checkpoint merged same-process unhashed records");
        add(destination.same_process_unhashed_record_bytes,
            source.same_process_unhashed_record_bytes,
            "checkpoint merged same-process unhashed record bytes");
        add(destination.record_copy_bytes, source.record_copy_bytes,
            "checkpoint merged copied record bytes");
        add(destination.capacity_probes, source.capacity_probes,
            "checkpoint merged capacity probes");
        add(destination.write_batches, source.write_batches,
            "checkpoint merged storage write batches");
        add(destination.write_syscalls, source.write_syscalls,
            "checkpoint merged storage write syscalls");
        add(destination.bytes_submitted, source.bytes_submitted,
            "checkpoint merged submitted bytes");
        destination.maximum_batch_bytes = std::max(
            destination.maximum_batch_bytes, source.maximum_batch_bytes);
        destination.transfer_buffer_bytes = std::max(
            destination.transfer_buffer_bytes, source.transfer_buffer_bytes);
        destination.transfer_buffer_count = std::max(
            destination.transfer_buffer_count, source.transfer_buffer_count);
        add(destination.writeback_files_enabled,
            source.writeback_files_enabled,
            "checkpoint merged writeback-enabled files");
        add(destination.writeback_files_fallback,
            source.writeback_files_fallback,
            "checkpoint merged writeback-fallback files");
        add(destination.writeback_files_submit_only,
            source.writeback_files_submit_only,
            "checkpoint merged submit-only writeback files");
        add(destination.writeback_submission_attempts,
            source.writeback_submission_attempts,
            "checkpoint merged writeback submission attempts");
        add(destination.writeback_submission_successes,
            source.writeback_submission_successes,
            "checkpoint merged writeback submission successes");
        add(destination.writeback_wait_attempts,
            source.writeback_wait_attempts,
            "checkpoint merged writeback wait attempts");
        add(destination.writeback_wait_successes,
            source.writeback_wait_successes,
            "checkpoint merged writeback wait successes");
        add(destination.writeback_range_bytes_submitted,
            source.writeback_range_bytes_submitted,
            "checkpoint merged submitted writeback range bytes");
        add(destination.writeback_range_bytes_waited,
            source.writeback_range_bytes_waited,
            "checkpoint merged waited writeback range bytes");
        destination.maximum_writeback_submission_bytes = std::max(
            destination.maximum_writeback_submission_bytes,
            source.maximum_writeback_submission_bytes);
        destination.writeback_window_bytes = std::max(
            destination.writeback_window_bytes,
            source.writeback_window_bytes);
        destination.maximum_unwaited_writeback_range_bytes = std::max(
            destination.maximum_unwaited_writeback_range_bytes,
            source.maximum_unwaited_writeback_range_bytes);
        add(destination.writeback_drains, source.writeback_drains,
            "checkpoint merged writeback drains");
        add(destination.writeback_drain_range_bytes,
            source.writeback_drain_range_bytes,
            "checkpoint merged writeback drain range bytes");
        add(destination.writeback_drains_skipped,
            source.writeback_drains_skipped,
            "checkpoint merged skipped writeback drains");
        add(destination.writeback_range_bytes_without_explicit_wait,
            source.writeback_range_bytes_without_explicit_wait,
            "checkpoint merged writeback range bytes without explicit wait");
        add(destination.positional_write_calls,
            source.positional_write_calls,
            "checkpoint merged positional write calls");
        add(destination.positional_write_bytes,
            source.positional_write_bytes,
            "checkpoint merged positional write bytes");
        destination.serialization += source.serialization;
        destination.buffer_assembly += source.buffer_assembly;
        destination.hashing += source.hashing;
        destination.capacity_admission += source.capacity_admission;
        destination.output_submission += source.output_submission;
        destination.storage_write += source.storage_write;
        destination.writeback_submission += source.writeback_submission;
        destination.writeback_wait += source.writeback_wait;
        destination.drain_close_and_publication +=
            source.drain_close_and_publication;
    }

    static void merge_io(PayloadCheckpointReplayIoReport &destination,
                         const PayloadCheckpointReplayIoReport &source) {
        destination.relation += source.relation;
        destination.deserialization += source.deserialization;
        destination.fhe_evaluation += source.fhe_evaluation;
        destination.modulus_switching += source.modulus_switching;
        merge_storage_read(destination.storage_reads, source.storage_reads);
        merge_storage_write(destination.storage_writes,
                            source.storage_writes);
        checkpoint_replay_execution_detail::accumulate(
            destination.encoded_ciphertext_bytes_read,
            source.encoded_ciphertext_bytes_read,
            "checkpoint merged encoded reads");
        checkpoint_replay_execution_detail::accumulate(
            destination.encoded_ciphertext_bytes_written,
            source.encoded_ciphertext_bytes_written,
            "checkpoint merged encoded writes");
        checkpoint_replay_execution_detail::accumulate(
            destination.framed_record_bytes_read,
            source.framed_record_bytes_read,
            "checkpoint merged framed reads");
        checkpoint_replay_execution_detail::accumulate(
            destination.physical_bytes_written,
            source.physical_bytes_written,
            "checkpoint merged physical writes");
        checkpoint_replay_execution_detail::accumulate(
            destination.physical_validation_bytes_read,
            source.physical_validation_bytes_read,
            "checkpoint merged validation reads");
        checkpoint_replay_execution_detail::accumulate(
            destination.physical_bytes_deleted,
            source.physical_bytes_deleted,
            "checkpoint merged deletions");
        checkpoint_replay_execution_detail::accumulate(
            destination.range_readers_opened,
            source.range_readers_opened,
            "checkpoint merged range readers");
        checkpoint_replay_execution_detail::accumulate(
            destination.monotone_dense_multiplication_relations,
            source.monotone_dense_multiplication_relations,
            "checkpoint merged monotone dense relations");
        checkpoint_replay_execution_detail::accumulate(
            destination.monotone_dense_multiplication_range_readers_opened,
            source.monotone_dense_multiplication_range_readers_opened,
            "checkpoint merged monotone dense readers");
        checkpoint_replay_execution_detail::accumulate(
            destination.monotone_dense_multiplication_source_records_read,
            source.monotone_dense_multiplication_source_records_read,
            "checkpoint merged monotone dense records");
        checkpoint_replay_execution_detail::accumulate(
            destination.alias_cached_dense_multiplication_relations,
            source.alias_cached_dense_multiplication_relations,
            "checkpoint merged alias-cached dense relations");
        checkpoint_replay_execution_detail::accumulate(
            destination
                .alias_cached_dense_multiplication_range_readers_opened,
            source.alias_cached_dense_multiplication_range_readers_opened,
            "checkpoint merged alias-cache readers");
        checkpoint_replay_execution_detail::accumulate(
            destination
                .alias_cached_dense_multiplication_distinct_source_records_read,
            source
                .alias_cached_dense_multiplication_distinct_source_records_read,
            "checkpoint merged alias-cache distinct records");
        checkpoint_replay_execution_detail::accumulate(
            destination
                .alias_cached_dense_multiplication_logical_source_uses,
            source.alias_cached_dense_multiplication_logical_source_uses,
            "checkpoint merged alias-cache logical uses");
        checkpoint_replay_execution_detail::accumulate(
            destination
                .alias_cached_dense_multiplication_fallback_source_records,
            source
                .alias_cached_dense_multiplication_fallback_source_records,
            "checkpoint merged alias-cache fallback source records");
        checkpoint_replay_execution_detail::accumulate(
            destination.identity_affine_alias_relations,
            source.identity_affine_alias_relations,
            "checkpoint merged identity affine aliases");
        checkpoint_replay_execution_detail::accumulate(
            destination.identity_affine_alias_fallbacks,
            source.identity_affine_alias_fallbacks,
            "checkpoint merged identity affine alias fallbacks");
        checkpoint_replay_execution_detail::accumulate(
            destination.identity_affine_alias_records_reused,
            source.identity_affine_alias_records_reused,
            "checkpoint merged identity affine alias records");
        checkpoint_replay_execution_detail::accumulate(
            destination.identity_affine_alias_layer_bytes_reused,
            source.identity_affine_alias_layer_bytes_reused,
            "checkpoint merged identity affine alias reused bytes");
        checkpoint_replay_execution_detail::accumulate(
            destination.identity_affine_alias_unique_bytes_written,
            source.identity_affine_alias_unique_bytes_written,
            "checkpoint merged identity affine alias written bytes");
    }
