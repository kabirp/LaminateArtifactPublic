// Internal member-definition fragment for PayloadCheckpointReplayTrace.
// Include only from checkpoint/session_engine.hpp.
// Chunk reads and affine or dense-multiplication relation evaluation.

    void append_stored_range(
        std::size_t layer, std::size_t live_begin, std::size_t live_end,
        PayloadCheckpointReplayIoReport &io,
        std::vector<fhe::FheValue<Backend>> &destination,
        FileTraceStoreReadDiagnostics *phase_storage_reads = nullptr) const {
        checkpoint_replay_execution_detail::accumulate(
            io.range_readers_opened, 1, "checkpoint range readers");
        auto reader = artifacts_.at(layer)->store.layer_range(
            0, live_begin, live_end,
            phase_storage_reads != nullptr ? phase_storage_reads
                                           : &io.storage_reads);
        while (const auto encoded = reader.next_view()) {
            destination.push_back(
                deserialize_stored_value(layer, *encoded, io));
        }
    }

    fhe::FheValue<Backend> deserialize_stored_value(
        std::size_t, std::span<const std::uint8_t> encoded,
        PayloadCheckpointReplayIoReport &io) const {
        checkpoint_replay_execution_detail::accumulate(
            io.encoded_ciphertext_bytes_read,
            checkpoint_replay_execution_detail::checked_count(
                encoded.size(), "checkpoint stored-range bytes"),
            "checkpoint stored-range bytes");
        checkpoint_replay_execution_detail::accumulate(
            io.framed_record_bytes_read,
            checkpoint_replay_execution_detail::checked_add(
                checkpoint_replay_execution_detail::checked_count(
                    encoded.size(), "checkpoint framed stored record"),
                sizeof(std::uint64_t),
                "checkpoint framed stored record"),
            "checkpoint framed stored record");
        checkpoint_replay_execution_detail::ScopedOperationTimer timer(
            io.deserialization);
        return fhe::decode_validated_private_fhe_value_record<Backend>(
            *eval_, encoded);
    }

    std::optional<std::size_t> monotone_dense_multiplication_split(
        std::size_t source_layer, std::size_t output_layer,
        const LayerStorageLayout &source_storage,
        const LayerStorageLayout &output_storage) const {
        const auto *multiplication =
            std::get_if<MultiplicationLayer>(&circuit_->layers[output_layer]);
        if (multiplication == nullptr ||
            source_storage.stored_wire_count !=
                trace_layout_->layout()
                    .wire_support[source_layer]
                    .live_wire_count) {
            return std::nullopt;
        }
        const std::size_t pair_count =
            multiplication->dimensions.padded_size;
        if (pair_count > std::numeric_limits<std::size_t>::max() / 2U ||
            source_storage.padded_wire_count != 2U * pair_count) {
            return std::nullopt;
        }

        // Canonical alias-free storage is ordered by padded index. Prove that
        // its two logical halves are independently contiguous before opening
        // either cursor; otherwise retain the fully general chunk evaluator.
        std::size_t left_count = 0;
        for (std::size_t padded = 0; padded < pair_count; ++padded) {
            const std::optional<std::size_t> stored =
                source_storage.stored_ordinal_of(padded);
            if (stored) {
                if (*stored != left_count) {
                    return std::nullopt;
                }
                ++left_count;
            }
        }
        std::size_t right_count = 0;
        for (std::size_t padded = pair_count;
             padded < source_storage.padded_wire_count; ++padded) {
            const std::optional<std::size_t> stored =
                source_storage.stored_ordinal_of(padded);
            if (stored) {
                if (*stored != left_count + right_count) {
                    return std::nullopt;
                }
                ++right_count;
            }
        }
        if (left_count + right_count !=
            source_storage.stored_wire_count) {
            return std::nullopt;
        }

        // Every retained source record must be consumed exactly once and in
        // ordinal order by retained output gates. Forward gates omit their
        // unused public right operands.
        std::size_t used_left = 0;
        std::size_t used_right = 0;
        for (std::size_t live_gate = 0;
             live_gate < output_storage.stored_wire_count; ++live_gate) {
            const std::size_t gate_index =
                output_storage.representative_padded_index_of(live_gate);
            const MultiplicationGate &gate =
                multiplication->gates.at(gate_index);
            if (gate.origin == GateOrigin::Padding) {
                return std::nullopt;
            }
            const std::optional<std::size_t> stored_left =
                source_storage.stored_ordinal_of(gate_index);
            if (stored_left) {
                if (*stored_left != used_left) {
                    return std::nullopt;
                }
                ++used_left;
            }
            if (gate.origin == GateOrigin::Payload) {
                const std::optional<std::size_t> stored_right =
                    source_storage.stored_ordinal_of(pair_count + gate_index);
                if (stored_right) {
                    if (*stored_right != left_count + used_right) {
                        return std::nullopt;
                    }
                    ++used_right;
                }
            }
        }
        if (used_left != left_count || used_right != right_count) {
            return std::nullopt;
        }
        return left_count;
    }

    std::optional<std::uint64_t> alias_cached_dense_multiplication_plan(
        std::size_t source_layer, std::size_t output_layer,
        const LayerStorageLayout &source_storage,
        const LayerStorageLayout &output_storage) const {
        if (!std::holds_alternative<MultiplicationLayer>(
                circuit_->layers[output_layer])) {
            return std::nullopt;
        }
        const LayerWireSupport &source_support =
            trace_layout_->layout().wire_support[source_layer];
        const std::size_t stored = source_storage.stored_wire_count;
        const std::size_t chunk = plan_->selected.chunk_ciphertexts;
        if (stored == 0 || stored >= source_support.live_wire_count) {
            return std::nullopt;
        }

        // Compute the exact number of records the ordinary chunk path would
        // read. Aliases already coalesce inside a chunk, so logical fanout by
        // itself is not evidence that a relation-scoped cache helps.
        std::uint64_t fallback_records = 0;
        std::size_t output_live_begin = 0;
        while (output_live_begin < output_storage.stored_wire_count) {
            std::vector<std::size_t> source_indices;
            std::size_t output_live_end = output_live_begin;
            while (output_live_end < output_storage.stored_wire_count &&
                   output_live_end - output_live_begin < chunk) {
                const std::size_t gate =
                    output_storage.representative_padded_index_of(
                        output_live_end);
                const std::vector<std::size_t> candidate =
                    checkpoint_replay_execution_detail::stored_gate_sources(
                        circuit_->layers[output_layer], gate,
                        source_storage);
                std::vector<std::size_t> merged = source_indices;
                checkpoint_replay_execution_detail::merge_sources(
                    merged, candidate);
                if (merged.size() > chunk) {
                    break;
                }
                source_indices = std::move(merged);
                ++output_live_end;
            }
            if (output_live_end == output_live_begin) {
                return std::nullopt;
            }
            fallback_records =
                checkpoint_replay_execution_detail::checked_add(
                    fallback_records,
                    checkpoint_replay_execution_detail::checked_count(
                        source_indices.size(),
                        "alias-cache fallback source records"),
                    "alias-cache fallback source records");
            output_live_begin = output_live_end;
        }
        const std::uint64_t minimum_useful_records =
            checkpoint_replay_execution_detail::checked_mul(
                4U,
                checkpoint_replay_execution_detail::checked_count(
                    stored, "alias-cache distinct source records"),
                "alias-cache minimum useful records");
        if (fallback_records < minimum_useful_records) {
            return std::nullopt;
        }

        // The cache may deliberately exceed the ordinary tiny-chunk peak.
        // Setup has already charged its exact decoded-cache-plus-one-staging
        // peak against the global resident cap and folded that bound into the
        // selected plan. Execution must agree with that immutable ledger.
        const std::uint64_t cache_peak =
            dense_multiplication_alias_cache_peak_resident_bytes(
                *problem_, *budgets_, output_layer);
        if (cache_peak == 0 ||
            cache_peak >
                plan_->selected
                    .dense_multiplication_alias_cache_peak_resident_bytes ||
            cache_peak > plan_->selected.peak_resident_bytes) {
            return std::nullopt;
        }
        return fallback_records;
    }

    bool is_exact_stored_identity_affine_relation(
        std::size_t source_layer, std::size_t output_layer,
        const LayerStorageLayout &source_storage,
        const LayerStorageLayout &output_storage) const {
        return checkpoint_replay_execution_detail::
            qualifies_stored_identity_affine_alias({
                .relation = circuit_->layers[output_layer],
                .source_descriptor =
                    natural_descriptor_.layers[source_layer],
                .output_descriptor =
                    natural_descriptor_.layers[output_layer],
                .source_resources = problem_->layers[source_layer],
                .output_resources = problem_->layers[output_layer],
                .source_storage = source_storage,
                .output_storage = output_storage,
                .source_classifications =
                    trace_layout_->layout()
                        .stored_value_classifications[source_layer],
                .output_classifications =
                    trace_layout_->layout()
                        .stored_value_classifications[output_layer],
            });
    }

    void evaluate_relation(
        std::size_t source_layer, std::size_t output_layer, bool checkpoint,
        PayloadCheckpointReplayIoReport &io, bool replay,
        std::size_t reduction_layer = kRuntimeProgressNoIndex) {
        FileTraceStoreReadDiagnostics phase_storage_reads;
        FileTraceStoreWriteDiagnostics phase_storage_writes;
        const checkpoint_replay_execution_detail::
            RelationProgressAttribution relation_progress(
                io, phase_storage_reads, phase_storage_writes);
        checkpoint_replay_execution_detail::ScopedOperationTimer
            relation_timer(io.relation);
        if (source_layer != output_layer + 1U ||
            !artifacts_.at(source_layer)) {
            throw std::logic_error(
                "checkpoint replay relation source is missing");
        }
        const LayerStorageLayout &output_storage =
            trace_layout_->layout().storage[output_layer];
        const LayerStorageLayout &source_storage =
            trace_layout_->layout().storage[source_layer];
        const std::size_t output_count =
            output_storage.stored_wire_count;
        const RuntimeProgressEvent relation_event{
            .boundary = RuntimeProgressBoundary::Begin,
            .stage = replay
                         ? RuntimeProgressStage::PayloadReplayRelation
                         : RuntimeProgressStage::PayloadForwardRelation,
            .layer_kind = runtime_layer_kind(output_layer),
            .reduction_layer = reduction_layer,
            .source_layer = source_layer,
            .output_layer = output_layer,
            .work_units = problem_->layers[output_layer].replay_work_units,
            .total_steps = output_count,
        };
        // `phase_storage_reads` is updated after every range-reader refill and
        // merges into `io.storage_reads` once the relation completes.
        // Completed writers enter both the phase-local and aggregate ledgers
        // at publication; an active writer remains separate until then, so
        // progress snapshots explicitly add its handle-local counters without
        // mutating either accounting ledger.
        notify_runtime_progress(options_.progress, relation_event);
        // Report progress about sixteen times per relation to keep long
        // replays observable with little journal overhead.
        const std::size_t progress_stride = std::max<std::size_t>(
            1U, (output_count + 15U) / 16U);
        std::size_t next_progress = progress_stride;
        const bool identity_alias_published =
            is_exact_stored_identity_affine_relation(
                source_layer, output_layer, source_storage,
                output_storage) &&
            try_publish_identity_affine_alias(
                source_layer, output_layer, checkpoint, io,
                phase_storage_writes);
        if (!identity_alias_published) {
            const std::optional<std::uint64_t>
                alias_cache_fallback_records =
                    alias_cached_dense_multiplication_plan(
                        source_layer, output_layer, source_storage,
                        output_storage);
            const std::optional<std::size_t> monotone_split =
                alias_cache_fallback_records
                    ? std::nullopt
                    : monotone_dense_multiplication_split(
                          source_layer, output_layer, source_storage,
                          output_storage);
            publish_layer(output_layer, checkpoint, [&](auto &sink) {
            const auto notify_update = [&](std::size_t completed) {
                RuntimeProgressEvent update = relation_event;
                update.boundary = RuntimeProgressBoundary::Update;
                update.completed_steps = completed;
                relation_progress.populate(update,
                                           sink.diagnostics_snapshot(),
                                           relation_timer.snapshot());
                notify_runtime_progress(options_.progress, update);
            };
            if (const auto *affine = std::get_if<AffineLayer>(
                    &circuit_->layers[output_layer]);
                affine != nullptr && !affine->intermediate_gates.empty()) {
                evaluate_affine_program_from_store(source_layer, output_layer,
                    *affine, source_storage, output_storage, sink, io,
                    phase_storage_reads, notify_update);
                return;
            }
            if (alias_cache_fallback_records) {
                checkpoint_replay_execution_detail::accumulate(
                    io.alias_cached_dense_multiplication_relations, 1,
                    "checkpoint alias-cached dense relations");
                checkpoint_replay_execution_detail::accumulate(
                    io.range_readers_opened, 1,
                    "checkpoint range readers");
                checkpoint_replay_execution_detail::accumulate(
                    io.alias_cached_dense_multiplication_range_readers_opened,
                    1, "checkpoint alias-cache readers");
                auto reader =
                    artifacts_.at(source_layer)->store.layer_range(
                        0, 0, source_storage.stored_wire_count,
                        &phase_storage_reads);
                std::vector<std::size_t> source_indices;
                std::vector<fhe::FheValue<Backend>> source;
                source_indices.reserve(source_storage.stored_wire_count);
                source.reserve(source_storage.stored_wire_count);
                for (std::size_t stored = 0;
                     stored < source_storage.stored_wire_count; ++stored) {
                    const auto encoded = reader.next_view();
                    if (!encoded) {
                        throw std::runtime_error(
                            "checkpoint alias-cache source ended early");
                    }
                    source_indices.push_back(stored);
                    source.push_back(deserialize_stored_value(
                        source_layer, *encoded, io));
                    checkpoint_replay_execution_detail::accumulate(
                        io.alias_cached_dense_multiplication_distinct_source_records_read,
                        1, "checkpoint alias-cache distinct records");
                    update_resident_peak(
                        source_layer, 1, source.size() - 1U,
                        output_layer, 0);
                }
                if (reader.position() != reader.end()) {
                    throw std::logic_error(
                        "checkpoint alias-cache source ledger drifted");
                }
                checkpoint_replay_execution_detail::accumulate(
                    io.alias_cached_dense_multiplication_logical_source_uses,
                    checkpoint_replay_execution_detail::checked_count(
                        trace_layout_->layout()
                            .wire_support[source_layer]
                            .live_wire_count,
                        "checkpoint alias-cache logical source uses"),
                    "checkpoint alias-cache logical source uses");
                checkpoint_replay_execution_detail::accumulate(
                    io.alias_cached_dense_multiplication_fallback_source_records,
                    *alias_cache_fallback_records,
                    "checkpoint alias-cache fallback source records");

                for (std::size_t live_gate = 0;
                     live_gate < output_count; ++live_gate) {
                    const std::size_t gate =
                        output_storage.representative_padded_index_of(
                            live_gate);
                    fhe::FheValue<Backend> value = evaluate_gate(
                        output_layer, gate, source_storage, source_indices,
                        source, io);
                    for (std::size_t count = 0;
                         count < problem_->layers[output_layer]
                                     .modulus_switches_after_layer;
                         ++count) {
                        checkpoint_replay_execution_detail::
                            ScopedOperationTimer timer(io.modulus_switching);
                        fhe::value_mod_switch_to_next<Backend>(*eval_, value);
                    }
                    validate_value_level(value, output_layer);
                    update_resident_peak(
                        source_layer, 0, source.size(), output_layer, 1);
                    sink.append_value(value);
                    const std::size_t completed = live_gate + 1U;
                    if (completed >= next_progress ||
                        completed == output_count) {
                        notify_update(completed);
                        while (next_progress <= completed &&
                               next_progress < output_count) {
                            next_progress = std::min(
                                output_count,
                                next_progress + progress_stride);
                        }
                    }
                }
                return;
            }
            if (monotone_split) {
                const std::size_t split = *monotone_split;
                checkpoint_replay_execution_detail::accumulate(
                    io.monotone_dense_multiplication_relations, 1,
                    "checkpoint monotone dense multiplication relations");
                checkpoint_replay_execution_detail::accumulate(
                    io.range_readers_opened, 2,
                    "checkpoint range readers");
                checkpoint_replay_execution_detail::accumulate(
                    io.monotone_dense_multiplication_range_readers_opened, 2,
                    "checkpoint monotone dense multiplication readers");
                auto left_reader =
                    artifacts_.at(source_layer)->store.layer_range(
                        0, 0, split, &phase_storage_reads);
                auto right_reader =
                    artifacts_.at(source_layer)->store.layer_range(
                        0, split, source_storage.stored_wire_count,
                        &phase_storage_reads);
                const auto read_next = [&](auto &reader) {
                    const auto encoded = reader.next_view();
                    if (!encoded) {
                        throw std::runtime_error(
                            "checkpoint monotone multiplication source ended "
                            "early");
                    }
                    checkpoint_replay_execution_detail::accumulate(
                        io.monotone_dense_multiplication_source_records_read,
                        1,
                        "checkpoint monotone dense multiplication records");
                    return deserialize_stored_value(
                        source_layer, *encoded, io);
                };
                const auto *multiplication =
                    std::get_if<MultiplicationLayer>(
                        &circuit_->layers[output_layer]);
                if (multiplication == nullptr) {
                    throw std::logic_error(
                        "checkpoint monotone multiplication kind drifted");
                }
                std::vector<std::size_t> source_indices;
                std::vector<fhe::FheValue<Backend>> source;
                source_indices.reserve(2);
                source.reserve(2);
                for (std::size_t live_gate = 0;
                     live_gate < output_count; ++live_gate) {
                    const std::size_t gate_index =
                        output_storage.representative_padded_index_of(
                            live_gate);
                    const MultiplicationGate &gate =
                        multiplication->gates.at(gate_index);
                    source_indices.clear();
                    source.clear();
                    if (const std::optional<std::size_t> stored_left =
                            source_storage.stored_ordinal_of(gate_index)) {
                        source_indices.push_back(*stored_left);
                        source.push_back(read_next(left_reader));
                    }
                    if (gate.origin == GateOrigin::Payload) {
                        if (const std::optional<std::size_t> stored_right =
                                source_storage.stored_ordinal_of(
                                    multiplication->dimensions.padded_size +
                                    gate_index)) {
                            source_indices.push_back(*stored_right);
                            source.push_back(read_next(right_reader));
                        }
                    }
                    fhe::FheValue<Backend> value = evaluate_gate(
                        output_layer, gate_index, source_storage,
                        source_indices, source, io);
                    for (std::size_t count = 0;
                         count < problem_->layers[output_layer]
                                     .modulus_switches_after_layer;
                         ++count) {
                        checkpoint_replay_execution_detail::
                            ScopedOperationTimer timer(io.modulus_switching);
                        fhe::value_mod_switch_to_next<Backend>(*eval_, value);
                    }
                    validate_value_level(value, output_layer);
                    update_resident_peak(source_layer, source.size(), 0,
                                         output_layer, 1);
                    sink.append_value(value);
                    const std::size_t completed = live_gate + 1U;
                    if (completed >= next_progress ||
                        completed == output_count) {
                        notify_update(completed);
                        while (next_progress <= completed &&
                               next_progress < output_count) {
                            next_progress = std::min(
                                output_count,
                                next_progress + progress_stride);
                        }
                    }
                }
                if (left_reader.position() != left_reader.end() ||
                    right_reader.position() != right_reader.end()) {
                    throw std::logic_error(
                        "checkpoint monotone multiplication source ledger "
                        "drifted");
                }
                return;
            }
            std::size_t output_live_begin = 0;
            while (output_live_begin < output_count) {
                std::vector<std::size_t> source_indices;
                std::size_t output_live_end = output_live_begin;
                while (output_live_end < output_count &&
                       output_live_end - output_live_begin <
                           plan_->selected.chunk_ciphertexts) {
                    const std::size_t gate =
                        output_storage.representative_padded_index_of(
                            output_live_end);
                    const std::vector<std::size_t> candidate =
                        checkpoint_replay_execution_detail::
                            stored_gate_sources(
                                circuit_->layers[output_layer], gate,
                                source_storage);
                    std::vector<std::size_t> merged = source_indices;
                    checkpoint_replay_execution_detail::merge_sources(
                        merged, candidate);
                    if (merged.size() >
                        plan_->selected.chunk_ciphertexts) {
                        break;
                    }
                    source_indices = std::move(merged);
                    ++output_live_end;
                }

                std::vector<fhe::FheValue<Backend>> output;
                if (output_live_end == output_live_begin) {
                    const std::size_t gate =
                        output_storage.representative_padded_index_of(
                            output_live_begin);
                    output.push_back(evaluate_affine_gate_from_store(
                        source_layer, output_layer, gate, source_storage,
                        io, phase_storage_reads));
                    output_live_end = output_live_begin + 1U;
                } else {
                    std::vector<fhe::FheValue<Backend>> source;
                    source.reserve(source_indices.size());
                    std::size_t cursor = 0;
                    while (cursor < source_indices.size()) {
                        const std::size_t stored_begin =
                            source_indices[cursor];
                        std::size_t group_end = cursor + 1U;
                        while (group_end < source_indices.size() &&
                               source_indices[group_end] ==
                                   stored_begin + (group_end - cursor)) {
                            ++group_end;
                        }
                        append_stored_range(
                            source_layer, stored_begin,
                            stored_begin + (group_end - cursor), io, source,
                            &phase_storage_reads);
                        cursor = group_end;
                    }
                    if (source.size() != source_indices.size()) {
                        throw std::runtime_error(
                            "checkpoint replay source range ended early");
                    }

                    output.reserve(output_live_end - output_live_begin);
                    for (std::size_t live_gate = output_live_begin;
                         live_gate < output_live_end; ++live_gate) {
                        const std::size_t gate =
                            output_storage.representative_padded_index_of(
                                live_gate);
                        output.push_back(evaluate_gate(
                            output_layer, gate, source_storage,
                            source_indices, source, io));
                    }
                    update_resident_peak(
                        source_layer, source.size(), 0,
                        output_layer, output.size());
                }
                for (fhe::FheValue<Backend> &value : output) {
                    for (std::size_t count = 0;
                         count < problem_->layers[output_layer]
                                     .modulus_switches_after_layer;
                         ++count) {
                        checkpoint_replay_execution_detail::
                            ScopedOperationTimer timer(io.modulus_switching);
                        fhe::value_mod_switch_to_next<Backend>(*eval_, value);
                    }
                    validate_value_level(value, output_layer);
                    sink.append_value(value);
                }
                output_live_begin = output_live_end;
                if (output_live_begin >= next_progress ||
                    output_live_begin == output_count) {
                    notify_update(output_live_begin);
                    while (next_progress <= output_live_begin &&
                           next_progress < output_count) {
                        next_progress = std::min(
                            output_count, next_progress + progress_stride);
                    }
                }
            }
            }, io, &phase_storage_writes);
        }
        if (replay) {
            checkpoint_replay_execution_detail::accumulate(
                replay_work_executed_,
                problem_->layers[output_layer].replay_work_units,
                "checkpoint replay work");
        } else {
            checkpoint_replay_execution_detail::accumulate(
                forward_work_executed_,
                problem_->layers[output_layer].replay_work_units,
                "checkpoint forward work");
        }
        relation_timer.finish();
        merge_storage_read(io.storage_reads, phase_storage_reads);
        RuntimeProgressEvent relation_end = relation_event;
        relation_end.boundary = RuntimeProgressBoundary::End;
        relation_end.completed_steps = output_count;
        relation_progress.populate(
            relation_end, {}, relation_progress.completed_relation_timing());
        notify_runtime_progress(options_.progress, relation_end);
        // Witness packing owns a distinct phase boundary. The natural layer
        // is complete before its S' copy starts, and S' is published before the
        // next payload relation begins.
        if (!replay && eager_laned_witness_packing_ && output_layer != 0U) {
            publish_eager_laned_witness(output_layer, io);
        }
    }

    const fhe::FheValue<Backend> *source_at(
        std::size_t index, const LayerStorageLayout &source_storage,
        std::span<const std::size_t> source_indices,
        std::span<const fhe::FheValue<Backend>> source) const {
        const std::optional<std::size_t> stored =
            source_storage.stored_ordinal_of(index);
        if (!stored) {
            return nullptr;
        }
        if (source_indices.size() == source.size() &&
            source_indices.size() == source_storage.stored_wire_count &&
            *stored < source_indices.size() &&
            source_indices[*stored] == *stored) {
            return &source[*stored];
        }
        const auto found =
            std::lower_bound(source_indices.begin(), source_indices.end(),
                             *stored);
        if (found == source_indices.end() || *found != *stored) {
            throw std::logic_error(
                "checkpoint replay chunk omitted a gate source");
        }
        return &source[static_cast<std::size_t>(found -
                                                source_indices.begin())];
    }

    template <typename Sink, typename Notify>
    void evaluate_affine_program_from_store(
        std::size_t source_layer, std::size_t output_layer,
        const AffineLayer &affine, const LayerStorageLayout &source_storage,
        const LayerStorageLayout &output_storage, Sink &sink,
        PayloadCheckpointReplayIoReport &io,
        FileTraceStoreReadDiagnostics &reads, Notify &&notify_update) {
        using Value = fhe::FheValue<Backend>;
        static_assert(sizeof(std::optional<Value>) + 4U * sizeof(std::size_t)
                      <= kAffineProgramMetadataBytesPerNode);
        // Charge the certified frontier before the first allocation or read.
        update_resident_peak(source_layer, 1, 0, output_layer, 1);
        auto program = affine_program_plan(affine,
            source_storage.padded_wire_count,
            output_storage.representative_padded_indices);
        std::vector<std::optional<Value>> intermediate(affine.intermediate_gates.size());
        auto reader = artifacts_.at(source_layer)->store.layer_range(
            0, 0, source_storage.stored_wire_count, &reads,
            FileTraceStoreReadPattern::Random);
        checkpoint_replay_execution_detail::accumulate(
            io.range_readers_opened, 1, "affine program range reader");
        std::size_t completed = 0;
        for (const auto &step : program.steps) {
            const auto &gate = step.output ? affine.gates[step.index]
                                          : affine.intermediate_gates[step.index];
            // Original primitive gates have bounded fan-in. Streaming source
            // loads occur outside the arithmetic timing scope.
            std::vector<std::pair<std::size_t, Value>> operands;
            for (const auto &term : gate.terms) {
                if (term.coefficient.is_zero()) continue;
                if (term.source >= source_storage.padded_wire_count) continue;
                const auto ordinal = source_storage.stored_ordinal_of(term.source);
                if (!ordinal) continue;
                reader.seek_to(*ordinal);
                const auto encoded = reader.next_view();
                if (!encoded) throw std::runtime_error("affine program source is missing");
                operands.emplace_back(term.source,
                    deserialize_stored_value(source_layer, *encoded, io));
            }
            const auto resolve = [&](std::size_t source) -> Value {
                if (source >= source_storage.padded_wire_count)
                    return intermediate.at(source - source_storage.padded_wire_count).value();
                for (const auto &[index, value] : operands)
                    if (index == source) return value;
                return Value::public_zero();
            };
            Value value;
            {
                checkpoint_replay_execution_detail::ScopedOperationTimer timer(io.fhe_evaluation);
                value = fhe_evaluation_detail::evaluate_affine_gate<Backend,
                    fhe_evaluation_detail::WideLayout>(*eval_, *circuit_, gate, resolve);
            }
            for (const auto &term : gate.terms) {
                if (!term.coefficient.is_zero() && term.source >= source_storage.padded_wire_count) {
                    const auto index = term.source - source_storage.padded_wire_count;
                    if (--program.remaining_uses[index] == 0) intermediate[index].reset();
                }
            }
            if (!step.output) {
                intermediate[step.index] = std::move(value);
                continue;
            }
            for (std::size_t drop = 0;
                 drop < problem_->layers[output_layer].modulus_switches_after_layer; ++drop) {
                checkpoint_replay_execution_detail::ScopedOperationTimer timer(io.modulus_switching);
                fhe::value_mod_switch_to_next<Backend>(*eval_, value);
            }
            validate_value_level(value, output_layer);
            sink.append_value(value);
            ++completed;
            if (completed == output_storage.stored_wire_count ||
                completed % std::max<std::size_t>(1U, output_storage.stored_wire_count / 16U) == 0)
                notify_update(completed);
        }
    }

    fhe::FheValue<Backend> evaluate_affine_gate_from_store(
        std::size_t source_layer, std::size_t output_layer,
        std::size_t gate_index, const LayerStorageLayout &source_storage,
        PayloadCheckpointReplayIoReport &io,
        FileTraceStoreReadDiagnostics &phase_storage_reads) {
        const auto *affine =
            std::get_if<AffineLayer>(&circuit_->layers[output_layer]);
        if (affine == nullptr) {
            throw std::logic_error(
                "checkpoint replay requested a non-affine gate from the "
                "affine source store");
        }
        const AffineGate &gate = affine->gates.at(gate_index);

        // Keep canonical term order so ciphertext arithmetic matches the
        // resident evaluator. Aliased logical terms seek to the same stored
        // record; consecutive aliases reuse one decoded value. Residency is
        // still one source value plus one partial sum.
        std::vector<std::pair<const AffineTerm *, std::size_t>> stored_terms;
        stored_terms.reserve(gate.terms.size());
        for (const AffineTerm &term : gate.terms) {
            if (term.coefficient.is_zero()) {
                continue;
            }
            const std::optional<std::size_t> stored =
                source_storage.stored_ordinal_of(term.source);
            if (stored) {
                stored_terms.emplace_back(&term, *stored);
            }
        }
        fhe::FheValue<Backend> accumulator =
            fhe::FheValue<Backend>::public_zero();
        const auto accumulate_term = [&](const AffineTerm &descriptor,
                                         const auto &stored) {
            checkpoint_replay_execution_detail::ScopedOperationTimer timer(
                io.fhe_evaluation);
            fhe::FheValue<Backend> term = stored;
            if (descriptor.rotation != 0) {
                term = fhe::value_rotate<Backend>(
                    *eval_, term, descriptor.rotation);
            }
            if (!(descriptor.coefficient == Fp::one())) {
                term = fhe::value_mul<Backend>(
                    *eval_, term,
                    fhe::FheValue<Backend>::public_scalar(
                        descriptor.coefficient));
            }
            if (descriptor.plaintext_index) {
                term = fhe::value_mul<Backend>(*eval_, term,
                    fhe::FheValue<Backend>::public_slots(
                        circuit_->plaintexts.at(*descriptor.plaintext_index)));
            }
            fhe::value_add_assign<Backend>(*eval_, accumulator,
                                           std::move(term));
        };

        if (!stored_terms.empty()) {
            checkpoint_replay_execution_detail::accumulate(
                io.range_readers_opened, 1, "checkpoint range readers");
            auto reader = artifacts_.at(source_layer)->store.layer_range(
                0, 0, source_storage.stored_wire_count,
                &phase_storage_reads,
                FileTraceStoreReadPattern::Random);
            std::size_t term_position = 0;
            while (term_position < stored_terms.size()) {
                const std::size_t stored = stored_terms[term_position].second;
                reader.seek_to(stored);
                const auto encoded = reader.next_view();
                if (!encoded) {
                    throw std::runtime_error(
                        "checkpoint replay affine source record is missing");
                }
                fhe::FheValue<Backend> source =
                    deserialize_stored_value(source_layer, *encoded, io);
                do {
                    accumulate_term(*stored_terms[term_position].first,
                                    source);
                    ++term_position;
                } while (term_position < stored_terms.size() &&
                         stored_terms[term_position].second == stored);
                update_resident_peak(source_layer, 1, 0, output_layer,
                                     accumulator.is_encrypted() ? 1 : 0);
            }
        }

        if (const auto *scalar = std::get_if<Fp>(&gate.constant)) {
            if (!scalar->is_zero()) {
                checkpoint_replay_execution_detail::ScopedOperationTimer
                    timer(io.fhe_evaluation);
                accumulator = fhe::value_add<Backend>(
                    *eval_, accumulator,
                    fhe::FheValue<Backend>::public_scalar(*scalar));
            }
        } else {
            const fhe::SlotVector constant = expand_for_encryption(
                circuit_->shape,
                std::get<fhe::SlotVector>(gate.constant));
            if (!is_zero_slot_vector(constant)) {
                checkpoint_replay_execution_detail::ScopedOperationTimer
                    timer(io.fhe_evaluation);
                accumulator = fhe::value_add<Backend>(
                    *eval_, accumulator,
                    fhe::FheValue<Backend>::public_slots(constant));
            }
        }
        return accumulator;
    }

    fhe::FheValue<Backend> evaluate_gate(
        std::size_t layer, std::size_t gate_index,
        const LayerStorageLayout &source_storage,
        std::span<const std::size_t> source_indices,
        std::span<const fhe::FheValue<Backend>> source,
        PayloadCheckpointReplayIoReport &io) const {
        checkpoint_replay_execution_detail::ScopedOperationTimer timer(
            io.fhe_evaluation);
        if (const auto *affine =
                std::get_if<AffineLayer>(&circuit_->layers[layer])) {
            const AffineGate &gate = affine->gates.at(gate_index);
            fhe::FheValue<Backend> accumulator =
                fhe::FheValue<Backend>::public_zero();
            for (const AffineTerm &descriptor : gate.terms) {
                if (descriptor.coefficient.is_zero()) {
                    continue;
                }
                const fhe::FheValue<Backend> *stored = source_at(
                    descriptor.source, source_storage, source_indices,
                    source);
                if (stored == nullptr) {
                    // A structural padding source is the public plaintext
                    // zero polynomial, so this affine term vanishes.
                    continue;
                }
                fhe::FheValue<Backend> term = *stored;
                if (descriptor.rotation != 0) {
                    term = fhe::value_rotate<Backend>(
                        *eval_, term, descriptor.rotation);
                }
                if (!(descriptor.coefficient == Fp::one())) {
                    term = fhe::value_mul<Backend>(
                        *eval_, term,
                        fhe::FheValue<Backend>::public_scalar(
                            descriptor.coefficient));
                }
                if (descriptor.plaintext_index) {
                    term = fhe::value_mul<Backend>(*eval_, term,
                        fhe::FheValue<Backend>::public_slots(
                            circuit_->plaintexts.at(*descriptor.plaintext_index)));
                }
                fhe::value_add_assign<Backend>(*eval_, accumulator,
                                               std::move(term));
            }
            if (const auto *scalar = std::get_if<Fp>(&gate.constant)) {
                if (!scalar->is_zero()) {
                    accumulator = fhe::value_add<Backend>(
                        *eval_, accumulator,
                        fhe::FheValue<Backend>::public_scalar(*scalar));
                }
            } else {
                const fhe::SlotVector constant = expand_for_encryption(
                    circuit_->shape,
                    std::get<fhe::SlotVector>(gate.constant));
                if (!is_zero_slot_vector(constant)) {
                    accumulator = fhe::value_add<Backend>(
                        *eval_, accumulator,
                        fhe::FheValue<Backend>::public_slots(constant));
                }
            }
            return accumulator;
        }

        const auto *multiplication =
            std::get_if<MultiplicationLayer>(&circuit_->layers[layer]);
        if (multiplication == nullptr) {
            throw std::logic_error(
                "checkpoint replay attempted to evaluate an input layer");
        }
        const MultiplicationGate &gate =
            multiplication->gates.at(gate_index);
        const std::size_t right_source =
            multiplication->dimensions.padded_size + gate_index;
        if (gate.origin == GateOrigin::Padding) {
            throw std::logic_error(
                "checkpoint replay attempted to publish a padding gate");
        }
        const fhe::FheValue<Backend> *left = source_at(
            gate_index, source_storage, source_indices, source);
        if (gate.origin == GateOrigin::Forward) {
            return left == nullptr
                       ? fhe::FheValue<Backend>::public_zero()
                       : *left;
        }
        const fhe::FheValue<Backend> *right = source_at(
            right_source, source_storage, source_indices, source);
        if (left == nullptr || right == nullptr) {
            return fhe::FheValue<Backend>::public_zero();
        }
        return fhe::value_mul<Backend>(*eval_, *left, *right);
    }
