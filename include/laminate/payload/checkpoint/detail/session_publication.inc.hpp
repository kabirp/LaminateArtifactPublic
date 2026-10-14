// Internal member-definition fragment for PayloadCheckpointReplayTrace.
// Include only from checkpoint/session_engine.hpp.
// Session construction, publication, metadata, replay setup, and proof ingress.

    PayloadCheckpointReplayTrace(
        const typename Backend::EvalContext &eval,
        const CertifiedPayloadCheckpointReplayStatic &certified,
        PayloadCheckpointReplayExecutionOptions options,
        std::filesystem::path root,
        std::span<const typename Backend::Ciphertext> encrypted_inputs,
        std::optional<Digest> authenticated_payload_schedule,
        std::optional<Digest> authenticated_proof_assessment,
        std::optional<Digest> expected_trace_id, bool output_only)
        : eval_(&eval), certified_(certified),
          trace_layout_(&certified_.trace_layout()),
          circuit_(&trace_layout_->circuit()),
          problem_(&certified_.problem()), budgets_(&certified_.budgets()),
          plan_(&certified_.plan()),
          options_(std::move(options)),
          root_(std::move(root)),
          backend_context_id_(Backend::storage_context_id(eval)),
          layered_circuit_id_(certified.layered_circuit_id()),
          authenticated_honest_payload_noise_schedule_digest_(
              std::move(authenticated_payload_schedule)),
          authenticated_honest_base_proof_noise_assessment_digest_(
              std::move(authenticated_proof_assessment)),
          natural_descriptor_(certified.natural_trace_template()),
          descriptor_(certified.proof_trace_template()),
          output_only_(output_only) {
        const LayeredCircuit &circuit = trace_layout_->circuit();
        natural_descriptor_.trace_id =
            prevalidated_trace_identity::validated_fhe_evaluated_trace_id<Backend>(
                natural_descriptor_.circuit_id, certified.input_count(),
                encrypted_inputs);
        if (expected_trace_id &&
            natural_descriptor_.trace_id != *expected_trace_id) {
            throw std::invalid_argument(
                "checkpoint replay ciphertext trace identity mismatch");
        }
        descriptor_.trace_id = natural_descriptor_.trace_id;
        eager_laned_witness_packing_ =
            options_.eager_laned_witness_packing &&
            supports_eager_laned_witness_packing(circuit);
        if (eager_laned_witness_packing_) {
            laned_witness_mask_cache_.emplace(
                circuit.shape.slot_count, circuit.shape.lane_count);
        }
        artifacts_.resize(circuit.layers.size());
        proof_ingress_artifacts_.resize(circuit.layers.size());
        proof_ingress_aliases_natural_.resize(circuit.layers.size(), false);
        eager_laned_packed_artifacts_.resize(circuit.layers.size());
        laned_packed_layouts_.resize(circuit.layers.size());
        laned_packed_rns_limbs_.resize(circuit.layers.size(), 0);
        laned_packed_artifact_byte_bounds_.resize(circuit.layers.size(), 0);
        layer_directories_.resize(circuit.layers.size());
        proof_ingress_directories_.resize(circuit.layers.size());
        eager_laned_packed_directories_.resize(circuit.layers.size());
        layer_directory_identities_.resize(circuit.layers.size());
        proof_ingress_directory_identities_.resize(circuit.layers.size());
        eager_laned_packed_directory_identities_.resize(
            circuit.layers.size());
        if (eager_laned_witness_packing_) {
            for (std::size_t layer = 1; layer < circuit.layers.size();
                 ++layer) {
                laned_packed_layouts_[layer] =
                    laned_witness_packing_layout(circuit, layer);
                const std::size_t source_limbs =
                    problem_->layers[layer].required_proof_depth + 1U;
                laned_packed_rns_limbs_[layer] =
                    source_limbs - static_cast<std::size_t>(
                        payload::layer_kind(circuit.layers[layer - 1U]) ==
                                LayerKind::Multiplication &&
                            laned_packed_layouts_[layer]
                                    .chunks_per_ciphertext() != 1U);
            }
        }
        report_.initial_forward_work_units =
            plan_->selected.initial_forward_work_units;
        report_.replay_work_units =
            output_only_ || eager_laned_witness_packing_
                ? 0
                : plan_->selected.replay_work_units;
        report_.segments.reserve(
            output_only_ ? 0U : plan_->reverse_gkr_segments.size());
        if (!output_only_) {
            for (const PayloadReplaySegment &segment :
                 plan_->reverse_gkr_segments) {
                report_.segments.push_back(
                    PayloadCheckpointReplaySegmentExecutionReport{
                        .reduction_layer = segment.reduction_layer,
                        .required_source_layer =
                            segment.required_source_layer,
                        .checkpoint_layer = segment.checkpoint_layer,
                        .replay_work_units =
                            eager_laned_witness_packing_
                                ? 0
                                : segment.replay_work_units,
                        .checkpoint_metadata_bytes_retired_after_use =
                            segment.fixed_metadata_bytes_retired_after,
                    });
            }
        }
    }

    void create_layer_directories() {
        for (std::size_t layer = 0; layer < layer_directories_.size();
             ++layer) {
            const std::filesystem::path directory =
                root_ /
                checkpoint_replay_execution_detail::layer_directory_name(
                    layer);
            if (!std::filesystem::create_directory(directory)) {
                throw std::runtime_error(
                    "failed to create checkpoint layer directory");
            }
            layer_directories_[layer] = directory;
            layer_directory_identities_[layer] =
                checkpoint_replay_execution_detail::
                    owned_directory_identity(directory);

            if (!output_only_ && !eager_laned_witness_packing_) {
                const std::filesystem::path ingress_directory =
                    root_ / ("proof-ingress-" +
                             checkpoint_replay_execution_detail::
                                 layer_directory_name(layer));
                if (!std::filesystem::create_directory(
                        ingress_directory)) {
                    throw std::runtime_error(
                        "failed to create proof-ingress layer directory");
                }
                proof_ingress_directories_[layer] = ingress_directory;
                proof_ingress_directory_identities_[layer] =
                    checkpoint_replay_execution_detail::
                        owned_directory_identity(ingress_directory);
            } else if (eager_laned_witness_packing_ && layer != 0U) {
                const std::filesystem::path packed_directory =
                    root_ / ("laned-packed-" +
                             checkpoint_replay_execution_detail::
                                 layer_directory_name(layer));
                if (!std::filesystem::create_directory(packed_directory)) {
                    throw std::runtime_error(
                        "failed to create Laned packed layer directory");
                }
                eager_laned_packed_directories_[layer] = packed_directory;
                eager_laned_packed_directory_identities_[layer] =
                    checkpoint_replay_execution_detail::
                        owned_directory_identity(packed_directory);
            }
        }
    }

    void preflight_output_only() {
        if (!output_only_ || eager_laned_witness_packing_ ||
            problem_->layers.empty() ||
            plan_->selected.chunk_ciphertexts == 0 ||
            budgets_->selection_objective !=
                PayloadCheckpointSelectionObjective::
                    OutputOnlyAdjacentLayers ||
            !plan_->selected.checkpoint_layers.empty() ||
            plan_->selected.checkpoint_metadata_bytes != 0 ||
            plan_->selected.checkpoint_bytes != 0 ||
            plan_->selected.replay_work_units != 0 ||
            !plan_->reverse_gkr_segments.empty()) {
            throw std::logic_error(
                "output-only payload preflight has invalid state");
        }
        if (!plan_->selected.feasible() ||
            plan_->selected.peak_live_scratch_bytes >
                budgets_->max_live_scratch_bytes ||
            plan_->selected.peak_resident_bytes >
                budgets_->max_resident_ciphertext_bytes) {
            throw std::invalid_argument(
                "output-only payload plan exceeds setup-admitted capacity");
        }
    }

    std::uint64_t checkpoint_metadata_identity_bytes() const {
        return checkpoint_replay_metadata_identity_bytes(
            plan_->selected.checkpoint_layers.size());
    }

    std::vector<std::uint8_t> checkpoint_metadata_identity_prefix() const {
        std::vector<std::uint8_t> encoded;
        encoded.reserve(static_cast<std::size_t>(
            checkpoint_metadata_identity_bytes()));
        constexpr char kMagic[] = "LMN-CHKPT-SET1";
        encoded.insert(encoded.end(), kMagic,
                       kMagic + sizeof(kMagic) - 1U);
        encoded.push_back(1U);
        encoded.insert(encoded.end(), backend_context_id_.begin(),
                       backend_context_id_.end());
        encoded.insert(encoded.end(), descriptor_.circuit_id.begin(),
                       descriptor_.circuit_id.end());
        encoded.insert(encoded.end(), descriptor_.trace_id.begin(),
                       descriptor_.trace_id.end());
        checkpoint_replay_execution_detail::append_u64(
            encoded, checkpoint_replay_execution_detail::checked_count(
                         plan_->selected.chunk_ciphertexts,
                         "checkpoint chunk count"));
        checkpoint_replay_execution_detail::append_u64(
            encoded, checkpoint_replay_execution_detail::checked_count(
                         plan_->selected.checkpoint_layers.size(),
                         "checkpoint layer count"));
        for (std::size_t layer : plan_->selected.checkpoint_layers) {
            checkpoint_replay_execution_detail::append_u64(
                encoded,
                checkpoint_replay_execution_detail::checked_count(
                    layer, "checkpoint layer"));
        }
        if (encoded.size() != checkpoint_metadata_identity_bytes()) {
            throw std::logic_error(
                "checkpoint metadata identity-size ledger drifted");
        }
        return encoded;
    }

    void preflight_checkpoint_metadata() {
        const std::uint64_t bytes =
            plan_->selected.checkpoint_metadata_bytes;
        const std::uint64_t identity_bytes =
            checkpoint_metadata_identity_bytes();
        const std::uint64_t minimum =
            checkpoint_replay_execution_detail::checked_add(
                identity_bytes, Digest{}.size(),
                "checkpoint metadata minimum identity");
        if (bytes > std::numeric_limits<std::size_t>::max() ||
            bytes > options_.max_checkpoint_metadata_bytes ||
            minimum > bytes) {
            throw std::invalid_argument(
                "checkpoint metadata size is outside its execution cap or "
                "too small for its identity");
        }
        const std::uint64_t metadata_buffers =
            checkpoint_replay_execution_detail::checked_add(
                bytes, identity_bytes,
                "checkpoint metadata validation buffers");
        if (metadata_buffers !=
            plan_->selected.checkpoint_metadata_validation_buffer_bytes) {
            throw std::logic_error(
                "checkpoint metadata resident ledger drifted");
        }
        const std::uint64_t controlled_peak =
            checkpoint_replay_execution_detail::checked_add(
                plan_->selected.retained_output_peak_resident_bytes,
                metadata_buffers,
                "checkpoint output and metadata resident peak");
        if (controlled_peak > budgets_->max_resident_ciphertext_bytes) {
            throw std::invalid_argument(
                "checkpoint output and metadata buffers exceed the "
                "admitted resident bound");
        }
        report_.peak_checkpoint_metadata_buffer_bytes = metadata_buffers;
        report_.peak_controlled_resident_bytes = std::max(
            report_.peak_controlled_resident_bytes, controlled_peak);
        if (plan_->selected.proof_ingress_peak_resident_bytes >
                budgets_->max_resident_ciphertext_bytes ||
            plan_->selected.proof_ingress_peak_live_scratch_bytes >
                budgets_->max_live_scratch_bytes) {
            throw std::logic_error(
                "admitted checkpoint plan exceeds an ingress capacity");
        }
    }

    std::vector<std::uint8_t> checkpoint_metadata_encoding() const {
        const std::uint64_t bytes =
            plan_->selected.checkpoint_metadata_bytes;
        std::vector<std::uint8_t> encoded =
            checkpoint_metadata_identity_prefix();
        const std::size_t encoded_size = static_cast<std::size_t>(bytes);
        const std::size_t body_size = encoded_size - Digest{}.size();
        // Allocate the complete encoding once. Growing only to the body and
        // then appending the digest can briefly retain both allocations.
        encoded.resize(encoded_size, 0);
        const Digest integrity = sha256(std::span<const std::uint8_t>(
            encoded.data(), body_size));
        std::copy(integrity.begin(), integrity.end(),
                  encoded.begin() + static_cast<std::ptrdiff_t>(body_size));
        return encoded;
    }

    void publish_checkpoint_metadata() {
        const std::uint64_t encoded_size =
            plan_->selected.checkpoint_metadata_bytes;
        require_live_capacity(encoded_size);
        {
            // End this full-size allocation before validation opens its own
            // full-size buffer. The preflight accounts for validation's one
            // encoding plus the small identity prefix.
            const std::vector<std::uint8_t> encoded =
                checkpoint_metadata_encoding();
            checkpoint_replay_execution_detail::write_file_exclusive(
                staged_metadata_path(), encoded);
            checkpoint_replay_execution_detail::publish_file_no_replace(
                staged_metadata_path(), complete_metadata_path());
        }
        validate_checkpoint_metadata(report_.forward);
        report_.checkpoint_metadata_physical_bytes = encoded_size;
        metadata_live_ = true;
        add_live_bytes(encoded_size, false);
        checkpoint_replay_execution_detail::accumulate(
            report_.forward.physical_bytes_written, encoded_size,
            "checkpoint metadata writes");
    }

    std::filesystem::path staged_metadata_path() const {
        return root_ / "checkpoint-set.partial";
    }
    std::filesystem::path complete_metadata_path() const {
        return root_ / "checkpoint-set.bin";
    }

    void remove_checkpoint_metadata() {
        const std::uint64_t bytes =
            report_.checkpoint_metadata_physical_bytes;
        if (!metadata_live_ || bytes == 0) {
            throw std::logic_error(
                "checkpoint metadata is not live at final retirement");
        }
        validate_checkpoint_metadata(report_.reverse_replay);
        if (!std::filesystem::remove(complete_metadata_path())) {
            throw std::runtime_error(
                "failed to retire checkpoint-set metadata");
        }
        subtract_live_bytes(bytes);
        checkpoint_replay_execution_detail::accumulate(
            report_.reverse_replay.physical_bytes_deleted, bytes,
            "checkpoint metadata deletion");
        checkpoint_replay_execution_detail::accumulate(
            report_.total_reclaimed_physical_bytes, bytes,
            "checkpoint total reclaimed bytes");
        report_.checkpoint_metadata_bytes_retired = bytes;
        metadata_live_ = false;
    }

    void validate_checkpoint_metadata(
        PayloadCheckpointReplayIoReport &io) const {
        const std::size_t expected_size = static_cast<std::size_t>(
            plan_->selected.checkpoint_metadata_bytes);
        const std::vector<std::uint8_t> actual =
            checkpoint_replay_execution_detail::
                read_regular_file_no_follow_exact(
                    complete_metadata_path(), expected_size);
        const std::vector<std::uint8_t> identity =
            checkpoint_metadata_identity_prefix();
        const std::size_t body_size = expected_size - Digest{}.size();
        const Digest integrity = sha256(std::span<const std::uint8_t>(
            actual.data(), body_size));
        const bool identity_matches =
            std::equal(identity.begin(), identity.end(), actual.begin());
        const bool padding_is_zero = std::all_of(
            actual.begin() + static_cast<std::ptrdiff_t>(identity.size()),
            actual.begin() + static_cast<std::ptrdiff_t>(body_size),
            [](std::uint8_t byte) { return byte == 0; });
        const bool digest_matches = std::equal(
            integrity.begin(), integrity.end(),
            actual.begin() + static_cast<std::ptrdiff_t>(body_size));
        if (!identity_matches || !padding_is_zero || !digest_matches) {
            throw std::runtime_error(
                "checkpoint-set metadata identity or digest mismatch");
        }
        checkpoint_replay_execution_detail::accumulate(
            io.physical_validation_bytes_read, actual.size(),
            "checkpoint metadata validation reads");
    }

    void cleanup_publication_failure_noexcept() noexcept {
        std::error_code ignored;
        if (root_.empty() || !std::filesystem::exists(root_, ignored)) {
            return;
        }
        // Ask complete stores to remove only files whose identities they
        // validated. Fail closed if a pathname changed.
        for (std::optional<LayerArtifact> &artifact : artifacts_) {
            if (artifact) {
                try {
                    (void)artifact->store.remove_validated_files();
                } catch (...) {
                }
                artifact.reset();
            }
        }
        for (std::optional<LayerArtifact> &artifact :
             proof_ingress_artifacts_) {
            if (artifact) {
                try {
                    (void)artifact->store.remove_validated_files();
                } catch (...) {
                }
                artifact.reset();
            }
        }
        for (std::optional<LayerArtifact> &artifact :
             eager_laned_packed_artifacts_) {
            if (artifact) {
                try {
                    (void)artifact->store.remove_validated_files();
                } catch (...) {
                }
                artifact.reset();
            }
        }
        const auto remove_regular = [&](const std::filesystem::path &path) {
            ignored.clear();
            const std::filesystem::file_status status =
                std::filesystem::symlink_status(path, ignored);
            if (!ignored && std::filesystem::is_regular_file(status)) {
                std::filesystem::remove(path, ignored);
            }
        };
        remove_regular(staged_metadata_path());
        remove_regular(complete_metadata_path());
        for (std::size_t layer = layer_directories_.size(); layer-- > 0;) {
            const std::filesystem::path &directory =
                layer_directories_[layer];
            if (directory.empty() ||
                !layer_directory_identities_[layer] ||
                !checkpoint_replay_execution_detail::
                    same_owned_directory_noexcept(
                        directory, *layer_directory_identities_[layer])) {
                continue;
            }
            // A partially constructed one-layer store can reserve only these
            // four names. Deletion is deliberately nonrecursive; an unknown
            // entry leaves the directory in place for diagnosis.
            constexpr const char *kOwnedFiles[] = {
                "layer-0000000000000000.partial",
                "layer-0000000000000000.bin", "manifest.partial",
                "manifest.bin"};
            for (const char *name : kOwnedFiles) {
                const std::filesystem::path file = directory / name;
                remove_regular(file);
            }
            ignored.clear();
            std::filesystem::remove(directory, ignored);
        }
        for (std::size_t layer = proof_ingress_directories_.size();
             layer-- > 0;) {
            const std::filesystem::path &directory =
                proof_ingress_directories_[layer];
            if (directory.empty() ||
                !proof_ingress_directory_identities_[layer] ||
                !checkpoint_replay_execution_detail::
                    same_owned_directory_noexcept(
                        directory,
                        *proof_ingress_directory_identities_[layer])) {
                continue;
            }
            constexpr const char *kOwnedFiles[] = {
                "layer-0000000000000000.partial",
                "layer-0000000000000000.bin", "manifest.partial",
                "manifest.bin"};
            for (const char *name : kOwnedFiles) {
                remove_regular(directory / name);
            }
            ignored.clear();
            std::filesystem::remove(directory, ignored);
        }
        for (std::size_t layer = eager_laned_packed_directories_.size();
             layer-- > 0;) {
            const std::filesystem::path &directory =
                eager_laned_packed_directories_[layer];
            if (directory.empty() ||
                !eager_laned_packed_directory_identities_[layer] ||
                !checkpoint_replay_execution_detail::
                    same_owned_directory_noexcept(
                        directory,
                        *eager_laned_packed_directory_identities_[layer])) {
                continue;
            }
            constexpr const char *kOwnedFiles[] = {
                "layer-0000000000000000.partial",
                "layer-0000000000000000.bin", "manifest.partial",
                "manifest.bin"};
            for (const char *name : kOwnedFiles) {
                remove_regular(directory / name);
            }
            ignored.clear();
            std::filesystem::remove(directory, ignored);
        }
        layer_directories_.clear();
        layer_directory_identities_.clear();
        proof_ingress_directories_.clear();
        proof_ingress_directory_identities_.clear();
        eager_laned_packed_directories_.clear();
        eager_laned_packed_directory_identities_.clear();
        report_.live_physical_bytes = 0;
    }

    void preflight_eager_laned_witness_packing() {
        if (!eager_laned_witness_packing_) {
            throw std::logic_error(
                "eager Laned witness preflight used by another profile");
        }
        const EagerLanedWitnessPackingAdmission admission =
            admit_eager_laned_witness_packing(
                *circuit_, *problem_, *budgets_, *plan_);
        if (!admission.resources.eligible) {
            throw std::logic_error("eager Laned witness eligibility changed");
        }
        laned_packed_artifact_byte_bounds_ =
            admission.resources.artifact_bytes_by_layer;
        report_.peak_controlled_resident_bytes = std::max(
            report_.peak_controlled_resident_bytes,
            admission.peak_resident_bytes);
    }

    void publish_input(
        std::span<const typename Backend::Ciphertext> encrypted_inputs) {
        const std::size_t layer = circuit_->layers.size() - 1U;
        const std::size_t count =
            problem_->layers[layer].stored_value_count;
        if (encrypted_inputs.size() != count) {
            throw std::invalid_argument(
                "checkpoint replay input count disagrees with live wire "
                "support");
        }
        std::vector<fhe::FheValue<Backend>> chunk;
        chunk.reserve(std::min(count, plan_->selected.chunk_ciphertexts));

        publish_layer(layer,
                      !output_only_ &&
                          !eager_laned_witness_packing_,
                      [&](auto &sink) {
            for (std::size_t begin = 0; begin < count;
                 begin += plan_->selected.chunk_ciphertexts) {
                const std::size_t end = std::min(
                    count, begin + plan_->selected.chunk_ciphertexts);
                chunk.clear();
                for (std::size_t wire = begin; wire < end; ++wire) {
                    chunk.push_back(fhe::FheValue<Backend>::from_ciphertext(
                        encrypted_inputs[wire]));
                }
                update_resident_peak(layer, chunk.size(), 0, layer, 0);
                for (fhe::FheValue<Backend> &value : chunk) {
                    validate_value_level(value, layer);
                    sink.append_value(value);
                }
            }
        }, report_.forward);
        if (eager_laned_witness_packing_) {
            publish_eager_laned_witness(layer, report_.forward);
        }
    }

    std::vector<fhe::FheValue<Backend>> evaluate_forward() {
        const std::size_t input = circuit_->layers.size() - 1U;
        std::size_t current = input;
        for (std::size_t output = input; output-- > 0;) {
            const bool checkpoint =
                !output_only_ && std::binary_search(
                    plan_->selected.checkpoint_layers.begin(),
                    plan_->selected.checkpoint_layers.end(), output);
            evaluate_relation(current, output,
                              !eager_laned_witness_packing_ && checkpoint,
                              report_.forward,
                              false);
            if (!artifacts_.at(current)->checkpoint) {
                (void)remove_artifact(current, false, &report_.forward);
            }
            current = output;
        }
        // Every challenge-independent S' artifact is now published. Prepared
        // public selectors are forward-only state and must not inflate GKR or
        // transcript-packing residency.
        if (eager_laned_witness_packing_) {
            laned_witness_mask_cache_.reset();
        }

        std::vector<fhe::FheValue<Backend>> output;
        output.reserve(problem_->layers[0].stored_value_count);
        append_stored_range(
            0, 0, problem_->layers[0].stored_value_count,
            report_.forward, output);
        update_resident_peak(0, output.size(), 0, 0, 0);
        (void)remove_artifact(0, false, &report_.forward);
        return output;
    }

    void activate_eager_laned_source(std::size_t required_source) const {
        if (!eager_laned_witness_packing_ || !published_ ||
            required_source == 0 ||
            required_source >= circuit_->layers.size() ||
            required_source != next_source_layer_) {
            throw std::logic_error(
                "eager Laned source request is out of order");
        }
        if (active_source_layer_ == required_source) {
            return;
        }
        if (active_source_layer_ != kNoLayer ||
            !eager_laned_packed_artifacts_.at(required_source)) {
            throw std::logic_error(
                "eager Laned source is missing or another source is active");
        }
        active_source_layer_ = required_source;
    }

    void ensure_source(std::size_t required_source) const {
        if (!published_ || required_source == 0 ||
            required_source >= circuit_->layers.size() ||
            required_source != next_source_layer_) {
            throw std::logic_error(
                "checkpoint replay source request is out of order");
        }
        if (active_source_layer_ == required_source) {
            return;
        }
        if (active_source_layer_ != kNoLayer) {
            throw std::logic_error(
                "previous checkpoint replay source is still active");
        }
        if (!metadata_validated_for_reverse_) {
            validate_checkpoint_metadata(report_.reverse_replay);
            metadata_validated_for_reverse_ = true;
        }

        const PayloadReplaySegment &segment =
            plan_->reverse_gkr_segments.at(required_source - 1U);
        PayloadCheckpointReplaySegmentExecutionReport &execution =
            report_.segments.at(required_source - 1U);
        if (segment.required_source_layer != required_source ||
            execution.required_source_layer != required_source ||
            !artifacts_.at(segment.checkpoint_layer) ||
            !artifacts_.at(segment.checkpoint_layer)->checkpoint) {
            throw std::logic_error(
                "checkpoint replay segment state drifted");
        }

        const RuntimeProgressEvent segment_event{
            .boundary = RuntimeProgressBoundary::Begin,
            .stage = RuntimeProgressStage::PayloadReplaySegment,
            .layer_kind = runtime_layer_kind(segment.reduction_layer),
            .reduction_layer = segment.reduction_layer,
            .source_layer = required_source,
            .checkpoint_layer = segment.checkpoint_layer,
            .work_units = segment.replay_work_units,
        };
        notify_runtime_progress(options_.progress, segment_event);

        std::size_t current = segment.checkpoint_layer;
        for (std::size_t output = segment.checkpoint_layer;
             output-- > required_source;) {
            const_cast<PayloadCheckpointReplayTrace *>(this)->
                evaluate_relation(current, output, false, execution.replay,
                                  true, segment.reduction_layer);
            if (current != segment.checkpoint_layer) {
                (void)const_cast<PayloadCheckpointReplayTrace *>(this)
                    ->remove_artifact(current, false, &execution.replay);
            }
            current = output;
        }
        if (segment.checkpoint_layer == required_source) {
            current = required_source;
        }
        if (current != required_source || !artifacts_.at(current)) {
            throw std::logic_error(
                "checkpoint replay did not materialize its source");
        }
        RuntimeProgressEvent segment_end = segment_event;
        segment_end.boundary = RuntimeProgressBoundary::End;
        notify_runtime_progress(options_.progress, segment_end);

        const PayloadReplayLayer &source =
            problem_->layers.at(required_source);
        const std::size_t ingress_limbs =
            source.required_proof_depth + 1U;
        const std::size_t drops_per_ciphertext =
            source.rns_limb_count - ingress_limbs;
        const RuntimeProgressEvent ingress_event{
            .boundary = RuntimeProgressBoundary::Begin,
            .stage = RuntimeProgressStage::PayloadProofIngress,
            .layer_kind = runtime_layer_kind(segment.reduction_layer),
            .reduction_layer = segment.reduction_layer,
            .source_layer = required_source,
            .checkpoint_layer = segment.checkpoint_layer,
            .work_units = checkpoint_replay_execution_detail::checked_mul(
                checkpoint_replay_execution_detail::checked_count(
                    source.stored_value_count,
                    "proof-ingress progress ciphertext count"),
                checkpoint_replay_execution_detail::checked_count(
                    drops_per_ciphertext,
                    "proof-ingress progress drops per ciphertext"),
                "proof-ingress progress modulus-switch calls"),
        };
        notify_runtime_progress(options_.progress, ingress_event);
        const_cast<PayloadCheckpointReplayTrace *>(this)
            ->publish_proof_ingress(required_source, execution.replay);
        if (!proof_ingress_aliases_natural_.at(required_source)) {
            const bool selected = std::binary_search(
                plan_->selected.checkpoint_layers.begin(),
                plan_->selected.checkpoint_layers.end(), required_source);
            if (!artifacts_.at(required_source) ||
                !proof_ingress_artifacts_.at(required_source)) {
                throw std::logic_error(
                    "distinct proof ingress publication is incomplete");
            }
            // The ingress artifact has been manifest-validated. Retire the
            // natural source now, before affine work or multiplication
            // scratch construction can begin.
            const std::uint64_t natural_retired =
                const_cast<PayloadCheckpointReplayTrace *>(this)
                    ->remove_artifact(required_source, selected,
                                      &execution.replay);
            const_cast<PayloadCheckpointReplayTrace *>(this)
                ->record_natural_source_retirement(
                    required_source, selected, natural_retired, execution);
        }
        active_source_layer_ = required_source;
        RuntimeProgressEvent ingress_end = ingress_event;
        ingress_end.boundary = RuntimeProgressBoundary::End;
        notify_runtime_progress(options_.progress, ingress_end);
    }

    void record_natural_source_retirement(
        std::size_t layer, bool selected, std::uint64_t retired,
        PayloadCheckpointReplaySegmentExecutionReport &segment) {
        if (retired == 0 ||
            segment.checkpoint_bytes_retired_after_use != 0 ||
            segment.transient_source_bytes_retired_after_use != 0) {
            throw std::logic_error(
                "checkpoint natural-source retirement ledger drifted");
        }
        if (selected) {
            segment.checkpoint_bytes_retired_after_use = retired;
            report_.checkpoint_retirement_order.push_back(layer);
        } else {
            segment.transient_source_bytes_retired_after_use = retired;
        }
        checkpoint_replay_execution_detail::accumulate(
            total_source_retirement_bytes_, retired,
            "checkpoint natural-source retirement bytes");
    }

    bool try_publish_identity_affine_alias(
        std::size_t source_layer, std::size_t output_layer,
        bool checkpoint, PayloadCheckpointReplayIoReport &io,
        FileTraceStoreWriteDiagnostics &phase_writes) {
        if (artifacts_.at(output_layer) ||
            !artifacts_.at(source_layer) ||
            !std::filesystem::is_empty(
                layer_directories_.at(output_layer))) {
            throw std::logic_error(
                "identity affine alias publication state is invalid");
        }
        const std::uint64_t maximum =
            problem_->layers[output_layer].checkpoint_bytes;
        // Planning remains deliberately conservative: the complete ordinary
        // output artifact was admitted, and a capability-only link failure
        // may therefore fall back to the normal materializer.
        require_live_capacity(maximum);
        const FileTraceStoreOptions storage_options{
            .max_total_bytes = maximum,
            .min_free_bytes = options_.min_free_bytes,
            .integrity_mode =
                FileTraceStoreIntegrityMode::SameProcessEphemeral,
        };
        EncryptedTraceDescriptor destination_descriptor;
        destination_descriptor.shape = natural_descriptor_.shape;
        destination_descriptor.provenance =
            natural_descriptor_.provenance;
        destination_descriptor.circuit_id =
            natural_descriptor_.circuit_id;
        destination_descriptor.trace_id =
            checkpoint_replay_execution_detail::layer_trace_id(
                natural_descriptor_.trace_id, output_layer);
        destination_descriptor.layers.push_back(
            natural_descriptor_.layers.at(output_layer));

        FileTraceStorePrivateLinkReport publication;
        std::optional<trace_storage::SerializedTraceStore> linked =
            artifacts_.at(source_layer)
                ->store.try_link_private_single_layer_store(
                    layer_directories_.at(output_layer),
                    destination_descriptor, storage_options, publication);
        if (!linked) {
            merge_storage_write(io.storage_writes,
                                publication.diagnostics);
            merge_storage_write(phase_writes,
                                publication.diagnostics);
            checkpoint_replay_execution_detail::accumulate(
                io.identity_affine_alias_fallbacks, 1,
                "identity affine alias fallbacks");
            if (!std::filesystem::is_empty(
                    layer_directories_.at(output_layer))) {
                throw std::logic_error(
                    "identity affine alias fallback left output files");
            }
            return false;
        }

        FileTraceStoreWriteReport written;
        bool backing_attributed_to_checkpoint = false;
        std::uint64_t checkpoint_attribution = 0;
        // Keep an independent handle armed until the artifact owns the linked
        // namespace. If a derived ledger check ever fails, whole-store removal
        // rolls back the manifest and hard link before the exception escapes.
        trace_storage::SerializedTraceStore rollback_store = *linked;
        try {
            written = linked->report();
            if (written.physical_bytes > maximum ||
                publication.unique_physical_bytes_added == 0 ||
                publication.reused_layer_file_bytes == 0 ||
                publication.unique_physical_bytes_added >
                    written.physical_bytes ||
                publication.reused_layer_file_bytes !=
                    written.physical_bytes -
                        publication.unique_physical_bytes_added) {
                throw std::logic_error(
                    "identity affine alias publication ledger drifted");
            }

            const LayerArtifact &source = *artifacts_.at(source_layer);
            backing_attributed_to_checkpoint =
                source.backing_attributed_to_checkpoint || checkpoint;
            checkpoint_attribution =
                checkpoint
                    ? checkpoint_replay_execution_detail::checked_add(
                          publication.unique_physical_bytes_added,
                          source.backing_attributed_to_checkpoint
                              ? 0U
                              : publication.reused_layer_file_bytes,
                          "identity affine checkpoint attribution")
                    : 0U;
            artifacts_[output_layer].emplace(LayerArtifact{
                output_layer, checkpoint, written, std::move(*linked),
                backing_attributed_to_checkpoint});
        } catch (...) {
            (void)rollback_store.remove_validated_files_detailed();
            throw;
        }
        add_live_bytes(publication.unique_physical_bytes_added, true);
        merge_storage_write(io.storage_writes, publication.diagnostics);
        merge_storage_write(phase_writes, publication.diagnostics);
        checkpoint_replay_execution_detail::accumulate(
            io.physical_bytes_written,
            publication.unique_physical_bytes_added,
            "identity affine alias physical writes");
        checkpoint_replay_execution_detail::accumulate(
            io.identity_affine_alias_relations, 1,
            "identity affine alias relations");
        checkpoint_replay_execution_detail::accumulate(
            io.identity_affine_alias_records_reused,
            checkpoint_replay_execution_detail::checked_count(
                natural_descriptor_.layers.at(output_layer).record_count,
                "identity affine alias records"),
            "identity affine alias records");
        checkpoint_replay_execution_detail::accumulate(
            io.identity_affine_alias_layer_bytes_reused,
            publication.reused_layer_file_bytes,
            "identity affine alias reused bytes");
        checkpoint_replay_execution_detail::accumulate(
            io.identity_affine_alias_unique_bytes_written,
            publication.unique_physical_bytes_added,
            "identity affine alias manifest bytes");
        if (checkpoint) {
            checkpoint_replay_execution_detail::accumulate(
                report_.checkpoint_layer_physical_bytes,
                checkpoint_attribution,
                "checkpoint retained identity affine alias bytes");
        }
        return true;
    }

    template <typename Emit>
    void publish_layer(std::size_t layer, bool checkpoint, Emit emit,
                       PayloadCheckpointReplayIoReport &io,
                       FileTraceStoreWriteDiagnostics *phase_writes = nullptr) {
        if (artifacts_.at(layer) ||
            !std::filesystem::is_empty(layer_directories_.at(layer))) {
            throw std::logic_error(
                "checkpoint layer destination is not empty");
        }
        const std::uint64_t maximum =
            problem_->layers[layer].checkpoint_bytes;
        require_live_capacity(maximum);
        const FileTraceStoreOptions storage_options{
            .max_total_bytes = maximum,
            .min_free_bytes = options_.min_free_bytes,
            .integrity_mode =
                FileTraceStoreIntegrityMode::SameProcessEphemeral,
        };
        FileEncryptedTraceSink<Backend> sink(
            *eval_, layer_directories_[layer],
            storage_options);
        const EncryptedTraceLayerDescriptor &description =
            natural_descriptor_.layers[layer];
        sink.begin_trace(natural_descriptor_.shape,
                         natural_descriptor_.provenance,
                         natural_descriptor_.circuit_id,
                         checkpoint_replay_execution_detail::layer_trace_id(
                             natural_descriptor_.trace_id, layer),
                         1);
        sink.begin_layer(0, description.layout, description.dimensions,
                         description.required_mult_depth,
                         description.record_count);

        emit(sink);
        sink.finish_layer();
        trace_storage::SerializedTraceStore opened =
            std::move(sink).finish_private_single_layer_store();
        const FileTraceStoreWriteReport written = opened.report();
        const FileTraceStoreWriteDiagnostics &writes =
            opened.write_diagnostics();
        merge_storage_write(io.storage_writes, writes);
        if (phase_writes != nullptr) {
            merge_storage_write(*phase_writes, writes);
        }
        if (written.physical_bytes > maximum) {
            throw std::logic_error(
                "checkpoint writer exceeded its admitted artifact bound");
        }
        artifacts_[layer].emplace(LayerArtifact{
            layer, checkpoint, written, std::move(opened), checkpoint});
        add_live_bytes(written.physical_bytes, true);
        checkpoint_replay_execution_detail::accumulate(
            io.encoded_ciphertext_bytes_written,
            written.logical_record_bytes,
            "checkpoint encoded writes");
        checkpoint_replay_execution_detail::accumulate(
            io.physical_bytes_written, written.physical_bytes,
            "checkpoint physical writes");
        if (checkpoint) {
            checkpoint_replay_execution_detail::accumulate(
                report_.checkpoint_layer_physical_bytes,
                written.physical_bytes,
                "checkpoint retained layer bytes");
        }

    }

    void publish_eager_laned_witness(
        std::size_t layer, PayloadCheckpointReplayIoReport &io) {
        if (!eager_laned_witness_packing_ || layer == 0U ||
            layer >= circuit_->layers.size() || !artifacts_.at(layer) ||
            eager_laned_packed_artifacts_.at(layer) ||
            !std::filesystem::is_empty(
                eager_laned_packed_directories_.at(layer))) {
            throw std::logic_error(
                "eager Laned witness source or destination is invalid");
        }

        const std::size_t source_count =
            problem_->layers[layer].stored_value_count;
        RuntimeProgressEvent progress_event{
            .boundary = RuntimeProgressBoundary::Begin,
            .stage = RuntimeProgressStage::LanedWitnessPacking,
            .layer_kind = runtime_layer_kind(layer - 1U),
            .reduction_layer = layer - 1U,
            .source_layer = layer,
            .work_units =
                checkpoint_replay_execution_detail::checked_count(
                    source_count, "Laned witness packing source values"),
            .total_steps =
                checkpoint_replay_execution_detail::checked_count(
                    source_count, "Laned witness packing source values"),
            .total_work_units =
                checkpoint_replay_execution_detail::checked_count(
                    source_count, "Laned witness packing source values"),
        };
        notify_runtime_progress(options_.progress, progress_event);

        const auto wall_start = std::chrono::steady_clock::now();
        const std::clock_t cpu_start = std::clock();
        EagerLanedWitnessLayerBuilder<Backend> builder(
            *eval_, *circuit_, layer,
            trace_layout_->layout().storage[layer],
            problem_->layers[layer].required_proof_depth + 1U,
            *laned_witness_mask_cache_);

        checkpoint_replay_execution_detail::accumulate(
            io.range_readers_opened, 1,
            "Laned witness natural-source range readers");
        auto reader = artifacts_.at(layer)->store.layer_range(
            0, 0, source_count, &io.storage_reads);
        std::size_t completed = 0;
        std::size_t next_update = 1024U;
        while (const auto encoded = reader.next_view()) {
            builder.append_stored_value(
                deserialize_stored_value(layer, *encoded, io));
            ++completed;
            if (completed != source_count && completed < next_update) {
                continue;
            }
            RuntimeProgressEvent update = progress_event;
            update.boundary = RuntimeProgressBoundary::Update;
            update.completed_steps =
                static_cast<std::uint64_t>(completed);
            update.completed_work_units =
                static_cast<std::uint64_t>(completed);
            notify_runtime_progress(options_.progress, update);
            while (next_update <= completed && next_update < source_count) {
                next_update = std::min(source_count, next_update + 1024U);
            }
        }
        if (completed != source_count || reader.position() != reader.end()) {
            throw std::runtime_error(
                "Laned witness natural source record count changed");
        }

        std::vector<fhe::FheValue<Backend>> packed_values =
            std::move(builder).finish();
        const LanedWitnessPackingStatistics statistics =
            builder.statistics();
        const std::uint64_t packed_maximum =
            laned_packed_artifact_byte_bounds_.at(layer);
        require_live_capacity(packed_maximum);
        const FileTraceStoreOptions packed_storage_options{
            .max_total_bytes = packed_maximum,
            .min_free_bytes = options_.min_free_bytes,
            .integrity_mode =
                FileTraceStoreIntegrityMode::SameProcessEphemeral,
        };
        FileEncryptedTraceSink<Backend> packed_sink(
            *eval_, eager_laned_packed_directories_[layer],
            packed_storage_options);
        packed_sink.begin_trace(
            PayloadShape::wide(descriptor_.shape.slot_count),
            descriptor_.provenance, descriptor_.circuit_id,
            checkpoint_replay_execution_detail::laned_packed_layer_trace_id(
                descriptor_.trace_id, layer),
            1);
        packed_sink.begin_layer(
            0, TraceLayerLayout::Wide,
            LayerDimensions{
                packed_values.size(),
                laned_packed_layouts_[layer].padded_ciphertext_count,
                packed_values.size(), 0},
            laned_packed_rns_limbs_[layer] - 1U,
            packed_values.size());
        for (const fhe::FheValue<Backend> &value : packed_values) {
            packed_sink.append_value(value);
        }
        packed_sink.finish_layer();
        trace_storage::SerializedTraceStore packed_opened =
            std::move(packed_sink).finish_private_single_layer_store();
        const FileTraceStoreWriteReport packed_written =
            packed_opened.report();
        merge_storage_write(io.storage_writes,
                            packed_opened.write_diagnostics());
        if (packed_written.physical_bytes > packed_maximum) {
            throw std::logic_error(
                "Laned packed witness exceeded its admitted bound");
        }
        eager_laned_packed_artifacts_[layer].emplace(LayerArtifact{
            layer, false, packed_written, std::move(packed_opened), false});
        add_live_bytes(packed_written.physical_bytes, true);
        checkpoint_replay_execution_detail::accumulate(
            io.encoded_ciphertext_bytes_written,
            packed_written.logical_record_bytes,
            "Laned packed witness encoded writes");
        checkpoint_replay_execution_detail::accumulate(
            io.physical_bytes_written, packed_written.physical_bytes,
            "Laned packed witness physical writes");
        checkpoint_replay_execution_detail::accumulate(
            report_.laned_witness_source_values, statistics.source_values,
            "Laned witness source values");
        checkpoint_replay_execution_detail::accumulate(
            report_.laned_witness_logical_values_packed,
            statistics.logical_values_packed,
            "Laned witness logical values");
        checkpoint_replay_execution_detail::accumulate(
            report_.laned_witness_mask_preparations,
            statistics.mask_preparations,
            "Laned witness mask preparations");
        checkpoint_replay_execution_detail::accumulate(
            report_.laned_witness_mask_cache_hits,
            statistics.mask_cache_hits,
            "Laned witness mask cache hits");
        checkpoint_replay_execution_detail::accumulate(
            report_.laned_witness_prepared_mask_ntt_bytes,
            statistics.prepared_mask_ntt_bytes,
            "Laned witness prepared-mask NTT bytes");
        report_.laned_witness_peak_mask_cache_ntt_bytes = std::max(
            report_.laned_witness_peak_mask_cache_ntt_bytes,
            laned_witness_mask_cache_->peak_ntt_bytes());
        checkpoint_replay_execution_detail::accumulate(
            report_.laned_witness_modulus_switches,
            statistics.modulus_switches,
            "Laned witness modulus switches");
        checkpoint_replay_execution_detail::accumulate(
            report_.laned_witness_plain_multiplications,
            statistics.plain_multiplications,
            "Laned witness plaintext multiplications");
        checkpoint_replay_execution_detail::accumulate(
            report_.laned_witness_additions, statistics.additions,
            "Laned witness additions");
        checkpoint_replay_execution_detail::accumulate(
            report_.laned_witness_rotations, statistics.rotations,
            "Laned witness rotations");
        checkpoint_replay_execution_detail::accumulate(
            report_.laned_witness_packed_ciphertexts,
            statistics.packed_ciphertexts,
            "Laned witness packed ciphertexts");
        checkpoint_replay_execution_detail::accumulate(
            report_.laned_witness_physical_bytes_written,
            packed_written.physical_bytes,
            "Laned witness physical bytes written");
        report_.laned_witness_packing_wall_ms +=
            std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - wall_start)
                .count();
        report_.laned_witness_packing_cpu_ms +=
            1000.0 * static_cast<double>(std::clock() - cpu_start) /
            static_cast<double>(CLOCKS_PER_SEC);

        progress_event.boundary = RuntimeProgressBoundary::End;
        progress_event.completed_steps = progress_event.total_steps;
        progress_event.completed_work_units =
            progress_event.total_work_units;
        notify_runtime_progress(options_.progress, progress_event);
    }

    void publish_proof_ingress(
        std::size_t layer, PayloadCheckpointReplayIoReport &io) {
        if (!artifacts_.at(layer) || proof_ingress_artifacts_.at(layer) ||
            !std::filesystem::is_empty(
                proof_ingress_directories_.at(layer))) {
            throw std::logic_error(
                "proof-ingress source or destination is invalid");
        }
        const PayloadReplaySegment &segment =
            plan_->reverse_gkr_segments.at(layer - 1U);
        const PayloadReplayLayer &resource = problem_->layers[layer];
        std::uint64_t expected_bound = 0;
        if (resource.required_proof_depth + 1U !=
            resource.rns_limb_count) {
            const std::uint64_t count =
                checkpoint_replay_execution_detail::checked_count(
                    resource.stored_value_count,
                    "proof-ingress ciphertext count");
            const std::uint64_t natural_payload =
                checkpoint_replay_execution_detail::checked_mul(
                    count, resource.serialized_ciphertext_bytes,
                    "natural checkpoint payload");
            const std::uint64_t ingress_serialized =
                resource.proof_ingress_serialized_ciphertext_bytes == 0
                    ? resource.serialized_ciphertext_bytes
                    : resource
                          .proof_ingress_serialized_ciphertext_bytes;
            expected_bound =
                checkpoint_replay_execution_detail::checked_add(
                    resource.checkpoint_bytes - natural_payload,
                    checkpoint_replay_execution_detail::checked_mul(
                        count, ingress_serialized,
                        "proof-ingress checkpoint payload"),
                    "proof-ingress checkpoint artifact");
        }
        if (segment.proof_ingress_artifact_bytes_upper_bound !=
            expected_bound) {
            throw std::logic_error(
                "proof-ingress artifact bound disagrees with admitted plan");
        }
        if (expected_bound == 0) {
            proof_ingress_aliases_natural_[layer] = true;
            return;
        }

        const std::uint64_t natural_ciphertext =
            checkpoint_replay_execution_detail::checked_add(
                resource.serialized_ciphertext_bytes,
                resource.resident_ciphertext_bytes,
                "proof-ingress encoded and decoded ciphertext");
        const std::uint64_t ingress_ciphertext =
            checkpoint_replay_execution_detail::checked_add(
                resource.proof_ingress_serialized_ciphertext_bytes == 0
                    ? resource.serialized_ciphertext_bytes
                    : resource
                          .proof_ingress_serialized_ciphertext_bytes,
                resource.proof_ingress_resident_ciphertext_bytes == 0
                    ? resource.resident_ciphertext_bytes
                    : resource.proof_ingress_resident_ciphertext_bytes,
                "reduced proof-ingress encoded and decoded ciphertext");
        const std::uint64_t expected_resident_peak =
            checkpoint_replay_execution_detail::checked_add(
                budgets_->reserved_resident_bytes,
                checkpoint_replay_execution_detail::checked_add(
                    natural_ciphertext, ingress_ciphertext,
                    "proof-ingress natural input and staged output"),
                "proof-ingress resident peak");
        if (segment.proof_ingress_peak_resident_bytes !=
            expected_resident_peak) {
            throw std::logic_error(
                "proof-ingress resident bound disagrees with admitted plan");
        }

        // The compact artifact cannot exceed its natural-level source bound.
        // Charging that conservative maximum before opening the writer makes
        // the transient natural-plus-ingress peak fail closed.
        const std::uint64_t maximum = expected_bound;
        const std::uint64_t projected =
            checkpoint_replay_execution_detail::checked_add(
                budgets_->reserved_live_scratch_bytes,
                checkpoint_replay_execution_detail::checked_add(
                    report_.live_physical_bytes, maximum,
                    "proof-ingress live artifacts"),
                "proof-ingress live scratch");
        if (projected >
            segment.proof_ingress_peak_live_scratch_bytes) {
            throw std::logic_error(
                "proof-ingress runtime peak exceeds its admitted segment");
        }
        require_live_capacity(maximum);
        const FileTraceStoreOptions storage_options{
            .max_total_bytes = maximum,
            .min_free_bytes = options_.min_free_bytes,
            .integrity_mode =
                FileTraceStoreIntegrityMode::SameProcessEphemeral,
        };
        FileEncryptedTraceSink<Backend> sink(
            *eval_, proof_ingress_directories_[layer],
            storage_options);
        const EncryptedTraceLayerDescriptor &description =
            descriptor_.layers[layer];
        sink.begin_trace(
            descriptor_.shape, descriptor_.provenance,
            descriptor_.circuit_id,
            checkpoint_replay_execution_detail::layer_trace_id(
                descriptor_.trace_id, layer),
            1);
        sink.begin_layer(0, description.layout, description.dimensions,
                         description.required_mult_depth,
                         description.record_count);

        checkpoint_replay_execution_detail::accumulate(
            io.range_readers_opened, 1,
            "proof-ingress natural-source range readers");
        auto reader = artifacts_.at(layer)->store.layer_range(
            0, 0, problem_->layers[layer].stored_value_count,
            &io.storage_reads);
        std::size_t record_count = 0;
        std::size_t ciphertext_count = 0;
        std::uint64_t switch_count = 0;
        while (const auto encoded = reader.next_view()) {
            fhe::FheValue<Backend> value =
                deserialize_stored_value(layer, *encoded, io);
            if (value.is_encrypted()) {
                const std::size_t before = Backend::rns_limb_count(
                    *eval_, value.ciphertext());
                {
                    checkpoint_replay_execution_detail::
                        ScopedOperationTimer timer(io.modulus_switching);
                    normalize_ciphertext_for_proof<Backend>(
                        *eval_, value.ciphertext(),
                        description.required_mult_depth);
                }
                if (Backend::rns_limb_count(*eval_, value.ciphertext()) !=
                    description.required_mult_depth + 1U) {
                    throw std::runtime_error(
                        "proof-ingress RNS limb target was not reached");
                }
                const std::size_t after = Backend::rns_limb_count(
                    *eval_, value.ciphertext());
                if (after > before) {
                    throw std::logic_error(
                        "proof-ingress preparation raised the RNS level");
                }
                switch_count =
                    checkpoint_replay_execution_detail::checked_add(
                        switch_count,
                        static_cast<std::uint64_t>(before - after),
                        "proof-ingress modulus switches");
                ++ciphertext_count;
            }
            update_proof_ingress_resident_peak(layer);
            sink.append_value(value);
            ++record_count;
        }
        if (record_count != description.record_count) {
            throw std::runtime_error(
                "proof-ingress source record count changed");
        }
        sink.finish_layer();
        trace_storage::SerializedTraceStore opened =
            std::move(sink).finish_private_single_layer_store();
        const FileTraceStoreWriteReport written = opened.report();
        merge_storage_write(io.storage_writes,
                            opened.write_diagnostics());
        if (written.physical_bytes > maximum) {
            throw std::logic_error(
                "proof-ingress writer exceeded the natural artifact bound");
        }
        proof_ingress_artifacts_[layer].emplace(LayerArtifact{
            layer, false, written, std::move(opened), false});
        add_live_bytes(written.physical_bytes, true);
        checkpoint_replay_execution_detail::accumulate(
            io.encoded_ciphertext_bytes_written,
            written.logical_record_bytes,
            "proof-ingress encoded writes");
        checkpoint_replay_execution_detail::accumulate(
            io.physical_bytes_written, written.physical_bytes,
            "proof-ingress physical writes");
        checkpoint_replay_execution_detail::accumulate(
            report_.proof_ingress_ciphertexts,
            static_cast<std::uint64_t>(ciphertext_count),
            "proof-ingress ciphertexts");
        checkpoint_replay_execution_detail::accumulate(
            report_.proof_ingress_modulus_switches, switch_count,
            "proof-ingress modulus switches");
        checkpoint_replay_execution_detail::accumulate(
            report_.proof_ingress_physical_bytes_written,
            written.physical_bytes,
            "proof-ingress physical bytes written");
    }
