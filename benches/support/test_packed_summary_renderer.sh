#!/usr/bin/env bash

set -euo pipefail

# All records and timings below are synthetic parser fixtures. They are not benchmark results.

if [[ $# -ne 2 ]]; then
  printf 'usage: %s PACKED_SUMMARY_RENDERER CONCISE_RENDERER\n' "$0" >&2
  exit 2
fi

renderer="$1"
concise_renderer="$2"
fixture="$(mktemp -d)"
lock_holder=''
cleanup() {
  if [[ -n "$lock_holder" ]]; then
    kill "$lock_holder" 2>/dev/null || true
    wait "$lock_holder" 2>/dev/null || true
  fi
  rm -rf -- "$fixture"
}
trap cleanup EXIT

mkdir -p \
  "$fixture/shared/report" \
  "$fixture/shared/transcript" \
  "$fixture/client" \
  "$fixture/server"
touch "$fixture/shared/lifecycle.lock"
chmod 600 "$fixture/shared/lifecycle.lock"

write_identity() {
  local destination="$1"
  local pinned_cpu="$2"
  printf '%s\n' \
    'protocol.variant=folded' \
    'protocol.fiat_shamir=single-transcript-gkr-then-packing-v1' \
    'protocol.gkr_claim_transition=selector-interpolation-v1' \
    'protocol.gkr_multiplication=gruen-stripped-h0-v1' \
    'benchmark.profile=quick' \
    'run.variant=folded' \
    'run.profile=quick' \
    'run.id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    'benchmark.evidence=reduced-security-stress-test' \
    'security.transcript_packing.actual_repetitions=4' \
    'security.transcript_packing.selected_repetitions=120' \
    'security.basefold.actual_queries=4' \
    'security.basefold.selected_queries=150' \
    'security.basefold.log_rate=3' \
    'security.basefold.bound_model=unique-decoding-rbr' \
    'security.basefold.target_bits=110' \
    'parameters.gate_mle_basefold_log_rate=3' \
    'parameters.gate_mle_basefold_queries=300' \
    'parameters.gate_mle_profile=wide-local-adjoint-foldable' \
    'security.claim=none-diagnostic-only' \
    'protocol.ciphertext_hash=simpleCTHash/v2' \
    'security.ciphertext_hash.claim=none-diagnostic-no-ciphertext-binding' \
    'schedule.policy=committed-conservative-no-search' \
    'schedule.proof_ingress_policy=LaminateImpl/ConservativePackedProofIngress/v1' \
    'schedule.proof_ingress_schedule_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    'schedule.proof_ingress_rns_limbs_by_layer=1,2,2' \
    'schedule.payload_modulus_switches_after_layer=0,1,0' \
    'geometry.N=16384' \
    'geometry.B=0' \
    'geometry.depth=6' \
    'geometry.workload=diamond' \
    'geometry.width=1024' \
    'geometry.inputs=64' \
    'geometry.outputs=1' \
    'geometry.payload_operations=13311' \
    'geometry.payload_add_gates=1023' \
    'geometry.payload_add_plain_gates=6144' \
    'geometry.payload_mul_gates=6144' \
    'fhe.data_rns_limbs=2' \
    'fhe.plain_modulus=65537' \
    'fhe.data_prime_bit_sizes=20,23' \
    'fhe.data_primes_bottom_to_top=786433,5767169' \
    'fhe.special_prime_bits=23' \
    'fhe.special_prime=7340033' \
    'fhe.fresh_modulus_product_bits=43' \
    'fhe.key_modulus_product_bits=65' \
    'environment.git_commit=0123456789abcdef0123456789abcdef01234567' \
    'environment.git_dirty=false' \
    'environment.build_type=Release' \
    'environment.seal_acceleration=intel-hexl-runtime-dispatch' \
    'environment.sha256_acceleration=openssl' \
    'environment.compiler=fixture-compiler' \
    'environment.seal_version=4.1.2' \
    'environment.fhe_backend=seal-bgv' \
    'environment.trace_execution=file-backed-checkpoint-replay' \
    "environment.pinned_cpu=$pinned_cpu" \
    'environment.threading=single-cpu-process' \
    'environment.os=fixture-os' \
    'environment.cpu=fixture-cpu' \
    'environment.physical_cores=4' \
    'environment.logical_cores=4' \
    'environment.ram_bytes=132719476736' \
    'environment.cpu_features.probe=gcc-runtime' \
    'environment.cpu_features.avx2_available=yes' \
    'environment.cpu_features.avx512f_available=yes' \
    'environment.cpu_features.avx512dq_available=yes' \
    'environment.cpu_features.avx512ifma_available=yes' \
    >> "$destination"
}

printf '%s\n' \
  'format=laminate-benchmark-run-v1' \
  'run.variant=folded' \
  'run.profile=quick' \
  'run.id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
  > "$fixture/shared/run-binding.txt"
truncate -s 1000 "$fixture/shared/transcript/cli-to-srv-request.bin"
truncate -s 2000 "$fixture/shared/transcript/srv-to-cli-response.bin"

setup="$fixture/shared/setup-result.txt"
printf '%s\n' \
  'format=laminate-packed-benchmark-setup-v1' \
  > "$setup"
write_identity "$setup" 0
printf '%s\n' \
  'packing.r1cs.actual.classification=exact-setup-bound-profile' \
  'packing.r1cs.actual.ring_degree=16384' \
  'packing.r1cs.actual.repetitions=4' \
  'packing.r1cs.actual.aligned_ciphertexts=321' \
  'packing.r1cs.actual.logical_packed_outputs=1' \
  'packing.r1cs.actual.physical_packed_ciphertexts=4' \
  'packing.r1cs.actual.packing_digit_count=4' \
  'packing.r1cs.actual.ciphertext_hash=simpleCTHash/v2' \
  'packing.r1cs.actual.ciphertext_commitment_constraints_per_ciphertext=32774' \
  'packing.r1cs.actual.ciphertext_commitment_constraints_total=10520454' \
  'packing.r1cs.actual.packing_relation_constraints=42338868' \
  'packing.r1cs.actual.active_constraints=52859322' \
  'packing.r1cs.actual.matrix_rows=52887552' \
  'packing.r1cs.actual.spartan_padded_constraints=67108864' \
  'packing.r1cs.actual.public_inputs=264114' \
  'packing.r1cs.actual.active_witness_variables=63113736' \
  'packing.r1cs.actual.witness_extent=64192512' \
  'packing.r1cs.actual.spartan_assignment_half_size=67108864' \
  'packing.r1cs.actual.spartan_padded_assignment_variables=134217728' \
  'packing.r1cs.selected_target.classification=formula-only-selected-target' \
  'packing.r1cs.selected_target.depth=8' \
  'packing.r1cs.selected_target.middle_width=65536' \
  'packing.r1cs.selected_target.payload_operations=1048576' \
  'packing.r1cs.selected_target.ring_degree=16384' \
  'packing.r1cs.selected_target.repetitions=120' \
  'packing.r1cs.selected_target.aligned_ciphertexts=517' \
  'packing.r1cs.selected_target.logical_packed_outputs=1' \
  'packing.r1cs.selected_target.physical_packed_ciphertexts=4' \
  'packing.r1cs.selected_target.packing_digit_count=4' \
  'packing.r1cs.selected_target.ciphertext_hash=poseidon/v2' \
  'packing.r1cs.selected_target.ciphertext_commitment_constraints_per_ciphertext=2186432' \
  'packing.r1cs.selected_target.ciphertext_commitment_constraints_total=1130385344' \
  'packing.r1cs.selected_target.packing_relation_constraints=2037116136' \
  'packing.r1cs.selected_target.active_constraints=3167501480' \
  'packing.r1cs.selected_target.matrix_rows=3167518720' \
  'packing.r1cs.selected_target.spartan_padded_constraints=4294967296' \
  'packing.r1cs.selected_target.public_inputs=4068438' \
  'packing.r1cs.selected_target.active_witness_variables=3180374098' \
  'packing.r1cs.selected_target.witness_extent=3181396898' \
  'packing.r1cs.selected_target.spartan_assignment_half_size=4294967296' \
  'packing.r1cs.selected_target.spartan_padded_assignment_variables=8589934592' \
  >> "$setup"
printf '%s\n' \
  'timing.setup.workload_compilation.wall_ms=300' \
  'timing.setup.workload_compilation.cpu_ms=250' \
  'timing.setup.storage_preflight.wall_ms=0' \
  'timing.setup.storage_preflight.cpu_ms=0' \
  'timing.setup.fhe_preprocessing.wall_ms=1200' \
  'timing.setup.fhe_preprocessing.cpu_ms=1050' \
  'timing.setup.packed_preprocessing.wall_ms=1400' \
  'timing.setup.packed_preprocessing.cpu_ms=1200' \
  'timing.setup.verify_persisted.wall_ms=400' \
  'timing.setup.verify_persisted.cpu_ms=350' \
  'timing.setup.resource_admission.wall_ms=200' \
  'timing.setup.resource_admission.cpu_ms=150' \
  'timing.setup.started_unix_ms=100000' \
  'timing.setup.finished_unix_ms=103500' \
  'timing.setup.total.wall_ms=3500' \
  'timing.setup.total.cpu_ms=3000' \
  'capacity.profile.max_live_disk_bytes=199999475712' \
  'capacity.profile.max_resident_ram_bytes=52718428160' \
  'capacity.profile.min_free_disk_bytes=100000000000' \
  'storage.planner_preflight.classification=exact-compiled-trace-formula-only' \
  'storage.planner_preflight.gross_live_disk_bytes=200000000000' \
  'storage.planner_preflight.max_live_disk_bytes=199980000000' \
  'storage.planner_preflight.min_free_disk_bytes=100000000000' \
  'storage.planner_preflight.client_private_persistent_reserve_bytes=20000000' \
  'storage.planner_preflight.server_common_reserve_bytes=128000000000' \
  'storage.planner_preflight.required_available_disk_bytes=300000000000' \
  'storage.planner_preflight.observed_available_disk_bytes=300000000000' \
  'storage.host_budget.gross_live_disk_bytes=200000000000' \
  'storage.host_budget.exact_client_private_persistent_bytes=524288' \
  'storage.host_budget.exact_server_live_disk_bytes=199999475712' \
  'memory.planner_preflight.observed_physical_ram_bytes=132719476736' \
  'memory.planner_preflight.safety_reserve_bytes=80000000000' \
  'memory.planner_preflight.gross_resident_budget_bytes=52719476736' \
  'memory.planner_preflight.client_peak_resident_reserve_bytes=2000000' \
  'memory.planner_preflight.server_resident_cap_bytes=52717476736' \
  'memory.host_budget.gross_resident_budget_bytes=52719476736' \
  'memory.host_budget.exact_client_peak_resident_bytes=1048576' \
  'memory.host_budget.exact_server_resident_cap_bytes=52718428160' \
  'memory.payload_storage.transfer_buffer_reserve_bytes=402653184' \
  'memory.payload_storage.writeback_window_bytes=0' \
  'storage.payload_storage.ephemeral_writeback_policy=linux-submit-only-with-buffered-portable-fallback' \
  'storage.payload_storage.maximum_writeback_submission_bytes=16777216' \
  'memory.payload_storage.sequential_reader_count=2' \
  'memory.payload_storage.prefetch_window_bytes_each=268435456' \
  'memory.payload_storage.prefetch_page_cache_budget_bytes=536870912' \
  'storage.payload_storage.maximum_prefetch_request_bytes=16777216' \
  'storage.planner_preflight.selected_peak_live_bytes=16777216' \
  'storage.planner_preflight.selected_checkpoint_count=3' \
  'storage.planner_preflight.selected_checkpoint_bytes=10485760' \
  'storage.planner_preflight.initial_forward_work_units=1000' \
  'storage.planner_preflight.repeated_work_units=1250' \
  'storage.planner_preflight.cumulative_work_units=2250' \
  'storage.planner_preflight.cumulative_recomputation_factor=2.250' \
  'storage.planner_preflight.maximum_recomputation_numerator=5' \
  'storage.planner_preflight.maximum_recomputation_denominator=2' \
  'storage.setup.server_persistent_bytes=1048576' \
  'storage.setup.shared_persistent_bytes=262144' \
  'storage.setup.server_private_persistent_bytes=786432' \
  'storage.setup.client_private_persistent_bytes=524288' \
  'storage.setup.proving_key_bytes=1048576' \
  'storage.setup.verifying_key_bytes=786432' \
  'storage.setup.all_roles_persistent_bytes=1572864' \
  'storage.setup.packing_persistent_bytes=524288' \
  'storage.setup.prepublication_fhe_persistent_bytes=524288' \
  'storage.setup.prepublication_admitted_persistent_bytes=2097152' \
  'storage.setup.prepublication_admitted_peak_live_bytes=4194304' \
  'storage.setup.prepublication_additional_live_bytes=3670016' \
  'storage.setup.prepublication_required_available_bytes=100003670016' \
  'storage.setup.prepublication_observed_available_bytes=300000000000' \
  'storage.online.packing_peak_live_bytes=2097152' \
  'storage.server.admitted_peak_live_bytes=5242880' \
  'storage.replay.selection_objective=minimum-replay-work' \
  'storage.replay.selected_checkpoint_layers=3,7,13' \
  'storage.replay.used_nonpreferred_checkpoint=0' \
  'storage.replay.selected_checkpoint_bytes=10485760' \
  'storage.replay.persistent_reserve_bytes=2097152' \
  'storage.replay.maximum_consumer_artifact_bytes=4194304' \
  'storage.replay.admitted_peak_live_bytes=16777216' \
  'memory.replay.dense_multiplication_alias_cache_peak_resident_bytes=4194304' \
  'memory.replay.admitted_peak_resident_bytes=6291456' \
  'work.replay.initial_forward_units=1000' \
  'work.replay.repeated_units=1250' \
  'work.replay.cumulative_units=2250' \
  'work.replay.cumulative_factor=2.250' \
  'memory.server.admitted_peak_resident_bytes=6291456' \
  'memory.client.admitted_peak_resident_bytes=1048576' \
  'memory.concurrent.admitted_peak_resident_bytes=7340032' \
  'memory.setup.prepublication_observed_peak_rss_bytes=1048576' \
  'memory.setup.prepublication_remaining_resident_reserve_bytes=3145728' \
  'memory.setup.prepublication_admitted_peak_resident_bytes=4194304' \
  'memory.setup.peak_rss_bytes=3145728' \
  'setup.result=PASS' \
  >> "$setup"

server="$fixture/server/result.txt"
printf '%s\n' 'format=laminate-packed-benchmark-server-v1' > "$server"
write_identity "$server" 0
printf '%s\n' \
  'timing.server.startup.load_preprocessing.wall_ms=100' \
  'timing.server.startup.load_preprocessing.cpu_ms=90' \
  'timing.server.startup.certify_replay_and_gkr_static.wall_ms=10' \
  'timing.server.startup.certify_replay_and_gkr_static.cpu_ms=9' \
  'timing.server.startup.derive_persistent_reserve.wall_ms=5' \
  'timing.server.startup.derive_persistent_reserve.cpu_ms=4' \
  'timing.server.startup.total.wall_ms=115' \
  'timing.server.startup.total.cpu_ms=103' \
  'timing.server.recurring_pre_request.prepare_roots.wall_ms=10' \
  'timing.server.recurring_pre_request.prepare_roots.cpu_ms=9' \
  'timing.server.recurring_pre_request.admit_transcript_packing.wall_ms=20' \
  'timing.server.recurring_pre_request.admit_transcript_packing.cpu_ms=20' \
  'timing.server.recurring_pre_request.admit_checkpoint_and_host.wall_ms=15' \
  'timing.server.recurring_pre_request.admit_checkpoint_and_host.cpu_ms=14' \
  'timing.server.recurring_pre_request.total.wall_ms=45' \
  'timing.server.recurring_pre_request.total.cpu_ms=43' \
  'timing.server.started_unix_ms=104100' \
  'timing.server.request_observed_unix_ms=104100' \
  'timing.server.response_published_unix_ms=134040' \
  'timing.server.finished_unix_ms=134050' \
  'timing.server.wait_for_request.wall_ms=0' \
  'timing.server.wait_for_request.cpu_ms=0' \
  'timing.server.read_request_file.wall_ms=2' \
  'timing.server.read_request_file.cpu_ms=2' \
  'timing.server.validate_request_capacity.wall_ms=4' \
  'timing.server.validate_request_capacity.cpu_ms=4' \
  'timing.server.decode_request.wall_ms=3' \
  'timing.server.decode_request.cpu_ms=3' \
  'work.replay.forward.monotone_relations=2' \
  'work.replay.forward.monotone_range_readers=4' \
  'work.replay.forward.monotone_source_records=100' \
  'work.replay.forward.alias_cached_relations=3' \
  'work.replay.forward.alias_cache_range_readers=3' \
  'work.replay.forward.alias_cache_distinct_source_records=12' \
  'work.replay.forward.alias_cache_logical_source_uses=1000' \
  'work.replay.forward.alias_cache_generic_source_records=900' \
  'work.replay.forward.identity_affine_alias_relations=2' \
  'work.replay.forward.identity_affine_alias_fallbacks=1' \
  'work.replay.forward.identity_affine_alias_records_reused=100' \
  'work.replay.forward.identity_affine_alias_layer_bytes_reused=104857600' \
  'work.replay.forward.identity_affine_alias_unique_bytes_written=4096' \
  'work.replay.reverse.monotone_relations=5' \
  'work.replay.reverse.monotone_range_readers=10' \
  'work.replay.reverse.monotone_source_records=250' \
  'work.replay.reverse.alias_cached_relations=8' \
  'work.replay.reverse.alias_cache_range_readers=8' \
  'work.replay.reverse.alias_cache_distinct_source_records=32' \
  'work.replay.reverse.alias_cache_logical_source_uses=4000' \
  'work.replay.reverse.alias_cache_generic_source_records=3000' \
  'work.replay.reverse.identity_affine_alias_relations=0' \
  'work.replay.reverse.identity_affine_alias_fallbacks=0' \
  'work.replay.reverse.identity_affine_alias_records_reused=0' \
  'work.replay.reverse.identity_affine_alias_layer_bytes_reused=0' \
  'work.replay.reverse.identity_affine_alias_unique_bytes_written=0' \
  'timing.server.payload_evaluation.wall_ms=10000' \
  'timing.server.payload_evaluation.cpu_ms=9900' \
  'work.replay.forward.timing.relation.wall_ms=9500' \
  'work.replay.forward.timing.relation.cpu_ms=9400' \
  'work.replay.forward.timing.fhe.wall_ms=5000' \
  'work.replay.forward.timing.fhe.cpu_ms=5000' \
  'work.replay.forward.timing.modulus_switch.wall_ms=1000' \
  'work.replay.forward.timing.modulus_switch.cpu_ms=1000' \
  'work.replay.forward.timing.deserialization.wall_ms=500' \
  'work.replay.forward.timing.deserialization.cpu_ms=500' \
  'work.replay.forward.timing.serialization.wall_ms=400' \
  'work.replay.forward.timing.serialization.cpu_ms=400' \
  'work.replay.forward.timing.buffer_assembly.wall_ms=0' \
  'work.replay.forward.timing.buffer_assembly.cpu_ms=0' \
  'work.replay.forward.timing.hashing.wall_ms=1' \
  'work.replay.forward.timing.hashing.cpu_ms=1' \
  'work.replay.forward.timing.capacity_admission.wall_ms=1' \
  'work.replay.forward.timing.capacity_admission.cpu_ms=1' \
  'work.replay.forward.timing.output_submission.wall_ms=850' \
  'work.replay.forward.timing.output_submission.cpu_ms=750' \
  'work.replay.forward.timing.storage_write.wall_ms=800' \
  'work.replay.forward.timing.storage_write.cpu_ms=700' \
  'work.replay.forward.timing.writeback_submission.wall_ms=10' \
  'work.replay.forward.timing.writeback_submission.cpu_ms=10' \
  'work.replay.forward.timing.writeback_wait.wall_ms=0' \
  'work.replay.forward.timing.writeback_wait.cpu_ms=0' \
  'work.replay.forward.timing.prefetch.wall_ms=5' \
  'work.replay.forward.timing.prefetch.cpu_ms=5' \
  'work.replay.forward.timing.storage_read.wall_ms=700' \
  'work.replay.forward.timing.storage_read.cpu_ms=600' \
  'work.replay.forward.timing.drain_close_publication.wall_ms=200' \
  'work.replay.forward.timing.drain_close_publication.cpu_ms=100' \
  'work.replay.forward.storage.application_write_bytes=20000000' \
  'work.replay.forward.storage.application_read_bytes=10000000' \
  'work.replay.forward.storage.write_batches=2' \
  'work.replay.forward.storage.write_syscalls=2' \
  'work.replay.forward.storage.maximum_write_batch_bytes=10000000' \
  'work.replay.forward.storage.writeback_files_enabled=1' \
  'work.replay.forward.storage.writeback_files_submit_only=1' \
  'work.replay.forward.storage.writeback_files_fallback=0' \
  'work.replay.forward.storage.writeback_submission_attempts=2' \
  'work.replay.forward.storage.writeback_submission_successes=2' \
  'work.replay.forward.storage.maximum_writeback_submission_bytes=16777216' \
  'work.replay.forward.storage.writeback_wait_attempts=0' \
  'work.replay.forward.storage.writeback_wait_successes=0' \
  'work.replay.forward.storage.writeback_range_bytes_submitted=20000000' \
  'work.replay.forward.storage.writeback_range_bytes_waited=0' \
  'work.replay.forward.storage.writeback_window_bytes=0' \
  'work.replay.forward.storage.maximum_unwaited_writeback_range_bytes=0' \
  'work.replay.forward.storage.writeback_drains=0' \
  'work.replay.forward.storage.writeback_drain_range_bytes=0' \
  'work.replay.forward.storage.writeback_drains_skipped=1' \
  'work.replay.forward.storage.writeback_range_bytes_without_explicit_wait=20000000' \
  'work.replay.forward.storage.positional_write_calls=1' \
  'work.replay.forward.storage.positional_write_bytes=8' \
  'work.replay.forward.storage.read_batches=1' \
  'work.replay.forward.storage.read_syscalls=1' \
  'work.replay.forward.storage.maximum_read_batch_bytes=10000000' \
  'work.replay.forward.storage.prefetch_requests=40' \
  'work.replay.forward.storage.prefetch_bytes_requested=10000000' \
  'work.replay.forward.storage.prefetch_fallbacks=0' \
  'work.replay.forward.storage.prefetch_seek_disables=0' \
  'work.replay.forward.storage.prefetch_window_bytes=268435456' \
  'work.replay.forward.storage.maximum_prefetch_request_bytes=8388608' \
  'work.replay.forward.storage.capacity_probes=3' \
  'work.replay.forward.storage.artifact_integrity=same-process-inode-bound-nonreopenable' \
  'work.replay.forward.storage.authenticated_record_bytes=0' \
  'work.replay.forward.storage.same_process_unhashed_record_bytes=19000000' \
  'work.replay.forward.storage.record_copy_bytes=0' \
  'work.replay.reverse.timing.relation.wall_ms=2400' \
  'work.replay.reverse.timing.relation.cpu_ms=2300' \
  'work.replay.reverse.timing.fhe.wall_ms=1000' \
  'work.replay.reverse.timing.fhe.cpu_ms=1000' \
  'work.replay.reverse.timing.modulus_switch.wall_ms=200' \
  'work.replay.reverse.timing.modulus_switch.cpu_ms=200' \
  'work.replay.reverse.timing.deserialization.wall_ms=100' \
  'work.replay.reverse.timing.deserialization.cpu_ms=90' \
  'work.replay.reverse.timing.serialization.wall_ms=80' \
  'work.replay.reverse.timing.serialization.cpu_ms=70' \
  'work.replay.reverse.timing.buffer_assembly.wall_ms=0' \
  'work.replay.reverse.timing.buffer_assembly.cpu_ms=0' \
  'work.replay.reverse.timing.hashing.wall_ms=1' \
  'work.replay.reverse.timing.hashing.cpu_ms=1' \
  'work.replay.reverse.timing.capacity_admission.wall_ms=1' \
  'work.replay.reverse.timing.capacity_admission.cpu_ms=1' \
  'work.replay.reverse.timing.output_submission.wall_ms=220' \
  'work.replay.reverse.timing.output_submission.cpu_ms=190' \
  'work.replay.reverse.timing.storage_write.wall_ms=200' \
  'work.replay.reverse.timing.storage_write.cpu_ms=180' \
  'work.replay.reverse.timing.writeback_submission.wall_ms=6' \
  'work.replay.reverse.timing.writeback_submission.cpu_ms=6' \
  'work.replay.reverse.timing.writeback_wait.wall_ms=0' \
  'work.replay.reverse.timing.writeback_wait.cpu_ms=0' \
  'work.replay.reverse.timing.prefetch.wall_ms=3' \
  'work.replay.reverse.timing.prefetch.cpu_ms=3' \
  'work.replay.reverse.timing.storage_read.wall_ms=400' \
  'work.replay.reverse.timing.storage_read.cpu_ms=350' \
  'work.replay.reverse.timing.drain_close_publication.wall_ms=100' \
  'work.replay.reverse.timing.drain_close_publication.cpu_ms=50' \
  'work.replay.reverse.storage.application_write_bytes=8000000' \
  'work.replay.reverse.storage.application_read_bytes=12000000' \
  'work.replay.reverse.storage.write_batches=4' \
  'work.replay.reverse.storage.write_syscalls=5' \
  'work.replay.reverse.storage.maximum_write_batch_bytes=2000000' \
  'work.replay.reverse.storage.writeback_files_enabled=2' \
  'work.replay.reverse.storage.writeback_files_submit_only=2' \
  'work.replay.reverse.storage.writeback_files_fallback=0' \
  'work.replay.reverse.storage.writeback_submission_attempts=4' \
  'work.replay.reverse.storage.writeback_submission_successes=4' \
  'work.replay.reverse.storage.maximum_writeback_submission_bytes=4194304' \
  'work.replay.reverse.storage.writeback_wait_attempts=0' \
  'work.replay.reverse.storage.writeback_wait_successes=0' \
  'work.replay.reverse.storage.writeback_range_bytes_submitted=8000000' \
  'work.replay.reverse.storage.writeback_range_bytes_waited=0' \
  'work.replay.reverse.storage.writeback_window_bytes=0' \
  'work.replay.reverse.storage.maximum_unwaited_writeback_range_bytes=0' \
  'work.replay.reverse.storage.writeback_drains=0' \
  'work.replay.reverse.storage.writeback_drain_range_bytes=0' \
  'work.replay.reverse.storage.writeback_drains_skipped=2' \
  'work.replay.reverse.storage.writeback_range_bytes_without_explicit_wait=8000000' \
  'work.replay.reverse.storage.positional_write_calls=2' \
  'work.replay.reverse.storage.positional_write_bytes=16' \
  'work.replay.reverse.storage.read_batches=3' \
  'work.replay.reverse.storage.read_syscalls=3' \
  'work.replay.reverse.storage.maximum_read_batch_bytes=4000000' \
  'work.replay.reverse.storage.prefetch_requests=48' \
  'work.replay.reverse.storage.prefetch_bytes_requested=12000000' \
  'work.replay.reverse.storage.prefetch_fallbacks=0' \
  'work.replay.reverse.storage.prefetch_seek_disables=0' \
  'work.replay.reverse.storage.prefetch_window_bytes=268435456' \
  'work.replay.reverse.storage.maximum_prefetch_request_bytes=8388608' \
  'work.replay.reverse.storage.capacity_probes=5' \
  'work.replay.reverse.storage.artifact_integrity=same-process-inode-bound-nonreopenable' \
  'work.replay.reverse.storage.authenticated_record_bytes=0' \
  'work.replay.reverse.storage.same_process_unhashed_record_bytes=7500000' \
  'work.replay.reverse.storage.record_copy_bytes=0' \
  'work.replay.gkr_source.timing.prefetch.wall_ms=2' \
  'work.replay.gkr_source.timing.prefetch.cpu_ms=2' \
  'work.replay.gkr_source.timing.storage_read.wall_ms=300' \
  'work.replay.gkr_source.timing.storage_read.cpu_ms=280' \
  'work.replay.gkr_source.storage.application_read_bytes=6000000' \
  'work.replay.gkr_source.storage.read_batches=2' \
  'work.replay.gkr_source.storage.read_syscalls=2' \
  'work.replay.gkr_source.storage.maximum_read_batch_bytes=3000000' \
  'work.replay.gkr_source.storage.prefetch_requests=32' \
  'work.replay.gkr_source.storage.prefetch_bytes_requested=6000000' \
  'work.replay.gkr_source.storage.prefetch_fallbacks=0' \
  'work.replay.gkr_source.storage.prefetch_seek_disables=0' \
  'work.replay.gkr_source.storage.prefetch_window_bytes=268435456' \
  'work.replay.gkr_source.storage.maximum_prefetch_request_bytes=4194304' \
  'work.replay.gkr_source.storage.artifact_integrity=same-process-inode-bound-nonreopenable' \
  'timing.server.prove.witness_packing.wall_ms=1000' \
  'timing.server.prove.witness_packing.cpu_ms=990' \
  'timing.server.prove.gkr.wall_ms=4995' \
  'timing.server.prove.gkr.cpu_ms=4905' \
  'timing.server.prove.transcript_packing.wall_ms=14000' \
  'timing.server.prove.transcript_packing.cpu_ms=14000' \
  'timing.server.prove.wall_ms=19995' \
  'timing.server.prove.cpu_ms=19895' \
  'timing.server.validate_proof_resource_reports.wall_ms=5' \
  'timing.server.validate_proof_resource_reports.cpu_ms=5' \
  'timing.server.encode_response.wall_ms=30' \
  'timing.server.encode_response.cpu_ms=30' \
  'timing.server.finalize_and_retire_work.wall_ms=6' \
  'timing.server.finalize_and_retire_work.cpu_ms=6' \
  'timing.server.publish_response.wall_ms=5' \
  'timing.server.publish_response.cpu_ms=5' \
  'timing.server.per_request_total.wall_ms=30095' \
  'timing.server.per_request_total.cpu_ms=29893' \
  'timing.server.process_total.wall_ms=30210' \
  'timing.server.process_total.cpu_ms=29996' \
  'timing.server.startup.total.scope=role-preprocessing-load-reusable-replay-gkr-static-certification-and-persistent-reserve-derivation;excludes-one-shot-request-resources-peer-idle-wait-and-per-request-work' \
  'timing.server.recurring_pre_request.total.scope=one-shot-work-root-creation-transcript-packing-admission-checkpoint-replay-scratch-and-host-capacity-admission;included-in-per-request-total-even-when-reserved-before-request-arrival' \
  'timing.server.per_request_total.scope=recurring-one-shot-resource-admission-request-read-and-codec-payload-evaluation-checkpoint-replay-gkr-and-transcript-packing-proof-response-codec-and-publication;excludes-reusable-static-preprocessing-and-peer-idle-wait' \
  'operations.server_payload_evaluation.add_plain.calls=10' \
  'operations.server_payload_evaluation.add_plain.limb_operations=20' \
  'operations.server_payload_evaluation.add_plain.by_rns_limb=2:10' \
  'operations.server_proving.multiply_plain.calls=3' \
  'operations.server_proving.multiply_plain.limb_operations=6' \
  'operations.server_proving.multiply_plain.by_rns_limb=2:3' \
  'wire.request_bytes=1000' \
  'wire.response_bytes=2000' \
  'proof.response.total_bytes=2000' \
  'proof.canonical.total_bytes=1800' \
  'proof.canonical.statement_and_metadata_bytes=100' \
  'proof.canonical.committed_gkr_bytes=1000' \
  'proof.canonical.well_formedness_reveal_bytes=200' \
  'proof.canonical.digit_packing_ciphertext_bytes=200' \
  'proof.canonical.spartan_packing_proof_bytes=300' \
  'proof.committed_gkr.commitment_digest_bytes=100' \
  'proof.committed_gkr.gate_mle_opening_bytes=100' \
  'storage.server.admitted_peak_live_bytes=5242880' \
  'memory.server.admitted_peak_resident_bytes=6291456' \
  'memory.client.admitted_peak_resident_bytes=1048576' \
  'memory.concurrent.admitted_peak_resident_bytes=7340032' \
  'memory.server.peak_rss_bytes=4194304' \
  'telemetry.schema=laminate-protocol-progress-v1' \
  'telemetry.logging_status=complete' \
  'telemetry.completed_spans=3' \
  'telemetry.span.0.name=folded.affine.sumcheck_round.reduction_3.source_4.round_2' \
  'telemetry.span.0.wall_ms=50' \
  'telemetry.span.0.cpu_ms=49' \
  'telemetry.span.1.name=transcript_packing.spartan.constraint_check' \
  'telemetry.span.1.wall_ms=5000' \
  'telemetry.span.1.cpu_ms=4990' \
  'telemetry.span.2.name=transcript_packing.spartan_prove' \
  'telemetry.span.2.wall_ms=6000' \
  'telemetry.span.2.cpu_ms=5990' \
  'server.result=PASS' \
  >> "$server"

client="$fixture/client/result.txt"
printf '%s\n' 'format=laminate-packed-benchmark-client-v3' > "$client"
write_identity "$client" 1
printf '%s\n' \
  'timing.client.load_preprocessing.wall_ms=10' \
  'timing.client.load_preprocessing.cpu_ms=9' \
  'timing.client.started_unix_ms=104000' \
  'timing.client.request_published_unix_ms=104030' \
  'timing.client.response_observed_unix_ms=134045' \
  'timing.client.verification_finished_unix_ms=134100' \
  'timing.client.process_finished_unix_ms=134105' \
  'timing.client.finished_unix_ms=134105' \
  'timing.client.wait_for_response.wall_ms=30000' \
  'timing.client.wait_for_response.cpu_ms=1' \
  'timing.client.construct_inputs.wall_ms=2' \
  'timing.client.construct_inputs.cpu_ms=2' \
  'timing.client.encrypt_inputs.wall_ms=20' \
  'timing.client.encrypt_inputs.cpu_ms=20' \
  'timing.client.generate_nonce.wall_ms=1' \
  'timing.client.generate_nonce.cpu_ms=1' \
  'timing.client.bind_request_session.wall_ms=1' \
  'timing.client.bind_request_session.cpu_ms=1' \
  'timing.client.encode_request.wall_ms=2' \
  'timing.client.encode_request.cpu_ms=2' \
  'timing.client.publish_request.wall_ms=1' \
  'timing.client.publish_request.cpu_ms=1' \
  'timing.client.read_response_file.wall_ms=1' \
  'timing.client.read_response_file.cpu_ms=1' \
  'timing.client.decode_response.wall_ms=2' \
  'timing.client.decode_response.cpu_ms=2' \
  'timing.client.open_response.wall_ms=3' \
  'timing.client.open_response.cpu_ms=3' \
  'timing.client.verify.wall_ms=30' \
  'timing.client.verify.cpu_ms=30' \
  'timing.client.honest_output_noise_audit.wall_ms=5' \
  'timing.client.honest_output_noise_audit.cpu_ms=5' \
  'timing.client.verify.transcript_packing.wall_ms=14' \
  'timing.client.verify.transcript_packing.cpu_ms=14' \
  'timing.client.verify.gate_mle_opening.wall_ms=2' \
  'timing.client.verify.gate_mle_opening.cpu_ms=2' \
  'timing.client.verify.layer_count=13' \
  'timing.client.per_request_total.wall_ms=68' \
  'timing.client.per_request_total.cpu_ms=67' \
  'timing.client.process_total.wall_ms=30100' \
  'timing.client.process_total.cpu_ms=60' \
  'timing.client.per_request_total.scope=role-preprocessing-load-input-encryption-request-codec-response-read-codec-open-output-decryption-output-claim-formation-and-proof-verification;excludes-setup-static-preprocessing-and-deterministic-input-construction-nonce-generation-session-binding-request-publication-peer-idle-wait-and-post-verification-honest-output-noise-audit' \
  'noise.final_output.measurement=client-secret-exact-canonical-error-with-invariant-budget-secondary-diagnostic' \
  'noise.final_output.encrypted_ciphertext_count=1' \
  'noise.final_output.data_rns_limb_count=1' \
  'noise.final_output.data_modulus_product_bits=20' \
  'noise.final_output.minimum_invariant_noise_budget_bits=12' \
  'noise.final_output.maximum_invariant_budget_implied_phase_norm_bits=7' \
  'noise.final_output.maximum_canonical_error_norm=37' \
  'noise.final_output.maximum_canonical_error_norm_bits=6' \
  'noise.final_output.target_maximum_norm_bits=10' \
  'noise.final_output.target_enforced=no' \
  'noise.final_output.target_result=NOT-ENFORCED-DIAGNOSTIC' \
  'noise.final_output.claim=secret-key-assisted-exact-canonical-error-honest-run-diagnostic-not-certificate' \
  'wire.request_bytes=1000' \
  'wire.response_bytes=2000' \
  'memory.client.peak_rss_bytes=1048576' \
  'memory.client.admitted_peak_resident_bytes=1048576' \
  'telemetry.schema=laminate-protocol-progress-v1' \
  'telemetry.logging_status=complete' \
  'telemetry.completed_spans=2' \
  'telemetry.span.0.name=transcript_packing.spartan_verify' \
  'telemetry.span.0.wall_ms=12' \
  'telemetry.span.0.cpu_ms=12' \
  'telemetry.span.1.name=transcript_packing.unpack' \
  'telemetry.span.1.wall_ms=1' \
  'telemetry.span.1.cpu_ms=1' \
  'verification.result=PASS' \
  >> "$client"

for ((index = 0; index < 13; ++index)); do
  if ((index % 2 == 0)); then
    kind='affine'
  else
    kind='multiplication'
  fi
  printf '%s\n' \
    "timing.client.verify.layer.$index.circuit_layer=$index" \
    "timing.client.verify.layer.$index.kind=$kind" \
    "timing.client.verify.layer.$index.wall_ms=2" \
    "timing.client.verify.layer.$index.cpu_ms=2" \
    >> "$client"
done

printf '%s\n' 'process.exit_status=0' \
  > "$fixture/shared/setup-process-exit.txt"
printf '%s\n' 'process.exit_status=0' > "$fixture/server/process-exit.txt"
printf '%s\n' 'process.exit_status=0' > "$fixture/client/process-exit.txt"

output="$fixture/shared/report/summary.md"

lane_error="$fixture/lane-error.txt"
if python3 "$renderer" --run-dir "$fixture" --variant laned \
    --profile quick --output "$output" 2>"$lane_error"; then
  printf '%s\n' 'Laned summary unexpectedly accepted an omitted lane count' >&2
  exit 1
fi
grep -Fq 'Laned summaries require --lanes 1, 128, or 16384' \
  "$lane_error" || {
  cat -- "$lane_error" >&2
  exit 1
}
if python3 "$renderer" --run-dir "$fixture" --variant folded \
    --profile quick --lanes 128 --output "$output" 2>"$lane_error"; then
  printf '%s\n' 'Folded summary unexpectedly accepted --lanes' >&2
  exit 1
fi
grep -Fq -- '--lanes is valid only for Laned summaries' "$lane_error" || {
  cat -- "$lane_error" >&2
  exit 1
}

replace_key() {
  local record="$1"
  local key="$2"
  local value="$3"
  local replacement="${record}.replacement"
  awk -v wanted="$key" -v replacement="$value" '
    BEGIN { matches = 0 }
    index($0, wanted "=") == 1 {
      print wanted "=" replacement
      ++matches
      next
    }
    { print }
    END { if (matches != 1) exit 3 }
  ' "$record" > "$replacement"
  mv -- "$replacement" "$record"
}

remove_key() {
  local record="$1"
  local key="$2"
  local replacement="${record}.replacement"
  awk -v wanted="$key" '
    BEGIN { matches = 0 }
    index($0, wanted "=") == 1 { ++matches; next }
    { print }
    END { if (matches != 1) exit 3 }
  ' "$record" > "$replacement"
  mv -- "$replacement" "$record"
}

remove_prefix() {
  local record="$1"
  local prefix="$2"
  local replacement="${record}.replacement"
  awk -v wanted="$prefix" '
    BEGIN { matches = 0 }
    index($0, wanted) == 1 { ++matches; next }
    { print }
    END { if (matches == 0) exit 3 }
  ' "$record" > "$replacement"
  mv -- "$replacement" "$record"
}

expect_render_failure() {
  local expected="$1"
  local label="$2"
  local error="$fixture/${label}-error.txt"
  local render_status=0
  python3 "$renderer" \
    --run-dir "$fixture" --variant folded --profile quick --output "$output" \
    >/dev/null 2>"$error" || render_status=$?
  if [[ "$render_status" -eq 0 ]] || ! grep -Fq "$expected" "$error"; then
    printf 'packed summary did not fail closed on %s:\n' "$label" >&2
    cat -- "$error" >&2
    exit 1
  fi
}

replace_key "$client" 'timing.client.per_request_total.wall_ms' '53'
replace_key "$client" 'timing.client.per_request_total.cpu_ms' '53'
replace_key "$client" 'timing.client.per_request_total.scope' 'input-encryption-output-decryption-vcoed-verification;excludes-preprocessing-load-transport-peer-wait-and-output-noise-audit'
printf '%s\n' 'timing.client.computation.schema=vcoed-client-computation-v1' >> "$client"
for component in \
  'decrypt_output|3' 'computation_total|53' 'verify.vcoed|30' 'verify.gkr|14' \
  'verify.gkr.transcript_recovery|4' 'verify.gkr.plaintext|10' \
  'verify.terminal_input_mle|2' 'verify.transcript_packing_snark|12' \
  'verify.well_formedness_noise|2'; do
  key="${component%%|*}"
  value="${component#*|}"
  printf 'timing.client.%s.wall_ms=%s\ntiming.client.%s.cpu_ms=%s\n' \
    "$key" "$value" "$key" "$value" >> "$client"
done
python3 "$renderer" \
  --run-dir "$fixture" --variant folded --profile quick --output "$output"
python3 "$renderer" \
  --run-dir "$fixture" --variant folded --profile quick --output "$output"

concise_output="$fixture/concise-summary.md"
python3 "$concise_renderer" \
  --input "$output" --output "$concise_output" \
  --run-dir "$fixture" \
  --variant folded --profile quick
for expected in \
  '<!-- laminate-benchmark-summary-v2 -->' \
  '| Laminate variant | Folded |' \
  '| Fiat–Shamir composition | One transcript: GKR, then Spartan packing argument |' \
  '| Payload profile | `quick` |' \
  '| Scalar gates | 218,087,424 (13,311 payload gates × 16,384 slots) |' \
  '| Plaintext modulus | 65,537 |' \
  '| ↳ Payload computation | 10.000 s |' \
  '| ↳ Witness packing | 1.000 s |' \
  '| ↳ GKR proving | 4.995 s |' \
  '| ↳ Transcript packing | 14.000 s |' \
  'Transcript recovery (FS, decryption, plaintext assembly)' \
  '## Server layer reductions and sumcheck round details' \
  '## Client verifier details' \
  '## Server FHE operation ledger' \
  '## Protocol artifacts' \
  'Proving key / server preprocessing' \
  'Verifying key / client preprocessing' \
  '## Memory and storage' \
  '## Provenance'; do
  grep -Fq -- "$expected" "$concise_output" || {
    printf 'concise packed summary omitted: %s\n' "$expected" >&2
    exit 1
  }
done
for forbidden in \
  'GCP VM and storage' \
  'Payload storage pipeline' \
  'Git revision' \
  'Client process total' \
  'Whole process including peer wait' \
  'Process exits' \
  'FHE backend' \
  'Exact data-prime schedule' \
  'q0=' \
  'Setup wall time' \
  'Run ID' \
  'Exact role commands' \
  'summary.csv'; do
  if grep -Fq -- "$forbidden" "$concise_output"; then
    printf 'concise packed summary retained: %s\n' "$forbidden" >&2
    exit 1
  fi
done
test ! -e "$fixture/shared/report/summary.csv"

for expected in \
  'Diagnostic profile.' \
  'ciphertext hash: simpleCTHash/v2 (diagnostic; no ciphertext-binding or transcript-packing integrity claim)' \
  '| Ciphertext hash | simpleCTHash/v2 (diagnostic; no ciphertext-binding or transcript-packing integrity claim) |' \
  'actual `T=4`, `q_BF=4`; selected `T=120`, `q_BF=150`' \
  '| BaseFold codeword expansion | `8x` (code rate `1/8`; log-rate 3) |' \
  '| GateMLE BaseFold | code rate `1/8`; `300` queries; generic foldable code; one FRI per PCS batch |' \
  'unique-decoding local interactive RBR error at most `2^-110`; one opening instance; excludes Merkle binding and Fiat--Shamir composition; actual reduced-query diagnostic is not certified' \
  'Reusable server startup' \
  'Proving key / server preprocessing' \
  'Verifying key / client preprocessing' \
  'Canonical proof inside response' \
  'Initial ciphertext data modulus' \
  'Ciphertext key modulus' \
  'Final encrypted-output honest noise' \
  'exact maximum canonical error 37 (6 bits; target at most 10: `NOT-ENFORCED-DIAGNOSTIC`)' \
  'Post-verification honest payload-output noise audit' \
  'well-formedness threshold checks remain inside `verify`' \
  'excluded from verification and per-request client time' \
  'One-shot recurring server admission' \
  '| Payload evaluation | 10.000 s wall; 9.900 s CPU; 99.0% CPU/wall |' \
  '| Proof generation | 19.995 s wall; 19.895 s CPU |' \
  '| ↳ Witness packing | 1.000 s wall; 0.990 s CPU |' \
  '| ↳ GKR | 4.995 s wall; 4.905 s CPU |' \
  '| ↳ Transcript packing | 14.000 s wall; 14.000 s CPU |' \
  'Payload storage pipeline' \
  '| Pipeline timing | Forward evaluation | Reverse replay | GKR source |' \
  'Circuit-relation evaluation' \
  'Trace maintenance (derived)' \
  '| Trace maintenance (derived) | 2.417 s wall; 2.217 s CPU; 91.7% |' \
  'Record output submission' \
  'not reported for read-only source diagnostics' \
  '6,000,000 B (5.722 MiB)' \
  'Application bytes submitted to write calls' \
  'Writeback-enabled / submit-only / fallback files' \
  'Writeback submission attempts / successes' \
  'Foreground wait attempts / successes' \
  'Largest successful writeback range hint' \
  'Planned writeback range-hint ceiling' \
  'successful range-hint bytes without explicit wait' \
  '16.000 MiB' \
  'Foreground drains / deliberately skipped drains' \
  'Prefetch requests / fallbacks / seek disables' \
  '268,435,456 B (256.000 MiB) / 8,388,608 B (8.000 MiB)' \
  'BDI read-ahead geometry' \
  'linux-submit-only-with-buffered-portable-fallback' \
  'no explicit foreground wait or layer-end drain' \
  'same-process-inode-bound-nonreopenable' \
  'a zero-replay target can report zero reverse circuit-relation time while still performing required proof-ingress work' \
  'Checkpoint-replay plan' \
  'minimum-replay-work' \
  'The objective minimizes the committed replay-work proxy among fully admitted schedules' \
  '| Checkpoint layers | `3,7,13` |' \
  '| Setup-selected dense multiplication alias-cache peak | 4,194,304 B (4.000 MiB) relation-scoped resident bound |' \
  '| Admitted replay resident peak | 6,291,456 B (6.000 MiB) |' \
  '| Cumulative / initial | 2.250x |' \
  'Per-request server' \
  'Checkpoint-replay source I/O' \
  '| `forward` | alias cache | 3 | 3 | 12 | 1,000 logical uses; 900 generic-path records; 888 net reads avoided |' \
  'selected/global resident cap' \
  'may deliberately exceed the ordinary tiny-chunk relation peak' \
  '| `reverse` | monotone streams | 5 | 10 | 250 | -- |' \
  'Identity affine relations can publish a distinct private namespace' \
  '| `forward` | 2 | 1 | 100 | 104,857,600 B (100.000 MiB) | 4,096 B (4.000 KiB) |' \
  'Per-request client and verifier' \
  'Request publication to verified client result' \
  'Measured FHE operation counts' \
  'server_payload_evaluation' \
  'Data-prime bit schedule (bottom to top)' \
  '786433,5767169' \
  '| Proof-ingress policy | `LaminateImpl/ConservativePackedProofIngress/v1` |' \
  '| Proof-ingress schedule digest | `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` |' \
  'Transcript-packing R1CS geometry' \
  '**52,859,322**' \
  '**3,167,501,480**' \
  '**67,108,864 (`2^26`)**' \
  '**4,294,967,296 (`2^32`)**' \
  '78.775x operations' \
  '**64.000x**' \
  'Peer wait for the response' \
  'Verifier reduction breakdown' \
  '| 0 | `affine` | 0.002 s | 0.002 s |' \
  '| 1 | `multiplication` | 0.002 s | 0.002 s |' \
  'Client reusable loading and fixture/session/transport bookkeeping' \
  'transcript_packing.spartan.constraint_check' \
  'transcript_packing.spartan_prove' \
  'transcript_packing.spartan_verify' \
  'Target expectations (projection, not measurement)' \
  '| Component | Current measured CPU | Selected-target CPU-work sensitivity |' \
  'single-thread CPU-work sensitivities, not elapsed or wall-time projections' \
  "| Request | 1,000 B | not estimated; use the fixed target chain's exact serialized ciphertexts |" \
  "server CPU rows do not charge additional RNS limbs" \
  'measured-chain-plus-`3`-limbs sensitivity (`2` to `5` limbs)' \
  'not a complete target-client projection' \
  'additional target Gate-MLE work is not estimated' \
  'does not estimate any additional target Gate-MLE-opening bytes' \
  '134,217,728 B (128.000 MiB)' \
  'These are planning estimates from one diagnostic run'; do
  if ! grep -Fq "$expected" "$output"; then
    printf 'packed summary omitted %s:\n' "$expected" >&2
    sed -n '1,260p' "$output" >&2
    exit 1
  fi
done

for report in "$output" "$concise_output"; do
  if grep -Fq 'OLD / STALE REPORT' "$report"; then
    printf '%s\n' 'current packed computation report incorrectly marked stale' >&2
    exit 1
  fi
  for expected in \
    '| Per-request client computation | 0.053 s' \
    '| Input encryption | 0.020 s' \
    '| Output decryption | 0.003 s' \
    '| VCoED proof verification | 0.030 s' \
    '| ↳ GKR proof verification | 0.014 s' \
    '| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 0.004 s' \
    '| ↳↳ Plaintext GKR and affine gate-opening checks | 0.010 s' \
    '| ↳ Terminal input MLE | 0.002 s' \
    '| ↳ Spartan packing argument | 0.012 s' \
    '| ↳ Well-formedness noise checks | 0.002 s'; do
    grep -Fq -- "$expected" "$report" || { printf 'missing computation row: %s\n' "$expected" >&2; exit 1; }
  done
done
# Setup may use its own worker pool, while both measured roles stay serial.
cp -- "$setup" "$setup.serial"
replace_key "$setup" 'environment.threading' 'setup-worker-pool'
remove_key "$setup" 'environment.pinned_cpu'
printf '%s\n' 'environment.worker_threads=3' 'environment.cpu_affinity=0,1,3' >> "$setup"
python3 "$renderer" --run-dir "$fixture" --variant folded --profile quick --output "$output"
grep -Fq 'setup: `3` worker(s); server and client: `single-cpu-process`' "$output"
replace_key "$setup" 'environment.worker_threads' 4
expect_render_failure 'setup worker count and CPU affinity are inconsistent' 'setup-worker-mismatch'
replace_key "$setup" 'environment.worker_threads' 3
replace_key "$setup" 'environment.cpu_affinity' '0,0,3'
expect_render_failure 'setup worker count and CPU affinity are inconsistent' 'setup-duplicate-cpu'
replace_key "$setup" 'environment.cpu_affinity' '0,1,3'
for online in "$server" "$client"; do
  cp -- "$online" "$online.serial"
  replace_key "$online" 'environment.threading' 'setup-worker-pool'
  expect_render_failure 'does not report single-CPU execution' 'parallel-online'
  mv -- "$online.serial" "$online"
  cp -- "$online" "$online.serial"
  printf '%s\n' 'environment.worker_threads=2' >> "$online"
  expect_render_failure 'reports multiple workers for single-CPU execution' 'online-worker-count'
  mv -- "$online.serial" "$online"
done
mv -- "$setup.serial" "$setup"

# Require the multiplication convention in every role.
for role_record in "$setup" "$server" "$client"; do
  cp -- "$role_record" "$role_record.gkr-multiplication"
done
remove_key "$client" 'protocol.gkr_multiplication'
expect_render_failure 'client is missing protocol.gkr_multiplication' 'partial-gkr-multiplication'
cp -- "$client.gkr-multiplication" "$client"
replace_key "$client" 'protocol.gkr_multiplication' 'unknown'
expect_render_failure 'setup/server/client disagree on protocol.gkr_multiplication' 'mixed-gkr-multiplication'
for role_record in "$setup" "$server" "$client"; do
  replace_key "$role_record" 'protocol.gkr_multiplication' 'unknown'
done
expect_render_failure 'unknown protocol.gkr_multiplication' 'unknown-gkr-multiplication'
for role_record in "$setup" "$server" "$client"; do
  remove_key "$role_record" 'protocol.gkr_multiplication'
done
expect_render_failure 'setup is missing protocol.gkr_multiplication' 'missing-gkr-multiplication'
for role_record in "$setup" "$server" "$client"; do
  cp -- "$role_record.gkr-multiplication" "$role_record"
done

# Require the same GKR transition identity in every role.
for role_record in "$setup" "$server" "$client"; do
  cp -- "$role_record" "$role_record.gkr-transition"
done
remove_key "$client" 'protocol.gkr_claim_transition'
expect_render_failure 'client is missing protocol.gkr_claim_transition' 'partial-gkr-transition'
cp -- "$client.gkr-transition" "$client"
replace_key "$client" 'protocol.gkr_claim_transition' 'additive-two-claim-batching-v1'
expect_render_failure 'setup/server/client disagree on protocol.gkr_claim_transition' 'mixed-gkr-transition'
for role_record in "$setup" "$server" "$client"; do
  replace_key "$role_record" 'protocol.gkr_claim_transition' 'unknown'
done
expect_render_failure 'unknown GKR claim transition' 'unknown-gkr-transition'
for role_record in "$setup" "$server" "$client"; do
  remove_key "$role_record" 'protocol.gkr_claim_transition'
done
expect_render_failure 'setup is missing protocol.gkr_claim_transition' 'missing-gkr-transition'
for role_record in "$setup" "$server" "$client"; do
  cp -- "$role_record.gkr-transition" "$role_record"
done

# Require the same transcript composition in every role.
for role_record in "$setup" "$server" "$client"; do
  cp -- "$role_record" "$role_record.fiat-shamir"
done
remove_key "$client" 'protocol.fiat_shamir'
expect_render_failure 'client is missing protocol.fiat_shamir' 'partial-fiat-shamir-identity'
cp -- "$client.fiat-shamir" "$client"
replace_key "$client" 'protocol.fiat_shamir' 'separate-gkr-packing-branches-v1'
expect_render_failure 'setup/server/client disagree on protocol.fiat_shamir' 'mixed-fiat-shamir-schedules'
for role_record in "$setup" "$server" "$client"; do
  replace_key "$role_record" 'protocol.fiat_shamir' 'unknown'
done
expect_render_failure 'unknown packed Fiat–Shamir schedule' 'unknown-fiat-shamir-schedule'
for role_record in "$setup" "$server" "$client"; do
  remove_key "$role_record" 'protocol.fiat_shamir'
done
expect_render_failure 'setup is missing protocol.fiat_shamir' 'missing-fiat-shamir'
for role_record in "$setup" "$server" "$client"; do
  mv -- "$role_record.fiat-shamir" "$role_record"
done
cp -- "$client" "$client.computation"
replace_key "$client" 'timing.client.load_preprocessing.wall_ms' '10000'
replace_key "$client" 'timing.client.encode_request.wall_ms' '10000'
python3 "$renderer" --run-dir "$fixture" --variant folded --profile quick --output "$output"
grep -Fq '| Per-request client computation | 0.053 s' "$output"
cp -- "$client.computation" "$client"
for mutation in \
  'timing.client.verify.gkr.plaintext.wall_ms|11|does not reconcile verify.gkr' \
  'timing.client.verify.vcoed.cpu_ms|31|does not reconcile verify.vcoed' \
  'timing.client.computation_total.wall_ms|54|does not reconcile computation_total' \
  'timing.client.per_request_total.wall_ms|54|does not reconcile per_request_total' \
  'timing.client.verify.terminal_input_mle.cpu_ms|-1|client has invalid' \
  'timing.client.verify.gkr.cpu_ms|nan|client has invalid' \
  'timing.client.computation.schema|unknown|unknown client computation timing schema'; do
  key="${mutation%%|*}"; remainder="${mutation#*|}"
  value="${remainder%%|*}"; expected="${remainder#*|}"
  replace_key "$client" "$key" "$value"
  expect_render_failure "$expected" 'client-computation-mutation'
  cp -- "$client.computation" "$client"
done
remove_key "$client" 'timing.client.verify.gkr.plaintext.cpu_ms'
expect_render_failure 'client is missing timing.client.verify.gkr.plaintext.cpu_ms' 'partial-client-computation'
cp -- "$client.computation" "$client"
remove_key "$client" 'timing.client.computation.schema'
expect_render_failure 'client computation timing schema is missing' 'missing-client-computation-schema'
cp -- "$client.computation" "$client"
# Independent three-decimal timer rounding must not cause a false rejection.
replace_key "$client" 'timing.client.verify.gkr.wall_ms' '14.001'
python3 "$renderer" --run-dir "$fixture" --variant folded --profile quick --output "$output"
cp -- "$client.computation" "$client"
rm -- "$client.computation"

for mutation in \
  'work.replay.initial_forward_units|0' \
  'work.replay.cumulative_units|2251' \
  'work.replay.cumulative_factor|2.200' \
  'storage.replay.selected_checkpoint_bytes|16777217' \
  'storage.replay.admitted_peak_live_bytes|200000000001' \
  'memory.replay.dense_multiplication_alias_cache_peak_resident_bytes|6291457'; do
  key="${mutation%%|*}"
  value="${mutation#*|}"
  label="replay-ledger-${key##*.}"
  cp -- "$setup" "$setup.saved"
  replace_key "$setup" "$key" "$value"
  expect_render_failure \
    'setup checkpoint-replay plan ledger is inconsistent' \
    "$label"
  mv -- "$setup.saved" "$setup"
done

cp -- "$server" "$server.saved"
replace_key "$server" 'work.replay.reverse.timing.relation.wall_ms' '0'
replace_key "$server" 'work.replay.reverse.timing.relation.cpu_ms' '0'
python3 "$renderer" \
  --run-dir "$fixture" --variant folded --profile quick --output "$output"
grep -Fq \
  'a zero-replay target can report zero reverse circuit-relation time while still performing required proof-ingress work' \
  "$output"
mv -- "$server.saved" "$server"

cp -- "$server" "$server.saved"
remove_key "$server" 'work.replay.reverse.alias_cache_range_readers'
expect_render_failure \
  'server has an incomplete checkpoint-replay I/O ledger' \
  'replay-io-incomplete'
mv -- "$server.saved" "$server"

for mutation in \
  'work.replay.gkr_source.storage.maximum_prefetch_request_bytes|6000001' \
  'work.replay.reverse.storage.writeback_submission_successes|5' \
  'work.replay.reverse.storage.maximum_writeback_submission_bytes|8000001' \
  'work.replay.reverse.storage.writeback_range_bytes_waited|8000001' \
  'work.replay.forward.storage.writeback_wait_attempts|1'; do
  key="${mutation%%|*}"
  value="${mutation#*|}"
  label="replay-storage-${key##*.}"
  phase="${key#work.replay.}"
  phase="${phase%%.*}"
  cp -- "$server" "$server.saved"
  replace_key "$server" "$key" "$value"
  expect_render_failure \
    "server has inconsistent replay storage telemetry for $phase" \
    "$label"
  mv -- "$server.saved" "$server"
done

cp -- "$server" "$server.saved"
replace_key \
  "$server" 'work.replay.forward.alias_cache_generic_source_records' '47'
expect_render_failure \
  'forward alias-cache savings ledger is inconsistent' \
  'replay-io-savings'
mv -- "$server.saved" "$server"

cp -- "$setup" "$setup.saved"
replace_key \
  "$setup" 'packing.r1cs.actual.spartan_padded_constraints' '134217728'
expect_render_failure \
  'actual Spartan constraint domain is not the smallest power of two' \
  'r1cs-padding'
mv -- "$setup.saved" "$setup"

cp -- "$setup" "$setup.saved"
replace_key "$setup" 'packing.r1cs.actual.physical_packed_ciphertexts' '0'
expect_render_failure \
  'setup packing.r1cs.actual physical_packed_ciphertexts is not positive' \
  'r1cs-physical-output-positivity'
mv -- "$setup.saved" "$setup"

cp -- "$setup" "$setup.saved"
replace_key "$setup" 'packing.r1cs.actual.active_constraints' '52859000'
expect_render_failure \
  'active constraints do not equal the commitment and packing-relation sum' \
  'r1cs-active-constraint-ledger'
mv -- "$setup.saved" "$setup"

# GateMLE parameters must agree across all three roles.
cp -- "$client" "$client.saved"
replace_key "$client" 'parameters.gate_mle_basefold_queries' '64'
expect_render_failure \
  'setup/server/client disagree on parameters.gate_mle_basefold_queries' \
  'gate-basefold-role-mismatch'
mv -- "$client.saved" "$client"

cp -- "$client" "$client.saved"
remove_key "$client" 'parameters.gate_mle_basefold_log_rate'
expect_render_failure \
  'client is missing parameters.gate_mle_basefold_log_rate' \
  'gate-basefold-missing-role-field'
mv -- "$client.saved" "$client"

cp -- "$setup" "$setup.saved"
cp -- "$server" "$server.saved"
cp -- "$client" "$client.saved"
for record in "$setup" "$server" "$client"; do
  remove_key "$record" 'parameters.gate_mle_basefold_log_rate'
  remove_key "$record" 'parameters.gate_mle_basefold_queries'
done
expect_render_failure 'setup is missing parameters.gate_mle_basefold_log_rate' 'missing-gate-policy'
mv -- "$setup.saved" "$setup"
mv -- "$server.saved" "$server"
mv -- "$client.saved" "$client"

# Reject altered query counts and bound models.
for mutation in \
  'parameters.gate_mle_basefold_queries|149|GateMLE BaseFold parameters do not match selected policy' \
  'security.basefold.target_bits|109|packed BaseFold bound policy is not selected' \
  'security.basefold.bound_model|list-decoding-iop-contribution|packed BaseFold bound policy is not selected'; do
  key="${mutation%%|*}"
  remainder="${mutation#*|}"
  value="${remainder%%|*}"
  expected="${remainder#*|}"
  cp -- "$setup" "$setup.saved"
  cp -- "$server" "$server.saved"
  cp -- "$client" "$client.saved"
  for record in "$setup" "$server" "$client"; do
    replace_key "$record" "$key" "$value"
  done
  expect_render_failure "$expected" 'invalid-rbr-policy'
  mv -- "$setup.saved" "$setup"
  mv -- "$server.saved" "$server"
  mv -- "$client.saved" "$client"
done

# Reduced query counts cannot be relabeled as the selected RBR policy.
cp -- "$setup" "$setup.saved"
cp -- "$server" "$server.saved"
cp -- "$client" "$client.saved"
for record in "$setup" "$server" "$client"; do
  replace_key "$record" 'security.basefold.selected_queries' '149'
done
expect_render_failure \
  'packed security parameters do not match the fixed profile policy' \
  'understrength-basefold-policy'
mv -- "$setup.saved" "$setup"
mv -- "$server.saved" "$server"
mv -- "$client.saved" "$client"

cp -- "$client" "$client.saved"
replace_key \
  "$client" 'noise.final_output.maximum_canonical_error_norm_bits' '7'
expect_render_failure \
  'packed final-output honest-noise audit is inconsistent' \
  'output-noise-derived-bound'
mv -- "$client.saved" "$client"

cp -- "$client" "$client.saved"
replace_key "$client" 'noise.final_output.target_enforced' 'yes'
replace_key "$client" 'noise.final_output.target_result' 'PASS'
expect_render_failure \
  'diagnostic packed output incorrectly enforces the target noise gate' \
  'output-noise-diagnostic-enforcement'
mv -- "$client.saved" "$client"

for record in "$setup" "$server" "$client"; do
  replace_key "$record" protocol.ciphertext_hash poseidon/v2
done
expect_render_failure \
  'ciphertext hash does not match the fixed profile policy' \
  'quick-poseidon-policy'
for record in "$setup" "$server" "$client"; do
  replace_key "$record" protocol.ciphertext_hash simpleCTHash/v2
done

lock_ready="$fixture/lifecycle-lock-ready"
python3 -c \
  'import fcntl, pathlib, sys, time; handle = open(sys.argv[1], "r+b"); fcntl.flock(handle, fcntl.LOCK_EX); pathlib.Path(sys.argv[2]).touch(); time.sleep(30)' \
  "$fixture/shared/lifecycle.lock" "$lock_ready" &
lock_holder=$!
while [[ ! -f "$lock_ready" ]]; do
  sleep 0.01
done
expect_render_failure 'benchmark run is being cleaned up' 'lifecycle-lock'
kill "$lock_holder"
wait "$lock_holder" 2>/dev/null || true
lock_holder=''

touch "$fixture/shared/transcript/unexpected-second-response.bin"
expect_render_failure \
  'protocol transcript must contain exactly one canonical request and one canonical response' \
  'extra-transcript-message'
rm -f -- "$fixture/shared/transcript/unexpected-second-response.bin"

cp -- "$client" "$client.saved"
replace_key "$client" 'timing.client.per_request_total.scope' 'wrong-scope'
expect_render_failure \
  'unexpected timing.client.per_request_total.scope cost boundary' \
  'client-cost-scope'
mv -- "$client.saved" "$client"

cp -- "$server" "$server.saved"
replace_key "$server" 'timing.server.startup.total.scope' 'wrong-scope'
expect_render_failure \
  'unexpected timing.server.startup.total.scope cost boundary' \
  'server-startup-cost-scope'
mv -- "$server.saved" "$server"

cp -- "$client" "$client.saved"
replace_key "$client" 'timing.client.verify.layer.0.kind' 'multiplication'
expect_render_failure \
  "client verifier layer 0 has kind 'multiplication'; expected 'affine'" \
  'verifier-layer-kind'
mv -- "$client.saved" "$client"

cp -- "$client" "$client.saved"
replace_key "$client" 'timing.client.verify.layer.1.circuit_layer' '2'
expect_render_failure \
  'client verifier row 1 names circuit layer 2; expected 1' \
  'verifier-circuit-layer'
mv -- "$client.saved" "$client"

cp -- "$server" "$server.saved"
printf '%s\n' 'wire.proof_bytes=1800' >> "$server"
expect_render_failure \
  'server has a noncanonical wire. schema: unexpected wire.proof_bytes' \
  'unexpected-wire-key'
mv -- "$server.saved" "$server"

cp -- "$setup" "$setup.saved"
printf '%s\n' \
  'timing.setup.persist_preprocessing.wall_ms=1' \
  'timing.setup.persist_preprocessing.cpu_ms=1' \
  >> "$setup"
expect_render_failure \
  'setup has a noncanonical timing.setup. schema' \
  'unexpected-setup-timing'
mv -- "$setup.saved" "$setup"

cp -- "$server" "$server.saved"
replace_key \
  "$server" 'timing.server.recurring_pre_request.total.scope' 'wrong-scope'
expect_render_failure \
  'unexpected timing.server.recurring_pre_request.total.scope cost boundary' \
  'server-recurring-admission-cost-scope'
mv -- "$server.saved" "$server"

cp -- "$server" "$server.saved"
replace_key "$server" 'timing.server.per_request_total.scope' 'wrong-scope'
expect_render_failure \
  'unexpected timing.server.per_request_total.scope cost boundary' \
  'server-request-cost-scope'
mv -- "$server.saved" "$server"

cp -- "$server" "$server.saved"
replace_key "$server" 'timing.server.per_request_total.wall_ms' '30050'
expect_render_failure \
  'timing.server.per_request_total wall total 30050.0 does not equal the declared phase sum 30095.0' \
  'server-request-omits-recurring-admission'
mv -- "$server.saved" "$server"

cp -- "$server" "$server.saved"
replace_key "$server" 'timing.server.response_published_unix_ms' '134060'
expect_render_failure 'server timestamps are not monotonic' 'timestamp-causality'
mv -- "$server.saved" "$server"

cp -- "$setup" "$setup.saved"
replace_key "$setup" 'environment.pinned_cpu' 'not-observed'
expect_render_failure \
  'setup did not observe a single pinned CPU' \
  'missing-cpu-affinity'
mv -- "$setup.saved" "$setup"

cp -- "$setup" "$setup.saved"
replace_key \
  "$setup" 'capacity.profile.max_live_disk_bytes' '199999475711'
expect_render_failure \
  'planner preflight policy is not the selected policy' \
  'prepublication-profile-capacity'
mv -- "$setup.saved" "$setup"

cp -- "$setup" "$setup.saved"
replace_key \
  "$setup" 'storage.setup.prepublication_additional_live_bytes' '3670015'
expect_render_failure \
  'setup prepublication additional live bytes do not equal peak live bytes minus already-present bytes' \
  'prepublication-additional-equation'
mv -- "$setup.saved" "$setup"

cp -- "$setup" "$setup.saved"
replace_key \
  "$setup" 'storage.setup.all_roles_persistent_bytes' '2097153'
replace_key \
  "$setup" 'storage.setup.client_private_persistent_bytes' '1048577'
replace_key \
  "$setup" 'storage.setup.verifying_key_bytes' '1310721'
replace_key \
  "$setup" 'storage.host_budget.exact_client_private_persistent_bytes' '1048577'
replace_key \
  "$setup" 'storage.host_budget.exact_server_live_disk_bytes' '199998951423'
replace_key \
  "$setup" 'capacity.profile.max_live_disk_bytes' '199998951423'
expect_render_failure \
  'observed all-role setup persistence exceeds its prepublication admission' \
  'prepublication-observed-persistence'
mv -- "$setup.saved" "$setup"

cp -- "$setup" "$setup.saved"
replace_key \
  "$setup" 'storage.setup.prepublication_admitted_peak_live_bytes' '200000000001'
replace_key \
  "$setup" 'storage.setup.prepublication_additional_live_bytes' '199999475713'
replace_key \
  "$setup" 'storage.setup.prepublication_required_available_bytes' '224999475713'
expect_render_failure \
  'setup prepublication peak live bytes exceed the whole-filesystem disk cap' \
  'prepublication-disk-cap'
mv -- "$setup.saved" "$setup"

cp -- "$setup" "$setup.saved"
replace_key \
  "$setup" 'memory.setup.prepublication_admitted_peak_resident_bytes' '52719476737'
replace_key \
  "$setup" 'memory.setup.prepublication_remaining_resident_reserve_bytes' '52718428161'
expect_render_failure \
  'setup prepublication peak resident bytes exceed the whole-setup or host RAM cap' \
  'prepublication-ram-cap'
mv -- "$setup.saved" "$setup"

cp -- "$setup" "$setup.saved"
replace_key \
  "$setup" 'storage.setup.prepublication_required_available_bytes' '100003670015'
expect_render_failure \
  'setup prepublication required available bytes do not equal additional live bytes plus the profile free-space floor' \
  'prepublication-required-available'
mv -- "$setup.saved" "$setup"

cp -- "$setup" "$setup.saved"
replace_key \
  "$setup" 'storage.setup.prepublication_observed_available_bytes' '100003670015'
expect_render_failure \
  'setup admission-time available disk is below the required prepublication envelope' \
  'prepublication-observed-available'
mv -- "$setup.saved" "$setup"

cp -- "$setup" "$setup.saved"
replace_key \
  "$setup" 'memory.setup.prepublication_remaining_resident_reserve_bytes' '3145727'
expect_render_failure \
  'setup prepublication resident admission does not equal the observed prefix peak plus the remaining reserve' \
  'prepublication-resident-equation'
mv -- "$setup.saved" "$setup"

cp -- "$setup" "$setup.saved"
replace_key \
  "$setup" 'memory.setup.peak_rss_bytes' '4194305'
expect_render_failure \
  'observed setup RSS exceeds its prepublication admission' \
  'prepublication-observed-rss'
mv -- "$setup.saved" "$setup"

printf '%s\n' 'human notes' > "$output"
status=0
python3 "$renderer" \
  --run-dir "$fixture" --variant folded --profile quick --output "$output" \
  >/dev/null 2>"$fixture/human-output-error.txt" || status=$?
if [[ "$status" -eq 0 ]] ||
   ! grep -Fq 'existing summary was not generated by this packed renderer' \
     "$fixture/human-output-error.txt" ||
   [[ "$(cat "$output")" != 'human notes' ]]; then
  printf 'packed summary renderer replaced a human-owned output\n' >&2
  exit 1
fi

rm -f -- "$output"

status=0
python3 "$renderer" \
  --run-dir "$fixture" --variant folded --profile target-balancedLaned --output "$output" \
  >/dev/null 2>"$fixture/mismatch-error.txt" || status=$?
if [[ "$status" -eq 0 ]] ||
   ! grep -Fq 'setup does not bind benchmark.profile=target-balancedLaned' \
     "$fixture/mismatch-error.txt"; then
  printf 'packed summary did not fail closed on profile mismatch\n' >&2
  exit 1
fi

# Target reports require two immutable filesystem-boundary snapshots and an
# internally consistent formula-only replay admission ledger. Exercise those
# target-only validators directly without manufacturing a full target proof.
target_storage_run="$fixture/target-storage"
mkdir -p "$target_storage_run/shared"
for phase in setup-start server-start; do
  if [[ "$phase" == setup-start ]]; then
    captured_at='2026-09-03T01:00:00Z'
    available=3170000000000
  else
    captured_at='2026-09-03T02:00:00Z'
    available=3120000000000
  fi
  printf '%s\n' \
    'format=laminate-storage-provenance-v2' \
    "storage.capture_phase=$phase" \
    "storage.captured_at_utc=$captured_at" \
    'storage.artifact_root=/mnt/disks/laminate-storage/laminate-bench' \
    'storage.backend=google-local-ssd-raid0' \
    'storage.mount_source=/dev/md127' \
    'storage.mount_target=/mnt/disks/laminate-storage' \
    'storage.filesystem_type=ext4' \
    'storage.mount_options=rw,noatime,nodiratime' \
    'storage.filesystem_total_bytes=3221225472000' \
    "storage.filesystem_available_bytes=$available" \
    'storage.local_ssd.raid_level=raid0' \
    'storage.local_ssd.raid_member_count=8' \
    'storage.local_ssd.raid_degraded_members=0' \
    'storage.local_ssd.raid_chunk_bytes=524288' \
    'storage.local_ssd.raid_members=nvme0n1,nvme1n1,nvme2n1,nvme3n1,nvme4n1,nvme5n1,nvme6n1,nvme7n1' \
    > "$target_storage_run/shared/storage-provenance.$phase.txt"
done
python3 - "$renderer" "$target_storage_run" <<'PY'
import importlib.util
from pathlib import Path
import sys

renderer_path = Path(sys.argv[1])
sys.path.insert(0, str(renderer_path.resolve().parent))
run = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("laminate_packed_summary", renderer_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

storage = module.target_storage_pair(run)
setup = {
    "storage.planner_preflight.classification": "exact-compiled-trace-formula-only",
    "storage.planner_preflight.gross_live_disk_bytes": "3020000000000",
    "storage.planner_preflight.max_live_disk_bytes": "3000000000000",
    "storage.planner_preflight.min_free_disk_bytes": "100000000000",
    "storage.planner_preflight.client_private_persistent_reserve_bytes": "20000000000",
    "storage.planner_preflight.server_common_reserve_bytes": "128000000000",
    "storage.planner_preflight.required_available_disk_bytes": "3120000000000",
    "storage.planner_preflight.observed_available_disk_bytes": "3120000000000",
    "storage.host_budget.gross_live_disk_bytes": "3020000000000",
    "storage.host_budget.exact_client_private_persistent_bytes": "10000000000",
    "storage.host_budget.exact_server_live_disk_bytes": "3010000000000",
    "storage.setup.client_private_persistent_bytes": "10000000000",
    "memory.planner_preflight.observed_physical_ram_bytes": "372000000000",
    "memory.planner_preflight.safety_reserve_bytes": "80000000000",
    "memory.planner_preflight.gross_resident_budget_bytes": "292000000000",
    "memory.planner_preflight.client_peak_resident_reserve_bytes": "20000000000",
    "memory.planner_preflight.server_resident_cap_bytes": "272000000000",
    "memory.host_budget.gross_resident_budget_bytes": "292000000000",
    "memory.host_budget.exact_client_peak_resident_bytes": "10000000000",
    "memory.host_budget.exact_server_resident_cap_bytes": "282000000000",
    "memory.client.admitted_peak_resident_bytes": "10000000000",
    "storage.planner_preflight.selected_peak_live_bytes": "2900000000000",
    "storage.planner_preflight.selected_checkpoint_count": "7",
    "storage.planner_preflight.selected_checkpoint_bytes": "1900000000000",
    "storage.planner_preflight.initial_forward_work_units": "1000",
    "storage.planner_preflight.repeated_work_units": "1250",
    "storage.planner_preflight.cumulative_work_units": "2250",
    "storage.planner_preflight.cumulative_recomputation_factor": "2.25",
    "storage.planner_preflight.maximum_recomputation_numerator": "5",
    "storage.planner_preflight.maximum_recomputation_denominator": "2",
}
capacity = {
    "max_live_disk_bytes": 3_010_000_000_000,
    "max_resident_ram_bytes": 282_000_000_000,
    "min_free_disk_bytes": 100_000_000_000,
}
exact_replay = {
    "storage.replay.selected_checkpoint_bytes": "100",
    "storage.replay.persistent_reserve_bytes": "20",
    "storage.replay.maximum_consumer_artifact_bytes": "30",
    "storage.replay.admitted_peak_live_bytes": "200",
    "memory.replay.dense_multiplication_alias_cache_peak_resident_bytes": "10",
    "memory.replay.admitted_peak_resident_bytes": "40",
    "work.replay.initial_forward_units": "1000",
    "work.replay.repeated_units": "1250",
    "work.replay.cumulative_units": "2250",
    "work.replay.cumulative_factor": "2.25",
}
exact_replay_keys = tuple(exact_replay)
assert module.replay_plan_ledger_present(
    exact_replay, exact_replay_keys, required=True
)
try:
    module.replay_plan_ledger_present({}, exact_replay_keys, required=True)
except module.ReportError as error:
    assert "incomplete checkpoint-replay plan ledger" in str(error)
else:
    raise AssertionError("target report without an exact replay ledger was accepted")
module.validate_replay_plan_ledger(exact_replay, capacity, (5, 2))
over_limit = dict(exact_replay)
over_limit["work.replay.repeated_units"] = "1600"
over_limit["work.replay.cumulative_units"] = "2600"
over_limit["work.replay.cumulative_factor"] = "2.6"
try:
    module.validate_replay_plan_ledger(over_limit, capacity, (5, 2))
except module.ReportError as error:
    assert "planner work ceiling" in str(error)
else:
    raise AssertionError("over-limit exact target replay work was accepted")
ledger = module.planner_preflight_ledger(
    setup, storage, capacity
)
medium_ledger = module.planner_preflight_ledger(
    setup, None, capacity
)
assert ledger["checkpoint_count"] == 7
assert medium_ledger == ledger
assert ledger["gross_live"] == 3_020_000_000_000
assert ledger["max_live"] == 3_000_000_000_000
assert ledger["exact_server_live"] == 3_010_000_000_000
assert ledger["gross_resident"] == 292_000_000_000
assert ledger["server_resident_cap"] == 272_000_000_000
assert ledger["exact_server_resident"] == 282_000_000_000
assert ledger["gross_resident"] > 128_000_000_000

bad = dict(setup)
bad["storage.planner_preflight.cumulative_work_units"] = "2251"
try:
    module.planner_preflight_ledger(
        bad, storage, capacity
    )
except module.ReportError as error:
    assert "ledger is inconsistent" in str(error)
else:
    raise AssertionError("inconsistent target storage preflight was accepted")

bad = dict(setup)
bad["storage.planner_preflight.max_live_disk_bytes"] = "2999999999999"
try:
    module.planner_preflight_ledger(bad, storage, capacity)
except module.ReportError as error:
    assert "selected policy" in str(error)
else:
    raise AssertionError("non-derived target disk budget was accepted")

bad = dict(setup)
bad["storage.host_budget.exact_server_live_disk_bytes"] = "3009999999999"
try:
    module.planner_preflight_ledger(bad, storage, capacity)
except module.ReportError as error:
    assert "selected policy" in str(error)
else:
    raise AssertionError("non-derived exact target server cap was accepted")

bad = dict(setup)
bad["storage.host_budget.exact_client_private_persistent_bytes"] = "10000000001"
try:
    module.planner_preflight_ledger(bad, storage, capacity)
except module.ReportError as error:
    assert "selected policy" in str(error)
else:
    raise AssertionError("mismatched exact client persistence was accepted")

bad = dict(setup)
bad["memory.planner_preflight.server_resident_cap_bytes"] = "335999999999"
try:
    module.planner_preflight_ledger(bad, storage, capacity)
except module.ReportError as error:
    assert "selected policy" in str(error)
else:
    raise AssertionError("non-derived preflight server RAM cap was accepted")

bad = dict(setup)
bad["memory.planner_preflight.gross_resident_budget_bytes"] = "355999999999"
try:
    module.planner_preflight_ledger(bad, storage, capacity)
except module.ReportError as error:
    assert "selected policy" in str(error)
else:
    raise AssertionError("non-derived gross target RAM budget was accepted")

bad = dict(setup)
bad["memory.host_budget.exact_client_peak_resident_bytes"] = "10000000001"
try:
    module.planner_preflight_ledger(bad, storage, capacity)
except module.ReportError as error:
    assert "selected policy" in str(error)
else:
    raise AssertionError("mismatched exact client RAM was accepted")

bad = dict(setup)
bad["memory.host_budget.exact_server_resident_cap_bytes"] = "345999999999"
try:
    module.planner_preflight_ledger(bad, storage, capacity)
except module.ReportError as error:
    assert "selected policy" in str(error)
else:
    raise AssertionError("non-derived exact server RAM cap was accepted")

server_path = run / "shared" / "storage-provenance.server-start.txt"
server = server_path.read_text(encoding="utf-8")
server_path.write_text(
    server.replace(
        "storage.local_ssd.raid_degraded_members=0",
        "storage.local_ssd.raid_degraded_members=1",
    ),
    encoding="utf-8",
)
try:
    module.target_storage_pair(run)
except module.ReportError as error:
    assert "healthy Local SSD RAID0" in str(error)
else:
    raise AssertionError("degraded target storage provenance was accepted")

server_path.write_text(
    server.replace(
        "storage.mount_target=/mnt/disks/laminate-storage",
        "storage.mount_target=/",
    ),
    encoding="utf-8",
)
try:
    module.target_storage_pair(run)
except module.ReportError as error:
    assert "invalid absolute storage paths" in str(error)
else:
    raise AssertionError("mount_target=/ was accepted for Local SSD storage")

# Replacing both snapshots with dedicated-block provenance exercises the
# Hyperdisk-shaped backend without needing a block device in this unit test.
for phase, captured_at, available in (
    ("setup-start", "2026-09-03T01:00:00Z", 3_170_000_000_000),
    ("server-start", "2026-09-03T02:00:00Z", 3_120_000_000_000),
):
    (run / "shared" / f"storage-provenance.{phase}.txt").write_text(
        "\n".join(
            (
                "format=laminate-storage-provenance-v2",
                f"storage.capture_phase={phase}",
                f"storage.captured_at_utc={captured_at}",
                "storage.artifact_root=/mnt/disks/laminate-storage/laminate-bench",
                "storage.mount_source=/dev/nvme0n2",
                "storage.mount_target=/mnt/disks/laminate-storage",
                "storage.filesystem_type=ext4",
                "storage.mount_options=rw,noatime,nodiratime",
                "storage.filesystem_total_bytes=3221225472000",
                f"storage.filesystem_available_bytes={available}",
                "storage.backend=dedicated-block",
                "storage.dedicated_block.device=/dev/nvme0n2",
                "storage.dedicated_block.device_type=disk",
                "storage.dedicated_block.device_ancestry=nvme0n2",
                "storage.dedicated_block.protected_ancestry=nvme0n1,nvme0n1p1",
                "",
            )
        ),
        encoding="utf-8",
    )
dedicated = module.target_storage_pair(run)
assert dedicated[0]["storage.backend"] == "dedicated-block"
dedicated_rows = "\n".join(module.target_storage_report_rows(*dedicated))
assert "Dedicated whole block device" in dedicated_rows
assert "/dev/nvme0n2" in dedicated_rows
assert "Protected root/boot ancestry" in dedicated_rows
assert "RAID0 chunk" not in dedicated_rows

dedicated_server_path = run / "shared" / "storage-provenance.server-start.txt"
dedicated_server = dedicated_server_path.read_text(encoding="utf-8")
dedicated_server_path.write_text(
    dedicated_server.replace(
        "storage.dedicated_block.device=/dev/nvme0n2",
        "storage.dedicated_block.device=/dev/nvme9n9",
    ),
    encoding="utf-8",
)
try:
    module.target_storage_pair(run)
except module.ReportError as error:
    assert "dedicated whole block device" in str(error)
else:
    raise AssertionError("dedicated device/mount mismatch was accepted")


def write_shared_root_snapshots() -> None:
    for phase, captured_at, available in (
        ("setup-start", "2026-09-03T01:00:00Z", 3_170_000_000_000),
        ("server-start", "2026-09-03T02:00:00Z", 3_120_000_000_000),
    ):
        (run / "shared" / f"storage-provenance.{phase}.txt").write_text(
            "\n".join(
                (
                    "format=laminate-storage-provenance-v2",
                    f"storage.capture_phase={phase}",
                    f"storage.captured_at_utc={captured_at}",
                    "storage.artifact_root=/var/lib/laminate-storage/laminate-bench",
                    "storage.mount_source=/dev/nvme0n1p1",
                    "storage.mount_target=/",
                    "storage.filesystem_type=ext4",
                    "storage.mount_options=rw,relatime",
                    "storage.filesystem_total_bytes=3221225472000",
                    f"storage.filesystem_available_bytes={available}",
                    "storage.backend=shared-root-filesystem",
                    "storage.shared_root.directory=/var/lib/laminate-storage",
                    "storage.shared_root.shares_os=true",
                    "",
                )
            ),
            encoding="utf-8",
        )


# A shared root filesystem deliberately permits mount_target=/ and ordinary
# rw,relatime options, but its dedicated subdirectory and lack of isolation
# must be explicit and stable across both snapshots.
write_shared_root_snapshots()
shared_root = module.target_storage_pair(run)
assert shared_root[0]["storage.backend"] == "shared-root-filesystem"
shared_root_rows = "\n".join(module.target_storage_report_rows(*shared_root))
assert "Shared storage directory" in shared_root_rows
assert "/var/lib/laminate-storage" in shared_root_rows
assert "Shares OS filesystem and I/O" in shared_root_rows
assert (
    "benchmark artifacts and the operating system share the root filesystem "
    "and I/O path" in shared_root_rows
)
assert "Dedicated whole block device" not in shared_root_rows
assert "RAID0 chunk" not in shared_root_rows

shared_server_path = run / "shared" / "storage-provenance.server-start.txt"
shared_server = shared_server_path.read_text(encoding="utf-8")
shared_server_path.write_text(
    shared_server.replace(
        "storage.shared_root.shares_os=true",
        "storage.shared_root.shares_os=false",
    ),
    encoding="utf-8",
)
try:
    module.target_storage_pair(run)
except module.ReportError as error:
    assert "does not acknowledge shared OS filesystem and I/O" in str(error)
else:
    raise AssertionError("false shared-root OS provenance was accepted")

write_shared_root_snapshots()
shared_server = shared_server_path.read_text(encoding="utf-8")
shared_server_path.write_text(
    shared_server.replace(
        "storage.artifact_root=/var/lib/laminate-storage/laminate-bench",
        "storage.artifact_root=/var/lib/other-storage/laminate-bench",
    ),
    encoding="utf-8",
)
try:
    module.target_storage_pair(run)
except module.ReportError as error:
    assert "must be exactly STORAGE/laminate-bench" in str(error)
else:
    raise AssertionError("artifact root outside shared-root storage was accepted")

write_shared_root_snapshots()
for snapshot_path in (
    run / "shared" / "storage-provenance.setup-start.txt",
    run / "shared" / "storage-provenance.server-start.txt",
):
    contents = snapshot_path.read_text(encoding="utf-8")
    snapshot_path.write_text(
        contents.replace(
            "/var/lib/laminate-storage", "/mnt/disks/laminate-storage"
        ),
        encoding="utf-8",
    )
try:
    module.target_storage_pair(run)
except module.ReportError as error:
    assert "must use /var/lib/laminate-storage" in str(error)
else:
    raise AssertionError("shared-root storage outside /var/lib was accepted")

write_shared_root_snapshots()
shared_server = shared_server_path.read_text(encoding="utf-8")
shared_server_path.write_text(
    shared_server.replace("storage.mount_target=/", "storage.mount_target=/var/lib"),
    encoding="utf-8",
)
try:
    module.target_storage_pair(run)
except module.ReportError as error:
    assert "must use / as storage.mount_target" in str(error)
else:
    raise AssertionError("non-root shared-root mount target was accepted")
PY
for target_heading in \
  '## Target storage provenance' \
  'Backend' \
  'Healthy Local SSD RAID0 members' \
  'Dedicated whole block device' \
  '## Host-derived checkpoint planner' \
  'Observed physical RAM' \
  'Gross resident-memory budget' \
  'Conservative waiting-client resident reserve' \
  'Preflight net server resident cap' \
  'Exact admitted client peak' \
  'Exact net server resident cap' \
  'Available at setup start' \
  'Available at server start' \
  'Gross live-disk budget' \
  'Conservative client-private persistence' \
  'Preflight net server live-disk cap' \
  'Server-common reserve inside that cap' \
  'Exact client-private persistence' \
  'Exact net server live-disk cap' \
  'Cumulative recomputation factor'; do
  grep -Fq -- "$target_heading" "$renderer" || {
    printf 'packed target report omitted renderer field: %s\n' \
      "$target_heading" >&2
    exit 1
  }
done

# Bind all five payload gate counts in every role.
for record in "$setup" "$server" "$client"; do
  printf '%s\n' 'geometry.payload_mul_plain_gates=0' \
    'geometry.payload_rotate_gates=0' >> "$record"
done
python3 "$renderer" --run-dir "$fixture" --variant folded --profile quick \
  --output "$output"
replace_key "$server" geometry.payload_rotate_gates 1
if python3 "$renderer" --run-dir "$fixture" --variant folded --profile quick \
    --output "$output" 2>/dev/null; then
  printf '%s\n' 'packed summary accepted inconsistent rotation ledgers' >&2
  exit 1
fi
replace_key "$server" geometry.payload_rotate_gates 0

# The Folded fixture has the same aligned-message geometry as B=N Laned.
# Rebind every accepted role record and prove that a successful Laned report
# requires the caller's explicit B to agree with the immutable setup.
for record in "$setup" "$server" "$client"; do
  replace_key "$record" protocol.variant laned
  replace_key "$record" run.variant laned
  replace_key "$record" parameters.gate_mle_profile structured-sparse-basefold
  replace_key "$record" parameters.gate_mle_basefold_queries 150
  replace_key "$record" geometry.B 16384
  replace_key \
    "$record" schedule.proof_ingress_policy \
    LaminateImpl/ConservativePackedProofIngress/v3
done
replace_key "$fixture/shared/run-binding.txt" run.variant laned
rm -f -- "$output"
python3 "$renderer" \
  --run-dir "$fixture" --variant laned --profile quick --lanes 16384 \
  --output "$output"
grep -Fq '| Variant/profile | `laned` / `quick` |' "$output" || {
  printf 'successful B=N Laned summary omitted its variant binding\n' >&2
  exit 1
}
python3 - "$renderer" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, str(Path(sys.argv[1]).resolve().parent))
import render_packed_checkpoint_summary as renderer
# Exact synthetic setup records for every supported current target chain.
# These are public metadata fixtures, not measured benchmark results.
from math import prod
prefix = [60, 48, 48, 37, 37, 37, 37, 38, 38, 39]
prime_prefix = [1053858393162252289, 281412698669057, 281449206448129,
                96638238721, 98785755137, 118113402881, 122408435713,
                246964387841, 272734584833, 547616686081]
prime_tail = [998595133441, 1005037682689, 1032955396097, 1095233372161]
special = 1152921504606748673
cases = [("folded", "target-balancedLaned", 0),
         ("folded", "target-mulHeavyPyramid", 0)]
cases += [("laned", "target-balancedLaned", lanes) for lanes in (1, 128, 16384)]
for variant, profile, lanes in cases:
    narrow = variant == "laned" and lanes < 16384
    widths = prefix + [40] * (5 if narrow else 4)
    primes = prime_prefix + ([972824936449] if narrow else []) + prime_tail
    policy = (renderer.LANED_PROOF_INGRESS_POLICY if variant == "laned"
              else "LaminateImpl/ConservativePackedProofIngress/v1")
    setup = {
        "fhe.data_rns_limbs": str(len(primes)),
        "fhe.data_prime_bit_sizes": ",".join(map(str, widths)),
        "fhe.data_primes_bottom_to_top": ",".join(map(str, primes)),
        "fhe.special_prime_bits": "60", "fhe.special_prime": str(special),
        "fhe.fresh_modulus_product_bits": str(prod(primes).bit_length()),
        "fhe.key_modulus_product_bits": str((prod(primes) * special).bit_length()),
    }
    assert (int(setup["fhe.fresh_modulus_product_bits"]),
            int(setup["fhe.key_modulus_product_bits"])) == ((617, 677) if narrow else (577, 637))
    renderer.validate_packed_target_modulus(
        profile, variant, lanes, policy,
        renderer.integer_list(setup, "fhe.data_prime_bit_sizes", "setup"),
        renderer.integer(setup, "fhe.special_prime_bits", "setup"),
        renderer.integer_list(setup, "fhe.data_primes_bottom_to_top", "setup"),
        renderer.integer(setup, "fhe.special_prime", "setup"))
    wrong_prime_order = primes.copy()
    wrong_prime_order[-1], wrong_prime_order[-2] = wrong_prime_order[-2], wrong_prime_order[-1]
    for wrong_widths, wrong_special_bits, wrong_primes, wrong_special in (
        (widths + [40], 60, primes, special),
        (widths[:-1], 60, primes[:-1], special),  # Truncated chain.
        (widths, 59, primes, special),
        (widths, 60, wrong_prime_order, special),
        (widths, 60, primes, special - 32768),
    ):
        try:
            renderer.validate_packed_target_modulus(
                profile, variant, lanes, policy, wrong_widths,
                wrong_special_bits, wrong_primes, wrong_special)
        except renderer.ReportError:
            pass
        else:
            raise AssertionError("accepted incorrect packed target modulus")

PY

# Check the Folded pyramid's separate exact chain and same-live-key admission.
python3 - "$renderer" <<'PY'
from pathlib import Path
from math import prod
import sys
sys.path.insert(0, str(Path(sys.argv[1]).resolve().parent))
import render_packed_checkpoint_summary as renderer
primes = [1053858393162252289, 281412698669057, 281449206448129,
          96638238721, 98785755137, 118113402881,
          35004517580801, 35017402679297, 35047467909121, 35092565753857,
          35111893401601, 35126926016513, 35144106147841, 35156991246337]
widths = [p.bit_length() for p in primes]
special = 1152921504606748673
policy = renderer.FOLDED_PYRAMID_PROOF_INGRESS_POLICY
renderer.validate_packed_target_modulus(
    "target-mulHeavyPyramid", "folded", 0, policy, widths, 60, primes, special)
assert (prod(primes).bit_length(), (prod(primes) * special).bit_length()) == (626, 686)
for variant, profile, lanes, wrong_policy in (
    ("folded", "target-balancedLaned", 0, policy),
    ("laned", "target-balancedLaned", 16384, policy),
    ("folded", "target-mulHeavyPyramid", 0, "LaminateImpl/ConservativePackedProofIngress/v1"),
):
    try:
        renderer.validate_packed_target_modulus(
            profile, variant, lanes, wrong_policy, widths, 60, primes, special)
    except renderer.ReportError:
        pass
    else:
        raise AssertionError("accepted new chain under another profile or policy")
admission = {
    "schedule.proof_ingress_policy": policy,
    "noise_preflight.result": "PASS",
    "noise_preflight.policy": "folded-target-pyramid-live-key-v1",
    "noise_preflight.same_setup_key": "true",
    "noise_preflight.root_wire": "1042862",
    "noise_preflight.outer_spartan_included": "false",
    "schedule.proof_ingress_rns_limbs_by_layer": "1,4,6,4,6,4,6,4,6,4,6,4,6,4,6,4,6,4",
    "schedule.payload_modulus_switches_after_layer": "3,3,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,0",
    "timing.setup.live_key_noise_preflight.wall_ms": "100",
    "timing.setup.live_key_noise_preflight.cpu_ms": "99",
    "timing.setup.workload_compilation.wall_ms": "200",
    "timing.setup.workload_compilation.cpu_ms": "199",
}
renderer.validate_folded_pyramid_preflight(admission)
timed = dict(admission)
timed.update({"timing.setup.started_unix_ms": "0",
              "timing.setup.finished_unix_ms": "300",
              "timing.setup.total.wall_ms": "300",
              "timing.setup.total.cpu_ms": "299"})
for phase in renderer.SETUP_TIMING_PHASES:
    for clock in ("wall_ms", "cpu_ms"):
        timed.setdefault(f"timing.setup.{phase}.{clock}", "10")
rows = renderer.setup_timing_rows(timed, "setup")
assert [row[0] for row in rows] == list(renderer.SETUP_TIMING_PHASES)
assert sum(row[1] for row in rows) == 250  # Component is not counted twice.
for key in admission:
    if key == "schedule.proof_ingress_policy":
        continue
    broken = dict(admission)
    broken.pop(key)
    try:
        renderer.validate_folded_pyramid_preflight(broken)
    except renderer.ReportError:
        pass
    else:
        raise AssertionError(f"accepted missing preflight field {key}")
for key, value in (("noise_preflight.result", "FAILED"),
                   ("noise_preflight.same_setup_key", "false"),
                   ("timing.setup.live_key_noise_preflight.cpu_ms", "0"),
                   ("timing.setup.live_key_noise_preflight.wall_ms", "201.1"),
                   ("schedule.proof_ingress_rns_limbs_by_layer", "1,3,6")):
    broken = dict(admission)
    broken[key] = value
    try:
        renderer.validate_folded_pyramid_preflight(broken)
    except renderer.ReportError:
        pass
    else:
        raise AssertionError(f"accepted invalid preflight field {key}")
PY

# Render current target records through the complete ordinary report path.
# Records remain synthetic parser fixtures; no benchmark measurement is made.
python3 - "$renderer" "$concise_renderer" "$fixture" "$target_storage_run" <<'PY'
from math import prod
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0, str(Path(sys.argv[1]).resolve().parent))
import render_packed_checkpoint_summary as renderer
renderer_path, concise_path, source, storage_source = map(Path, sys.argv[1:])

def write(path, record):
    path.write_text("".join(f"{key}={value}\n" for key, value in record.items()))

for variant, lanes in (("folded", 0), ("laned", 1), ("laned", 128), ("laned", 16384)):
    run = source / f"target-render-{variant}-{lanes}"
    for directory in ("shared", "client", "server"):
        shutil.copytree(source / directory, run / directory)
    for phase in ("setup-start", "server-start"):
        storage = renderer.parse_record(storage_source / "shared" / f"storage-provenance.{phase}.txt")
        storage["storage.mount_target"] = "/"
        write(run / "shared" / f"storage-provenance.{phase}.txt", storage)
    paths = (run / "shared/setup-result.txt", run / "server/result.txt", run / "client/result.txt")
    records = [renderer.parse_record(path) for path in paths]
    setup, server, client = records
    narrow = variant == "laned" and lanes < 16384
    widths = [60, 48, 48, 37, 37, 37, 37, 38, 38, 39] + [40] * (5 if narrow else 4)
    primes = [1053858393162252289, 281412698669057, 281449206448129,
              96638238721, 98785755137, 118113402881, 122408435713,
              246964387841, 272734584833, 547616686081]
    primes += ([972824936449] if narrow else [])
    primes += [998595133441, 1005037682689, 1032955396097, 1095233372161]
    for record in records:
        record.update({
            "protocol.variant": variant, "run.variant": variant,
            "run.profile": "target-balancedLaned", "benchmark.profile": "target-balancedLaned",
            "benchmark.evidence": "evaluation", "security.claim": "selected-rbr-target-pending-composition",
            "security.transcript_packing.actual_repetitions": "120",
            "security.basefold.actual_queries": "150",
            "protocol.ciphertext_hash": "poseidon/v2",
            "security.ciphertext_hash.claim": "poseidon-ciphertext-binding",
            "parameters.gate_mle_profile": "wide-local-adjoint-foldable" if variant == "folded" else "structured-sparse-basefold",
            "parameters.gate_mle_basefold_queries": "300" if variant == "folded" else "150",
            "schedule.proof_ingress_policy": "LaminateImpl/ConservativePackedProofIngress/v1" if variant == "folded" else renderer.LANED_PROOF_INGRESS_POLICY,
            "geometry.B": str(lanes), "geometry.depth": "8", "geometry.width": "65536",
            "geometry.workload": "balancedLaned", "geometry.payload_operations": "1048576",
            "geometry.payload_add_gates": "471859", "geometry.payload_add_plain_gates": "52429",
            "geometry.payload_mul_gates": "524288",
            "fhe.data_rns_limbs": str(len(primes)),
            "fhe.data_prime_bit_sizes": ",".join(map(str, widths)),
            "fhe.data_primes_bottom_to_top": ",".join(map(str, primes)),
            "fhe.special_prime_bits": "60", "fhe.special_prime": "1152921504606748673",
            "fhe.fresh_modulus_product_bits": str(prod(primes).bit_length()),
            "fhe.key_modulus_product_bits": str((prod(primes) * 1152921504606748673).bit_length()),
        })
    for field in (*renderer.PACKING_R1CS_INTEGER_FIELDS, "ciphertext_hash"):
        setup[f"packing.r1cs.actual.{field}"] = setup[f"packing.r1cs.selected_target.{field}"]
    for key, value in {
        "work.replay.repeated_units": "0", "work.replay.cumulative_units": setup["work.replay.initial_forward_units"],
        "work.replay.cumulative_factor": "1",
        "storage.planner_preflight.repeated_work_units": "0",
        "storage.planner_preflight.cumulative_work_units": setup["storage.planner_preflight.initial_forward_work_units"],
        "storage.planner_preflight.cumulative_recomputation_factor": "1",
    }.items():
        setup[key] = value
    client.update({
        "noise.final_output.data_modulus_product_bits": "60",
        "noise.final_output.maximum_invariant_budget_implied_phase_norm_bits": "47",
        "noise.final_output.target_enforced": "yes", "noise.final_output.target_result": "PASS",
        "timing.client.verify.layer_count": "17",
    })
    for index in range(17):
        prefix = f"timing.client.verify.layer.{index}"
        client.update({f"{prefix}.circuit_layer": str(index),
                       f"{prefix}.kind": "affine" if index % 2 == 0 else "multiplication",
                       f"{prefix}.wall_ms": "0.5", f"{prefix}.cpu_ms": "0.5"})
    binding = renderer.parse_record(run / "shared/run-binding.txt")
    binding.update({"run.variant": variant, "run.profile": "target-balancedLaned"})
    write(run / "shared/run-binding.txt", binding)
    for path, record in zip(paths, records):
        write(path, record)
    output = run / "shared/report/summary.md"
    args = ["--run-dir", str(run), "--variant", variant, "--profile", "target-balancedLaned"]
    if variant == "laned":
        args += ["--lanes", str(lanes)]
    subprocess.run([sys.executable, str(renderer_path), *args, "--output", str(output)], check=True)
    expected = f"{617 if narrow else 577} bits across {15 if narrow else 14} limbs"
    assert expected in output.read_text()
    subprocess.run([sys.executable, str(concise_path), "--input", str(output),
                    "--output", str(run / "shared/report/target.md"),
                    *args], check=True)
    # Consistent cross-role values must still match the selected profile.
    for path, record in zip(paths, records):
        shorter = primes[:-1]
        record.update({"fhe.data_rns_limbs": str(len(shorter)),
                       "fhe.data_prime_bit_sizes": ",".join(map(str, widths[:-1])),
                       "fhe.data_primes_bottom_to_top": ",".join(map(str, shorter)),
                       "fhe.fresh_modulus_product_bits": str(prod(shorter).bit_length()),
                       "fhe.key_modulus_product_bits": str((prod(shorter) * 1152921504606748673).bit_length())})
        write(path, record)
    rejected = subprocess.run([sys.executable, str(renderer_path), *args,
                               "--output", str(output)],
                              text=True, capture_output=True)
    assert rejected.returncode != 0 and "fixed profile chain" in rejected.stderr, rejected.stderr
PY

rm -f -- "$output"
status=0
python3 "$renderer" \
  --run-dir "$fixture" --variant laned --profile quick --lanes 128 \
  --output "$output" >/dev/null 2>"$fixture/laned-b-mismatch.txt" || status=$?
if [[ "$status" -eq 0 ]] ||
   ! grep -Fq 'packed workload geometry does not match the fixed profile' \
     "$fixture/laned-b-mismatch.txt"; then
  printf 'packed summary did not fail closed on a mismatched Laned B\n' >&2
  cat -- "$fixture/laned-b-mismatch.txt" >&2
  exit 1
fi
