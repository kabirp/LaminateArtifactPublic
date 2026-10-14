#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf 'usage: %s NO_INTEGRITY_SUMMARY_RENDERER CONCISE_RENDERER\n' "$0" >&2
  exit 2
fi

renderer="$1"
concise_renderer="$2"
fixture="$(mktemp -d)"
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/shared/report" "$fixture/shared/transcript" \
  "$fixture/client" "$fixture/server"
touch "$fixture/shared/lifecycle.lock"
chmod 600 "$fixture/shared/lifecycle.lock"

run_id='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
commit='0123456789abcdef0123456789abcdef01234567'
primes='18014336227311617,15032614913,53687910401,96638238721,98785755137,118113402881,122408435713'

write_common() {
  local destination="$1"
  local cpu="$2"
  printf '%s\n' \
    'run.variant=noIntegrity' \
    'run.profile=quick' \
    "run.id=$run_id" \
    "environment.git_commit=$commit" \
    'environment.git_dirty=false' \
    'environment.build_type=Release' \
    'environment.compiler=fixture' \
    'environment.seal_version=4.1.2' \
    'environment.seal_acceleration=intel-hexl-runtime-dispatch' \
    'environment.sha256_acceleration=openssl' \
    'environment.fhe_backend=seal-bgv' \
    'environment.trace_execution=file-backed-output-only' \
    'environment.threading=single-cpu-process' \
    "environment.pinned_cpu=$cpu" \
    'environment.os=fixture-os' \
    'environment.cpu=fixture-cpu' \
    'environment.physical_cores=4' \
    'environment.logical_cores=4' \
    'environment.ram_bytes=68719476736' \
    'environment.cpu_features.probe=fixture' \
    'environment.cpu_features.avx2_available=yes' \
    'environment.cpu_features.avx512f_available=yes' \
    'environment.cpu_features.avx512dq_available=yes' \
    'environment.cpu_features.avx512ifma_available=yes' \
    'parameters.slots=16384' \
    'parameters.payload_multiplicative_depth=6' \
    'parameters.payload_workload=diamond' \
    'parameters.payload_width=1024' \
    'parameters.payload_inputs=64' \
    'parameters.payload_outputs=1' \
    'parameters.payload_operations=13311' \
    'parameters.payload_add_gates=1023' \
    'parameters.payload_add_plain_gates=6144' \
    'parameters.payload_mul_gates=6144' \
    'parameters.compiled_layers=14' \
    'parameters.fresh_rns_limbs=7' \
    'parameters.fresh_modulus_product_bits=271' \
    'parameters.key_modulus_product_bits=304' \
    'parameters.output_rns_limbs=1' \
    'parameters.plaintext_modulus=65537' \
    "parameters.data_primes_bottom_to_top=$primes" \
    'parameters.special_prime=8590163969' \
    'parameters.output_modulus=18014336227311617' \
    'parameters.output_modulus_bits=54' \
    'parameters.modulus_switch_policy=one-after-each-ctct-multiplication-layer' \
    'parameters.security=SEAL sec_level_type::tc128' \
    'parameters.galois_keys=omitted-no-rotation-gates' \
    'parameters.integrity=none' \
    'integrity.result=NOT_PROVIDED' >> "$destination"
}

printf '%s\n' \
  'format=laminate-benchmark-run-v1' \
  'run.variant=noIntegrity' \
  'run.profile=quick' \
  "run.id=$run_id" > "$fixture/shared/run-binding.txt"

setup="$fixture/shared/setup-result.txt"
printf '%s\n' 'format=laminate-benchmark-setup-v1' > "$setup"
write_common "$setup" 0
printf '%s\n' \
  'benchmark.intent=fhe-payload-evaluation-without-integrity' \
  'timing.setup.started_unix_ms=1' \
  'timing.setup.key_generation.wall_ms=100' \
  'timing.setup.key_generation.cpu_ms=90' \
  'timing.setup.context_serialization.wall_ms=10' \
  'timing.setup.context_serialization.cpu_ms=9' \
  'timing.setup.process_total.wall_ms=120' \
  'timing.setup.process_total.cpu_ms=105' \
  'storage.server_preprocessing_bytes=1000' \
  'storage.client_preprocessing_bytes=800' \
  'storage.request_bytes_upper=9999' \
  'storage.response_bytes_upper=9999' \
  'storage.persistent_disk_reserve_bytes=2000000000' \
  'storage.host_observed_available_bytes=100000000000' \
  'storage.host_free_reserve_bytes=100000000000' \
  'memory.client.admitted_peak_resident_bytes=4000000000' \
  'memory.server.admitted_peak_resident_bytes=50000000000' \
  'memory.host_safety_reserve_bytes=16000000000' \
  'memory.host_operating_system_reserve_bytes=16000000000' \
  'memory.host_page_cache_reserve_bytes=64000000000' \
  'memory.payload_storage.transfer_buffer_reserve_bytes=402653184' \
  'memory.payload_storage.writeback_window_bytes=0' \
  'storage.payload_storage.ephemeral_writeback_policy=linux-submit-only-with-buffered-portable-fallback' \
  'storage.payload_storage.maximum_writeback_submission_bytes=16777216' \
  'memory.payload_storage.sequential_reader_count=2' \
  'memory.payload_storage.prefetch_window_bytes_each=268435456' \
  'memory.payload_storage.prefetch_page_cache_budget_bytes=536870912' \
  'storage.payload_storage.maximum_prefetch_request_bytes=16777216' \
  'planner.output_only_chunk_ciphertexts=64' \
  'planner.execution_mode=output-only-adjacent-layers' \
  'planner.payload_replay_work_units=0' \
  'planner.payload_checkpoint_count=0' \
  'planner.payload_checkpoint_bytes=0' \
  'storage.payload_output_only_plan.peak_live_scratch_bytes=5000000000' \
  'memory.payload_output_only_plan.peak_resident_bytes=6000000000' \
  'memory.payload_output_only_plan.dense_multiplication_alias_cache_peak_resident_bytes=10485760' \
  'storage.payload_output_only_plan.remaining_headroom_bytes=90000000000' \
  'environment.command=fixture setup' \
  'setup.result=PASS' >> "$setup"

truncate -s 1000 "$fixture/shared/transcript/cli-to-srv-request.bin"
truncate -s 2000 "$fixture/shared/transcript/srv-to-cli-response.bin"

server="$fixture/server/result.txt"
printf '%s\n' 'format=laminate-benchmark-server-v1' > "$server"
write_common "$server" 2
printf '%s\n' \
  'timing.server.started_unix_ms=2' \
  'timing.server.request_observed_unix_ms=3' \
  'timing.server.load_preprocessing_and_plan.wall_ms=25' \
  'timing.server.load_preprocessing_and_plan.cpu_ms=24' \
  'timing.server.wait_for_request.wall_ms=5' \
  'timing.server.wait_for_request.cpu_ms=0' \
  'timing.server.read_request.wall_ms=2' \
  'timing.server.read_request.cpu_ms=2' \
  'timing.server.decode_request.wall_ms=3' \
  'timing.server.decode_request.cpu_ms=3' \
  'timing.server.payload_evaluation.wall_ms=12345' \
  'timing.server.payload_evaluation.cpu_ms=12000' \
  'timing.server.payload_evaluation.relation_total.wall_ms=12000' \
  'timing.server.payload_evaluation.relation_total.cpu_ms=11700' \
  'timing.server.payload_evaluation.fhe.wall_ms=6000' \
  'timing.server.payload_evaluation.fhe.cpu_ms=6000' \
  'timing.server.payload_evaluation.modulus_switch.wall_ms=1000' \
  'timing.server.payload_evaluation.modulus_switch.cpu_ms=1000' \
  'timing.server.payload_evaluation.deserialization.wall_ms=500' \
  'timing.server.payload_evaluation.deserialization.cpu_ms=500' \
  'timing.server.payload_evaluation.serialization.wall_ms=400' \
  'timing.server.payload_evaluation.serialization.cpu_ms=400' \
  'timing.server.payload_evaluation.buffer_assembly.wall_ms=0' \
  'timing.server.payload_evaluation.buffer_assembly.cpu_ms=0' \
  'timing.server.payload_evaluation.hashing.wall_ms=1' \
  'timing.server.payload_evaluation.hashing.cpu_ms=1' \
  'timing.server.payload_evaluation.capacity_admission.wall_ms=1' \
  'timing.server.payload_evaluation.capacity_admission.cpu_ms=1' \
  'timing.server.payload_evaluation.output_submission.wall_ms=950' \
  'timing.server.payload_evaluation.output_submission.cpu_ms=850' \
  'timing.server.payload_evaluation.storage_write.wall_ms=900' \
  'timing.server.payload_evaluation.storage_write.cpu_ms=800' \
  'timing.server.payload_evaluation.writeback_submission.wall_ms=10' \
  'timing.server.payload_evaluation.writeback_submission.cpu_ms=10' \
  'timing.server.payload_evaluation.writeback_wait.wall_ms=0' \
  'timing.server.payload_evaluation.writeback_wait.cpu_ms=0' \
  'timing.server.payload_evaluation.prefetch.wall_ms=5' \
  'timing.server.payload_evaluation.prefetch.cpu_ms=5' \
  'timing.server.payload_evaluation.storage_read.wall_ms=800' \
  'timing.server.payload_evaluation.storage_read.cpu_ms=700' \
  'timing.server.payload_evaluation.drain_close_publication.wall_ms=200' \
  'timing.server.payload_evaluation.drain_close_publication.cpu_ms=100' \
  'timing.server.encode_response.wall_ms=1' \
  'timing.server.encode_response.cpu_ms=1' \
  'timing.server.publish_response.wall_ms=1' \
  'timing.server.publish_response.cpu_ms=1' \
  'timing.server.online_total.wall_ms=12377' \
  'timing.server.online_total.cpu_ms=12031' \
  'timing.server.process_total.wall_ms=12382' \
  'timing.server.process_total.cpu_ms=12031' \
  'wire.request_bytes=1000' \
  'wire.response_bytes=2000' \
  'storage.payload_peak_live_physical_bytes=10000000' \
  'storage.payload_total_reclaimed_physical_bytes=20000000' \
  'storage.payload_forward_encoded_bytes_read=1000000' \
  'storage.payload_forward_encoded_bytes_written=2000000' \
  'storage.payload_forward_physical_bytes_written=20000000' \
  'storage.payload_forward_physical_bytes_deleted=20000000' \
  'storage.payload_forward_application_write_bytes=20000000' \
  'storage.payload_forward_application_read_bytes=10000000' \
  'storage.payload_forward_write_batches=2' \
  'storage.payload_forward_write_syscalls=2' \
  'storage.payload_forward_maximum_write_batch_bytes=10000000' \
  'storage.payload_forward_writeback_files_enabled=1' \
  'storage.payload_forward_writeback_files_submit_only=1' \
  'storage.payload_forward_writeback_files_fallback=0' \
  'storage.payload_forward_writeback_submission_attempts=2' \
  'storage.payload_forward_writeback_submission_successes=2' \
  'storage.payload_forward_maximum_writeback_submission_bytes=16777216' \
  'storage.payload_forward_writeback_wait_attempts=0' \
  'storage.payload_forward_writeback_wait_successes=0' \
  'storage.payload_forward_writeback_range_bytes_submitted=20000000' \
  'storage.payload_forward_writeback_range_bytes_waited=0' \
  'storage.payload_forward_writeback_window_bytes=0' \
  'storage.payload_forward_maximum_unwaited_writeback_range_bytes=0' \
  'storage.payload_forward_writeback_drains=0' \
  'storage.payload_forward_writeback_drain_range_bytes=0' \
  'storage.payload_forward_writeback_drains_skipped=1' \
  'storage.payload_forward_writeback_range_bytes_without_explicit_wait=20000000' \
  'storage.payload_forward_positional_write_calls=1' \
  'storage.payload_forward_positional_write_bytes=8' \
  'storage.payload_forward_read_batches=1' \
  'storage.payload_forward_read_syscalls=1' \
  'storage.payload_forward_maximum_read_batch_bytes=10000000' \
  'storage.payload_forward_prefetch_requests=40' \
  'storage.payload_forward_prefetch_bytes_requested=10000000' \
  'storage.payload_forward_prefetch_fallbacks=0' \
  'storage.payload_forward_prefetch_seek_disables=0' \
  'storage.payload_forward_prefetch_window_bytes=268435456' \
  'storage.payload_forward_maximum_prefetch_request_bytes=8388608' \
  'storage.payload_forward_capacity_probes=3' \
  'storage.payload_artifact_integrity=same-process-inode-bound-nonreopenable' \
  'storage.payload_forward_authenticated_record_bytes=0' \
  'storage.payload_forward_same_process_unhashed_record_bytes=19000000' \
  'storage.payload_forward_record_copy_bytes=0' \
  'storage.payload_forward_identity_affine_alias_relations=6' \
  'storage.payload_forward_identity_affine_alias_fallbacks=0' \
  'storage.payload_forward_identity_affine_alias_records_reused=932400' \
  'storage.payload_forward_identity_affine_alias_layer_bytes_reused=104857600' \
  'storage.payload_forward_identity_affine_alias_unique_bytes_written=4096' \
  'storage.payload_forward_alias_cached_dense_multiplication_relations=1' \
  'storage.payload_forward_alias_cache_range_readers=1' \
  'storage.payload_forward_alias_cache_distinct_source_records=12' \
  'storage.payload_forward_alias_cache_logical_source_uses=1000' \
  'storage.payload_forward_alias_cache_generic_source_records=900' \
  'memory.payload_peak_controlled_resident_bytes=30000000' \
  'memory.server.peak_rss_bytes=40000000' \
  'environment.command=fixture server' \
  'server.result=PASS' >> "$server"
for operation in add mul_no_relin relinearize add_plain mul_plain_scalar \
  mul_plain_vector mod_switch rotate encrypt decrypt negate sub \
  logical_ext_add logical_ext_sub logical_ext_mul logical_ext_mul_plain; do
  calls=1
  [[ "$operation" == rotate || "$operation" == encrypt ]] && calls=0
  printf 'operations.server_payload_evaluation.%s.calls=%s\n' \
    "$operation" "$calls" >> "$server"
  printf 'operations.server_payload_evaluation.%s.limb_operations=%s\n' \
    "$operation" "$calls" >> "$server"
done

client="$fixture/client/result.txt"
printf '%s\n' 'format=laminate-benchmark-client-v2' > "$client"
write_common "$client" 1
printf '%s\n' \
  'timing.client.started_unix_ms=2' \
  'timing.client.request_published_unix_ms=3' \
  'timing.client.load_preprocessing.wall_ms=5' \
  'timing.client.load_preprocessing.cpu_ms=5' \
  'timing.client.encrypt_inputs.wall_ms=100' \
  'timing.client.encrypt_inputs.cpu_ms=99' \
  'timing.client.encode_request.wall_ms=5' \
  'timing.client.encode_request.cpu_ms=5' \
  'timing.client.publish_request.wall_ms=1' \
  'timing.client.publish_request.cpu_ms=1' \
  'timing.client.wait_for_response.wall_ms=12000' \
  'timing.client.wait_for_response.cpu_ms=1' \
  'timing.client.read_response.wall_ms=1' \
  'timing.client.read_response.cpu_ms=1' \
  'timing.client.decode_response.wall_ms=2' \
  'timing.client.decode_response.cpu_ms=2' \
  'timing.client.full_decrypt_output.wall_ms=3' \
  'timing.client.full_decrypt_output.cpu_ms=3' \
  'timing.client.per_request_total.wall_ms=117' \
  'timing.client.per_request_total.cpu_ms=116' \
  'timing.client.process_total.wall_ms=12117' \
  'timing.client.process_total.cpu_ms=117' \
  'wire.request_bytes=1000' \
  'wire.response_bytes=2000' \
  'output.rns_limbs=1' \
  'output.invariant_noise_budget_bits=35' \
  'output.decrypted_slots_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  'memory.client.peak_rss_bytes=30000000' \
  'verification.scope=response-binding-decode-and-full-decryption-only' \
  'environment.command=fixture client' \
  'verification.result=PASS' >> "$client"

for exit_record in \
  "$fixture/shared/setup-process-exit.txt" \
  "$fixture/server/process-exit.txt" \
  "$fixture/client/process-exit.txt"; do
  printf '%s\n' 'process.exit_status=0' > "$exit_record"
done

output="$fixture/shared/report/summary.md"
python3 "$renderer" --run-dir "$fixture" --variant noIntegrity \
  --profile quick --output "$output"
for expected in \
  '<!-- laminate-no-integrity-summary-v1 -->' \
  '**No integrity is provided.**' \
  'ordinary 54-bit payload prime; not native Fq' \
  '**12.345 s wall**' \
  'Client full output decryption' \
  'Trace maintenance (derived)' \
  '| Trace maintenance (derived) | 2.617 s | 2.417 s | 92.4% |' \
  'Record output submission (inclusive parent; excluded from derived sum)' \
  'Application bytes submitted to write calls' \
  'Writeback-enabled / submit-only / fallback files' \
  'Writeback submission attempts / successes' \
  'Foreground wait attempts / successes' \
  'Largest successful writeback range hint' \
  'Configured writeback range-hint ceiling' \
  'successful range-hint bytes without explicit wait' \
  '16.00 MiB' \
  'Foreground drains / deliberately skipped drains' \
  'Prefetch requests / fallbacks / seek disables' \
  '256.00 MiB / 8.00 MiB' \
  'BDI read-ahead geometry' \
  'linux-submit-only-with-buffered-portable-fallback' \
  'no explicit foreground wait or layer-end drain' \
  'same-process-inode-bound-nonreopenable' \
  'Identity-affine alias relations / capability fallbacks' \
  '| Identity-affine alias relations / capability fallbacks | 6 / 0 |' \
  '| Identity-affine records reused | 932,400 |' \
  '| Existing identity-affine layer bytes reused | 100.00 MiB |' \
  '| Unique identity-affine alias bytes written | 4.00 KiB |' \
  'reused layer bytes are existing file lengths' \
  'Setup-selected dense multiplication alias-cache peak' \
  '10.00 MiB relation-scoped resident bound' \
  '| Cached dense multiplication relations | 1 |' \
  '| Alias-cache range readers | 1 |' \
  '| Distinct source records read | 12 |' \
  '| Logical source uses | 1,000 |' \
  '| Generic-path source records without cache | 900 |' \
  '| Net source-record reads avoided | 888 |' \
  'admitted against the setup-selected global resident cap' \
  'Output-only plan' \
  'Remaining admitted output-only disk headroom' \
  'not an expected-output comparison'; do
  grep -Fq -- "$expected" "$output" || {
    printf 'noIntegrity summary omitted: %s\n' "$expected" >&2
    exit 1
  }
done

concise_output="$fixture/concise-summary.md"
python3 "$concise_renderer" \
  --input "$output" --output "$concise_output" \
  --run-dir "$fixture" \
  --variant noIntegrity --profile quick
for expected in \
  '<!-- laminate-benchmark-summary-v2 -->' \
  '| Laminate variant | noIntegrity |' \
  '| Payload profile | `quick` |' \
  '| Scalar gates | 218,087,424 (13,311 payload gates × 16,384 slots) |' \
  '| Initial ciphertext modulus (data primes only) | 271 bits |' \
  '| Plaintext modulus | 65,537 |' \
  '| Payload-only server wall time | 12.377 s |' \
  '| Proof verification | not applicable (no proof) |' \
  '| Client full output decryption | 0.003 s |' \
  '## Server FHE operation ledger' \
  '## Protocol artifacts' \
  '## Memory and storage' \
  '## Provenance'; do
  grep -Fq -- "$expected" "$concise_output" || {
    printf 'concise noIntegrity summary omitted: %s\n' "$expected" >&2
    exit 1
  }
done
for forbidden in \
  'GCP VM and storage' \
  'Payload storage pipeline' \
  'Identity affine storage aliases' \
  'Git commit' \
  "| Build | \`$commit\`" \
  'Client process total' \
  'Process exits' \
  'FHE backend' \
  'Exact data-prime schedule' \
  'q0=18014336227311617' \
  'Setup wall time' \
  'Run ID' \
  'Exact role commands' \
  'summary.csv'; do
  if grep -Fq -- "$forbidden" "$concise_output"; then
    printf 'concise noIntegrity summary retained: %s\n' "$forbidden" >&2
    exit 1
  fi
done
for report in "$output" "$concise_output"; do
  if grep -Fq 'OLD / STALE REPORT' "$report"; then
    printf '%s\n' 'current quick baseline incorrectly marked stale' >&2
    exit 1
  fi
done

test ! -e "$fixture/shared/report/summary.csv"

concise_without_context="$fixture/concise-without-context.md"
python3 "$concise_renderer" \
  --input "$output" --output "$concise_without_context"
grep -Fq '| Plaintext modulus | 65,537 |' "$concise_without_context"
for forbidden in \
  'Process exits' \
  'FHE backend' \
  'Exact data-prime schedule' \
  'Setup wall time' \
  'Run ID' \
  'Exact role commands'; do
  if grep -Fq -- "$forbidden" "$concise_without_context"; then
    printf 'noIntegrity summary retained: %s\n' "$forbidden" >&2
    exit 1
  fi
done

sed -i.bak \
  's/output.invariant_noise_budget_bits=35/output.invariant_noise_budget_bits=0/' \
  "$client"
if python3 "$renderer" --run-dir "$fixture" --variant noIntegrity \
  --profile quick --output "$output" > "$fixture/noise-error.txt" 2>&1; then
  printf '%s\n' 'renderer accepted an exhausted output noise budget' >&2
  exit 1
fi
grep -Fqx 'error: noIntegrity output has exhausted its noise budget' \
  "$fixture/noise-error.txt"
mv "$client.bak" "$client"

sed -i.bak \
  's/output.invariant_noise_budget_bits=35/output.invariant_noise_budget_bits=1/' \
  "$client"
python3 "$renderer" --run-dir "$fixture" --variant noIntegrity \
  --profile quick --output "$output"
mv "$client.bak" "$client"

sed -i.bak \
  's/operations.server_payload_evaluation.rotate.calls=0/operations.server_payload_evaluation.rotate.calls=1/' \
  "$server"
if python3 "$renderer" --run-dir "$fixture" --variant noIntegrity \
  --profile quick --output "$output" 2>/dev/null; then
  printf '%s\n' 'renderer accepted a server rotation' >&2
  exit 1
fi
mv "$server.bak" "$server"

sed -i.bak \
  's/timing.server.payload_evaluation.relation_total.wall_ms=12000/timing.server.payload_evaluation.relation_total.wall_ms=9000/' \
  "$server"
if python3 "$renderer" --run-dir "$fixture" --variant noIntegrity \
  --profile quick --output "$output" 2>/dev/null; then
  printf '%s\n' 'renderer accepted leaf timings above the phase total' >&2
  exit 1
fi
mv "$server.bak" "$server"

sed -i.bak \
  's/storage.payload_forward_maximum_prefetch_request_bytes=8388608/storage.payload_forward_maximum_prefetch_request_bytes=10000001/' \
  "$server"
if python3 "$renderer" --run-dir "$fixture" --variant noIntegrity \
  --profile quick --output "$output" 2>/dev/null; then
  printf '%s\n' 'renderer accepted an inconsistent payload storage ledger' >&2
  exit 1
fi
mv "$server.bak" "$server"

sed -i.bak \
  's/storage.payload_forward_alias_cache_generic_source_records=900/storage.payload_forward_alias_cache_generic_source_records=47/' \
  "$server"
if python3 "$renderer" --run-dir "$fixture" --variant noIntegrity \
  --profile quick --output "$output" 2>/dev/null; then
  printf '%s\n' 'renderer accepted an inconsistent payload alias-cache ledger' >&2
  exit 1
fi
mv "$server.bak" "$server"

sed -i.bak \
  's/memory.payload_output_only_plan.dense_multiplication_alias_cache_peak_resident_bytes=10485760/memory.payload_output_only_plan.dense_multiplication_alias_cache_peak_resident_bytes=6000000001/' \
  "$setup"
if python3 "$renderer" --run-dir "$fixture" --variant noIntegrity \
  --profile quick --output "$output" 2>/dev/null; then
  printf '%s\n' 'renderer accepted an alias cache above the output-only resident peak' >&2
  exit 1
fi
mv "$setup.bak" "$setup"

for record in "$setup" "$server" "$client"; do
  sed -i.bak 's/18014336227311617/1053858393162252289/g' "$record"
done
if python3 "$renderer" --run-dir "$fixture" --variant noIntegrity \
  --profile quick --output "$output" 2>/dev/null; then
  printf '%s\n' 'renderer accepted the native Fq proof prime' >&2
  exit 1
fi
for record in "$setup" "$server" "$client"; do
  mv "$record.bak" "$record"
done

python3 - "$renderer" "$fixture" <<'PY'
from pathlib import Path
import math
import shutil
import sys

sys.path.insert(0, str(Path(sys.argv[1]).resolve().parent))
import render_no_integrity_summary as renderer
import render_concise_summary as concise
from render_payload_profiles import PROFILE_GEOMETRY

source = Path(sys.argv[2])

def write_record(path, values):
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))

for catalog in (PROFILE_GEOMETRY,):
    for profile, geometry in catalog.items():
        if profile == "quick":
            continue
        run = source / (profile + "-" + str(geometry["workload"]))
        for role in ("shared", "server", "client"):
            shutil.copytree(source / role, run / role)
        binding_path = run / "shared/run-binding.txt"
        binding = renderer.parse_record(binding_path)
        binding["run.profile"] = profile
        write_record(binding_path, binding)
        paths = (run / "shared/setup-result.txt", run / "server/result.txt",
                 run / "client/result.txt")
        primes, special_prime = renderer.PAYLOAD_MODULI_BY_PROFILE[profile]
        data_product = math.prod(primes)
        for path in paths:
            record = renderer.parse_record(path)
            record.update({
                "run.profile": profile,
                "parameters.payload_workload": geometry["workload"],
                "parameters.payload_multiplicative_depth": 8,
                "parameters.payload_width": geometry["width"],
                "parameters.payload_operations": geometry["operations"],
                "parameters.fresh_rns_limbs": 9,
                "parameters.fresh_modulus_product_bits": data_product.bit_length(),
                "parameters.key_modulus_product_bits": (data_product * special_prime).bit_length(),
                "parameters.output_modulus": primes[0],
                "parameters.output_modulus_bits": primes[0].bit_length(),
                "parameters.special_prime": special_prime,
                "parameters.security": renderer.PAYLOAD_SECURITY_BY_PROFILE[profile],
                "parameters.data_primes_bottom_to_top": ",".join(str(prime) for prime in primes),
                "parameters.galois_keys": "generated" if geometry["rotate"]
                    else "omitted-no-rotation-gates",
            })
            for kind in ("add", "add_plain", "mul", "mul_plain", "rotate"):
                record[f"parameters.payload_{kind}_gates"] = geometry[kind]
            if path == paths[1]:
                record["operations.server_payload_evaluation.rotate.calls"] = geometry["rotate"]
            write_record(path, record)
        for phase in ("setup", "server"):
            write_record(run / f"shared/storage-provenance.{phase}-start.txt", {
                "format": "laminate-storage-provenance-v2",
                "storage.capture_phase": f"{phase}-start",
                "storage.backend": "fixture",
                "storage.artifact_root": str(run),
                "storage.mount_source": "/dev/fixture",
                "storage.mount_target": str(run),
                "storage.filesystem_type": "fixture",
                "storage.filesystem_total_bytes": 9_000_000_000_000,
            })
        rendered = renderer.render(run, profile)
        concise_rendered = concise.render(rendered, None)
        assert ("10,000-GB Hyperdisk Balanced; 2,400 MiB/s throughput; "
                "150,000 IOPS (current campaign reference configuration)"
                in concise_rendered)
        # Measurement observations are independent of the campaign reference.
        stored = renderer.parse_record(run / "shared/storage-provenance.setup-start.txt")
        assert stored["storage.filesystem_total_bytes"] == "9000000000000"
        assert f"`{geometry['workload']}`" in rendered
        assert f"Rotate {geometry['rotate']:,}" in rendered
        client_record = renderer.parse_record(paths[2])
        exhausted_client = dict(client_record)
        exhausted_client["output.invariant_noise_budget_bits"] = 0
        write_record(paths[2], exhausted_client)
        try:
            renderer.render(run, profile)
        except renderer.ReportError as error:
            assert str(error) == "noIntegrity output has exhausted its noise budget", error
        else:
            raise AssertionError("accepted a target output with exhausted noise budget")
        write_record(paths[2], client_record)
        assert renderer.render(run, profile) == rendered

        saved_records = [renderer.parse_record(path) for path in paths]
        for key in ("parameters.data_primes_bottom_to_top", "parameters.special_prime"):
            for path, saved in zip(paths, saved_records):
                changed = dict(saved)
                if key.endswith("bottom_to_top"):
                    values = changed[key].split(",")
                    values[-1] = str(int(values[-1]) + 2)
                    changed[key] = ",".join(values)
                else:
                    changed[key] = int(changed[key]) + 2
                write_record(path, changed)
            try:
                renderer.render(run, profile)
            except renderer.ReportError as error:
                assert "differs from the payload-only chain" in str(error) or \
                    "differ from the payload-only chain" in str(error), error
            else:
                raise AssertionError("accepted drift in a target's exact modulus chain")
            for path, saved in zip(paths, saved_records):
                write_record(path, saved)
        assert renderer.render(run, profile) == rendered
        if geometry["rotate"]:
            record = renderer.parse_record(paths[1])
            record["operations.server_payload_evaluation.rotate.calls"] = 0
            write_record(paths[1], record)
            try:
                renderer.render(run, profile)
            except renderer.ReportError:
                pass
            else:
                raise AssertionError("accepted missing cross-slot payload execution")
            record["operations.server_payload_evaluation.rotate.calls"] = geometry["rotate"]
            write_record(paths[1], record)
            for path in paths:
                record = renderer.parse_record(path)
                del record["parameters.payload_rotate_gates"]
                write_record(path, record)
            try:
                renderer.render(run, profile)
            except renderer.ReportError:
                pass
            else:
                raise AssertionError("accepted a revised workload without its rotation ledger")
PY

printf '%s\n' 'noIntegrity summary renderer: PASS'
