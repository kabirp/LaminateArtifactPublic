#!/usr/bin/env bash

set -euo pipefail
umask 077

if [[ $# -ne 1 ]]; then
  printf 'usage: %s NO_INTEGRITY_BENCHMARK\n' "$0" >&2
  exit 2
fi

benchmark="$1"
fixture="$(mktemp -d)"
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/shared/transcript" "$fixture/client" "$fixture/server"
touch "$fixture/shared/lifecycle.lock"
chmod 600 "$fixture/shared/lifecycle.lock"
printf '%s\n' 'setup.result=PASS' > "$fixture/shared/setup-result.txt"
printf '%s\n' 'server.result=PASS' > "$fixture/server/result.txt"
printf '%s\n' 'verification.result=PASS' > "$fixture/client/result.txt"
for exit_record in \
  "$fixture/shared/setup-process-exit.txt" \
  "$fixture/server/process-exit.txt" \
  "$fixture/client/process-exit.txt"; do
  printf '%s\n' 'process.exit_status=0' > "$exit_record"
done
touch "$fixture/shared/transcript/cli-to-srv-request.bin"
touch "$fixture/shared/transcript/srv-to-cli-response.bin"
printf '%s\n' \
  '{"schema":"laminate-protocol-progress-v1","seq":1,"event":"progress","stage":"payload.forward_relation.source_4.output_3","run_elapsed_ms":12000.000,"completed_steps":12,"total_steps":16,"phase_wall_ms":10000,"phase_cpu_ms":7000,"fhe_wall_ms":5000,"modulus_switch_wall_ms":500,"serialization_wall_ms":200,"buffer_assembly_wall_ms":100,"hashing_wall_ms":50,"storage_read_wall_ms":2000,"storage_write_wall_ms":1000,"prefetch_wall_ms":100,"writeback_submission_wall_ms":100,"writeback_wait_wall_ms":0,"read_syscalls":8,"application_read_bytes":1073741824,"write_syscalls":4,"application_write_bytes":536870912,"prefetch_requests":2,"prefetch_bytes_requested":2147483648,"prefetch_fallbacks":0,"prefetch_seek_disables":0,"writeback_submission_attempts":4,"writeback_submission_successes":4,"writeback_wait_attempts":0,"writeback_wait_successes":0,"writeback_range_bytes_submitted":536870912,"writeback_range_bytes_waited":0,"writeback_files_submit_only":1,"writeback_drains":0,"writeback_drains_skipped":0}' \
  > "$fixture/server/progress.jsonl"

output="$($benchmark status --variant noIntegrity --profile quick \
  --run-dir "$fixture")"
for expected in \
  'Laminate noIntegrity quick status' \
  'integrity: NOT PROVIDED' \
  'client decode and full decryption: PASS' \
  'live phase snapshot: 10.0s wall, 70.0% CPU/wall' \
  'timed read/write/prefetch/writeback-submit/wait 2.0/1.0/0.1/0.1/0.0s' \
  'read/write 1.0/0.5 GiB in 8/4 syscalls' \
  'prefetch 2.0 GiB in 2 requests (fallbacks/seek-disables 0/0)' \
  'writeback hinted/waited range 0.5/0.0 GiB in 4/4 successful/attempted submits, 0/0 successful/attempted waits (submit-only files/drains/skipped 1/0/0)' \
  'COMPLETE: output ciphertext was fully decrypted.' \
  'This run makes no integrity claim.'; do
  [[ "$output" == *"$expected"* ]] || {
    printf 'noIntegrity status omitted %s:\n%s\n' "$expected" "$output" >&2
    exit 1
  }
done

printf '%s\n' \
  '{"schema":"laminate-protocol-progress-v1","seq":2,"event":"end","stage":"payload.forward_relation.source_3.output_2","run_elapsed_ms":13000.000,"completed_steps":16,"total_steps":16,"phase_wall_ms":1,"phase_cpu_ms":1,"application_write_bytes":4096,"identity_affine_alias_relations":1,"identity_affine_alias_records_reused":16,"identity_affine_alias_layer_bytes_reused":1073741824,"identity_affine_alias_unique_bytes_written":4096}' \
  >> "$fixture/server/progress.jsonl"
alias_output="$($benchmark status --variant noIntegrity --profile quick \
  --run-dir "$fixture")"
[[ "$alias_output" == *'identity-affine alias relations/fallbacks 1/0; records reused 16; existing layer bytes reused 1073741824; unique manifest bytes written 4096'* ]] || {
  printf 'noIntegrity status omitted identity-alias success:\n%s\n' \
    "$alias_output" >&2
  exit 1
}

printf '%s\n' \
  '{"schema":"laminate-protocol-progress-v1","seq":3,"event":"end","stage":"payload.forward_relation.source_2.output_1","run_elapsed_ms":14000.000,"completed_steps":16,"total_steps":16,"phase_wall_ms":1,"phase_cpu_ms":1,"identity_affine_alias_fallbacks":1}' \
  >> "$fixture/server/progress.jsonl"
fallback_output="$($benchmark status --variant noIntegrity --profile quick \
  --run-dir "$fixture")"
[[ "$fallback_output" == *'identity-affine alias relations/fallbacks 0/1; records reused 0; existing layer bytes reused 0; unique manifest bytes written 0'* ]] || {
  printf 'noIntegrity status omitted identity-alias fallback:\n%s\n' \
    "$fallback_output" >&2
  exit 1
}

printf '%s\n' 'noIntegrity live status: PASS'
