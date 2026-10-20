#!/usr/bin/env bash

set -euo pipefail

[[ $# -eq 1 ]] || exit 2
runner="$1"
scratch="$(mktemp -d)"
scratch="$(cd -P -- "$scratch" && pwd)"
trap 'rm -rf -- "$scratch"' EXIT
source_run="$scratch/source run"
mkdir -p "$source_run"
printf 'original preprocessing\n' > "$source_run/sentinel"
ln -s "$source_run" "$scratch/source-link"

# Exercise the real public parser without host-specific Linux preflight.
parser="$(sed '/^setup_cpu=/,$d' "$runner")"
for profile in quick target-balancedLaned target-mulHeavyPyramid; do
  (
    set -- recover_setup base "$profile" new --source-run-dir "$source_run"
    eval "$parser"
    [[ "$action" == setup && "$requested_action" == recover_setup &&
       "$recovery_source_run" == "$source_run" && "$run_selector" == new ]]
  )
done

expect_rejected() {
  local output status=0
  output="$("$runner" "$@" 2>&1)" || status=$?
  if [[ "$status" -ne 2 || "$output" != *'ERROR:'* ]]; then
    printf 'expected recovery usage rejection, got %s: %s\n%s\n' \
      "$status" "$*" "$output" >&2
    exit 1
  fi
}
for variant in local folded laned noIntegrity; do
  expect_rejected recover_setup "$variant" quick new --source-run-dir "$source_run"
done
for destination in current "$source_run" "$scratch/nonexistent-destination"; do
  expect_rejected recover_setup base quick "$destination" --source-run-dir "$source_run"
done
for invalid_source in relative / "$scratch/missing" "$source_run/sentinel" \
                      "$scratch/source-link" "$source_run/../source run" \
                      "$source_run/" $'/tmp/source\nrun'; do
  expect_rejected recover_setup base quick new --source-run-dir "$invalid_source"
done
expect_rejected recover_setup base quick new
expect_rejected recover_setup base quick new --recover-from "$source_run"
expect_rejected recover_setup base quick new --source-run-dir "$source_run" extra
expect_rejected recover_setup base unsupported new --source-run-dir "$source_run"
expect_rejected setup base quick new --source-run-dir "$source_run"
expect_rejected start_setup base quick new --source-run-dir "$source_run"

# Capture the real command construction; paths with spaces must remain one
# argument, and recovery must never reach a client or server command.
(
  eval "$(sed -n '/^role_cpu() {/,/^}/p' "$runner")"
  command_prefix="$(sed -n '/^run_benchmark_role() {/,/  local role_status=0/p' "$runner")"
  command_prefix="${command_prefix%  local role_status=0}"
  eval "$command_prefix"'printf "%s\n" "${role_command[@]}"; }'
  variant=base profile=target-balancedLaned benchmark='/fixture/benchmark'
  run_directory='/fixture/new run' recovery_source_run="$source_run"
  setup_threads=3 setup_cpu_list='0,1,4' server_cpu=0 client_cpu=1
  command_text="$(run_benchmark_role setup)"
  expected_tail="$(printf '%s\n' "$benchmark" setup --variant base --profile "$profile" \
    --run-dir "$run_directory" --recover-from "$source_run")"
  [[ "$command_text" == *"$expected_tail" &&
     "$command_text" == *$'LAMINATE_SETUP_THREADS=3\n'* ]]
  for role in run_client run_server; do
    command_text="$(run_benchmark_role "$role")"
    [[ "$command_text" != *--recover-from* && "$command_text" != *"$source_run"* ]]
  done
  recovery_source_run=''
  command_text="$(run_benchmark_role setup)"
  [[ "$command_text" != *--recover-from* ]]
)

# Execute the actual setup dispatch with a tiny benchmark fixture. Replace
# host/storage operations only; preserve activity checks, exit publication,
# source argument selection and current-pointer publication. A failed recovery
# or active current/source run must preserve the previous current pointer.
for scenario in pass failure active-current active-source; do
  fixture="$scratch/$scenario"
  mkdir -p "$fixture/runs/previous/shared"
  printf '%s\n' "$fixture/runs/previous" > "$fixture/current"
  status=0
  FIXTURE="$fixture" SOURCE_RUN="$source_run" SCENARIO="$scenario" \
    bash -s -- "$runner" > "$fixture/output" 2>&1 <<'SH' || status=$?
set -euo pipefail
runner="$1"
set -- recover_setup base quick new --source-run-dir "$SOURCE_RUN"
eval "$(sed '/^setup_cpu=/,$d' "$runner")"
artifact_root="$FIXTURE"
current_pointer="$FIXTURE/current"
run_directory="$FIXTURE/runs/recovered"
record_current_run=true
observer_cpu=2 follow_seconds=1
for function_name in require_current_run_inactive require_recovery_source_inactive \
                     publish_process_exit record_current_pointer; do
  function_pattern="$(printf '/^%s() {/,/^}/p' "$function_name")"
  eval "$(sed -n "$function_pattern" "$runner")"
done
activity_is_active() {
  case "$SCENARIO:$1" in
    "active-current:$FIXTURE/runs/previous/shared/setup-activity.jsonl"|\
    "active-source:$SOURCE_RUN/server/activity.jsonl") return 0 ;;
  esac
  return 1
}
capture_target_setup_storage() { : > "$FIXTURE/storage-captured"; }
publish_target_setup_storage() { : > "$run_directory/shared/storage-provenance.setup-start.txt"; }
discard_target_setup_storage() { :; }
setup_heartbeat_loop() { :; }
stop_setup_heartbeat() { wait "$setup_heartbeat_pid"; }
release_benchmark_wrapper_locks() {
  [[ -f "$run_directory/shared/setup-process-exit.txt" ]] || return 1
  : > "$FIXTURE/locks-released"
}
run_benchmark_role() {
  [[ "$1" == setup && "$recovery_source_run" == "$SOURCE_RUN" ]] || return 1
  benchmark_role_launched=true
  mkdir -p "$run_directory/shared"
  if [[ "$SCENARIO" == failure ]]; then
    return 23
  fi
  printf 'setup.result=PASS\nsetup.mode=recovered-preprocessing\n' \
    > "$run_directory/shared/setup-result.txt"
}
setup_dispatch="$(sed -n '/^  setup)$/,/^    ;;$/p' "$runner")"
eval 'case "$action" in' "$setup_dispatch" 'esac'
SH
  expected_status=1
  [[ "$scenario" != pass ]] || expected_status=0
  [[ "$scenario" != failure ]] || expected_status=23
  if [[ "$status" -ne "$expected_status" ]]; then
    printf 'recovery %s fixture returned %s, expected %s:\n' \
      "$scenario" "$status" "$expected_status" >&2
    cat "$fixture/output" >&2
    exit 1
  fi
  if [[ "$scenario" == pass ]]; then
    [[ "$status" -eq 0 && "$(<"$fixture/current")" == "$fixture/runs/recovered" &&
       -f "$fixture/locks-released" &&
       -f "$fixture/runs/recovered/shared/storage-provenance.setup-start.txt" ]] || exit 1
    grep -Fxq 'process.exit_status=0' "$fixture/runs/recovered/shared/setup-process-exit.txt"
  elif [[ "$scenario" == failure ]]; then
    [[ "$status" -eq 23 && "$(<"$fixture/current")" == "$fixture/runs/previous" &&
       -f "$fixture/locks-released" ]] || exit 1
    grep -Fxq 'process.exit_status=23' "$fixture/runs/recovered/shared/setup-process-exit.txt"
  else
    [[ "$status" -eq 1 && "$(<"$fixture/current")" == "$fixture/runs/previous" &&
       ! -e "$fixture/runs/recovered" && ! -e "$fixture/storage-captured" ]] || exit 1
    grep -Fq 'active' "$fixture/output"
  fi
  [[ "$(ls -A "$source_run")" == sentinel &&
     "$(<"$source_run/sentinel")" == 'original preprocessing' ]]
done
