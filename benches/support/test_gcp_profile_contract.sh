#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  printf 'usage: %s RUN_GCP GCP_RUNBOOK\n' "$0" >&2
  exit 2
fi

runner="$1"
if [[ $# -eq 2 ]]; then
  runbook="$2"
else
  runner_directory="$(cd -- "$(dirname -- "$runner")" && pwd)"
  runbook="$runner_directory/../docs/GCP_BENCHMARKS.md"
fi
concise_renderer="$(cd -- "$(dirname -- "$runner")" && pwd)/support/render_concise_summary.py"
bash "$(dirname -- "$runner")/support/test_gcp_setup_recovery.sh" "$runner"
python3 "$(dirname -- "$runner")/support/test_gcp_summary_concurrency.py" "$runner" "$BASH"

# Exercise CPU selection without depending on this test host's topology.
(
  source "$(dirname -- "$runner")/support/setup_parallelism.sh"
  read_physical_core_key() {
    local fixture_core="0:$1"
    if [[ "$1" == 2 || "$1" == 3 ]]; then fixture_core='0:2'; fi
    printf -v "$2" '%s' "$fixture_core"
  }
  expect_selection() {
    local expected_threads="$1" expected_cpus="$2"
    shift 2
    select_setup_parallelism "$@"
    [[ "$setup_threads" == "$expected_threads" &&
       "$setup_cpu_list" == "$expected_cpus" ]] || {
      printf 'unexpected setup allocation: %s workers on %s\n' \
        "$setup_threads" "$setup_cpu_list" >&2
      exit 1
    }
  }
  expect_selection 6 '0,1,4,5,6,7' '0-7' '0:2' 0 auto
  expect_selection 3 '0,1,4' '0-7' '0:2' 0 3
  expect_selection 1 '4' '0-7' '0:2' 4 1
  expect_selection 2 '4,7' '4,7' '0:2' 4 auto
  select_setup_parallelism '0-299' '0:999' 0 auto
  [[ "$setup_threads" == 256 ]] || exit 1
  for invalid in 0 257 2x 01; do
    if select_setup_parallelism '0-7' '0:2' 0 "$invalid" 2>/dev/null; then
      printf 'accepted invalid setup worker count: %s\n' "$invalid" >&2
      exit 1
    fi
  done
  for invalid in '' '0,,1' '2-1' '1,0' '0-2,2-3' '0,' '00'; do
    if select_setup_parallelism "$invalid" '0:2' 0 auto 2>/dev/null; then
      printf 'accepted invalid setup CPU mask: %s\n' "$invalid" >&2
      exit 1
    fi
  done
  for selection in '2-3|auto|0' '4|2|4' '4|1|0' '2-4|1|2'; do
    IFS='|' read -r mask workers serial_cpu <<< "$selection"
    if select_setup_parallelism "$mask" '0:2' "$serial_cpu" "$workers" 2>/dev/null; then
      printf 'accepted unavailable setup CPUs: %s\n' "$selection" >&2
      exit 1
    fi
  done
)

# Run the actual launcher's command construction with a harmless capture sink.
# Stop before locks, filesystem writes, or execution of the benchmark binary.
(
  eval "$(sed -n '/^role_cpu() {/,/^}/p' "$runner")"
  command_prefix="$(sed -n '/^run_benchmark_role() {/,/  local role_status=0/p' "$runner")"
  command_prefix="${command_prefix%  local role_status=0}"
  eval "$command_prefix"'printf "%s\n" "${role_command[@]}"; }'
  server_cpu=0 client_cpu=1
  benchmark='/fixture/benchmark' profile=quick run_directory='/fixture/run' lanes=128
  export LAMINATE_SETUP_THREADS=99
  for variant in base folded laned local noIntegrity; do
    setup_threads=1 setup_cpu_list=0
    if [[ "$variant" == base || "$variant" == folded ]]; then
      setup_threads=3 setup_cpu_list='0,1,4'
    fi
    for action in setup run_server run_client; do
      command_text="$(run_benchmark_role "$action")"
      [[ "$command_text" == *$'env\n-u\nLAMINATE_SETUP_THREADS\n'* &&
         "$command_text" == *$'OMP_NUM_THREADS=1\n'* ]] || exit 1
      if [[ "$action" == setup && ("$variant" == base || "$variant" == folded) ]]; then
        [[ "$command_text" == *$'LAMINATE_SETUP_THREADS=3\n'* &&
           "$command_text" == *$'taskset\n-c\n0,1,4\n'* ]] || exit 1
      else
        [[ "$command_text" != *'LAMINATE_SETUP_THREADS='* ]] || exit 1
        if [[ "$action" == setup ]]; then
          [[ "$command_text" == *$'taskset\n-c\n0\n'* ]] || exit 1
        fi
      fi
      if [[ "$action" == run_server ]]; then
        [[ "$command_text" == *$'taskset\n-c\n0\n'* ]] || exit 1
      elif [[ "$action" == run_client ]]; then
        [[ "$command_text" == *$'taskset\n-c\n1\n'* ]] || exit 1
      fi
    done
  done
)

# Construct the detached wrapper command too. Its taskset must restore the
# approved setup mask after tmux inherits the launcher's observer affinity.
(
  detached_setup="$(sed -n '/^start_detached_setup() {/,/^}/p' "$runner")"
  detached_printf="$(sed -n '/^  printf -v command /,/^    "$observer_cpu"/p' <<< "$detached_setup")"
  [[ -n "$detached_printf" ]] || exit 1
  setup_cpu_list='0,1,4' observer_cpu=2 setup_cpu=0 setup_threads=3
  server_cpu=0 client_cpu=1 build_directory='/fixture/build' build_jobs=8
  artifact_root='/fixture/runs' storage_mount='/fixture/storage'
  archive_root='/fixture/archive' follow_seconds=5
  quoted_wrapper='/fixture/runner setup folded quick /fixture/run '
  console='/fixture/console.log'
  eval "$detached_printf"
  expected_prefix="$(printf 'exec taskset -c %q env ' "$setup_cpu_list,$observer_cpu")"
  [[ "$command" == "$expected_prefix"* &&
     "$command" == *' LAMINATE_SETUP_THREADS=3 '* &&
     "$command" == *' LAMINATE_OBSERVER_CPU=2 '* &&
     "$command" == *"$quoted_wrapper"* ]] || {
    printf 'detached setup lost its approved allocation: %s\n' "$command" >&2
    exit 1
  }
)

for campaign_contract in \
  '10,000-GB Hyperdisk Balanced' \
  '2,400 MiB/s throughput; 150,000 IOPS (current campaign reference configuration)'; do
  if ! grep -Fq -- "$campaign_contract" "$concise_renderer"; then
    printf 'Concise summary renderer omitted campaign storage contract: %s\n' \
      "$campaign_contract" >&2
    exit 1
  fi
done

# Both login-shell examples set the capacity floor consumed by the shared
# storage verification helper.
if [[ "$(grep -Fc -- 'export LAMINATE_STORAGE_MIN_TOTAL_BYTES=9500000000000' "$runbook")" -ne 2 ]]; then
  printf 'Runbook must set the 9.5-TB filesystem floor in both environment blocks.\n' >&2
  exit 1
fi
if ! grep -Fq -- 'benches/prepare_gcp_root_storage.sh verify' "$runbook"; then
  printf 'Runbook omitted the storage helper that enforces its filesystem floor.\n' >&2
  exit 1
fi

local_only_build="$({
  sed -n \
    '/^## 1\. Prepare the source and build$/,/^## 2\./p' \
    "$(dirname -- "$runbook")/LOCAL_BENCHMARKS.md"
})"
for expected in \
  '"$LAMINATE_BENCH_ROOT"' \
  '"$LAMINATE_BENCH_ROOT/runs"' \
  '"$LAMINATE_BENCH_ROOT/logs"' \
  'export LAMINATE_BENCH_ARCHIVE_ROOT=/var/lib/laminate-bench-archive'; do
  if [[ "$local_only_build" != *"$expected"* ]]; then
    printf 'Local-only runbook initialization omitted %s\n' \
      "$expected" >&2
    exit 1
  fi
done

output=''
status=0
output="$("$runner" 2>&1)" || status=$?
if [[ "$status" -ne 2 ]]; then
  printf 'run_gcp usage should exit 2, got %s:\n%s\n' \
    "$status" "$output" >&2
  exit 1
fi

for expected in \
  'quick        N=16384, D=6, W=1024,  I=64; packed T=4, q_BF=4, simpleCTHash/v2 diagnostic.' \
  'target-balancedLaned' \
  'N=16384, D=8, n_FHE=2^20, 50% Mul; packed T=120, q_BF=150,' \
  'target-mulHeavyPyramid' \
  'N=16384, D=8, n_FHE=2^20, 85% Mul concentrated near the input;' \
  'local        Resident plaintext scalar payload evaluation in the client only;' \
  'Local rejects start_server and run_server.' \
  'noIntegrity  FHE payload evaluation only; return one output ciphertext and' \
  'but makes no ciphertext-binding or transcript-packing integrity claim.' \
  'laned        target-balancedLaned, with --lanes 1, 128, or 16384.' \
  'base         target-balancedLaned or target-mulHeavyPyramid.' \
  'folded       target-balancedLaned or target-mulHeavyPyramid.' \
  'Either target payload for comparison baselines.' \
  'Quick diagnostics remain available for every variant.' \
  'target profiles use Poseidon and the selected integrity parameters.'; do
  if [[ "$output" != *"$expected"* ]]; then
    printf 'run_gcp usage omitted packed-profile policy %s:\n%s\n' \
      "$expected" "$output" >&2
    exit 1
  fi
done

if [[ "$output" == *'Reserved interface'* ||
      "$output" == *'standalone runner not implemented'* ]]; then
  printf 'run_gcp still describes Folded/Laned as reserved:\n%s\n' \
    "$output" >&2
  exit 1
fi

for expected in \
  'start_setup  Start setup in a detached process that survives SSH exit.' \
  'follow_setup Show setup progress and exit at setup PASS or failure.' \
  'recover_setup base PROFILE new --source-run-dir /ABS/SOURCE/RUN' \
  'archive_retire' \
  'archive_retire_failed' \
  '--confirm-retire-failed-current-run' \
  '/var/lib/laminate-storage/laminate-bench' \
  'MOUNT/toolchain/build/LaminateImpl' \
  'LAMINATE_BUILD_JOBS' \
  'LAMINATE_STORAGE_MOUNT' \
  'LAMINATE_BENCH_ARCHIVE_ROOT'; do
  if [[ "$output" != *"$expected"* ]]; then
    printf 'run_gcp usage omitted target-campaign contract %s:\n%s\n' \
      "$expected" "$output" >&2
    exit 1
  fi
done
for expected in \
  'default_build_directory="$storage_mount/toolchain/build/LaminateImpl"' \
  'benchmark="$build_directory/benches/laminate_local_payload_bench"' \
  'renderer="$script_directory/support/render_local_payload_summary.py"' \
  "build_info_format='laminate-local-payload-build-info-v1'" \
  'verify_laminate_target_storage_root' \
  '"$artifact_root" "$storage_mount"' \
  'require_target_prefetch_geometry() {' \
  'require_target_private_hard_links() {' \
  'findmnt -rn -o MAJ:MIN --target "$artifact_root"' \
  'laminate_canonical_bdi "$raw_storage_device"' \
  'laminate_resolve_backing_bdi "$storage_device"' \
  'setup|start_setup|start_server|run_server)' \
  'read_ahead_kb=%s; required 8192' \
  'capture_target_setup_storage' \
  'storage-provenance.setup-start.txt' \
  'storage-provenance.server-start.txt' \
  'write_laminate_storage_snapshot' \
  'capture_and_publish_target_server_storage() {' \
  'require_matching_laminate_storage_snapshots' \
  'start_detached_setup() {' \
  'setup_is_complete() {' \
  'require_durable_archive_root() {' \
  'laminate_require_gcp_archive_root "$archive_root"' \
  'storage_backend" != shared-root-filesystem' \
  'isolated target storage requires its evidence archive on another filesystem' \
  'print_runner_command follow_setup "$run_directory"' \
  'archive_completed_run.sh' \
  'render_concise_summary.py' \
  '--input "$summary"' \
  '--output "$summary"' \
  'archive_retire_failed requires RUN=current' \
  'failed "$run_directory" "$artifact_root" "$archive_root"'; do
  if ! grep -Fq -- "$expected" "$runner"; then
    printf 'run_gcp omitted target-campaign implementation %s\n' \
      "$expected" >&2
    exit 1
  fi
done

server_rejection_line="$(grep -n -m1 \
  "Local is client-only; start_server and run_server are not valid" \
  "$runner" | cut -d: -f1)"
first_affinity_line="$(grep -n -m1 'taskset -pc' "$runner" | cut -d: -f1)"
if [[ -z "$server_rejection_line" || -z "$first_affinity_line" ||
      "$server_rejection_line" -ge "$first_affinity_line" ]]; then
  printf '%s\n' \
    'Local server actions must be rejected before affinity or artifact preflight' >&2
  exit 1
fi
for expected in \
  '"$target_profile" == true && "$local_variant" != true' \
  'capture_target_setup_storage() {' \
  'capture_and_publish_target_server_storage() {' \
  'Local summary requires setup/client PASS and zero process exit statuses.' \
  "expected_result='client.result=PASS'" \
  "runner_kind=local"; do
  if ! grep -Fq -- "$expected" "$runner"; then
    printf 'run_gcp omitted Local isolation contract %s\n' "$expected" >&2
    exit 1
  fi
done

follow_setup_dispatch="$(sed -n \
  '/^  follow_setup)/,/^    ;;/p' "$runner")"
follow_failure_line="$(grep -n -m1 \
  'if \[\[ "$setup_status_code" -ne 0 \]\]; then' \
  <<< "$follow_setup_dispatch" | cut -d: -f1)"
follow_accept_line="$(grep -n -m1 'if setup_is_complete; then' \
  <<< "$follow_setup_dispatch" | cut -d: -f1)"
if [[ -z "$follow_failure_line" || -z "$follow_accept_line" ||
      "$follow_failure_line" -ge "$follow_accept_line" ]]; then
  printf '%s\n' \
    'follow_setup must honor a failed status before accepting setup PASS' >&2
  exit 1
fi

missing_build_gate="$(sed -n \
  '/^# Surface a missing build/,/^require_target_prefetch_geometry() {/p' \
  "$runner")"
for expected in \
  'require_executable "$benchmark" "$benchmark_target"' \
  'verify_laminate_target_storage_root'; do
  if [[ "$missing_build_gate" != *"$expected"* ]]; then
    printf 'missing-build preflight omitted %s\n' "$expected" >&2
    exit 1
  fi
done
if [[ "$missing_build_gate" != *'require_executable'* ||
      "${missing_build_gate%%require_executable*}" == \
        *'verify_laminate_target_storage_root'* ]]; then
  printf '%s\n' \
    'missing executable must be reported before target storage checks' >&2
  exit 1
fi
for expected in \
  'The configured build directory is incomplete or points at the wrong build tree.' \
  'No benchmark run was created.'; do
  if ! grep -Fq -- "$expected" "$runner"; then
    printf 'missing executable diagnostic omitted: %s\n' "$expected" >&2
    exit 1
  fi
done

detached_setup="$(sed -n '/^start_detached_setup() {/,/^}/p' "$runner")"
tmux_launch_line="$(grep -n -m1 'new-session -d -s' \
  <<< "$detached_setup" | cut -d: -f1)"
pointer_publish_line="$(grep -n -m1 'record_current_pointer' \
  <<< "$detached_setup" | cut -d: -f1)"
startup_poll_line="$(grep -n -m1 'for ((attempt = 0;' \
  <<< "$detached_setup" | cut -d: -f1)"
if [[ -z "$tmux_launch_line" || -z "$pointer_publish_line" ||
      -z "$startup_poll_line" ||
      "$tmux_launch_line" -ge "$startup_poll_line" ||
      "$startup_poll_line" -ge "$pointer_publish_line" ]]; then
  printf '%s\n' \
    'detached setup must publish current only after startup evidence is observed' >&2
  exit 1
fi
for expected in \
  'record_failed_setup_pointer_if_recoverable() {' \
  '-f "$run_directory/shared/lifecycle.lock"' \
  '-e "$run_directory/shared/setup-activity.jsonl"' \
  'record_failed_setup_pointer_if_recoverable'; do
  if ! grep -Fq -- "$expected" "$runner"; then
    printf 'detached setup omitted recoverable early-failure handling: %s\n' \
      "$expected" >&2
    exit 1
  fi
done

for forbidden in \
  'target_local_ssd_count' \
  'LAMINATE_LOCAL_SSD_MOUNT' \
  'verify_laminate_local_ssd_root' \
  'write_laminate_local_ssd_snapshot' \
  'c4-highmem-48-lssd host'; do
  if grep -Fq -- "$forbidden" "$runner"; then
    printf 'run_gcp retained machine-specific target logic: %s\n' \
      "$forbidden" >&2
    exit 1
  fi
done

for invalid_command in \
  'status laned quick /tmp/example' \
  'status laned quick /tmp/example --lanes 64' \
  'status folded quick /tmp/example --lanes 128' \
  'status local quick /tmp/example --lanes 1' \
  'start_server local quick /tmp/example' \
  'run_server local target-balancedLaned /tmp/example' \
  'status noIntegrity quick /tmp/example --lanes 1' \
  'status noIntegrity old-target /tmp/example' \
  'archive_retire_failed base target-balancedLaned current' \
  'archive_retire_failed laned target-balancedLaned current --lanes 128'; do
  read -r -a arguments <<< "$invalid_command"
  invalid_output=''
  invalid_status=0
  invalid_output="$("$runner" "${arguments[@]}" 2>&1)" || invalid_status=$?
  if [[ "$invalid_status" -ne 2 ]]; then
    printf 'invalid command should exit 2, got %s for %s:\n%s\n' \
      "$invalid_status" "$invalid_command" "$invalid_output" >&2
    exit 1
  fi
done

server_rejection_scratch="$(mktemp -d)"
for local_server_action in start_server run_server; do
  local_server_output=''
  local_server_status=0
  local_server_output="$(
    LAMINATE_BENCH_ROOT="$server_rejection_scratch/artifacts" \
      "$runner" "$local_server_action" local quick \
      "$server_rejection_scratch/run" 2>&1
  )" || local_server_status=$?
  if [[ "$local_server_status" -ne 2 ||
        "$local_server_output" != *'Local is client-only'* ||
        -e "$server_rejection_scratch/artifacts" ]]; then
    printf 'Local %s rejection was late or imprecise:\n%s\n' \
      "$local_server_action" "$local_server_output" >&2
    rm -rf -- "$server_rejection_scratch"
    exit 1
  fi
done
rm -rf -- "$server_rejection_scratch"

# Check campaign admission through the public runner, before any host-specific
# preflight. An invalid CPU is a sentinel: allowed selectors must reach that
# existing check, while rejected executions must fail at campaign admission.
campaign_scratch="$(mktemp -d)"
for campaign_action in setup start_setup start_client start_server run_client run_server \
                       follow_setup follow status summary archive_retire \
                       archive_retire_failed cleanup_old; do
  for campaign_variant in base folded laned local noIntegrity; do
    for campaign_profile in quick target-balancedLaned target-mulHeavyPyramid; do
      campaign_lanes=(0)
      [[ "$campaign_variant" != laned ]] || campaign_lanes=(1 128 16384)
      for campaign_lane in "${campaign_lanes[@]}"; do
        campaign_arguments=("$campaign_action" "$campaign_variant" "$campaign_profile" current)
        [[ "$campaign_variant" != laned ]] || campaign_arguments+=(--lanes "$campaign_lane")
        [[ "$campaign_action" != archive_retire_failed ]] || \
          campaign_arguments+=(--confirm-retire-failed-current-run)
        campaign_output=''
        campaign_status=0
        campaign_output="$(LAMINATE_SETUP_CPU=invalid \
          LAMINATE_BENCH_ROOT="$campaign_scratch/artifacts" \
          "$runner" "${campaign_arguments[@]}" 2>&1)" || campaign_status=$?
        expected_rejection='LAMINATE_SETUP_CPU must be one non-negative integer'
        if [[ "$campaign_variant" == local &&
              ( "$campaign_action" == start_server || "$campaign_action" == run_server ) ]]; then
          expected_rejection='Local is client-only'
        else
          case "$campaign_action:$campaign_variant:$campaign_profile" in
            setup:laned:target-mulHeavyPyramid|start_setup:laned:target-mulHeavyPyramid|start_client:laned:target-mulHeavyPyramid|start_server:laned:target-mulHeavyPyramid|run_client:laned:target-mulHeavyPyramid|run_server:laned:target-mulHeavyPyramid)
              expected_rejection='target campaign requires Laned to use target-balancedLaned'
              ;;
          esac
        fi
        if [[ "$campaign_status" -ne 2 || "$campaign_output" != *"$expected_rejection"* ||
              -e "$campaign_scratch/artifacts" ]]; then
          printf 'campaign admission failed for %s:\n%s\n' \
            "${campaign_arguments[*]}" "$campaign_output" >&2
          rm -rf -- "$campaign_scratch"
          exit 1
        fi
      done
    done
  done
done
rm -rf -- "$campaign_scratch"

if grep -Fq -- '--parallel 4' "$runner"; then
  printf '%s\n' \
    'run_gcp still hard-codes four remediation build jobs instead of host nproc' >&2
  exit 1
fi
for expected in \
  'Laned requires --lanes 1, 128, or 16384 on every command' \
  'lane_arguments=(--lanes "$lanes")' \
  'role_command+=(--lanes "$lanes")' \
  'wrapper_command+=(--lanes "$lanes")'; do
  if ! grep -Fq -- "$expected" "$runner"; then
    printf 'run_gcp omitted the explicit Laned-B contract %s\n' \
      "$expected" >&2
    exit 1
  fi
done

role_runner="$(sed -n '/^run_benchmark_role() {/,/^}/p' "$runner")"
for expected in \
  'client_measurement_lock="$artifact_root/.laminate-measured-client.lock"' \
  '"$role_action" == run_client && "$local_variant" != true' \
  'another measured setup, server, or Local client is active' \
  'measured_resource_lock="$client_measurement_lock"' \
  'ERROR: another measured client is active under this artifact root.'; do
  if ! grep -Fq -- "$expected" "$runner"; then
    printf 'run_gcp omitted the exclusive client-measurement contract %s\n' \
      "$expected" >&2
    exit 1
  fi
done

support_directory="$(cd -- "$(dirname -- "$runner")/support" && pwd)"
campaign_support="$support_directory/measurement_campaign.sh"
for expected in \
  'campaign_binding_lock="$artifact_root/.laminate-measured-campaign-binding.lock"' \
  'campaign_binding_file="$artifact_root/.laminate-measured-campaign.run"' \
  'source "$script_directory/support/measurement_campaign.sh"' \
  'acquire_measurement_role_attempt "$role_name"' \
  'require_fresh_role_attempt "$role_name"' \
  'acquire_measurement_campaign' \
  'benchmark_role_launched=true'; do
  if ! grep -Fq -- "$expected" "$runner"; then
    printf 'run_gcp omitted measured-role coordination %s\n' \
      "$expected" >&2
    exit 1
  fi
done
for expected in \
  'acquire_measurement_campaign() {' \
  'flock -s "$measurement_campaign_lease_fd"' \
  'measurement_campaign_is_active "$bound_run"' \
  'a measured client/server campaign from another run is active.' \
  'acquire_measurement_role_attempt() {' \
  'flock -x -n "$measurement_role_attempt_fd"' \
  'release_measurement_campaign() {'; do
  if ! grep -Fq -- "$expected" "$campaign_support"; then
    printf 'measurement campaign helper omitted contract %s\n' \
      "$expected" >&2
    exit 1
  fi
done

role_claim_line="$(grep -n -m1 \
  'acquire_measurement_role_attempt "$role_name"' <<< "$role_runner" | cut -d: -f1)"
campaign_acquire_line="$(grep -n -m1 \
  'acquire_measurement_campaign' <<< "$role_runner" | cut -d: -f1)"
role_launch_line="$(grep -n -m1 \
  'benchmark_role_launched=true' <<< "$role_runner" | cut -d: -f1)"
if [[ -z "$role_claim_line" || -z "$campaign_acquire_line" ||
      -z "$role_launch_line" ||
      "$role_claim_line" -ge "$campaign_acquire_line" ||
      "$campaign_acquire_line" -ge "$role_launch_line" ]]; then
  printf '%s\n' \
    'run_gcp must atomically claim the role and campaign before measured startup work' >&2
  exit 1
fi

online_dispatch="$(sed -n '/^  run_client|run_server)/,/^    ;;/p' "$runner")"
prelaunch_guard_line="$(grep -n -m1 \
  'if \[\[ "$benchmark_role_launched" != true \]\]; then' \
  <<< "$online_dispatch" | cut -d: -f1)"
publish_line="$(grep -n -m1 'publish_process_exit \\' \
  <<< "$online_dispatch" | cut -d: -f1)"
release_line="$(grep -n -m1 'release_benchmark_wrapper_locks' \
  <<< "$online_dispatch" | cut -d: -f1)"
if [[ -z "$prelaunch_guard_line" || -z "$publish_line" ||
      -z "$release_line" ||
      "$prelaunch_guard_line" -ge "$publish_line" ||
      "$publish_line" -ge "$release_line" ]]; then
  printf '%s\n' \
    'only an executed role may publish immutable exit evidence, while holding its attempt lock' >&2
  exit 1
fi

if command -v flock >/dev/null 2>&1 &&
   readlink -f -- "$support_directory" >/dev/null 2>&1; then
source "$campaign_support"

scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
artifact_root="$scratch/root"
campaign_binding_lock="$artifact_root/.laminate-measured-campaign-binding.lock"
campaign_binding_file="$artifact_root/.laminate-measured-campaign.run"
run_a="$artifact_root/runs/folded-quick-a"
run_b="$artifact_root/runs/folded-quick-b"
mkdir -p "$run_a/shared" "$run_b/shared"

wait_for_file() {
  local path="$1"
  local attempt
  for ((attempt = 0; attempt < 500; ++attempt)); do
    [[ -e "$path" ]] && return 0
    sleep 0.01
  done
  printf 'timed out waiting for campaign-test marker: %s\n' "$path" >&2
  return 1
}

hold_campaign() {
  local held_run="$1"
  local ready="$2"
  local release="$3"
  (
    run_directory="$held_run"
    measurement_campaign_lease_fd=''
    measurement_campaign_run=''
    acquire_measurement_campaign
    : > "$ready"
    wait_for_file "$release"
    release_measurement_campaign
  )
}

first_ready="$scratch/first-ready"
first_release="$scratch/first-release"
second_ready="$scratch/second-ready"
second_release="$scratch/second-release"
hold_campaign "$run_a" "$first_ready" "$first_release" &
first_pid="$!"
wait_for_file "$first_ready"
hold_campaign "$run_a" "$second_ready" "$second_release" &
second_pid="$!"
wait_for_file "$second_ready"
if [[ "$(<"$campaign_binding_file")" != "$run_a" ]]; then
  printf '%s\n' 'same-run client/server holders did not share one campaign binding' >&2
  exit 1
fi

run_directory="$run_b"
measurement_campaign_lease_fd=''
measurement_campaign_run=''
if acquire_measurement_campaign 2>/dev/null; then
  printf '%s\n' 'a role from another run joined an active measured campaign' >&2
  release_measurement_campaign
  exit 1
fi
if [[ -n "$measurement_campaign_lease_fd" ||
      "$(<"$campaign_binding_file")" != "$run_a" ]]; then
  printf '%s\n' 'cross-run rejection leaked a lease or changed the active binding' >&2
  exit 1
fi

role_ready="$scratch/role-ready"
role_release="$scratch/role-release"
(
  run_directory="$run_a"
  measurement_role_attempt_fd=''
  acquire_measurement_role_attempt server
  : > "$role_ready"
  wait_for_file "$role_release"
  release_measurement_role_attempt
) &
role_pid="$!"
wait_for_file "$role_ready"
run_directory="$run_a"
measurement_role_attempt_fd=''
if acquire_measurement_role_attempt server 2>/dev/null; then
  printf '%s\n' 'duplicate server launchers both acquired one immutable role attempt' >&2
  release_measurement_role_attempt
  exit 1
fi
if ! acquire_measurement_role_attempt client; then
  printf '%s\n' 'paired client and server roles could not claim distinct attempts' >&2
  exit 1
fi
release_measurement_role_attempt
: > "$role_release"
wait "$role_pid"

: > "$first_release"
wait "$first_pid"
if [[ "$(<"$campaign_binding_file")" != "$run_a" ]]; then
  printf '%s\n' 'the first completed role removed its peer campaign binding' >&2
  exit 1
fi
: > "$second_release"
wait "$second_pid"
if [[ -e "$campaign_binding_file" ]]; then
  printf '%s\n' 'the final completed role did not retire its campaign binding' >&2
  exit 1
fi

printf '%s\n' "$run_a" > "$campaign_binding_file"
run_directory="$run_b"
measurement_campaign_lease_fd=''
measurement_campaign_run=''
if ! acquire_measurement_campaign; then
  printf '%s\n' 'a stale binding left by a crashed campaign was not reclaimed' >&2
  exit 1
fi
if [[ "$(<"$campaign_binding_file")" != "$run_b" ]]; then
  printf '%s\n' 'stale-binding recovery did not publish the requested run' >&2
  exit 1
fi
release_measurement_campaign
if [[ -e "$campaign_binding_file" ]]; then
  printf '%s\n' 'recovered campaign binding survived its final lease' >&2
  exit 1
fi
else
  printf '%s\n' \
    'SKIP: measured-campaign lock behavior requires flock and GNU readlink -f.'
fi

source "$support_directory/checkpoint_build_info.sh"
commit='0123456789abcdef0123456789abcdef01234567'
common="$({
  printf '%s\n' \
    "environment.git_commit=$commit" \
    'environment.git_dirty=false' \
    'environment.build_type=Release' \
    'environment.seal_acceleration=intel-hexl-runtime-dispatch' \
    'environment.sha256_acceleration=openssl'
})"
local_build="$({
  printf '%s\n' \
    'format=laminate-local-payload-build-info-v1' \
    "environment.git_commit=$commit" \
    'environment.git_dirty=false' \
    'environment.build_type=Release' \
    'environment.compiler=GNU 13.3.0' \
    'environment.architecture=x86-64' \
    'benchmark.variant=local' \
    'benchmark.roles=client-only' \
    'environment.field_backend=scalar-fp65537' \
    'environment.vectorization=enabled' \
    'environment.cpu_target=native' \
    'environment.hexl=not-used' \
    'environment.fhe_backend=none' \
    'environment.threading=single-cpu-process' \
    'computation.integrity=not-applicable' \
    'computation.delegation=none' \
    'computation.server=none' \
    'payload.execution=indexed-cross-slot-prefix-then-coordinate-major' \
    'payload.worker_threads=1'
})"
if ! validate_checkpoint_build_info_metadata \
    local laminate-local-payload-build-info-v1 "$commit" "$local_build"; then
  printf 'exact Local build metadata was rejected: %s\n' \
    "$checkpoint_build_validation_error" >&2
  exit 1
fi
for unsupported_execution in cross-slot-prefix-then-coordinate-major unknown; do
  candidate_local="${local_build/payload.execution=indexed-cross-slot-prefix-then-coordinate-major/payload.execution=$unsupported_execution}"
  if validate_checkpoint_build_info_metadata \
      local laminate-local-payload-build-info-v1 "$commit" "$candidate_local"; then
    printf 'Local build metadata accepted unsupported execution model: %s\n' \
      "$unsupported_execution" >&2
    exit 1
  fi
done
local_with_seal="$local_build"$'\n''environment.seal_acceleration=intel-hexl-runtime-dispatch'
if validate_checkpoint_build_info_metadata \
    local laminate-local-payload-build-info-v1 "$commit" "$local_with_seal"; then
  printf '%s\n' 'Local build metadata claimed an unused SEAL backend' >&2
  exit 1
fi
unvectorized_local="${local_build/environment.vectorization=enabled/environment.vectorization=disabled}"
if validate_checkpoint_build_info_metadata \
    local laminate-local-payload-build-info-v1 "$commit" "$unvectorized_local"; then
  printf '%s\n' 'Local build metadata accepted disabled compiler vectorization' >&2
  exit 1
fi
for bad_cpu_target in \
    "${local_build/environment.cpu_target=native/environment.cpu_target=compiler-default}" \
    "${local_build/environment.cpu_target=native$'\n'/}" \
    "$local_build"$'\n''environment.cpu_target=native'; do
  if validate_checkpoint_build_info_metadata \
      local laminate-local-payload-build-info-v1 "$commit" "$bad_cpu_target"; then
    printf '%s\n' 'Local build metadata accepted an incorrect, missing, or duplicate CPU target' >&2
    exit 1
  fi
done
server_local="${local_build/benchmark.roles=client-only/benchmark.roles=client-server}"
if validate_checkpoint_build_info_metadata \
    local laminate-local-payload-build-info-v1 "$commit" "$server_local"; then
  printf '%s\n' 'Local build metadata accepted a server role' >&2
  exit 1
fi
local_with_packed="$local_build"$'\n''profile.gate_mle=folded:wide-local-adjoint-foldable,laned:structured-sparse-basefold'
if validate_checkpoint_build_info_metadata \
    local laminate-local-payload-build-info-v1 "$commit" "$local_with_packed"; then
  printf '%s\n' 'Local build metadata accepted proof-only fields' >&2
  exit 1
fi

packed="$({
  printf '%s\n' \
    'format=laminate-packed-checkpoint-build-info-v1' \
    'protocol.gkr_claim_transition=selector-interpolation-v1' \
    'protocol.gkr_multiplication=gruen-stripped-h0-v1' \
    'protocol.fiat_shamir=single-transcript-gkr-then-packing-v1' \
    "$common" \
    'protocol.variants=folded,laned' \
    'protocol.exchange=one-request-one-response' \
    'schedule.policy=committed-conservative-no-search' \
    'campaign.target-balancedLaned.variants=folded,laned' \
    'campaign.target-mulHeavyPyramid.variants=folded' \
    'campaign.laned.lanes=1,128,16384' \
    'profile.quick.packing_repetitions=4' \
    'profile.target-balancedLaned.packing_repetitions=120' \
    'profile.target-mulHeavyPyramid.packing_repetitions=120' \
    'profile.quick.basefold_queries=4' \
    'profile.target-balancedLaned.basefold_queries=150' \
    'profile.target-mulHeavyPyramid.basefold_queries=150' \
    'profile.basefold_log_rate=3' \
    'profile.gate_mle=folded:wide-local-adjoint-foldable,laned:structured-sparse-basefold' \
    'profile.quick.ciphertext_hash=simpleCTHash/v2' \
    'profile.target-balancedLaned.ciphertext_hash=poseidon/v2' \
    'profile.target-mulHeavyPyramid.ciphertext_hash=poseidon/v2' \
    'profile.target-balancedLaned.admitted=true' \
    'profile.target-mulHeavyPyramid.admitted=true'
})"
if ! validate_checkpoint_build_info_metadata \
    packed laminate-packed-checkpoint-build-info-v1 "$commit" "$packed"; then
  printf 'exact packed build metadata was rejected: %s\n' \
    "$checkpoint_build_validation_error" >&2
  exit 1
fi

for invalid_campaign in \
    "${packed/campaign.target-balancedLaned.variants=folded,laned/campaign.target-balancedLaned.variants=laned}" \
    "${packed/campaign.target-mulHeavyPyramid.variants=folded/campaign.target-mulHeavyPyramid.variants=folded,laned}" \
    "${packed/campaign.laned.lanes=1,128,16384/campaign.laned.lanes=1,128}" \
    "${packed//$'campaign.target-balancedLaned.variants=folded,laned\n'/}" \
    "$packed"$'\n''campaign.laned.lanes=1,128,16384'; do
  if validate_checkpoint_build_info_metadata \
      packed laminate-packed-checkpoint-build-info-v1 "$commit" "$invalid_campaign"; then
    printf '%s\n' 'packed build metadata accepted an incorrect campaign matrix' >&2
    exit 1
  fi
done

wrong_queries="${packed/profile.target-mulHeavyPyramid.basefold_queries=150/profile.target-mulHeavyPyramid.basefold_queries=151}"
if validate_checkpoint_build_info_metadata \
    packed laminate-packed-checkpoint-build-info-v1 "$commit" "$wrong_queries"; then
  printf 'packed build metadata accepted q_BF=151 for target-mulHeavyPyramid\n' >&2
  exit 1
fi
missing_queries="${packed//$'profile.target-balancedLaned.basefold_queries=150\n'/}"
if validate_checkpoint_build_info_metadata \
    packed laminate-packed-checkpoint-build-info-v1 "$commit" "$missing_queries"; then
  printf 'packed build metadata accepted a missing target q_BF\n' >&2
  exit 1
fi
wrong_log_rate="${packed/profile.basefold_log_rate=3/profile.basefold_log_rate=2}"
if validate_checkpoint_build_info_metadata \
    packed laminate-packed-checkpoint-build-info-v1 "$commit" "$wrong_log_rate"; then
  printf 'packed build metadata accepted BaseFold log-rate 2\n' >&2
  exit 1
fi
searched_schedule="${packed/schedule.policy=committed-conservative-no-search/schedule.policy=setup-exhaustive-search}"
if validate_checkpoint_build_info_metadata \
    packed laminate-packed-checkpoint-build-info-v1 "$commit" "$searched_schedule"; then
  printf 'packed build metadata accepted a setup-time schedule search\n' >&2
  exit 1
fi
diagnostic_target_hash="${packed/profile.target-balancedLaned.ciphertext_hash=poseidon\/v2/profile.target-balancedLaned.ciphertext_hash=simpleCTHash\/v2}"
if validate_checkpoint_build_info_metadata \
    packed laminate-packed-checkpoint-build-info-v1 "$commit" "$diagnostic_target_hash"; then
  printf 'packed build metadata accepted simpleCTHash for target\n' >&2
  exit 1
fi
wrong_gate_mle="${packed/profile.gate_mle=folded:wide-local-adjoint-foldable,laned:structured-sparse-basefold/profile.gate_mle=direct-matrix-evaluation}"
if validate_checkpoint_build_info_metadata \
    packed laminate-packed-checkpoint-build-info-v1 "$commit" "$wrong_gate_mle"; then
  printf 'packed build metadata accepted an unsupported GateMLE mode\n' >&2
  exit 1
fi
missing_gate_mle="${packed//$'profile.gate_mle=folded:wide-local-adjoint-foldable,laned:structured-sparse-basefold\n'/}"
if validate_checkpoint_build_info_metadata \
    packed laminate-packed-checkpoint-build-info-v1 "$commit" "$missing_gate_mle"; then
  printf 'packed build metadata accepted a missing GateMLE mode\n' >&2
  exit 1
fi
duplicate_gate_mle="$packed"$'\n''profile.gate_mle=folded:wide-local-adjoint-foldable,laned:structured-sparse-basefold'
if validate_checkpoint_build_info_metadata \
    packed laminate-packed-checkpoint-build-info-v1 "$commit" "$duplicate_gate_mle"; then
  printf 'packed build metadata accepted a duplicate GateMLE mode\n' >&2
  exit 1
fi
wrong_target_admission="${packed/profile.target-balancedLaned.admitted=true/profile.target-balancedLaned.admitted=false}"
if validate_checkpoint_build_info_metadata \
    packed laminate-packed-checkpoint-build-info-v1 "$commit" "$wrong_target_admission"; then
  printf 'packed build metadata accepted a disabled target profile\n' >&2
  exit 1
fi
unexpected_field="$packed"$'\n''profile.unrecognized=true'
if validate_checkpoint_build_info_metadata \
    packed laminate-packed-checkpoint-build-info-v1 "$commit" "$unexpected_field"; then
  printf 'packed build metadata accepted an unknown field\n' >&2
  exit 1
fi
if [[ "$checkpoint_build_validation_error" != \
      'unexpected build metadata field(s): profile.unrecognized' ]]; then
  printf 'unknown-field diagnostic was not precise: %s\n' \
    "$checkpoint_build_validation_error" >&2
  exit 1
fi

base="$({
  printf '%s\n' \
    'format=laminate-base-checkpoint-build-info-v1' \
    'protocol.gkr_claim_transition=selector-interpolation-v1' \
    'protocol.gkr_multiplication=gruen-stripped-h0-v1' \
    "$common" \
    'campaign.target-balancedLaned.variants=base' \
    'campaign.target-mulHeavyPyramid.variants=base' \
    'profile.gate_mle=wide-local-adjoint-foldable'
})"
if ! validate_checkpoint_build_info_metadata \
    base laminate-base-checkpoint-build-info-v1 "$commit" "$base"; then
  printf 'exact Base build metadata was rejected: %s\n' \
    "$checkpoint_build_validation_error" >&2
  exit 1
fi
for invalid_campaign in \
    "${base/campaign.target-balancedLaned.variants=base/campaign.target-balancedLaned.variants=none}" \
    "${base//$'campaign.target-mulHeavyPyramid.variants=base\n'/}" \
    "$base"$'\n''campaign.target-balancedLaned.variants=base'; do
  if validate_checkpoint_build_info_metadata \
      base laminate-base-checkpoint-build-info-v1 "$commit" "$invalid_campaign"; then
    printf '%s\n' 'Base build metadata accepted an incorrect campaign matrix' >&2
    exit 1
  fi
done

wrong_acceleration="${base/environment.seal_acceleration=intel-hexl-runtime-dispatch/environment.seal_acceleration=none}"
if validate_checkpoint_build_info_metadata \
    base laminate-base-checkpoint-build-info-v1 "$commit" "$wrong_acceleration"; then
  printf 'Base build metadata without Intel HEXL was accepted\n' >&2
  exit 1
fi
wrong_sha256="${base/environment.sha256_acceleration=openssl/environment.sha256_acceleration=portable}"
if validate_checkpoint_build_info_metadata \
    base laminate-base-checkpoint-build-info-v1 "$commit" "$wrong_sha256"; then
  printf 'Base build metadata without accelerated SHA-256 was accepted\n' >&2
  exit 1
fi
base_with_packed="$base"$'\n''profile.quick.ciphertext_hash=simpleCTHash/v2'
if validate_checkpoint_build_info_metadata \
    base laminate-base-checkpoint-build-info-v1 "$commit" "$base_with_packed"; then
  printf 'Base build metadata accepted packed-only profile fields\n' >&2
  exit 1
fi
base_with_target_blocker="$base"$'\n''profile.target-balancedLaned.admitted=true'
if validate_checkpoint_build_info_metadata \
    base laminate-base-checkpoint-build-info-v1 "$commit" "$base_with_target_blocker"; then
  printf 'Base build metadata accepted the packed target blocker\n' >&2
  exit 1
fi

no_integrity="$({
  printf '%s\n' \
    'format=laminate-no-integrity-build-info-v1' \
    "$common" \
    'benchmark.variant=noIntegrity' \
    'protocol.integrity=none' \
    'protocol.exchange=one-request-one-response' \
    'fhe.switch_policy=one-after-each-ctct-multiplication-layer' \
    'fhe.target_data_limbs=9'
})"
if ! validate_checkpoint_build_info_metadata \
    noIntegrity laminate-no-integrity-build-info-v1 "$commit" "$no_integrity"; then
  printf 'exact noIntegrity build metadata was rejected: %s\n' \
    "$checkpoint_build_validation_error" >&2
  exit 1
fi
wrong_no_integrity_limbs="${no_integrity/fhe.target_data_limbs=9/fhe.target_data_limbs=10}"
if validate_checkpoint_build_info_metadata \
    noIntegrity laminate-no-integrity-build-info-v1 "$commit" \
    "$wrong_no_integrity_limbs"; then
  printf '%s\n' 'noIntegrity build metadata accepted ten target data limbs' >&2
  exit 1
fi
no_integrity_with_gate_mle="$no_integrity"$'\n''profile.gate_mle=folded:wide-local-adjoint-foldable,laned:structured-sparse-basefold'
if validate_checkpoint_build_info_metadata \
    noIntegrity laminate-no-integrity-build-info-v1 "$commit" \
    "$no_integrity_with_gate_mle"; then
  printf '%s\n' 'noIntegrity build metadata accepted a proof-only GateMLE field' >&2
  exit 1
fi

# Bind each proof-bearing executable to the supported protocol identities.
for runner_kind in base packed; do
  if [[ "$runner_kind" == base ]]; then
    protocol_metadata="$base"
    protocol_format=laminate-base-checkpoint-build-info-v1
  else
    protocol_metadata="$packed"
    protocol_format=laminate-packed-checkpoint-build-info-v1
  fi
  for field in \
      protocol.gkr_claim_transition=selector-interpolation-v1 \
      protocol.gkr_multiplication=gruen-stripped-h0-v1; do
    for invalid_protocol in \
        "${protocol_metadata/$field$'\n'/}" \
        "${protocol_metadata/$field/${field%=*}=unsupported}" \
        "$protocol_metadata"$'\n'"$field"; do
      if validate_checkpoint_build_info_metadata \
          "$runner_kind" "$protocol_format" "$commit" "$invalid_protocol"; then
        printf '%s accepted a missing, incorrect, or duplicate %s\n' \
          "$runner_kind" "${field%=*}" >&2
        exit 1
      fi
    done
  done
done

field=protocol.fiat_shamir=single-transcript-gkr-then-packing-v1
for invalid_protocol in \
    "${packed/$field$'\n'/}" \
    "${packed/$field/${field%=*}=unsupported}" \
    "$packed"$'\n'"$field"; do
  if validate_checkpoint_build_info_metadata \
      packed laminate-packed-checkpoint-build-info-v1 "$commit" "$invalid_protocol"; then
    printf '%s\n' 'packed build metadata accepted an invalid Fiat-Shamir schedule' >&2
    exit 1
  fi
done
if validate_checkpoint_build_info_metadata \
    base laminate-base-checkpoint-build-info-v1 "$commit" "$base"$'\n'"$field"; then
  printf '%s\n' 'Base build metadata accepted a packed Fiat-Shamir field' >&2
  exit 1
fi

for runner_kind in local noIntegrity; do
  if [[ "$runner_kind" == local ]]; then
    baseline_metadata="$local_build"
    baseline_format=laminate-local-payload-build-info-v1
  else
    baseline_metadata="$no_integrity"
    baseline_format=laminate-no-integrity-build-info-v1
  fi
  for field in \
      protocol.gkr_claim_transition=selector-interpolation-v1 \
      protocol.gkr_multiplication=gruen-stripped-h0-v1 \
      protocol.fiat_shamir=single-transcript-gkr-then-packing-v1; do
    if validate_checkpoint_build_info_metadata \
        "$runner_kind" "$baseline_format" "$commit" "$baseline_metadata"$'\n'"$field"; then
      printf '%s accepted a proof-only %s\n' "$runner_kind" "${field%=*}" >&2
      exit 1
    fi
  done
done

if validate_checkpoint_build_info_metadata \
    base laminate-base-checkpoint-build-info-v1 \
    fedcba9876543210fedcba9876543210fedcba98 "$base"; then
  printf '%s\n' 'Base build metadata accepted an executable from a different revision' >&2
  exit 1
fi
if [[ "$checkpoint_build_validation_error" != \
      'executable revision differs from source HEAD' ]]; then
  printf 'stale-revision diagnostic was not precise: %s\n' \
    "$checkpoint_build_validation_error" >&2
  exit 1
fi
