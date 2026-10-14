#!/usr/bin/env bash

# Named-profile artifact runner. Paths, immutable run state, build provenance,
# storage admission, and role locking are enforced here before the C++ driver
# starts. Reviewer commands are documented in docs/GCP_BENCHMARKS.md.

set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
Usage:
  benches/run_gcp.sh ACTION local|base|folded|noIntegrity PROFILE RUN
  benches/run_gcp.sh ACTION laned PROFILE RUN --lanes 1|128|16384
  benches/run_gcp.sh recover_setup base PROFILE new --source-run-dir /ABS/SOURCE/RUN
  benches/run_gcp.sh archive_retire_failed local|base|folded|noIntegrity PROFILE current \
    --confirm-retire-failed-current-run
  benches/run_gcp.sh archive_retire_failed laned PROFILE current \
    --lanes 1|128|16384 --confirm-retire-failed-current-run

Actions:
  setup        Create immutable preprocessing under RUN.
  start_setup  Start setup in a detached process that survives SSH exit.
  recover_setup
               Validate and reuse completed Base preprocessing in a new run;
               run in the foreground and leave the source unchanged.
  follow_setup Show setup progress and exit at setup PASS or failure.
  start_client Start the client in a detached process that survives SSH exit.
  start_server Start the server in a detached process that survives SSH exit.
  run_client   Publish one request, wait, verify one response, and report PASS.
  run_server   Consume one request and publish one response.
  follow       Print human-readable status every 60 seconds until PASS/failure.
  status       Print the state of setup, client, server, and verification.
  summary      Regenerate the reviewer-oriented summary.md after PASS.
  archive_retire
               Archive compact evidence, then remove this exact completed run.
  archive_retire_failed
               With explicit confirmation, archive diagnostics and remove the
               exact inactive failed/abandoned current run.
  cleanup_old  Keep the current run and permanently remove other inactive matching siblings.

Variants:
  local        Resident plaintext scalar payload evaluation in the client only;
               no delegation, request/response exchange, or server role.
  base         Base checkpoint/replay benchmark.
  folded       Folded GKR plus external transcript-packing Spartan benchmark.
  laned        Laned GKR plus external transcript-packing Spartan benchmark.
  noIntegrity  FHE payload evaluation only; return one output ciphertext and
               make no computation-integrity claim.

Laned geometry:
  --lanes 1       One active slot per ciphertext.
  --lanes 128     The representative partially packed configuration.
  --lanes 16384   Every slot is an independent lane (B=N).

The lane count is required on every Laned command. It is rejected for Local,
Base, Folded, and noIntegrity, so a run can never silently inherit B from a
path or a default. Local rejects start_server and run_server.

Profiles:
  quick        N=16384, D=6, W=1024,  I=64; packed T=4, q_BF=4, simpleCTHash/v2 diagnostic.
  target-balancedLaned
               N=16384, D=8, n_FHE=2^20, 50% Mul; packed T=120, q_BF=150,
               Poseidon evaluation.
  target-mulHeavyPyramid
               N=16384, D=8, n_FHE=2^20, 85% Mul concentrated near the input;
               packed T=120, q_BF=150, Poseidon evaluation.

For Folded and Laned, quick deliberately reduces the selected
T=120 well-formedness repetitions and selected q_BF=150 queries per
single BaseFold opening. It uses diagnostic
simpleCTHash/v2. It stresses the implementation
but makes no ciphertext-binding or transcript-packing integrity claim. Both
target profiles use Poseidon and the selected integrity parameters.

Target campaign for new setup and execution:
  laned        target-balancedLaned, with --lanes 1, 128, or 16384.
  base         target-balancedLaned or target-mulHeavyPyramid.
  folded       target-balancedLaned or target-mulHeavyPyramid.
  local|noIntegrity
               Either target payload for comparison baselines.
Quick diagnostics remain available for every variant.

RUN may be:
  new          For setup/start_setup/recover_setup: create a timestamped run below the artifact root.
  current      Resolve the current-run pointer for the explicit variant/profile.
  /ABS/PATH    Operate on that exact run directory.

recover_setup requires Base, RUN=new, and an explicit canonical absolute source
run directory. It rejects active source/current runs and never retires either.

No action infers the variant or profile from a path. cleanup_old and
archive_retire_failed require RUN=current. Only matching inactive siblings
below the same runs/ directory are eligible for cleanup_old deletion.

Environment:
  LAMINATE_BUILD_DIR  Release+SEAL build (default: REPO/build-seal).
                      Target-profile default: MOUNT/toolchain/build/LaminateImpl.
  LAMINATE_BUILD_JOBS Parallel build jobs shown in repair commands
                      (default: nproc).
  LAMINATE_BENCH_ROOT Artifact root. Target-profile default:
                      /var/lib/laminate-storage/laminate-bench.
                      Quick default: /var/lib/laminate-bench.
  LAMINATE_STORAGE_MOUNT
                      Target storage root. The campaign default is an
                      owner-only directory on the 10-TB Hyperdisk root
                      filesystem (default: /var/lib/laminate-storage).
  LAMINATE_BENCH_ARCHIVE_ROOT
                      Compact completed-run evidence. The GCP runner requires
                      /var/lib/laminate-bench-archive.
  LAMINATE_SETUP_THREADS
                      Base/Folded setup workers (1..256). Default: available
                      allowed CPUs outside the observer core, capped at 256.
  LAMINATE_SETUP_CPU  Logical CPU for serial setup (default: 0).
  LAMINATE_SERVER_CPU Server logical CPU (default: 0; unused by Local).
  LAMINATE_CLIENT_CPU Client logical CPU (default: 1).
  LAMINATE_OBSERVER_CPU Status/follow logical CPU (default: 2).
  LAMINATE_FOLLOW_SECONDS Seconds between follow/setup-heartbeat updates
                          (default: 60).
EOF
}

fail_usage() {
  printf 'ERROR: %s\n\n' "$1" >&2
  usage >&2
  exit 2
}

require_executable() {
  local executable="$1"
  local target="$2"
  if [[ ! -x "$executable" ]]; then
    printf 'ERROR: required executable is missing: %s\n' "$executable" >&2
    printf '%s\n' \
      'The configured build directory is incomplete or points at the wrong build tree.' >&2
    printf 'From the repository root, run:\n' >&2
    printf '  cmake --build %q --target %q --parallel %q\n' \
      "$build_directory" "$target" "$build_jobs" >&2
    printf '%s\n' 'No benchmark run was created.' >&2
    exit 1
  fi
}

if [[ $# -lt 4 ]]; then
  fail_usage 'expected ACTION VARIANT PROFILE RUN, plus --lanes B for Laned'
fi

action="$1"
requested_action="$action"
variant="$2"
profile="$3"
run_selector="$4"
run_directory="$run_selector"
lanes=0

case "$action" in
  setup|start_setup|recover_setup|follow_setup|start_client|start_server|run_client|run_server|follow|status|summary|archive_retire|archive_retire_failed|cleanup_old) ;;
  *) fail_usage 'unknown ACTION; run without arguments to see the supported actions' ;;
esac

packed_variant=false
no_integrity_variant=false
local_variant=false
case "$variant" in
  local)
    local_variant=true
    ;;
  base)
    ;;
  folded|laned)
    packed_variant=true
    ;;
  noIntegrity)
    no_integrity_variant=true
    ;;
  *) fail_usage 'VARIANT must be local, base, folded, laned, or noIntegrity' ;;
esac

if [[ "$local_variant" == true &&
      ( "$action" == start_server || "$action" == run_server ) ]]; then
  fail_usage 'Local is client-only; start_server and run_server are not valid'
fi

failed_retire_confirmation=''
recovery_source_run=''
if [[ "$action" == recover_setup ]]; then
  [[ "$variant" == base ]] || fail_usage 'recover_setup is available only for Base'
  [[ "$run_selector" == new ]] || fail_usage 'recover_setup requires RUN=new'
  [[ $# -eq 6 && "$5" == --source-run-dir ]] || \
    fail_usage 'recover_setup requires --source-run-dir /ABS/SOURCE/RUN'
  recovery_source_run="$6"
  if [[ "$recovery_source_run" != /* || "$recovery_source_run" == / ||
        "$recovery_source_run" == *$'\n'* || "$recovery_source_run" == *$'\r'* ||
        ! -d "$recovery_source_run" || -L "$recovery_source_run" ||
        "$(cd -P -- "$recovery_source_run" && pwd)" != "$recovery_source_run" ]]; then
    fail_usage 'recovery source must be an existing canonical absolute directory, without symlinks'
  fi
  # Recovery uses the complete ordinary setup wrapper, including host/build
  # admission, locks, heartbeat, storage and exit evidence, and current pointer.
  action=setup
elif [[ "$variant" == laned ]]; then
  if [[ $# -lt 6 || "$5" != --lanes ]]; then
    fail_usage 'Laned requires --lanes 1, 128, or 16384 on every command'
  fi
  lanes="$6"
  case "$lanes" in
    1|128|16384) ;;
    *) fail_usage 'Laned --lanes must be 1, 128, or 16384' ;;
  esac
  if [[ "$action" == archive_retire_failed ]]; then
    [[ $# -eq 7 ]] || \
      fail_usage 'archive_retire_failed requires one confirmation flag after --lanes B'
    failed_retire_confirmation="$7"
  elif [[ $# -ne 6 ]]; then
    fail_usage 'unexpected arguments after Laned --lanes B'
  fi
elif [[ "$action" == archive_retire_failed ]]; then
  [[ $# -eq 5 ]] || \
    fail_usage 'archive_retire_failed requires one confirmation flag'
  failed_retire_confirmation="$5"
elif [[ $# -ne 4 ]]; then
  fail_usage '--lanes is valid only for the Laned variant'
fi
if [[ "$action" == archive_retire_failed &&
      "$failed_retire_confirmation" != --confirm-retire-failed-current-run ]]; then
  fail_usage 'archive_retire_failed requires --confirm-retire-failed-current-run'
fi

lane_arguments=()
if [[ "$variant" == laned ]]; then
  lane_arguments=(--lanes "$lanes")
fi

case "$profile" in
  quick)
    geometry='N=16384, D=6, W=1024, I=64'
    packing_repetitions=4
    packing_basefold_queries=4
    target_profile=false
    ;;
  target-balancedLaned)
    geometry='N=16384, D=8, n_FHE=2^20, balanced (50% Mul)'
    packing_repetitions=120
    packing_basefold_queries=150
    target_profile=true
    ;;
  target-mulHeavyPyramid)
    geometry='N=16384, D=8, n_FHE=2^20, input-heavy pyramid (85% Mul)'
    packing_repetitions=120
    packing_basefold_queries=150
    target_profile=true
    ;;
  *) fail_usage 'PROFILE must be quick, target-balancedLaned, or target-mulHeavyPyramid' ;;
esac
# Check workload/variant compatibility before starting any measured role.
case "$action" in
  setup|start_setup|start_client|start_server|run_client|run_server)
    case "$variant:$profile" in
      laned:target-mulHeavyPyramid)
        fail_usage 'target campaign requires Laned to use target-balancedLaned with --lanes 1, 128, or 16384'
        ;;
    esac
    ;;
esac
if [[ "$variant" == laned ]]; then
  geometry="$geometry, B=$lanes"
fi

setup_cpu="${LAMINATE_SETUP_CPU:-0}"
setup_threads=1
setup_cpu_list="$setup_cpu"
server_cpu="${LAMINATE_SERVER_CPU:-0}"
client_cpu="${LAMINATE_CLIENT_CPU:-1}"
observer_cpu="${LAMINATE_OBSERVER_CPU:-2}"
follow_seconds="${LAMINATE_FOLLOW_SECONDS:-60}"
if [[ -n "${LAMINATE_BUILD_JOBS:-}" ]]; then
  build_jobs="$LAMINATE_BUILD_JOBS"
elif command -v nproc >/dev/null 2>&1; then
  build_jobs="$(nproc)"
else
  build_jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '4')"
fi

validate_cpu() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^(0|[1-9][0-9]*)$ ]]; then
    printf 'ERROR: %s must be one non-negative integer.\n' "$name" >&2
    exit 2
  fi
}

validate_cpu LAMINATE_SETUP_CPU "$setup_cpu"
if [[ "$local_variant" == true ]]; then
  validate_cpu LAMINATE_CLIENT_CPU "$client_cpu"
  validate_cpu LAMINATE_OBSERVER_CPU "$observer_cpu"
else
  validate_cpu LAMINATE_SERVER_CPU "$server_cpu"
  validate_cpu LAMINATE_CLIENT_CPU "$client_cpu"
  validate_cpu LAMINATE_OBSERVER_CPU "$observer_cpu"
fi
if [[ "$local_variant" == true && "$observer_cpu" == "$client_cpu" ]]; then
  printf '%s\n' \
    'ERROR: Local client and observer must use different logical CPUs.' >&2
  exit 2
elif [[ "$local_variant" != true && "$server_cpu" == "$client_cpu" ]]; then
  printf '%s\n' \
    'ERROR: client and server must use different logical CPUs.' >&2
  exit 2
elif [[ "$local_variant" != true &&
        ( "$observer_cpu" == "$server_cpu" ||
          "$observer_cpu" == "$client_cpu" ) ]]; then
  printf '%s\n' \
    'ERROR: observer, client, and server must use three different logical CPUs.' >&2
  exit 2
fi
if [[ ! "$follow_seconds" =~ ^[1-9][0-9]*$ ]]; then
  printf '%s\n' \
    'ERROR: LAMINATE_FOLLOW_SECONDS must be a positive integer.' >&2
  exit 2
fi
if [[ ! "$build_jobs" =~ ^[1-9][0-9]*$ ]]; then
  printf '%s\n' \
    'ERROR: LAMINATE_BUILD_JOBS must be a positive integer.' >&2
  exit 2
fi
if ! command -v taskset >/dev/null 2>&1; then
  printf 'ERROR: taskset is required for benchmark affinity.\n' >&2
  exit 1
fi

online_cpu_list=''
IFS= read -r online_cpu_list < /sys/devices/system/cpu/online || true
online_cpu_list="${online_cpu_list//[[:space:]]/}"
if [[ -z "$online_cpu_list" ]]; then
  printf 'ERROR: could not read the online logical CPUs from /sys/devices/system/cpu/online.\n' >&2
  exit 1
fi

cpu_is_allowed() {
  local target="$1"
  local segment lower upper
  local -a segments
  IFS=',' read -r -a segments <<< "$online_cpu_list"
  for segment in "${segments[@]}"; do
    if [[ "$segment" == *-* ]]; then
      lower="${segment%-*}"
      upper="${segment#*-}"
      if ((target >= lower && target <= upper)); then
        return 0
      fi
    elif [[ "$target" == "$segment" ]]; then
      return 0
    fi
  done
  return 1
}

if [[ "$local_variant" == true ]]; then
  required_cpus=("$setup_cpu" "$client_cpu" "$observer_cpu")
else
  required_cpus=("$setup_cpu" "$server_cpu" "$client_cpu" "$observer_cpu")
fi
for cpu in "${required_cpus[@]}"; do
  if ! cpu_is_allowed "$cpu"; then
    printf 'ERROR: logical CPU %s is not online on this host.\n' \
      "$cpu" >&2
    exit 1
  fi
done

read_physical_core_key() {
  local cpu="$1"
  local destination="$2"
  local package_id core_id
  IFS= read -r package_id < \
    "/sys/devices/system/cpu/cpu${cpu}/topology/physical_package_id" || return 1
  IFS= read -r core_id < \
    "/sys/devices/system/cpu/cpu${cpu}/topology/core_id" || return 1
  printf -v "$destination" '%s:%s' "$package_id" "$core_id"
}

setup_core=''
server_core=''
client_core=''
observer_core=''
if [[ "$action" == setup || "$action" == start_setup ]]; then
  read_physical_core_key "$setup_cpu" setup_core || {
    printf 'ERROR: cannot inspect physical-core topology for logical CPU %s.\n' \
      "$setup_cpu" >&2
    exit 1
  }
fi
if [[ "$local_variant" != true ]]; then
  read_physical_core_key "$server_cpu" server_core || {
    printf 'ERROR: cannot inspect physical-core topology for logical CPU %s.\n' \
      "$server_cpu" >&2
    exit 1
  }
fi
read_physical_core_key "$client_cpu" client_core || {
  printf 'ERROR: cannot inspect physical-core topology for logical CPU %s.\n' \
    "$client_cpu" >&2
  exit 1
}
read_physical_core_key "$observer_cpu" observer_core || {
  printf 'ERROR: cannot inspect physical-core topology for logical CPU %s.\n' \
    "$observer_cpu" >&2
  exit 1
}
if [[ "$local_variant" == true && "$client_core" == "$observer_core" ]]; then
  printf '%s\n' \
    'ERROR: Local client and observer logical CPUs must map to distinct physical cores.' >&2
  exit 2
elif [[ "$local_variant" != true &&
        ( "$server_core" == "$client_core" ||
          "$server_core" == "$observer_core" ||
          "$client_core" == "$observer_core" ) ]]; then
  printf '%s\n' \
    'ERROR: server, client, and observer logical CPUs must map to distinct physical cores.' >&2
  exit 2
fi
if [[ ("$action" == setup || "$action" == start_setup) &&
      "$setup_core" == "$observer_core" ]]; then
  printf '%s\n' \
    'ERROR: setup and observer logical CPUs must map to distinct physical cores.' >&2
  exit 2
fi

# Select setup CPUs before pinning this launcher to the observer. A detached
# setup wrapper is launched on this same approved mask plus the observer CPU.
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_directory/support/setup_parallelism.sh"
if [[ ("$action" == setup || "$action" == start_setup) &&
      ("$variant" == base || "$variant" == folded) ]]; then
  allowed_cpu_list="$(awk '$1 == "Cpus_allowed_list:" {print $2}' /proc/self/status)"
  select_setup_parallelism "$allowed_cpu_list" "$observer_core" "$setup_cpu" \
    "${LAMINATE_SETUP_THREADS:-auto}"
fi

# Keep every launcher and observer operation off the measured server and
# client CPUs. Explicit taskset calls below move only the measured role.
taskset -pc "$observer_cpu" "$$" >/dev/null

repository="$(cd -- "$script_directory/.." && pwd)"
storage_mount="${LAMINATE_STORAGE_MOUNT:-/var/lib/laminate-storage}"
if [[ "$target_profile" == true ]]; then
  default_artifact_root="$storage_mount/laminate-bench"
  default_build_directory="$storage_mount/toolchain/build/LaminateImpl"
else
  default_artifact_root=/var/lib/laminate-bench
  default_build_directory="$repository/build-seal"
fi
artifact_root="${LAMINATE_BENCH_ROOT:-$default_artifact_root}"
archive_root="${LAMINATE_BENCH_ARCHIVE_ROOT:-/var/lib/laminate-bench-archive}"
build_directory="${LAMINATE_BUILD_DIR:-$default_build_directory}"
python_renderer=false
if [[ "$local_variant" == true ]]; then
  benchmark="$build_directory/benches/laminate_local_payload_bench"
  benchmark_target='laminate_local_payload_bench'
  build_info_format='laminate-local-payload-build-info-v1'
  renderer="$script_directory/support/render_local_payload_summary.py"
  renderer_target='render_local_payload_summary.py'
  python_renderer=true
elif [[ "$packed_variant" == true ]]; then
  benchmark="$build_directory/benches/laminate_packed_checkpoint_bench"
  benchmark_target='laminate_packed_checkpoint_bench'
  build_info_format='laminate-packed-checkpoint-build-info-v1'
  renderer="$script_directory/support/render_packed_checkpoint_summary.py"
  renderer_target='render_packed_checkpoint_summary.py'
  python_renderer=true
elif [[ "$no_integrity_variant" == true ]]; then
  benchmark="$build_directory/benches/laminate_no_integrity_bench"
  benchmark_target='laminate_no_integrity_bench'
  build_info_format='laminate-no-integrity-build-info-v1'
  renderer="$script_directory/support/render_no_integrity_summary.py"
  renderer_target='render_no_integrity_summary.py'
  python_renderer=true
else
  benchmark="$build_directory/benches/laminate_base_checkpoint_bench"
  benchmark_target='laminate_base_checkpoint_bench'
  build_info_format='laminate-base-checkpoint-build-info-v1'
  renderer="$build_directory/benches/laminate_base_report_summary"
  renderer_target='laminate_base_report_summary'
fi
cleanup="$build_directory/benches/laminate_benchmark_cleanup"
archive_helper="$script_directory/support/archive_completed_run.sh"
concise_renderer="$script_directory/support/render_concise_summary.py"
current_pointer_name="current-${variant}-${profile}"
if [[ "$variant" == laned ]]; then
  current_pointer_name="${current_pointer_name}-b${lanes}"
fi
current_pointer="$artifact_root/${current_pointer_name}.run"
compute_lock="$artifact_root/.laminate-measured-compute.lock"
client_measurement_lock="$artifact_root/.laminate-measured-client.lock"
campaign_io_lock="$artifact_root/.laminate-campaign-io.lock"
campaign_binding_lock="$artifact_root/.laminate-measured-campaign-binding.lock"
campaign_binding_file="$artifact_root/.laminate-measured-campaign.run"
source "$script_directory/support/setup_heartbeat.sh"
source "$script_directory/support/checkpoint_build_info.sh"
source "$script_directory/support/measurement_campaign.sh"
source "$script_directory/support/target_storage_contract.sh"

# Surface a missing build before checking optional performance geometry. This
# keeps setup launch failures actionable after a fresh clone or an incomplete
# build.
case "$action" in
  setup|start_setup|start_server|run_server)
    require_executable "$benchmark" "$benchmark_target"
    ;;
esac

if [[ "$target_profile" == true && "$local_variant" != true ]]; then
  verify_laminate_target_storage_root \
    "$artifact_root" "$storage_mount"
fi

require_target_prefetch_geometry() {
  [[ "$target_profile" == true && "$local_variant" != true ]] || return 0
  local storage_device raw_storage_device resolved_bdi bdi_read_ahead
  local configured_read_ahead
  raw_storage_device="$(findmnt -rn -o MAJ:MIN --target "$artifact_root")" || {
    printf 'ERROR: cannot resolve the backing-device BDI for %s.\n' \
      "$artifact_root" >&2
    return 1
  }
  if ! storage_device="$(laminate_canonical_bdi "$raw_storage_device")"; then
    printf 'ERROR: invalid filesystem device for %s: %q\n' \
      "$artifact_root" "$raw_storage_device" >&2
    return 1
  fi
  if ! resolved_bdi="$(laminate_resolve_backing_bdi "$storage_device")"; then
    printf 'ERROR: cannot resolve target BDI for filesystem device %s.\n' \
      "$storage_device" >&2
    return 1
  fi
  bdi_read_ahead="/sys/class/bdi/$resolved_bdi/read_ahead_kb"
  if ! IFS= read -r configured_read_ahead < "$bdi_read_ahead"; then
    printf 'ERROR: cannot read target BDI read-ahead geometry: %s\n' \
      "$bdi_read_ahead" >&2
    return 1
  fi
  if [[ "$configured_read_ahead" != 8192 ]]; then
    printf 'ERROR: target BDI %s has read_ahead_kb=%s; required 8192.\n' \
      "$resolved_bdi" "$configured_read_ahead" >&2
    printf '%s\n' \
      'Tune read-ahead after this VM boot using the command in docs/GCP_BENCHMARKS.md before setup or server launch.' >&2
    return 1
  fi
  printf 'Target filesystem device %s uses BDI %s read_ahead_kb=%s: PASS.\n' \
    "$storage_device" "$resolved_bdi" "$configured_read_ahead"
}

require_target_private_hard_links() {
  [[ "$target_profile" == true && "$local_variant" != true &&
     "$profile" == target-mulHeavyPyramid ]] ||
    return 0
  local probe_directory source_link alias_link
  probe_directory="$(mktemp -d \
    "$artifact_root/logs/.private-hard-link-preflight.XXXXXX")" || {
    printf 'ERROR: cannot create target hard-link preflight directory.\n' >&2
    return 1
  }
  source_link="$probe_directory/source"
  alias_link="$probe_directory/alias"
  if ! printf '%s\n' laminate-private-alias-preflight > "$source_link" ||
     ! ln -- "$source_link" "$alias_link" ||
     [[ ! "$source_link" -ef "$alias_link" ]]; then
    rm -f -- "$alias_link" "$source_link"
    rmdir -- "$probe_directory" 2>/dev/null || true
    printf '%s\n' \
      'ERROR: target-mulHeavyPyramid storage does not support same-filesystem private hard links; refusing a run that would rematerialize six identity layers.' >&2
    return 1
  fi
  rm -f -- "$alias_link" "$source_link"
  rmdir -- "$probe_directory"
  printf '%s\n' \
    'Target private hard-link capability: PASS (six identity layers must use aliases).'
}

# A reboot resets this sysfs value. Fail before expensive setup and check it
# again before launching the measured server, so a completed run cannot merely
# discover the missing performance prerequisite in its final telemetry.
case "$action" in
  setup|start_setup|start_server|run_server)
    require_target_prefetch_geometry
    require_target_private_hard_links
    ;;
esac

case "$action" in
  setup|start_setup|start_client|start_server|run_client|run_server|summary|archive_retire|archive_retire_failed|cleanup_old)
    if ! command -v flock >/dev/null 2>&1; then
      printf 'ERROR: flock is required for current-run coordination.\n' >&2
      exit 1
    fi
    ;;
esac

# Summary replacement and rollback share the launch/retirement lock so one
# invocation cannot remove another invocation's successfully published report.
case "$action" in
  setup|start_client|start_server|summary|archive_retire|archive_retire_failed|cleanup_old)
    if [[ ! -d "$artifact_root" ]]; then
      printf 'ERROR: artifact root is not initialized: %s\n' \
        "$artifact_root" >&2
      exit 1
    fi
    exec 9>"$artifact_root/.laminate-${variant}-${profile}-launcher.lock"
    if ! flock -n 9; then
      printf 'ERROR: another %s/%s launch, report, or retirement action is active; retry after it finishes.\n' \
        "$variant" "$profile" >&2
      exit 1
    fi
    ;;
esac

if [[ "$action" == cleanup_old && "$run_selector" != current ]]; then
  fail_usage 'cleanup_old requires RUN=current so the preserved run and pointer cannot diverge'
fi
if [[ "$action" == archive_retire_failed && "$run_selector" != current ]]; then
  fail_usage 'archive_retire_failed requires RUN=current'
fi

record_current_run=false
case "$run_directory" in
  new)
    if [[ "$action" != setup && "$action" != start_setup ]]; then
      fail_usage "RUN=new is valid only for setup or start_setup"
    fi
    run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    run_name="${variant}-${profile}"
    if [[ "$variant" == laned ]]; then
      run_name="${run_name}-b${lanes}"
    fi
    run_directory="$artifact_root/runs/${run_name}-${run_id}"
    record_current_run=true
    ;;
  current)
    if [[ "$action" == setup || "$action" == start_setup ]]; then
      fail_usage 'setup and start_setup require RUN=new or an absolute run path'
    fi
    if [[ ! -f "$current_pointer" || -L "$current_pointer" ]]; then
      printf 'ERROR: no current %s/%s run pointer exists at:\n  %s\n' \
        "$variant" "$profile" "$current_pointer" >&2
      exit 1
    fi
    IFS= read -r run_directory < "$current_pointer"
    ;;
  /*)
    # Explicit setup paths remain explicit. Only RUN=new updates current,
    # keeping cleanup's current-pointer contract inside the artifact root.
    ;;
  *)
    fail_usage 'RUN must be new, current, or an absolute path'
    ;;
esac
if [[ "$run_directory" == / ]]; then
  fail_usage 'RUN must not be the filesystem root'
fi
case "$run_directory" in
  /*) ;;
  *) fail_usage 'the resolved RUN path is not absolute' ;;
esac

# Every run is an immediate child of this artifact root's runs directory.
# Besides making cleanup unambiguous, this binds target storage provenance to
# the filesystem that actually holds every preprocessing and online artifact.
if [[ ! -d "$artifact_root" || -L "$artifact_root" ||
      ! -d "$artifact_root/runs" || -L "$artifact_root/runs" ]]; then
  printf 'ERROR: artifact root must contain a safe runs directory:\n  %s/runs\n' \
    "$artifact_root" >&2
  exit 1
fi
canonical_artifact_root="$(cd -P -- "$artifact_root" && pwd)"
canonical_runs_root="$(cd -P -- "$artifact_root/runs" && pwd)"
if [[ "$canonical_artifact_root" != "$artifact_root" ||
      "$canonical_runs_root" != "$artifact_root/runs" ||
      "${run_directory%/*}" != "$canonical_runs_root" ]]; then
  printf '%s\n' \
    'ERROR: RUN must be a canonical immediate child of ARTIFACT_ROOT/runs.' >&2
  printf '  Artifact runs: %s\n  Run:           %s\n' \
    "$canonical_runs_root" "$run_directory" >&2
  exit 1
fi
if [[ -n "$recovery_source_run" &&
      ( -e "$run_directory" || -L "$run_directory" ) ]]; then
  printf 'ERROR: recovery requires a new destination; RUN already exists:\n  %s\n' \
    "$run_directory" >&2
  exit 1
fi
if [[ -e "$run_directory" || -L "$run_directory" ]]; then
  if [[ ! -d "$run_directory" || -L "$run_directory" ||
        "$(cd -P -- "$run_directory" && pwd)" != "$run_directory" ]]; then
    printf 'ERROR: existing RUN is not a safe canonical directory:\n  %s\n' \
      "$run_directory" >&2
    exit 1
  fi
fi

record_current_pointer() {
  if [[ ! -d "$artifact_root/runs" ]]; then
    printf 'ERROR: artifact root is not initialized: %s/runs\n' \
      "$artifact_root" >&2
    exit 1
  fi
  local temporary_pointer="${current_pointer}.tmp.$$"
  printf '%s\n' "$run_directory" > "$temporary_pointer"
  mv -f -- "$temporary_pointer" "$current_pointer"
  printf 'Current %s/%s run:\n  %s\n' \
    "$variant" "$profile" "$run_directory"
}

# A detached child can fail after creating an immutable run but before its
# activity lock becomes observable. Publish that run only when it already has
# enough lifecycle/evidence structure for the documented failed-run retirement
# command. A launch that dies before creating a run leaves the prior selector
# untouched because there is nothing to retire.
record_failed_setup_pointer_if_recoverable() {
  [[ "$record_current_run" == true &&
     -d "$run_directory/shared" &&
     -f "$run_directory/shared/lifecycle.lock" ]] || return 0
  if [[ -e "$run_directory/shared/setup-activity.jsonl" ||
        -e "$run_directory/shared/setup-failure.txt" ||
        -e "$run_directory/shared/setup-process-exit.txt" ]]; then
    record_current_pointer
  fi
}

setup_storage_snapshot_staging=''

capture_target_setup_storage() {
  [[ "$target_profile" == true && "$local_variant" != true ]] || return 0
  local run_checksum
  run_checksum="$(cksum <<< "$run_directory")"
  run_checksum="${run_checksum%% *}"
  setup_storage_snapshot_staging="$artifact_root/logs/.storage-provenance.setup-start.${run_checksum}.$$.$RANDOM.txt"
  write_laminate_storage_snapshot \
    "$setup_storage_snapshot_staging" "$artifact_root" \
    "$storage_mount" setup-start
}

publish_target_setup_storage() {
  [[ -n "$setup_storage_snapshot_staging" ]] || return 0
  local destination="$run_directory/shared/storage-provenance.setup-start.txt"
  if [[ ! -d "$run_directory/shared" || -L "$run_directory/shared" ]]; then
    rm -f -- "$setup_storage_snapshot_staging"
    setup_storage_snapshot_staging=''
    printf '%s\n' \
      'ERROR: setup did not create a safe shared directory for its storage provenance.' >&2
    return 1
  fi
  if ! ln -- "$setup_storage_snapshot_staging" "$destination"; then
    rm -f -- "$setup_storage_snapshot_staging"
    setup_storage_snapshot_staging=''
    printf 'ERROR: failed to publish setup-start storage provenance: %s\n' \
      "$destination" >&2
    return 1
  fi
  rm -f -- "$setup_storage_snapshot_staging"
  setup_storage_snapshot_staging=''
}

discard_target_setup_storage() {
  if [[ -n "$setup_storage_snapshot_staging" ]]; then
    rm -f -- "$setup_storage_snapshot_staging"
    setup_storage_snapshot_staging=''
  fi
}

capture_and_publish_target_server_storage() {
  [[ "$target_profile" == true && "$local_variant" != true ]] || return 0
  local setup_snapshot="$run_directory/shared/storage-provenance.setup-start.txt"
  local destination="$run_directory/shared/storage-provenance.server-start.txt"
  local run_checksum
  run_checksum="$(cksum <<< "$run_directory")"
  run_checksum="${run_checksum%% *}"
  local staging="$artifact_root/logs/.storage-provenance.server-start.${run_checksum}.$$.$RANDOM.txt"

  if ! write_laminate_storage_snapshot \
      "$staging" "$artifact_root" "$storage_mount" server-start; then
    rm -f -- "$staging"
    return 1
  fi
  if ! require_matching_laminate_storage_snapshots \
      "$setup_snapshot" "$staging"; then
    rm -f -- "$staging"
    printf '%s\n' \
      'ERROR: target server will not start on storage that differs from setup.' >&2
    return 1
  fi
  if ! ln -- "$staging" "$destination"; then
    rm -f -- "$staging"
    printf 'ERROR: failed to publish server-start storage provenance: %s\n' \
      "$destination" >&2
    return 1
  fi
  rm -f -- "$staging"
}

print_runner_command() {
  local requested_action="$1"
  local requested_run="$2"
  printf '  benches/run_gcp.sh %q %q %q %q' \
    "$requested_action" "$variant" "$profile" "$requested_run"
  if [[ "$variant" == laned ]]; then
    printf ' --lanes %q' "$lanes"
  fi
  printf '\n'
}

activity_is_active() {
  local activity="$1"
  [[ -f "$activity" ]] || return 1
  if flock -n "$activity" true 2>/dev/null; then
    return 1
  fi
  return 0
}

require_current_run_inactive() {
  [[ -f "$current_pointer" ]] || return 0
  local previous_run
  IFS= read -r previous_run < "$current_pointer"
  case "$previous_run" in
    /*) ;;
    *)
      printf 'ERROR: current-run pointer is not an absolute path: %s\n' \
        "$current_pointer" >&2
      exit 1
      ;;
  esac
  local role
  if activity_is_active "$previous_run/shared/setup-activity.jsonl"; then
    printf 'ERROR: cannot replace current %s/%s while its setup is active.\n' \
      "$variant" "$profile" >&2
    printf '  Active run: %s\n' "$previous_run" >&2
    exit 1
  fi
  for role in client server; do
    if activity_is_active "$previous_run/$role/activity.jsonl"; then
      printf 'ERROR: cannot replace current %s/%s while its %s is active.\n' \
        "$variant" "$profile" "$role" >&2
      printf '  Active run: %s\n' "$previous_run" >&2
      exit 1
    fi
  done
}

require_recovery_source_inactive() {
  [[ -n "$recovery_source_run" ]] || return 0
  local activity
  for activity in shared/setup-activity.jsonl client/activity.jsonl server/activity.jsonl; do
    if activity_is_active "$recovery_source_run/$activity"; then
      printf 'ERROR: cannot recover preprocessing while the source run is active:\n  %s\n' \
        "$recovery_source_run" >&2
      return 1
    fi
  done
}

role_cpu() {
  case "$1" in
    setup) printf '%s' "$setup_cpu_list" ;;
    run_client) printf '%s' "$client_cpu" ;;
    run_server) printf '%s' "$server_cpu" ;;
    *) printf '%s' "$observer_cpu" ;;
  esac
}

publish_process_exit() {
  local path="$1"
  local status="$2"
  local parent="${path%/*}"
  [[ -d "$parent" ]] || return 0
  local temporary="${path}.tmp.$$.$RANDOM"
  printf 'process.exit_status=%s\n' "$status" > "$temporary"
  if ! ln -- "$temporary" "$path" 2>/dev/null; then
    rm -f -- "$temporary"
    printf 'ERROR: refusing to replace existing process-exit evidence: %s\n' \
      "$path" >&2
    return 1
  fi
  rm -f -- "$temporary"
}

require_fresh_role_attempt() {
  local role="$1"
  local artifact
  for artifact in \
    "$run_directory/$role/activity.jsonl" \
    "$run_directory/$role/result.txt" \
    "$run_directory/$role/failure.txt" \
    "$run_directory/$role/process-exit.txt"; do
    if [[ -e "$artifact" || -L "$artifact" ]]; then
      printf 'ERROR: %s already has a prior attempt artifact:\n  %s\n' \
        "$role" "$artifact" >&2
      printf '%s\n' \
        'This immutable protocol role cannot be launched a second time.' >&2
      return 1
    fi
  done
  if [[ "$target_profile" == true && "$role" == server ]]; then
    artifact="$run_directory/shared/storage-provenance.server-start.txt"
    if [[ -e "$artifact" || -L "$artifact" ]]; then
      printf 'ERROR: server already has a prior attempt artifact:\n  %s\n' \
        "$artifact" >&2
      printf '%s\n' \
        'This immutable protocol role cannot be launched a second time.' >&2
      return 1
    fi
  fi
}

benchmark_role_launched=false
benchmark_campaign_acquired=false
benchmark_campaign_io_locked=false
benchmark_measured_resource_locked=false
benchmark_role_attempt_acquired=false

release_benchmark_wrapper_locks() {
  local release_status=0
  if [[ "$benchmark_campaign_acquired" == true ]]; then
    release_measurement_campaign || release_status=$?
    benchmark_campaign_acquired=false
  fi
  if [[ "$benchmark_measured_resource_locked" == true ]]; then
    flock -u 25 || true
    exec 25>&-
    benchmark_measured_resource_locked=false
  fi
  if [[ "$benchmark_campaign_io_locked" == true ]]; then
    flock -u 24 || true
    exec 24>&-
    benchmark_campaign_io_locked=false
  fi
  if [[ "$benchmark_role_attempt_acquired" == true ]]; then
    release_measurement_role_attempt
    benchmark_role_attempt_acquired=false
  fi
  return "$release_status"
}

run_benchmark_role() {
  local role_action="$1"
  benchmark_role_launched=false
  benchmark_campaign_acquired=false
  benchmark_campaign_io_locked=false
  benchmark_measured_resource_locked=false
  benchmark_role_attempt_acquired=false
  local cpu
  cpu="$(role_cpu "$role_action")"
  local -a role_environment=(
    env -u LAMINATE_SETUP_THREADS
    "LAMINATE_BENCH_CPU=$cpu"
    OMP_NUM_THREADS=1
    OPENBLAS_NUM_THREADS=1
    MKL_NUM_THREADS=1
    VECLIB_MAXIMUM_THREADS=1
  )
  if [[ "$role_action" == setup &&
        ("$variant" == base || "$variant" == folded) ]]; then
    role_environment+=("LAMINATE_SETUP_THREADS=$setup_threads")
  fi
  local -a role_command=(
    "${role_environment[@]}"
    taskset -c "$cpu"
    "$benchmark" "$role_action"
    --variant "$variant"
    --profile "$profile"
    --run-dir "$run_directory"
  )
  if [[ "$variant" == laned ]]; then
    role_command+=(--lanes "$lanes")
  fi
  if [[ "$role_action" == setup && -n "${recovery_source_run:-}" ]]; then
    role_command+=(--recover-from "$recovery_source_run")
  fi
  local role_status=0
  if [[ "$role_action" == run_server ||
        "$role_action" == run_client ]]; then
    local role_name="${role_action#run_}"
    if ! acquire_measurement_role_attempt "$role_name"; then
      return 1
    fi
    benchmark_role_attempt_acquired=true
    if ! require_fresh_role_attempt "$role_name"; then
      release_benchmark_wrapper_locks || true
      return 1
    fi
  fi

  if [[ "$role_action" != setup &&
        "$role_action" != run_server &&
        "$role_action" != run_client ]]; then
    printf 'ERROR: unsupported measured role action: %s\n' \
      "$role_action" >&2
    role_status=1
  elif ! exec 24>>"$campaign_io_lock"; then
    printf 'ERROR: cannot open campaign I/O lock: %s\n' \
      "$campaign_io_lock" >&2
    role_status=1
  elif [[ "$role_action" == setup ]] &&
       ! flock -x -n 24; then
    exec 24>&-
    printf '%s\n' \
      'ERROR: setup requires an idle campaign, but a measured role or cleanup is active.' >&2
    printf '%s\n' \
      'Wait for all client/server roles and cleanup under this artifact root to finish.' >&2
    role_status=1
  elif [[ "$role_action" != setup ]] &&
       ! flock -s -n 24; then
    exec 24>&-
    printf '%s\n' \
      'ERROR: benchmark cleanup is active under this artifact root.' >&2
    printf '%s\n' \
      'Wait for cleanup to finish before starting a measured role.' >&2
    role_status=1
  else
    benchmark_campaign_io_locked=true
  fi

  if [[ "$role_status" -eq 0 ]]; then
    local measured_resource_lock="$compute_lock"
    if [[ "$role_action" == run_client && "$local_variant" != true ]]; then
      measured_resource_lock="$client_measurement_lock"
    fi
    if ! exec 25>>"$measured_resource_lock"; then
      printf 'ERROR: cannot open measured-role lock: %s\n' \
        "$measured_resource_lock" >&2
      role_status=1
    elif ! flock -x -n 25; then
      exec 25>&-
      if [[ "$role_action" == run_client && "$local_variant" != true ]]; then
        printf '%s\n' \
          'ERROR: another measured client is active under this artifact root.' >&2
        printf '%s\n' \
          'Wait for it to finish; sharing the pinned client CPU would invalidate client timings.' >&2
      elif [[ "$role_action" == run_client ]]; then
        printf '%s\n' \
          'ERROR: another measured setup, server, or Local client is active under this artifact root.' >&2
        printf '%s\n' \
          'Wait for it to finish; concurrent compute would invalidate the Local timing.' >&2
      else
        printf '%s\n' \
          'ERROR: another measured setup or server is active under this artifact root.' >&2
        printf '%s\n' \
          'Wait for it to finish; concurrent campaigns would invalidate single-core timings.' >&2
      fi
      role_status=1
    else
      benchmark_measured_resource_locked=true
    fi
  fi

  if [[ "$role_status" -eq 0 &&
        "$role_action" != setup ]]; then
    if ! acquire_measurement_campaign; then
      role_status=1
    else
      benchmark_campaign_acquired=true
    fi
  fi

  if [[ "$role_status" -eq 0 ]]; then
    if [[ "$target_profile" == true &&
          "$role_action" == run_server ]]; then
      if ! capture_and_publish_target_server_storage; then
        role_status=1
      fi
    fi
  fi

  if [[ "$role_status" -eq 0 ]]; then
    benchmark_role_launched=true
    "${role_command[@]}" || role_status=$?
  fi

  if [[ "$benchmark_role_launched" != true ]]; then
    release_benchmark_wrapper_locks || true
  fi
  return "$role_status"
}

require_setup_pass() {
  if ! grep -q '^setup.result=PASS$' \
       "$run_directory/shared/setup-result.txt" 2>/dev/null ||
     ! grep -q '^process.exit_status=0$' \
       "$run_directory/shared/setup-process-exit.txt" 2>/dev/null; then
    printf '%s\n' \
      'ERROR: setup PASS and setup process exit status zero are required for this online action.' >&2
    printf '%s\n' \
      'Inspect setup status, its console output, and the exact run path.' >&2
    return 1
  fi
  if [[ "$target_profile" == true && "$local_variant" != true &&
        (! -f "$run_directory/shared/storage-provenance.setup-start.txt" ||
         -L "$run_directory/shared/storage-provenance.setup-start.txt") ]]; then
    printf '%s\n' \
      'ERROR: target setup PASS is missing its immutable storage provenance.' >&2
    printf '  Expected: %s\n' \
      "$run_directory/shared/storage-provenance.setup-start.txt" >&2
    return 1
  fi

  local setup_result="$run_directory/shared/setup-result.txt"
  local expected
  for expected in \
    "run.variant=$variant" \
    "run.profile=$profile"; do
    if ! grep -Fqx -- "$expected" "$setup_result"; then
      printf 'ERROR: selected command does not match the immutable setup (%s).\n' \
        "$expected" >&2
      printf '%s\n' \
        'Check VARIANT, PROFILE, RUN, and --lanes before starting a role.' >&2
      printf '%s\n' \
        'No client or server attempt artifact was created.' >&2
      return 1
    fi
  done
  if [[ "$packed_variant" == true ]]; then
    local expected_lanes=0
    if [[ "$variant" == laned ]]; then
      expected_lanes="$lanes"
    fi
    expected="geometry.B=$expected_lanes"
    if ! grep -Fqx -- "$expected" "$setup_result"; then
      printf 'ERROR: selected command does not match the immutable setup (%s).\n' \
        "$expected" >&2
      printf '%s\n' \
        'Check VARIANT, PROFILE, RUN, and --lanes before starting a role.' >&2
      printf '%s\n' \
        'No client or server attempt artifact was created.' >&2
      return 1
    fi
  fi
}

run_is_complete() {
  grep -q '^setup.result=PASS$' \
    "$run_directory/shared/setup-result.txt" 2>/dev/null &&
  grep -q '^process.exit_status=0$' \
    "$run_directory/shared/setup-process-exit.txt" 2>/dev/null || return 1
  if [[ "$local_variant" == true ]]; then
    [[ ! -e "$run_directory/server" &&
       ! -L "$run_directory/server" &&
       ! -e "$run_directory/shared/transcript" &&
       ! -L "$run_directory/shared/transcript" ]] || return 1
    grep -q '^client.result=PASS$' \
      "$run_directory/client/result.txt" 2>/dev/null &&
    grep -q '^process.exit_status=0$' \
      "$run_directory/client/process-exit.txt" 2>/dev/null
    return
  fi
  grep -q '^server.result=PASS$' \
    "$run_directory/server/result.txt" 2>/dev/null &&
  grep -q '^process.exit_status=0$' \
    "$run_directory/server/process-exit.txt" 2>/dev/null &&
  grep -q '^verification.result=PASS$' \
    "$run_directory/client/result.txt" 2>/dev/null &&
  grep -q '^process.exit_status=0$' \
    "$run_directory/client/process-exit.txt" 2>/dev/null
}

setup_is_complete() {
  grep -q '^setup.result=PASS$' \
    "$run_directory/shared/setup-result.txt" 2>/dev/null &&
  grep -q '^process.exit_status=0$' \
    "$run_directory/shared/setup-process-exit.txt" 2>/dev/null
}

start_detached_role() {
  local role="$1"
  local foreground_action="run_${role}"
  local run_label="${run_directory##*/}"
  run_label="${run_label:-run}"
  run_label="${run_label//[^[:alnum:]_-]/_}"
  run_label="${run_label:0:64}"
  local run_checksum
  run_checksum="$(cksum <<< "$run_directory")"
  run_checksum="${run_checksum%% *}"
  local session="laminate-${role}-${run_label}-${run_checksum}"
  local tmux_socket="laminate-benchmark-cpu-${observer_cpu}"
  local console="$run_directory/$role/console.log"
  local exit_record="$run_directory/$role/process-exit.txt"
  require_executable "$benchmark" "$benchmark_target"
  if ! command -v tmux >/dev/null 2>&1; then
    printf 'ERROR: tmux is required to start a detached role.\n' >&2
    exit 1
  fi
  require_setup_pass
  if tmux -L "$tmux_socket" has-session -t "$session" 2>/dev/null; then
    printf 'ERROR: detached %s session is already active: %s\n' \
      "$role" "$session" >&2
    exit 1
  fi
  require_fresh_role_attempt "$role"
  if [[ -e "$console" || -L "$console" ]]; then
    printf 'ERROR: %s already has a prior console artifact:\n  %s\n' \
      "$role" "$console" >&2
    exit 1
  fi
  local -a wrapper_command=(
    "$script_directory/run_gcp.sh" "$foreground_action"
    "$variant" "$profile" "$run_directory"
  )
  if [[ "$variant" == laned ]]; then
    wrapper_command+=(--lanes "$lanes")
  fi
  local quoted_wrapper
  printf -v quoted_wrapper '%q ' "${wrapper_command[@]}"
  local command
  printf -v command \
    'exec env PATH=%q LAMINATE_BUILD_DIR=%q LAMINATE_BUILD_JOBS=%q LAMINATE_BENCH_ROOT=%q LAMINATE_STORAGE_MOUNT=%q LAMINATE_BENCH_ARCHIVE_ROOT=%q LAMINATE_SETUP_CPU=%q LAMINATE_SERVER_CPU=%q LAMINATE_CLIENT_CPU=%q LAMINATE_OBSERVER_CPU=%q LAMINATE_FOLLOW_SECONDS=%q %s> %q 2>&1' \
    "$PATH" "$build_directory" "$build_jobs" "$artifact_root" "$storage_mount" \
    "$archive_root" "$setup_cpu" "$server_cpu" "$client_cpu" \
    "$observer_cpu" "$follow_seconds" \
    "$quoted_wrapper" "$console"
  tmux -L "$tmux_socket" -f /dev/null \
    new-session -d -s "$session" -n "$role" "$command" 9>&-

  local activity="$run_directory/$role/activity.jsonl"
  local failure="$run_directory/$role/failure.txt"
  local result="$run_directory/$role/result.txt"
  local expected_result='server.result=PASS'
  if [[ "$role" == client ]]; then
    if [[ "$local_variant" == true ]]; then
      expected_result='client.result=PASS'
    else
      expected_result='verification.result=PASS'
    fi
  fi
  local ready=false
  local attempt
  for ((attempt = 0; attempt < 50; ++attempt)); do
    if activity_is_active "$activity" ||
       { grep -q "^${expected_result}$" "$result" 2>/dev/null &&
         grep -q '^process.exit_status=0$' "$exit_record" 2>/dev/null; }; then
      ready=true
      break
    fi
    if [[ -f "$failure" ]]; then
      printf 'ERROR: detached %s failed during startup; inspect:\n  %s\n' \
        "$role" "$failure" >&2
      return 1
    fi
    sleep 0.1
  done
  if [[ "$ready" != true ]]; then
    if [[ ! -e "$activity" && ! -e "$failure" && ! -e "$result" ]] &&
       ! tmux -L "$tmux_socket" has-session -t "$session" 2>/dev/null; then
      local failed_at
      failed_at="$(date -u +%Y%m%dT%H%M%SZ)"
      if [[ -e "$console" ]]; then
        mv -- "$console" \
          "$run_directory/$role/launcher-failure-${failed_at}.log"
      fi
      if [[ -e "$exit_record" ]]; then
        mv -- "$exit_record" \
          "$run_directory/$role/launcher-failure-${failed_at}.exit.txt"
      fi
      printf 'ERROR: detached %s exited before entering the immutable role.\n' \
        "$role" >&2
      printf '%s\n' \
        'Its launcher diagnostics were retained; after correcting the cause, retry start_'"$role"'.' >&2
      return 1
    fi
    printf 'ERROR: detached %s did not reach a live or completed state.\n' \
      "$role" >&2
    printf 'Inspect its console log:\n  %s\n' "$console" >&2
    return 1
  fi
  printf 'Started the %s as a detached single-threaded process.\n' "$role"
  printf '  CPU: %s\n  Console log: %s\n' \
    "$(role_cpu "$foreground_action")" "$console"
  printf 'It will continue if SSH disconnects. Check it with:\n'
  print_runner_command status "$run_directory"
}

start_detached_setup() {
  [[ -d "$artifact_root" && ! -L "$artifact_root" &&
     -d "$artifact_root/runs" && ! -L "$artifact_root/runs" &&
     -d "$artifact_root/logs" && ! -L "$artifact_root/logs" ]] || {
    printf 'ERROR: artifact root must contain safe runs/ and logs/ directories:\n  %s\n' \
      "$artifact_root" >&2
    exit 1
  }
  exec 8>"$artifact_root/.laminate-${variant}-${profile}-start-setup.lock"
  if ! flock -n 8; then
    printf 'ERROR: another detached %s/%s setup launch is active.\n' \
      "$variant" "$profile" >&2
    exit 1
  fi
  require_executable "$benchmark" "$benchmark_target"
  require_current_benchmark_build
  require_current_run_inactive
  if [[ -e "$run_directory" || -L "$run_directory" ]]; then
    printf 'ERROR: setup run path already exists:\n  %s\n' \
      "$run_directory" >&2
    exit 1
  fi
  if ! command -v tmux >/dev/null 2>&1; then
    printf 'ERROR: tmux is required to start detached setup.\n' >&2
    exit 1
  fi
  local run_label="${run_directory##*/}"
  run_label="${run_label//[^[:alnum:]_-]/_}"
  run_label="${run_label:0:64}"
  local run_checksum
  run_checksum="$(cksum <<< "$run_directory")"
  run_checksum="${run_checksum%% *}"
  local session="laminate-setup-${run_label}-${run_checksum}"
  local tmux_socket="laminate-benchmark-cpu-${observer_cpu}"
  local console="$artifact_root/logs/${run_label}.setup.log"
  if [[ -e "$console" || -L "$console" ]]; then
    printf 'ERROR: detached setup console already exists:\n  %s\n' \
      "$console" >&2
    exit 1
  fi
  if tmux -L "$tmux_socket" has-session -t "$session" 2>/dev/null; then
    printf 'ERROR: detached setup session is already active: %s\n' \
      "$session" >&2
    exit 1
  fi

  local -a wrapper_command=(
    "$script_directory/run_gcp.sh" setup
    "$variant" "$profile" "$run_directory"
  )
  if [[ "$variant" == laned ]]; then
    wrapper_command+=(--lanes "$lanes")
  fi
  local quoted_wrapper
  printf -v quoted_wrapper '%q ' "${wrapper_command[@]}"
  local command
  printf -v command \
    'exec taskset -c %q env PATH=%q LAMINATE_BUILD_DIR=%q LAMINATE_BUILD_JOBS=%q LAMINATE_BENCH_ROOT=%q LAMINATE_STORAGE_MOUNT=%q LAMINATE_BENCH_ARCHIVE_ROOT=%q LAMINATE_SETUP_CPU=%q LAMINATE_SETUP_THREADS=%q LAMINATE_SERVER_CPU=%q LAMINATE_CLIENT_CPU=%q LAMINATE_OBSERVER_CPU=%q LAMINATE_FOLLOW_SECONDS=%q %s> %q 2>&1' \
    "$setup_cpu_list,$observer_cpu" "$PATH" "$build_directory" "$build_jobs" "$artifact_root" "$storage_mount" \
    "$archive_root" "$setup_cpu" "$setup_threads" "$server_cpu" "$client_cpu" \
    "$observer_cpu" "$follow_seconds" "$quoted_wrapper" "$console"
  tmux -L "$tmux_socket" -f /dev/null \
    new-session -d -s "$session" -n setup "$command" 8>&- 9>&-

  local activity="$run_directory/shared/setup-activity.jsonl"
  local failure="$run_directory/shared/setup-failure.txt"
  local result="$run_directory/shared/setup-result.txt"
  local ready=false
  local attempt
  for ((attempt = 0; attempt < 100; ++attempt)); do
    if activity_is_active "$activity" ||
       grep -q '^setup.result=PASS$' "$result" 2>/dev/null; then
      ready=true
      break
    fi
    if [[ -f "$failure" ]]; then
      record_failed_setup_pointer_if_recoverable
      printf 'ERROR: detached setup failed during startup; inspect:\n  %s\n' \
        "$failure" >&2
      return 1
    fi
    if ! tmux -L "$tmux_socket" has-session -t "$session" 2>/dev/null; then
      record_failed_setup_pointer_if_recoverable
      printf 'ERROR: detached setup exited before publishing activity. Inspect:\n  %s\n' \
        "$console" >&2
      return 1
    fi
    sleep 0.1
  done
  if [[ "$ready" != true ]]; then
    record_failed_setup_pointer_if_recoverable
    printf 'ERROR: detached setup did not publish activity within ten seconds. Inspect:\n  %s\n' \
      "$console" >&2
    return 1
  fi
  if [[ "$record_current_run" == true ]]; then
    record_current_pointer
  fi
  printf 'Started detached setup with %s worker(s).\n' "$setup_threads"
  printf '  CPU set: %s\n  Console log: %s\n' "$setup_cpu_list" "$console"
  printf '%s\n' 'It will continue if SSH disconnects. Follow it with:'
  print_runner_command follow_setup "$run_directory"
}

run_status() {
  local status_code=0
  env LAMINATE_BENCH_CPU="$observer_cpu" \
    taskset -c "$observer_cpu" \
    "$benchmark" status \
    --variant "$variant" \
    --profile "$profile" \
    --run-dir "$run_directory" \
    "${lane_arguments[@]}" || status_code=$?
  if [[ "$local_variant" == true ]] &&
     activity_is_active "$run_directory/client/activity.jsonl"; then
    emit_role_heartbeat \
      "$run_directory" client "$observer_cpu" \
      server_heartbeat_now_seconds \
      server_heartbeat_observed_at \
      server_heartbeat_process_snapshot
  elif activity_is_active "$run_directory/server/activity.jsonl"; then
    emit_server_heartbeat "$run_directory" "$observer_cpu"
  fi
  return "$status_code"
}

render_human_summary() {
  require_executable "$benchmark" "$benchmark_target"
  if [[ ! -f "$concise_renderer" ]]; then
    printf 'ERROR: required concise summary renderer is missing: %s\n' \
      "$concise_renderer" >&2
    return 1
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' \
      'ERROR: python3 is required to render benchmark summaries.' >&2
    return 1
  fi
  if [[ "$python_renderer" == true ]]; then
    if [[ ! -f "$renderer" ]]; then
      printf 'ERROR: required summary renderer is missing: %s\n' \
        "$renderer" >&2
      return 1
    fi
  else
    require_executable "$renderer" "$renderer_target"
  fi
  require_setup_pass
  if ! run_is_complete; then
    if [[ "$local_variant" == true ]]; then
      printf '%s\n' \
        'ERROR: Local summary requires setup/client PASS and zero process exit statuses.' >&2
    else
      printf '%s\n' \
        'ERROR: summary requires setup/server/client PASS and zero process exit statuses.' >&2
    fi
    return 1
  fi
  summary="$run_directory/shared/report/summary.md"
  local summary_backup=''
  local existing_marker=''
  if [[ -e "$summary" || -L "$summary" ]]; then
    if [[ ! -f "$summary" || -L "$summary" ]]; then
      printf 'ERROR: existing summary is not a safe regular file: %s\n' \
        "$summary" >&2
      return 1
    fi
    IFS= read -r existing_marker < "$summary" || true
    case "$existing_marker" in
      '<!-- laminate-base-summary-v1 -->'|\
      '<!-- laminate-packed-summary-v1 -->'|\
      '<!-- laminate-no-integrity-summary-v1 -->'|\
      '<!-- laminate-local-payload-summary-v1 -->'|\
      '<!-- laminate-benchmark-summary-v2 -->') ;;
      *)
        printf 'ERROR: existing summary is not renderer-owned: %s\n' \
          "$summary" >&2
        return 1
        ;;
    esac
    summary_backup="$(mktemp \
      "$run_directory/shared/report/.summary-backup.XXXXXX")"
    cp -p -- "$summary" "$summary_backup"
    rm -f -- "$summary"
  fi

  local render_status=0
  if [[ "$python_renderer" == true ]]; then
    taskset -c "$observer_cpu" python3 "$renderer" \
      --run-dir "$run_directory" \
      --variant "$variant" \
      --profile "$profile" \
      "${lane_arguments[@]}" \
      --output "$summary" || render_status=$?
  else
    taskset -c "$observer_cpu" "$renderer" \
      --run-dir "$run_directory" \
      --variant "$variant" \
      --profile "$profile" \
      --output "$summary" || render_status=$?
  fi
  if [[ "$render_status" -eq 0 ]]; then
    taskset -c "$observer_cpu" python3 "$concise_renderer" \
      --input "$summary" \
      --output "$summary" \
      --run-dir "$run_directory" \
      --variant "$variant" \
      --profile "$profile" \
      "${lane_arguments[@]}" || render_status=$?
  fi
  if [[ "$render_status" -ne 0 ]]; then
    rm -f -- "$summary"
    if [[ -n "$summary_backup" ]]; then
      mv -- "$summary_backup" "$summary"
    fi
    return "$render_status"
  fi
  if [[ -n "$summary_backup" ]]; then
    rm -f -- "$summary_backup"
  fi

}

require_durable_archive_root() {
  [[ -d "$archive_root" && ! -L "$archive_root" ]] || {
    printf 'ERROR: durable archive root is missing or unsafe:\n  %s\n' \
      "$archive_root" >&2
    return 1
  }
  laminate_require_normalized_dedicated_path \
    "$archive_root" LAMINATE_BENCH_ARCHIVE_ROOT || return 1
  laminate_require_gcp_archive_root "$archive_root" || return 1
  if [[ "$target_profile" == true && "$local_variant" != true ]]; then
    local storage_records storage_backend
    storage_records="$(laminate_collect_target_storage_records \
      "$artifact_root" "$storage_mount" validation)" || return 1
    storage_backend="$(sed -n 's/^storage\.backend=//p' \
      <<< "$storage_records")"
    [[ -n "$storage_backend" ]] || {
      printf '%s\n' \
        'ERROR: target storage verification did not identify its backend.' >&2
      return 1
    }

    local canonical_archive canonical_mount archive_device work_device
    canonical_archive="$(cd -P -- "$archive_root" && pwd)" || return 1
    canonical_mount="$(cd -P -- "$storage_mount" && pwd)" || return 1
    if laminate_path_is_below "$canonical_archive" "$canonical_mount"; then
      printf '%s\n' \
        'ERROR: target evidence archive must be outside live benchmark storage.' >&2
      printf '  Archive: %s\n  Live storage: %s\n' \
        "$canonical_archive" "$canonical_mount" >&2
      return 1
    fi

    # A shared-root run has no second filesystem by construction. Its compact
    # archive is still kept in a disjoint, bounded directory and should be
    # copied off the VM after each run. Dedicated and Local-SSD runs retain
    # the stronger cross-filesystem archive requirement.
    if [[ "$storage_backend" != shared-root-filesystem ]]; then
      archive_device="$(findmnt -rn -o MAJ:MIN --target "$canonical_archive")" || \
        return 1
      work_device="$(findmnt -rn -o MAJ:MIN --target "$canonical_mount")" || \
        return 1
      if [[ -z "$archive_device" || "$archive_device" == "$work_device" ]]; then
        printf '%s\n' \
          'ERROR: isolated target storage requires its evidence archive on another filesystem.' >&2
        printf '  Archive filesystem: %s\n  Work filesystem:    %s\n' \
          "${archive_device:-unknown}" "${work_device:-unknown}" >&2
        return 1
      fi
    fi
  fi
}

setup_heartbeat_pid=''
stop_setup_heartbeat() {
  if [[ -z "$setup_heartbeat_pid" ]]; then
    return 0
  fi
  kill "$setup_heartbeat_pid" 2>/dev/null || true
  wait "$setup_heartbeat_pid" 2>/dev/null || true
  setup_heartbeat_pid=''
}

# This check deliberately requires a local Git snapshot even when the source
# arrived as an archive. It compares the executable to that snapshot, without
# requiring an upstream commit identity, network connection, or Git remote.
require_current_benchmark_build() {
  local source_commit
  if ! source_commit="$(git -C "$repository" rev-parse --verify HEAD)" ||
     [[ ! "$source_commit" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
    printf 'ERROR: cannot determine the current source revision.\n' >&2
    exit 1
  fi
  local source_status
  if ! source_status="$(git -C "$repository" status --porcelain --untracked-files=normal)"; then
    printf 'ERROR: cannot inspect the current source tree.\n' >&2
    exit 1
  fi
  if [[ -n "$source_status" ]]; then
    printf '%s\n' \
      'ERROR: setup requires a clean source tree before checking the benchmark executable.' >&2
    printf '%s\n' "$source_status" >&2
    exit 1
  fi

  local build_info
  if ! build_info="$("$benchmark" build_info 2>&1)"; then
    printf '%s\n' \
      'ERROR: the selected checkpoint benchmark predates build-info validation or cannot start.' >&2
    printf 'Executable: %s\n' "$benchmark" >&2
    printf '%s\n' "$build_info" >&2
    printf 'Rebuild it with:\n  cmake --build %q --target %q --parallel %q\n' \
      "$build_directory" "$benchmark_target" "$build_jobs" >&2
    exit 1
  fi

  local runner_kind=base
  if [[ "$local_variant" == true ]]; then
    runner_kind=local
  elif [[ "$packed_variant" == true ]]; then
    runner_kind=packed
  elif [[ "$no_integrity_variant" == true ]]; then
    runner_kind=noIntegrity
  fi
  if ! validate_checkpoint_build_info_metadata \
      "$runner_kind" "$build_info_format" "$source_commit" "$build_info"; then
    printf '%s\n' \
      'ERROR: the selected checkpoint benchmark returned invalid build metadata.' >&2
    printf 'Reason: %s\n' "$checkpoint_build_validation_error" >&2
    printf 'Executable: %s\n' "$benchmark" >&2
    printf '%s\n' "$build_info" >&2
    printf '  Source HEAD:       %s\n' "$source_commit" >&2
    printf '  Executable commit: %s\n' \
      "${checkpoint_build_commit:-not-reported}" >&2
    printf '  Executable dirty:  %s\n' \
      "${checkpoint_build_dirty:-not-reported}" >&2
    printf '  Build type:        %s\n' \
      "${checkpoint_build_type:-not-reported}" >&2
    if [[ "$local_variant" == true ]]; then
      printf '  Compiler:           %s\n' \
        "${checkpoint_build_compiler:-not-reported}" >&2
    else
      printf '  SEAL acceleration: %s\n' \
        "${checkpoint_build_acceleration:-not-reported}" >&2
      printf '  SHA-256 provider:  %s\n' \
        "${checkpoint_build_sha256_acceleration:-not-reported}" >&2
    fi
    printf 'Rebuild it with:\n  cmake --build %q --target %q --parallel %q\n' \
      "$build_directory" "$benchmark_target" "$build_jobs" >&2
    exit 1
  fi
}

if [[ "$action" == setup ]]; then
  require_executable "$benchmark" "$benchmark_target"
  require_current_benchmark_build
fi

printf 'Laminate benchmark: action=%s variant=%s profile=%s\n' \
  "$requested_action" "$variant" "$profile"
printf 'Geometry: %s\n' "$geometry"
printf 'Run directory: %s\n' "$run_directory"
if [[ -n "$recovery_source_run" ]]; then
  printf 'Recovery source (unchanged): %s\n' "$recovery_source_run"
fi

if [[ "$local_variant" == true ]]; then
  printf '%s\n' \
    'LOCAL BASELINE: the pinned client evaluates the payload with a resident scalar field interpreter. There is no delegation, FHE, request/response exchange, or computation-integrity claim.'
elif [[ "$packed_variant" == true ]]; then
  printf 'Packed security parameters: actual T=%s, q_BF=%s; selected T=120, q_BF=150.\n' \
    "$packing_repetitions" "$packing_basefold_queries"
  if [[ "$target_profile" != true ]]; then
    printf '%s\n' \
      'ciphertext hash: simpleCTHash/v2 (diagnostic; no ciphertext-binding or transcript-packing integrity claim)'
    printf '%s\n' \
      'DIAGNOSTIC ONLY: reduced-T/reduced-query/simpleCTHash stress profile; no transcript-packing integrity claim.'
  else
    printf '%s\n' 'ciphertext hash: Poseidon (poseidon/v2)'
    printf '%s\n' \
      'EVALUATION PROFILE: selected transcript-packing parameters; all target admission blockers remain fail-closed.'
  fi
elif [[ "$no_integrity_variant" == true ]]; then
  printf '%s\n' \
    'NO-INTEGRITY BASELINE: the server evaluates only the FHE payload and returns one output ciphertext. No proof or computation-integrity claim is produced.'
  printf '%s\n' \
    'FHE schedule: profile-specific payload-only primes, exactly D+1 data limbs, one modulus drop after each CT-CT multiplication layer, one output limb, and Galois keys when the payload includes rotations.'
fi

if [[ "$target_profile" == true && "$local_variant" != true &&
      "$action" != status && "$action" != summary &&
      "$action" != follow_setup && "$action" != archive_retire &&
      "$action" != archive_retire_failed && "$action" != cleanup_old ]]; then
  printf '%s\n' \
    'TARGET PROFILE: workload parameters are fixed; setup derives checkpoint/replay budgets from the validated scratch filesystem and physical RAM, then fails closed if no admitted plan fits.' >&2
fi

case "$action" in
  setup)
    require_current_run_inactive
    require_recovery_source_inactive
    capture_target_setup_storage
    setup_heartbeat_loop \
      "$run_directory" "$observer_cpu" "$follow_seconds" &
    setup_heartbeat_pid="$!"
    trap 'stop_setup_heartbeat; discard_target_setup_storage' EXIT
    setup_status=0
    run_benchmark_role setup || setup_status=$?
    stop_setup_heartbeat
    trap - EXIT
    storage_publish_status=0
    if [[ -d "$run_directory/shared" ]]; then
      publish_target_setup_storage || storage_publish_status=$?
    else
      discard_target_setup_storage
    fi
    setup_evidence_status="$setup_status"
    if [[ "$storage_publish_status" -ne 0 ]]; then
      setup_evidence_status="$storage_publish_status"
    fi
    if [[ "$benchmark_role_launched" != true ]]; then
      if [[ "$storage_publish_status" -ne 0 ]]; then
        exit "$storage_publish_status"
      fi
      exit "$setup_status"
    fi
    publish_status=0
    publish_process_exit \
      "$run_directory/shared/setup-process-exit.txt" \
      "$setup_evidence_status" || \
      publish_status=$?
    release_status=0
    release_benchmark_wrapper_locks || release_status=$?
    if [[ "$publish_status" -ne 0 ]]; then
      exit "$publish_status"
    fi
    if [[ "$storage_publish_status" -ne 0 ]]; then
      exit "$storage_publish_status"
    fi
    if [[ "$release_status" -ne 0 ]]; then
      exit "$release_status"
    fi
    if [[ "$setup_status" -ne 0 ]]; then
      exit "$setup_status"
    fi
    if ! grep -q '^setup.result=PASS$' \
         "$run_directory/shared/setup-result.txt" 2>/dev/null; then
      printf 'ERROR: setup exited without publishing setup.result=PASS.\n' >&2
      printf 'Failed run path:\n  %s\n' "$run_directory" >&2
      exit 1
    fi
    if [[ "$record_current_run" == true ]]; then
      record_current_pointer
    else
      printf '%s\n' \
        'Setup PASS. This explicit run was not assigned to the current pointer.'
      printf 'Start its client with:\n'
      print_runner_command start_client "$run_directory"
    fi
    ;;

  start_setup)
    start_detached_setup
    ;;

  follow_setup)
    require_executable "$benchmark" "$benchmark_target"
    printf '\nFollowing setup progress every %s seconds.\n' \
      "$follow_seconds"
    printf 'This observer uses CPU %s; setup allocation is recorded in its launch log.\n' \
      "$observer_cpu"
    printf '%s\n' \
      'Ctrl-C stops only this observer; detached setup continues.'
    while true; do
      printf '\n------------------------------------------------------------\n'
      date -u '+Setup status at %Y-%m-%d %H:%M:%S UTC'
      printf '%s\n' '------------------------------------------------------------'
      setup_status_code=0
      run_status || setup_status_code=$?
      if [[ "$setup_status_code" -ne 0 ]]; then
        printf '%s\n' \
          'SETUP FAILED OR WAS ABANDONED. The current run can be archived and retired only with the explicit failed-run command.' >&2
        exit "$setup_status_code"
      fi
      if setup_is_complete; then
        printf '\nSETUP COMPLETE AND ACCEPTED. Start the client with:\n'
        print_runner_command start_client "$run_directory"
        exit 0
      fi
      sleep "$follow_seconds"
    done
    ;;

  run_client|run_server)
    require_executable "$benchmark" "$benchmark_target"
    require_setup_pass
    role_name="${action#run_}"
    require_fresh_role_attempt "$role_name"
    role_status=0
    run_benchmark_role "$action" || role_status=$?
    if [[ "$benchmark_role_launched" != true ]]; then
      exit "$role_status"
    fi
    publish_status=0
    publish_process_exit \
      "$run_directory/$role_name/process-exit.txt" "$role_status" || \
      publish_status=$?
    release_status=0
    release_benchmark_wrapper_locks || release_status=$?
    if [[ "$publish_status" -ne 0 ]]; then
      exit "$publish_status"
    fi
    if [[ "$release_status" -ne 0 ]]; then
      exit "$release_status"
    fi
    exit "$role_status"
    ;;

  start_client)
    start_detached_role client
    ;;

  start_server)
    start_detached_role server
    ;;

  follow)
    require_executable "$benchmark" "$benchmark_target"
    require_setup_pass
    printf '\nFollowing human-readable progress every %s seconds.\n' \
      "$follow_seconds"
    if [[ "$local_variant" == true ]]; then
      printf 'This observer uses CPU %s; the Local client uses CPU %s.\n' \
        "$observer_cpu" "$client_cpu"
      printf '%s\n' \
        'Ctrl-C stops only this observer; the detached Local client continues.'
    else
      printf 'This observer uses CPU %s; the server uses CPU %s.\n' \
        "$observer_cpu" "$server_cpu"
      printf '%s\n' \
        'Ctrl-C stops only this observer; the detached client and server continue.'
    fi
    while true; do
      printf '\n------------------------------------------------------------\n'
      date -u '+Status at %Y-%m-%d %H:%M:%S UTC'
      printf '%s\n' '------------------------------------------------------------'
      status_code=0
      run_status || status_code=$?
      if [[ "$status_code" -ne 0 ]]; then
        printf '\nBenchmark failed or a role stopped without a result.\n' >&2
        exit "$status_code"
      fi
      if run_is_complete; then
        printf '\nBenchmark complete. Render the report with:\n'
        print_runner_command summary "$run_directory"
        exit 0
      fi
      sleep "$follow_seconds"
    done
    ;;

  status)
    require_executable "$benchmark" "$benchmark_target"
    run_status
    ;;

  summary)
    run_status
    render_human_summary
    printf '\nHuman-readable summary: %s\n' "$summary"
    printf '\n'
    cat -- "$summary"
    ;;

  archive_retire)
    [[ -x "$archive_helper" ]] || {
      printf 'ERROR: completed-run archive helper is missing: %s\n' \
        "$archive_helper" >&2
      exit 1
    }
    require_durable_archive_root
    render_human_summary
    archive_status=0
    flock -x -n -E 74 "$campaign_io_lock" \
      taskset -c "$observer_cpu" "$archive_helper" \
        complete "$run_directory" "$artifact_root" "$archive_root" \
        "$current_pointer" || archive_status=$?
    if [[ "$archive_status" -eq 74 ]]; then
      if [[ "$local_variant" == true ]]; then
        printf '%s\n' \
          'ERROR: Local setup or client is active; completed-run retirement is unsafe.' >&2
      else
        printf '%s\n' \
          'ERROR: setup, a client, or a server is active; completed-run retirement is unsafe.' >&2
      fi
      exit 1
    fi
    exit "$archive_status"
    ;;

  archive_retire_failed)
    [[ -x "$archive_helper" ]] || {
      printf 'ERROR: failed-run archive helper is missing: %s\n' \
        "$archive_helper" >&2
      exit 1
    }
    require_durable_archive_root
    archive_status=0
    flock -x -n -E 74 "$campaign_io_lock" \
      taskset -c "$observer_cpu" "$archive_helper" \
        failed "$run_directory" "$artifact_root" "$archive_root" \
        "$current_pointer" --confirm-retire-failed-current-run || \
      archive_status=$?
    if [[ "$archive_status" -eq 74 ]]; then
      if [[ "$local_variant" == true ]]; then
        printf '%s\n' \
          'ERROR: Local setup or client is active; failed-run retirement is unsafe.' >&2
      else
        printf '%s\n' \
          'ERROR: setup, a client, or a server is active; failed-run retirement is unsafe.' >&2
      fi
      exit 1
    fi
    exit "$archive_status"
    ;;

  cleanup_old)
    require_executable "$cleanup" laminate_benchmark_cleanup
    require_setup_pass
    cleanup_status=0
    flock -x -n -E 74 "$campaign_io_lock" \
      taskset -c "$observer_cpu" "$cleanup" \
        --variant "$variant" \
        --profile "$profile" \
        --keep-run "$run_directory" \
        "${lane_arguments[@]}" || cleanup_status=$?
    if [[ "$cleanup_status" -eq 74 ]]; then
      if [[ "$local_variant" == true ]]; then
        printf '%s\n' \
          'ERROR: Local setup or client is active; cleanup would contaminate its measurements.' >&2
      else
        printf '%s\n' \
          'ERROR: setup, a client, or a server is active; cleanup would contaminate its measurements.' >&2
      fi
      exit 1
    fi
    exit "$cleanup_status"
    ;;
esac
