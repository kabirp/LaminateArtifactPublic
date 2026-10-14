#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly evidence_limit_bytes=250000000
readonly evidence_file_limit_bytes=125000000
readonly archive_free_space_reserve_bytes=2000000000

usage() {
  cat <<'EOF'
Usage:
  archive_completed_run.sh complete RUN ARTIFACT_ROOT ARCHIVE_ROOT CURRENT_POINTER
  archive_completed_run.sh failed RUN ARTIFACT_ROOT ARCHIVE_ROOT CURRENT_POINTER \
    --confirm-retire-failed-current-run

Both modes retain a bounded, exact allowlist of reports, results, telemetry,
and console diagnostics before removing RUN. Completed archives retain the
single Markdown report. The failed mode is only for the inactive run named by
CURRENT_POINTER and requires the literal confirmation flag.
EOF
}

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

stat_uid() {
  stat -c '%u' -- "$1" 2>/dev/null || stat -f '%u' -- "$1"
}

stat_mode() {
  stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1"
}

stat_bytes() {
  stat -c '%s' -- "$1" 2>/dev/null || stat -f '%z' -- "$1"
}

sync_directory() {
  sync -f "$1" 2>/dev/null || sync
}

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=target_storage_contract.sh
source "$script_directory/target_storage_contract.sh"

for required_command in awk cmp cp df findmnt flock grep tar; do
  command -v "$required_command" >/dev/null 2>&1 || \
    fail "required archive tool is missing: $required_command"
done

sha256_digest() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$path" | awk '{print $1}'
  else
    fail 'sha256sum or shasum is required to archive benchmark evidence'
  fi
}

if [[ $# -ne 5 && $# -ne 6 ]]; then
  usage >&2
  exit 2
fi

mode="$1"
run_directory="$2"
artifact_root="$3"
archive_root="$4"
current_pointer="$5"
confirmation="${6:-}"
case "$mode" in
  complete)
    [[ $# -eq 5 ]] || {
      usage >&2
      exit 2
    }
    ;;
  failed)
    [[ $# -eq 6 &&
       "$confirmation" == --confirm-retire-failed-current-run ]] || {
      printf '%s\n' \
        'ERROR: failed-run retirement requires --confirm-retire-failed-current-run.' >&2
      usage >&2
      exit 2
    }
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

# Validate and canonicalize every path before locks, archives, or deletions.
laminate_require_normalized_dedicated_path \
  "$artifact_root" ARTIFACT_ROOT || exit 1
laminate_require_normalized_dedicated_path \
  "$archive_root" ARCHIVE_ROOT || exit 1
laminate_require_normalized_dedicated_path \
  "$run_directory" RUN || exit 1
[[ -d "$artifact_root" && ! -L "$artifact_root" ]] || \
  fail "artifact root is missing or unsafe: $artifact_root"
[[ -d "$artifact_root/runs" && ! -L "$artifact_root/runs" ]] || \
  fail "artifact runs directory is missing or unsafe: $artifact_root/runs"
[[ -d "$archive_root" && ! -L "$archive_root" ]] || \
  fail "archive root is missing or unsafe: $archive_root"

canonical_artifact="$(cd -P -- "$artifact_root" && pwd)"
canonical_runs="$(cd -P -- "$artifact_root/runs" && pwd)"
canonical_archive="$(cd -P -- "$archive_root" && pwd)"
[[ "$canonical_artifact" == "$artifact_root" &&
   "$canonical_runs" == "$artifact_root/runs" &&
   "$canonical_archive" == "$archive_root" ]] || \
  fail 'artifact, runs, and archive roots must use their canonical paths'
[[ "${run_directory%/*}" == "$canonical_runs" ]] || \
  fail 'only an immediate child of ARTIFACT_ROOT/runs can be retired'
[[ "$canonical_archive" != "$canonical_artifact" &&
   "$canonical_archive" != "$canonical_artifact/"* &&
   "$canonical_artifact" != "$canonical_archive/"* ]] || \
  fail 'archive root and benchmark artifact root must be disjoint'

pointer_parent="${current_pointer%/*}"
pointer_name="${current_pointer##*/}"
[[ "$current_pointer" == /* && "$pointer_parent" == "$canonical_artifact" ]] || \
  fail 'CURRENT_POINTER must be an immediate child of ARTIFACT_ROOT'
if [[ "$pointer_name" =~ ^current-(local|base|folded|laned|noIntegrity)-(quick|target-balancedLaned|target-mulHeavyPyramid)(-b(1|128|16384))?\.run$ ]]; then
  selected_variant="${BASH_REMATCH[1]}"
  selected_profile="${BASH_REMATCH[2]}"
  selected_lanes="${BASH_REMATCH[4]:-}"
else
  fail "unexpected current-run pointer name: $pointer_name"
fi
if [[ "$selected_variant" == laned ]]; then
  [[ -n "$selected_lanes" ]] || \
    fail 'Laned current-run pointer omits its lane count'
elif [[ -n "$selected_lanes" ]]; then
  fail 'only a Laned current-run pointer may contain a lane count'
fi

for directory in "$canonical_artifact" "$canonical_runs" "$canonical_archive"; do
  owner="$(stat_uid "$directory")"
  mode_bits="$(stat_mode "$directory")"
  [[ "$owner" == "$(id -u)" && "$((8#$mode_bits & 0022))" -eq 0 ]] || \
    fail "directory must be owned by the current user and not group/world writable: $directory"
done

run_name="${run_directory##*/}"
if [[ "$mode" == complete ]]; then
  archive_path="$canonical_archive/${run_name}.evidence.tar.gz"
  human_copy="$canonical_archive/${run_name}.summary.md"
else
  archive_path="$canonical_archive/${run_name}.failed-evidence.tar.gz"
  human_copy="$canonical_archive/${run_name}.failed.txt"
fi
checksum_path="${archive_path}.sha256"

clear_matching_pointer() {
  if [[ -f "$current_pointer" && ! -L "$current_pointer" ]]; then
    local pointer_run=''
    IFS= read -r pointer_run < "$current_pointer" || true
    if [[ "$pointer_run" == "$run_directory" ]]; then
      rm -f -- "$current_pointer"
    fi
  fi
}

validate_existing_archive() {
  [[ -f "$archive_path" && ! -L "$archive_path" &&
     -f "$checksum_path" && ! -L "$checksum_path" &&
     -f "$human_copy" && ! -L "$human_copy" ]] || return 1
  [[ "$(stat_bytes "$archive_path")" -le "$evidence_limit_bytes" &&
     "$(stat_bytes "$human_copy")" -le "$evidence_file_limit_bytes" ]] || \
    return 1
  local checksum_record expected_digest expected_name
  IFS= read -r checksum_record < "$checksum_path" || return 1
  local checksum_pattern='^([0-9a-f]{64})[[:space:]][[:space:]]([^/]+)$'
  [[ "$checksum_record" =~ $checksum_pattern ]] || return 1
  expected_digest="${BASH_REMATCH[1]}"
  expected_name="${BASH_REMATCH[2]}"
  [[ "$expected_name" == "${archive_path##*/}" &&
     "$(sha256_digest "$archive_path")" == "$expected_digest" ]] || return 1
  local archive_csv_present=false member members
  members="$(tar -tzf "$archive_path")" || return 1
  while IFS= read -r member; do
    case "$member" in
      ./|./README.txt|./retained-files-and-bytes.tsv|\
      ./evidence/|./evidence/shared/|./evidence/shared/report/|\
      ./evidence/client/|./evidence/server/|\
      ./evidence/shared/setup-result.txt|\
      ./evidence/shared/setup-process-exit.txt|\
      ./evidence/shared/setup-activity.jsonl|\
      ./evidence/shared/setup-failure.txt|\
      ./evidence/shared/run-binding.txt|\
      ./evidence/shared/recovery-source-setup.bin|\
      ./evidence/shared/storage-provenance.setup-start.txt|\
      ./evidence/shared/storage-provenance.server-start.txt|\
      ./evidence/shared/setup-console.log|\
      ./evidence/shared/report/summary.md|\
      ./evidence/client/result.txt|\
      ./evidence/client/process-exit.txt|\
      ./evidence/client/activity.jsonl|\
      ./evidence/client/progress.jsonl|\
      ./evidence/client/failure.txt|\
      ./evidence/client/console.log|\
      ./evidence/server/result.txt|\
      ./evidence/server/process-exit.txt|\
      ./evidence/server/activity.jsonl|\
      ./evidence/server/progress.jsonl|\
      ./evidence/server/failure.txt|\
      ./evidence/server/console.log) ;;
      *) return 1 ;;
    esac
  done <<< "$members"
  if [[ "$mode" == complete ]]; then
    grep -Fqx './evidence/shared/report/summary.md' <<< "$members" || \
      return 1
    tar -xOzf "$archive_path" './evidence/shared/report/summary.md' |
      cmp -s -- - "$human_copy" || return 1
  fi
  if [[ "$mode" == complete &&
        -f "$run_directory/shared/report/summary.md" ]]; then
    cmp -s -- "$run_directory/shared/report/summary.md" "$human_copy" || \
      return 1
    if [[ "$archive_csv_present" == true ]]; then
      [[ -f "$run_directory/shared/report/summary.csv" &&
         ! -L "$run_directory/shared/report/summary.csv" ]] || return 1
      cmp -s -- "$run_directory/shared/report/summary.csv" "$csv_copy" || \
        return 1
    fi
  fi
}

# A completed prior invocation is a success, including after RUN was retired.
if [[ ! -e "$run_directory" && ! -L "$run_directory" ]]; then
  validate_existing_archive || \
    fail 'run is absent and no complete, valid evidence archive exists'
  clear_matching_pointer
  printf 'ARCHIVE PASS (existing): %s\n' "$archive_path"
  printf 'RETIRE PASS (already absent): %s\n' "$run_directory"
  exit 0
fi
[[ -d "$run_directory" && ! -L "$run_directory" ]] || \
  fail "run is missing or is a symlink: $run_directory"
canonical_run="$(cd -P -- "$run_directory" && pwd)"
[[ "$canonical_run" == "$run_directory" &&
   "${canonical_run%/*}" == "$canonical_runs" ]] || \
  fail 'RUN must be a canonical immediate child of ARTIFACT_ROOT/runs'
run_owner="$(stat_uid "$canonical_run")"
run_mode="$(stat_mode "$canonical_run")"
[[ "$run_owner" == "$(id -u)" && "$((8#$run_mode & 0022))" -eq 0 ]] || \
  fail "run must be owned by the current user and not group/world writable: $canonical_run"
[[ -d "$canonical_run/shared" && ! -L "$canonical_run/shared" ]] || \
  fail "run shared directory is missing or unsafe: $canonical_run/shared"
for role_directory in "$canonical_run/client" "$canonical_run/server"; do
  if [[ -e "$role_directory" || -L "$role_directory" ]]; then
    [[ -d "$role_directory" && ! -L "$role_directory" ]] || \
      fail "run role directory is unsafe: $role_directory"
  fi
done

# The lifecycle lock is shared by setup, client, server, status, and report
# rendering. Holding it exclusively makes the filesystem snapshot and final
# retirement atomic with respect to all protocol processes.
lifecycle="$canonical_run/shared/lifecycle.lock"
[[ -f "$lifecycle" && ! -L "$lifecycle" ]] || \
  fail "run lifecycle lock is missing or unsafe: $lifecycle"
[[ "$(stat_uid "$lifecycle")" == "$(id -u)" &&
   "$((8#$(stat_mode "$lifecycle") & 0077))" -eq 0 ]] || \
  fail "run lifecycle lock must be owner-only: $lifecycle"
exec 23>>"$lifecycle"
if ! flock -x -n 23; then
  fail 'run is active; wait for every setup/client/server/report reader to stop'
fi

# Check each role lock as well before retiring its files.
for activity in \
  "$canonical_run/shared/setup-activity.jsonl" \
  "$canonical_run/client/activity.jsonl" \
  "$canonical_run/server/activity.jsonl"; do
  [[ -e "$activity" || -L "$activity" ]] || continue
  [[ -f "$activity" && ! -L "$activity" ]] || \
    fail "activity record is unsafe: $activity"
  exec 22>>"$activity"
  if ! flock -x -n 22; then
    fail "run activity is still live: $activity"
  fi
  flock -u 22
  exec 22>&-
done

# The pointer chooses the deletion target, but its filename is not an identity
# boundary. Bind completion semantics to the immutable run record before
# deciding whether this is a Local or a client/server benchmark. Early failed
# setups may legitimately stop before publishing a binding; a completed setup
# may not.
binding="$canonical_run/shared/run-binding.txt"
binding_present=false
if [[ -e "$binding" || -L "$binding" ]]; then
  [[ -f "$binding" && ! -L "$binding" ]] || \
    fail "run binding is unsafe: $binding"
  [[ "$(stat_uid "$binding")" == "$(id -u)" &&
     "$((8#$(stat_mode "$binding") & 0077))" -eq 0 ]] || \
    fail "run binding must be owner-only: $binding"
  binding_id="$(sed -n 's/^run\.id=//p' "$binding")"
  [[ "$binding_id" =~ ^[0-9a-f]{64}$ ]] || \
    fail 'run binding has a noncanonical run id'
  expected_binding="$(printf '%s\n' \
    'format=laminate-benchmark-run-v1' \
    "run.variant=$selected_variant" \
    "run.profile=$selected_profile" \
    "run.id=$binding_id")"
  actual_binding="$(cat -- "$binding")"
  [[ "$actual_binding" == "$expected_binding" ]] || \
    fail 'current-run pointer namespace disagrees with the immutable run binding'
  binding_present=true
fi
if [[ "$binding_present" != true ]] &&
   grep -Fqx -- 'setup.result=PASS' \
     "$canonical_run/shared/setup-result.txt" 2>/dev/null; then
  fail 'a completed setup is missing its immutable run binding'
fi
if [[ "$selected_variant" == laned &&
      -f "$canonical_run/shared/setup-result.txt" ]]; then
  setup_lanes="$(sed -n 's/^geometry\.B=//p' \
    "$canonical_run/shared/setup-result.txt")"
  if [[ ! "$setup_lanes" =~ ^(1|128|16384)$ ||
        "$setup_lanes" != "$selected_lanes" ]]; then
    fail 'Laned current-run pointer disagrees with setup geometry.B'
  fi
fi

run_is_complete=false
if grep -Fqx -- 'setup.result=PASS' \
     "$canonical_run/shared/setup-result.txt" 2>/dev/null &&
   grep -Fqx -- 'process.exit_status=0' \
     "$canonical_run/shared/setup-process-exit.txt" 2>/dev/null; then
  if [[ "$selected_variant" == local ]]; then
    if grep -Fqx -- 'client.result=PASS' \
         "$canonical_run/client/result.txt" 2>/dev/null &&
       grep -Fqx -- 'process.exit_status=0' \
         "$canonical_run/client/process-exit.txt" 2>/dev/null; then
      run_is_complete=true
    fi
  elif grep -Fqx -- 'server.result=PASS' \
         "$canonical_run/server/result.txt" 2>/dev/null &&
       grep -Fqx -- 'process.exit_status=0' \
         "$canonical_run/server/process-exit.txt" 2>/dev/null &&
       grep -Fqx -- 'verification.result=PASS' \
         "$canonical_run/client/result.txt" 2>/dev/null &&
       grep -Fqx -- 'process.exit_status=0' \
         "$canonical_run/client/process-exit.txt" 2>/dev/null; then
    run_is_complete=true
  fi
fi

if [[ "$mode" == complete ]]; then
  [[ "$binding_present" == true ]] || \
    fail 'completed run is missing its immutable run binding'
  if [[ "$selected_variant" == local &&
        ( -e "$canonical_run/server" || -L "$canonical_run/server" ||
          -e "$canonical_run/shared/transcript" ||
          -L "$canonical_run/shared/transcript" ) ]]; then
    fail 'completed Local run contains forbidden server or transcript artifacts'
  fi
  [[ "$run_is_complete" == true ]] || \
    fail 'run is not complete and accepted; use explicit failed-run retirement if it is abandoned'
  [[ -f "$canonical_run/shared/report/summary.md" &&
     ! -L "$canonical_run/shared/report/summary.md" ]] || \
    fail 'render shared/report/summary.md before archiving the completed run'
else
  [[ "$run_is_complete" != true ]] || \
    fail 'run completed successfully; use normal completed-run retirement'
  [[ -f "$current_pointer" && ! -L "$current_pointer" ]] || \
    fail 'failed-run retirement requires an existing current-run pointer'
  pointer_run=''
  IFS= read -r pointer_run < "$current_pointer" || true
  [[ "$pointer_run" == "$canonical_run" ]] || \
    fail 'failed-run retirement is restricted to the exact current run'
  if [[ ! -e "$canonical_run/shared/setup-activity.jsonl" &&
        ! -e "$canonical_run/shared/setup-failure.txt" &&
        ! -e "$canonical_run/shared/setup-process-exit.txt" &&
        ! -e "$canonical_run/client/activity.jsonl" &&
        ! -e "$canonical_run/client/failure.txt" &&
        ! -e "$canonical_run/client/process-exit.txt" &&
        ! -e "$canonical_run/server/activity.jsonl" &&
        ! -e "$canonical_run/server/failure.txt" &&
        ! -e "$canonical_run/server/process-exit.txt" ]]; then
    fail 'run has no role-attempt evidence and cannot be classified as failed or abandoned'
  fi
fi

# Do not let an accidental nested mount turn retirement into a cross-device
# recursive deletion.
mount_targets="$(findmnt -rn -o TARGET)" || \
  fail 'cannot inspect nested mount points before retirement'
while IFS= read -r mounted_path; do
  # `findmnt` canonicalizes TARGET paths by default. Compare those paths
  # directly instead of entering every mount on the host: ordinary users may
  # not traverse unrelated kernel mounts such as /sys/fs/pstore. A target
  # lexically inside the already-canonical run still fails closed, even when
  # that nested mount itself is inaccessible.
  [[ -n "$mounted_path" ]] || continue
  if [[ "$mounted_path" == "$canonical_run" ||
        "$mounted_path" == "$canonical_run/"* ]]; then
    fail "refusing to retire a run containing a mount point: $mounted_path"
  fi
done <<< "$mount_targets"

# This exact allowlist includes the optional public recovery provenance record,
# and excludes private preprocessing, requests, responses, proof bytes, replay
# checkpoints, and every server work file.
readonly -a evidence_allowlist=(
  shared/setup-result.txt
  shared/setup-process-exit.txt
  shared/setup-activity.jsonl
  shared/setup-failure.txt
  shared/run-binding.txt
  shared/recovery-source-setup.bin
  shared/storage-provenance.setup-start.txt
  shared/storage-provenance.server-start.txt
  shared/report/summary.md
  client/result.txt
  client/process-exit.txt
  client/activity.jsonl
  client/progress.jsonl
  client/failure.txt
  client/console.log
  server/result.txt
  server/process-exit.txt
  server/activity.jsonl
  server/progress.jsonl
  server/failure.txt
  server/console.log
)

staging_directory=''
archive_temporary="${archive_path}.tmp.$$"
checksum_temporary="${checksum_path}.tmp.$$"
human_temporary="${human_copy}.tmp.$$"
cleanup_temporary() {
  [[ -z "$staging_directory" ]] || rm -rf -- "$staging_directory"
  rm -f -- "$archive_temporary" "$checksum_temporary" "$human_temporary"
}
trap cleanup_temporary EXIT

if validate_existing_archive; then
  printf 'ARCHIVE PASS (existing): %s\n' "$archive_path"
else
  if [[ -e "$archive_path" || -L "$archive_path" ||
        -e "$checksum_path" || -L "$checksum_path" ||
        -e "$human_copy" || -L "$human_copy" ]]; then
    fail "partial or invalid prior archive exists for this run: $archive_path"
  fi

  staging_directory="$(mktemp -d "$canonical_archive/.${run_name}.archive.XXXXXX")"
  mkdir -p "$staging_directory/evidence"
  selected_bytes=0
  selected_files=0
  : > "$staging_directory/retained-files-and-bytes.tsv"
  for relative_path in "${evidence_allowlist[@]}"; do
    source_file="$canonical_run/$relative_path"
    [[ -e "$source_file" || -L "$source_file" ]] || continue
    [[ -f "$source_file" && ! -L "$source_file" ]] || \
      fail "allowlisted evidence is not a safe regular file: $source_file"
    file_bytes="$(stat_bytes "$source_file")"
    [[ "$file_bytes" =~ ^(0|[1-9][0-9]*)$ ]] || \
      fail "cannot determine evidence size: $source_file"
    ((file_bytes <= evidence_file_limit_bytes)) || \
      fail "one evidence file exceeds the 125 MB archive bound: $source_file"
    selected_bytes=$((selected_bytes + file_bytes))
    ((selected_bytes <= evidence_limit_bytes)) || \
      fail 'allowlisted evidence exceeds the 250 MB per-run archive bound'
    selected_files=$((selected_files + 1))
    mkdir -p -- "$staging_directory/evidence/${relative_path%/*}"
    cp -p -- "$source_file" "$staging_directory/evidence/$relative_path"
    printf '%s\t%s\n' "$relative_path" "$file_bytes" \
      >> "$staging_directory/retained-files-and-bytes.tsv"
  done

  setup_console="$canonical_artifact/logs/${run_name}.setup.log"
  if [[ -e "$setup_console" || -L "$setup_console" ]]; then
    [[ -f "$setup_console" && ! -L "$setup_console" ]] || \
      fail "setup console is not a safe regular file: $setup_console"
    file_bytes="$(stat_bytes "$setup_console")"
    ((file_bytes <= evidence_file_limit_bytes)) || \
      fail 'setup console exceeds the 125 MB archive bound'
    selected_bytes=$((selected_bytes + file_bytes))
    ((selected_bytes <= evidence_limit_bytes)) || \
      fail 'allowlisted evidence exceeds the 250 MB per-run archive bound'
    selected_files=$((selected_files + 1))
    mkdir -p "$staging_directory/evidence/shared"
    cp -p -- "$setup_console" \
      "$staging_directory/evidence/shared/setup-console.log"
    printf 'shared/setup-console.log\t%s\n' "$file_bytes" \
      >> "$staging_directory/retained-files-and-bytes.tsv"
  fi

  if [[ "$mode" == complete ]]; then
    cp -p -- "$canonical_run/shared/report/summary.md" "$human_temporary"
  else
    {
      printf '# Retired failed or abandoned Laminate run\n\n'
      printf -- '- Original run: `%s`\n' "$canonical_run"
      printf -- '- Retired at: `%s`\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf -- '- Retained evidence files: `%s`\n' "$selected_files"
      printf -- '- Retained evidence bytes: `%s`\n' "$selected_bytes"
      printf '%s\n' \
        '- Large preprocessing, transcript, request, response, proof, replay, and work artifacts were intentionally retired.'
      printf '%s\n' \
        '- Inspect the adjacent failed-evidence archive for the terminal result, activity, progress, failure, and console records that existed.'
    } > "$human_temporary"
  fi
  chmod 0600 "$human_temporary"

  {
    printf 'Laminate bounded run-evidence archive\n'
    printf 'archive_mode=%s\n' "$mode"
    printf 'original_run=%s\n' "$canonical_run"
    printf 'archived_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'retained_file_count=%s\n' "$selected_files"
    printf 'retained_bytes=%s\n' "$selected_bytes"
    printf 'retained_limit_bytes=%s\n' "$evidence_limit_bytes"
    printf '%s\n' \
      'Only the repository-defined evidence allowlist is retained.'
  } > "$staging_directory/README.txt"

  archive_capacity="$(laminate_read_filesystem_capacity "$canonical_archive")" || \
    fail 'cannot determine durable archive filesystem capacity'
  read -r _archive_total archive_available <<< "$archive_capacity"
  required_available=$((selected_bytes * 2 + archive_free_space_reserve_bytes))
  ((archive_available >= required_available)) || \
    fail "durable archive filesystem has $archive_available free bytes; $required_available are required"

  tar -C "$staging_directory" -czf "$archive_temporary" .
  chmod 0600 "$archive_temporary"
  archive_output_bytes="$(stat_bytes "$archive_temporary")"
  ((archive_output_bytes <= evidence_limit_bytes)) || \
    fail 'compressed evidence archive exceeds the 250 MB per-run bound'
  tar -tzf "$archive_temporary" >/dev/null
  mv -- "$archive_temporary" "$archive_path"
  printf '%s  %s\n' "$(sha256_digest "$archive_path")" \
    "${archive_path##*/}" > "$checksum_temporary"
  chmod 0600 "$checksum_temporary"
  mv -- "$checksum_temporary" "$checksum_path"
  mv -- "$human_temporary" "$human_copy"
  sync_directory "$canonical_archive"
  printf 'ARCHIVE PASS: %s\n' "$archive_path"
  printf 'HUMAN COPY: %s\n' "$human_copy"
fi

rm -rf -- "$canonical_run"
setup_console="$canonical_artifact/logs/${run_name}.setup.log"
if [[ -f "$setup_console" && ! -L "$setup_console" ]]; then
  rm -f -- "$setup_console"
fi
clear_matching_pointer
sync_directory "$canonical_runs"
sync_directory "$canonical_artifact"

trap - EXIT
cleanup_temporary
printf 'RETIRE PASS: removed inactive benchmark run %s\n' "$canonical_run"
