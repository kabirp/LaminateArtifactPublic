#!/usr/bin/env bash

# Coordination primitives for one measured client/server campaign. The caller
# supplies artifact_root, campaign_binding_lock, campaign_binding_file, and
# run_directory before invoking these functions.
#
# The runner requires Bash with mapfile, Linux `flock`, and GNU `readlink -f`.
# Fixed descriptor roles are shared across the functions: 20 is the per-run
# campaign lease, 21 serializes the root binding, 22 probes an existing lease,
# and 23 owns one immutable role attempt.

measurement_campaign_lease_fd=''
measurement_campaign_run=''
measurement_role_attempt_fd=''
measurement_role_attempt_run=''
measurement_role_attempt_role=''

read_measurement_campaign_binding() {
  local destination="$1"
  local -a lines=()
  if ! mapfile -t lines < "$campaign_binding_file"; then
    printf 'ERROR: cannot read measured-campaign binding: %s\n' \
      "$campaign_binding_file" >&2
    return 1
  fi
  if [[ "${#lines[@]}" -ne 1 || "${lines[0]}" != /* ]]; then
    printf 'ERROR: measured-campaign binding is malformed: %s\n' \
      "$campaign_binding_file" >&2
    return 1
  fi
  printf -v "$destination" '%s' "${lines[0]}"
}

measurement_campaign_is_active() {
  local bound_run="$1"
  local lease="$bound_run/shared/measurement-campaign.lock"
  [[ -f "$lease" ]] || return 1
  if ! exec 22<"$lease"; then
    printf 'ERROR: cannot inspect measured-campaign lease: %s\n' \
      "$lease" >&2
    return 2
  fi
  if flock -x -n 22; then
    flock -u 22 || true
    exec 22>&-
    return 1
  fi
  exec 22>&-
  return 0
}

abandon_measurement_campaign_acquire() {
  local binding_open="${1:-false}"
  if [[ "$binding_open" == true ]]; then
    flock -u 21 2>/dev/null || true
    exec 21>&-
  fi
  if [[ -n "$measurement_campaign_lease_fd" ]]; then
    flock -u "$measurement_campaign_lease_fd" 2>/dev/null || true
    exec 20>&-
    measurement_campaign_lease_fd=''
  fi
}

acquire_measurement_campaign() {
  local canonical_run
  canonical_run="$(readlink -f -- "$run_directory")" || {
    printf 'ERROR: cannot resolve benchmark run path: %s\n' \
      "$run_directory" >&2
    return 1
  }
  if [[ "$canonical_run" == *$'\n'* ||
        ! -d "$canonical_run/shared" ]]; then
    printf 'ERROR: benchmark run has an invalid shared directory: %s\n' \
      "$canonical_run" >&2
    return 1
  fi

  local lease="$canonical_run/shared/measurement-campaign.lock"
  if ! exec 20>>"$lease"; then
    printf 'ERROR: cannot open the run measurement lease: %s\n' \
      "$lease" >&2
    measurement_campaign_lease_fd=''
    return 1
  fi
  measurement_campaign_lease_fd=20
  if ! flock -s "$measurement_campaign_lease_fd"; then
    printf 'ERROR: cannot lock the run measurement lease: %s\n' \
      "$lease" >&2
    abandon_measurement_campaign_acquire
    return 1
  fi

  if ! exec 21>"$campaign_binding_lock"; then
    printf 'ERROR: cannot open measured-campaign binding lock: %s\n' \
      "$campaign_binding_lock" >&2
    abandon_measurement_campaign_acquire
    return 1
  fi
  if ! flock -x 21; then
    printf 'ERROR: cannot lock measured-campaign binding: %s\n' \
      "$campaign_binding_lock" >&2
    exec 21>&-
    abandon_measurement_campaign_acquire
    return 1
  fi

  local bound_run=''
  if [[ -e "$campaign_binding_file" ]]; then
    if ! read_measurement_campaign_binding bound_run; then
      abandon_measurement_campaign_acquire true
      return 1
    fi
    if [[ "$bound_run" != "$canonical_run" ]]; then
      local active_status=0
      measurement_campaign_is_active "$bound_run" || active_status=$?
      if [[ "$active_status" -eq 0 ]]; then
        printf '%s\n' \
          'ERROR: a measured client/server campaign from another run is active.' >&2
        printf '  Active run:    %s\n  Requested run: %s\n' \
          "$bound_run" "$canonical_run" >&2
        printf '%s\n' \
          'Wait for both roles in the active run to finish; cross-run overlap would contaminate timings.' >&2
        abandon_measurement_campaign_acquire true
        return 1
      fi
      if [[ "$active_status" -ne 1 ]]; then
        abandon_measurement_campaign_acquire true
        return 1
      fi
      if ! rm -f -- "$campaign_binding_file"; then
        printf 'ERROR: cannot retire stale measured-campaign binding: %s\n' \
          "$campaign_binding_file" >&2
        abandon_measurement_campaign_acquire true
        return 1
      fi
    fi
  fi

  if [[ ! -e "$campaign_binding_file" ]]; then
    local temporary="${campaign_binding_file}.tmp.$$.$RANDOM"
    if ! printf '%s\n' "$canonical_run" > "$temporary" ||
       ! mv -f -- "$temporary" "$campaign_binding_file"; then
      rm -f -- "$temporary" 2>/dev/null || true
      printf 'ERROR: cannot publish measured-campaign binding: %s\n' \
        "$campaign_binding_file" >&2
      abandon_measurement_campaign_acquire true
      return 1
    fi
  fi

  local confirmed_run=''
  if ! read_measurement_campaign_binding confirmed_run ||
     [[ "$confirmed_run" != "$canonical_run" ]]; then
    printf 'ERROR: measured-campaign binding does not name the requested run: %s\n' \
      "$campaign_binding_file" >&2
    abandon_measurement_campaign_acquire true
    return 1
  fi
  measurement_campaign_run="$canonical_run"
  flock -u 21 || true
  exec 21>&-
}

release_measurement_campaign() {
  [[ -n "$measurement_campaign_lease_fd" ]] || return 0
  flock -u "$measurement_campaign_lease_fd" || true
  exec 20>&-
  measurement_campaign_lease_fd=''

  if ! exec 21>"$campaign_binding_lock"; then
    printf 'ERROR: cannot reopen measured-campaign binding lock: %s\n' \
      "$campaign_binding_lock" >&2
    return 1
  fi
  if ! flock -x 21; then
    printf 'ERROR: cannot relock measured-campaign binding: %s\n' \
      "$campaign_binding_lock" >&2
    exec 21>&-
    return 1
  fi
  local bound_run=''
  if [[ -e "$campaign_binding_file" ]]; then
    if ! read_measurement_campaign_binding bound_run; then
      flock -u 21 || true
      exec 21>&-
      return 1
    fi
    if [[ "$bound_run" == "$measurement_campaign_run" ]]; then
      local active_status=0
      measurement_campaign_is_active "$bound_run" || active_status=$?
      if [[ "$active_status" -eq 1 ]]; then
        if ! rm -f -- "$campaign_binding_file"; then
          printf 'ERROR: cannot retire measured-campaign binding: %s\n' \
            "$campaign_binding_file" >&2
          flock -u 21 || true
          exec 21>&-
          return 1
        fi
      elif [[ "$active_status" -ne 0 ]]; then
        flock -u 21 || true
        exec 21>&-
        return 1
      fi
    fi
  fi
  measurement_campaign_run=''
  flock -u 21 || true
  exec 21>&-
}

acquire_measurement_role_attempt() {
  local role="$1"
  case "$role" in
    client|server) ;;
    *)
      printf 'ERROR: invalid measured role: %s\n' "$role" >&2
      return 1
      ;;
  esac
  local canonical_run
  canonical_run="$(readlink -f -- "$run_directory")" || {
    printf 'ERROR: cannot resolve benchmark run path: %s\n' \
      "$run_directory" >&2
    return 1
  }
  if [[ ! -d "$canonical_run/shared" ]]; then
    printf 'ERROR: benchmark run has no shared directory: %s\n' \
      "$canonical_run" >&2
    return 1
  fi
  local lock="$canonical_run/shared/${role}-measurement-attempt.lock"
  if ! exec 23>>"$lock"; then
    printf 'ERROR: cannot open %s role-attempt lock: %s\n' \
      "$role" "$lock" >&2
    measurement_role_attempt_fd=''
    return 1
  fi
  measurement_role_attempt_fd=23
  if ! flock -x -n "$measurement_role_attempt_fd"; then
    printf 'ERROR: another %s launcher already owns this run attempt.\n' \
      "$role" >&2
    exec 23>&-
    measurement_role_attempt_fd=''
    return 1
  fi
  measurement_role_attempt_run="$canonical_run"
  measurement_role_attempt_role="$role"
}

release_measurement_role_attempt() {
  [[ -n "$measurement_role_attempt_fd" ]] || return 0
  flock -u "$measurement_role_attempt_fd" || true
  exec 23>&-
  measurement_role_attempt_fd=''
  measurement_role_attempt_run=''
  measurement_role_attempt_role=''
}
