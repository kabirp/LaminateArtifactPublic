#!/usr/bin/env bash

# Read-only role-observation helpers. The caller owns process placement and
# passes the immutable run path, observer CPU, and reporting interval.

format_heartbeat_elapsed_seconds() {
  local total_seconds="$1"
  printf '%02d:%02d:%02d' \
    "$((total_seconds / 3600))" \
    "$(((total_seconds / 60) % 60))" \
    "$((total_seconds % 60))"
}

format_setup_elapsed_seconds() {
  format_heartbeat_elapsed_seconds "$1"
}

setup_heartbeat_now_seconds() {
  date +%s
}

setup_heartbeat_observed_at() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

setup_heartbeat_process_snapshot() {
  local observer_cpu="$1"
  local setup_pid="$2"
  local snapshot
  snapshot="$(env LC_ALL=C taskset -c "$observer_cpu" \
    ps -p "$setup_pid" -o etimes=,time=,pcpu=,rss=,stat= \
    2>/dev/null || true)"
  if [[ -z "$snapshot" ]]; then
    return 0
  fi
  local peak_rss_kib=''
  if [[ -r "/proc/$setup_pid/status" ]]; then
    peak_rss_kib="$(
      env LC_ALL=C taskset -c "$observer_cpu" \
        awk '$1 == "VmHWM:" { print $2; exit }' "/proc/$setup_pid/status" \
          2>/dev/null || true
    )"
  fi
  printf '%s %s\n' "$snapshot" "${peak_rss_kib:-0}"
}

server_heartbeat_now_seconds() {
  date +%s
}

server_heartbeat_observed_at() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

server_heartbeat_process_snapshot() {
  local observer_cpu="$1"
  local server_pid="$2"
  local snapshot
  snapshot="$(env LC_ALL=C taskset -c "$observer_cpu" \
    ps -p "$server_pid" -o etimes=,time=,pcpu=,rss=,stat= \
    2>/dev/null || true)"
  if [[ -z "$snapshot" ]]; then
    return 0
  fi
  local peak_rss_kib=''
  if [[ -r "/proc/$server_pid/status" ]]; then
    peak_rss_kib="$(
      env LC_ALL=C taskset -c "$observer_cpu" \
        awk '$1 == "VmHWM:" { print $2; exit }' "/proc/$server_pid/status" \
          2>/dev/null || true
    )"
  fi
  printf '%s %s\n' "$snapshot" "${peak_rss_kib:-0}"
}

emit_role_heartbeat() {
  local run_directory="$1"
  local role="$2"
  local observer_cpu="$3"
  local now_function="$4"
  local observed_at_function="$5"
  local process_snapshot_function="$6"
  local label='ROLE HEARTBEAT'
  case "$role" in
    setup) label='SETUP HEARTBEAT' ;;
    client) label='CLIENT HEARTBEAT' ;;
    server) label='SERVER HEARTBEAT' ;;
  esac
  local activity="$run_directory/$role/activity.jsonl"
  if [[ "$role" == setup ]]; then
    activity="$run_directory/shared/setup-activity.jsonl"
  fi
  if [[ ! -f "$activity" ]]; then
    printf '%s: waiting for %s activity at %s\n' \
      "$label" "$role" "$activity"
    return 0
  fi

  # Ignore both incomplete appends and periodic telemetry heartbeats. Phase age
  # starts at the latest actual transition, not at the latest liveness record.
  # Every valid start/stage RoleActivity record contains all three fields.
  local latest
  latest="$(
    awk '
      /^\{.*"event":"(start|stage)".*"stage":"[^"]+".*"pid":[0-9]+.*"unix_ms":[0-9]+\}$/ {
        latest = $0
      }
      END { if (latest != "") print latest }
    ' "$activity" 2>/dev/null || true
  )"
  local first_start
  first_start="$(
    awk '
      /^\{.*"event":"start".*"stage":"[^"]+".*"pid":[0-9]+.*"unix_ms":[0-9]+\}$/ {
        print
        exit
      }
    ' "$activity" 2>/dev/null || true
  )"
  local stage_pattern='"stage":"([^"]+)"'
  local pid_pattern='"pid":([0-9]+)'
  local time_pattern='"unix_ms":([0-9]+)'
  local stage='starting'
  local role_pid=''
  local event_unix_ms=''
  local started_unix_ms=''
  if [[ "$latest" =~ $stage_pattern ]]; then
    stage="${BASH_REMATCH[1]}"
  fi
  if [[ "$latest" =~ $pid_pattern ]]; then
    role_pid="${BASH_REMATCH[1]}"
  fi
  if [[ "$latest" =~ $time_pattern ]]; then
    event_unix_ms="${BASH_REMATCH[1]}"
  fi
  if [[ "$first_start" =~ $time_pattern ]]; then
    started_unix_ms="${BASH_REMATCH[1]}"
  fi
  stage="${stage//_/ }"

  local now_seconds
  now_seconds="$("$now_function")"
  local phase_age='unknown'
  if [[ "$event_unix_ms" =~ ^[0-9]+$ ]]; then
    local event_seconds age_seconds
    event_seconds="$((event_unix_ms / 1000))"
    if [[ "$now_seconds" =~ ^[0-9]+$ ]] &&
       ((now_seconds >= event_seconds)); then
      age_seconds="$((now_seconds - event_seconds))"
      phase_age="$(format_heartbeat_elapsed_seconds "$age_seconds")"
    fi
  fi

  local observed_at
  observed_at="$("$observed_at_function")"
  local process_snapshot=''
  if [[ "$role_pid" =~ ^[1-9][0-9]*$ ]]; then
    process_snapshot="$(
      "$process_snapshot_function" "$observer_cpu" "$role_pid"
    )"
  fi
  if [[ -z "$process_snapshot" ]]; then
    printf '%s: at=%s process not observed; phase="%s" phase_age=%s\n' \
      "$label" "$observed_at" "$stage" "$phase_age"
    return 0
  fi

  local elapsed_seconds cpu_time average_cpu rss_kib process_state peak_rss_kib
  read -r elapsed_seconds cpu_time average_cpu rss_kib process_state \
    peak_rss_kib \
    <<< "$process_snapshot"
  if [[ ! "$elapsed_seconds" =~ ^[0-9]+$ ||
        ! "$rss_kib" =~ ^[0-9]+$ ]]; then
    printf '%s: at=%s process metrics unavailable; phase="%s" phase_age=%s\n' \
      "$label" "$observed_at" "$stage" "$phase_age"
    return 0
  fi
  if [[ "$started_unix_ms" =~ ^[0-9]+$ &&
        "$now_seconds" =~ ^[0-9]+$ ]]; then
    local started_seconds="$((started_unix_ms / 1000))"
    if ((now_seconds >= started_seconds)); then
      elapsed_seconds="$((now_seconds - started_seconds))"
    fi
  fi
  local rss_mib="$(((rss_kib + 1023) / 1024))"
  if [[ ! "$peak_rss_kib" =~ ^[1-9][0-9]*$ ]]; then
    peak_rss_kib="$rss_kib"
  fi
  local peak_rss_mib="$(((peak_rss_kib + 1023) / 1024))"
  printf '%s: at=%s elapsed=%s cpu=%s avg_cpu=%s%% rss=%s MiB peak_rss=%s MiB state=%s phase="%s" phase_age=%s\n' \
    "$label" "$observed_at" \
    "$(format_heartbeat_elapsed_seconds "$elapsed_seconds")" \
    "$cpu_time" "$average_cpu" "$rss_mib" "$peak_rss_mib" \
    "$process_state" \
    "$stage" "$phase_age"
}

emit_setup_heartbeat() {
  emit_role_heartbeat \
    "$1" setup "$2" \
    setup_heartbeat_now_seconds \
    setup_heartbeat_observed_at \
    setup_heartbeat_process_snapshot
}

emit_server_heartbeat() {
  emit_role_heartbeat \
    "$1" server "$2" \
    server_heartbeat_now_seconds \
    server_heartbeat_observed_at \
    server_heartbeat_process_snapshot
}

setup_heartbeat_loop() {
  local run_directory="$1"
  local observer_cpu="$2"
  local follow_seconds="$3"
  local activity="$run_directory/shared/setup-activity.jsonl"
  local setup_result="$run_directory/shared/setup-result.txt"
  local setup_failure="$run_directory/shared/setup-failure.txt"
  local sleep_pid=''
  cleanup_setup_heartbeat_sleep() {
    if [[ -n "$sleep_pid" ]]; then
      kill "$sleep_pid" 2>/dev/null || true
      wait "$sleep_pid" 2>/dev/null || true
      sleep_pid=''
    fi
  }
  trap 'cleanup_setup_heartbeat_sleep; exit 0' TERM INT HUP
  printf 'SETUP HEARTBEAT: observer active on CPU %s; interval=%s seconds\n' \
    "$observer_cpu" "$follow_seconds"
  while [[ ! -f "$activity" && ! -f "$setup_result" &&
           ! -f "$setup_failure" ]]; do
    sleep 1 &
    sleep_pid="$!"
    wait "$sleep_pid" || true
    sleep_pid=''
  done
  while [[ ! -f "$setup_result" && ! -f "$setup_failure" ]]; do
    emit_setup_heartbeat "$run_directory" "$observer_cpu"
    sleep "$follow_seconds" &
    sleep_pid="$!"
    wait "$sleep_pid" || true
    sleep_pid=''
  done
}
