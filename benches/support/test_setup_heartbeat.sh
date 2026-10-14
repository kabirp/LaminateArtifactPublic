#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s SETUP_HEARTBEAT_LIBRARY\n' "$0" >&2
  exit 2
fi

source "$1"

fixture_root="$(mktemp -d)"
monitor_pid=''
cleanup_test() {
  if [[ -n "$monitor_pid" ]]; then
    kill "$monitor_pid" 2>/dev/null || true
    wait "$monitor_pid" 2>/dev/null || true
  fi
  rm -rf -- "$fixture_root"
}
trap cleanup_test EXIT

mkdir -p "$fixture_root/shared"
activity="$fixture_root/shared/setup-activity.jsonl"
printf '%s\n' \
  '{"schema":"laminate-role-activity-v1","role":"setup","event":"stage","stage":"schedule_preflight","pid":4242,"unix_ms":1700000000000}' \
  > "$activity"

setup_heartbeat_now_seconds() {
  printf '1700000072\n'
}
setup_heartbeat_observed_at() {
  printf '2026-08-24T18:04:00Z\n'
}
setup_heartbeat_process_snapshot() {
  if [[ "$1" != 7 || "$2" != 4242 ]]; then
    return 1
  fi
  printf '300 00:04:58 99.3 1263000 R 1500000\n'
}

heartbeat="$(emit_setup_heartbeat "$fixture_root" 7)"
for expected in \
  'at=2026-08-24T18:04:00Z' \
  'elapsed=00:05:00' \
  'cpu=00:04:58' \
  'avg_cpu=99.3%' \
  'rss=1234 MiB' \
  'peak_rss=1465 MiB' \
  'state=R' \
  'phase="schedule preflight"' \
  'phase_age=00:01:12'; do
  if [[ "$heartbeat" != *"$expected"* ]]; then
    printf 'heartbeat is missing %s:\n%s\n' "$expected" "$heartbeat" >&2
    exit 1
  fi
done

# Liveness telemetry must not reset the age of the underlying setup phase.
printf '%s\n' \
  '{"schema":"laminate-role-activity-v1","role":"setup","event":"heartbeat","stage":"schedule_preflight","pid":4242,"unix_ms":1700000060000}' \
  >> "$activity"
telemetry_heartbeat="$(emit_setup_heartbeat "$fixture_root" 7)"
if [[ "$telemetry_heartbeat" != *'phase_age=00:01:12'* ]]; then
  printf 'telemetry reset setup phase age:\n%s\n' \
    "$telemetry_heartbeat" >&2
  exit 1
fi

# A concurrent partial append must not hide the preceding complete transition
# record or make its setup PID disappear.
printf '%s' '{"schema":"laminate-role-activity-v1","role":"setup"' \
  >> "$activity"
partial_heartbeat="$(emit_setup_heartbeat "$fixture_root" 7)"
if [[ "$partial_heartbeat" != *'phase="schedule preflight"'* ||
      "$partial_heartbeat" == *'process not observed'* ]]; then
  printf 'partial activity append corrupted the heartbeat:\n%s\n' \
    "$partial_heartbeat" >&2
  exit 1
fi

# The server observer must be useful before progress.jsonl exists. Its elapsed
# time is the whole role lifetime; its phase age is the latest stage transition.
mkdir -p "$fixture_root/server"
server_activity="$fixture_root/server/activity.jsonl"
printf '%s\n' \
  '{"schema":"laminate-role-activity-v1","role":"server","event":"start","stage":"starting","pid":4343,"unix_ms":1700000000000}' \
  '{"schema":"laminate-role-activity-v1","role":"server","event":"stage","stage":"loading_preprocessing","pid":4343,"unix_ms":1700000060000}' \
  '{"schema":"laminate-role-activity-v1","role":"server","event":"heartbeat","stage":"loading_preprocessing","pid":4343,"unix_ms":1700000120000}' \
  > "$server_activity"
server_heartbeat_now_seconds() {
  printf '1700000125\n'
}
server_heartbeat_observed_at() {
  printf '2026-08-25T02:13:38Z\n'
}
server_heartbeat_process_snapshot() {
  if [[ "$1" != 7 || "$2" != 4343 ]]; then
    return 1
  fi
  printf '125 00:02:03 98.4 130000 R+ 160000\n'
}
if [[ -e "$fixture_root/server/progress.jsonl" ]]; then
  printf 'server heartbeat fixture unexpectedly has progress telemetry\n' >&2
  exit 1
fi
server_heartbeat="$(emit_server_heartbeat "$fixture_root" 7)"
for expected in \
  'SERVER HEARTBEAT:' \
  'at=2026-08-25T02:13:38Z' \
  'elapsed=00:02:05' \
  'cpu=00:02:03' \
  'avg_cpu=98.4%' \
  'rss=127 MiB' \
  'peak_rss=157 MiB' \
  'state=R+' \
  'phase="loading preprocessing"' \
  'phase_age=00:01:05'; do
  if [[ "$server_heartbeat" != *"$expected"* ]]; then
    printf 'server heartbeat is missing %s:\n%s\n' \
      "$expected" "$server_heartbeat" >&2
    exit 1
  fi
done

monitor_output="$fixture_root/monitor.out"
setup_heartbeat_loop "$fixture_root" 7 1 > "$monitor_output" &
monitor_pid="$!"
for _ in {1..50}; do
  heartbeat_count="$(
    grep -c '^SETUP HEARTBEAT:' "$monitor_output" 2>/dev/null || true
  )"
  if [[ "$heartbeat_count" -ge 3 ]]; then
    break
  fi
  sleep 0.1
done
heartbeat_count="$(
  grep -c '^SETUP HEARTBEAT:' "$monitor_output" 2>/dev/null || true
)"
if [[ "$heartbeat_count" -lt 3 ]]; then
  printf 'periodic heartbeat did not produce repeated output:\n' >&2
  sed -n '1,20p' "$monitor_output" >&2
  exit 1
fi

timer_pid=''
if command -v pgrep >/dev/null 2>&1; then
  timer_pid="$(pgrep -P "$monitor_pid" 2>/dev/null | head -n 1 || true)"
fi
kill "$monitor_pid"
wait "$monitor_pid" 2>/dev/null || true
monitor_pid=''
if [[ -n "$timer_pid" ]] && kill -0 "$timer_pid" 2>/dev/null; then
  printf 'heartbeat monitor left its timer process running: %s\n' \
    "$timer_pid" >&2
  exit 1
fi
