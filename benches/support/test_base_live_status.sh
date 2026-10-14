#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s BASE_CHECKPOINT_BENCHMARK\n' "$0" >&2
  exit 2
fi

benchmark="$1"
fixture_root="$(mktemp -d)"
lock_pid=''
cleanup_test() {
  if [[ -n "$lock_pid" ]]; then
    kill "$lock_pid" 2>/dev/null || true
    wait "$lock_pid" 2>/dev/null || true
  fi
  rm -rf -- "$fixture_root"
}
trap cleanup_test EXIT

mkdir -p "$fixture_root/shared" "$fixture_root/server"
chmod 700 "$fixture_root" "$fixture_root/shared" "$fixture_root/server"
activity="$fixture_root/server/activity.jsonl"
progress="$fixture_root/server/progress.jsonl"

run_incomplete_status() {
  local output_path="$1"
  local expected_status="$2"
  local status=0
  "$benchmark" status \
    --variant base \
    --profile quick \
    --run-dir "$fixture_root" > "$output_path" 2>&1 || status=$?
  if [[ "$status" -ne "$expected_status" ]]; then
    printf 'fixture status should be %s, got %s:\n' \
      "$expected_status" "$status" >&2
    sed -n '1,120p' "$output_path" >&2
    exit 1
  fi
}

printf '%s\n' \
  '{"schema":"laminate-role-activity-v1","role":"server","event":"start","stage":"starting","pid":4242,"unix_ms":1700000000000}' \
  '{"schema":"laminate-role-activity-v1","role":"server","event":"stage","stage":"payload_execution_preflight","pid":4242,"unix_ms":1700000060000}' \
  > "$activity"
printf '%s\n' \
  '{"schema":"laminate-base-progress-v1","seq":0,"event":"run-status","status":"started","run_elapsed_ms":0.000}' \
  '{"schema":"laminate-base-progress-v1","seq":1,"event":"begin","stage":"server_payload_execution_preflight","run_elapsed_ms":1000.000}' \
  > "$progress"
chmod 600 "$activity" "$progress"

# Status identifies a live role through the same advisory lock used by the
# process runner. Linux benchmark hosts provide flock(1); the macOS developer
# test fallback uses Python's direct flock syscall.
lock_ready="$fixture_root/server-lock-ready"
if command -v flock >/dev/null 2>&1; then
  (
    exec 9<>"$activity"
    flock -x 9
    : > "$lock_ready"
    sleep 300
  ) &
  lock_pid="$!"
elif command -v python3 >/dev/null 2>&1; then
  python3 -c \
    'import fcntl, pathlib, sys, time
handle = open(sys.argv[1], "r+")
fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
pathlib.Path(sys.argv[2]).touch()
time.sleep(300)' \
    "$activity" "$lock_ready" &
  lock_pid="$!"
else
  printf 'base live-status test needs flock or python3\n' >&2
  exit 1
fi
for _ in {1..100}; do
  [[ -e "$lock_ready" ]] && break
  sleep 0.01
done
if [[ ! -e "$lock_ready" ]]; then
  printf 'failed to acquire the server activity fixture lock\n' >&2
  exit 1
fi

preflight_status="$fixture_root/preflight-status.txt"
run_incomplete_status "$preflight_status" 0
if ! grep -Fq 'last stage: payload execution preflight' \
    "$preflight_status" ||
   grep -Fq 'payload evaluation is in progress' "$preflight_status"; then
  printf 'payload preflight status was mislabeled as FHE evaluation:\n' >&2
  sed -n '1,120p' "$preflight_status" >&2
  exit 1
fi

printf '%s\n' \
  '{"schema":"laminate-role-activity-v1","role":"server","event":"start","stage":"starting","pid":4242,"unix_ms":1700000000000}' \
  '{"schema":"laminate-role-activity-v1","role":"server","event":"stage","stage":"payload_evaluation","pid":4242,"unix_ms":1700000060000}' \
  > "$activity"
printf '%s\n' \
  '{"schema":"laminate-base-progress-v1","seq":0,"event":"run-status","status":"started","run_elapsed_ms":0.000}' \
  '{"schema":"laminate-base-progress-v1","seq":1,"event":"begin","stage":"payload.forward_relation","run_elapsed_ms":1000.000}' \
  > "$progress"

payload_status="$fixture_root/payload-status.txt"
run_incomplete_status "$payload_status" 0
if ! grep -Fq \
  'server sumcheck: has not started; payload evaluation is in progress' \
  "$payload_status"; then
  printf 'payload status did not explain that sumcheck has not started:\n' >&2
  sed -n '1,120p' "$payload_status" >&2
  exit 1
fi

printf '%s\n' \
  '{"schema":"laminate-role-activity-v1","role":"server","event":"start","stage":"starting","pid":4242,"unix_ms":1700000000000}' \
  '{"schema":"laminate-role-activity-v1","role":"server","event":"stage","stage":"gkr_proving","pid":4242,"unix_ms":1700000120000}' \
  > "$activity"
printf '%s\n' \
  '{"schema":"laminate-base-progress-v1","seq":18,"event":"begin","stage":"base.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_6","run_elapsed_ms":125000.000,"layer_kind":"multiplication","reduction_layer":9,"source_layer":10,"coordinate_domain":"ciphertext_index","round":6,"rounds":28}' \
  > "$progress"

sumcheck_status="$fixture_root/sumcheck-status.txt"
run_incomplete_status "$sumcheck_status" 0
for expected in \
  'server telemetry: current [PROTOCOL/FHE] LaminateBase multiplication layer reduction | layer 9 -> source layer 10 | ciphertext-index sumcheck round 7/28' \
  'event recorded at server elapsed 00:02:05' \
  'ciphertext-index sumcheck round 7/28'; do
  if ! grep -Fq "$expected" "$sumcheck_status"; then
    printf 'sumcheck status is missing %s:\n' "$expected" >&2
    sed -n '1,120p' "$sumcheck_status" >&2
    exit 1
  fi
done
if grep -Fq 'detailed telemetry elapsed' "$sumcheck_status"; then
  printf 'event timestamp was mislabeled as elapsed phase duration:\n' >&2
  sed -n '1,120p' "$sumcheck_status" >&2
  exit 1
fi

printf '%s\n' \
  '{"schema":"laminate-base-progress-v1","seq":24,"event":"progress","stage":"payload.replay_relation.reduction_1.source_3.output_2","run_elapsed_ms":245000.000,"layer_kind":"affine","reduction_layer":1,"source_layer":3,"output_layer":2,"completed_steps":46080,"total_steps":73728,"work_units":73728,"phase_wall_ms":10000,"phase_cpu_ms":7000,"fhe_wall_ms":5000,"modulus_switch_wall_ms":500,"serialization_wall_ms":200,"buffer_assembly_wall_ms":100,"hashing_wall_ms":50,"storage_read_wall_ms":2000,"storage_write_wall_ms":1000,"prefetch_wall_ms":100,"writeback_submission_wall_ms":100,"writeback_wait_wall_ms":0,"read_syscalls":8,"application_read_bytes":1073741824,"write_syscalls":4,"application_write_bytes":536870912,"prefetch_requests":2,"prefetch_bytes_requested":2147483648,"prefetch_fallbacks":0,"prefetch_seek_disables":0,"writeback_submission_attempts":4,"writeback_submission_successes":4,"writeback_wait_attempts":0,"writeback_wait_successes":0,"writeback_range_bytes_submitted":536870912,"writeback_range_bytes_waited":0,"writeback_files_submit_only":1,"writeback_drains":0,"writeback_drains_skipped":0}' \
  > "$progress"
replay_status="$fixture_root/replay-status.txt"
run_incomplete_status "$replay_status" 0
for expected in \
  'current [PAYLOAD/FHE] payload replay relation | layer 1 -> source layer 3 | output layer 2' \
  'event recorded at server elapsed 00:04:05' \
  'source layer 3' \
  'output records 46080 of 73728' \
  'live phase snapshot: 10.0s wall, 70.0% CPU/wall' \
  'read/write 1.0/0.5 GiB in 8/4 syscalls' \
  'prefetch 2.0 GiB in 2 requests (fallbacks/seek-disables 0/0)' \
  'writeback hinted/waited range 0.5/0.0 GiB in 4/4 successful/attempted submits, 0/0 successful/attempted waits (submit-only files/drains/skipped 1/0/0)'; do
  if ! grep -Fq "$expected" "$replay_status"; then
    printf 'replay status is missing %s:\n' "$expected" >&2
    sed -n '1,120p' "$replay_status" >&2
    exit 1
  fi
done
if grep -Fq 'payload evaluation is in progress' "$replay_status"; then
  printf 'checkpoint replay was mislabeled as initial payload evaluation:\n' >&2
  sed -n '1,120p' "$replay_status" >&2
  exit 1
fi

printf '%s\n' \
  '{"schema":"laminate-base-progress-v1","seq":33,"event":"progress","stage":"transcript_packing.spartan.witness_commitment.ntt","run_elapsed_ms":365000.000,"layer_kind":"unspecified","subpass":"local_ntt","completed_steps":3,"total_steps":5,"phase_completed_steps":1,"phase_total_steps":2,"progress_work_unit":"ntt_butterflies","completed_work_units":9961472,"total_work_units":16252928,"completed_read_bytes":8388608,"total_read_bytes":16777216,"completed_write_bytes":8388608,"total_write_bytes":16777216,"phase_completed_read_bytes":25165824,"phase_total_read_bytes":33554432,"phase_completed_write_bytes":25165824,"phase_total_write_bytes":33554432,"completed_butterflies":9961472,"total_butterflies":16252928,"phase_completed_butterflies":26214400,"phase_total_butterflies":32505856,"radix_elements":131072,"row_count":128,"row_size":131072,"recent_work_units_per_second":2621440.000,"estimated_remaining_ms":2400.000,"column_index":0,"column_count":1}' \
  > "$progress"
witness_status="$fixture_root/witness-status.txt"
run_incomplete_status "$witness_status" 0
for expected in \
  'current [TRANSCRIPT PACKING] transcript packing spartan witness commitment ntt' \
  'event recorded at server elapsed 00:06:05' \
  'local ntt' \
  'commitment artifact passes 3 of 5' \
  'active-phase passes 1 of 2' \
  'current-pass 9961472 of 16252928 ntt_butterflies' \
  'radix 131072' \
  '128 rows x 131072 elements' \
  'current-pass read bytes 8388608 of 16777216' \
  'active-phase written bytes 25165824 of 33554432' \
  'current-pass butterflies 9961472 of 16252928' \
  'active-phase butterflies 26214400 of 32505856' \
  'recent 2621440.000 ntt_butterflies/s, current-pass ETA 00:00:02' \
  'column 1 of 1'; do
  if ! grep -Fq "$expected" "$witness_status"; then
    printf 'witness-commitment status is missing %s:\n' "$expected" >&2
    sed -n '1,120p' "$witness_status" >&2
    exit 1
  fi
done

printf '%s\n' \
  '{"schema":"laminate-base-progress-v1","seq":40,"event":"begin","stage":"base.affine.terminal_source_evaluation.reduction_8.source_9","run_elapsed_ms":425000.000,"layer_kind":"affine","reduction_layer":8,"source_layer":9}' \
  > "$progress"
terminal_status="$fixture_root/terminal-status.txt"
run_incomplete_status "$terminal_status" 0
grep -Fq \
  'current [PROTOCOL/FHE] LaminateBase affine terminal source evaluation | layer 8 -> source layer 9' \
  "$terminal_status" || {
  printf 'terminal affine evaluation was not described as a protocol operation:\n' >&2
  sed -n '1,120p' "$terminal_status" >&2
  exit 1
}

printf '%s\n' \
  '{"schema":"laminate-base-progress-v1","seq":41,"event":"begin","stage":"base.multiplication.source_artifact_build.reduction_5.source_6","run_elapsed_ms":425500.000,"layer_kind":"multiplication","reduction_layer":5,"source_layer":6}' \
  > "$progress"
artifact_status="$fixture_root/artifact-status.txt"
run_incomplete_status "$artifact_status" 0
grep -Fq \
  'current [STORAGE] LaminateBase multiplication source artifact build | layer 5 -> source layer 6' \
  "$artifact_status" || {
  printf 'multiplication artifact construction lost its semantic stage name:\n' >&2
  sed -n '1,120p' "$artifact_status" >&2
  exit 1
}

printf '%s\n' \
  '{"schema":"laminate-base-progress-v1","seq":42,"event":"begin","stage":"base.multiplication.terminal_source_evaluation.reduction_5.source_6.ciphertext_index","run_elapsed_ms":426000.000,"layer_kind":"multiplication","coordinate_domain":"ciphertext_index","reduction_layer":5,"source_layer":6}' \
  > "$progress"
checkpoint_status="$fixture_root/checkpoint-status.txt"
run_incomplete_status "$checkpoint_status" 0
grep -Fq \
  'current [PROTOCOL/FHE] LaminateBase multiplication terminal source evaluation | layer 5 -> source layer 6' \
  "$checkpoint_status" || {
  printf 'Base checkpoint did not explain the coordinate transition:\n' >&2
  sed -n '1,120p' "$checkpoint_status" >&2
  exit 1
}

printf '%s\n' \
  '{"schema":"laminate-base-progress-v1","seq":43,"event":"begin","stage":"base.gate_mle_opening","run_elapsed_ms":426500.000,"layer_kind":"unspecified"}' \
  > "$progress"
gate_mle_status="$fixture_root/gate-mle-status.txt"
run_incomplete_status "$gate_mle_status" 0
grep -Fq 'current [PROTOCOL] LaminateBase GateMLE opening' "$gate_mle_status" || {
  printf 'GateMLE completion was not described as an opening operation:\n' >&2
  sed -n '1,120p' "$gate_mle_status" >&2
  exit 1
}

# The last telemetry survives an abrupt process exit, but it must not be
# described as current work once the role no longer holds its activity lock.
printf '%s\n' \
  '{"schema":"laminate-role-activity-v1","role":"server","event":"start","stage":"starting","pid":4242,"unix_ms":1700000000000}' \
  '{"schema":"laminate-role-activity-v1","role":"server","event":"stage","stage":"payload_evaluation","pid":4242,"unix_ms":1700000060000}' \
  > "$activity"
kill "$lock_pid"
wait "$lock_pid" 2>/dev/null || true
lock_pid=''

stale_status="$fixture_root/stale-status.txt"
run_incomplete_status "$stale_status" 1
if grep -Fq 'payload evaluation is in progress' "$stale_status"; then
  printf 'inactive server telemetry was described as current work:\n' >&2
  sed -n '1,120p' "$stale_status" >&2
  exit 1
fi

# Exercise the setup codec through the real status command without building
# FHE keys or commitments. Include every supported target profile name.
python3 - "$benchmark" "$fixture_root" <<'PY_SETUP'
from pathlib import Path
import struct
import subprocess
import sys

benchmark = str(Path(sys.argv[1]).resolve())
root = Path(sys.argv[2]) / "setup-status"
root.mkdir(mode=0o700)
for role in ("shared", "server", "client"):
    (root / role).mkdir(mode=0o700)

profiles = ("quick", "target-balancedLaned", "target-mulHeavyPyramid")


def fixture(profile):
    body = bytearray()

    def u64(value):
        body.extend(struct.pack("<Q", value))

    def text(value):
        encoded = value.encode()
        u64(len(encoded))
        body.extend(encoded)

    def digest():
        body.extend(bytes([17]) * 32)

    text("LaminateImpl/BaseProcessSetup/v11")
    for value in ("base", profile, "synthetic-source", "Release", "synthetic-build"):
        text(value)
    for _ in range(6):
        digest()
    u64(0)  # No GateMLE key; status only decodes and checks selectors.
    text("LaminateImpl/UniformBaseProofIngress/v1")
    u64(3)
    u64(390)
    for _ in range(4):
        u64(0)  # Host observations and limits.
    for value in (0, 0, 0, 1, 1, 0, 0, 0, 0):
        u64(value)  # Replay budgets, objective, and empty artifact bounds.
    digest()
    u64(1)  # Client resident reserve.
    for value in (1, 1, 1, 1) + (0,) * 12:
        u64(value)  # Canonical bounded client wire limits.
    for _ in range(3):
        u64(0)
        digest()  # Server, client context, and client static artifacts.
    path = root / "shared/setup.bin"
    path.write_bytes(body)
    path.chmod(0o600)


def status(profile):
    return subprocess.run(
        [benchmark, "status", "--variant", "base", "--profile", profile,
         "--run-dir", str(root)], text=True, capture_output=True)


for profile in profiles:
    fixture(profile)
    result = status(profile)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"Laminate Base {profile} status" in result.stdout
    for wrong_profile in profiles:
        if wrong_profile == profile:
            continue
        rejected = status(wrong_profile)
        assert rejected.returncode != 0, rejected.stdout + rejected.stderr
        assert "command variant/profile does not match setup.bin" in rejected.stderr

fixture("unrecognized-profile")
rejected = status("quick")
assert rejected.returncode != 0, rejected.stdout + rejected.stderr
assert "command variant/profile does not match setup.bin" in rejected.stderr

fixture("x" * 65)
rejected = status("quick")
assert rejected.returncode != 0, rejected.stdout + rejected.stderr
assert "setup profile exceeds its decode limit" in rejected.stderr
PY_SETUP
