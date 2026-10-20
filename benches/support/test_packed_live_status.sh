#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s PACKED_CHECKPOINT_BENCHMARK\n' "$0" >&2
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

write_activity() {
  local stage="$1"
  printf '%s\n' \
    '{"schema":"laminate-role-activity-v1","role":"server","event":"start","stage":"starting","pid":4242,"unix_ms":1700000000000}' \
    "{\"schema\":\"laminate-role-activity-v1\",\"role\":\"server\",\"event\":\"stage\",\"stage\":\"$stage\",\"pid\":4242,\"unix_ms\":1700000060000}" \
    >"$activity"
  chmod 600 "$activity"
}

run_status() {
  local output="$1"
  local expected="$2"
  local status=0
  "$benchmark" status --variant folded --profile quick \
    --run-dir "$fixture_root" >"$output" 2>&1 || status=$?
  if [[ "$status" -ne "$expected" ]]; then
    printf 'status expected %s, got %s:\n' "$expected" "$status" >&2
    sed -n '1,160p' "$output" >&2
    exit 1
  fi
}

write_activity payload_evaluation
printf '%s\n' \
  '{"schema":"laminate-protocol-progress-v1","seq":1,"event":"begin","stage":"payload.forward_relation.source_11.output_10","run_elapsed_ms":125000.000,"layer_kind":"affine","source_layer":11,"output_layer":10,"work_units":16384}' \
  >"$progress"
chmod 600 "$progress"

lock_ready="$fixture_root/server-lock-ready"
if command -v flock >/dev/null 2>&1; then
  (
    exec 9<>"$activity"
    flock -x 9
    : >"$lock_ready"
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
  printf 'packed live-status test needs flock or python3\n' >&2
  exit 1
fi
for _ in {1..100}; do
  [[ -e "$lock_ready" ]] && break
  sleep 0.01
done
[[ -e "$lock_ready" ]] || { printf 'failed to lock fixture\n' >&2; exit 1; }

payload_status="$fixture_root/payload-status.txt"
run_status "$payload_status" 0
for expected in \
  'ciphertext hash: simpleCTHash/v2 (diagnostic; no ciphertext-binding or transcript-packing integrity claim)' \
  'event recorded at server elapsed 00:02:05' \
  'source layer 11' \
  'output layer 10' \
  'server proof phase: payload evaluation; GKR sumcheck has not started'; do
  grep -Fq "$expected" "$payload_status" || {
    printf 'payload status missing %s:\n' "$expected" >&2
    sed -n '1,160p' "$payload_status" >&2
    exit 1
  }
done

write_activity proving
printf '%s\n' \
  '{"schema":"laminate-protocol-progress-v1","seq":12,"event":"progress","stage":"payload.replay_relation.reduction_1.source_3.output_2","run_elapsed_ms":205000.000,"layer_kind":"affine","reduction_layer":1,"source_layer":3,"output_layer":2,"work_units":73728,"completed_steps":24576,"total_steps":49152,"phase_wall_ms":10000,"phase_cpu_ms":7000,"fhe_wall_ms":5000,"modulus_switch_wall_ms":500,"serialization_wall_ms":200,"buffer_assembly_wall_ms":100,"hashing_wall_ms":50,"storage_read_wall_ms":2000,"storage_write_wall_ms":1000,"prefetch_wall_ms":100,"writeback_submission_wall_ms":100,"writeback_wait_wall_ms":0,"read_syscalls":8,"application_read_bytes":1073741824,"write_syscalls":4,"application_write_bytes":536870912,"prefetch_requests":2,"prefetch_bytes_requested":2147483648,"prefetch_fallbacks":0,"prefetch_seek_disables":0,"writeback_submission_attempts":4,"writeback_submission_successes":4,"writeback_wait_attempts":0,"writeback_wait_successes":0,"writeback_range_bytes_submitted":536870912,"writeback_range_bytes_waited":0,"writeback_files_submit_only":1,"writeback_drains":0,"writeback_drains_skipped":0}' \
  >"$progress"

replay_status="$fixture_root/replay-status.txt"
run_status "$replay_status" 0
for expected in \
  'current [PAYLOAD/FHE] payload replay relation | layer 1 -> source layer 3 | output layer 2' \
  'source layer 3' \
  'output layer 2' \
  'output records 24576 of 49152' \
  'live phase snapshot: 10.0s wall, 70.0% CPU/wall' \
  'read/write 1.0/0.5 GiB in 8/4 syscalls' \
  'prefetch 2.0 GiB in 2 requests (fallbacks/seek-disables 0/0)' \
  'writeback hinted/waited range 0.5/0.0 GiB in 4/4 successful/attempted submits, 0/0 successful/attempted waits (submit-only files/drains/skipped 1/0/0)' \
  'server proof phase: encrypted GKR checkpoint replay and source preparation'; do
  grep -Fq "$expected" "$replay_status" || {
    printf 'checkpoint replay status missing %s:\n' "$expected" >&2
    sed -n '1,160p' "$replay_status" >&2
    exit 1
  }
done
if grep -Fq 'GKR sumcheck has not started' "$replay_status"; then
  printf 'checkpoint replay was mislabeled as pre-GKR payload work:\n' >&2
  sed -n '1,160p' "$replay_status" >&2
  exit 1
fi

printf '%s\n' \
  '{"schema":"laminate-protocol-progress-v1","seq":18,"event":"begin","stage":"folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_6","run_elapsed_ms":245000.000,"layer_kind":"multiplication","reduction_layer":9,"source_layer":10,"coordinate_domain":"slot_index","round":6,"rounds":28}' \
  >"$progress"

sumcheck_status="$fixture_root/sumcheck-status.txt"
run_status "$sumcheck_status" 0
for expected in \
  'server telemetry: current [PROTOCOL/FHE] LaminateFolded multiplication layer reduction | layer 9 -> source layer 10 | slot-index sumcheck round 7/28' \
  'event recorded at server elapsed 00:04:05' \
  'slot-index sumcheck round 7/28' \
  'server proof phase: encrypted GKR reduction and sumcheck'; do
  grep -Fq "$expected" "$sumcheck_status" || {
    printf 'sumcheck status missing %s:\n' "$expected" >&2
    sed -n '1,160p' "$sumcheck_status" >&2
    exit 1
  }
done

printf '%s\n' \
  '{"schema":"laminate-protocol-progress-v1","seq":33,"event":"progress","stage":"transcript_packing.spartan.witness_commitment.ntt","run_elapsed_ms":365000.000,"layer_kind":"unspecified","subpass":"local_ntt","completed_steps":3,"total_steps":5,"phase_completed_steps":1,"phase_total_steps":2,"progress_work_unit":"ntt_butterflies","completed_work_units":9961472,"total_work_units":16252928,"completed_read_bytes":8388608,"total_read_bytes":16777216,"completed_write_bytes":8388608,"total_write_bytes":16777216,"phase_completed_read_bytes":25165824,"phase_total_read_bytes":33554432,"phase_completed_write_bytes":25165824,"phase_total_write_bytes":33554432,"completed_butterflies":9961472,"total_butterflies":16252928,"phase_completed_butterflies":26214400,"phase_total_butterflies":32505856,"radix_elements":131072,"row_count":128,"row_size":131072,"recent_work_units_per_second":2621440.000,"estimated_remaining_ms":2400.000,"column_index":0,"column_count":1}' \
  >"$progress"
spartan_status="$fixture_root/spartan-status.txt"
run_status "$spartan_status" 0
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
  'column 1 of 1' \
  'server proof phase: external Spartan transcript-packing proof (transcript_packing.spartan.witness_commitment.ntt)'; do
  grep -Fq "$expected" "$spartan_status" || {
    printf 'external Spartan status missing %s:\n' "$expected" >&2
    sed -n '1,160p' "$spartan_status" >&2
    exit 1
  }
done

printf '%s\n' \
  '{"schema":"laminate-protocol-progress-v1","seq":40,"event":"begin","stage":"folded.affine.slot_checkpoint.reduction_8.source_9.checkpoint_9.slot_index","run_elapsed_ms":425000.000,"layer_kind":"affine","coordinate_domain":"slot_index","reduction_layer":8,"source_layer":9,"checkpoint_layer":9}' \
  >"$progress"
checkpoint_status="$fixture_root/checkpoint-status.txt"
run_status "$checkpoint_status" 0
grep -Fq \
  'current [PROTOCOL/FHE] LaminateFolded affine slot checkpoint | layer 8 -> source layer 9 | ciphertext-index prefix -> slot-index checkpoint at layer 9' \
  "$checkpoint_status" || {
  printf 'Folded checkpoint did not explain the coordinate transition:\n' >&2
  sed -n '1,160p' "$checkpoint_status" >&2
  exit 1
}

printf '%s\n' \
  '{"schema":"laminate-protocol-progress-v1","seq":41,"event":"begin","stage":"folded.gate_mle_opening","run_elapsed_ms":426000.000,"layer_kind":"unspecified"}' \
  >"$progress"
gate_mle_status="$fixture_root/gate-mle-status.txt"
run_status "$gate_mle_status" 0
grep -Fq 'current [PROTOCOL] LaminateFolded GateMLE opening' "$gate_mle_status" || {
  printf 'Folded GateMLE completion was not described as an opening operation:\n' >&2
  sed -n '1,160p' "$gate_mle_status" >&2
  exit 1
}
if grep -Fq 'detailed telemetry elapsed' "$spartan_status"; then
  printf 'event timestamp was mislabeled as elapsed phase duration:\n' >&2
  sed -n '1,160p' "$spartan_status" >&2
  exit 1
fi

target_status="$fixture_root/target-status.txt"
target_status_code=0
"$benchmark" status --variant folded --profile target-balancedLaned \
  --run-dir "$fixture_root" >"$target_status" 2>&1 || target_status_code=$?
if [[ "$target_status_code" -ne 0 ]] ||
   ! grep -Fq 'ciphertext hash: Poseidon (poseidon/v2)' "$target_status" ||
   grep -Fq 'simpleCTHash' "$target_status"; then
  printf 'target status did not preserve the Poseidon policy:\n' >&2
  sed -n '1,160p' "$target_status" >&2
  exit 1
fi

for lanes in 1 128 16384; do
  laned_status="$fixture_root/laned-b${lanes}-status.txt"
  "$benchmark" status --variant laned --profile quick \
    --run-dir "$fixture_root" --lanes "$lanes" >"$laned_status" 2>&1
  grep -Fq "Laminate laned quick (B=$lanes) status" "$laned_status" || {
    printf 'Laned status omitted its explicit lane count B=%s:\n' \
      "$lanes" >&2
    sed -n '1,80p' "$laned_status" >&2
    exit 1
  }
done

# This synthetic current-codec record exercises status identity checks
# without constructing preprocessing or a proof.
python3 - "$benchmark" "$fixture_root" <<'PY_SETUP'
from pathlib import Path
import hashlib
import struct
import subprocess
import sys

benchmark = str(Path(sys.argv[1]).resolve())
root = Path(sys.argv[2]) / "setup-status"
root.mkdir(mode=0o700)
for role in ("shared", "server", "client"):
    (root / role).mkdir(mode=0o700)

run_id = bytes.fromhex("11" * 32)
def fixture(profile, codec_version=14):
    body = bytearray()
    def u64(value): body.extend(struct.pack("<Q", value))
    def text(value):
        encoded = value.encode()
        u64(len(encoded))
        body.extend(encoded)
    def words(values):
        u64(len(values))
        for value in values: u64(value)
    def zeros(count): body.extend(bytes(8 * count))
    def digest(): body.extend(run_id)
    text("LaminateImpl/PackedCheckpointProcessSetup/v7")
    u64(codec_version)
    for value in ("laned", profile, "synthetic-source", "Release", "synthetic-build"):
        text(value)
    for _ in range(6): digest()
    text("LaminateImpl/ConservativePackedProofIngress/v2")
    digest()
    for value in (16384, 16384, 8, 65536, 1048576, 64, 1, 120, 120, 150, 150, 3, 3):
        u64(value)
    words([60, 48, 48, 37, 37, 37, 37, 38, 38, 39, 40, 40, 40, 40])
    u64(60)
    words([0] * 14)  # Synthetic chain; status does not perform FHE work.
    for value in (0, 577, 637, 0): u64(value)
    for _ in range(4):
        u64(0)
        digest()
    digest()
    zeros(1 + 8 + 10)  # Fixed-basis bytes, artifact caps, workload decode caps.
    zeros(3)  # Empty evaluation-plan vectors.
    u64(1)
    zeros(16 + 4)  # Replay layer and checkpoint framing.
    for value in (0, 0, 0, 1, 1, 0, 0, 0, 0): u64(value)
    digest()
    zeros(8 + 1 + 16 + 3)
    # Capacity/host/client fields, empty scratch, wire caps and gate disk reserves.
    digest()
    zeros(2)
    encoded = bytes(body) + hashlib.sha256(body).digest()
    (root / "shared/setup.bin").write_bytes(encoded)
    (root / "shared/setup.bin").chmod(0o600)
    binding = ("format=laminate-benchmark-run-v1\nrun.variant=laned\n"
               f"run.profile={profile}\nrun.id={run_id.hex()}\n")
    (root / "shared/run-binding.txt").write_text(binding)
    (root / "shared/run-binding.txt").chmod(0o600)
    return encoded

def status(profile, lanes=16384):
    return subprocess.run([benchmark, "status", "--variant", "laned", "--profile", profile,
                           "--run-dir", str(root), "--lanes", str(lanes)],
                          text=True, capture_output=True)

fixture("target-balancedLaned", codec_version=0)
rejected = status("target-balancedLaned")
assert rejected.returncode != 0
assert "setup record header is invalid" in rejected.stderr

for profile in ("target-balancedLaned",):
    encoded = fixture(profile)
    result = status(profile)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"Laminate laned {profile} (B=16384) status" in result.stdout
    assert "Fiat-Shamir: one transcript, GKR then Spartan packing argument" in result.stdout
    assert "GKR layer transitions: one claim by selector interpolation" in result.stdout
    assert "GKR multiplication: h(0) messages and stripped terminal product" in result.stdout
    for wrong_profile, wrong_lanes in (("quick", 16384), (profile, 128)):
        rejected = status(wrong_profile, wrong_lanes)
        assert rejected.returncode != 0
        assert "status selector does not match setup record identity" in rejected.stderr
    binding = root / "shared/run-binding.txt"
    binding.write_text(binding.read_text().replace(run_id.hex(), "22" * 32))
    rejected = status(profile)
    assert rejected.returncode != 0
    assert "run binding does not match setup record" in rejected.stderr
    fixture(profile)
    damaged = bytearray(encoded)
    damaged[-1] ^= 1
    (root / "shared/setup.bin").write_bytes(damaged)
    rejected = status(profile)
    assert rejected.returncode != 0
    assert "setup record checksum mismatch" in rejected.stderr
PY_SETUP

kill "$lock_pid"
wait "$lock_pid" 2>/dev/null || true
lock_pid=''
stale_status="$fixture_root/stale-status.txt"
run_status "$stale_status" 1
grep -Fq 'FAILED OR ABANDONED' "$stale_status" || {
  printf 'inactive packed role was not reported abandoned:\n' >&2
  sed -n '1,160p' "$stale_status" >&2
  exit 1
}

# A terminal status must surface the concrete client rejection and the last
# protocol phase, not merely collapse every client exception into FAILED.
mkdir -p "$fixture_root/client"
printf '%s\n' \
  '{"schema":"laminate-protocol-progress-v1","seq":7,"event":"end","stage":"transcript_packing.threshold_checks","run_elapsed_ms":3456.000,"layer_kind":"unspecified"}' \
  '{"schema":"laminate-protocol-progress-v1","seq":8,"event":"run-status","status":"failed","run_elapsed_ms":3457.000}' \
  >"$fixture_root/client/progress.jsonl"
printf '%s\n' \
  'FAILED: LaminateFolded transcript-packing threshold rejected: configured threshold=100; maximum observed norm=140; failing reveals=2; checked reveals=4; observed reveals=4; expected reveals=4; first failing reveal (one-based)=2 of 4' \
  >"$fixture_root/client/failure.txt"
chmod 600 \
  "$fixture_root/client/progress.jsonl" \
  "$fixture_root/client/failure.txt"

client_failure_status="$fixture_root/client-failure-status.txt"
run_status "$client_failure_status" 1
for expected in \
  'client telemetry: last completed [TRANSCRIPT PACKING] transcript packing threshold checks (event recorded at client elapsed 00:00:03)' \
  'client failure: FAILED: LaminateFolded transcript-packing threshold rejected: configured threshold=100; maximum observed norm=140; failing reveals=2; checked reveals=4; observed reveals=4; expected reveals=4; first failing reveal (one-based)=2 of 4'; do
  grep -Fq "$expected" "$client_failure_status" || {
    printf 'client failure status missing %s:\n' "$expected" >&2
    sed -n '1,200p' "$client_failure_status" >&2
    exit 1
  }
done
