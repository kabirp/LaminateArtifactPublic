#!/usr/bin/env bash

set -euo pipefail
umask 077

if [[ $# -ne 1 ]]; then
  printf 'usage: %s ARCHIVE_HELPER\n' "$0" >&2
  exit 2
fi

helper="$1"
scratch="$(mktemp -d)"
scratch="$(cd -P -- "$scratch" && pwd)"
cleanup() {
  if [[ -n "${unrelated_inaccessible_mount:-}" ]]; then
    chmod 0700 "$unrelated_inaccessible_mount" 2>/dev/null || true
  fi
  rm -rf -- "$scratch"
}
trap cleanup EXIT
artifact_root="$scratch/bench"
archive_root="$scratch/archive"
mkdir -m 0700 "$artifact_root" "$artifact_root/runs" \
  "$artifact_root/logs" "$archive_root"

fake_bin="$scratch/bin"
mkdir "$fake_bin"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'if [[ "${FAKE_FLOCK_REJECT_FD:-}" != "" ]]; then' \
  '  for argument in "$@"; do' \
  '    [[ "$argument" != "$FAKE_FLOCK_REJECT_FD" ]] || exit 1' \
  '  done' \
  'fi' \
  'exit 0' > "$fake_bin/flock"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  '[[ -z "${FAKE_FINDMNT_TARGETS:-}" ]] || printf "%s\n" "$FAKE_FINDMNT_TARGETS"' \
  'exit 0' > "$fake_bin/findmnt"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "%s\\n" "1B-blocks Avail" "10000000000 ${FAKE_DF_AVAILABLE:-9000000000}"' \
  > "$fake_bin/df"
chmod +x "$fake_bin/findmnt" "$fake_bin/flock" "$fake_bin/df"

make_complete_run() {
  local run="$1"
  local variant="${2:-base}"
  local profile="${3:-target-balancedLaned}"
  mkdir -m 0700 "$run" "$run/shared" "$run/shared/report" \
    "$run/client" "$run/server" "$run/server/work"
  printf '%s\n' \
    'format=laminate-benchmark-run-v1' \
    "run.variant=$variant" \
    "run.profile=$profile" \
    'run.id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    > "$run/shared/run-binding.txt"
  printf 'setup.result=PASS\n' > "$run/shared/setup-result.txt"
  printf 'process.exit_status=0\n' > "$run/shared/setup-process-exit.txt"
  printf 'server.result=PASS\n' > "$run/server/result.txt"
  printf 'process.exit_status=0\n' > "$run/server/process-exit.txt"
  printf 'verification.result=PASS\n' > "$run/client/result.txt"
  printf 'process.exit_status=0\n' > "$run/client/process-exit.txt"
  printf 'format=laminate-storage-provenance-v2\n' \
    > "$run/shared/storage-provenance.setup-start.txt"
  printf 'format=laminate-storage-provenance-v2\n' \
    > "$run/shared/storage-provenance.server-start.txt"
  printf '# Human report\n' > "$run/shared/report/summary.md"
  printf 'not allowlisted\n' > "$run/server/unexpected.txt"
  printf 'large online artifact\n' > "$run/server/work/not-archived.bin"
  : > "$run/shared/lifecycle.lock"
  chmod 0600 "$run/shared/lifecycle.lock"
}

make_complete_local_run() {
  local run="$1"
  local variant="${2:-local}"
  local profile="${3:-target-balancedLaned}"
  mkdir -m 0700 "$run" "$run/shared" "$run/shared/report" \
    "$run/client"
  printf '%s\n' \
    'format=laminate-benchmark-run-v1' \
    "run.variant=$variant" \
    "run.profile=$profile" \
    'run.id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    > "$run/shared/run-binding.txt"
  printf 'setup.result=PASS\n' > "$run/shared/setup-result.txt"
  printf 'process.exit_status=0\n' > "$run/shared/setup-process-exit.txt"
  printf 'client.result=PASS\n' > "$run/client/result.txt"
  printf 'process.exit_status=0\n' > "$run/client/process-exit.txt"
  printf '# Local human report\n' > "$run/shared/report/summary.md"
  : > "$run/shared/lifecycle.lock"
  chmod 0600 "$run/shared/lifecycle.lock"
}

run="$artifact_root/runs/base-target-balancedLaned-example"
pointer="$artifact_root/current-base-target-balancedLaned.run"
make_complete_run "$run"
printf 'setup console\n' > "$artifact_root/logs/base-target-balancedLaned-example.setup.log"
printf '%s\n' "$run" > "$pointer"

# Unrelated kernel mounts can be directories which the benchmark user cannot
# enter. They must not prevent retirement of the independently validated run.
unrelated_inaccessible_mount="$scratch/inaccessible-system-mount"
mkdir -m 000 "$unrelated_inaccessible_mount"
FAKE_FINDMNT_TARGETS="$unrelated_inaccessible_mount" \
  PATH="$fake_bin:$PATH" "$helper" complete \
  "$run" "$artifact_root" "$archive_root" "$pointer" \
  > "$scratch/output.txt"
grep -q '^ARCHIVE PASS:' "$scratch/output.txt"
grep -q '^HUMAN COPY:' "$scratch/output.txt"
if grep -q '^CSV COPY:' "$scratch/output.txt"; then
  printf '%s\n' 'single-report archive unexpectedly published a CSV copy' >&2
  exit 1
fi
grep -q '^RETIRE PASS:' "$scratch/output.txt"
[[ ! -e "$run" && ! -e "$pointer" ]]
archive="$archive_root/base-target-balancedLaned-example.evidence.tar.gz"
summary_copy="$archive_root/base-target-balancedLaned-example.summary.md"
csv_copy="$archive_root/base-target-balancedLaned-example.summary.csv"
[[ -f "$archive" && -f "$archive.sha256" && -f "$summary_copy" &&
   ! -e "$csv_copy" ]]
grep -Fqx '# Human report' "$summary_copy"
(cd "$archive_root" &&
  sha256sum -c "${archive##*/}.sha256" >/dev/null)
tar -tzf "$archive" > "$scratch/archive-files.txt"
grep -q './evidence/shared/report/summary.md' "$scratch/archive-files.txt"
if grep -q './evidence/shared/report/summary.csv' "$scratch/archive-files.txt"; then
  printf '%s\n' 'single-report evidence archive unexpectedly contains CSV' >&2
  exit 1
fi
grep -q './evidence/shared/setup-console.log' "$scratch/archive-files.txt"
grep -q './evidence/shared/storage-provenance.setup-start.txt' \
  "$scratch/archive-files.txt"
grep -q './evidence/shared/storage-provenance.server-start.txt' \
  "$scratch/archive-files.txt"
if grep -q 'not-archived.bin' "$scratch/archive-files.txt"; then
  printf '%s\n' 'large online artifact leaked into compact evidence archive' >&2
  exit 1
fi
if grep -q 'unexpected.txt' "$scratch/archive-files.txt"; then
  printf '%s\n' 'name-based wildcard leaked an unapproved text file' >&2
  exit 1
fi

# Repeating an already completed operation is explicitly successful.
PATH="$fake_bin:$PATH" "$helper" complete \
  "$run" "$artifact_root" "$archive_root" "$pointer" \
  > "$scratch/idempotent-output.txt"
grep -q '^ARCHIVE PASS (existing):' "$scratch/idempotent-output.txt"
grep -q '^RETIRE PASS (already absent):' "$scratch/idempotent-output.txt"

# Recovered runs retain the exact original public setup record and its reported
# hash. Role preprocessing remains excluded, including the client's secret key.
recovered_run="$artifact_root/runs/base-target-balancedLaned-recovered"
make_complete_run "$recovered_run"
mkdir -m 0700 "$recovered_run/client/preprocessing" \
  "$recovered_run/server/preprocessing"
printf 'private client key\n' \
  > "$recovered_run/client/preprocessing/client.bin"
printf 'server preprocessing\n' \
  > "$recovered_run/server/preprocessing/server.bin"
printf 'original public setup\000\377\n' \
  > "$scratch/recovery-source-setup.bin"
cp "$scratch/recovery-source-setup.bin" \
  "$recovered_run/shared/recovery-source-setup.bin"
recovery_digest="$(sha256sum "$scratch/recovery-source-setup.bin" | awk '{print $1}')"
printf '%s\n' 'setup.mode=recovered-preprocessing' \
  "recovery.source_setup_sha256=$recovery_digest" \
  >> "$recovered_run/shared/setup-result.txt"
printf '%s\n' "$recovered_run" > "$pointer"
PATH="$fake_bin:$PATH" "$helper" complete \
  "$recovered_run" "$artifact_root" "$archive_root" "$pointer" \
  > "$scratch/recovered-output.txt"
[[ ! -e "$recovered_run" && ! -e "$pointer" ]]
recovered_archive="$archive_root/base-target-balancedLaned-recovered.evidence.tar.gz"
tar -xOzf "$recovered_archive" \
  './evidence/shared/recovery-source-setup.bin' \
  > "$scratch/archived-recovery-source-setup.bin"
cmp "$scratch/recovery-source-setup.bin" \
  "$scratch/archived-recovery-source-setup.bin"
tar -xOzf "$recovered_archive" './evidence/shared/setup-result.txt' | \
  grep -Fqx "recovery.source_setup_sha256=$recovery_digest"
tar -tzf "$recovered_archive" > "$scratch/recovered-archive-files.txt"
if grep -q '/preprocessing/' "$scratch/recovered-archive-files.txt"; then
  printf '%s\n' 'recovered archive retained private role preprocessing' >&2
  exit 1
fi
PATH="$fake_bin:$PATH" "$helper" complete \
  "$recovered_run" "$artifact_root" "$archive_root" "$pointer" \
  > "$scratch/recovered-idempotent-output.txt"
grep -q '^ARCHIVE PASS (existing):' \
  "$scratch/recovered-idempotent-output.txt"

# Local completion is setup plus its one client. It has no server or
# request/response transcript, and its distinct terminal key must be honored.
local_run="$artifact_root/runs/local-target-balancedLaned-example"
local_pointer="$artifact_root/current-local-target-balancedLaned.run"
make_complete_local_run "$local_run"
printf '%s\n' "$local_run" > "$local_pointer"
PATH="$fake_bin:$PATH" "$helper" complete \
  "$local_run" "$artifact_root" "$archive_root" "$local_pointer" \
  > "$scratch/local-output.txt"
grep -q '^ARCHIVE PASS:' "$scratch/local-output.txt"
grep -q '^RETIRE PASS:' "$scratch/local-output.txt"
[[ ! -e "$local_run" && ! -e "$local_pointer" ]]
local_archive="$archive_root/local-target-balancedLaned-example.evidence.tar.gz"
tar -tzf "$local_archive" > "$scratch/local-archive-files.txt"
grep -q './evidence/client/result.txt' "$scratch/local-archive-files.txt"
if grep -q './evidence/server/' "$scratch/local-archive-files.txt"; then
  printf '%s\n' 'Local evidence archive unexpectedly contains a server role' >&2
  exit 1
fi

# Extending completion for Local must not weaken the two-role variants.
base_without_server="$artifact_root/runs/base-quick-missing-server"
base_without_server_pointer="$artifact_root/current-base-quick.run"
make_complete_local_run "$base_without_server" base quick
printf 'verification.result=PASS\n' > "$base_without_server/client/result.txt"
printf '%s\n' "$base_without_server" > "$base_without_server_pointer"
if PATH="$fake_bin:$PATH" "$helper" complete \
    "$base_without_server" "$artifact_root" "$archive_root" \
    "$base_without_server_pointer" >/dev/null 2>&1; then
  printf '%s\n' 'Base completion unexpectedly accepted a missing server role' >&2
  exit 1
fi
[[ -d "$base_without_server" && -f "$base_without_server_pointer" ]]

# A corrupted cross-variant pointer must never reinterpret an accepted run as
# failed and authorize permanent failed-run retirement.
misbound_run="$artifact_root/runs/base-quick-misbound"
misbound_pointer="$artifact_root/current-local-quick.run"
make_complete_run "$misbound_run" base quick
printf '%s\n' "$misbound_run" > "$misbound_pointer"
if PATH="$fake_bin:$PATH" "$helper" failed \
    "$misbound_run" "$artifact_root" "$archive_root" \
    "$misbound_pointer" --confirm-retire-failed-current-run \
    >/dev/null 2>&1; then
  printf '%s\n' \
    'cross-variant pointer unexpectedly authorized failed-run retirement' >&2
  exit 1
fi
[[ -d "$misbound_run" && -f "$misbound_pointer" ]]

# A mount at or below the exact run remains a fail-closed stop condition.
mounted_run="$artifact_root/runs/base-target-balancedLaned-mounted"
mounted_pointer="$artifact_root/current-base-target-balancedLaned.run"
make_complete_run "$mounted_run"
printf '%s\n' "$mounted_run" > "$mounted_pointer"
if FAKE_FINDMNT_TARGETS="$mounted_run/server/work" \
    PATH="$fake_bin:$PATH" "$helper" complete \
    "$mounted_run" "$artifact_root" "$archive_root" "$mounted_pointer" \
    >/dev/null 2>&1; then
  printf '%s\n' 'nested mount unexpectedly allowed run retirement' >&2
  exit 1
fi
[[ -d "$mounted_run" && -f "$mounted_pointer" ]]

# The 250 MB cap is checked before anything is retired.
oversized_run="$artifact_root/runs/folded-target-balancedLaned-oversized"
oversized_pointer="$artifact_root/current-folded-target-balancedLaned.run"
make_complete_run "$oversized_run" folded target-balancedLaned
truncate -s 125000001 "$oversized_run/server/progress.jsonl"
printf '%s\n' "$oversized_run" > "$oversized_pointer"
if PATH="$fake_bin:$PATH" "$helper" complete \
    "$oversized_run" "$artifact_root" "$archive_root" \
    "$oversized_pointer" >/dev/null 2>&1; then
  printf '%s\n' 'oversized evidence unexpectedly archived' >&2
  exit 1
fi
[[ -d "$oversized_run" && -f "$oversized_pointer" ]]

# Free-space admission also fails without deleting source data.
space_run="$artifact_root/runs/base-quick-no-space"
space_pointer="$artifact_root/current-base-quick.run"
make_complete_run "$space_run" base quick
printf '%s\n' "$space_run" > "$space_pointer"
if FAKE_DF_AVAILABLE=1 PATH="$fake_bin:$PATH" "$helper" complete \
    "$space_run" "$artifact_root" "$archive_root" "$space_pointer" \
    >/dev/null 2>&1; then
  printf '%s\n' 'archive publication ignored insufficient free space' >&2
  exit 1
fi
[[ -d "$space_run" && -f "$space_pointer" ]]

# Failed/abandoned retirement is confirmation-gated and current-run scoped.
failed_run="$artifact_root/runs/laned-target-balancedLaned-b128-failed"
failed_pointer="$artifact_root/current-laned-target-balancedLaned-b128.run"
mkdir -m 0700 "$failed_run" "$failed_run/shared" "$failed_run/client" \
  "$failed_run/server" "$failed_run/server/work"
: > "$failed_run/shared/lifecycle.lock"
chmod 0600 "$failed_run/shared/lifecycle.lock"
printf '{"status":"failed"}\n' > "$failed_run/server/activity.jsonl"
printf 'error=deliberate fixture\n' > "$failed_run/server/failure.txt"
truncate -s 1048576 "$failed_run/server/work/large-not-archived.bin"
printf '%s\n' "$failed_run" > "$failed_pointer"
if PATH="$fake_bin:$PATH" "$helper" failed \
    "$failed_run" "$artifact_root" "$archive_root" "$failed_pointer" \
    >/dev/null 2>&1; then
  printf '%s\n' 'failed-run retirement did not require confirmation' >&2
  exit 1
fi
[[ -d "$failed_run" && -f "$failed_pointer" ]]

other_pointer="$artifact_root/current-laned-target-balancedLaned-b1.run"
printf '%s\n' "$artifact_root/runs/some-other-run" > "$other_pointer"
if PATH="$fake_bin:$PATH" "$helper" failed \
    "$failed_run" "$artifact_root" "$archive_root" "$other_pointer" \
    --confirm-retire-failed-current-run >/dev/null 2>&1; then
  printf '%s\n' 'failed-run retirement accepted a different current pointer' >&2
  exit 1
fi
[[ -d "$failed_run" ]]

if FAKE_FLOCK_REJECT_FD=23 PATH="$fake_bin:$PATH" "$helper" failed \
    "$failed_run" "$artifact_root" "$archive_root" "$failed_pointer" \
    --confirm-retire-failed-current-run >/dev/null 2>&1; then
  printf '%s\n' 'active lifecycle lock unexpectedly allowed retirement' >&2
  exit 1
fi
[[ -d "$failed_run" ]]

if FAKE_FLOCK_REJECT_FD=22 PATH="$fake_bin:$PATH" "$helper" failed \
    "$failed_run" "$artifact_root" "$archive_root" "$failed_pointer" \
    --confirm-retire-failed-current-run >/dev/null 2>&1; then
  printf '%s\n' 'active role activity lock unexpectedly allowed retirement' >&2
  exit 1
fi
[[ -d "$failed_run" ]]

PATH="$fake_bin:$PATH" "$helper" failed \
  "$failed_run" "$artifact_root" "$archive_root" "$failed_pointer" \
  --confirm-retire-failed-current-run > "$scratch/failed-output.txt"
grep -q '^ARCHIVE PASS:' "$scratch/failed-output.txt"
grep -q '^RETIRE PASS:' "$scratch/failed-output.txt"
[[ ! -e "$failed_run" && ! -e "$failed_pointer" ]]
failed_archive="$archive_root/laned-target-balancedLaned-b128-failed.failed-evidence.tar.gz"
failed_human="$archive_root/laned-target-balancedLaned-b128-failed.failed.txt"
[[ -f "$failed_archive" && -f "$failed_archive.sha256" &&
   -f "$failed_human" ]]
tar -tzf "$failed_archive" > "$scratch/failed-archive-files.txt"
grep -q './evidence/server/failure.txt' "$scratch/failed-archive-files.txt"
if grep -q 'large-not-archived.bin' "$scratch/failed-archive-files.txt"; then
  printf '%s\n' 'failed archive retained a large work artifact' >&2
  exit 1
fi

# Non-normalized and overly broad roots fail before any removal.
unsafe_run="$artifact_root/runs/base-target-balancedLaned-unsafe"
unsafe_pointer="$artifact_root/current-base-target-balancedLaned.run"
make_complete_run "$unsafe_run"
printf '%s\n' "$unsafe_run" > "$unsafe_pointer"
if PATH="$fake_bin:$PATH" "$helper" complete \
    "$artifact_root/runs/../runs/base-target-balancedLaned-unsafe" \
    "$artifact_root" "$archive_root" "$unsafe_pointer" \
    >/dev/null 2>&1; then
  printf '%s\n' 'non-normalized run path unexpectedly allowed retirement' >&2
  exit 1
fi
[[ -d "$unsafe_run" ]]
