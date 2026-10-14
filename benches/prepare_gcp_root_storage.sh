#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly default_storage_root=/var/lib/laminate-storage

usage() {
  cat <<'EOF'
Usage:
  sudo benches/prepare_gcp_root_storage.sh prepare \
    --confirm-share-root-filesystem
  benches/prepare_gcp_root_storage.sh verify

prepare creates an owner-only benchmark directory on the filesystem mounted at
/. This is the canonical layout when the locked 10,000-GB Hyperdisk is the VM's
root disk. It does not format, partition, mount, remount, or delete anything.
Target provenance records that the operating system and benchmark share the
filesystem. verify is read-only.

Environment:
  LAMINATE_STORAGE_MOUNT    Storage directory on the root filesystem
                            (required: /var/lib/laminate-storage)
  LAMINATE_BENCH_ROOT       Artifact root below it
                            (default: STORAGE/laminate-bench)
  LAMINATE_STORAGE_MIN_TOTAL_BYTES
                            Optional operator capacity floor (default: 1)
  LAMINATE_BENCH_ARCHIVE_ROOT
                            Compact evidence archive outside live storage
                            (required: /var/lib/laminate-bench-archive)

The documented `sudo env ...` invocation preserves this path contract through
sudo, which commonly removes caller-defined environment variables.
EOF
}

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

[[ $# -ge 1 ]] || {
  usage >&2
  exit 2
}

action="$1"
shift
storage_root="${LAMINATE_STORAGE_MOUNT:-$default_storage_root}"
artifact_root="${LAMINATE_BENCH_ROOT:-$storage_root/laminate-bench}"
archive_root="${LAMINATE_BENCH_ARCHIVE_ROOT:-/var/lib/laminate-bench-archive}"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=support/target_storage_contract.sh
source "$script_directory/support/target_storage_contract.sh"

case "$action" in
  prepare)
    [[ $# -eq 1 && "$1" == --confirm-share-root-filesystem ]] || {
      usage >&2
      exit 2
    }
    ;;
  verify)
    [[ $# -eq 0 ]] || {
      usage >&2
      exit 2
    }
    verify_laminate_target_storage_root "$artifact_root" "$storage_root"
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

[[ "$(id -u)" -eq 0 ]] || fail 'prepare must be run through sudo'
benchmark_user="${SUDO_USER:-}"
[[ -n "$benchmark_user" && "$benchmark_user" != root ]] || \
  fail 'run prepare as the benchmark login user through sudo, not as a root login'
benchmark_uid="$(id -u "$benchmark_user")"
benchmark_gid="$(id -g "$benchmark_user")"

for command in find findmnt install mountpoint sudo; do
  command -v "$command" >/dev/null 2>&1 || \
    fail "required host tool is missing: $command"
done

# Keep the shared-root layout distinct from the mount point used by dedicated
# disks. This prevents a missing data-disk mount from silently becoming an OS-
# disk benchmark after a reboot.
laminate_require_normalized_dedicated_path \
  "$storage_root" LAMINATE_STORAGE_MOUNT || exit 1
[[ "$storage_root" == "$default_storage_root" ]] || \
  fail "shared-root LAMINATE_STORAGE_MOUNT must be $default_storage_root"
laminate_require_normalized_dedicated_path \
  "$artifact_root" LAMINATE_BENCH_ROOT || exit 1
laminate_require_normalized_dedicated_path \
  "$archive_root" LAMINATE_BENCH_ARCHIVE_ROOT || exit 1
laminate_require_gcp_archive_root "$archive_root" || exit 1
[[ "$artifact_root" == "$storage_root/laminate-bench" ]] || \
  fail 'LAMINATE_BENCH_ROOT must be exactly STORAGE/laminate-bench'
[[ "$archive_root" != "$storage_root" &&
   "$archive_root" != "$storage_root/"* &&
   "$storage_root" != "$archive_root/"* ]] || \
  fail 'LAMINATE_BENCH_ARCHIVE_ROOT and live storage must be disjoint'
if mountpoint -q -- "$storage_root"; then
  fail 'shared-root storage must be a directory on /, not a separate mount point'
fi

# Confirm the destination parent really belongs to the ext4 root filesystem
# before creating anything. Normal GCP root mounts use relatime; unlike a
# dedicated scratch mount, shared-root storage does not require noatime.
parent="${storage_root%/*}"
[[ -d "$parent" && ! -L "$parent" ]] || \
  fail "shared-root storage parent is missing or unsafe: $parent"
root_record="$(laminate_read_mount_record "$parent")" || \
  fail "cannot inspect the filesystem containing $parent"
record_pattern='^SOURCE="([^"]+)"[[:space:]]+TARGET="([^"]+)"[[:space:]]+FSTYPE="([^"]+)"[[:space:]]+OPTIONS="([^"]+)"$'
[[ "$root_record" =~ $record_pattern ]] || \
  fail "unexpected findmnt response for $parent"
[[ "${BASH_REMATCH[2]}" == / ]] || \
  fail "$storage_root is not on the filesystem mounted at /"
[[ "${BASH_REMATCH[3]}" == ext4 ]] || \
  fail 'shared-root target storage requires an ext4 root filesystem'
laminate_mount_option_present "${BASH_REMATCH[4]}" rw || \
  fail 'the root filesystem is not mounted read-write'

if [[ -e "$storage_root" || -L "$storage_root" ]]; then
  [[ -d "$storage_root" && ! -L "$storage_root" ]] || \
    fail "shared-root storage path is not a safe directory: $storage_root"
  while IFS= read -r existing; do
    case "${existing##*/}" in
      .laminate-shared-root-storage|laminate-bench|toolchain) ;;
      *) fail "shared-root storage has an unexpected existing entry: $existing" ;;
    esac
  done < <(find "$storage_root" -mindepth 1 -maxdepth 1 -print)
fi

for directory in \
  "$artifact_root" "$artifact_root/runs" "$artifact_root/logs" \
  "$storage_root/toolchain" "$storage_root/toolchain/src" \
  "$storage_root/toolchain/build" "$storage_root/toolchain/install"; do
  if [[ -e "$directory" || -L "$directory" ]]; then
    [[ -d "$directory" && ! -L "$directory" ]] || \
      fail "benchmark layout contains an unsafe path: $directory"
  fi
done

install -d -m 0700 -o "$benchmark_uid" -g "$benchmark_gid" \
  "$storage_root" "$artifact_root" "$artifact_root/runs" \
  "$artifact_root/logs" "$storage_root/toolchain" \
  "$storage_root/toolchain/src" "$storage_root/toolchain/build" \
  "$storage_root/toolchain/install"
laminate_prepare_gcp_archive_root \
  "$archive_root" "$benchmark_uid" "$benchmark_gid"

marker="$(laminate_shared_root_marker_path "$storage_root")"
if [[ -e "$marker" || -L "$marker" ]]; then
  [[ -f "$marker" && ! -L "$marker" ]] || \
    fail "shared-root storage marker is unsafe: $marker"
fi
install -m 0600 -o "$benchmark_uid" -g "$benchmark_gid" \
  /dev/null "$marker"
printf '%s\n' \
  'laminate-storage-backend=shared-root-filesystem-v1' > "$marker"

sudo -u "$benchmark_user" env \
  LAMINATE_STORAGE_MOUNT="$storage_root" \
  LAMINATE_BENCH_ROOT="$artifact_root" \
  LAMINATE_STORAGE_MIN_TOTAL_BYTES="${LAMINATE_STORAGE_MIN_TOTAL_BYTES:-1}" \
  "$script_directory/prepare_gcp_root_storage.sh" verify
printf '%s\n' \
  'Root-Hyperdisk preparation complete. Benchmark storage and the OS share this filesystem.'
