#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s ROOT_STORAGE_HELPER\n' "$0" >&2
  exit 2
fi

helper="$1"
for required in \
  '/var/lib/laminate-storage' \
  '--confirm-share-root-filesystem' \
  'laminate_require_normalized_dedicated_path' \
  'shared-root LAMINATE_STORAGE_MOUNT must be $default_storage_root' \
  'LAMINATE_BENCH_ROOT must be exactly STORAGE/laminate-bench' \
  '.laminate-shared-root-storage' \
  'laminate-storage-backend=shared-root-filesystem-v1' \
  'laminate_require_gcp_archive_root "$archive_root"' \
  'laminate_prepare_gcp_archive_root' \
  'mountpoint -q -- "$storage_root"' \
  'unexpected existing entry' \
  'verify_laminate_target_storage_root "$artifact_root" "$storage_root"' \
  'Root-Hyperdisk preparation complete.'; do
  grep -Fq -- "$required" "$helper" || {
    printf 'Shared-root preparation omitted required contract: %s\n' \
      "$required" >&2
    exit 1
  }
done

# This helper only creates a directory layout. Any storage-destructive or
# mount-changing command would violate its central safety property.
for forbidden in \
  wipefs mkfs.ext4 fdisk parted mdadm losetup; do
  if grep -Eq "^[[:space:]]*$forbidden([[:space:]]|$)" "$helper"; then
    printf 'Shared-root preparation contains forbidden command: %s\n' \
      "$forbidden" >&2
    exit 1
  fi
done
if grep -Eq '^[[:space:]]*mount[[:space:]]' "$helper" ||
   grep -Eq '(^|[[:space:]])(>>?|tee[^|]*)[[:space:]]+/etc/fstab' "$helper"; then
  printf '%s\n' \
    'Shared-root preparation unexpectedly changes mounts or /etc/fstab' >&2
  exit 1
fi

usage_output=''
usage_status=0
usage_output="$("$helper" 2>&1)" || usage_status=$?
if [[ "$usage_status" -ne 2 ||
      "$usage_output" != *'--confirm-share-root-filesystem'* ]]; then
  printf 'Shared-root preparation usage failed closed incorrectly:\n%s\n' \
    "$usage_output" >&2
  exit 1
fi
