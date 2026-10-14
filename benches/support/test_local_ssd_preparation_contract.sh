#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s PREPARATION_HELPER\n' "$0" >&2
  exit 2
fi

helper="$1"
for required in \
  'laminate_require_normalized_dedicated_path' \
  'LAMINATE_BENCH_ROOT must be exactly MOUNT/laminate-bench' \
  'LAMINATE_STORAGE_MOUNT must be one dedicated child of /mnt/disks' \
  'laminate_require_gcp_archive_root "$archive_root"' \
  'laminate_prepare_gcp_archive_root' \
  'LAMINATE_STORAGE_MIN_TOTAL_BYTES:-1' \
  'refusing to mount over a non-empty directory' \
  'expected at least two Google Local SSD links' \
  'DESTROYING all %s attached ephemeral Google Local SSD devices' \
  'Local SSD already has partitions or mapped children' \
  'Local SSD is already held by another block device' \
  'local_ssd_count="${#local_ssd_devices[@]}"' \
  '--raid-devices="$local_ssd_count"' \
  '--chunk=512K' \
  '-b 4096' \
  '-T largefile' \
  'stripe_width=$((128 * local_ssd_count))' \
  'stride=128,stripe_width=$stripe_width' \
  'lazy_itable_init=0,lazy_journal_init=0' \
  'RAID stripe width:' \
  'mount -o noatime,nodiratime' \
  '"$mount_path/toolchain/src"' \
  '"$mount_path/toolchain/build"' \
  '"$mount_path/toolchain/install"' \
  'verify_laminate_target_storage_root'; do
  if ! grep -Fq -- "$required" "$helper"; then
    printf 'Local SSD preparation omitted required contract: %s\n' \
      "$required" >&2
    exit 1
  fi
done
if grep -Fq -- '-T largefile4' "$helper"; then
  printf '%s\n' 'Local SSD preparation used the unsafe low-inode largefile4 profile' >&2
  exit 1
fi
for forbidden in '>> /etc/fstab' 'fstab_record=' 'blkid -s UUID'; do
  if grep -Fq -- "$forbidden" "$helper"; then
    printf 'ephemeral Local SSD preparation retained forbidden persistence: %s\n' \
      "$forbidden" >&2
    exit 1
  fi
done

path_validation_line="$(grep -n -m1 \
  'laminate_require_normalized_dedicated_path' "$helper" | cut -d: -f1)"
device_destruction_line="$(grep -n -m1 'wipefs --all' "$helper" | cut -d: -f1)"
if [[ -z "$path_validation_line" || -z "$device_destruction_line" ||
      "$path_validation_line" -ge "$device_destruction_line" ]]; then
  printf '%s\n' \
    'path validation must occur before the first destructive device command' >&2
  exit 1
fi

usage_output=''
usage_status=0
usage_output="$("$helper" 2>&1)" || usage_status=$?
if [[ "$usage_status" -ne 2 ||
      "$usage_output" != *'--confirm-destroy-local-ssds'* ]]; then
  printf '%s\n' \
    'Local SSD preparation usage did not fail closed behind literal confirmation' >&2
  exit 1
fi
