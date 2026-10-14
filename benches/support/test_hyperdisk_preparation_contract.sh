#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s HYPERDISK_HELPER\n' "$0" >&2
  exit 2
fi

helper="$1"
bash -n "$helper"
for required in \
  'laminate_require_normalized_dedicated_path' \
  'validate_unmounted_whole_data_disk "$device"' \
  'device must be an existing /dev/disk/by-id/google-* symlink' \
  'dedicated Hyperdisk already has partitions or mapped children' \
  'dedicated Hyperdisk is held by another block device' \
  'refusing to mount over a non-empty directory' \
  '--confirm-destroy-hyperdisk' \
  'wipefs --all --force' \
  '-b 4096' \
  '-T largefile' \
  'lazy_itable_init=0,lazy_journal_init=0' \
  'mount -o noatime,nodiratime' \
  'LAMINATE_BENCH_ROOT must be exactly MOUNT/laminate-bench' \
  'laminate_require_gcp_archive_root "$archive_root"' \
  'laminate_prepare_gcp_archive_root' \
  'verify_laminate_target_storage_root' \
  'benches/prepare_gcp_hyperdisk.sh inspect' \
  'prepare or mount may omit --device' \
  'Increasing the size of the boot disk does not create a separate target data disk.' \
  'No safe, unmounted, whole Google data disk is currently eligible.' \
  'filesystem=%s; label=%s' \
  'refusing to erase a device with an existing filesystem or storage signature' \
  'mount requires an ext4 device labeled laminate-storage' \
  'follow storage option A in docs/GCP_BENCHMARKS.md' \
  'Pass one exact path above with --device; Laminate will not guess.'; do
  grep -Fq -- "$required" "$helper" || {
    printf 'Hyperdisk preparation omitted required contract: %s\n' \
      "$required" >&2
    exit 1
  }
done
if grep -Eq '(^|[[:space:]])(>>?|tee[^|]*)[[:space:]]+/etc/fstab' "$helper"; then
  printf '%s\n' 'Hyperdisk helper unexpectedly modifies /etc/fstab' >&2
  exit 1
fi

validation_line="$(grep -n -m1 \
  'validate_unmounted_whole_data_disk "$device"' "$helper" | cut -d: -f1)"
destruction_line="$(grep -n -m1 'wipefs --all' "$helper" | cut -d: -f1)"
signature_line="$(grep -n -m1 'blkid -p -- "$device"' "$helper" | cut -d: -f1)"
if [[ -z "$validation_line" || -z "$destruction_line" ||
      -z "$signature_line" ||
      "$validation_line" -ge "$signature_line" ||
      "$signature_line" -ge "$destruction_line" ]]; then
  printf '%s\n' \
    'device validation must occur before the first destructive command' >&2
  exit 1
fi

if grep -Eq 'gcloud[[:space:]]+compute|curl.*metadata\.google\.internal' \
    "$helper"; then
  printf '%s\n' \
    'Hyperdisk guest discovery unexpectedly depends on GCP API credentials' >&2
  exit 1
fi

# Exercise read-only discovery with a fake guest block topology. This checks
# root exclusion, unique selection, alias deduplication, and multiple-candidate
# refusal without requiring root or exposing any destructive command.
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
by_id="$scratch/by-id"
device_root="$scratch/dev"
sys_block="$scratch/sys/class/block"
mkdir -p "$by_id" "$device_root" \
  "$sys_block/rootdisk/holders" "$sys_block/data0/holders" \
  "$sys_block/data1/holders"
touch "$device_root/rootp1" "$device_root/rootdisk" \
  "$device_root/data0" "$device_root/data1" "$device_root/localssd"
ln -s "$device_root/rootdisk" "$by_id/google-boot-disk"
ln -s "$device_root/localssd" "$by_id/google-local-nvme-ssd-0"

fake_findmnt="$scratch/findmnt"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf '\''SOURCE="%s" TARGET="/" FSTYPE="ext4" OPTIONS="rw,noatime"\n'\'' "$FAKE_ROOT_PARTITION"' \
  > "$fake_findmnt"
chmod +x "$fake_findmnt"

fake_lsblk="$scratch/lsblk"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'last=""' \
  'for argument in "$@"; do last="$argument"; done' \
  'case " $* " in' \
  '  *" -o TYPE "*) printf "disk\\n" ;;' \
  '  *" -o KNAME "*)' \
  '    case "${last##*/}" in' \
  '      rootp1) printf "rootp1\\nrootdisk\\n" ;;' \
  '      *) printf "%s\\n" "${last##*/}" ;;' \
  '    esac ;;' \
  '  *" -nrpo NAME "*) printf "%s\\n" "$last" ;;' \
  '  *" -o MOUNTPOINTS "*) printf "\\n" ;;' \
  '  *" -o SIZE "*) printf "1.5T\\n" ;;' \
  '  *" -o FSTYPE "*) printf "${FAKE_DATA_FSTYPE:-}\\n" ;;' \
  '  *" -o LABEL "*) printf "${FAKE_DATA_LABEL:-}\\n" ;;' \
  '  *) exit 1 ;;' \
  'esac' \
  > "$fake_lsblk"
chmod +x "$fake_lsblk"

inspect_disks() {
  env \
    LAMINATE_GOOGLE_DEVICE_BY_ID_DIRECTORY="$by_id" \
    LAMINATE_FINDMNT_COMMAND="$fake_findmnt" \
    LAMINATE_LSBLK_COMMAND="$fake_lsblk" \
    LAMINATE_SYS_BLOCK_ROOT="$sys_block" \
    LAMINATE_LOCAL_SSD_BY_ID="$by_id" \
    FAKE_ROOT_PARTITION="$device_root/rootp1" \
    FAKE_DATA_FSTYPE="${FAKE_DATA_FSTYPE:-}" \
    FAKE_DATA_LABEL="${FAKE_DATA_LABEL:-}" \
    "$helper" inspect
}

zero_output="$(inspect_disks)"
for expected in \
  'Eligible dedicated data disks: none' \
  'No safe, unmounted, whole Google data disk is currently eligible.' \
  'Increasing the size of the boot disk does not create a separate target data disk.' \
  'follow storage option A in docs/GCP_BENCHMARKS.md' \
  'No device was modified.'; do
  [[ "$zero_output" == *"$expected"* ]] || {
    printf 'zero-candidate inspection omitted: %s\n%s\n' \
      "$expected" "$zero_output" >&2
    exit 1
  }
done

ln -s "$device_root/data0" "$by_id/google-data-primary"
canonical_data0="$(readlink -f -- "$device_root/data0")"
one_output="$(inspect_disks)"
[[ "$one_output" == *'Eligible dedicated data disks: 1'* &&
   "$one_output" == *"$by_id/google-data-primary -> $canonical_data0"* &&
   "$one_output" == *'filesystem=none; label=none'* &&
   "$one_output" == *'prepare or mount may omit --device.'* ]] || {
  printf 'one-candidate inspection is incorrect:\n%s\n' "$one_output" >&2
  exit 1
}

FAKE_DATA_FSTYPE=ext4
FAKE_DATA_LABEL=laminate-storage
export FAKE_DATA_FSTYPE FAKE_DATA_LABEL
formatted_output="$(inspect_disks)"
[[ "$formatted_output" == *'filesystem=ext4; label=laminate-storage'* ]] || {
  printf 'formatted-disk inspection omitted its identity:\n%s\n' \
    "$formatted_output" >&2
  exit 1
}
unset FAKE_DATA_FSTYPE FAKE_DATA_LABEL
[[ "$one_output" != *'google-boot-disk ->'* ]] || {
  printf 'root disk unexpectedly became eligible:\n%s\n' "$one_output" >&2
  exit 1
}

ln -s "$device_root/data0" "$by_id/google-data-alias"
alias_output="$(inspect_disks)"
[[ "$alias_output" == *'Eligible dedicated data disks: 1'* ]] || {
  printf 'aliases of one disk were counted separately:\n%s\n' \
    "$alias_output" >&2
  exit 1
}
alias_matches="$(grep -c -- "-> $canonical_data0" <<< "$alias_output")"
[[ "$alias_matches" -eq 1 ]] || {
  printf 'one canonical device was printed %s times:\n%s\n' \
    "$alias_matches" "$alias_output" >&2
  exit 1
}

ln -s "$device_root/data1" "$by_id/google-data-secondary"
multiple_output="$(inspect_disks)"
for expected in \
  'Eligible dedicated data disks: 2' \
  'Automatic selection is disabled because more than one safe disk is visible.' \
  'Pass one exact path above with --device; Laminate will not guess.'; do
  [[ "$multiple_output" == *"$expected"* ]] || {
    printf 'multiple-candidate inspection omitted: %s\n%s\n' \
      "$expected" "$multiple_output" >&2
    exit 1
  }
done

usage_output=''
usage_status=0
usage_output="$("$helper" 2>&1)" || usage_status=$?
if [[ "$usage_status" -ne 2 ||
      "$usage_output" != *'--confirm-destroy-hyperdisk'* ]]; then
  printf '%s\n' \
    'Hyperdisk preparation usage did not fail closed behind literal confirmation' >&2
  exit 1
fi

empty_prepare_status=0
"$helper" prepare --device '' --confirm-destroy-hyperdisk \
  >/dev/null 2>&1 || empty_prepare_status=$?
[[ "$empty_prepare_status" -eq 2 ]] || {
  printf 'empty prepare device should exit 2, got %s\n' \
    "$empty_prepare_status" >&2
  exit 1
}
empty_mount_status=0
"$helper" mount --device '' >/dev/null 2>&1 || empty_mount_status=$?
[[ "$empty_mount_status" -eq 2 ]] || {
  printf 'empty mount device should exit 2, got %s\n' \
    "$empty_mount_status" >&2
  exit 1
}
