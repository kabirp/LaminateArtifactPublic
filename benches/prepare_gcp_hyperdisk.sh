#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly default_mount=/mnt/disks/laminate-storage

usage() {
  cat <<'EOF'
Usage:
  benches/prepare_gcp_hyperdisk.sh inspect
  sudo benches/prepare_gcp_hyperdisk.sh prepare \
    --confirm-destroy-hyperdisk
  sudo benches/prepare_gcp_hyperdisk.sh prepare \
    --device /dev/disk/by-id/google-DATA-DISK-NAME \
    --confirm-destroy-hyperdisk
  sudo benches/prepare_gcp_hyperdisk.sh mount
  sudo benches/prepare_gcp_hyperdisk.sh mount \
    --device /dev/disk/by-id/google-DATA-DISK-NAME
  benches/prepare_gcp_hyperdisk.sh verify

prepare permanently erases one dedicated whole block device, formats it as
ext4, and mounts it for the invoking user. mount attaches an already prepared
ext4 device after a reboot without formatting it. inspect and verify are
read-only.

When --device is omitted, prepare and mount proceed only if exactly one safe
dedicated Google data disk is visible. inspect shows what that automatic
selection sees. No gcloud permissions or Compute API access are required.

The helper rejects partitions, Google Local SSD members, mounted devices, and
anything sharing block-device ancestry with the root or boot filesystem. It
does not modify /etc/fstab.

Environment:
  LAMINATE_STORAGE_MOUNT    Mount path (default: /mnt/disks/laminate-storage)
  LAMINATE_BENCH_ROOT       Artifact root below it
                            (default: MOUNT/laminate-bench)
  LAMINATE_STORAGE_MIN_TOTAL_BYTES
                            Optional operator capacity floor (default: 1)
  LAMINATE_BENCH_ARCHIVE_ROOT
                            Small durable evidence archive on another
                            filesystem
                            (required: /var/lib/laminate-bench-archive)

The documented `sudo env ...` invocation preserves any non-default paths for
prepare or mount; ordinary sudo commonly removes caller-defined variables.
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
mount_path="${LAMINATE_STORAGE_MOUNT:-$default_mount}"
artifact_root="${LAMINATE_BENCH_ROOT:-$mount_path/laminate-bench}"
archive_root="${LAMINATE_BENCH_ARCHIVE_ROOT:-/var/lib/laminate-bench-archive}"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=support/target_storage_contract.sh
source "$script_directory/support/target_storage_contract.sh"

device_link=''
device_option_seen=false
destruction_confirmed=false
case "$action" in
  inspect|verify)
    [[ $# -eq 0 ]] || {
      usage >&2
      exit 2
    }
    ;;
  prepare)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --device)
          [[ "$device_option_seen" == false && $# -ge 2 && -n "$2" ]] || {
            usage >&2
            exit 2
          }
          device_option_seen=true
          device_link="$2"
          shift 2
          ;;
        --confirm-destroy-hyperdisk)
          [[ "$destruction_confirmed" == false ]] || {
            usage >&2
            exit 2
          }
          destruction_confirmed=true
          shift
          ;;
        *)
          usage >&2
          exit 2
          ;;
      esac
    done
    [[ "$destruction_confirmed" == true ]] || {
      usage >&2
      exit 2
    }
    ;;
  mount)
    if [[ $# -gt 0 ]]; then
      [[ $# -eq 2 && "$1" == --device && -n "$2" ]] || {
        usage >&2
        exit 2
      }
      device_option_seen=true
      device_link="$2"
    fi
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

google_by_id_directory="${LAMINATE_GOOGLE_DEVICE_BY_ID_DIRECTORY:-/dev/disk/by-id}"
findmnt_command="${LAMINATE_FINDMNT_COMMAND:-findmnt}"
lsblk_command="${LAMINATE_LSBLK_COMMAND:-lsblk}"
sys_block_root="${LAMINATE_SYS_BLOCK_ROOT:-/sys/class/block}"
eligible_device_links=()
eligible_devices=()

# Apply the same topology checks used immediately before formatting/mounting.
# This function deliberately does not accept partitions, mounted disks, disks
# with child mappings, Local SSD members, or root/boot ancestry.
validate_unmounted_whole_data_disk() {
  local candidate="$1"
  laminate_validate_dedicated_block "$candidate" >/dev/null || return 1

  local node tree_count=0 only_node=''
  while IFS= read -r node; do
    [[ -n "$node" ]] || continue
    tree_count=$((tree_count + 1))
    only_node="$node"
  done < <("$lsblk_command" -nrpo NAME -- "$candidate")
  if [[ "$tree_count" -ne 1 || "$only_node" != "$candidate" ]]; then
    printf 'ERROR: dedicated Hyperdisk already has partitions or mapped children: %s\n' \
      "$candidate" >&2
    return 1
  fi

  local candidate_name="${candidate##*/}"
  local holder
  for holder in "$sys_block_root/$candidate_name/holders/"*; do
    [[ -e "$holder" || -L "$holder" ]] || continue
    printf 'ERROR: dedicated Hyperdisk is held by another block device: %s\n' \
      "$candidate" >&2
    return 1
  done
  if "$lsblk_command" -nr -o MOUNTPOINTS -- "$candidate" | \
      grep -q '[^[:space:]]'; then
    printf 'ERROR: dedicated Hyperdisk is already mounted: %s\n' \
      "$candidate" >&2
    return 1
  fi
}

# Discover aliases exposed by the guest kernel. Multiple aliases resolving to
# one disk count once. A stale symlink is ignored because its target must
# still exist and pass lsblk validation.
discover_eligible_data_disks() {
  eligible_device_links=()
  eligible_devices=()

  local link link_name candidate existing duplicate index
  for link in "$google_by_id_directory"/google-*; do
    [[ -L "$link" ]] || continue
    link_name="${link##*/}"
    case "$link_name" in
      google-local-nvme-ssd-*|*-part[0-9]*) continue ;;
    esac
    candidate="$(readlink -f -- "$link")" || continue
    [[ -e "$candidate" ]] || continue
    validate_unmounted_whole_data_disk "$candidate" >/dev/null 2>&1 || \
      continue

    duplicate=false
    for ((index = 0; index < ${#eligible_devices[@]}; ++index)); do
      existing="${eligible_devices[index]}"
      if [[ "$existing" == "$candidate" ]]; then
        duplicate=true
        break
      fi
    done
    if [[ "$duplicate" == false ]]; then
      eligible_device_links+=("$link")
      eligible_devices+=("$candidate")
    fi
  done
}

print_discovery_result() {
  discover_eligible_data_disks
  printf '%s\n' 'Laminate dedicated-data-disk inspection'
  if [[ "${#eligible_devices[@]}" -eq 0 ]]; then
    printf '%s\n' \
      '  Eligible dedicated data disks: none' \
      '' \
      'No safe, unmounted, whole Google data disk is currently eligible.' \
      'Increasing the size of the boot disk does not create a separate target data disk.' \
      'To use that existing root filesystem, follow storage option A in docs/GCP_BENCHMARKS.md.' \
      'Otherwise inspect `lsblk`, attach or unmount one data disk, run `sudo udevadm settle`, and inspect again.' \
      'No device was modified.'
    return 0
  fi

  printf '  Eligible dedicated data disks: %s\n' \
    "${#eligible_devices[@]}"
  local index size filesystem label
  for ((index = 0; index < ${#eligible_devices[@]}; ++index)); do
    size="$("$lsblk_command" -d -n -r -o SIZE -- \
      "${eligible_devices[index]}" 2>/dev/null || true)"
    filesystem="$("$lsblk_command" -d -n -r -o FSTYPE -- \
      "${eligible_devices[index]}" 2>/dev/null || true)"
    label="$("$lsblk_command" -d -n -r -o LABEL -- \
      "${eligible_devices[index]}" 2>/dev/null || true)"
    printf '  %s -> %s (size=%s; filesystem=%s; label=%s)\n' \
      "${eligible_device_links[index]}" "${eligible_devices[index]}" \
      "${size:-unknown}" "${filesystem:-none}" "${label:-none}"
  done
  if [[ "${#eligible_devices[@]}" -eq 1 ]]; then
    printf '%s\n' \
      'Automatic selection is unambiguous. prepare or mount may omit --device.'
  else
    printf '%s\n' \
      'Automatic selection is disabled because more than one safe disk is visible.' \
      'Pass one exact path above with --device; Laminate will not guess.'
  fi
  printf '%s\n' 'No device was modified.'
}

select_automatic_data_disk() {
  discover_eligible_data_disks
  if [[ "${#eligible_devices[@]}" -eq 0 ]]; then
    print_discovery_result >&2
    return 1
  fi
  if [[ "${#eligible_devices[@]}" -gt 1 ]]; then
    print_discovery_result >&2
    return 1
  fi
  device_link="${eligible_device_links[0]}"
  printf 'Automatically selected dedicated data disk: %s -> %s\n' \
    "$device_link" "${eligible_devices[0]}"
}

for command in "$findmnt_command" "$lsblk_command" grep readlink; do
  command -v "$command" >/dev/null 2>&1 || \
    fail "required host tool is missing: $command"
done

if [[ "$action" == inspect ]]; then
  print_discovery_result
  exit 0
fi
if [[ "$action" == verify ]]; then
  verify_laminate_target_storage_root "$artifact_root" "$mount_path"
  exit 0
fi

[[ "$(id -u)" -eq 0 ]] || fail "$action must be run through sudo"
benchmark_user="${SUDO_USER:-}"
[[ -n "$benchmark_user" && "$benchmark_user" != root ]] || \
  fail "run $action as the benchmark login user through sudo, not as a root login"
benchmark_uid="$(id -u "$benchmark_user")"
benchmark_gid="$(id -g "$benchmark_user")"

for command in find install mountpoint sudo; do
  command -v "$command" >/dev/null 2>&1 || \
    fail "required host tool is missing: $command"
done
if [[ "$action" == prepare ]]; then
  for command in blkid mkfs.ext4 tune2fs wipefs; do
    command -v "$command" >/dev/null 2>&1 || \
      fail "required host tool is missing: $command"
  done
else
  command -v blkid >/dev/null 2>&1 || \
    fail 'required host tool is missing: blkid'
fi

if [[ -z "$device_link" ]]; then
  select_automatic_data_disk || exit 1
fi

# Validate every operator-controlled path and the full device identity before
# the first destructive command or mount.
laminate_require_normalized_dedicated_path \
  "$mount_path" LAMINATE_STORAGE_MOUNT || exit 1
laminate_require_normalized_dedicated_path \
  "$artifact_root" LAMINATE_BENCH_ROOT || exit 1
laminate_require_normalized_dedicated_path \
  "$archive_root" LAMINATE_BENCH_ARCHIVE_ROOT || exit 1
laminate_require_gcp_archive_root "$archive_root" || exit 1
case "$mount_path" in
  /mnt/disks/*)
    [[ "${mount_path#/mnt/disks/}" != */* ]] || \
      fail 'LAMINATE_STORAGE_MOUNT must be one dedicated child of /mnt/disks'
    ;;
  *) fail 'LAMINATE_STORAGE_MOUNT must be one dedicated child of /mnt/disks' ;;
esac
[[ "$artifact_root" == "$mount_path/laminate-bench" ]] || \
  fail 'LAMINATE_BENCH_ROOT must be exactly MOUNT/laminate-bench'
[[ "$archive_root" != "$mount_path" &&
   "$archive_root" != "$mount_path/"* ]] || \
  fail 'LAMINATE_BENCH_ARCHIVE_ROOT must be outside live benchmark storage'
laminate_prepare_gcp_archive_root \
  "$archive_root" "$benchmark_uid" "$benchmark_gid"
case "$device_link" in
  "$google_by_id_directory"/google-*) ;;
  *) fail 'device must be an existing /dev/disk/by-id/google-* symlink' ;;
esac
[[ -L "$device_link" ]] || \
  fail 'device must be an existing /dev/disk/by-id/google-* symlink'
device="$(readlink -f -- "$device_link")"
[[ -b "$device" ]] || fail "device identifier is not a block device: $device_link"
validate_unmounted_whole_data_disk "$device" || \
  fail "device is not one safe, unmounted, dedicated whole data disk: $device_link"

if [[ "$action" == prepare ]]; then
  signature_status=0
  blkid -p -- "$device" >/dev/null 2>&1 || signature_status=$?
  case "$signature_status" in
    0)
      fail "refusing to erase a device with an existing filesystem or storage signature: $device_link"
      ;;
    2) ;;
    *)
      fail "could not establish that the selected device is signature-free: $device_link"
      ;;
  esac
else
  filesystem_type="$(blkid -p -o value -s TYPE -- "$device")" || \
    fail "cannot identify the filesystem on the selected device: $device_link"
  filesystem_label="$(blkid -p -o value -s LABEL -- "$device")" || \
    fail "cannot identify the filesystem label on the selected device: $device_link"
  [[ "$filesystem_type" == ext4 && "$filesystem_label" == laminate-storage ]] || \
    fail "mount requires an ext4 device labeled laminate-storage: $device_link"
fi
if mountpoint -q -- "$mount_path"; then
  fail "mount path is already a mount point: $mount_path; use verify instead"
fi
if [[ -d "$mount_path" ]] &&
   [[ -n "$(find "$mount_path" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  fail "refusing to mount over a non-empty directory: $mount_path"
fi

if [[ "$action" == prepare ]]; then
  printf 'DESTROYING dedicated Hyperdisk %s (%s)\n' \
    "$device_link" "$device"
  wipefs --all --force -- "$device"
  mkfs.ext4 -F -b 4096 -m 0 -T largefile \
    -E lazy_itable_init=0,lazy_journal_init=0 \
    -L laminate-storage "$device"
  filesystem_header="$(LC_ALL=C tune2fs -l "$device")"
  grep -Eq '^Block size:[[:space:]]+4096$' <<< "$filesystem_header" || \
    fail 'new ext4 filesystem did not retain its 4096-byte block size'
else
  [[ "$(blkid -o value -s TYPE -- "$device")" == ext4 ]] || \
    fail "existing dedicated device is not ext4: $device"
fi

mkdir -p -- "$mount_path"
mount -o noatime,nodiratime "$device" "$mount_path"
install -d -m 0700 -o "$benchmark_uid" -g "$benchmark_gid" \
  "$artifact_root" "$artifact_root/runs" "$artifact_root/logs" \
  "$mount_path/toolchain" "$mount_path/toolchain/src" \
  "$mount_path/toolchain/build" "$mount_path/toolchain/install"
chown "$benchmark_uid:$benchmark_gid" "$mount_path"
chmod 0700 "$mount_path"

sudo -u "$benchmark_user" env \
  LAMINATE_STORAGE_MOUNT="$mount_path" \
  LAMINATE_BENCH_ROOT="$artifact_root" \
  LAMINATE_STORAGE_MIN_TOTAL_BYTES="${LAMINATE_STORAGE_MIN_TOTAL_BYTES:-1}" \
  "$script_directory/prepare_gcp_hyperdisk.sh" verify
printf '%s\n' \
  'Dedicated Hyperdisk preparation complete. The script did not modify /etc/fstab.'
