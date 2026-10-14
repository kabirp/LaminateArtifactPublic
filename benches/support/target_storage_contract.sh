#!/usr/bin/env bash

# Target-benchmark storage admission and provenance.
#
# The filesystem containing the artifact root determines the backend. Linux MD
# sources must be a healthy RAID0 containing every attached Google Local SSD.
# A separately mounted non-MD source must be one dedicated whole block device.
# The exact marked `/var/lib/laminate-storage` directory may use the filesystem
# mounted at `/`; it is recorded explicitly as shared-root-filesystem. Every
# backend uses ext4, read-write, owner-only artifact storage, and the same
# capacity accounting. Dedicated storage additionally requires noatime and
# must not share root/boot ancestry.

laminate_canonical_directory() {
  (cd -P -- "$1" && pwd)
}

# Resolve an absolute directory path without requiring its final components to
# exist. Existing symlink components are resolved, so callers can reject a
# dangerous spelling before creating, mounting over, or removing anything.
laminate_normalize_future_directory_path() {
  if [[ $# -ne 1 || "$1" != /* || "$1" == *$'\n'* ]]; then
    return 2
  fi

  local cursor="$1"
  local component canonical missing_suffix=''
  while [[ ! -e "$cursor" && ! -L "$cursor" ]]; do
    [[ "$cursor" != / ]] || return 1
    component="${cursor##*/}"
    case "$component" in
      ''|.|..) return 1 ;;
    esac
    missing_suffix="/$component$missing_suffix"
    cursor="${cursor%/*}"
    [[ -n "$cursor" ]] || cursor=/
  done
  [[ -d "$cursor" && ! -L "$cursor" ]] || return 1
  canonical="$(laminate_canonical_directory "$cursor")" || return 1
  canonical="${canonical%/}$missing_suffix"
  printf '%s\n' "$canonical"
}

laminate_require_normalized_dedicated_path() {
  if [[ $# -ne 2 ]]; then
    printf '%s\n' \
      'ERROR: path validation requires PATH and a human-readable label.' >&2
    return 2
  fi
  local path="$1"
  local label="$2"
  local normalized
  if [[ "$path" == *[[:space:]]* ]] ||
     ! normalized="$(laminate_normalize_future_directory_path "$path")"; then
    printf 'ERROR: %s is not a safe absolute directory path: %s\n' \
      "$label" "$path" >&2
    return 1
  fi
  if [[ "$normalized" != "$path" ]]; then
    printf 'ERROR: %s must already be normalized and contain no symlink components.\n' \
      "$label" >&2
    printf '  Supplied:   %s\n  Normalized: %s\n' \
      "$path" "$normalized" >&2
    return 1
  fi
  case "$path" in
    /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/mnt|/mnt/disks|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/var/lib)
      printf 'ERROR: %s is too broad to be a dedicated benchmark path: %s\n' \
        "$label" "$path" >&2
      return 1
      ;;
  esac
}

laminate_require_gcp_archive_root() {
  if [[ $# -ne 1 || "$1" != /var/lib/laminate-bench-archive ]]; then
    printf '%s\n' \
      'ERROR: LAMINATE_BENCH_ARCHIVE_ROOT must be /var/lib/laminate-bench-archive.' >&2
    return 1
  fi
}

laminate_path_is_below() {
  local path="$1"
  local root="$2"
  [[ "$path" == "$root" || "$path" == "$root/"* ]]
}

laminate_stat_uid() {
  stat -c '%u' -- "$1" 2>/dev/null || stat -f '%u' -- "$1"
}

laminate_stat_mode() {
  stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1"
}

# Preparation helpers run this as root. They may create the one reserved
# archive directory, but never take ownership of an arbitrary existing path.
laminate_prepare_gcp_archive_root() {
  if [[ $# -ne 3 ]]; then
    return 2
  fi
  local archive_root="$1"
  local benchmark_uid="$2"
  local benchmark_gid="$3"
  laminate_require_gcp_archive_root "$archive_root" || return 1
  if [[ -e "$archive_root" || -L "$archive_root" ]]; then
    [[ -d "$archive_root" && ! -L "$archive_root" ]] || {
      printf 'ERROR: benchmark archive path is unsafe: %s\n' \
        "$archive_root" >&2
      return 1
    }
    local owner mode
    owner="$(laminate_stat_uid "$archive_root")" || return 1
    mode="$(laminate_stat_mode "$archive_root")" || return 1
    if [[ "$owner" != "$benchmark_uid" ||
          "$((8#$mode & 0077))" -ne 0 ]]; then
      printf '%s\n' \
        'ERROR: existing benchmark archive must already be owned by the benchmark user and owner-only.' >&2
      printf '  Path: %s\n  owner uid=%s mode=%s\n' \
        "$archive_root" "$owner" "$mode" >&2
      return 1
    fi
    return 0
  fi
  install -d -m 0700 -o "$benchmark_uid" -g "$benchmark_gid" \
    "$archive_root"
}

laminate_shared_root_marker_path() {
  printf '%s/.laminate-shared-root-storage\n' "$1"
}

# A directory on / is a valid backend only when the root-storage preparation
# helper marked that exact directory. Without this opt-in, a missing dedicated
# mount such as /mnt/disks/laminate-storage could silently fall back to the OS
# disk.
laminate_validate_shared_root_marker() {
  local storage_root="$1"
  local marker owner mode value
  marker="$(laminate_shared_root_marker_path "$storage_root")"
  if [[ ! -f "$marker" || -L "$marker" ]]; then
    printf '%s\n' \
      'ERROR: storage resolves to / but is not explicitly prepared for shared-root use.' >&2
    printf '  Missing marker: %s\n' "$marker" >&2
    printf '%s\n' \
      'Run benches/prepare_gcp_root_storage.sh or mount the intended data disk.' >&2
    return 1
  fi
  owner="$(laminate_stat_uid "$marker")" || return 1
  mode="$(laminate_stat_mode "$marker")" || return 1
  if [[ "$owner" != "$(id -u)" || "$((8#$mode & 0077))" -ne 0 ]]; then
    printf 'ERROR: shared-root storage marker must be owner-only: %s\n' \
      "$marker" >&2
    return 1
  fi
  value="$(< "$marker")" || return 1
  if [[ "$value" != 'laminate-storage-backend=shared-root-filesystem-v1' ]]; then
    printf 'ERROR: shared-root storage marker has an unsupported value: %s\n' \
      "$marker" >&2
    return 1
  fi
}

laminate_validate_shared_root_layout() {
  local storage_root="$1"
  local artifact_root="$2"
  local expected_storage=/var/lib/laminate-storage
  local canonical_expected
  canonical_expected="$(laminate_canonical_directory "$expected_storage")" || {
    printf 'ERROR: shared-root storage directory is missing or unsafe: %s\n' \
      "$expected_storage" >&2
    return 1
  }
  if [[ "$storage_root" != "$canonical_expected" ]]; then
    printf 'ERROR: shared-root storage must use %s.\n' \
      "$canonical_expected" >&2
    return 1
  fi
  if [[ "$artifact_root" != "$storage_root/laminate-bench" ]]; then
    printf '%s\n' \
      'ERROR: shared-root artifact storage must be exactly STORAGE/laminate-bench.' >&2
    return 1
  fi
  local owner mode
  owner="$(laminate_stat_uid "$storage_root")" || return 1
  mode="$(laminate_stat_mode "$storage_root")" || return 1
  if [[ "$owner" != "$(id -u)" || "$((8#$mode & 0077))" -ne 0 ]]; then
    printf '%s\n' \
      'ERROR: shared-root storage directory must be owned by the benchmark user and owner-only.' >&2
    return 1
  fi
}

laminate_local_ssd_device_names() {
  local by_id_directory="$1"
  local link target
  local -a links=() device_names=()
  shopt -s nullglob
  links=("$by_id_directory"/google-local-nvme-ssd-*)
  shopt -u nullglob
  for link in "${links[@]}"; do
    if [[ ! -L "$link" ||
          ! "${link##*/}" =~ ^google-local-nvme-ssd-[0-9]+$ ]]; then
      printf 'ERROR: invalid Google Local SSD identifier: %s\n' "$link" >&2
      return 1
    fi
    target="$(readlink -f -- "$link")" || return 1
    device_names+=("${target##*/}")
  done
  if [[ "${#device_names[@]}" -gt 0 ]]; then
    printf '%s\n' "${device_names[@]}" | LC_ALL=C sort -u
  fi
}

laminate_join_comma() {
  local IFS=,
  printf '%s' "$*"
}

laminate_mount_option_present() {
  local options="$1"
  local expected="$2"
  case ",$options," in
    *",$expected,"*) return 0 ;;
    *) return 1 ;;
  esac
}

# `findmnt` can pad columns unless raw output is requested. Accept
# harmless horizontal padding around one MAJ:MIN token, but reject embedded
# whitespace, extra records, and every other spelling before constructing a
# sysfs path from it.
laminate_canonical_bdi() {
  if [[ $# -ne 1 ]]; then
    return 2
  fi
  local candidate="$1"
  if [[ "$candidate" =~ ^[[:blank:]]*([0-9]+:[0-9]+)[[:blank:]]*$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

# Filesystems mounted from a partition report the partition's MAJ:MIN, while
# Linux registers backing-device information for the containing whole disk.
# Resolve that parent only when sysfs explicitly identifies a partition; do
# not guess from device names or minor numbers.
laminate_resolve_backing_bdi() {
  if [[ $# -ne 1 ]]; then
    return 2
  fi
  local filesystem_device parent_device
  filesystem_device="$(laminate_canonical_bdi "$1")" || return 1
  local sys_bdi_root="${LAMINATE_SYS_BDI_ROOT:-/sys/class/bdi}"
  local sys_dev_block_root="${LAMINATE_SYS_DEV_BLOCK_ROOT:-/sys/dev/block}"
  if [[ -f "$sys_bdi_root/$filesystem_device/read_ahead_kb" ]]; then
    printf '%s\n' "$filesystem_device"
    return 0
  fi
  [[ -f "$sys_dev_block_root/$filesystem_device/partition" ]] || return 1
  IFS= read -r parent_device < \
    "$sys_dev_block_root/$filesystem_device/../dev" || return 1
  parent_device="$(laminate_canonical_bdi "$parent_device")" || return 1
  [[ -f "$sys_bdi_root/$parent_device/read_ahead_kb" ]] || return 1
  printf '%s\n' "$parent_device"
}

laminate_read_filesystem_capacity() {
  local root="$1"
  local df_command="${LAMINATE_DF_COMMAND:-df}"
  local df_record total_bytes='' available_bytes='' ignored
  df_record="$($df_command -B1 --output=size,avail -- "$root")" || return 1
  while read -r total_candidate available_candidate ignored; do
    if [[ "$total_candidate" =~ ^[1-9][0-9]*$ &&
          "$available_candidate" =~ ^(0|[1-9][0-9]*)$ ]]; then
      [[ -z "$total_bytes" ]] || return 1
      total_bytes="$total_candidate"
      available_bytes="$available_candidate"
    fi
  done <<< "$df_record"
  [[ -n "$total_bytes" && "$available_bytes" -le "$total_bytes" ]] || return 1
  printf '%s %s\n' "$total_bytes" "$available_bytes"
}

laminate_read_mount_record() {
  local target="$1"
  local findmnt_command="${LAMINATE_FINDMNT_COMMAND:-findmnt}"
  "$findmnt_command" -n -P -o SOURCE,TARGET,FSTYPE,OPTIONS --target "$target"
}

laminate_device_ancestry_names() {
  local device="$1"
  local lsblk_command="${LAMINATE_LSBLK_COMMAND:-lsblk}"
  "$lsblk_command" -s -n -r -o KNAME -- "$device" | \
    awk 'NF == 1 && !seen[$1]++ { print $1 }'
}

laminate_validate_dedicated_block() {
  local source_path="$1"
  local source_name="${source_path##*/}"
  local findmnt_command="${LAMINATE_FINDMNT_COMMAND:-findmnt}"
  local lsblk_command="${LAMINATE_LSBLK_COMMAND:-lsblk}"
  local device_type
  device_type="$($lsblk_command -d -n -r -o TYPE -- "$source_path")" || {
    printf 'ERROR: cannot identify target block device: %s\n' \
      "$source_path" >&2
    return 1
  }
  if [[ "$device_type" != disk ]]; then
    printf '%s\n' \
      'ERROR: dedicated target storage must be a whole block device, not a partition, mapper, or array.' >&2
    printf '  Source: %s (lsblk type %s)\n' "$source_path" "$device_type" >&2
    return 1
  fi

  # A directly mounted Google Local SSD must not bypass the all-device RAID0
  # contract merely because it lacks MD metadata.
  local by_id_directory="${LAMINATE_LOCAL_SSD_BY_ID:-/dev/disk/by-id}"
  local local_member local_inventory
  local_inventory="$(laminate_local_ssd_device_names "$by_id_directory")" || \
    return 1
  while IFS= read -r local_member; do
    if [[ "$local_member" == "$source_name" ]]; then
      printf '%s\n' \
        'ERROR: Google Local SSD target storage must use one RAID0 containing every attached Local SSD.' >&2
      return 1
    fi
  done <<< "$local_inventory"

  local -a target_ancestry=() protected_ancestry=()
  local ancestry_node
  while IFS= read -r ancestry_node; do
    [[ -n "$ancestry_node" ]] && target_ancestry+=("$ancestry_node")
  done < <(laminate_device_ancestry_names "$source_path")
  if [[ "${#target_ancestry[@]}" -eq 0 ]]; then
    printf 'ERROR: cannot resolve block-device ancestry for %s.\n' \
      "$source_path" >&2
    return 1
  fi

  local probe record source mounted_at filesystem options protected_source
  local record_pattern='^SOURCE="([^"]+)"[[:space:]]+TARGET="([^"]+)"[[:space:]]+FSTYPE="([^"]+)"[[:space:]]+OPTIONS="([^"]+)"$'
  for probe in / /boot /boot/efi; do
    [[ -e "$probe" ]] || continue
    record="$($findmnt_command -n -P \
      -o SOURCE,TARGET,FSTYPE,OPTIONS --target "$probe")" || {
      printf 'ERROR: cannot resolve system filesystem containing %s.\n' \
        "$probe" >&2
      return 1
    }
    if [[ ! "$record" =~ $record_pattern ]]; then
      printf 'ERROR: unexpected findmnt response for %s:\n%s\n' \
        "$probe" "$record" >&2
      return 1
    fi
    source="${BASH_REMATCH[1]}"
    protected_source="$(readlink -f -- "$source")" || {
      printf 'ERROR: cannot resolve system filesystem source: %s\n' \
        "$source" >&2
      return 1
    }
    local -a one_ancestry=()
    while IFS= read -r ancestry_node; do
      [[ -n "$ancestry_node" ]] && one_ancestry+=("$ancestry_node")
    done < <(laminate_device_ancestry_names "$protected_source")
    if [[ "${#one_ancestry[@]}" -eq 0 ]]; then
      printf 'ERROR: cannot resolve block-device ancestry for system source %s.\n' \
        "$protected_source" >&2
      return 1
    fi
    protected_ancestry+=("${one_ancestry[@]}")
  done

  local -a unique_protected_ancestry=()
  while IFS= read -r ancestry_node; do
    [[ -n "$ancestry_node" ]] && unique_protected_ancestry+=("$ancestry_node")
  done < <(
    printf '%s\n' "${protected_ancestry[@]}" | LC_ALL=C sort -u
  )
  protected_ancestry=("${unique_protected_ancestry[@]}")

  local target_node protected_node
  for target_node in "${target_ancestry[@]}"; do
    for protected_node in "${protected_ancestry[@]}"; do
      if [[ "$target_node" == "$protected_node" ]]; then
        printf '%s\n' \
          'ERROR: dedicated target storage shares a backing device with the root or boot filesystem.' >&2
        printf '  Shared device: %s\n' "$target_node" >&2
        return 1
      fi
    done
  done

  printf '%s\n' \
    "storage.dedicated_block.device=$source_path" \
    "storage.dedicated_block.device_type=$device_type" \
    "storage.dedicated_block.device_ancestry=$(laminate_join_comma "${target_ancestry[@]}")" \
    "storage.dedicated_block.protected_ancestry=$(laminate_join_comma "${protected_ancestry[@]}")"
}

laminate_validate_local_ssd_raid0() {
  local source_path="$1"
  local sys_block_root="${LAMINATE_SYS_BLOCK_ROOT:-/sys/class/block}"
  local by_id_directory="${LAMINATE_LOCAL_SSD_BY_ID:-/dev/disk/by-id}"
  local expected_chunk_bytes="${LAMINATE_LOCAL_SSD_EXPECTED_CHUNK_BYTES:-524288}"
  local md_name="${source_path##*/}"
  local md_directory="$sys_block_root/$md_name/md"

  local level raid_devices degraded chunk_bytes
  IFS= read -r level < "$md_directory/level" || return 1
  IFS= read -r raid_devices < "$md_directory/raid_disks" || return 1
  IFS= read -r degraded < "$md_directory/degraded" || return 1
  IFS= read -r chunk_bytes < "$md_directory/chunk_size" || return 1
  if [[ ! "$raid_devices" =~ ^([2-9]|[1-9][0-9]+)$ ]]; then
    printf 'ERROR: Local SSD RAID0 member count is invalid: %s\n' \
      "$raid_devices" >&2
    return 1
  fi
  if [[ "$level" != raid0 || "$degraded" != 0 ]]; then
    printf '%s\n' 'ERROR: Local SSD array is not a healthy RAID0.' >&2
    printf '  level=%s members=%s degraded=%s\n' \
      "$level" "$raid_devices" "$degraded" >&2
    return 1
  fi
  if [[ "$chunk_bytes" != "$expected_chunk_bytes" ]]; then
    printf 'ERROR: Local SSD RAID0 chunk is %s bytes; expected %s bytes.\n' \
      "$chunk_bytes" "$expected_chunk_bytes" >&2
    return 1
  fi

  local -a expected_members=() actual_members=() sorted_members=()
  local member expected_inventory
  expected_inventory="$(laminate_local_ssd_device_names "$by_id_directory")" || \
    return 1
  while IFS= read -r member; do
    [[ -n "$member" ]] && expected_members+=("$member")
  done <<< "$expected_inventory"
  local -a inventory_links=()
  shopt -s nullglob
  inventory_links=("$by_id_directory"/google-local-nvme-ssd-*)
  shopt -u nullglob
  if [[ "${#inventory_links[@]}" -ne "${#expected_members[@]}" ]]; then
    printf '%s\n' \
      'ERROR: multiple Google Local SSD identifiers resolve to one device.' >&2
    return 1
  fi
  local slave
  shopt -s nullglob
  for slave in "$sys_block_root/$md_name/slaves/"*; do
    actual_members+=("${slave##*/}")
  done
  shopt -u nullglob
  if [[ "${#actual_members[@]}" -gt 0 ]]; then
    while IFS= read -r member; do
      [[ -n "$member" ]] && sorted_members+=("$member")
    done < <(printf '%s\n' "${actual_members[@]}" | LC_ALL=C sort -u)
    actual_members=("${sorted_members[@]}")
  fi

  if [[ "${#expected_members[@]}" -ne "$raid_devices" ||
        "${#actual_members[@]}" -ne "$raid_devices" ]]; then
    printf '%s\n' \
      'ERROR: Local SSD RAID0 does not contain exactly every attached Google Local SSD.' >&2
    printf '  attached=%s array-members=%s metadata-members=%s\n' \
      "${#expected_members[@]}" "${#actual_members[@]}" "$raid_devices" >&2
    return 1
  fi

  local index
  for ((index = 0; index < raid_devices; ++index)); do
    if [[ "${expected_members[index]}" != "${actual_members[index]}" ]]; then
      printf '%s\n' \
        'ERROR: MD members are not exactly the attached Google Local SSD devices.' >&2
      printf '  Attached: %s\n  RAID0:    %s\n' \
        "${expected_members[*]}" "${actual_members[*]}" >&2
      return 1
    fi
  done

  printf '%s\n' \
    'storage.backend=google-local-ssd-raid0' \
    "storage.local_ssd.raid_level=$level" \
    "storage.local_ssd.raid_member_count=$raid_devices" \
    "storage.local_ssd.raid_degraded_members=$degraded" \
    "storage.local_ssd.raid_chunk_bytes=$chunk_bytes" \
    "storage.local_ssd.raid_members=$(laminate_join_comma "${actual_members[@]}")"
}

laminate_collect_target_storage_records() {
  if [[ $# -ne 3 ]]; then
    printf '%s\n' \
      'ERROR: target storage inspection requires ARTIFACT_ROOT MOUNT CAPTURE_PHASE.' >&2
    return 2
  fi
  local artifact_root="$1"
  local expected_mount="$2"
  local capture_phase="$3"
  local findmnt_command="${LAMINATE_FINDMNT_COMMAND:-findmnt}"
  local sys_block_root="${LAMINATE_SYS_BLOCK_ROOT:-/sys/class/block}"
  local minimum_total_bytes="${LAMINATE_STORAGE_MIN_TOTAL_BYTES:-1}"

  case "$capture_phase" in
    validation|setup-start|server-start) ;;
    *)
      printf 'ERROR: unsupported target storage capture phase: %s\n' \
        "$capture_phase" >&2
      return 2
      ;;
  esac
  if [[ ! "$minimum_total_bytes" =~ ^[1-9][0-9]*$ ]]; then
    printf 'ERROR: storage minimum capacity is not a positive integer: %s\n' \
      "$minimum_total_bytes" >&2
    return 2
  fi
  command -v "$findmnt_command" >/dev/null 2>&1 || {
    printf '%s\n' 'ERROR: findmnt is required to verify target storage.' >&2
    return 1
  }
  laminate_require_normalized_dedicated_path \
    "$expected_mount" LAMINATE_STORAGE_MOUNT || return 1
  laminate_require_normalized_dedicated_path \
    "$artifact_root" LAMINATE_BENCH_ROOT || return 1
  if [[ ! -d "$expected_mount" || -L "$expected_mount" ]]; then
    printf 'ERROR: expected target storage mount is missing or is a symlink:\n  %s\n' \
      "$expected_mount" >&2
    return 1
  fi
  if [[ ! -d "$artifact_root" || -L "$artifact_root" ]]; then
    printf 'ERROR: target artifact root is missing or is a symlink:\n  %s\n' \
      "$artifact_root" >&2
    return 1
  fi

  local canonical_mount canonical_root
  canonical_mount="$(laminate_canonical_directory "$expected_mount")" || return 1
  canonical_root="$(laminate_canonical_directory "$artifact_root")" || return 1
  if ! laminate_path_is_below "$canonical_root" "$canonical_mount"; then
    printf '%s\n' 'ERROR: target artifacts must live below the target storage mount.' >&2
    printf '  Artifact root: %s\n  Storage mount: %s\n' \
      "$canonical_root" "$canonical_mount" >&2
    return 1
  fi

  local mount_record source mounted_at filesystem options
  mount_record="$(laminate_read_mount_record "$canonical_root")" || {
    printf 'ERROR: cannot resolve the filesystem containing %s.\n' \
      "$canonical_root" >&2
    return 1
  }
  local mount_record_pattern='^SOURCE="([^"]+)"[[:space:]]+TARGET="([^"]+)"[[:space:]]+FSTYPE="([^"]+)"[[:space:]]+OPTIONS="([^"]+)"$'
  if [[ ! "$mount_record" =~ $mount_record_pattern ]]; then
    printf 'ERROR: unexpected findmnt response while verifying target storage:\n%s\n' \
      "$mount_record" >&2
    return 1
  fi
  source="${BASH_REMATCH[1]}"
  mounted_at="${BASH_REMATCH[2]}"
  filesystem="${BASH_REMATCH[3]}"
  options="${BASH_REMATCH[4]}"
  mounted_at="$(laminate_canonical_directory "$mounted_at")" || return 1
  local shared_root=false
  if [[ "$mounted_at" == / && "$canonical_mount" != / ]]; then
    laminate_validate_shared_root_layout \
      "$canonical_mount" "$canonical_root" || return 1
    laminate_validate_shared_root_marker "$canonical_mount" || return 1
    shared_root=true
  elif [[ "$mounted_at" != "$canonical_mount" ]]; then
    printf '%s\n' 'ERROR: the artifact root is not on the expected target storage mount.' >&2
    printf '  Expected mount: %s\n  Actual mount:   %s\n' \
      "$canonical_mount" "$mounted_at" >&2
    return 1
  fi
  if [[ "$filesystem" != ext4 ]]; then
    printf 'ERROR: target storage filesystem must be ext4, not %s.\n' \
      "$filesystem" >&2
    return 1
  fi
  if ! laminate_mount_option_present "$options" rw; then
    printf 'ERROR: target storage filesystem is not mounted read-write: %s\n' \
      "$options" >&2
    return 1
  fi
  if [[ "$shared_root" != true ]] &&
     ! laminate_mount_option_present "$options" noatime; then
    printf 'ERROR: target storage filesystem must be mounted with noatime: %s\n' \
      "$options" >&2
    return 1
  fi

  local source_path source_name backend_records
  if [[ "$source" != /* ]]; then
    printf 'ERROR: target filesystem source is not an absolute device path: %s\n' \
      "$source" >&2
    return 1
  fi
  source_path="$(readlink -f -- "$source")" || {
    printf 'ERROR: cannot resolve target filesystem source: %s\n' "$source" >&2
    return 1
  }
  if [[ ! -e "$source_path" ]]; then
    printf 'ERROR: target filesystem source does not exist: %s\n' \
      "$source_path" >&2
    return 1
  fi
  source_name="${source_path##*/}"
  if [[ "$shared_root" == true ]]; then
    backend_records="storage.backend=shared-root-filesystem"$'\n'\
"storage.shared_root.directory=$canonical_mount"$'\n'\
"storage.shared_root.shares_os=true"
  elif [[ -d "$sys_block_root/$source_name/md" ]]; then
    backend_records="$(laminate_validate_local_ssd_raid0 "$source_path")" || \
      return 1
  else
    local dedicated_records
    dedicated_records="$(laminate_validate_dedicated_block "$source_path")" || \
      return 1
    backend_records="storage.backend=dedicated-block"$'\n'"$dedicated_records"
  fi

  local owner mode
  owner="$(laminate_stat_uid "$artifact_root")" || return 1
  mode="$(laminate_stat_mode "$artifact_root")" || return 1
  if [[ "$owner" != "$(id -u)" || "$((8#$mode & 0077))" -ne 0 ]]; then
    printf '%s\n' \
      'ERROR: target artifact root must be owned by the benchmark user and owner-only.' >&2
    printf '  Path: %s\n  owner uid=%s mode=%s\n' \
      "$artifact_root" "$owner" "$mode" >&2
    return 1
  fi

  local capacity total_bytes available_bytes
  capacity="$(laminate_read_filesystem_capacity "$canonical_root")" || {
    printf '%s\n' \
      'ERROR: target filesystem returned invalid capacity information.' >&2
    return 1
  }
  read -r total_bytes available_bytes <<< "$capacity"
  if ((total_bytes < minimum_total_bytes)); then
    printf 'ERROR: target filesystem has %s bytes; expected at least %s bytes.\n' \
      "$total_bytes" "$minimum_total_bytes" >&2
    return 1
  fi

  printf '%s\n' \
    'format=laminate-storage-provenance-v2' \
    "storage.capture_phase=$capture_phase" \
    "storage.captured_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "storage.artifact_root=$canonical_root" \
    "storage.mount_source=$source_path" \
    "storage.mount_target=$mounted_at" \
    "storage.filesystem_type=$filesystem" \
    "storage.mount_options=$options" \
    "storage.filesystem_total_bytes=$total_bytes" \
    "storage.filesystem_available_bytes=$available_bytes" \
    "$backend_records"
}

verify_laminate_target_storage_root() {
  if [[ $# -ne 2 ]]; then
    printf '%s\n' \
      'ERROR: verify_laminate_target_storage_root requires ARTIFACT_ROOT MOUNT.' >&2
    return 2
  fi

  local records backend total available
  records="$(laminate_collect_target_storage_records "$1" "$2" validation)" || \
    return 1
  backend="$(sed -n 's/^storage\.backend=//p' <<< "$records")"
  total="$(sed -n 's/^storage\.filesystem_total_bytes=//p' <<< "$records")"
  available="$(sed -n 's/^storage\.filesystem_available_bytes=//p' <<< "$records")"
  case "$backend" in
    dedicated-block|shared-root-filesystem|google-local-ssd-raid0) ;;
    *)
      printf 'ERROR: target storage verifier returned an unknown backend: %s\n' \
        "$backend" >&2
      return 1
      ;;
  esac
  printf 'Target storage PASS: %s uses %s (%s/%s bytes available).\n' \
    "$1" "$backend" "$available" "$total"
}

# Publish one immutable provenance snapshot at a semantic boundary. Validation
# and backend autodetection happen immediately before sampling. Existing output
# is never replaced.
write_laminate_storage_snapshot() {
  if [[ $# -ne 4 ]]; then
    printf '%s\n' \
      'ERROR: write_laminate_storage_snapshot requires OUTPUT ARTIFACT_ROOT MOUNT CAPTURE_PHASE.' >&2
    return 2
  fi
  local output="$1"
  local artifact_root="$2"
  local expected_mount="$3"
  local capture_phase="$4"
  case "$capture_phase" in
    setup-start|server-start) ;;
    *)
      printf 'ERROR: unsupported target storage snapshot phase: %s\n' \
        "$capture_phase" >&2
      return 2
      ;;
  esac
  case "$output" in
    /*) ;;
    *)
      printf 'ERROR: storage snapshot path must be absolute: %s\n' \
        "$output" >&2
      return 2
      ;;
  esac
  if [[ -e "$output" || -L "$output" ]]; then
    printf 'ERROR: refusing to replace storage snapshot: %s\n' \
      "$output" >&2
    return 1
  fi
  local output_parent="${output%/*}"
  if [[ ! -d "$output_parent" || -L "$output_parent" ]]; then
    printf 'ERROR: storage snapshot parent is missing or unsafe: %s\n' \
      "$output_parent" >&2
    return 1
  fi

  local records temporary
  records="$(laminate_collect_target_storage_records \
    "$artifact_root" "$expected_mount" "$capture_phase")" || return 1
  temporary="$(mktemp "$output_parent/.storage-provenance.XXXXXX")" || return 1
  chmod 0600 "$temporary" || {
    rm -f -- "$temporary"
    return 1
  }
  if ! printf '%s\n' "$records" > "$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  chmod 0400 "$temporary" || {
    rm -f -- "$temporary"
    return 1
  }
  if ! ln -- "$temporary" "$output"; then
    rm -f -- "$temporary"
    printf 'ERROR: failed to publish immutable storage snapshot: %s\n' \
      "$output" >&2
    return 1
  fi
  rm -f -- "$temporary"
}

# Read one exact field from an immutable provenance snapshot. A missing or
# duplicated key is malformed rather than something callers should guess at.
laminate_storage_snapshot_value() {
  if [[ $# -ne 2 ]]; then
    return 2
  fi
  awk -F= -v expected="$2" '
    $1 == expected {
      count += 1
      value = substr($0, length($1) + 2)
    }
    END {
      if (count != 1) {
        exit 1
      }
      print value
    }
  ' "$1"
}

# Mount-option ordering is not an identity property. Canonicalize the option
# set before comparing snapshots so a harmless findmnt ordering change does
# not invalidate an otherwise identical campaign.
laminate_canonical_mount_options() {
  if [[ $# -ne 1 || -z "$1" || "$1" == ,* || "$1" == *, ||
        "$1" == *,,* || "$1" == *$'\n'* ]]; then
    return 1
  fi
  local -a options=()
  IFS=',' read -r -a options <<< "$1"
  local index prior
  for ((index = 0; index < ${#options[@]}; ++index)); do
    [[ -n "${options[index]}" ]] || return 1
    for ((prior = 0; prior < index; ++prior)); do
      [[ "${options[index]}" != "${options[prior]}" ]] || return 1
    done
  done
  local lines
  lines="$(printf '%s\n' "$1" | tr ',' '\n' | LC_ALL=C sort -u)" || return 1
  [[ -n "$lines" ]] || return 1
  printf '%s\n' "${lines//$'\n'/,}"
}

# Require the server-start storage to be the same filesystem/backend/topology
# used for setup. Capture time and available bytes are intentionally allowed to
# change. This runs before the expensive server and prevents a campaign whose
# final report would necessarily reject its provenance.
require_matching_laminate_storage_snapshots() {
  if [[ $# -ne 2 ]]; then
    printf '%s\n' \
      'ERROR: storage snapshot comparison requires SETUP_SNAPSHOT SERVER_SNAPSHOT.' >&2
    return 2
  fi
  local setup_snapshot="$1"
  local server_snapshot="$2"
  local snapshot
  for snapshot in "$setup_snapshot" "$server_snapshot"; do
    if [[ ! -f "$snapshot" || -L "$snapshot" ]]; then
      printf 'ERROR: storage provenance is missing or unsafe: %s\n' \
        "$snapshot" >&2
      return 1
    fi
  done

  local setup_phase server_phase
  setup_phase="$(laminate_storage_snapshot_value \
    "$setup_snapshot" storage.capture_phase)" || return 1
  server_phase="$(laminate_storage_snapshot_value \
    "$server_snapshot" storage.capture_phase)" || return 1
  if [[ "$setup_phase" != setup-start || "$server_phase" != server-start ]]; then
    printf '%s\n' \
      'ERROR: storage provenance comparison requires setup-start and server-start snapshots.' >&2
    return 1
  fi

  local key setup_value server_value
  local -a common_keys=(
    format
    storage.backend
    storage.artifact_root
    storage.mount_source
    storage.mount_target
    storage.filesystem_type
    storage.filesystem_total_bytes
  )
  for key in "${common_keys[@]}"; do
    setup_value="$(laminate_storage_snapshot_value \
      "$setup_snapshot" "$key")" || return 1
    server_value="$(laminate_storage_snapshot_value \
      "$server_snapshot" "$key")" || return 1
    if [[ "$setup_value" != "$server_value" ]]; then
      printf 'ERROR: setup/server storage provenance disagrees on %s.\n' \
        "$key" >&2
      printf '  setup:  %s\n  server: %s\n' \
        "$setup_value" "$server_value" >&2
      return 1
    fi
  done

  setup_value="$(laminate_storage_snapshot_value \
    "$setup_snapshot" storage.mount_options)" || return 1
  setup_value="$(laminate_canonical_mount_options "$setup_value")" || return 1
  server_value="$(laminate_storage_snapshot_value \
    "$server_snapshot" storage.mount_options)" || return 1
  server_value="$(laminate_canonical_mount_options "$server_value")" || return 1
  if [[ "$setup_value" != "$server_value" ]]; then
    printf '%s\n' \
      'ERROR: setup/server storage provenance disagrees on storage.mount_options.' >&2
    return 1
  fi

  local backend
  backend="$(laminate_storage_snapshot_value \
    "$setup_snapshot" storage.backend)" || return 1
  local -a backend_keys=()
  case "$backend" in
    google-local-ssd-raid0)
      backend_keys=(
        storage.local_ssd.raid_level
        storage.local_ssd.raid_member_count
        storage.local_ssd.raid_degraded_members
        storage.local_ssd.raid_chunk_bytes
        storage.local_ssd.raid_members
      )
      ;;
    dedicated-block)
      backend_keys=(
        storage.dedicated_block.device
        storage.dedicated_block.device_type
        storage.dedicated_block.device_ancestry
        storage.dedicated_block.protected_ancestry
      )
      ;;
    shared-root-filesystem)
      backend_keys=(
        storage.shared_root.directory
        storage.shared_root.shares_os
      )
      ;;
    *)
      printf 'ERROR: unsupported storage backend in setup provenance: %s\n' \
        "$backend" >&2
      return 1
      ;;
  esac
  for key in "${backend_keys[@]}"; do
    setup_value="$(laminate_storage_snapshot_value \
      "$setup_snapshot" "$key")" || return 1
    server_value="$(laminate_storage_snapshot_value \
      "$server_snapshot" "$key")" || return 1
    if [[ "$setup_value" != "$server_value" ]]; then
      printf 'ERROR: setup/server storage provenance disagrees on %s.\n' \
        "$key" >&2
      printf '  setup:  %s\n  server: %s\n' \
        "$setup_value" "$server_value" >&2
      return 1
    fi
  done
}
