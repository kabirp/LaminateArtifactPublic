#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly default_mount=/mnt/disks/laminate-storage

usage() {
  cat <<'EOF'
Usage:
  sudo benches/prepare_gcp_local_ssds.sh prepare --confirm-destroy-local-ssds
  benches/prepare_gcp_local_ssds.sh verify

prepare destroys every attached device named google-local-nvme-ssd-*, creates
one RAID0 using all of them, formats it as ext4, and mounts it for the invoking
user. It requires at least two Local SSDs. It also creates owner-only
laminate-bench/ and toolchain/{src,build,install}/ directories on the array.
verify is read-only. The ephemeral array is intentionally not written to
/etc/fstab. Do not reboot a benchmark VM while using this backend: this helper
does not reassemble or resume an existing array after reboot.

Environment:
  LAMINATE_STORAGE_MOUNT    Mount path (default: /mnt/disks/laminate-storage)
  LAMINATE_BENCH_ROOT       Artifact root below it
                            (default: MOUNT/laminate-bench)
  LAMINATE_STORAGE_MIN_TOTAL_BYTES
                            Minimum capacity checked by verify
                            (default: 1; benchmark planning enforces fit)
  LAMINATE_BENCH_ARCHIVE_ROOT
                            Small durable evidence archive on the boot disk
                            (required: /var/lib/laminate-bench-archive)
EOF
}

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 2
fi

action="$1"
shift
mount_path="${LAMINATE_STORAGE_MOUNT:-$default_mount}"
artifact_root="${LAMINATE_BENCH_ROOT:-$mount_path/laminate-bench}"
archive_root="${LAMINATE_BENCH_ARCHIVE_ROOT:-/var/lib/laminate-bench-archive}"
minimum_total_bytes="${LAMINATE_STORAGE_MIN_TOTAL_BYTES:-1}"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=support/target_storage_contract.sh
source "$script_directory/support/target_storage_contract.sh"

case "$action" in
  verify)
    [[ $# -eq 0 ]] || {
      usage >&2
      exit 2
    }
    verify_laminate_target_storage_root "$artifact_root" "$mount_path"
    ;;

  prepare)
    if [[ $# -ne 1 || "$1" != --confirm-destroy-local-ssds ]]; then
      printf '%s\n' \
        'ERROR: prepare requires the literal --confirm-destroy-local-ssds flag.' >&2
      usage >&2
      exit 2
    fi
    if [[ "$(id -u)" -ne 0 ]]; then
      fail 'prepare must be run through sudo'
    fi
    benchmark_user="${SUDO_USER:-}"
    if [[ -z "$benchmark_user" || "$benchmark_user" == root ]]; then
      fail 'run prepare as the benchmark login user through sudo, not as a root login'
    fi
    benchmark_uid="$(id -u "$benchmark_user")"
    benchmark_gid="$(id -g "$benchmark_user")"

    for command in \
      find findmnt grep install lsblk mdadm mkfs.ext4 mountpoint \
      readlink sort sudo tune2fs udevadm wipefs; do
      command -v "$command" >/dev/null 2>&1 || \
        fail "required host tool is missing: $command"
    done

    # Resolve every operator-controlled path before discovering the devices.
    # No destructive command is reached if a path is broad, non-normalized, or
    # traverses a symlink.
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
      fail 'LAMINATE_BENCH_ARCHIVE_ROOT must be outside the ephemeral Local SSD mount'
    laminate_prepare_gcp_archive_root \
      "$archive_root" "$benchmark_uid" "$benchmark_gid"
    if mountpoint -q -- "$mount_path"; then
      fail "mount path is already a mount point: $mount_path; use verify instead"
    fi
    if [[ -d "$mount_path" ]] &&
       [[ -n "$(find "$mount_path" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
      fail "refusing to mount over a non-empty directory: $mount_path"
    fi
    by_id_directory=/dev/disk/by-id
    shopt -s nullglob
    local_ssd_links=("$by_id_directory"/google-local-nvme-ssd-*)
    shopt -u nullglob
    if [[ "${#local_ssd_links[@]}" -lt 2 ]]; then
      fail "expected at least two Google Local SSD links; found ${#local_ssd_links[@]}"
    fi
    sorted_local_ssd_links=()
    while IFS= read -r link; do
      [[ -n "$link" ]] && sorted_local_ssd_links+=("$link")
    done < <(printf '%s\n' "${local_ssd_links[@]}" | LC_ALL=C sort)
    local_ssd_links=("${sorted_local_ssd_links[@]}")
    local_ssd_devices=()
    declare -A seen_devices=()
    for link in "${local_ssd_links[@]}"; do
      [[ -L "$link" ]] || fail "Local SSD identifier is not a symlink: $link"
      [[ "${link##*/}" =~ ^google-local-nvme-ssd-[0-9]+$ ]] || \
        fail "unexpected Google Local SSD identifier: $link"
      device="$(readlink -f -- "$link")"
      [[ -b "$device" ]] || fail "Local SSD identifier does not resolve to a block device: $link"
      [[ -z "${seen_devices[$device]:-}" ]] || \
        fail "two Local SSD identifiers resolve to the same device: $device"
      seen_devices[$device]=1
      [[ "$(lsblk -dn -o TYPE -- "$device")" == disk ]] || \
        fail "Local SSD identifier does not resolve to a whole disk: $link"
      mapfile -t device_tree < <(lsblk -nrpo NAME -- "$device")
      [[ "${#device_tree[@]}" -eq 1 && "${device_tree[0]}" == "$device" ]] || \
        fail "Local SSD already has partitions or mapped children: $device"
      device_name="${device##*/}"
      shopt -s nullglob
      device_holders=("/sys/class/block/$device_name/holders/"*)
      shopt -u nullglob
      [[ "${#device_holders[@]}" -eq 0 ]] || \
        fail "Local SSD is already held by another block device: $device"
      if lsblk -nr -o MOUNTPOINTS -- "$device" | grep -q '[^[:space:]]'; then
        fail "refusing to destroy mounted Local SSD: $device"
      fi
      local_ssd_devices+=("$device")
    done

    local_ssd_count="${#local_ssd_devices[@]}"
    if [[ -e /dev/md/laminate-storage ]]; then
      fail 'an MD array already occupies the expected Laminate array path; inspect it before proceeding'
    fi

    printf 'DESTROYING all %s attached ephemeral Google Local SSD devices:\n' \
      "$local_ssd_count"
    printf '  %s\n' "${local_ssd_devices[@]}"
    for device in "${local_ssd_devices[@]}"; do
      wipefs --all --force -- "$device"
    done

    mkdir -p /dev/md
    mdadm --create /dev/md/laminate-storage \
      --metadata=1.2 --level=0 --raid-devices="$local_ssd_count" \
      --chunk=512K --run -- "${local_ssd_devices[@]}"
    udevadm settle
    stripe_width=$((128 * local_ssd_count))
    mkfs.ext4 -F -b 4096 -m 0 -T largefile \
      -E "stride=128,stripe_width=$stripe_width,lazy_itable_init=0,lazy_journal_init=0" \
      -L laminate-storage /dev/md/laminate-storage
    filesystem_header="$(LC_ALL=C tune2fs -l /dev/md/laminate-storage)"
    grep -Eq '^Block size:[[:space:]]+4096$' <<< "$filesystem_header" || \
      fail 'new ext4 filesystem did not retain its 4096-byte block size'
    grep -Eq '^RAID stride:[[:space:]]+128$' <<< "$filesystem_header" || \
      fail 'new ext4 filesystem did not retain its RAID stride'
    grep -Eq "^RAID stripe width:[[:space:]]+$stripe_width$" <<< "$filesystem_header" || \
      fail 'new ext4 filesystem did not retain its RAID stripe width'
    mkdir -p -- "$mount_path"
    mount -o noatime,nodiratime /dev/md/laminate-storage "$mount_path"

    install -d -m 0700 -o "$benchmark_uid" -g "$benchmark_gid" \
      "$artifact_root" "$artifact_root/runs" "$artifact_root/logs" \
      "$mount_path/toolchain" "$mount_path/toolchain/src" \
      "$mount_path/toolchain/build" "$mount_path/toolchain/install"
    chown "$benchmark_uid:$benchmark_gid" "$mount_path"
    chmod 0700 "$mount_path"

    # Run the same contract that every target benchmark will enforce, as the
    # login user whose ownership is part of that contract.
    sudo -u "$benchmark_user" env \
      LAMINATE_STORAGE_MOUNT="$mount_path" \
      LAMINATE_BENCH_ROOT="$artifact_root" \
      LAMINATE_STORAGE_MIN_TOTAL_BYTES="$minimum_total_bytes" \
      "$script_directory/prepare_gcp_local_ssds.sh" verify
    printf '%s\n' \
      'Local SSD preparation complete. This ephemeral mount will not survive a VM reboot.'
    ;;

  *)
    usage >&2
    exit 2
    ;;
esac
