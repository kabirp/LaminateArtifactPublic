#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s STORAGE_CONTRACT\n' "$0" >&2
  exit 2
fi

contract="$1"
scratch="$(cd -P -- "$(mktemp -d)" && pwd)"
trap 'rm -rf -- "$scratch"' EXIT

local_mount="$scratch/mnt/local"
local_root="$local_mount/laminate-bench"
block_mount="$scratch/mnt/block"
block_root="$block_mount/laminate-bench"
shared_storage="$scratch/shared-root-storage"
shared_root="$shared_storage/laminate-bench"
by_id="$scratch/by-id"
sys_block="$scratch/sys/class/block"
sys_bdi="$scratch/sys/class/bdi"
sys_dev_block="$scratch/sys/dev/block"
sys_nvme="$scratch/sys/devices/pci/block/nvme0n1"
device_root="$scratch/dev"
mkdir -p "$local_root" "$block_root" "$shared_root" "$by_id" "$sys_block/md0/md" \
  "$sys_block/md0/slaves" "$sys_bdi/8:0" "$sys_bdi/259:0" \
  "$sys_dev_block" "$sys_nvme/nvme0n1p1" "$device_root"
chmod 0700 "$local_root" "$block_root" "$shared_storage" "$shared_root"
printf '%s\n' \
  'laminate-storage-backend=shared-root-filesystem-v1' \
  > "$shared_storage/.laminate-shared-root-storage"
chmod 0600 "$shared_storage/.laminate-shared-root-storage"
printf 'raid0\n' > "$sys_block/md0/md/level"
printf '8\n' > "$sys_block/md0/md/raid_disks"
printf '0\n' > "$sys_block/md0/md/degraded"
printf '524288\n' > "$sys_block/md0/md/chunk_size"
printf '8192\n' > "$sys_bdi/8:0/read_ahead_kb"
printf '8192\n' > "$sys_bdi/259:0/read_ahead_kb"
printf '259:0\n' > "$sys_nvme/dev"
printf '259:1\n' > "$sys_nvme/nvme0n1p1/dev"
printf '1\n' > "$sys_nvme/nvme0n1p1/partition"
ln -s "$sys_nvme/nvme0n1p1" "$sys_dev_block/259:1"
touch "$device_root/md0" "$device_root/data0" "$device_root/data1" \
  "$device_root/rootp1" "$device_root/rootdisk"
for index in 0 1 2 3 4 5 6 7; do
  touch "$device_root/nvme${index}n1"
  ln -s "$device_root/nvme${index}n1" \
    "$by_id/google-local-nvme-ssd-$index"
  mkdir "$sys_block/md0/slaves/nvme${index}n1"
done

fake_findmnt="$scratch/findmnt"
target_record="$scratch/findmnt-target-record"
protected_record="$scratch/findmnt-protected-record"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'last=""' \
  'for argument in "$@"; do last="$argument"; done' \
  'case "$last" in' \
  '  /|/boot|/boot/efi) cat "$FAKE_FINDMNT_PROTECTED_RECORD" ;;' \
  '  *) cat "$FAKE_FINDMNT_TARGET_RECORD" ;;' \
  'esac' \
  > "$fake_findmnt"
chmod +x "$fake_findmnt"
printf 'SOURCE="%s" TARGET="/" FSTYPE="ext4" OPTIONS="rw,relatime"\n' \
  "$device_root/rootp1" > "$protected_record"

fake_lsblk="$scratch/lsblk"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'last=""' \
  'for argument in "$@"; do last="$argument"; done' \
  'case " $* " in' \
  '  *" -o TYPE "*)' \
  '    case "${last##*/}" in' \
  '      data0|rootdisk|nvme*n1) printf "disk\\n" ;;' \
  '      data1|rootp1) printf "part\\n" ;;' \
  '      md0) printf "raid0\\n" ;;' \
  '      *) exit 1 ;;' \
  '    esac ;;' \
  '  *" -o KNAME "*)' \
  '    case "${last##*/}" in' \
  '      data0) printf "data0\\n" ;;' \
  '      data1) printf "data1\\ndata0\\n" ;;' \
  '      rootp1) printf "rootp1\\nrootdisk\\n" ;;' \
  '      rootdisk) printf "rootdisk\\n" ;;' \
  '      nvme*n1) printf "%s\\n" "${last##*/}" ;;' \
  '      *) exit 1 ;;' \
  '    esac ;;' \
  '  *) exit 1 ;;' \
  'esac' \
  > "$fake_lsblk"
chmod +x "$fake_lsblk"

fake_df="$scratch/df"
df_record="$scratch/df-record"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'cat "$FAKE_DF_RECORD"' \
  > "$fake_df"
chmod +x "$fake_df"
printf '%s\n' '1B-blocks Avail' '3221225472000 3150000000000' \
  > "$df_record"

# Exercise the production contract with its fixed shared-root path relocated
# into this unprivileged test sandbox. The replacement changes only the path,
# not the admission logic.
grep -Fq '/var/lib/laminate-storage' "$contract"
test_contract="$scratch/target_storage_contract.sh"
sed "s|/var/lib/laminate-storage|$shared_storage|g" \
  "$contract" > "$test_contract"
# shellcheck source=target_storage_contract.sh
source "$test_contract"
export LAMINATE_FINDMNT_COMMAND="$fake_findmnt"
export LAMINATE_SYS_BLOCK_ROOT="$sys_block"
export LAMINATE_SYS_BDI_ROOT="$sys_bdi"
export LAMINATE_SYS_DEV_BLOCK_ROOT="$sys_dev_block"
export LAMINATE_LOCAL_SSD_BY_ID="$by_id"
export LAMINATE_LSBLK_COMMAND="$fake_lsblk"
export LAMINATE_DF_COMMAND="$fake_df"
export FAKE_FINDMNT_TARGET_RECORD="$target_record"
export FAKE_FINDMNT_PROTECTED_RECORD="$protected_record"
export FAKE_DF_RECORD="$df_record"
export LAMINATE_STORAGE_MIN_TOTAL_BYTES=3000000000000

for padded_bdi in '259:1' '259:1  ' $'\t259:1\t'; do
  [[ "$(laminate_canonical_bdi "$padded_bdi")" == 259:1 ]]
done
for malformed_bdi in '' '25 9:1' '259 :1' '259: 1' '259:1 extra' \
  $'259:1\n8:2'; do
  if laminate_canonical_bdi "$malformed_bdi" >/dev/null 2>&1; then
    printf 'malformed BDI unexpectedly passed: %q\n' "$malformed_bdi" >&2
    exit 1
  fi
done
[[ "$(laminate_resolve_backing_bdi 8:0)" == 8:0 ]]
[[ "$(laminate_resolve_backing_bdi 259:1)" == 259:0 ]]
if laminate_resolve_backing_bdi 7:7 >/dev/null 2>&1; then
  printf '%s\n' 'missing non-partition BDI unexpectedly resolved' >&2
  exit 1
fi
printf 'invalid parent\n' > "$sys_nvme/dev"
if laminate_resolve_backing_bdi 259:1 >/dev/null 2>&1; then
  printf '%s\n' 'partition with malformed parent BDI unexpectedly resolved' >&2
  exit 1
fi
printf '259:0\n' > "$sys_nvme/dev"

laminate_require_gcp_archive_root /var/lib/laminate-bench-archive
if laminate_require_gcp_archive_root /etc/ssh >/dev/null 2>&1; then
  printf '%s\n' 'unsafe GCP archive path unexpectedly passed' >&2
  exit 1
fi

set_target_mount() {
  local source="$1"
  local target="$2"
  local filesystem="${3:-ext4}"
  local options="${4:-rw,noatime}"
  printf 'SOURCE="%s" TARGET="%s" FSTYPE="%s" OPTIONS="%s"\n' \
    "$source" "$target" "$filesystem" "$options" > "$target_record"
}

# A healthy array passes with no machine-specific expected member count.
set_target_mount "$device_root/md0" "$local_mount"
verify_laminate_target_storage_root "$local_root" "$local_mount" \
  > "$scratch/local-pass.txt"
grep -q 'uses google-local-ssd-raid0' "$scratch/local-pass.txt"

snapshot="$scratch/storage-provenance.setup-start.txt"
write_laminate_storage_snapshot \
  "$snapshot" "$local_root" "$local_mount" setup-start
canonical_local_root="$(cd -P -- "$local_root" && pwd)"
canonical_local_mount="$(cd -P -- "$local_mount" && pwd)"
canonical_md_device="$(readlink -f -- "$device_root/md0")"
for expected in \
  'format=laminate-storage-provenance-v2' \
  'storage.capture_phase=setup-start' \
  'storage.backend=google-local-ssd-raid0' \
  "storage.artifact_root=$canonical_local_root" \
  "storage.mount_source=$canonical_md_device" \
  "storage.mount_target=$canonical_local_mount" \
  'storage.filesystem_type=ext4' \
  'storage.mount_options=rw,noatime' \
  'storage.filesystem_total_bytes=3221225472000' \
  'storage.filesystem_available_bytes=3150000000000' \
  'storage.local_ssd.raid_level=raid0' \
  'storage.local_ssd.raid_member_count=8' \
  'storage.local_ssd.raid_degraded_members=0' \
  'storage.local_ssd.raid_chunk_bytes=524288' \
  'storage.local_ssd.raid_members=nvme0n1,nvme1n1,nvme2n1,nvme3n1,nvme4n1,nvme5n1,nvme6n1,nvme7n1'; do
  grep -Fqx -- "$expected" "$snapshot" || {
    printf 'Local SSD snapshot omitted expected record: %s\n' "$expected" >&2
    exit 1
  }
done
grep -Eq '^storage\.captured_at_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
  "$snapshot"
if write_laminate_storage_snapshot \
    "$snapshot" "$local_root" "$local_mount" setup-start \
    >/dev/null 2>&1; then
  printf '%s\n' 'snapshot writer unexpectedly replaced immutable evidence' >&2
  exit 1
fi

# Server-start available space and mount-option ordering may differ, while the
# filesystem and backend identity must remain exactly setup-bound.
printf '%s\n' '1B-blocks Avail' '3221225472000 3010000000000' \
  > "$df_record"
set_target_mount "$device_root/md0" "$local_mount" ext4 noatime,rw
matching_server_snapshot="$scratch/storage-provenance.matching-server.txt"
write_laminate_storage_snapshot \
  "$matching_server_snapshot" "$local_root" "$local_mount" server-start
require_matching_laminate_storage_snapshots \
  "$snapshot" "$matching_server_snapshot"
if laminate_canonical_mount_options 'rw,noatime,rw' >/dev/null 2>&1; then
  printf '%s\n' 'mount-option canonicalizer accepted a duplicate option' >&2
  exit 1
fi
printf '%s\n' '1B-blocks Avail' '3221225472000 3150000000000' \
  > "$df_record"
set_target_mount "$device_root/md0" "$local_mount"

# Any Linux MD source is held to the strict Local SSD contract and cannot fall
# back to the generic block-device path.
printf 'raid1\n' > "$sys_block/md0/md/level"
if verify_laminate_target_storage_root \
    "$local_root" "$local_mount" >/dev/null 2>&1; then
  printf '%s\n' 'invalid MD source unexpectedly fell back to dedicated-block' >&2
  exit 1
fi
printf 'raid0\n' > "$sys_block/md0/md/level"

printf '1\n' > "$sys_block/md0/md/degraded"
if verify_laminate_target_storage_root \
    "$local_root" "$local_mount" >/dev/null 2>&1; then
  printf '%s\n' 'degraded RAID0 unexpectedly passed the target contract' >&2
  exit 1
fi
printf '0\n' > "$sys_block/md0/md/degraded"

printf '262144\n' > "$sys_block/md0/md/chunk_size"
if verify_laminate_target_storage_root \
    "$local_root" "$local_mount" >/dev/null 2>&1; then
  printf '%s\n' 'wrong RAID chunk unexpectedly passed the target contract' >&2
  exit 1
fi
printf '524288\n' > "$sys_block/md0/md/chunk_size"

rm -f "$by_id/google-local-nvme-ssd-7"
if verify_laminate_target_storage_root \
    "$local_root" "$local_mount" >/dev/null 2>&1; then
  printf '%s\n' 'array omitting an attached-inventory change unexpectedly passed' >&2
  exit 1
fi
ln -s "$device_root/nvme7n1" "$by_id/google-local-nvme-ssd-7"

# Four members are also valid when those are exactly all attached Local SSDs.
for index in 4 5 6 7; do
  rm -f "$by_id/google-local-nvme-ssd-$index"
  rmdir "$sys_block/md0/slaves/nvme${index}n1"
done
printf '4\n' > "$sys_block/md0/md/raid_disks"
verify_laminate_target_storage_root "$local_root" "$local_mount" \
  > "$scratch/four-member-pass.txt"
grep -q 'uses google-local-ssd-raid0' "$scratch/four-member-pass.txt"

# A directly mounted, dedicated whole block device is the portable Hyperdisk
# path. Its v2 provenance has common fields plus dedicated topology fields.
set_target_mount "$device_root/data0" "$block_mount"
verify_laminate_target_storage_root "$block_root" "$block_mount" \
  > "$scratch/block-pass.txt"
grep -q 'uses dedicated-block' "$scratch/block-pass.txt"
block_snapshot="$scratch/storage-provenance.server-start.txt"
write_laminate_storage_snapshot \
  "$block_snapshot" "$block_root" "$block_mount" server-start
canonical_data_device="$(readlink -f -- "$device_root/data0")"
for expected in \
  'format=laminate-storage-provenance-v2' \
  'storage.capture_phase=server-start' \
  'storage.backend=dedicated-block' \
  "storage.dedicated_block.device=$canonical_data_device" \
  'storage.dedicated_block.device_type=disk' \
  'storage.dedicated_block.device_ancestry=data0' \
  'storage.dedicated_block.protected_ancestry=rootdisk,rootp1'; do
  grep -Fqx -- "$expected" "$block_snapshot" || {
    printf 'dedicated-block snapshot omitted expected record: %s\n' \
      "$expected" >&2
    exit 1
  }
done
if require_matching_laminate_storage_snapshots \
    "$snapshot" "$block_snapshot" >/dev/null 2>&1; then
  printf '%s\n' \
    'storage comparison accepted a different setup/server backend' >&2
  exit 1
fi

# A deliberately selected directory on the filesystem mounted at / is a
# supported fallback for VMs whose large Hyperdisk is their boot disk. It is
# labeled as shared with the OS and keeps the actual system mount in the common
# provenance fields. Root filesystems normally use relatime, which is allowed.
set_target_mount "$device_root/rootp1" / ext4 rw,relatime

# A missing dedicated mount must not silently become shared-root storage.
if verify_laminate_target_storage_root \
    "$block_root" "$block_mount" >/dev/null 2>&1; then
  printf '%s\n' \
    'unmarked directory on / unexpectedly passed as shared-root storage' >&2
  exit 1
fi

verify_laminate_target_storage_root "$shared_root" "$shared_storage" \
  > "$scratch/shared-root-pass.txt"
grep -q 'uses shared-root-filesystem' "$scratch/shared-root-pass.txt"
if grep -Eq 'DIAGNOSTIC ONLY|QUALIFIED dedicated' \
    "$scratch/local-pass.txt" "$scratch/block-pass.txt" \
    "$scratch/shared-root-pass.txt"; then
  printf '%s\n' \
    'storage safety verification unexpectedly classified campaign quality' >&2
  exit 1
fi

shared_setup="$scratch/storage-provenance.shared-root.setup.txt"
write_laminate_storage_snapshot \
  "$shared_setup" "$shared_root" "$shared_storage" setup-start
canonical_shared_storage="$(cd -P -- "$shared_storage" && pwd)"
canonical_shared_root="$(cd -P -- "$shared_root" && pwd)"
canonical_root_partition="$(readlink -f -- "$device_root/rootp1")"
for expected in \
  'format=laminate-storage-provenance-v2' \
  'storage.capture_phase=setup-start' \
  'storage.backend=shared-root-filesystem' \
  "storage.artifact_root=$canonical_shared_root" \
  "storage.mount_source=$canonical_root_partition" \
  'storage.mount_target=/' \
  'storage.filesystem_type=ext4' \
  'storage.mount_options=rw,relatime' \
  "storage.shared_root.directory=$canonical_shared_storage" \
  'storage.shared_root.shares_os=true'; do
  grep -Fqx -- "$expected" "$shared_setup" || {
    printf 'shared-root snapshot omitted expected record: %s\n' \
      "$expected" >&2
    exit 1
  }
done

set_target_mount "$device_root/rootp1" / ext4 relatime,rw
shared_server="$scratch/storage-provenance.shared-root.server.txt"
write_laminate_storage_snapshot \
  "$shared_server" "$shared_root" "$shared_storage" server-start
require_matching_laminate_storage_snapshots "$shared_setup" "$shared_server"

chmod 0644 "$shared_storage/.laminate-shared-root-storage"
if verify_laminate_target_storage_root \
    "$shared_root" "$shared_storage" >/dev/null 2>&1; then
  printf '%s\n' 'non-owner-only shared-root marker unexpectedly passed' >&2
  exit 1
fi
chmod 0600 "$shared_storage/.laminate-shared-root-storage"

printf '%s\n' 'laminate-storage-backend=unknown' \
  > "$shared_storage/.laminate-shared-root-storage"
if verify_laminate_target_storage_root \
    "$shared_root" "$shared_storage" >/dev/null 2>&1; then
  printf '%s\n' 'invalid shared-root marker unexpectedly passed' >&2
  exit 1
fi
printf '%s\n' \
  'laminate-storage-backend=shared-root-filesystem-v1' \
  > "$shared_storage/.laminate-shared-root-storage"

changed_root="$scratch/storage-provenance.shared-root.changed.txt"
cp "$shared_server" "$changed_root"
sed -i.bak \
  's/^storage.shared_root.shares_os=true$/storage.shared_root.shares_os=false/' \
  "$changed_root"
rm -f "$changed_root.bak"
if require_matching_laminate_storage_snapshots \
    "$shared_setup" "$changed_root" >/dev/null 2>&1; then
  printf '%s\n' \
    'storage comparison ignored a changed shared-root identity field' >&2
  exit 1
fi

set_target_mount "$device_root/rootp1" / xfs rw,relatime
if verify_laminate_target_storage_root \
    "$shared_root" "$shared_storage" >/dev/null 2>&1; then
  printf '%s\n' 'non-ext4 shared-root storage unexpectedly passed' >&2
  exit 1
fi
set_target_mount "$device_root/rootp1" / ext4 ro,relatime
if verify_laminate_target_storage_root \
    "$shared_root" "$shared_storage" >/dev/null 2>&1; then
  printf '%s\n' 'read-only shared-root storage unexpectedly passed' >&2
  exit 1
fi
set_target_mount "$device_root/rootp1" "$scratch" ext4 rw,relatime
if verify_laminate_target_storage_root \
    "$shared_root" "$shared_storage" >/dev/null 2>&1; then
  printf '%s\n' \
    'non-root shared filesystem unexpectedly passed as shared-root' >&2
  exit 1
fi

set_target_mount "$device_root/data1" "$block_mount"
if verify_laminate_target_storage_root \
    "$block_root" "$block_mount" >/dev/null 2>&1; then
  printf '%s\n' 'partition-backed target unexpectedly passed as dedicated' >&2
  exit 1
fi

set_target_mount "$device_root/rootdisk" "$block_mount"
if verify_laminate_target_storage_root \
    "$block_root" "$block_mount" >/dev/null 2>&1; then
  printf '%s\n' 'root backing disk unexpectedly passed as dedicated target' >&2
  exit 1
fi

set_target_mount "$device_root/nvme0n1" "$block_mount"
if verify_laminate_target_storage_root \
    "$block_root" "$block_mount" >/dev/null 2>&1; then
  printf '%s\n' 'directly mounted Google Local SSD unexpectedly passed' >&2
  exit 1
fi

set_target_mount "$device_root/data0" "$block_mount" xfs rw,noatime
if verify_laminate_target_storage_root \
    "$block_root" "$block_mount" >/dev/null 2>&1; then
  printf '%s\n' 'non-ext4 filesystem unexpectedly passed' >&2
  exit 1
fi
set_target_mount "$device_root/data0" "$block_mount" ext4 rw,relatime
if verify_laminate_target_storage_root \
    "$block_root" "$block_mount" >/dev/null 2>&1; then
  printf '%s\n' 'filesystem without noatime unexpectedly passed' >&2
  exit 1
fi
set_target_mount "$device_root/data0" "$block_mount" ext4 ro,noatime
if verify_laminate_target_storage_root \
    "$block_root" "$block_mount" >/dev/null 2>&1; then
  printf '%s\n' 'read-only filesystem unexpectedly passed' >&2
  exit 1
fi

set_target_mount "$device_root/data0" "$block_mount"
printf '%s\n' '1B-blocks Avail' '2999999999999 2900000000000' \
  > "$df_record"
if verify_laminate_target_storage_root \
    "$block_root" "$block_mount" >/dev/null 2>&1; then
  printf '%s\n' 'undersized filesystem unexpectedly passed target capacity' >&2
  exit 1
fi
printf '%s\n' '1B-blocks Avail' '3221225472000 3150000000000' \
  > "$df_record"

# Storage health has no hard-coded campaign size. A caller may impose an
# operator floor, while the benchmark planner decides whether the workload
# itself fits the observed available capacity.
unset LAMINATE_STORAGE_MIN_TOTAL_BYTES
printf '%s\n' '1B-blocks Avail' '1000000000 900000000' > "$df_record"
verify_laminate_target_storage_root "$block_root" "$block_mount" \
  > "$scratch/no-fixed-floor-pass.txt"
export LAMINATE_STORAGE_MIN_TOTAL_BYTES=3000000000000
printf '%s\n' '1B-blocks Avail' '3221225472000 3150000000000' \
  > "$df_record"

outside="$scratch/not-on-storage"
mkdir -m 0700 "$outside"
if verify_laminate_target_storage_root \
    "$outside" "$block_mount" >/dev/null 2>&1; then
  printf '%s\n' 'artifact root outside the storage mount unexpectedly passed' >&2
  exit 1
fi

if laminate_require_normalized_dedicated_path \
    "$block_root/../escape" TEST_PATH >/dev/null 2>&1; then
  printf '%s\n' 'non-normalized destructive path unexpectedly passed' >&2
  exit 1
fi
if laminate_require_normalized_dedicated_path /var TEST_PATH \
    >/dev/null 2>&1; then
  printf '%s\n' 'broad destructive path unexpectedly passed' >&2
  exit 1
fi
ln -s "$block_root" "$scratch/artifact-alias"
if laminate_require_normalized_dedicated_path \
    "$scratch/artifact-alias/child" TEST_PATH >/dev/null 2>&1; then
  printf '%s\n' 'path through a symlink unexpectedly passed' >&2
  exit 1
fi
