#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 0 ]]; then
  printf 'Usage: benches/verify_gcp_storage.sh\n' >&2
  exit 2
fi

storage_mount="${LAMINATE_STORAGE_MOUNT:-/var/lib/laminate-storage}"
artifact_root="${LAMINATE_BENCH_ROOT:-$storage_mount/laminate-bench}"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=support/target_storage_contract.sh
source "$script_directory/support/target_storage_contract.sh"

verify_laminate_target_storage_root "$artifact_root" "$storage_mount"
