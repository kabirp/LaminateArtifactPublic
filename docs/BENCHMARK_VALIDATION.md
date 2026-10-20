# Benchmark validation

Use the first check after building, before starting a server-backed run. Use
the second after `summary` succeeds, before archiving a target result. Both
run in Bash on the VM with the [GCP runbook](GCP_BENCHMARKS.md)'s path exports.
The [local runbook](LOCAL_BENCHMARKS.md) has its own build/result checks.

## Before a run: build and host

Both extended test suites from [GCP section 4](GCP_BENCHMARKS.md#4-build-seal-and-laminate)
must pass first. This check requires the configured Release build and its
configuration log. Continue only on `TARGET ENVIRONMENT ACCEPTED`; confirm
cloud disk product, throughput, and IOPS separately in the GCP console.

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"

  source /etc/os-release
  test "$ID" = ubuntu
  dpkg --compare-versions "$VERSION_ID" ge 26.04
  test "$(uname -m)" = x86_64
  physical_cores="$(lscpu -p=SOCKET,CORE | \
    awk '!/^#/ { seen[$1 ":" $2]=1 } END { print length(seen) }')"
  test "$physical_cores" -ge 3
  grep -qm1 -w avx2 /proc/cpuinfo
  grep -qm1 -w avx512f /proc/cpuinfo
  grep -qm1 -w avx512dq /proc/cpuinfo
  grep -qm1 -w avx512ifma /proc/cpuinfo
  test -z "$(git status --porcelain)"

  seal_build_dir="$LAMINATE_STORAGE_MOUNT/toolchain/build/SEAL-4.1.2"
  grep -Eq '^CMAKE_C_COMPILER:[^=]+=/usr/bin/gcc-15$' "$seal_build_dir/CMakeCache.txt"
  grep -Eq '^CMAKE_CXX_COMPILER:[^=]+=/usr/bin/g\+\+-15$' "$seal_build_dir/CMakeCache.txt"
  grep -Fqx 'CMAKE_BUILD_TYPE:STRING=Release' "$seal_build_dir/CMakeCache.txt"
  grep -Fqx 'CMAKE_CXX_FLAGS:STRING=-march=native' "$seal_build_dir/CMakeCache.txt"
  grep -Fqx 'SEAL_USE_INTEL_HEXL:BOOL=ON' "$seal_build_dir/CMakeCache.txt"
  grep -Fqx 'SEAL_USE_INTRIN:BOOL=ON' "$seal_build_dir/CMakeCache.txt"
  grep -Fqx 'SEAL_USE_GAUSSIAN_NOISE:BOOL=OFF' "$seal_build_dir/CMakeCache.txt"
  grep -Eq '^CMAKE_CXX_COMPILER:[^=]+=/usr/bin/g\+\+-15$' "$LAMINATE_BUILD_DIR/CMakeCache.txt"
  grep -Fqx 'CMAKE_BUILD_TYPE:STRING=Release' "$LAMINATE_BUILD_DIR/CMakeCache.txt"
  grep -Fqx 'CMAKE_CXX_FLAGS:STRING=-march=native' "$LAMINATE_BUILD_DIR/CMakeCache.txt"
  grep -Fqx 'LAMINATE_REQUIRE_SEAL_HEXL:BOOL=ON' "$LAMINATE_BUILD_DIR/CMakeCache.txt"
  grep -Fq 'Laminate SEAL acceleration: Intel HEXL enabled' \
    "$LAMINATE_BUILD_DIR/laminate-configure.log"
  grep -Fq 'Laminate native-Fq NTT: Intel HEXL through SEAL dispatch' \
    "$LAMINATE_BUILD_DIR/laminate-configure.log"
  grep -Fq 'Laminate SHA-256 provider: openssl' \
    "$LAMINATE_BUILD_DIR/laminate-configure.log"

  source_commit="$(git rev-parse HEAD)"
  for executable in \
    "$LAMINATE_BUILD_DIR/benches/laminate_no_integrity_bench" \
    "$LAMINATE_BUILD_DIR/benches/laminate_base_checkpoint_bench" \
    "$LAMINATE_BUILD_DIR/benches/laminate_packed_checkpoint_bench"
  do
    if [[ ! -x "$executable" ]]; then
      printf 'ERROR: required Release benchmark was not built: %s\n' \
        "$executable" >&2
      printf '%s\n' \
        'LAMINATE_BUILD_DIR names an incomplete or incorrect build tree.' >&2
      printf 'After configuring section 4, build the missing target with:\n' >&2
      printf '  cmake --build %q --target %q --parallel %q\n' \
        "$LAMINATE_BUILD_DIR" "${executable##*/}" "$LAMINATE_BUILD_JOBS" >&2
      exit 1
    fi
    build_info="$($executable build_info)"
    grep -qx "environment.git_commit=$source_commit" <<<"$build_info"
    grep -qx 'environment.git_dirty=false' <<<"$build_info"
    grep -qx 'environment.build_type=Release' <<<"$build_info"
    grep -qx 'environment.seal_acceleration=intel-hexl-runtime-dispatch' \
      <<<"$build_info"
    grep -qx 'environment.sha256_acceleration=openssl' <<<"$build_info"
  done

  packed_info="$($LAMINATE_BUILD_DIR/benches/laminate_packed_checkpoint_bench build_info)"
  grep -qx 'profile.target-balancedLaned.admitted=true' <<<"$packed_info"
  grep -qx 'profile.target-mulHeavyPyramid.admitted=true' <<<"$packed_info"
  grep -qx 'campaign.target-balancedLaned.variants=folded,laned' <<<"$packed_info"
  grep -qx 'campaign.target-mulHeavyPyramid.variants=folded' <<<"$packed_info"
  grep -qx 'campaign.laned.lanes=1,128,16384' <<<"$packed_info"
  base_info="$($LAMINATE_BUILD_DIR/benches/laminate_base_checkpoint_bench build_info)"
  grep -qx 'campaign.target-balancedLaned.variants=base' <<<"$base_info"
  grep -qx 'campaign.target-mulHeavyPyramid.variants=base' <<<"$base_info"
  echo 'BUILD ACCEPTED: clean x86-64 Release/HEXL binaries match this source snapshot.'

  storage_check="$(benches/verify_gcp_storage.sh)"
  grep -Fq ' uses shared-root-filesystem ' <<<"$storage_check"
  printf '%s\n' "$storage_check"
  ram_bytes="$(awk '/^MemTotal:/ { print $2 * 1024 }' /proc/meminfo)"
  storage_bytes="$(df --output=size -B1 "$LAMINATE_STORAGE_MOUNT" | tail -n 1 | tr -d ' ')"
  awk -v bytes="$ram_bytes" 'BEGIN { exit !(bytes >= 360000000000) }'
  awk -v bytes="$storage_bytes" 'BEGIN { exit !(bytes >= 9500000000000) }'
  source benches/support/target_storage_contract.sh
  storage_device="$(findmnt -rn -o MAJ:MIN --target "$LAMINATE_STORAGE_MOUNT")"
  storage_device="$(laminate_canonical_bdi "$storage_device")"
  storage_bdi="$(laminate_resolve_backing_bdi "$storage_device")"
  bdi_read_ahead="/sys/class/bdi/$storage_bdi/read_ahead_kb"
  read -r configured_read_ahead < "$bdi_read_ahead"
  test "$configured_read_ahead" = 8192
  printf 'Architecture: %s\n' "$(uname -m)"
  printf 'Physical cores: %s\n' "$physical_cores"
  awk '/^MemTotal:/ { printf "Physical RAM: %.1f GiB\n", $2 / 1048576 }' /proc/meminfo
  df -hT "$LAMINATE_STORAGE_MOUNT"
  printf 'Target filesystem device %s uses BDI %s read_ahead_kb=%s\n' \
    "$storage_device" "$storage_bdi" "$configured_read_ahead"
  echo 'TARGET ENVIRONMENT ACCEPTED: build, root-Hyperdisk layout, RAM, and capacity passed.'
)
```

## After a run: target storage behavior

After `summary` succeeds, retain the selected variant, profile, and (for
Laned) lane count in the current shell. This check applies to server-backed
targets, excluding `local` and `quick`. The
[storage contract](../benches/support/target_storage_contract.sh) defines the
required host settings.

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  [[ "$LAMINATE_PROFILE" == target-balancedLaned || "$LAMINATE_PROFILE" == target-mulHeavyPyramid ]]
  [[ "$LAMINATE_VARIANT" == noIntegrity || "$LAMINATE_VARIANT" == base ||
     "$LAMINATE_VARIANT" == folded || "$LAMINATE_VARIANT" == laned ]]
  bench_root="${LAMINATE_BENCH_ROOT:-${LAMINATE_STORAGE_MOUNT:-/var/lib/laminate-storage}/laminate-bench}"
  pointer="$bench_root/current-${LAMINATE_VARIANT}-${LAMINATE_PROFILE}"
  if [[ "$LAMINATE_VARIANT" == laned ]]; then
    pointer="${pointer}-b${LAMINATE_LANES}"
  fi
  run="$(sed -n '1p' "${pointer}.run")"
  if [[ "$LAMINATE_PROFILE" == target-* ]]; then
    if [[ "$LAMINATE_VARIANT" == noIntegrity ]]; then
      grep -Fqx 'storage.payload_forward_prefetch_fallbacks=0' \
        "$run/server/result.txt"
      grep -Fqx 'storage.payload_forward_maximum_prefetch_request_bytes=16777216' \
        "$run/server/result.txt"
    else
      grep -Fqx 'work.replay.forward.storage.prefetch_fallbacks=0' \
        "$run/server/result.txt"
      grep -Fqx 'work.replay.forward.storage.maximum_prefetch_request_bytes=16777216' \
        "$run/server/result.txt"
    fi
  fi
  echo 'TARGET RESULT EVIDENCE ACCEPTED'
)
```

A successful block exits zero and prints `TARGET RESULT EVIDENCE ACCEPTED`.
The field prefixes differ because `noIntegrity` has no GKR replay engine:

| Evidence | Required target value | What it establishes |
| --- | --- | --- |
| Forward prefetch fallbacks | 0 | Reads used the qualified prefetch path |
| Largest forward prefetch request | 16,777,216 bytes | The observed request matches the tuned BDI geometry |

Keep the run's measured alias, cache, layer, and manifest counters.
Reused bytes refer to data already in storage. Every target setup must select
zero repeated payload replay; this does not eliminate the trace writes and
subsequent GKR reads.

If a check fails, keep the run's evidence and investigate the reported
configuration or storage behavior. A successful proof can still fall outside
the reference configuration's storage qualification. Do not alter the evidence
or relax the profile to convert that run into a matched result. Return to
[archive and retirement](GCP_BENCHMARKS.md#9-archive-and-retire-the-completed-run)
only after the acceptance boundary is understood.
