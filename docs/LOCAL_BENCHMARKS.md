# Local benchmark: direct scalar computation

`local` measures deterministic payload evaluation over `F_65537` in one client
process. It provides the plaintext baseline, with no server, FHE, transport,
or integrity proof. The
[local evaluator](../benches/payload/local_scalar_evaluator.cpp) evaluates
cross-slot dependencies first and the remaining gates in coordinate-major
order. Its [build configuration](../benches/CMakeLists.txt) enables compiler
vectorization and native x86 instructions without linking SEAL or HEXL.
Retain the recorded compiler and CPU-target metadata with each measurement.

See [timing boundaries](BENCHMARKING.md#local-computation-and-verifier-arithmetic)
when comparing this baseline with client verification.

This runbook uses the Linux process runner, with the client performing the
entire computation. For timings comparable to the server-backed benchmarks,
use the same Intel `c4-highmem-48` host, Ubuntu 26.04 or later (Minimal,
x86/AMD64), one vCPU per physical core, and all-core-turbo frequency
configuration. Local-only runs do not need the 10-TB disk, SEAL, BDI tuning, or
an encrypted-trace capacity plan. Other hosts yield separate measurements.

Use **Bash on the VM**. Do not overlap this run with any other benchmark or
build. The client and observer use distinct physical cores (logical CPUs 1
and 2 by default), and setup uses CPU 0 before the client starts. Closing an
observer or disconnecting SSH does not stop a detached measured role.

## 1. Prepare the source and build

Install the [host packages](GCP_BENCHMARKS.md#2-install-packages-and-prepare-the-source).
Use an Ubuntu Minimal 26.04 or later x86/AMD64 image from `ubuntu-os-cloud`
and the same GCC 15 toolchain as the server-backed benchmarks. Start a fresh
build directory after changing the OS or compiler.

Clone the public repository on the VM, unless the checkout is already prepared:

```bash
(
  set -euo pipefail
  git clone https://github.com/kabirp/LaminateArtifactPublic.git \
    "$HOME/LaminateArtifactPublic"
  cd "$HOME/LaminateArtifactPublic"
  test -z "$(git status --porcelain)"
  git rev-parse HEAD
)
```

Retain the printed revision with the measurements. For a downloaded archive
instead, follow the [archive preparation instructions](ARTIFACT_GUIDE.md#prepare-an-extracted-source-archive).

For a local-only VM, create the ordinary writable run directories and build:

```bash
export LAMINATE_BUILD_DIR="$HOME/LaminateArtifactPublic/build-local-release"
export LAMINATE_BENCH_ROOT="$HOME/laminate-local-bench"
export LAMINATE_BENCH_ARCHIVE_ROOT=/var/lib/laminate-bench-archive
export LAMINATE_BUILD_JOBS="$(nproc)"

(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  install -d -m 700 \
    "$LAMINATE_BENCH_ROOT" \
    "$LAMINATE_BENCH_ROOT/runs" \
    "$LAMINATE_BENCH_ROOT/logs"
  sudo install -d -o "$(id -u)" -g "$(id -g)" -m 700 \
    "$LAMINATE_BENCH_ARCHIVE_ROOT"
  cmake \
    -S . \
    -B "$LAMINATE_BUILD_DIR" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER=/usr/bin/g++-15 \
    -DBUILD_TESTING=ON \
    -DBUILD_BENCHMARKS=ON \
    -DLAMINATE_WITH_SEAL=OFF
  cmake --build "$LAMINATE_BUILD_DIR" \
    --target laminate_local_payload_bench laminate_benchmark_cleanup \
    --parallel "$LAMINATE_BUILD_JOBS"
  "$LAMINATE_BUILD_DIR/benches/laminate_local_payload_bench" self_test
)
```

The small `self_test` checks the evaluator. It is not a target run.
If the GCP build is already prepared, keep its GCP path exports
and use its independent local executable. Reconfigure and rebuild after any
source update. Build on the measurement host: `-march=native` binaries can
require instructions unavailable on a different CPU.
Do not reconfigure the SEAL build directory with `LAMINATE_WITH_SEAL=OFF`.

## 2. Validate the client build

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  source /etc/os-release
  test "$ID" = ubuntu
  dpkg --compare-versions "$VERSION_ID" ge 26.04
  test "$(uname -m)" = x86_64
  grep -Eq '^CMAKE_CXX_COMPILER:[^=]+=/usr/bin/g\+\+-15$' "$LAMINATE_BUILD_DIR/CMakeCache.txt"
  test -z "$(git status --porcelain)"
  source_commit="$(git rev-parse HEAD)"
  executable="$LAMINATE_BUILD_DIR/benches/laminate_local_payload_bench"
  test -x "$executable"
  build_info="$($executable build_info)"
  grep -qx 'format=laminate-local-payload-build-info-v1' <<<"$build_info"
  grep -qx "environment.git_commit=$source_commit" <<<"$build_info"
  grep -qx 'environment.git_dirty=false' <<<"$build_info"
  grep -qx 'environment.build_type=Release' <<<"$build_info"
  grep -qx 'benchmark.variant=local' <<<"$build_info"
  grep -qx 'benchmark.roles=client-only' <<<"$build_info"
  grep -qx 'environment.architecture=x86-64' <<<"$build_info"
  grep -qx 'environment.field_backend=scalar-fp65537' <<<"$build_info"
  grep -qx 'environment.vectorization=enabled' <<<"$build_info"
  grep -qx 'environment.cpu_target=native' <<<"$build_info"
  grep -qx 'environment.hexl=not-used' <<<"$build_info"
  grep -qx 'environment.fhe_backend=none' <<<"$build_info"
  grep -qx 'environment.threading=single-cpu-process' <<<"$build_info"
  grep -qx 'computation.integrity=not-applicable' <<<"$build_info"
  grep -qx 'computation.delegation=none' <<<"$build_info"
  grep -qx 'computation.server=none' <<<"$build_info"
  grep -qx 'payload.execution=indexed-cross-slot-prefix-then-coordinate-major' <<<"$build_info"
  grep -qx 'payload.worker_threads=1' <<<"$build_info"
  echo 'LOCAL TARGET ENVIRONMENT ACCEPTED: clean optimized Release client matches this checkout.'
)
```

The revision must match your source snapshot. Local acceptance concerns
the local client only and says nothing about SEAL or storage qualification.
`environment.vectorization=enabled` records compiler permission, not observed
SIMD instructions. Non-x86 builds report `environment.cpu_target=compiler-default`
and are separate from this reference-host measurement procedure.

After reconnecting, restore the same build/run/archive paths you used above
(or the GCP path exports if using its full build), plus `LAMINATE_BUILD_JOBS`.
Repeat the profile selection below. Do not switch run roots mid-lifecycle.

## 3. Select a profile

Set **one** of `quick`, `target-balancedLaned`, or `target-mulHeavyPyramid`:

```bash
export LAMINATE_PROFILE=quick
```

All profiles evaluate 16,384 scalar coordinates. Each target contains `2^20`
payload gates, representing `2^34` scalar logical gates across all coordinates.
Rotation gates are indexed wiring, requiring no field arithmetic or
materialized rotation-output copies. The report separates additions,
multiplications, and permutation wiring.

The [profile definitions](../include/laminate/bench/payload_profile.hpp) fix the
workloads, and the [evaluator](../benches/payload/local_scalar_evaluator.cpp)
defines cross-coordinate storage and traversal. Setup's memory admission
includes shared arithmetic dependencies and view metadata as well as the
scalar wire buffer.

## 4. Run setup and the client

Start a new setup and wait for success:

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  benches/run_gcp.sh start_setup local "$LAMINATE_PROFILE" new
  benches/run_gcp.sh follow_setup local "$LAMINATE_PROFILE" current
)
```

Setup validates the deterministic geometry and scalar-work ledger and binds
the run. It does not perform payload evaluation or reusable cryptographic
preprocessing. The client reconstructs its circuit and inputs before the
separately timed scalar evaluation phase.

After setup passes:

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  benches/run_gcp.sh start_client local "$LAMINATE_PROFILE" current
  benches/run_gcp.sh follow local "$LAMINATE_PROFILE" current
)
```

There is no `start_server` step. `--lanes` is also invalid for `local`.
The runner rejects both. The observer reports completed coordinates and
scalar gates; use progress and CPU activity when assessing a long phase.

## 5. Read and preserve the result

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  benches/run_gcp.sh status local "$LAMINATE_PROFILE" current
  benches/run_gcp.sh summary local "$LAMINATE_PROFILE" current
  run="$(sed -n '1p' "$LAMINATE_BENCH_ROOT/current-local-${LAMINATE_PROFILE}.run")"
  grep -Fqx 'client.result=PASS' "$run/client/result.txt"
  grep -Fqx 'process.exit_status=0' "$run/shared/setup-process-exit.txt"
  grep -Fqx 'process.exit_status=0' "$run/client/process-exit.txt"
  test ! -e "$run/server"
)
```

Read `shared/report/summary.md` at the run path printed by the wrapper.
Success means the client completed its scalar evaluation; it does not mean a
proof was verified. The raw output checksum identifies repeated runs and
profiles but is not an independent correctness oracle. Compare the scalar
evaluation span, setup/startup, and total client time as separately labeled
quantities; see [Benchmarking](BENCHMARKING.md).

After reviewing an accepted report:

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  benches/run_gcp.sh archive_retire local "$LAMINATE_PROFILE" current
)
```

Wait for `ARCHIVE PASS` and `RETIRE PASS` before starting another measurement.
The command verifies the compact evidence archive before deleting the live
run. Follow [Copy results off the VM](GCP_BENCHMARKS.md#copy-results-off-the-vm)
to preserve the summary, evidence archive, and checksum. For a complete
comparison, repeat this flow for each target profile, using the matching
server-backed runs from the GCP guide. Keep each run's source revision and
host metadata with its measurements.

## Retire an incomplete run

Use `status` to inspect the selected run. Do not restart an interrupted role
in place. Before stopping it, interrupt any outer launch/follow shell with
Ctrl-C so it cannot launch a later role. Then stop the exact run on the VM:

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  python3 benches/support/stop_benchmark_run.py \
    --variant local --run-dir '/ABSOLUTE/PATH/TO/RUN'
)
```

The helper validates process identities, sends TERM only to that run's setup
and client, and waits for its role, lifecycle, and per-run wrapper locks to become
inactive. It preserves the artifacts. Continue only after `STOPPED`; inspect
any error before proceeding. Once inactive, preserve failure evidence and
remove scratch files with:

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  benches/run_gcp.sh archive_retire_failed local "$LAMINATE_PROFILE" current \
    --confirm-retire-failed-current-run
)
```

Then begin again with `start_setup ... new`. The archived failed run is not an
accepted measurement.
