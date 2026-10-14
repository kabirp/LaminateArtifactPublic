# GCP benchmarks: noIntegrity, Base, Folded, and Laned

This runbook describes the **server-backed** benchmarks. For direct
plaintext computation, use the separate
[local benchmark runbook](LOCAL_BENCHMARKS.md).

Follow the sections in order: prepare the host and source, build, select one
profile and variant, run setup/client/server, check the result, and preserve
it. Commands run in **Bash on the VM**, except the final download block.
Operational blocks use a fail-fast subshell so a failed command stops that
block without closing the surrounding SSH shell. Exports outside those
blocks remain available to later commands.

The target set contains seven proof-bearing configurations. Both workloads also
have local and noIntegrity baselines:

| Payload | Proof-bearing runs | Baselines |
| --- | --- | --- |
| `target-balancedLaned` | Base and Folded, plus Laned at `B=1`, `128`, and `16,384` | `local`, `noIntegrity` |
| `target-mulHeavyPyramid` | Base and Folded | `local`, `noIntegrity` |

The two noIntegrity baselines use this runbook, and the two local baselines
use their own guide. Laned requires `balancedLaned`. The paired client
and server of one run execute together; do not overlap different runs,
compilation, or unrelated measured work. `quick` checks integration and is
not a target result. No standalone kernel or storage microbenchmarks are
required by this runbook.

## 1. Provision the reference host

The reference configuration is fixed to make reproduced timings comparable:

| Property | Target configuration |
| --- | --- |
| Machine | Intel x86-64 `c4-highmem-48` |
| CPU configuration | One vCPU per physical core; frequency limited to all-core turbo |
| RAM | 372 GB |
| Root disk | One 10,000-GB Hyperdisk Balanced volume |
| Provisioned disk performance | 2,400 MiB/s and 150,000 IOPS |
| OS | Ubuntu 26.04 LTS Minimal, x86/AMD64 |

In the GCP console, select those settings and the instance label
`laminate-benchmark=true`. Do not attach a second benchmark disk. Confirm the
disk product, size, throughput, and IOPS in the console: Linux can check the
filesystem and capacity but cannot establish all provisioned cloud settings.
See Google's [C4 machine table](https://docs.cloud.google.com/compute/docs/general-purpose-machines#c4_machine_types)
and [Hyperdisk documentation](https://docs.cloud.google.com/compute/docs/disks/hyperdisks)
for provisioning details. If capacity is unavailable, try another zone.

Use Ubuntu 26.04 LTS Minimal (AMD64) from project `ubuntu-os-cloud`, with image
family `ubuntu-minimal-2604-lts-amd64`. For `gcloud compute instances create`,
the image arguments are:

```text
--image-project=ubuntu-os-cloud --image-family=ubuntu-minimal-2604-lts-amd64
```

Before provisioning, resolve the current family member with this read-only
command from a machine with an authenticated Google Cloud CLI:

```bash
gcloud compute images describe-from-family ubuntu-minimal-2604-lts-amd64 \
  --project=ubuntu-os-cloud \
  --format='yaml(name,family,architecture,status,creationTimestamp)'
```

Retain that output and the boot disk's resolved source image with the
measurement metadata. To reuse the exact image later, replace `--image-family`
with `--image=NAME` using the returned name and keep the same image project.
The family advances as Canonical publishes updates.

Server, client, and observer must use distinct physical cores. The runner
checks this and uses logical CPUs 0, 1, and 2 by default. Each online role
is single-threaded. Base and Folded setup can use a worker pool for GateMLE
preprocessing. Setup runs before online work and holds the
exclusive setup locks. Target builds require AVX2, AVX-512F, AVX-512DQ,
AVX-512IFMA, Intel HEXL, and Laminate's native-Fq HEXL adapter.

The root filesystem holds both live work and compact evidence:

```text
/var/lib/laminate-storage/
  laminate-bench/       live runs
  toolchain/            dependency sources, builds, and installs
/var/lib/laminate-bench-archive/   compact completed-run evidence
```

The archive directory is separate from live scratch but shares the disk.
Copy completed evidence off the VM before deleting it. Results from another
host or storage configuration must be labeled separately.

## 2. Install packages and prepare the source

Install the host tools on Ubuntu 26.04. Its archive provides
[GCC 15](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/)
and [CMake 4.2](https://packages.ubuntu.com/resolute/cmake). Select the compiler
explicitly in every build below so all variants use the same toolchain:

```bash
(
  set -euo pipefail
  source /etc/os-release
  test "$ID" = ubuntu
  test "$VERSION_ID" = 26.04
  test "$(dpkg --print-architecture)" = amd64
  sudo apt-get update
  sudo apt-get install -y \
    build-essential gcc-15 g++-15 cmake ninja-build git libssl-dev pkg-config \
    time sysstat util-linux mdadm e2fsprogs python3 ca-certificates tmux
  sudo apt-get clean
  gcc-15 --version
  g++-15 --version
  cmake --version
  ninja --version
)
```

On the VM, clone the public repository before building:

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

Run this once on a fresh VM; skip it if the checkout is already prepared.
Retain the printed revision with the measurements and keep results outside
the source directory. The runner checks a clean source identity and never
updates the source automatically. For a downloaded archive instead, follow
the [archive preparation instructions](ARTIFACT_GUIDE.md#prepare-an-extracted-source-archive).

## 3. Prepare the root filesystem

This uses the existing 10-TB root disk. The helper creates owner-only
work directories and a marker; it does not format, partition, mount, remount,
or delete data. Run as the benchmark login user through `sudo`:

```bash
export LAMINATE_STORAGE_MOUNT=/var/lib/laminate-storage
export LAMINATE_BENCH_ROOT="$LAMINATE_STORAGE_MOUNT/laminate-bench"
export LAMINATE_BUILD_DIR="$LAMINATE_STORAGE_MOUNT/toolchain/build/LaminateImpl"
export LAMINATE_BENCH_ARCHIVE_ROOT=/var/lib/laminate-bench-archive
export LAMINATE_STORAGE_MIN_TOTAL_BYTES=9500000000000
export LAMINATE_BUILD_JOBS="$(nproc)"

(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  sudo env \
    LAMINATE_STORAGE_MOUNT="$LAMINATE_STORAGE_MOUNT" \
    LAMINATE_BENCH_ROOT="$LAMINATE_BENCH_ROOT" \
    LAMINATE_BENCH_ARCHIVE_ROOT="$LAMINATE_BENCH_ARCHIVE_ROOT" \
    LAMINATE_STORAGE_MIN_TOTAL_BYTES="$LAMINATE_STORAGE_MIN_TOTAL_BYTES" \
    benches/prepare_gcp_root_storage.sh prepare \
      --confirm-share-root-filesystem
  benches/prepare_gcp_root_storage.sh verify
  df -hT "$LAMINATE_STORAGE_MOUNT"
  lsblk -o NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL
)
```

The `LaminateImpl` build-directory name matches the runner's target default;
the source checkout is `LaminateArtifactPublic`.

The recorded backend `shared-root-filesystem` means the OS and benchmark
share the root disk. The 9.5-TB capacity floor catches an undersized filesystem;
setup separately measures available space and leaves its reserves.

Set the required read-ahead after every VM boot, using the filesystem's
actual backing device:

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  : "$LAMINATE_STORAGE_MOUNT"
  source benches/support/target_storage_contract.sh
  storage_device="$(findmnt -rn -o MAJ:MIN --target "$LAMINATE_STORAGE_MOUNT")"
  storage_device="$(laminate_canonical_bdi "$storage_device")"
  storage_bdi="$(laminate_resolve_backing_bdi "$storage_device")"
  bdi_read_ahead="/sys/class/bdi/$storage_bdi/read_ahead_kb"
  printf '%s\n' 8192 | sudo tee -- "$bdi_read_ahead" >/dev/null
  read -r configured_read_ahead < "$bdi_read_ahead"
  test "$configured_read_ahead" = 8192
  printf 'Target filesystem device %s uses BDI %s read_ahead_kb=%s\n' \
    "$storage_device" "$storage_bdi" "$configured_read_ahead"
)
```

The 8-MiB BDI setting permits the implementation's 16-MiB prefetch requests.
The target storage contract requires this setting. It does not persist
across reboots.

### Restore paths after reconnecting

SSH reconnects lose shell exports. Repeat this block before further work:

```bash
export LAMINATE_STORAGE_MOUNT=/var/lib/laminate-storage
export LAMINATE_BENCH_ROOT="$LAMINATE_STORAGE_MOUNT/laminate-bench"
export LAMINATE_BUILD_DIR="$LAMINATE_STORAGE_MOUNT/toolchain/build/LaminateImpl"
export LAMINATE_BENCH_ARCHIVE_ROOT=/var/lib/laminate-bench-archive
export LAMINATE_STORAGE_MIN_TOTAL_BYTES=9500000000000
export LAMINATE_BUILD_JOBS="$(nproc)"
```

Also repeat the profile and variant selection in section 6 when continuing a
run. Restore any explicitly chosen CPU exports as well.

## 4. Build SEAL and Laminate

Build the pinned [Microsoft SEAL 4.1.2](https://github.com/microsoft/SEAL/tree/v4.1.2)
dependency with its [pinned Intel HEXL 1.2.5](https://github.com/microsoft/SEAL/blob/v4.1.2/cmake/ExternalIntelHEXL.cmake).
Use the Laminate source prepared in section 2 and fresh toolchain directories
after an OS or compiler change.

The C11 setting and subshell-scoped
[CMake policy override](https://cmake.org/cmake/help/v4.2/envvar/CMAKE_POLICY_VERSION_MINIMUM.html)
provide compatibility for SEAL's bundled dependency build files.

```bash
(
  set -euo pipefail
  export CMAKE_POLICY_VERSION_MINIMUM=3.5
  if [[ ! -d "$LAMINATE_STORAGE_MOUNT/toolchain/src/SEAL-4.1.2/.git" ]]; then
    git clone --depth 1 --branch v4.1.2 \
      https://github.com/microsoft/SEAL.git \
      "$LAMINATE_STORAGE_MOUNT/toolchain/src/SEAL-4.1.2"
  fi

  cmake \
    -S "$LAMINATE_STORAGE_MOUNT/toolchain/src/SEAL-4.1.2" \
    -B "$LAMINATE_STORAGE_MOUNT/toolchain/build/SEAL-4.1.2" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=/usr/bin/gcc-15 \
    -DCMAKE_CXX_COMPILER=/usr/bin/g++-15 \
    -DCMAKE_C_STANDARD=11 \
    -DCMAKE_C_STANDARD_REQUIRED=ON \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_CXX_FLAGS="-march=native" \
    -DSEAL_BUILD_DEPS=ON \
    -DSEAL_USE_INTEL_HEXL=ON \
    -DSEAL_USE_INTRIN=ON \
    -DSEAL_BUILD_TESTS=OFF \
    -DSEAL_BUILD_EXAMPLES=OFF \
    -DSEAL_BUILD_BENCH=OFF \
    -DCMAKE_INSTALL_PREFIX="$LAMINATE_STORAGE_MOUNT/toolchain/install/seal-4.1.2"

  cmake --build \
    "$LAMINATE_STORAGE_MOUNT/toolchain/build/SEAL-4.1.2" \
    --parallel "$(nproc)"
  cmake --install \
    "$LAMINATE_STORAGE_MOUNT/toolchain/build/SEAL-4.1.2"
)
```

Build Laminate and run its extended SEAL correctness tests:

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  cmake -E make_directory "$LAMINATE_BUILD_DIR"
  cmake \
    -S . \
    -B "$LAMINATE_BUILD_DIR" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER=/usr/bin/g++-15 \
    -DCMAKE_CXX_FLAGS="-march=native" \
    -DBUILD_TESTING=ON \
    -DBUILD_BENCHMARKS=ON \
    -DLAMINATE_EXTENDED_TESTS=ON \
    -DLAMINATE_WITH_SEAL=ON \
    -DLAMINATE_REQUIRE_SEAL_HEXL=ON \
    -DLAMINATE_SEAL_DIR="$LAMINATE_STORAGE_MOUNT/toolchain/install/seal-4.1.2/lib/cmake/SEAL-4.1" \
    2>&1 | tee "$LAMINATE_BUILD_DIR/laminate-configure.log"

  cmake --build "$LAMINATE_BUILD_DIR" --parallel "$(nproc)"
  ctest --test-dir "$LAMINATE_BUILD_DIR" --output-on-failure
)
```

The SEAL configuration selects real-backend tests; the backend-independent
tests run in a separate Mock configuration. Build and run that extended suite
as well, keeping the benchmark build directory above unchanged:

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  laminate_mock_build_dir="$LAMINATE_STORAGE_MOUNT/toolchain/build/LaminateImpl-mock"
  cmake \
    -S . \
    -B "$laminate_mock_build_dir" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER=/usr/bin/g++-15 \
    -DCMAKE_CXX_FLAGS="-march=native" \
    -DBUILD_TESTING=ON \
    -DBUILD_BENCHMARKS=ON \
    -DLAMINATE_EXTENDED_TESTS=ON \
    -DLAMINATE_WITH_SEAL=OFF
  cmake --build "$laminate_mock_build_dir" --parallel "$(nproc)"
  ctest --test-dir "$laminate_mock_build_dir" --output-on-failure
)
```

Both suites must pass on the measurement host. Tests are bounded checks and do
not launch the target workloads. Keep builds and tests separate from measured
runs. The build also provides the independent scalar executable used by the
[local runbook](LOCAL_BENCHMARKS.md).

## 5. Validate the build and host

Open [build and host checks](BENCHMARK_VALIDATION.md#before-a-run-build-and-host)
and **execute its entire Bash block on the VM before launching any run**,
retaining the path exports from section 3. Both extended test suites must pass,
and the validation block must finish with `TARGET ENVIRONMENT ACCEPTED`. It
checks source/build identity, acceleration, RAM, storage layout, and read-ahead.
Confirm the cloud disk product and provisioned settings separately in the GCP
console.

## 6. Select one profile and variant

All selections use `N=16,384`, 64 encrypted inputs, and one output. Target
profiles have depth 8 and exactly `2^20` payload gates:

| Profile | Workload | Supported variants |
| --- | --- | --- |
| `quick` | Bounded depth-six integration check | noIntegrity, Base, Folded, Laned |
| `target-balancedLaned` | Depth-eight balanced payload without cross-slot operations | noIntegrity, Base, Folded, Laned |
| `target-mulHeavyPyramid` | Depth-eight multiplication-heavy Wide payload | noIntegrity, Base, Folded |

The profile selects fixed cryptographic parameters; setup does not search for
an alternative chain or weaker integrity settings. `quick` uses reduced
security parameters and serves only as an integration rehearsal. Current
parameters and security scope are summarized in [Status](STATUS.md); exact
workloads and profiles are defined in
[`payload_profile.hpp`](../include/laminate/bench/payload_profile.hpp) and
[`packed_process_profile.hpp`](../include/laminate/bench/packed_process_profile.hpp).
See [privacy estimates](PRIVACY_ESTIMATES.md) for the selected lattice model.

For an integration rehearsal, use `quick` with any variant below:

```bash
export LAMINATE_PROFILE=quick
```

For a target run, choose one workload. Base, Folded, and noIntegrity support
either profile. Laned requires `target-balancedLaned`.

```bash
export LAMINATE_PROFILE=target-balancedLaned
```

```bash
export LAMINATE_PROFILE=target-mulHeavyPyramid
```

Then copy **one** variant block:

For the FHE-only baseline:

```bash
export LAMINATE_VARIANT=noIntegrity
unset LAMINATE_LANES
```

For Base (either target, or `quick` for rehearsal):

```bash
export LAMINATE_VARIANT=base
unset LAMINATE_LANES
```

For Folded (either target, or `quick` for rehearsal):

```bash
export LAMINATE_VARIANT=folded
unset LAMINATE_LANES
```

For Laned (`target-balancedLaned`, or `quick` for rehearsal), copy exactly one block:

```bash
export LAMINATE_VARIANT=laned
export LAMINATE_LANES=1
```

```bash
export LAMINATE_VARIANT=laned
export LAMINATE_LANES=128
```

```bash
export LAMINATE_VARIANT=laned
export LAMINATE_LANES=16384
```

The spelling `noIntegrity` is case-sensitive. After an SSH
reconnect, restore the applicable path exports and repeat both selection
steps.

`noIntegrity` measures encrypted payload evaluation and output decryption
without a proof. Base sends the GKR proof directly; Folded and Laned additionally
prove transcript packing. Laned always requires an explicit lane count on
every action, including observation and retirement. Its independent scalar
workload is `B * 2^20` gates per target; the wide variants and the full local
baseline have `N * 2^20`. Compare the reported scalar-gate scale as well as the
profile when comparing different lane counts.

## 7. Run setup, client, and server

Keep the source snapshot and binaries fixed for the lifetime of a run. Setup
checks geometry, the selected noise schedule, and resource capacity before the
online roles start. See the [runtime reference](#runtime-and-resource-reference)
for setup threading and bounded noise checks.

Run the entire block below in a `tmux` session (for example, start one with
`tmux new -s laminate-run`). Set the path, profile, and variant exports from
sections 3 and 6 inside that session. The block starts a new immutable setup,
waits for setup to pass, then launches the client followed by the server and
follows the run to completion. A setup failure stops the block before either
online role starts; no manual handoff after setup is needed.

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  run_args=()
  if [[ "$LAMINATE_VARIANT" == laned ]]; then
    : "$LAMINATE_LANES"
    run_args=(--lanes "$LAMINATE_LANES")
  fi
  benches/run_gcp.sh start_setup "$LAMINATE_VARIANT" "$LAMINATE_PROFILE" new "${run_args[@]}"
  benches/run_gcp.sh follow_setup "$LAMINATE_VARIANT" "$LAMINATE_PROFILE" current "${run_args[@]}"
  benches/run_gcp.sh start_client "$LAMINATE_VARIANT" "$LAMINATE_PROFILE" current "${run_args[@]}"
  benches/run_gcp.sh start_server "$LAMINATE_VARIANT" "$LAMINATE_PROFILE" current "${run_args[@]}"
  benches/run_gcp.sh follow "$LAMINATE_VARIANT" "$LAMINATE_PROFILE" current "${run_args[@]}"
)
```

Setup and the online roles run detached, but the shell executing this block
must remain alive to launch the later steps. Detach from `tmux` with **Ctrl-B,
then D**; the whole sequence continues after SSH disconnects. Interrupting
`follow_setup` stops the block's pending client/server launches while the
detached setup continues. Once both online roles have started, stopping
`follow` leaves them running. A new SSH session can issue `status` using the
same selections and replacing the action in a runner command above. The
`current` pointer is scoped by variant, profile, and Laned width.

Targets can take days. A long phase is not itself a failure: use the reported
phase and CPU/I/O progress to distinguish active work from a stall. Do not
restart a role in an existing immutable run.

## 8. Validate and read the result

Check terminal status and render the report:

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  run_args=()
  if [[ "$LAMINATE_VARIANT" == laned ]]; then
    : "$LAMINATE_LANES"
    run_args=(--lanes "$LAMINATE_LANES")
  fi
  benches/run_gcp.sh status "$LAMINATE_VARIANT" "$LAMINATE_PROFILE" current "${run_args[@]}"
  benches/run_gcp.sh summary "$LAMINATE_VARIANT" "$LAMINATE_PROFILE" current "${run_args[@]}"
)
```

The report is `shared/report/summary.md` under the selected run directory
printed by the wrapper. Read it before retirement. For a target run, perform the
[post-run target evidence checks](BENCHMARK_VALIDATION.md#after-a-run-target-storage-behavior) before accepting
and archiving it. These inspect the completed records; they do not launch
another workload.

For Base, Folded, and Laned, success requires client proof verification `PASS`
and zero setup, client, and server exits. Packed target runs also require the
final output-noise audit to pass. For `noIntegrity`, the client must
finish decoding and fully decrypting the output, and all three roles must
exit zero; this is not an integrity claim. A response file alone is not success.
`summary` validates the evidence before publishing the human report.

Use [Benchmarking](BENCHMARKING.md#reading-the-report) to interpret timings,
communication sizes, and resource bounds. Exact parameters and process records
remain in the raw evidence.

## 9. Archive and retire the completed run

After reviewing an accepted report:

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  run_args=()
  if [[ "$LAMINATE_VARIANT" == laned ]]; then
    : "$LAMINATE_LANES"
    run_args=(--lanes "$LAMINATE_LANES")
  fi
  benches/run_gcp.sh archive_retire "$LAMINATE_VARIANT" "$LAMINATE_PROFILE" current "${run_args[@]}"
)
```

Continue to the next measurement only after `ARCHIVE PASS` and `RETIRE PASS`.
This command copies and verifies compact evidence, then deletes the exact
completed live run, including its large preprocessing and trace artifacts.
It exports the report, an evidence archive, and a checksum under
`/var/lib/laminate-bench-archive`; it does not preserve restartable keys or
proof/trace files. The runner rejects retirement while measured roles are active.

Run `local` and `noIntegrity` once per target profile, and complete the seven
proof-bearing configurations listed at the start of this guide. Keep the build
and host settings fixed between matched measurements.

To reuse the VM, copy the exported evidence off the VM, select the next
configuration in section 6, and start a new run in section 7. Preserve each
run's source identity. If source or toolchain settings change, repeat both
build/test suites and host validation before measuring. After rebooting,
restore the path exports and read-ahead setting from section 3.

## Stop or retire an incomplete run

First inspect `status` and the failure it reports. An interrupted or failed
immutable run must not be resumed in place.

Before stopping roles, interrupt any outer `follow_setup`/`follow` orchestration
shell with Ctrl-C so it cannot launch another role. To stop the selected
noIntegrity, Base, Folded, or Laned run, use its exact absolute directory:

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  python3 benches/support/stop_benchmark_run.py \
    --variant "$LAMINATE_VARIANT" --run-dir '/ABSOLUTE/PATH/TO/RUN'
)
```

The helper checks process identity before sending TERM, waits for roles to exit,
and requires inactive role, lifecycle, and per-run wrapper locks. It preserves all
artifacts and stops only the selected run. If it reports an error, inspect that
error before proceeding.

Once all roles are inactive, this operation preserves compact failure evidence
and removes the exact failed current run:

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  run_args=()
  if [[ "$LAMINATE_VARIANT" == laned ]]; then
    : "$LAMINATE_LANES"
    run_args=(--lanes "$LAMINATE_LANES")
  fi
  benches/run_gcp.sh archive_retire_failed "$LAMINATE_VARIANT" "$LAMINATE_PROFILE" current "${run_args[@]}" --confirm-retire-failed-current-run
)
```

The retirement command requires the explicit confirmation flag. Failed
evidence is labeled as failed and does not become an accepted measurement. After
retirement, start a new run with `start_setup ... new`.

After the new current run has passed setup, `cleanup_old` can remove older
inactive siblings matching the same variant, profile, and lane count. It
preserves `current` and permanently deletes those siblings without archiving
them; use it only when their evidence is no longer needed:

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  run_args=()
  if [[ "$LAMINATE_VARIANT" == laned ]]; then
    : "$LAMINATE_LANES"
    run_args=(--lanes "$LAMINATE_LANES")
  fi
  benches/run_gcp.sh cleanup_old "$LAMINATE_VARIANT" "$LAMINATE_PROFILE" current "${run_args[@]}"
)
```

## Copy results off the VM

These instructions also apply to the local benchmark. After `archive_retire`,
the VM archive directory contains three files per accepted run:

- `RUN_NAME.summary.md`: the standalone human report;
- `RUN_NAME.evidence.tar.gz`: compact raw evidence plus the same report;
- `RUN_NAME.evidence.tar.gz.sha256`: checksum for that archive.

Copy the archive directory to your own computer before deleting the VM. With
Google Cloud CLI authenticated, edit the three placeholders below and run this
block in **Bash on your computer**. It creates a fresh local destination and
verifies every archive checksum with OpenSSL.

```bash
(
  set -euo pipefail
  laminate_vm=VM_NAME
  laminate_zone=ZONE
  laminate_project=PROJECT_ID
  laminate_download="$(mktemp -d "$HOME/laminate-reports.XXXXXX")"
  gcloud compute scp --recurse \
    "$laminate_vm:/var/lib/laminate-bench-archive" "$laminate_download" \
    --zone "$laminate_zone" --project "$laminate_project"

  cd "$laminate_download/laminate-bench-archive"
  checksum_count=0
  for checksum in *.tar.gz.sha256; do
    [[ -f "$checksum" ]] || continue
    archive="${checksum%.sha256}"
    test -s "$archive"
    expected="$(awk 'NR == 1 { print $1 }' "$checksum")"
    actual="$(openssl dgst -sha256 "$archive" | awk '{ print $NF }')"
    test "$actual" = "$expected"
    printf '%s: checksum OK\n' "$archive"
    checksum_count=$((checksum_count + 1))
  done
  test "$checksum_count" -gt 0
  printf 'Reports and evidence: %s\n' "$PWD"
)
```

Only stop or delete the VM after checking the copied summaries and
successfully verifying the evidence checksums.

For a local-only VM, use the [local runbook](LOCAL_BENCHMARKS.md) for directory
initialization, build, and execution.

## Runtime and resource reference

Setup reserves 100 GB of disk, 16 GB of host RAM, and 64 GB for page cache,
then charges the concurrent client's modeled peak before admitting the server.
It must find a target plan with **zero repeated payload replay**. The general
2.5x cumulative-work ceiling only permits nonzero replay in smaller profiles.
If target admission fails, inspect free capacity and the reported reason;
retire earlier runs or use another correctly provisioned VM. Changing the
host configuration produces a separate measurement configuration. Do not edit
target parameters to make admission pass.

Setup validates circuit geometry, the fixed noise schedule, and RAM/disk
admission before publishing preprocessing. It binds the selected schedule to
the run; keep the source snapshot and binaries fixed for its lifetime.
The [BGV parameter reference](BGV_NOISE_AND_MODULUS_SWITCHING.md) links to the
chain and proof-ingress definitions.

The Base and Folded `target-mulHeavyPyramid` setups include bounded ciphertext
noise checks before GateMLE construction. Folded uses the same key that setup
publishes, and includes GKR, alignment, and transcript-packing checks. Any
rejection stops setup without retrying keys. These guards contribute to setup
time and do not replace full client verification. Their scope and resource
requirements are defined in
[`target_noise_preflight.hpp`](../benches/support/target_noise_preflight.hpp) and
[`folded_target_noise_preflight.hpp`](../benches/support/folded_target_noise_preflight.hpp).
Allow roughly 15 minutes for the Folded guard, with 16 GiB of resident
allowance and 32 GiB of temporary scratch space.

On a 372-GB host, Folded's structural admission requires approximately 4.45 TB
of available disk for `target-balancedLaned` and 6.66 TB for
`target-mulHeavyPyramid`, including reserves and concurrent artifacts. The
filesystem-size check alone does not establish available capacity. Retire
completed runs before the next setup; setup reports the exact requirement and
checks generated artifact sizes before publication. The admission model is
implemented in
[`packed_setup_admission.hpp`](../include/laminate/bench/packed_setup_admission.hpp).

By default, Base and Folded setup use all CPUs allowed by the launcher's mask,
up to 256 logical CPUs, excluding the observer's physical core. Set `LAMINATE_SETUP_THREADS`
to a smaller count to limit setup CPU use. For example,
`export LAMINATE_SETUP_THREADS=16` selects 16 available CPUs. Requests that
exceed the available CPUs are rejected. `LAMINATE_SETUP_THREADS=1` runs on
`LAMINATE_SETUP_CPU` (default 0), which must be allowed by the launcher's mask.
Laned, local, and noIntegrity setup use this single CPU.

The worker pool accelerates supported GateMLE encoding and Merkle-tree work.
Other setup stages may still use one core. Setup records its worker count and
CPU affinity in the run report. Server and client processes always use their
own single-CPU settings, and the runner removes `LAMINATE_SETUP_THREADS` from
their environments. Setup timing therefore depends on the setup allocation;
compare online timings under the recorded server and client settings.
