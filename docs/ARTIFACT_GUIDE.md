# Artifact evaluation guide

This guide gives a short path through the implementation and its benchmarks.
The repository contains source, tests, reproduction instructions, and
[benchmark summaries](../bench_outputs/README.md). Keep newly generated run
data outside the source tree.

## Review the implementation

Begin with the [README quick start](../README.md#build-and-run-a-small-proof).
The Mock tests and three small proof examples require no SEAL library or cloud
account. A SEAL build adds bounded checks with real BGV ciphertexts. The
`quick` process profile then exercises the separate setup, server, and client
executables on Linux. Packed quick profiles use a diagnostic hash and reduced
query counts to check the workflow.

For protocol definitions and proofs, use the accompanying paper; the
[documentation index](README.md#paper-and-artifact) identifies the relevant
sections. Read [architecture](ARCHITECTURE.md) for the software structure and
[protocols](PROTOCOLS.md#paper-references) for the
paper-to-code correspondence.
The [source guide](../include/laminate/README.md) links the main APIs and tests.
[Status](STATUS.md) records the current parameters and security assumptions,
and [privacy estimates](PRIVACY_ESTIMATES.md) gives a separate reproduction of
the lattice attack estimates.

## Reproduce the benchmarks

The seven proof-bearing target configurations are:

| Variant | Profile | Lanes |
| --- | --- | --- |
| Base | `target-balancedLaned` | Wide |
| Base | `target-mulHeavyPyramid` | Wide |
| Folded | `target-balancedLaned` | Wide |
| Folded | `target-mulHeavyPyramid` | Wide |
| Laned | `target-balancedLaned` | 1 |
| Laned | `target-balancedLaned` | 128 |
| Laned | `target-balancedLaned` | 16,384 |

Both payloads contain `2^20` payload operations at ring degree `N=16,384`.
Full-width runs evaluate `2^34` scalar gates; Laned evaluates `B × 2^20`.
See the
[workload definitions](BENCHMARKING.md#benchmark-workload-scope) before
comparing different lane counts. Follow the [GCP runbook](GCP_BENCHMARKS.md)
for these runs and the FHE-only `noIntegrity` baselines. The direct scalar
`local` baselines have their own [runbook](LOCAL_BENCHMARKS.md). Rehearse the
workflow with `quick` before starting an expensive target run.

## Read and preserve results

Each completed run exports three files:

| File | Purpose |
| --- | --- |
| `RUN_NAME.summary.md` | Human-readable report |
| `RUN_NAME.evidence.tar.gz` | Compact raw records and a copy of the summary |
| `RUN_NAME.evidence.tar.gz.sha256` | Archive checksum |

Check the source revision, workload, protocol, lane count, and verification
outcome before comparing timings. Client computation includes input
encryption, output decryption, and verification with preprocessing already
loaded. Reusable setup and startup have separate raw timing records; the
concise summary omits setup duration.
[Benchmarking](BENCHMARKING.md#reading-the-report) defines the remaining
measurement boundaries and resource counters.

For `local`, setup and client must exit zero and `client.result=PASS` must
appear. For `noIntegrity`, setup, server, and client must exit zero and the
client must finish decoding and decrypting the output. A proof-bearing run
also requires successful client verification. The
[target validation guide](BENCHMARK_VALIDATION.md) explains the storage and
execution checks.

Both runbooks finish with `summary` and `archive_retire`. Retirement checks
the compact evidence archive before deleting that run's large live artifacts.
Copy all three exported files off the VM before deleting it, following the
[transfer instructions](GCP_BENCHMARKS.md#copy-results-off-the-vm). Keep repeated
runs separate so their source identity and host remain clear. The archive
contains reports rather than keys, requests, responses, or trace files, so
reproduction starts a new execution.

## Obtain the public source

The runbooks assume the source root is `$HOME/LaminateArtifactPublic`, with
`CMakeLists.txt`, `include/`, `src/`, and `benches/` immediately inside it.
Clone the [public repository](https://github.com/kabirp/LaminateArtifactPublic)
after installing Git:

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

Retain the printed commit with the measurements. A clone already has its
source identity and does not need the archive initialization below. Keep the
checkout unchanged throughout a run and keep generated logs and results
outside the source tree.

## Prepare an extracted source archive

As an alternative to cloning, download the
[main-branch ZIP archive](https://github.com/kabirp/LaminateArtifactPublic/archive/refs/heads/main.zip).
Extract it and rename the extracted `LaminateArtifactPublic-main` directory to
`$HOME/LaminateArtifactPublic`. For a fixed source version, download a specific
commit's archive from the repository instead of the moving `main` branch.
Preserve the download URL and original archive, and check its checksum when
one is provided.

### Record the source identity

The benchmark runner requires a clean Git revision and checks that each
binary was built from it. For an extracted archive without `.git`, initialize
a local snapshot **before configuring or building**. No remote is needed.

After installing Git, run this once in a fresh extraction, using Bash:

```bash
(
  set -euo pipefail
  cd "$HOME/LaminateArtifactPublic"
  test -f CMakeLists.txt
  test -f benches/run_gcp.sh
  test ! -e .git
  # Restore script permissions if the archive extractor did not preserve them.
  chmod u+x run_all_tests.sh benches/*.sh benches/support/*.sh
  git init
  git add --all
  git -c user.name='Artifact reviewer' \
      -c user.email='artifact-reviewer@example.invalid' \
      -c commit.gpgsign=false \
      commit -m 'Snapshot of extracted Laminate artifact'
  test -z "$(git status --porcelain)"
  git rev-parse HEAD
)
```

Keep the original source archive and checksum alongside the local snapshot
revision. For an existing Git checkout, skip this initialization. Keep the
source unchanged throughout a run so setup, binaries, and reports refer to
the same revision.
Ignored `build/` and `build-*/` directories can hold workstation builds. The
GCP guide uses a separate toolchain directory.
