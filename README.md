# Laminate artifact

This repository contains the C++20 implementation accompanying
[*Laminate: Succinct SIMD-Friendly Verifiable FHE*](https://eprint.iacr.org/2025/2285).
It implements LaminateBase,
LaminateFolded, and LaminateLaned with Microsoft SEAL BGV, a shared payload
compiler, file-backed proving, and separate client and server processes.

**Research software. Not intended for production use.** The implementation
supports protocol evaluation and reproducible cost studies. It is provided
without warranty under the [Apache License 2.0](LICENSE). Read
[status and security assumptions](docs/STATUS.md) before interpreting its
parameters or results.

## Build and run a small proof

You need Git, a C++20 compiler, CMake 3.20 or newer, Make, Bash, and Python 3.10
or newer. The default preset uses the functional Mock backend and needs no
SEAL installation. Clone the repository and run:

```sh
git clone https://github.com/kabirp/LaminateArtifactPublic.git
cd LaminateArtifactPublic
cmake --preset dev-mock
cmake --build --preset dev-mock --parallel
ctest --test-dir build --output-on-failure
```

This Debug build writes `build/compile_commands.json` for editor support.
Add `-DLAMINATE_EXTENDED_TESTS=ON` when configuring to include further component
and edge-case tests. CTest runs bounded checks; the target benchmark campaign
is separate.

The following Bash example generates and verifies a small proof for each
variant, keeping its reports in a temporary directory:

```bash
(
  set -euo pipefail
  laminate_smoke_dir="$(mktemp -d)"
  for variant in base folded laned; do
    build/benches/laminate_protocol_bench \
      --protocol "$variant" --backend mock --slots 32 --depth 1 --width 1 \
      --result-file "$laminate_smoke_dir/$variant-result.txt" \
      --progress-file "$laminate_smoke_dir/$variant-progress.jsonl" \
      > "$laminate_smoke_dir/$variant-stdout.txt" \
      2> "$laminate_smoke_dir/$variant-stderr.txt"
  done
  for variant in base folded laned; do
    grep -H '^verification.result=ACCEPT$' "$laminate_smoke_dir/$variant-result.txt"
  done
  printf 'Reports: %s\n' "$laminate_smoke_dir"
)
```

Mock checks algebra and control flow. To exercise real BGV encryption, install
Microsoft SEAL 4.1 and build the complementary SEAL test suite:

```sh
cmake -S . -B build-seal -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON -DBUILD_BENCHMARKS=ON \
  -DLAMINATE_WITH_SEAL=ON
cmake --build build-seal --parallel
ctest --test-dir build-seal --output-on-failure
```

If CMake cannot find SEAL, add
`-DLAMINATE_SEAL_DIR=/path/to/seal/lib/cmake/SEAL-4.1` to the configure command,
using the directory that contains `SEALConfig.cmake`.
On x86-64, the default requires an Intel-HEXL-enabled SEAL build.
The [GCP runbook](docs/GCP_BENCHMARKS.md) gives the complete benchmark toolchain
and host configuration. Workstation checks support Linux and macOS; the
process-separated campaign uses Linux.

## What the protocols do

The client encrypts its inputs and sends them to the server. The server
computes the encrypted output and a proof. The client decrypts the response,
checks the proof, and releases the plaintext output only after acceptance.
The server receives no plaintext output claim.

All three variants compile the payload into alternating affine and
multiplication layers. They differ in how much of GKR they perform under FHE
and how they send its messages to the client.

| Variant | Payload | GKR and proof transport |
| --- | --- | --- |
| Base | Wide SIMD computation, including rotations and slot-varying public operations | Reduces ciphertext indices under FHE and sends the GKR messages directly; the client completes the slot checks |
| Folded | The same Wide computation | Also reduces slot indices under FHE; commits to the GKR messages and proves transcript packing |
| Laned | `B` independent lanes; uniform scalar multiplication and lane-varying plaintext addition | Uses the lane structure to pack witnesses, then proves transcript packing |

The [protocol guide](docs/PROTOCOLS.md) maps each variant to the accompanying
paper and implementation. The [GateMLE module](include/laminate/gates/README.md)
locates affine coefficient preprocessing and openings.

## Benchmarks

The benchmark suite has seven proof-bearing configurations, each with `2^20`
payload operations at ring degree `N=16,384`:

- Base and Folded on `balancedLaned` and `mulHeavyPyramid`;
- Laned on `balancedLaned` with `B=1`, `128`, and `16,384`.

`balancedLaned` has eight equal-width multiplication stages and no cross-slot
operations. `mulHeavyPyramid` has decreasing multiplication widths, rotations,
and slot-varying plaintext multiplication. The
[workload definitions](docs/BENCHMARKING.md#benchmark-workload-scope) give their
exact operation counts. Full-width evaluation covers `2^34` scalar gates;
Laned with `B` active lanes covers `B × 2^20` scalar gates.

Two baselines help interpret the cost: `local` evaluates all scalar coordinates
directly in the client, while `noIntegrity` performs the encrypted payload
computation without a proof. Use the [local runbook](docs/LOCAL_BENCHMARKS.md)
and [GCP runbook](docs/GCP_BENCHMARKS.md) to run them.

The [included reports](bench_outputs/README.md) record measured timings, proof
sizes, verification outcomes, and build provenance. Section 7, “Evaluation,”
of the paper discusses the results. [Benchmarking](docs/BENCHMARKING.md)
defines the measurements; the [cost model](docs/COST_MODEL.md) locates resource
estimates. CTest exercises bounded instances rather than the full-scale runs.

## Read the implementation

Start with the [artifact guide](docs/ARTIFACT_GUIDE.md) for a review path,
[architecture and code map](docs/ARCHITECTURE.md) for entry points and data flow, and
[protocols](docs/PROTOCOLS.md) for the paper-to-code correspondence. The
[source reading guide](include/laminate/README.md) connects public APIs to
implementations and tests.

| Directory | Responsibility |
| --- | --- |
| [payload](include/laminate/payload/README.md) | Payload construction, layering, evaluation, and trace storage |
| [delegation](include/laminate/delegation/README.md) | Client/server lifecycles and message codecs |
| [gkr](include/laminate/gkr/README.md) | Encrypted layer reductions |
| [protocol](include/laminate/protocol/README.md) | Complete Base, Folded, and Laned proofs |
| [packing](include/laminate/packing/README.md) | Alignment, well-formedness tests, and transcript-packing relation |
| [Spartan](include/laminate/spartan/README.md) and [BaseFold](include/laminate/basefold/README.md) | Packing argument and polynomial commitments |
| [benches](benches/README.md) | Benchmark drivers, report tools, and run wrappers |
| [tests](tests/README.md) | Correctness, storage, codec, and integration checks |

The [documentation index](docs/README.md) links parameter reproduction,
security scope, and the relevant paper sections.
