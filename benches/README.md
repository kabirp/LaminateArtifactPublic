# Benchmark executables

This directory contains benchmark drivers and report renderers. Read
[Benchmarking](../docs/BENCHMARKING.md) for evidence labels and
[the GCP runbook](../docs/GCP_BENCHMARKS.md) for the process-separated
real-SEAL workflow. The [local runbook](../docs/LOCAL_BENCHMARKS.md) covers the
scalar baseline. The benchmark guide defines the measurement contract and
explains which quantities are measured, calculated, or projected.

Paths below assume `BUILD_BENCHMARKS=ON`. SEAL programs also require
`LAMINATE_WITH_SEAL=ON`. CTest covers benchmark interfaces and report
contracts; the full target workloads run separately.

## End-to-end drivers

| Executable | Backend | Purpose |
| --- | --- | --- |
| [`laminate_local_payload_bench`](protocol/local_payload_benchmark.cpp) | Scalar `F_65537` | Client-only local baseline: evaluate each payload coordinate and DAG gate serially, with no server, FHE, transport, or integrity claim. |
| [`laminate_protocol_bench`](protocol/protocol_benchmark.cpp) | Mock or SEAL | Bounded, single-process Base/Folded/Laned proof and report rehearsal. |
| [`laminate_no_integrity_bench`](protocol/no_integrity_benchmark.cpp) | SEAL | Process-separated FHE-only payload baseline: one request, bounded file-backed evaluation, one output ciphertext, and explicitly no integrity proof. |
| [`laminate_base_checkpoint_bench`](protocol/base_checkpoint_benchmark.cpp) | SEAL | Process-separated Base setup, client, and server with a real Wide payload and checkpoint/replay GKR. |
| [`laminate_packed_checkpoint_bench`](protocol/packed_checkpoint_benchmark.cpp) | SEAL | Process-separated Folded/Laned setup, client, and server with real FHE payload evaluation, checkpoint/replay GKR, and artifact-backed transcript packing. |
| [`laminate_benchmark_cleanup`](tools/benchmark_cleanup.cpp) | Host | Safely remove inactive sibling runs while preserving the selected run. |

The local executable retains scalar field source and coordinate-major traversal,
but GNU/Clang builds permit compiler vectorization and native x86 instructions.
This does not guarantee vectorization of the gate loop. The
[local runbook](../docs/LOCAL_BENCHMARKS.md) explains the recorded compiler and
CPU-target metadata.

[`prepare_gcp_root_storage.sh`](prepare_gcp_root_storage.sh) non-destructively prepares an owner-only work
tree on the existing root filesystem. [`prepare_gcp_local_ssds.sh`](prepare_gcp_local_ssds.sh) builds a
RAID0 from every attached Google Local SSD, while
[`prepare_gcp_hyperdisk.sh`](prepare_gcp_hyperdisk.sh) locally discovers a dedicated data disk, refuses to
erase existing signatures, and remounts only its labeled Laminate filesystem.
The runner verifies and records the selected backend before every target
phase; [`verify_gcp_storage.sh`](verify_gcp_storage.sh) runs that same read-only check directly.
[`run_gcp.sh`](run_gcp.sh) launches detached roles, follows progress, renders reports,
archives/retires one immutable run, and cleans inactive siblings. The local
and GCP runbooks describe the operator workflows. Alternative storage
helpers are component tools; the GCP guide specifies the storage
configuration for comparable measurements.

Use `run_gcp.sh` for process-separated measurements:

```text
benches/run_gcp.sh ACTION VARIANT PROFILE RUN
benches/run_gcp.sh ACTION laned PROFILE RUN --lanes 1|128|16384
```

The [GCP runbook](../docs/GCP_BENCHMARKS.md#6-select-one-profile-and-variant)
lists the required variant, profile, run selector, and Laned lane count.
[`payload_profile.hpp`](../include/laminate/bench/payload_profile.hpp) defines
workload geometry; [`packed_process_profile.hpp`](../include/laminate/bench/packed_process_profile.hpp)
defines Folded/Laned parameters. Setup admits a capacity plan with fixed
cryptographic parameters, and target runs require zero repeated payload replay.
The `quick` profile is a reduced-security integration check.

## Reports and cost models

| Executable | Backend | Purpose |
| --- | --- | --- |
| [`laminate_target_cost_report`](reports/target_cost_report.cpp) | Host | Circuit geometry, logical/RNS operation counts, proof-size formulas, and verifier work. |
| [`laminate_packing_relation_size_report`](reports/packing_relation_size_report.cpp) | Host | Transcript-packing relation geometry without materializing the target matrix. |
| [`laminate_base_report_summary`](reports/base_report_summary.cpp) | Host | Validate a Base artifact set and render its human report. |
| [`laminate_protocol_report_summary`](reports/protocol_report_summary.cpp) | Host | Validate Folded/Laned reports from the bounded single-process protocol driver. |

The runner's `summary` action validates the detailed evidence with the
variant-specific renderer, then publishes `summary.md` through
[`render_concise_summary.py`](support/render_concise_summary.py).
Process-separated Folded/Laned, noIntegrity, and local reports use
[`render_packed_checkpoint_summary.py`](support/render_packed_checkpoint_summary.py),
[`render_no_integrity_summary.py`](support/render_no_integrity_summary.py), and
[`render_local_payload_summary.py`](support/render_local_payload_summary.py),
respectively. See [report interpretation](../docs/BENCHMARKING.md#reading-the-report)
for timing boundaries, evidence scope, and retained raw records.

## Component measurements

These tools isolate implementation costs. They are not prerequisites for the
artifact runbooks and do not establish end-to-end target performance.

| Executable | Backend | Purpose |
| --- | --- | --- |
| [`laminate_gate_mle_bench`](gates/gate_mle_benchmark.cpp) | Host | Gate-only structural planning, preprocessing, and opening measurements; see the [diagnostic guide](gates/README.md). |
| [`laminate_spartan_scaling_bench`](reports/spartan_scaling_benchmark.cpp) | Host | Spartan-core scaling without matrix authentication. |
| [`laminate_hybrid_tensor_bench`](reports/hybrid_tensor_benchmark.cpp) | Host | Selected factored matrix argument and BaseFold boundary. |
| [`laminate_seal_preprocessing_ownership`](reports/seal_preprocessing_ownership.cpp) | SEAL | Role-bundle construction, serialization, and key sizes. |
| [`laminate_seal_honest_noise_calibration`](reports/seal_honest_noise_calibration.cpp) | SEAL | Secret-key-assisted finite-sample noise diagnostic; not a tail bound. |
| [`laminate_packing_capacity_report`](packing/packing_capacity_report.cpp) | SEAL | Signed-digit packing capacity at the final modulus. |
| [`laminate_outer_relation_rows_bench`](packing/outer_relation_rows_benchmark.cpp) | Host | Sparse outer-relation row generation. |
| [`laminate_outer_relation_assignment_bench`](packing/outer_relation_assignment_benchmark.cpp) | Host | Compact outer-relation assignment construction. |
| [`laminate_outer_relation_packing_matrix_bench`](packing/outer_relation_packing_matrix_benchmark.cpp) | SEAL | Packing-matrix traversal over real SEAL values. |
| [`laminate_laned_payload_bench`](payload/laned_payload_benchmark.cpp) | SEAL | Laned FHE payload evaluation with decrypted-output comparison. |
| [`laminate_plaintext_payload_bench`](payload/plaintext_payload_benchmark.cpp) | Host | Plaintext payload calibration; distinct from the scalar local baseline. |
| [`laminate_payload_storage_bench`](storage/file_trace_store_benchmark.cpp) | Host | Sequential file-trace storage microbenchmark. |
| [`laminate_payload_storage_duplex_bench`](storage/file_trace_store_duplex_benchmark.cpp) | Host | Overlapping source-read/output-write storage microbenchmark. |
| [`laminate_basefold_native_kernels_bench`](reports/basefold_native_kernels_benchmark.cpp) | Host | Native-Fq transform and commitment kernel measurements. |
| [`laminate_basefold_rate_tradeoff_bench`](reports/basefold_rate_tradeoff_benchmark.cpp) | Host | Bounded BaseFold rate/query tradeoff measurement. |
| [`laminate_laned_source_packing_bench`](reports/laned_source_packing_benchmark.cpp) | SEAL | Laned witness-packing kernel measurement. |

## Small examples

Print Base cost formulas for a small Diamond component fixture:

```sh
build/benches/laminate_target_cost_report \
  --protocol base --slots 16384 --depth 4 --width 64
```

The [top-level quick start](../README.md#build-and-run-a-small-proof) runs one
small Mock proof for every variant and saves the machine-readable report.
It is a control-flow check: Mock timing is not FHE performance, and a
diagnostic/capacity result is not selected-target evidence. Principal drivers
expose `--help`; consult their usage output and the source links above for
specialized tools.
