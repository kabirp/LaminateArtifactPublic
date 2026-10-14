# Gate-only diagnostic

[`laminate_gate_mle_bench`](gate_mle_benchmark.cpp) measures GateMLE work without
FHE setup, encryption, or payload evaluation. Build it with `BUILD_BENCHMARKS=ON`; it also works with
`LAMINATE_WITH_SEAL=OFF`.

The default is a tiny structural plan. The target profiles use the same public
payload generators and geometry as the process benchmarks:

```sh
build/benches/laminate_gate_mle_bench --profile target-balancedLaned --mode plan
build/benches/laminate_gate_mle_bench --profile target-mulHeavyPyramid --mode plan
```

Planning reports sparse support, remaining adjoint dimensions, public PCS rows
and columns, and conservative RAM, disk, and proof bounds. It does not build
commitments or authorize their materialization. A `false` admission field in a
plan means that the reported bound exceeds the supplied cap.

Use explicit materializing modes for timing. `preprocess` builds, persists, and
reopens the proving key; `prove` additionally creates and verifies a batch with
one constant and one wiring query per affine layer. `--threads` changes only
commitment preprocessing; proving and verification remain serial.

```sh
build/benches/laminate_gate_mle_bench --profile tiny --mode prove \
  --slots 64 --depth 4 --width 64 --workload diamond \
  --max-ram-bytes 8000000000 --max-disk-bytes 16000000000

build/benches/laminate_gate_mle_bench --profile tiny --mode prove \
  --slots 64 --depth 3 --width 16 --workload mixedActions \
  --max-ram-bytes 8000000000 --max-disk-bytes 16000000000
```

`tiny` permits arbitrary supported slot, depth, and width parameters. Its
workload choices are `diamond`, `fanoutHeavy`, `rotationHeavy`, `deepSnake`, and
`mixedActions`. The last family chains rotations with nonuniform masks to
exercise the retained local-DAG fallback. Named quick/target profiles reject
geometry overrides so their identity remains meaningful.

The materializing modes check their resource caps and available disk before
commitment construction. RAM admission includes retained proving state plus
opening and affine-preparation workspace, which can coexist. Disk admission
includes the source and exported key coexisting during persistence. Defaults
are 1 GiB RAM and 2 GiB disk; the conservative bounds can exceed these even on a modest
example. `--scratch-parent` chooses an existing directory for private temporary
artifacts. Those artifacts are removed on completion or exception.

Each phase reports elapsed seconds and cumulative process peak RSS. Reopen is
measured in the same process immediately after exporting and dropping the
source key, so it is explicitly labeled **warm after export**. It measures the cache
loading path, not cold-device throughput. The report also includes the actual
encoded proof size and verifies transcript agreement. Small examples and
structural target plans do not predict complete target server runtime.
