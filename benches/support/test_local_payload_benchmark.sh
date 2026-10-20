#!/usr/bin/env bash

set -euo pipefail
umask 077

if [[ $# -ne 3 ]]; then
  printf 'usage: %s LOCAL_BENCHMARK LOCAL_SUMMARY_RENDERER CONCISE_RENDERER\n' \
    "$0" >&2
  exit 2
fi

benchmark="$1"
renderer="$2"
concise_renderer="$3"

build_info="$($benchmark build_info)"
for expected in \
  'format=laminate-local-payload-build-info-v1' \
  'benchmark.variant=local' \
  'benchmark.roles=client-only' \
  'environment.field_backend=scalar-fp65537' \
  'environment.vectorization=enabled' \
  'environment.hexl=not-used' \
  'environment.fhe_backend=none' \
  'environment.threading=single-cpu-process' \
  'computation.integrity=not-applicable' \
  'computation.delegation=none' \
  'computation.server=none' \
  'payload.execution=indexed-cross-slot-prefix-then-coordinate-major' \
  'payload.worker_threads=1'; do
  grep -Fqx -- "$expected" <<< "$build_info" || {
    printf 'local payload build_info omitted: %s\n' "$expected" >&2
    exit 1
  }
done
if grep -Eq '^environment\.(seal|sha256)_acceleration=' <<< "$build_info"; then
  printf '%s\n' 'local payload build_info claims an unused accelerator' >&2
  exit 1
fi
if ! grep -Eq '^environment\.architecture=(x86-64|non-x86-64)$' \
    <<< "$build_info"; then
  printf '%s\n' 'local payload build_info omitted its architecture' >&2
  exit 1
fi
if grep -Fqx 'environment.architecture=x86-64' <<< "$build_info"; then
  expected_cpu_target=native
else
  expected_cpu_target=compiler-default
fi
if ! grep -Fqx "environment.cpu_target=$expected_cpu_target" <<< "$build_info"; then
  printf '%s\n' 'local payload build_info has an incorrect CPU target' >&2
  exit 1
fi
"$benchmark" self_test
fixture="$(mktemp -d)"
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/shared/report" "$fixture/client"
touch "$fixture/shared/lifecycle.lock"
chmod 600 "$fixture/shared/lifecycle.lock"

run_id='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
commit='0123456789abcdef0123456789abcdef01234567'

write_common() {
  local destination="$1"
  local cpu="$2"
  printf '%s\n' \
    'run.variant=local' \
    'run.profile=quick' \
    "run.id=$run_id" \
    "environment.git_commit=$commit" \
    'environment.git_dirty=false' \
    'environment.build_type=Release' \
    'environment.compiler=fixture-compiler' \
    'environment.architecture=x86-64' \
    'environment.field_backend=scalar-fp65537' \
    'environment.vectorization=enabled' \
    'environment.cpu_target=native' \
    'environment.hexl=not-used' \
    'environment.fhe_backend=none' \
    'environment.threading=single-cpu-process' \
    "environment.pinned_cpu=$cpu" \
    'environment.os=fixture-os' \
    'environment.cpu=fixture-cpu' \
    'environment.physical_cores=4' \
    'environment.logical_cores=4' \
    'environment.ram_bytes=68719476736' \
    'computation.integrity=not-applicable' \
    'computation.delegation=none' \
    'computation.server=none' \
    'parameters.slots=16384' \
    'parameters.payload_multiplicative_depth=6' \
    'parameters.payload_workload=diamond' \
    'parameters.payload_width=1024' \
    'parameters.payload_inputs=64' \
    'parameters.payload_outputs=1' \
    'parameters.payload_operations=13311' \
    'parameters.payload_add_gates=1023' \
    'parameters.payload_add_plain_gates=6144' \
    'parameters.payload_mul_gates=6144' \
    'parameters.payload_mul_plain_gates=0' \
    'parameters.payload_rotate_gates=0' \
    'parameters.plaintext_modulus=65537' >> "$destination"
}

write_operations() {
  local destination="$1"
  printf '%s\n' \
    'operations.client_local.add.calls=1023' \
    'operations.client_local.add_plain.calls=6144' \
    'operations.client_local.mul.calls=6144' \
    'operations.client_local.mul_plain.calls=0' \
    'operations.client_local.rotate.calls=0' \
    'operations.client_local.scalar_additions=117424128' \
    'operations.client_local.scalar_multiplications=100663296' \
    'operations.client_local.scalar_total=218087424' >> "$destination"
}

printf '%s\n' \
  'format=laminate-benchmark-run-v1' \
  'run.variant=local' \
  'run.profile=quick' \
  "run.id=$run_id" > "$fixture/shared/run-binding.txt"

printf '%s\n' \
  'format=laminate-local-payload-setup-v1' \
  'run.variant=local' \
  'run.profile=quick' \
  "run.id=$run_id" \
  "environment.git_commit=$commit" \
  'environment.build_type=Release' \
  'environment.compiler=fixture-compiler' \
  'payload.circuit_fingerprint=123' \
  'parameters.slots=16384' \
  'parameters.payload_multiplicative_depth=6' \
  'parameters.payload_width=1024' \
  'parameters.payload_inputs=64' \
  'parameters.payload_outputs=1' \
  'parameters.payload_operations=13311' \
  'parameters.payload_add_gates=1023' \
  'parameters.payload_add_plain_gates=6144' \
  'parameters.payload_mul_gates=6144' \
  'parameters.payload_mul_plain_gates=0' \
  'parameters.payload_rotate_gates=0' \
  'memory.client.scalar_wire_bytes=107000' \
  'memory.client.cross_slot_workspace_bytes=0' \
  'memory.client.input_bytes=8388608' \
  'memory.client.output_bytes=131072' \
  'memory.client.circuit_bytes=425960' \
  'memory.client.admitted_peak_resident_bytes=1000000000' \
  > "$fixture/shared/setup.bin"

setup="$fixture/shared/setup-result.txt"
printf '%s\n' 'format=laminate-benchmark-setup-v1' > "$setup"
write_common "$setup" 0
write_operations "$setup"
printf '%s\n' \
  'benchmark.intent=client-local-scalar-payload-evaluation' \
  'timing.setup.construct_payload.wall_ms=10' \
  'timing.setup.construct_payload.cpu_ms=9' \
  'timing.setup.process_total.wall_ms=15' \
  'timing.setup.process_total.cpu_ms=13' \
  'memory.client.scalar_wire_bytes=107000' \
  'memory.client.cross_slot_workspace_bytes=0' \
  'memory.client.input_bytes=8388608' \
  'memory.client.output_bytes=131072' \
  'memory.client.circuit_bytes=425960' \
  'memory.client.admitted_peak_resident_bytes=1000000000' \
  'environment.command=fixture setup' \
  'setup.result=PASS' >> "$setup"

client="$fixture/client/result.txt"
printf '%s\n' 'format=laminate-local-payload-client-v1' > "$client"
write_common "$client" 1
write_operations "$client"
printf '%s\n' \
  'timing.client.construct_payload.wall_ms=100' \
  'timing.client.construct_payload.cpu_ms=90' \
  'timing.client.construct_inputs.wall_ms=50' \
  'timing.client.construct_inputs.cpu_ms=45' \
  'timing.client.local_payload_evaluation.wall_ms=1000' \
  'timing.client.local_payload_evaluation.cpu_ms=990' \
  'timing.client.output_checksum.wall_ms=5' \
  'timing.client.output_checksum.cpu_ms=5' \
  'timing.client.process_total.wall_ms=1200' \
  'timing.client.process_total.cpu_ms=1150' \
  'output.values=16384' \
  'output.checksum=42' \
  'memory.client.peak_rss_bytes=100000000' \
  'environment.command=fixture client' \
  'client.result=PASS' >> "$client"

printf '%s\n' 'process.exit_status=0' \
  > "$fixture/shared/setup-process-exit.txt"
printf '%s\n' 'process.exit_status=0' \
  > "$fixture/client/process-exit.txt"

output="$fixture/shared/report/summary.md"
for pass in 1 2; do
  python3 "$renderer" --run-dir "$fixture" --variant local \
    --profile quick --output "$output"
done

for expected in \
  '<!-- laminate-local-payload-summary-v1 -->' \
  '# Local payload benchmark' \
  'There was no server, transport, ciphertext, FHE backend, or computation-integrity protocol.' \
  '| Computation location | client only; no server |' \
  '| Total scalar F_t operations | 218,087,424 |' \
  '| Evaluation order | one coordinate at a time; one scalar DAG gate at a time |' \
  '| Client local payload evaluation | **1.000 s wall**, 0.990 s CPU; 99.0% CPU/wall |' \
  'Client runtime breakdown' \
  'Scalar operation ledger' \
  '| AddPlain | 6,144 | 100,663,296 |' \
  '| Mul | 6,144 | 100,663,296 |' \
  'Memory and execution model' \
  '| One-coordinate scalar wire buffer | 104.49 KiB |' \
  '| Resident circuit representation | 415.98 KiB |' \
  '| Arithmetic backend | scalar F_65537; compiler vectorization enabled; HEXL not used |' \
  '| Compiler CPU target | native |' \
  '| Compiler vectorization / external accelerator | enabled / none |' \
  'not an independent correctness oracle'; do
  grep -Fq -- "$expected" "$output" || {
    printf 'local payload summary omitted: %s\n' "$expected" >&2
    exit 1
  }
done

concise_output="$fixture/concise-summary.md"
python3 "$concise_renderer" \
  --input "$output" --output "$concise_output" \
  --run-dir "$fixture" \
  --variant local --profile quick
for expected in \
  '<!-- laminate-benchmark-summary-v2 -->' \
  '| Laminate variant | local |' \
  '| Payload profile | `quick` |' \
  '| Scalar gates | 218,087,424 |' \
  '| Plaintext modulus | 65,537 |' \
  '| Client-local payload evaluation | 1.000 s |' \
  '| VCoED server wall time | not applicable |' \
  '| Proof verification | not applicable |' \
  '## Scalar operation ledger' \
  '## Memory and storage' \
  '| Compiler vectorization / external accelerator | enabled / none |' \
  '| Compiler CPU target | native |' \
  '## Provenance'; do
  grep -Fq -- "$expected" "$concise_output" || {
    printf 'concise local payload summary omitted: %s\n' "$expected" >&2
    exit 1
  }
done
for forbidden in \
  'Client runtime breakdown' \
  'Client process total' \
  'Git commit' \
  'Process exits' \
  'FHE backend' \
  'Arithmetic backend' \
  'Exact data-prime schedule' \
  'q0=' \
  'Setup wall time' \
  'Run ID' \
  'Exact role commands' \
  'summary.csv'; do
  if grep -Fq -- "$forbidden" "$concise_output"; then
    printf 'concise local payload summary retained: %s\n' "$forbidden" >&2
    exit 1
  fi
done
for report in "$output" "$concise_output"; do
  if grep -Fq 'OLD / STALE REPORT' "$report"; then
    printf '%s\n' 'current quick baseline incorrectly marked stale' >&2
    exit 1
  fi
done

test ! -e "$fixture/shared/report/summary.csv"

status_output="$($benchmark status --variant local --profile quick \
  --run-dir "$fixture")"
grep -Fq -- 'server: not applicable (never started)' <<< "$status_output"
grep -Fq -- 'COMPLETE: the client evaluated the complete payload locally.' \
  <<< "$status_output"
if "$benchmark" status --variant local --profile target-balancedLaned \
    --run-dir "$fixture" >/dev/null 2>&1; then
  printf '%s\n' 'Local status accepted a wrong-profile selector' >&2
  exit 1
fi
for required in shared/setup.bin shared/run-binding.txt; do
  mv "$fixture/$required" "$fixture/$required.bak"
  if "$benchmark" status --variant local --profile quick \
      --run-dir "$fixture" >/dev/null 2>&1; then
    printf 'Local status accepted completed setup without %s\n' \
      "$required" >&2
    exit 1
  fi
  mv "$fixture/$required.bak" "$fixture/$required"
done
mkdir "$fixture/server"
if "$benchmark" status --variant local --profile quick \
    --run-dir "$fixture" >/dev/null 2>&1; then
  printf '%s\n' 'Local status accepted an unexpected server role' >&2
  exit 1
fi
rmdir "$fixture/server"

contaminated="$fixture/contaminated"
mkdir -p "$contaminated/shared" "$contaminated/client" \
  "$contaminated/server"
touch "$contaminated/shared/lifecycle.lock"
chmod 600 "$contaminated/shared/lifecycle.lock"
printf '%s\n' 'setup.result=PASS' \
  > "$contaminated/shared/setup-result.txt"
printf '%s\n' 'process.exit_status=0' \
  > "$contaminated/shared/setup-process-exit.txt"
if "$benchmark" run_client --variant local --profile quick \
    --run-dir "$contaminated" \
    > "$contaminated/client/launch.log" 2>&1; then
  printf '%s\n' \
    'Local client started despite an unexpected server role' >&2
  exit 1
fi
grep -Fq -- \
  'Local runs must not contain a server role or request/response transcript' \
  "$contaminated/client/launch.log"
for forbidden in activity.jsonl progress.jsonl result.txt; do
  if [[ -e "$contaminated/client/$forbidden" ]]; then
    printf 'Contaminated Local client created %s before rejection\n' \
      "$forbidden" >&2
    exit 1
  fi
done

sed -i.bak \
  's/operations.client_local.scalar_total=218087424/operations.client_local.scalar_total=218087423/' \
  "$client"
if python3 "$renderer" --run-dir "$fixture" --variant local \
    --profile quick --output "$output" 2>/dev/null; then
  printf '%s\n' 'renderer accepted an incorrect scalar-operation total' >&2
  exit 1
fi
mv "$client.bak" "$client"

sed -i.bak \
  's/memory.client.circuit_bytes=425960/memory.client.circuit_bytes=0/' \
  "$setup"
if python3 "$renderer" --run-dir "$fixture" --variant local \
  --profile quick --output "$output" 2>/dev/null; then
  printf '%s\n' 'renderer accepted an empty resident circuit footprint' >&2
  exit 1
fi
mv "$setup.bak" "$setup"

sed -i.bak 's/environment.vectorization=enabled/environment.vectorization=disabled/' \
  "$setup"
if python3 "$renderer" --run-dir "$fixture" --variant local \
    --profile quick --output "$output" 2>/dev/null; then
  printf '%s\n' 'renderer accepted mismatched vectorization policies' >&2
  exit 1
fi
mv "$setup.bak" "$setup"

# Optimized records require a supported CPU target in both roles.
for mutation in \
    's/environment.cpu_target=native/environment.cpu_target=compiler-default/' \
    '/^environment.cpu_target=/d' \
    's/environment.vectorization=enabled/environment.vectorization=unknown/'; do
  for record in "$setup" "$client"; do
    cp "$record" "$record.current"
    sed "$mutation" "$record.current" > "$record"
  done
  if python3 "$renderer" --run-dir "$fixture" --variant local \
      --profile quick --output "$output" 2>/dev/null; then
    printf 'renderer accepted invalid optimized metadata: %s\n' "$mutation" >&2
    exit 1
  fi
  for record in "$setup" "$client"; do
    mv "$record.current" "$record"
  done
done
sed -i.bak 's/environment.cpu_target=native/environment.cpu_target=compiler-default/' \
  "$client"
if python3 "$renderer" --run-dir "$fixture" --variant local \
    --profile quick --output "$output" 2>/dev/null; then
  printf '%s\n' 'renderer accepted mismatched CPU targets' >&2
  exit 1
fi
mv "$client.bak" "$client"

mkdir "$fixture/server"
if python3 "$renderer" --run-dir "$fixture" --variant local \
    --profile quick --output "$output" 2>/dev/null; then
  printf '%s\n' 'renderer accepted a local run with a server role directory' >&2
  exit 1
fi
rmdir "$fixture/server"

printf '%s\n' 'process.exit_status=1' \
  > "$fixture/client/process-exit.txt"
if python3 "$renderer" --run-dir "$fixture" --variant local \
    --profile quick --output "$output" 2>/dev/null; then
  printf '%s\n' 'renderer accepted a failed client wrapper' >&2
  exit 1
fi

if compgen -G "$fixture/shared/report/.local-payload-summary-*" >/dev/null; then
  printf '%s\n' 'renderer left a temporary summary artifact' >&2
  exit 1
fi

python3 - "$renderer" "$fixture" <<'PY'
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(sys.argv[1]).resolve().parent))
import render_local_payload_summary as renderer
import render_concise_summary as concise
from render_payload_profiles import PROFILE_GEOMETRY

source = Path(sys.argv[2])

def write_record(path, values):
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))

def expect_rejected(run, profile, message):
    try:
        renderer.render(run, profile)
    except renderer.ReportError as error:
        assert message in str(error), error
    else:
        raise AssertionError(f"accepted invalid record: {message}")

for profile, geometry in PROFILE_GEOMETRY.items():
    run = source / (profile + "-" + str(geometry["workload"]))
    for role in ("shared", "client"):
        shutil.copytree(source / role, run / role)
    write_record(run / "client/process-exit.txt", {"process.exit_status": 0})
    binding_path = run / "shared/run-binding.txt"
    binding = renderer.parse_record(binding_path)
    binding["run.profile"] = profile
    write_record(binding_path, binding)
    paths = (run / "shared/setup-result.txt", run / "client/result.txt")
    for path in paths:
        record = renderer.parse_record(path)
        record.update({
            "run.profile": profile,
            "parameters.payload_workload": geometry["workload"],
            "parameters.payload_multiplicative_depth": geometry["depth"],
            "parameters.payload_width": geometry["width"],
            "parameters.payload_operations": geometry["operations"],
            "operations.client_local.scalar_additions":
                16_384 * (geometry["add"] + geometry["add_plain"]),
            "operations.client_local.scalar_multiplications":
                16_384 * (geometry["mul"] + geometry["mul_plain"]),
            "operations.client_local.scalar_rotation_copies":
                16_384 * geometry["rotate"],
            "operations.client_local.scalar_total": 16_384 * geometry["operations"],
            "memory.client.scalar_wire_bytes": 8 * (64 + geometry["operations"]),
            "memory.client.cross_slot_workspace_bytes":
                16_777_216 if geometry["rotate"] else 0,
            "memory.client.admitted_peak_resident_bytes": 1_000_000_000,
        })
        for kind in ("add", "add_plain", "mul", "mul_plain", "rotate"):
            record[f"parameters.payload_{kind}_gates"] = geometry[kind]
            record[f"operations.client_local.{kind}.calls"] = geometry[kind]
        if path == paths[1]:
            # The producer emits the memory plan in setup, and only RSS in client.
            for key in tuple(record):
                if key.startswith("memory.client.") and key != "memory.client.peak_rss_bytes":
                    del record[key]
        write_record(path, record)
    workspace_key = "memory.client.cross_slot_workspace_bytes"
    legacy_records = tuple(renderer.parse_record(path) for path in paths)
    assert workspace_key in legacy_records[0]
    assert workspace_key not in legacy_records[1]

    # Preserve records produced before indexed permutation views were introduced.
    legacy_rendered = renderer.render(run, profile)
    assert f"`{geometry['workload']}`" in legacy_rendered
    if geometry["rotate"]:
        assert "| Scalar rotation copies | 429,490,176 |" in legacy_rendered
        assert "| Total scalar F_t operations | 16,750,379,008 |" in legacy_rendered
        assert "| Total scalar gate operations | 17,179,869,184 |" in legacy_rendered
        for invalid_value in (None, 0):
            invalid_setup = dict(legacy_records[0])
            if invalid_value is None:
                del invalid_setup[workspace_key]
                expected_error = f"setup is missing {workspace_key}"
            else:
                invalid_setup[workspace_key] = invalid_value
                expected_error = "cross-slot workspace disagrees with rotation work"
            write_record(paths[0], invalid_setup)
            expect_rejected(run, profile, expected_error)
        write_record(paths[0], legacy_records[0])

    permutation_key = "operations.client_local.scalar_permutation_wires"
    rotation_key = "operations.client_local.scalar_rotation_copies"
    total_key = "operations.client_local.scalar_total"
    execution_key = "payload.execution"
    indexed_records = tuple(dict(record) for record in legacy_records)
    for path, record in zip(paths, indexed_records):
        record.update({
            execution_key: renderer.INDEXED_EXECUTION,
            permutation_key: str(16_384 * geometry["rotate"]),
            rotation_key: "0",
        })
        write_record(path, record)
    rendered = renderer.render(run, profile)
    assert "| Indexed views and arithmetic prefix workspace |" in rendered
    assert f"| Semantic scalar permutation wiring | {16_384 * geometry['rotate']:,} |" in rendered
    assert "| Materialized scalar rotation copies | 0 |" in rendered
    field_operations = 16_384 * (geometry["operations"] - geometry["rotate"])
    assert f"| Total scalar F_t operations | {field_operations:,} |" in rendered
    assert f"| Rotate | {geometry['rotate']:,} | 0 |" in rendered
    if geometry["rotate"]:
        assert "| Scalar rotation copies | 0 |" in rendered
        assert "| Total scalar gate operations | 17,179,869,184 |" in rendered
        assert "indexed permutation views and arithmetic prefix" in rendered
    concise_lines = concise.local_summary(rendered.splitlines(), None)
    concise_text = "\n".join(concise_lines)
    assert "| Materialized scalar rotation copies | 0 |" in concise_text
    assert "| Indexed views and arithmetic prefix workspace |" in concise_text

    def restore_indexed():
        for path, record in zip(paths, indexed_records):
            write_record(path, record)

    # Optional duplicated workspace must agree, while real setup-only records pass.
    matching_client = dict(indexed_records[1])
    matching_client[workspace_key] = indexed_records[0][workspace_key]
    write_record(paths[1], matching_client)
    assert renderer.render(run, profile) == rendered
    matching_client[workspace_key] = int(indexed_records[0][workspace_key]) + 1
    write_record(paths[1], matching_client)
    expect_rejected(run, profile, "setup/client disagree on cross-slot workspace")
    restore_indexed()

    missing_workspace = dict(indexed_records[0])
    del missing_workspace[workspace_key]
    write_record(paths[0], missing_workspace)
    expect_rejected(run, profile, f"setup is missing {workspace_key}")
    restore_indexed()

    # Workspace is a separately admitted plan, not inferred from permutation count.
    zero_workspace = dict(indexed_records[0])
    zero_workspace[workspace_key] = 0
    write_record(paths[0], zero_workspace)
    assert "| Indexed views and arithmetic prefix workspace | 0 B |" in renderer.render(run, profile)
    restore_indexed()

    # Agreement between roles is insufficient: the selected model and DAG ledger
    # independently constrain copies, semantic wiring, arithmetic, and totals.
    for key, bad_value, error in (
        (rotation_key, "1", "client scalar F_t operation ledger is inconsistent"),
        (permutation_key, str(16_384 * geometry["rotate"] + 1),
         "client scalar permutation wiring ledger is inconsistent"),
        (total_key, "0", "client scalar F_t operation ledger is inconsistent"),
        ("operations.client_local.scalar_multiplications", "0",
         "client scalar F_t operation ledger is inconsistent"),
        (execution_key, "unknown", "local benchmark has an unknown execution model"),
        (execution_key, renderer.LEGACY_EXECUTION,
         "permutation wiring requires the indexed execution model"),
    ):
        for path, original in zip(paths, indexed_records):
            changed = dict(original)
            changed[key] = bad_value
            write_record(path, changed)
        expect_rejected(run, profile, error)
        restore_indexed()
    for key in (rotation_key, permutation_key, execution_key):
        changed_client = dict(indexed_records[1])
        del changed_client[key]
        write_record(paths[1], changed_client)
        expect_rejected(run, profile, f"client is missing {key}")
        restore_indexed()

    # New metadata never makes failed computation acceptable.
    changed_client = dict(indexed_records[1])
    changed_client["client.result"] = "FAIL"
    write_record(paths[1], changed_client)
    expect_rejected(run, profile, "local client computation did not pass")
    restore_indexed()
    assert renderer.render(run, profile) == rendered

PY

printf '%s\n' 'local payload benchmark reporting: PASS'
