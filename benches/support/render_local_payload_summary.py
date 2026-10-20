#!/usr/bin/env python3
"""Validate and render one completed client-local payload benchmark run."""

from __future__ import annotations

import argparse
import fcntl
import math
import os
from pathlib import Path
import re
import stat
import tempfile

from render_payload_profiles import (
    PROFILE_GEOMETRY, is_budgeted_workload, profile_geometry,
)


class ReportError(RuntimeError):
    """A local-payload run cannot be certified or rendered."""


SLOTS = 16_384
INPUTS = 64
OUTPUTS = 1
PLAINTEXT_MODULUS = 65_537
FIELD_BYTES = 8
DERIVED_TIMING_TOLERANCE_MS = 0.001
LEGACY_EXECUTION = "cross-slot-prefix-then-coordinate-major"
INDEXED_EXECUTION = "indexed-cross-slot-prefix-then-coordinate-major"

IDENTITY_KEYS = (
    "run.variant",
    "run.profile",
    "run.id",
    "environment.git_commit",
    "environment.git_dirty",
    "environment.build_type",
    "environment.compiler",
    "environment.architecture",
    "environment.field_backend",
    "environment.vectorization",
    "environment.hexl",
    "environment.fhe_backend",
    "environment.threading",
    "environment.os",
    "environment.cpu",
    "environment.physical_cores",
    "environment.logical_cores",
    "environment.ram_bytes",
    "computation.integrity",
    "computation.delegation",
    "computation.server",
)

GEOMETRY_KEYS = (
    "parameters.slots",
    "parameters.payload_multiplicative_depth",
    "parameters.payload_workload",
    "parameters.payload_width",
    "parameters.payload_inputs",
    "parameters.payload_outputs",
    "parameters.payload_operations",
    "parameters.payload_add_gates",
    "parameters.payload_add_plain_gates",
    "parameters.payload_mul_gates",
    "parameters.payload_mul_plain_gates",
    "parameters.payload_rotate_gates",
    "parameters.plaintext_modulus",
)

OPERATION_KEYS = (
    "operations.client_local.add.calls",
    "operations.client_local.add_plain.calls",
    "operations.client_local.mul.calls",
    "operations.client_local.mul_plain.calls",
    "operations.client_local.rotate.calls",
    "operations.client_local.scalar_additions",
    "operations.client_local.scalar_multiplications",
    "operations.client_local.scalar_total",
)


def parse_record(path: Path) -> dict[str, str]:
    try:
        metadata = os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode):
            raise ReportError(f"record is not a regular file: {path}")
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ReportError(f"cannot read {path}: {error}") from error

    result: dict[str, str] = {}
    for line_number, line in enumerate(lines, 1):
        if not line or "=" not in line:
            raise ReportError(f"{path}:{line_number}: expected key=value")
        key, value = line.split("=", 1)
        if not key or key in result:
            raise ReportError(f"{path}:{line_number}: duplicate or empty key")
        result[key] = value
    return result


def require(record: dict[str, str], key: str, source: str) -> str:
    try:
        return record[key]
    except KeyError as error:
        raise ReportError(f"{source} is missing {key}") from error


def integer(record: dict[str, str], key: str, source: str) -> int:
    value = require(record, key, source)
    try:
        result = int(value)
    except ValueError as error:
        raise ReportError(f"{source} has non-integer {key}={value!r}") from error
    if result < 0 or str(result) != value:
        raise ReportError(f"{source} has non-canonical {key}={value!r}")
    return result


def number(record: dict[str, str], key: str, source: str) -> float:
    value = require(record, key, source)
    try:
        result = float(value)
    except ValueError as error:
        raise ReportError(f"{source} has non-numeric {key}={value!r}") from error
    if not math.isfinite(result) or result < 0:
        raise ReportError(f"{source} has invalid {key}={value!r}")
    return result


def timing(record: dict[str, str], prefix: str, source: str) -> tuple[float, float]:
    wall = number(record, f"{prefix}.wall_ms", source)
    cpu = number(record, f"{prefix}.cpu_ms", source)
    return wall, cpu


def require_exit_zero(path: Path) -> None:
    if parse_record(path) != {"process.exit_status": "0"}:
        raise ReportError(f"{path} is not the canonical zero-exit record")


def same_fields(
    records: tuple[dict[str, str], ...],
    keys: tuple[str, ...],
    labels: tuple[str, ...],
) -> None:
    for key in keys:
        values = [
            require(record, key, label)
            for record, label in zip(records, labels, strict=True)
        ]
        if len(set(values)) != 1:
            raise ReportError(f"completed role records disagree on {key}")


def require_absent(path: Path, description: str) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise ReportError(f"cannot inspect {path}: {error}") from error
    raise ReportError(f"local benchmark must not contain {description}: {path}")


def elapsed(value_ms: float) -> str:
    seconds = value_ms / 1_000.0
    if seconds < 60:
        return f"{seconds:.3f} s"
    minutes = seconds / 60.0
    if minutes < 60:
        return f"{minutes:.2f} min"
    return f"{minutes / 60.0:.2f} h"


def bytes_text(value: int) -> str:
    amount = float(value)
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024.0 or suffix == "TiB":
            if suffix == "B":
                return f"{value:,} B"
            return f"{amount:.2f} {suffix}"
        amount /= 1024.0
    raise AssertionError("unreachable")


def utilization(cpu_ms: float, wall_ms: float) -> str:
    return "n/a" if wall_ms == 0 else f"{100.0 * cpu_ms / wall_ms:.1f}%"


def timing_row(label: str, measured: tuple[float, float]) -> str:
    wall, cpu = measured
    return (
        f"| {label} | {elapsed(wall)} | {elapsed(cpu)} | "
        f"{utilization(cpu, wall)} |"
    )


def validate_profile_geometry(
    record: dict[str, str], profile: str, source: str
) -> dict[str, int | str]:
    try:
        expected = profile_geometry(
            profile, require(record, "parameters.payload_workload", source)
        )
    except ValueError as error:
        raise ReportError(str(error)) from error
    checks = {
        "parameters.slots": SLOTS,
        "parameters.payload_multiplicative_depth": expected["depth"],
        "parameters.payload_width": expected["width"],
        "parameters.payload_inputs": INPUTS,
        "parameters.payload_outputs": OUTPUTS,
        "parameters.payload_operations": expected["operations"],
        "parameters.payload_add_gates": expected["add"],
        "parameters.payload_add_plain_gates": expected["add_plain"],
        "parameters.payload_mul_gates": expected["mul"],
        "parameters.payload_mul_plain_gates": expected["mul_plain"],
        "parameters.payload_rotate_gates": expected["rotate"],
        "parameters.plaintext_modulus": PLAINTEXT_MODULUS,
    }
    for key, expected_value in checks.items():
        if integer(record, key, source) != expected_value:
            raise ReportError(f"{source} has unexpected {key}")
    if require(record, "parameters.payload_workload", source) != expected["workload"]:
        raise ReportError(f"{source} has the wrong payload workload")
    return expected


def render(run: Path, profile: str) -> str:
    binding = parse_record(run / "shared" / "run-binding.txt")
    setup = parse_record(run / "shared" / "setup-result.txt")
    client = parse_record(run / "client" / "result.txt")
    require_exit_zero(run / "shared" / "setup-process-exit.txt")
    require_exit_zero(run / "client" / "process-exit.txt")

    if binding != {
        "format": "laminate-benchmark-run-v1",
        "run.variant": "local",
        "run.profile": profile,
        "run.id": require(binding, "run.id", "run binding"),
    }:
        raise ReportError("run-binding.txt is not the exact local binding")
    if not re.fullmatch(r"[0-9a-f]{64}", binding["run.id"]):
        raise ReportError("run binding has an invalid run id")
    if require(setup, "format", "setup") != "laminate-benchmark-setup-v1":
        raise ReportError("setup has an unsupported format")
    if require(client, "format", "client") != "laminate-local-payload-client-v1":
        raise ReportError("client has an unsupported format")
    if require(setup, "setup.result", "setup") != "PASS":
        raise ReportError("setup did not pass")
    if require(client, "client.result", "client") != "PASS":
        raise ReportError("local client computation did not pass")

    records = (setup, client)
    labels = ("setup", "client")
    same_fields(records, IDENTITY_KEYS + GEOMETRY_KEYS + OPERATION_KEYS, labels)
    execution_key = "payload.execution"
    if any(execution_key in record for record in records):
        same_fields(records, (execution_key,), labels)
    execution = setup.get(execution_key, LEGACY_EXECUTION)
    if execution not in (LEGACY_EXECUTION, INDEXED_EXECUTION):
        raise ReportError("local benchmark has an unknown execution model")
    indexed_permutations = execution == INDEXED_EXECUTION
    rotation_key = "operations.client_local.scalar_rotation_copies"
    if indexed_permutations or any(rotation_key in record for record in records):
        same_fields(records, (rotation_key,), labels)
    permutation_key = "operations.client_local.scalar_permutation_wires"
    if indexed_permutations:
        same_fields(records, (permutation_key,), labels)
    elif any(permutation_key in record for record in records):
        raise ReportError("permutation wiring requires the indexed execution model")
    if (
        setup["run.variant"] != "local"
        or setup["run.profile"] != profile
        or setup["run.id"] != binding["run.id"]
    ):
        raise ReportError("role identity differs from the selected run")
    if setup["environment.git_dirty"] != "false":
        raise ReportError("measurement was built from a dirty tree")
    if setup["environment.build_type"] != "Release":
        raise ReportError("measurement was not a Release build")
    if setup["environment.architecture"] != "x86-64":
        raise ReportError("measurement was not produced on x86-64")
    if setup["environment.field_backend"] != "scalar-fp65537":
        raise ReportError("local benchmark did not use the scalar F_t backend")
    vectorization = setup["environment.vectorization"]
    if vectorization not in ("enabled", "disabled"):
        raise ReportError("local benchmark has an unknown vectorization policy")
    # The CPU target is part of the measured build configuration.
    cpu_target = require(setup, "environment.cpu_target", "setup")
    if cpu_target != client.get("environment.cpu_target"):
        raise ReportError("completed role records disagree on environment.cpu_target")
    if vectorization == "enabled" and cpu_target != "native":
        raise ReportError("vectorization-enabled x86-64 measurement must target native CPU")
    if cpu_target is not None and cpu_target not in ("native", "compiler-default"):
        raise ReportError("local benchmark has an unknown CPU target")
    if setup["environment.hexl"] != "not-used":
        raise ReportError("local benchmark claims HEXL use")
    if setup["environment.fhe_backend"] != "none":
        raise ReportError("local benchmark claims an FHE backend")
    if setup["environment.threading"] != "single-cpu-process":
        raise ReportError("local benchmark is not single-threaded")
    if (
        setup["computation.integrity"] != "not-applicable"
        or setup["computation.delegation"] != "none"
        or setup["computation.server"] != "none"
    ):
        raise ReportError("local benchmark claims delegation, a server, or integrity")
    if setup.get("benchmark.intent") != "client-local-scalar-payload-evaluation":
        raise ReportError("setup has the wrong benchmark intent")

    expected = validate_profile_geometry(setup, profile, "setup")
    validate_profile_geometry(client, profile, "client")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", setup["environment.git_commit"]):
        raise ReportError("measurement has an invalid Git revision")

    setup_cpu = integer(setup, "environment.pinned_cpu", "setup")
    client_cpu = integer(client, "environment.pinned_cpu", "client")

    require_absent(run / "server", "a server role directory")
    require_absent(run / "shared" / "transcript", "transport artifacts")

    add_calls = integer(client, "operations.client_local.add.calls", "client")
    add_plain_calls = integer(
        client, "operations.client_local.add_plain.calls", "client"
    )
    mul_calls = integer(client, "operations.client_local.mul.calls", "client")
    mul_plain_calls = integer(
        client, "operations.client_local.mul_plain.calls", "client"
    )
    rotate_calls = integer(
        client, "operations.client_local.rotate.calls", "client"
    )
    expected_calls = (
        int(expected["add"]),
        int(expected["add_plain"]),
        int(expected["mul"]),
        int(expected["mul_plain"]),
        int(expected["rotate"]),
    )
    if (
        add_calls,
        add_plain_calls,
        mul_calls,
        mul_plain_calls,
        rotate_calls,
    ) != expected_calls:
        raise ReportError("client DAG-gate operation ledger is inconsistent")

    scalar_additions = integer(
        client, "operations.client_local.scalar_additions", "client"
    )
    scalar_multiplications = integer(
        client, "operations.client_local.scalar_multiplications", "client"
    )
    scalar_total = integer(
        client, "operations.client_local.scalar_total", "client"
    )
    expected_scalar_additions = SLOTS * (add_calls + add_plain_calls)
    expected_scalar_multiplications = SLOTS * (mul_calls + mul_plain_calls)
    scalar_permutation_wires = SLOTS * rotate_calls
    if indexed_permutations and integer(
        client, permutation_key, "client"
    ) != scalar_permutation_wires:
        raise ReportError("client scalar permutation wiring ledger is inconsistent")
    expected_rotation_copies = 0 if indexed_permutations else scalar_permutation_wires
    rotation_key = "operations.client_local.scalar_rotation_copies"
    rotation_copies = (
        integer(client, rotation_key, "client")
        if indexed_permutations or rotation_key in client
        or is_budgeted_workload(str(expected["workload"]))
        else 0
    )
    expected_scalar_total = SLOTS * int(expected["operations"])
    if (
        scalar_additions != expected_scalar_additions
        or scalar_multiplications != expected_scalar_multiplications
        or scalar_total != expected_scalar_total
        or rotation_copies != expected_rotation_copies
        or scalar_total != scalar_additions + scalar_multiplications + scalar_permutation_wires
    ):
        raise ReportError("client scalar F_t operation ledger is inconsistent")

    scalar_wire_bytes = integer(
        setup, "memory.client.scalar_wire_bytes", "setup"
    )
    workspace_key = "memory.client.cross_slot_workspace_bytes"
    cross_slot_workspace = 0
    if indexed_permutations or workspace_key in setup or workspace_key in client or rotate_calls:
        cross_slot_workspace = integer(setup, workspace_key, "setup")
        if workspace_key in client and cross_slot_workspace != integer(
            client, workspace_key, "client"
        ):
            raise ReportError("setup/client disagree on cross-slot workspace")
    if not indexed_permutations and bool(cross_slot_workspace) != bool(rotate_calls):
        raise ReportError("cross-slot workspace disagrees with rotation work")
    input_bytes = integer(setup, "memory.client.input_bytes", "setup")
    output_bytes = integer(setup, "memory.client.output_bytes", "setup")
    circuit_bytes = integer(setup, "memory.client.circuit_bytes", "setup")
    admitted_peak = integer(
        setup, "memory.client.admitted_peak_resident_bytes", "setup"
    )
    peak_rss = integer(client, "memory.client.peak_rss_bytes", "client")
    if scalar_wire_bytes != (INPUTS + int(expected["operations"])) * FIELD_BYTES:
        raise ReportError("setup has the wrong coordinate-local wire footprint")
    if input_bytes != INPUTS * SLOTS * FIELD_BYTES:
        raise ReportError("setup has the wrong deterministic-input footprint")
    if output_bytes != OUTPUTS * SLOTS * FIELD_BYTES:
        raise ReportError("setup has the wrong output footprint")
    if circuit_bytes == 0:
        raise ReportError("setup has an empty resident circuit footprint")
    if admitted_peak < (
        scalar_wire_bytes + cross_slot_workspace + input_bytes + output_bytes + circuit_bytes
    ):
        raise ReportError("setup resident admission omits required local buffers")
    if peak_rss > admitted_peak:
        raise ReportError("client peak RSS exceeds setup resident admission")

    output_values = integer(client, "output.values", "client")
    output_checksum = integer(client, "output.checksum", "client")
    if output_values != OUTPUTS * SLOTS:
        raise ReportError("client output value count is inconsistent")

    setup_construct = timing(setup, "timing.setup.construct_payload", "setup")
    setup_total = timing(setup, "timing.setup.process_total", "setup")
    client_construct = timing(
        client, "timing.client.construct_payload", "client"
    )
    client_inputs = timing(client, "timing.client.construct_inputs", "client")
    evaluation = timing(
        client, "timing.client.local_payload_evaluation", "client"
    )
    checksum = timing(client, "timing.client.output_checksum", "client")
    client_total = timing(client, "timing.client.process_total", "client")
    if evaluation[0] == 0:
        raise ReportError("client reported a zero-duration payload evaluation")
    client_leaf_wall = sum(
        value[0] for value in (client_construct, client_inputs, evaluation, checksum)
    )
    client_leaf_cpu = sum(
        value[1] for value in (client_construct, client_inputs, evaluation, checksum)
    )
    if (
        client_leaf_wall > client_total[0] + DERIVED_TIMING_TOLERANCE_MS
        or client_leaf_cpu > client_total[1] + DERIVED_TIMING_TOLERANCE_MS
        or setup_construct[0] > setup_total[0] + DERIVED_TIMING_TOLERANCE_MS
        or setup_construct[1] > setup_total[1] + DERIVED_TIMING_TOLERANCE_MS
    ):
        raise ReportError("leaf timings exceed their enclosing process total")
    residual = (
        max(0.0, client_total[0] - client_leaf_wall),
        max(0.0, client_total[1] - client_leaf_cpu),
    )

    geometry = (
        f"N={SLOTS:,}, D={expected['depth']}, W={int(expected['width']):,}, "
        f"I={INPUTS}"
    )
    scalar_field_total = scalar_additions + scalar_multiplications
    if indexed_permutations and rotate_calls:
        execution_order = (
            "indexed permutation views and arithmetic prefix, then remaining gates "
            "one coordinate at a time"
        )
    elif rotate_calls:
        execution_order = "cross-slot prefix once, then remaining gates one coordinate at a time"
    else:
        execution_order = "one coordinate at a time; one scalar DAG gate at a time"
    rotation_rows = (
        [f"| Scalar permutation wiring | {scalar_permutation_wires:,} |",
         f"| Scalar rotation copies | {rotation_copies:,} |",
         f"| Total scalar gate operations | {scalar_total:,} |"]
        if rotate_calls else []
    )
    permutation_ledger = (
        ["", "| Permutation handling | Count |", "|---|---:|",
         f"| Semantic scalar permutation wiring | {scalar_permutation_wires:,} |",
         f"| Materialized scalar rotation copies | {rotation_copies:,} |"]
        if indexed_permutations else []
    )
    workspace_label = (
        "Indexed views and arithmetic prefix workspace"
        if indexed_permutations else "Cross-slot prefix workspace"
    )
    lines = [
        "<!-- laminate-local-payload-summary-v1 -->",
        "# Local payload benchmark",
        "",
        "> The client performed the complete payload computation locally. There was no server, transport, ciphertext, FHE backend, or computation-integrity protocol.",
        "",
        "## Result",
        "",
        "| Property | Measured value |",
        "|---|---:|",
        f"| Profile | `{profile}` |",
        "| Computation location | client only; no server |",
        "| Delegation / integrity | none / not applicable |",
        f"| Payload workload | `{expected['workload']}` |",
        f"| Payload geometry | {geometry} |",
        f"| Payload DAG gates | {int(expected['operations']):,} |",
        f"| Scalar F_t additions | {scalar_additions:,} |",
        f"| Scalar F_t multiplications | {scalar_multiplications:,} |",
        f"| Total scalar F_t operations | {scalar_field_total:,} |",
        *rotation_rows,
        f"| Plaintext field | F_t with t={PLAINTEXT_MODULUS:,} |",
        f"| Evaluation order | {execution_order} |",
        f"| Client local payload evaluation | **{elapsed(evaluation[0])} wall**, {elapsed(evaluation[1])} CPU; {utilization(evaluation[1], evaluation[0])} CPU/wall |",
        f"| Client process total | {elapsed(client_total[0])} wall, {elapsed(client_total[1])} CPU; {utilization(client_total[1], client_total[0])} CPU/wall |",
        f"| Output values / checksum | {output_values:,} / `{output_checksum}` |",
        f"| Client peak RSS | {bytes_text(peak_rss)} |",
        f"| Scalar wire buffer | {bytes_text(scalar_wire_bytes)} |",
        f"| Build | `{setup['environment.git_commit']}`; Release; `{setup['environment.compiler']}` |",
        f"| Pinned CPUs | setup {setup_cpu}; client {client_cpu} |",
        f"| Arithmetic backend | scalar F_65537; compiler vectorization {vectorization}; HEXL not used |",
        f"| Compiler CPU target | {cpu_target} |",
        "",
        "## Client runtime breakdown",
        "",
        "| Phase | Wall | CPU | CPU / wall |",
        "|---|---:|---:|---:|",
        timing_row("Reconstruct deterministic payload circuit", client_construct),
        timing_row("Construct deterministic plaintext inputs", client_inputs),
        timing_row("Evaluate scalar payload", evaluation),
        timing_row("Compute output checksum", checksum),
        timing_row("Other process work (derived)", residual),
        timing_row("Complete client process", client_total),
        "",
        "## Scalar operation ledger",
        "",
        "| Gate kind | DAG gates | Scalar F_t operations |",
        "|---|---:|---:|",
        f"| Add | {add_calls:,} | {SLOTS * add_calls:,} |",
        f"| AddPlain | {add_plain_calls:,} | {SLOTS * add_plain_calls:,} |",
        f"| Mul | {mul_calls:,} | {SLOTS * mul_calls:,} |",
        f"| MulPlain | {mul_plain_calls:,} | {SLOTS * mul_plain_calls:,} |",
        f"| Rotate | {rotate_calls:,} | 0 |",
        f"| **Total** | {int(expected['operations']):,} | {scalar_field_total:,} |",
        *permutation_ledger,
        "",
        "## Memory and execution model",
        "",
        "| Property | Measured or admitted value |",
        "|---|---:|",
        f"| One-coordinate scalar wire buffer | {bytes_text(scalar_wire_bytes)} |",
        f"| {workspace_label} | {bytes_text(cross_slot_workspace)} |",
        f"| Deterministic plaintext inputs | {bytes_text(input_bytes)} |",
        f"| Retained plaintext outputs | {bytes_text(output_bytes)} |",
        f"| Resident circuit representation | {bytes_text(circuit_bytes)} |",
        f"| Setup-admitted client peak | {bytes_text(admitted_peak)} |",
        f"| Measured client peak RSS | {bytes_text(peak_rss)} |",
        f"| Host physical RAM | {bytes_text(integer(setup, 'environment.ram_bytes', 'setup'))} |",
        "| Threads | one process pinned to one logical CPU |",
        f"| Compiler vectorization / external accelerator | {vectorization} / none |",
        f"| Compiler CPU target | {cpu_target} |",
        "",
        "The output checksum identifies the completed deterministic output but is not an independent correctness oracle. This benchmark measures ordinary local scalar field execution and makes no delegation or integrity claim.",
    ]
    return "\n".join(lines)


def publish(output: Path, contents: str) -> None:
    if not output.parent.is_dir():
        raise ReportError(f"output parent is not a directory: {output.parent}")
    if os.path.lexists(output):
        if output.is_symlink() or not output.is_file():
            raise ReportError(f"refusing to replace non-regular output: {output}")
        marker = output.read_text(encoding="utf-8").splitlines()[:1]
        if marker != ["<!-- laminate-local-payload-summary-v1 -->"]:
            raise ReportError("existing summary was not generated by this renderer")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".local-payload-summary-", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(contents)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def acquire_lifecycle_lock(run: Path) -> int:
    if not run.is_absolute() or run == Path("/"):
        raise ReportError("--run-dir must be an absolute directory below root")
    path = run / "shared" / "lifecycle.lock"
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReportError(f"cannot open benchmark lifecycle lock: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
        ):
            raise ReportError("benchmark lifecycle lock is not owner-only")
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--variant", choices=("local",), required=True)
    parser.add_argument(
        "--profile", choices=tuple(PROFILE_GEOMETRY), required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.output.is_absolute():
        raise ReportError("--output must be absolute")

    lifecycle = acquire_lifecycle_lock(args.run_dir)
    try:
        expected_parent = (args.run_dir / "shared" / "report").resolve(
            strict=True
        )
        if (
            args.output.parent.resolve(strict=True) != expected_parent
            or args.output.name != "summary.md"
        ):
            raise ReportError("--output must be RUN/shared/report/summary.md")
        publish(args.output, render(args.run_dir, args.profile))
    finally:
        fcntl.flock(lifecycle, fcntl.LOCK_UN)
        os.close(lifecycle)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReportError, BlockingIOError) as error:
        raise SystemExit(f"error: {error}")
