#!/usr/bin/env python3
"""Validate and render one completed noIntegrity benchmark run."""

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
    PROFILE_GEOMETRY, gate_counts, gate_summary,
    is_budgeted_workload, profile_geometry,
)


class ReportError(RuntimeError):
    pass


NATIVE_FQ = 1_053_858_393_162_252_289
PAYLOAD_OUTPUT_PRIME = 18_014_336_227_311_617
PAYLOAD_DATA_PRIMES = (
    PAYLOAD_OUTPUT_PRIME,
    15_032_614_913,
    53_687_910_401,
    96_638_238_721,
    98_785_755_137,
    118_113_402_881,
    122_408_435_713,
    246_964_387_841,
    272_734_584_833,
)
BALANCED_DATA_PRIMES = (
    1_152_921_497_895_862_273,
    15_032_614_913,
    122_408_435_713,
    246_964_387_841,
    272_734_584_833,
    547_616_686_081,
    140_720_308_191_233,
    4_503_599_626_321_921,
    9_007_072_549_175_297,
)
PYRAMID_DATA_PRIMES = (
    1_152_921_497_895_862_273,
    36_028_481_325_662_209,
    36_028_509_243_375_617,
    36_028_635_946_844_161,
    36_028_638_094_360_577,
    36_028_674_602_139_649,
    36_028_681_044_688_897,
    36_028_700_372_336_641,
    36_028_786_272_993_281,
)
PAYLOAD_SECURITY_BY_PROFILE = {
    "quick": "SEAL sec_level_type::tc128",
    "target-balancedLaned": "SEAL sec_level_type::tc128",
    "target-mulHeavyPyramid": "SEAL sec_level_type::none (80-bit privacy target)",
}
PAYLOAD_MODULI_BY_PROFILE = {
    "quick": (PAYLOAD_DATA_PRIMES[:7], 8_590_163_969),
    "target-balancedLaned": (BALANCED_DATA_PRIMES, 1_099_510_054_913),
    "target-mulHeavyPyramid": (PYRAMID_DATA_PRIMES, 36_028_797_017_456_641),
}
DERIVED_TIMING_TOLERANCE_MS = 0.001
IDENTITY_KEYS = (
    "run.variant",
    "run.profile",
    "run.id",
    "environment.git_commit",
    "environment.git_dirty",
    "environment.build_type",
    "environment.seal_acceleration",
    "environment.fhe_backend",
    "environment.trace_execution",
    "environment.threading",
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
    "parameters.compiled_layers",
    "parameters.fresh_rns_limbs",
    "parameters.fresh_modulus_product_bits",
    "parameters.key_modulus_product_bits",
    "parameters.output_rns_limbs",
    "parameters.plaintext_modulus",
    "parameters.data_primes_bottom_to_top",
    "parameters.special_prime",
    "parameters.output_modulus",
    "parameters.output_modulus_bits",
    "parameters.modulus_switch_policy",
    "parameters.security",
    "parameters.galois_keys",
    "parameters.integrity",
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


def checked_timing_residual(
    total_ms: float, attributed_ms: float, description: str
) -> float:
    if attributed_ms > total_ms + DERIVED_TIMING_TOLERANCE_MS:
        raise ReportError(
            f"{description} leaf timings exceed the enclosing phase total"
        )
    return max(0.0, total_ms - attributed_ms)


def validate_payload_storage_ledger(server: dict[str, str]) -> dict[str, int]:
    prefix = "storage.payload_forward_"

    def value(suffix: str) -> int:
        return integer(server, prefix + suffix, "server")

    prefetch_bytes = value("prefetch_bytes_requested")
    maximum_prefetch = value("maximum_prefetch_request_bytes")
    submission_attempts = value("writeback_submission_attempts")
    submission_successes = value("writeback_submission_successes")
    submitted_bytes = value("writeback_range_bytes_submitted")
    maximum_submission = value("maximum_writeback_submission_bytes")
    wait_attempts = value("writeback_wait_attempts")
    wait_successes = value("writeback_wait_successes")
    waited_bytes = value("writeback_range_bytes_waited")
    submit_only_files = value("writeback_files_submit_only")

    if (
        maximum_prefetch > prefetch_bytes
        or submission_successes > submission_attempts
        or wait_successes > wait_attempts
        or (submission_successes != 0 and maximum_submission > submitted_bytes)
        or waited_bytes > submitted_bytes
        or (
            submit_only_files != 0
            and (wait_attempts != 0 or wait_successes != 0 or waited_bytes != 0)
        )
    ):
        raise ReportError("server has inconsistent payload storage telemetry")

    alias_suffixes = (
        "alias_cached_dense_multiplication_relations",
        "alias_cache_range_readers",
        "alias_cache_distinct_source_records",
        "alias_cache_logical_source_uses",
        "alias_cache_generic_source_records",
    )
    alias_values = {suffix: value(suffix) for suffix in alias_suffixes}
    relations = alias_values["alias_cached_dense_multiplication_relations"]
    if alias_values["alias_cache_range_readers"] != relations:
        raise ReportError("server has an inconsistent payload alias-cache reader ledger")
    if relations == 0:
        if any(alias_values[suffix] != 0 for suffix in alias_suffixes[1:]):
            raise ReportError(
                "server has payload alias-cache counters without a relation"
            )
    elif (
        alias_values["alias_cache_distinct_source_records"] == 0
        or alias_values["alias_cache_generic_source_records"]
        < 4 * alias_values["alias_cache_distinct_source_records"]
    ):
        raise ReportError("server has an inconsistent payload alias-cache savings ledger")
    return alias_values


def require_exit_zero(path: Path) -> None:
    if parse_record(path) != {"process.exit_status": "0"}:
        raise ReportError(f"{path} is not the canonical zero-exit record")


def same_fields(
    records: tuple[dict[str, str], ...], keys: tuple[str, ...], labels: tuple[str, ...]
) -> None:
    for key in keys:
        values = [require(record, key, label) for record, label in zip(records, labels)]
        if len(set(values)) != 1:
            raise ReportError(f"completed role records disagree on {key}")


def elapsed(value: float) -> str:
    seconds = value / 1_000.0
    if seconds < 60:
        return f"{seconds:.3f} s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.2f} min"
    return f"{minutes / 60:.2f} h"


def bytes_text(value: int) -> str:
    amount = float(value)
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or suffix == "TiB":
            return f"{amount:.2f} {suffix}" if suffix != "B" else f"{value:,} B"
        amount /= 1024
    raise AssertionError("unreachable")


def utilization(cpu_ms: float, wall_ms: float) -> str:
    return "n/a" if wall_ms == 0 else f"{100.0 * cpu_ms / wall_ms:.1f}%"


def throughput(byte_count: int, wall_ms: float) -> str:
    if wall_ms == 0:
        return "n/a"
    return f"{1000.0 * byte_count / (1024.0 * 1024.0) / wall_ms:.1f} MiB/s"


def file_size(path: Path) -> int:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise ReportError(f"cannot inspect {path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ReportError(f"wire artifact is not a regular file: {path}")
    return metadata.st_size


def validate_target_storage(run: Path) -> str | None:
    setup_path = run / "shared" / "storage-provenance.setup-start.txt"
    server_path = run / "shared" / "storage-provenance.server-start.txt"
    setup = parse_record(setup_path)
    server = parse_record(server_path)
    if require(setup, "format", "setup storage") != "laminate-storage-provenance-v2":
        raise ReportError("setup storage provenance has an unsupported format")
    if require(server, "format", "server storage") != "laminate-storage-provenance-v2":
        raise ReportError("server storage provenance has an unsupported format")
    if require(setup, "storage.capture_phase", "setup storage") != "setup-start":
        raise ReportError("setup storage provenance has the wrong phase")
    if require(server, "storage.capture_phase", "server storage") != "server-start":
        raise ReportError("server storage provenance has the wrong phase")
    static_keys = (
        "storage.backend",
        "storage.artifact_root",
        "storage.mount_source",
        "storage.mount_target",
        "storage.filesystem_type",
        "storage.filesystem_total_bytes",
    )
    same_fields((setup, server), static_keys, ("setup storage", "server storage"))
    return require(setup, "storage.backend", "setup storage")


def render(run: Path, profile: str) -> str:
    binding = parse_record(run / "shared" / "run-binding.txt")
    setup = parse_record(run / "shared" / "setup-result.txt")
    server = parse_record(run / "server" / "result.txt")
    client = parse_record(run / "client" / "result.txt")
    require_exit_zero(run / "shared" / "setup-process-exit.txt")
    require_exit_zero(run / "server" / "process-exit.txt")
    require_exit_zero(run / "client" / "process-exit.txt")

    if binding != {
        "format": "laminate-benchmark-run-v1",
        "run.variant": "noIntegrity",
        "run.profile": profile,
        "run.id": require(binding, "run.id", "run binding"),
    }:
        raise ReportError("run-binding.txt is not the exact noIntegrity binding")
    if not re.fullmatch(r"[0-9a-f]{64}", binding["run.id"]):
        raise ReportError("run binding has an invalid run id")
    if require(setup, "format", "setup") != "laminate-benchmark-setup-v1":
        raise ReportError("setup has an unsupported format")
    if require(server, "format", "server") != "laminate-benchmark-server-v1":
        raise ReportError("server has an unsupported format")
    if require(client, "format", "client") != "laminate-benchmark-client-v2":
        raise ReportError("client has an unsupported format")
    if require(setup, "setup.result", "setup") != "PASS":
        raise ReportError("setup did not pass")
    if require(server, "server.result", "server") != "PASS":
        raise ReportError("server did not pass")
    if require(client, "verification.result", "client") != "PASS":
        raise ReportError("client transport/decryption lifecycle did not pass")
    records = (setup, server, client)
    labels = ("setup", "server", "client")
    same_fields(records, IDENTITY_KEYS + GEOMETRY_KEYS, labels)
    for key in ("parameters.payload_mul_plain_gates",
                "parameters.payload_rotate_gates"):
        if any(key in record for record in records):
            same_fields(records, (key,), labels)
    sha256_providers = [
        record.get("environment.sha256_acceleration") for record in records
    ]
    if any(value is not None for value in sha256_providers) and (
        any(value is None for value in sha256_providers)
        or len(set(sha256_providers)) != 1
    ):
        raise ReportError(
            "setup, server, and client disagree on SHA-256 acceleration"
        )
    if setup["run.variant"] != "noIntegrity" or setup["run.profile"] != profile:
        raise ReportError("role identity differs from the selected run")
    if setup["run.id"] != binding["run.id"]:
        raise ReportError("role identity differs from run-binding.txt")
    if any(require(record, "integrity.result", label) != "NOT_PROVIDED"
           for record, label in zip(records, labels)):
        raise ReportError("a noIntegrity role made an integrity claim")
    if setup["parameters.integrity"] != "none":
        raise ReportError("noIntegrity parameters claim integrity")
    if client["verification.scope"] != "response-binding-decode-and-full-decryption-only":
        raise ReportError("client completion scope is not exact")
    if setup["environment.git_dirty"] != "false":
        raise ReportError("measurement was built from a dirty tree")
    if setup["environment.build_type"] != "Release":
        raise ReportError("measurement was not a Release build")
    if setup["environment.seal_acceleration"] != "intel-hexl-runtime-dispatch":
        raise ReportError("measurement did not use Intel HEXL runtime dispatch")
    if setup["environment.threading"] != "single-cpu-process":
        raise ReportError("measurement is not single-threaded")
    setup_cpu = integer(setup, "environment.pinned_cpu", "setup")
    server_cpu = integer(server, "environment.pinned_cpu", "server")
    client_cpu = integer(client, "environment.pinned_cpu", "client")
    if server_cpu == client_cpu:
        raise ReportError("client and server used the same logical CPU")

    expected_workload = setup["parameters.payload_workload"]
    try:
        expected = profile_geometry(profile, expected_workload)
    except ValueError as error:
        raise ReportError(str(error)) from error
    depth, width, payload_operations = (
        int(expected[key]) for key in ("depth", "width", "operations")
    )
    expected_primes, expected_special_prime = PAYLOAD_MODULI_BY_PROFILE[profile]
    expected_data_modulus = math.prod(expected_primes)
    expected_output_prime = expected_primes[0]
    expected_output_bits = expected_output_prime.bit_length()
    expected_gate_counts = gate_counts(expected)
    unary_gate_counts = []
    for kind in ("mul_plain", "rotate"):
        key = f"parameters.payload_{kind}_gates"
        unary_gate_counts.append(
            integer(setup, key, "setup")
            if key in setup or is_budgeted_workload(expected_workload) else 0
        )
    if (
        integer(setup, "parameters.slots", "setup") != 16_384
        or setup["parameters.payload_workload"] != expected_workload
        or integer(setup, "parameters.payload_multiplicative_depth", "setup") != depth
        or integer(setup, "parameters.payload_width", "setup") != width
        or integer(setup, "parameters.payload_inputs", "setup") != 64
        or integer(setup, "parameters.payload_outputs", "setup") != 1
        or integer(setup, "parameters.payload_operations", "setup")
        != payload_operations
        or (
            integer(setup, "parameters.payload_add_gates", "setup"),
            integer(setup, "parameters.payload_add_plain_gates", "setup"),
            integer(setup, "parameters.payload_mul_gates", "setup"),
            *unary_gate_counts,
        )
        != expected_gate_counts
        or integer(setup, "parameters.fresh_rns_limbs", "setup") != depth + 1
        or integer(setup, "parameters.fresh_modulus_product_bits", "setup")
        != expected_data_modulus.bit_length()
        or integer(setup, "parameters.key_modulus_product_bits", "setup")
        != (expected_data_modulus * expected_special_prime).bit_length()
        or integer(setup, "parameters.output_rns_limbs", "setup") != 1
        or integer(setup, "parameters.plaintext_modulus", "setup") != 65_537
        or integer(setup, "parameters.output_modulus", "setup")
        != expected_output_prime
        or integer(setup, "parameters.output_modulus_bits", "setup")
        != expected_output_bits
        or integer(client, "output.rns_limbs", "client") != 1
    ):
        raise ReportError("noIntegrity geometry or payload-only chain drifted")
    if setup["parameters.modulus_switch_policy"] != "one-after-each-ctct-multiplication-layer":
        raise ReportError("noIntegrity modulus-switch policy drifted")
    if setup["parameters.security"] != PAYLOAD_SECURITY_BY_PROFILE[profile]:
        raise ReportError("noIntegrity privacy policy differs from the selected profile")
    expected_galois = (
        "generated" if expected["rotate"] else "omitted-no-rotation-gates"
    )
    if setup["parameters.galois_keys"] != expected_galois:
        raise ReportError("noIntegrity Galois keys disagree with the payload")
    try:
        primes = tuple(int(value) for value in setup["parameters.data_primes_bottom_to_top"].split(","))
    except ValueError as error:
        raise ReportError("data-prime list is not numeric") from error
    if primes != expected_primes:
        raise ReportError("data primes differ from the payload-only chain")
    if integer(setup, "parameters.special_prime", "setup") != expected_special_prime:
        raise ReportError("special prime differs from the payload-only chain")
    if (
        primes[0] == NATIVE_FQ
        or primes[0].bit_length() != expected_output_bits
        or primes[0] % 65_537 != 1
        or (primes[0] - 1) % (2 * 16_384) != 0
    ):
        raise ReportError("final ciphertext modulus is not the payload-only output prime")

    request_size = file_size(run / "shared" / "transcript" / "cli-to-srv-request.bin")
    response_size = file_size(run / "shared" / "transcript" / "srv-to-cli-response.bin")
    if (
        integer(server, "wire.request_bytes", "server") != request_size
        or integer(client, "wire.request_bytes", "client") != request_size
        or integer(server, "wire.response_bytes", "server") != response_size
        or integer(client, "wire.response_bytes", "client") != response_size
    ):
        raise ReportError("wire files disagree with completed role reports")
    digest = require(client, "output.decrypted_slots_digest", "client")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ReportError("decrypted output digest is invalid")

    payload_wall = number(server, "timing.server.payload_evaluation.wall_ms", "server")
    payload_cpu = number(server, "timing.server.payload_evaluation.cpu_ms", "server")
    server_total_wall = number(server, "timing.server.online_total.wall_ms", "server")
    server_total_cpu = number(server, "timing.server.online_total.cpu_ms", "server")
    encrypt_wall = number(client, "timing.client.encrypt_inputs.wall_ms", "client")
    decrypt_wall = number(client, "timing.client.full_decrypt_output.wall_ms", "client")
    decrypt_cpu = number(client, "timing.client.full_decrypt_output.cpu_ms", "client")
    noise_bits = integer(client, "output.invariant_noise_budget_bits", "client")
    if noise_bits == 0:
        raise ReportError("noIntegrity output has exhausted its noise budget")
    peak_disk = integer(server, "storage.payload_peak_live_physical_bytes", "server")
    peak_server_rss = integer(server, "memory.server.peak_rss_bytes", "server")
    peak_client_rss = integer(client, "memory.client.peak_rss_bytes", "client")
    controlled_ram = integer(server, "memory.payload_peak_controlled_resident_bytes", "server")
    operation_names = (
        "add",
        "mul_no_relin",
        "relinearize",
        "add_plain",
        "mul_plain_scalar",
        "mul_plain_vector",
        "mod_switch",
        "rotate",
        "encrypt",
    )
    operations = {
        name: integer(
            server,
            f"operations.server_payload_evaluation.{name}.calls",
            "server",
        )
        for name in operation_names
    }
    if (not expected["rotate"] and operations["rotate"] != 0) or operations["encrypt"] != 0:
        raise ReportError("server performed a forbidden rotation or encryption")
    if expected["rotate"] and operations["rotate"] == 0:
        raise ReportError("server omitted the payload's cross-slot rotation work")
    storage_backend = validate_target_storage(run) if profile != "quick" else None

    lines = [
        "<!-- laminate-no-integrity-summary-v1 -->",
        "# Laminate noIntegrity benchmark",
        "",
        "> **No integrity is provided.** This is an FHE payload-evaluation baseline, not a Laminate proof benchmark. The client checked response binding, decoded one ciphertext, and fully decrypted it; it did not verify that the server evaluated the requested circuit.",
        "",
        "## Result",
        "",
        "| Property | Measured value |",
        "|---|---:|",
        f"| Profile | `{profile}` |",
        f"| Payload workload | `{expected_workload}`; {gate_summary(expected_gate_counts)} |",
        f"| Payload geometry | N=16,384, D={depth}, W={width:,}, I=64 |",
        f"| Payload operations | {integer(setup, 'parameters.payload_operations', 'setup'):,} |",
        f"| Data limbs | {depth + 1} fresh; 1 in returned output |",
        f"| Data / key modulus product | {integer(setup, 'parameters.fresh_modulus_product_bits', 'setup')} / {integer(setup, 'parameters.key_modulus_product_bits', 'setup')} bits |",
        f"| Final ciphertext modulus | {expected_output_prime:,} (ordinary {expected_output_bits}-bit payload prime; not native Fq) |",
        f"| Privacy policy | {setup['parameters.security']} |",
        f"| Modulus switching | one drop after each of {depth} CT-CT multiplication layers |",
        f"| Server payload evaluation | **{elapsed(payload_wall)} wall**, {elapsed(payload_cpu)} CPU; {utilization(payload_cpu, payload_wall)} CPU/wall |",
        f"| Server online total, excluding peer wait | {elapsed(server_total_wall)} wall, {elapsed(server_total_cpu)} CPU |",
        f"| Client input encryption | {elapsed(encrypt_wall)} wall |",
        f"| Client full output decryption | {elapsed(decrypt_wall)} wall, {elapsed(decrypt_cpu)} CPU |",
        f"| Output invariant noise budget | {noise_bits} bits |",
        f"| Request / response | {bytes_text(request_size)} / {bytes_text(response_size)} |",
        f"| Server / client peak RSS | {bytes_text(peak_server_rss)} / {bytes_text(peak_client_rss)} |",
        f"| File-backed payload peak | {bytes_text(peak_disk)} physical; {bytes_text(controlled_ram)} controlled resident |",
        f"| Build | `{setup['environment.git_commit']}`; Release; SEAL `{setup['environment.seal_acceleration']}`; SHA-256 `{setup.get('environment.sha256_acceleration', 'not-reported')}` |",
        f"| Pinned CPUs | setup {setup_cpu}; server {server_cpu}; client {client_cpu} |",
    ]
    if storage_backend is not None:
        lines.append(f"| Target storage backend | `{storage_backend}` |")
    if "memory.host_operating_system_reserve_bytes" in setup:
        replay_work = integer(setup, "planner.payload_replay_work_units", "setup")
        checkpoint_count = integer(
            setup, "planner.payload_checkpoint_count", "setup"
        )
        checkpoint_bytes = integer(
            setup, "planner.payload_checkpoint_bytes", "setup"
        )
        output_only_disk_peak = integer(
            setup, "storage.payload_output_only_plan.peak_live_scratch_bytes", "setup"
        )
        output_only_resident_peak = integer(
            setup, "memory.payload_output_only_plan.peak_resident_bytes", "setup"
        )
        alias_cache_resident_peak = integer(
            setup,
            "memory.payload_output_only_plan.dense_multiplication_alias_cache_peak_resident_bytes",
            "setup",
        )
        output_only_disk_headroom = integer(
            setup,
            "storage.payload_output_only_plan.remaining_headroom_bytes",
            "setup",
        )
        if (
            require(setup, "planner.execution_mode", "setup")
            != "output-only-adjacent-layers"
            or replay_work != 0
            or checkpoint_count != 0
            or checkpoint_bytes != 0
        ):
            raise ReportError("noIntegrity report contains proof replay state")
        if alias_cache_resident_peak > output_only_resident_peak:
            raise ReportError(
                "noIntegrity alias-cache peak exceeds the output-only resident peak"
            )
        lines.extend(
            [
                f"| Host OS / page-cache reserve | {bytes_text(integer(setup, 'memory.host_operating_system_reserve_bytes', 'setup'))} / {bytes_text(integer(setup, 'memory.host_page_cache_reserve_bytes', 'setup'))} |",
                f"| Payload transfer-buffer reserve | {bytes_text(integer(setup, 'memory.payload_storage.transfer_buffer_reserve_bytes', 'setup'))} |",
                f"| Payload ephemeral foreground wait window | {bytes_text(integer(setup, 'memory.payload_storage.writeback_window_bytes', 'setup'))} |",
                f"| Payload ephemeral writeback policy | `{require(setup, 'storage.payload_storage.ephemeral_writeback_policy', 'setup')}` |",
                f"| Configured writeback range-hint ceiling | {bytes_text(integer(setup, 'storage.payload_storage.maximum_writeback_submission_bytes', 'setup'))} |",
                f"| Sequential payload readers | {integer(setup, 'memory.payload_storage.sequential_reader_count', 'setup'):,} |",
                f"| Prefetch logical window per reader | {bytes_text(integer(setup, 'memory.payload_storage.prefetch_window_bytes_each', 'setup'))} |",
                f"| Payload prefetch page-cache budget | {bytes_text(integer(setup, 'memory.payload_storage.prefetch_page_cache_budget_bytes', 'setup'))} (inside page-cache reserve) |",
                f"| Configured prefetch-request ceiling | {bytes_text(integer(setup, 'storage.payload_storage.maximum_prefetch_request_bytes', 'setup'))}; the Linux runtime further qualifies requests from the backing device's BDI read-ahead geometry |",
                f"| Payload replay work / checkpoints | {replay_work:,} / {checkpoint_count:,} |",
                f"| Output-only plan | {bytes_text(output_only_disk_peak)} adjacent-layer disk peak; {bytes_text(output_only_resident_peak)} resident peak |",
                f"| Setup-selected dense multiplication alias-cache peak | {bytes_text(alias_cache_resident_peak)} relation-scoped resident bound, included in the output-only resident peak |",
                f"| Remaining admitted output-only disk headroom | {bytes_text(output_only_disk_headroom)} |",
            ]
        )
    relation_key = "timing.server.payload_evaluation.relation_total.wall_ms"
    if relation_key in server:
        alias_cache = validate_payload_storage_ledger(server)
        phase_names = [
            ("Complete forward relations", "relation_total"),
            ("FHE arithmetic", "fhe"),
            ("Deterministic modulus switching", "modulus_switch"),
            ("Source deserialization", "deserialization"),
            ("Output serialization", "serialization"),
            ("Transfer-slab record copying", "buffer_assembly"),
            ("Artifact hashing", "hashing"),
            ("Capacity admission", "capacity_admission"),
            (
                "Record output submission (inclusive parent; excluded from derived sum)",
                "output_submission",
            ),
            ("Page-cache write calls", "storage_write"),
            ("Background writeback submission", "writeback_submission"),
            ("Explicit foreground writeback waits", "writeback_wait"),
            ("Page-cache prefetch advice", "prefetch"),
            ("Source storage reads", "storage_read"),
            ("Drain, close, and publication", "drain_close_publication"),
        ]
        storage_rows = []
        phase_timings = {}
        for label, key in phase_names:
            wall = number(
                server,
                f"timing.server.payload_evaluation.{key}.wall_ms",
                "server",
            )
            cpu = number(
                server,
                f"timing.server.payload_evaluation.{key}.cpu_ms",
                "server",
            )
            phase_timings[key] = (wall, cpu)
            storage_rows.append(
                f"| {label} | {elapsed(wall)} | {elapsed(cpu)} | {utilization(cpu, wall)} |"
            )
        useful_wall = sum(phase_timings[key][0] for key in ("fhe", "modulus_switch"))
        useful_cpu = sum(phase_timings[key][1] for key in ("fhe", "modulus_switch"))
        trace_keys = (
            "deserialization",
            "serialization",
            "buffer_assembly",
            "hashing",
            "capacity_admission",
            "storage_write",
            "writeback_submission",
            "writeback_wait",
            "prefetch",
            "storage_read",
        )
        trace_wall = sum(phase_timings[key][0] for key in trace_keys)
        trace_cpu = sum(phase_timings[key][1] for key in trace_keys)
        relation_wall, relation_cpu = phase_timings["relation_total"]
        residual_wall = checked_timing_residual(
            relation_wall,
            useful_wall + trace_wall,
            "server payload-relation wall",
        )
        residual_cpu = checked_timing_residual(
            relation_cpu,
            useful_cpu + trace_cpu,
            "server payload-relation CPU",
        )
        storage_rows[1:1] = [
            f"| FHE + ciphertext maintenance (derived) | {elapsed(useful_wall)} | {elapsed(useful_cpu)} | {utilization(useful_cpu, useful_wall)} |",
            f"| Trace maintenance (derived) | {elapsed(trace_wall)} | {elapsed(trace_cpu)} | {utilization(trace_cpu, trace_wall)} |",
            f"| Residual relation work (derived) | {elapsed(residual_wall)} | {elapsed(residual_cpu)} | {utilization(residual_cpu, residual_wall)} |",
        ]
        write_bytes = integer(
            server, "storage.payload_forward_application_write_bytes", "server"
        )
        read_bytes = integer(
            server, "storage.payload_forward_application_read_bytes", "server"
        )
        write_wall = number(
            server,
            "timing.server.payload_evaluation.storage_write.wall_ms",
            "server",
        )
        read_wall = number(
            server,
            "timing.server.payload_evaluation.storage_read.wall_ms",
            "server",
        )
        lines.extend(
            [
                "",
                "## Payload storage pipeline",
                "",
                "| Phase | Wall | CPU | CPU / wall |",
                "|---|---:|---:|---:|",
                *storage_rows,
                "",
                "Derived rows sum disjoint leaf timers; drain/close/publication is shown separately and excluded because it encloses some of those leaves.",
                "",
                "| Transfer evidence | Measured value |",
                "|---|---:|",
                f"| Application bytes submitted to write calls | {bytes_text(write_bytes)} at {throughput(write_bytes, write_wall)} call-path throughput; not device traffic |",
                f"| Write batches / syscalls | {integer(server, 'storage.payload_forward_write_batches', 'server'):,} / {integer(server, 'storage.payload_forward_write_syscalls', 'server'):,} |",
                f"| Largest write batch | {bytes_text(integer(server, 'storage.payload_forward_maximum_write_batch_bytes', 'server'))} |",
                f"| Writeback-enabled / submit-only / fallback files | {integer(server, 'storage.payload_forward_writeback_files_enabled', 'server'):,} / {integer(server, 'storage.payload_forward_writeback_files_submit_only', 'server'):,} / {integer(server, 'storage.payload_forward_writeback_files_fallback', 'server'):,} |",
                f"| Writeback submission attempts / successes | {integer(server, 'storage.payload_forward_writeback_submission_attempts', 'server'):,} / {integer(server, 'storage.payload_forward_writeback_submission_successes', 'server'):,} |",
                f"| Foreground wait attempts / successes | {integer(server, 'storage.payload_forward_writeback_wait_attempts', 'server'):,} / {integer(server, 'storage.payload_forward_writeback_wait_successes', 'server'):,} |",
                f"| Largest successful writeback range hint | {bytes_text(integer(server, 'storage.payload_forward_maximum_writeback_submission_bytes', 'server'))} |",
                f"| Successful range-hint / explicitly waited range bytes | {bytes_text(integer(server, 'storage.payload_forward_writeback_range_bytes_submitted', 'server'))} / {bytes_text(integer(server, 'storage.payload_forward_writeback_range_bytes_waited', 'server'))} |",
                f"| Foreground wait window / maximum application-tracked unwaited range | {bytes_text(integer(server, 'storage.payload_forward_writeback_window_bytes', 'server'))} / {bytes_text(integer(server, 'storage.payload_forward_maximum_unwaited_writeback_range_bytes', 'server'))} |",
                f"| Foreground drains / deliberately skipped drains | {integer(server, 'storage.payload_forward_writeback_drains', 'server'):,} / {integer(server, 'storage.payload_forward_writeback_drains_skipped', 'server'):,} |",
                f"| Foreground-drain range / successful range-hint bytes without explicit wait | {bytes_text(integer(server, 'storage.payload_forward_writeback_drain_range_bytes', 'server'))} / {bytes_text(integer(server, 'storage.payload_forward_writeback_range_bytes_without_explicit_wait', 'server'))} |",
                f"| Positional header-write calls / bytes | {integer(server, 'storage.payload_forward_positional_write_calls', 'server'):,} / {bytes_text(integer(server, 'storage.payload_forward_positional_write_bytes', 'server'))} |",
                f"| Application bytes returned by read calls | {bytes_text(read_bytes)} at {throughput(read_bytes, read_wall)} call-path throughput; not device traffic |",
                f"| Read batches / syscalls | {integer(server, 'storage.payload_forward_read_batches', 'server'):,} / {integer(server, 'storage.payload_forward_read_syscalls', 'server'):,} |",
                f"| Largest read batch | {bytes_text(integer(server, 'storage.payload_forward_maximum_read_batch_bytes', 'server'))} |",
                f"| Prefetch requests / fallbacks / seek disables | {integer(server, 'storage.payload_forward_prefetch_requests', 'server'):,} / {integer(server, 'storage.payload_forward_prefetch_fallbacks', 'server'):,} / {integer(server, 'storage.payload_forward_prefetch_seek_disables', 'server'):,} |",
                f"| Prefetch bytes requested | {bytes_text(integer(server, 'storage.payload_forward_prefetch_bytes_requested', 'server'))} |",
                f"| Prefetch logical window / largest BDI-qualified request | {bytes_text(integer(server, 'storage.payload_forward_prefetch_window_bytes', 'server'))} / {bytes_text(integer(server, 'storage.payload_forward_maximum_prefetch_request_bytes', 'server'))} |",
                f"| Filesystem-capacity probes | {integer(server, 'storage.payload_forward_capacity_probes', 'server'):,} (layer/trace boundaries only) |",
                f"| Private scratch integrity | `{require(server, 'storage.payload_artifact_integrity', 'server')}` |",
                f"| Authenticated / same-process-unhashed record bytes | {bytes_text(integer(server, 'storage.payload_forward_authenticated_record_bytes', 'server'))} / {bytes_text(integer(server, 'storage.payload_forward_same_process_unhashed_record_bytes', 'server'))} |",
                f"| Whole-record bytes recopied into transfer slabs | {bytes_text(integer(server, 'storage.payload_forward_record_copy_bytes', 'server'))} |",
                f"| Identity-affine alias relations / capability fallbacks | {integer(server, 'storage.payload_forward_identity_affine_alias_relations', 'server'):,} / {integer(server, 'storage.payload_forward_identity_affine_alias_fallbacks', 'server'):,} |",
                f"| Identity-affine records reused | {integer(server, 'storage.payload_forward_identity_affine_alias_records_reused', 'server'):,} |",
                f"| Existing identity-affine layer bytes reused | {bytes_text(integer(server, 'storage.payload_forward_identity_affine_alias_layer_bytes_reused', 'server'))} |",
                f"| Unique identity-affine alias bytes written | {bytes_text(integer(server, 'storage.payload_forward_identity_affine_alias_unique_bytes_written', 'server'))} |",
                "",
                "A relation-scoped multiplication alias cache is admitted against the setup-selected global resident cap, may deliberately exceed the ordinary tiny-chunk peak, and is released at the relation boundary. Its generic-path record count is the measured no-cache reference; net source-record reads avoided equal that reference minus the distinct records the cache still reads.",
                "",
                "| Alias-cache evidence | Measured value |",
                "|---|---:|",
                f"| Cached dense multiplication relations | {alias_cache['alias_cached_dense_multiplication_relations']:,} |",
                f"| Alias-cache range readers | {alias_cache['alias_cache_range_readers']:,} |",
                f"| Distinct source records read | {alias_cache['alias_cache_distinct_source_records']:,} |",
                f"| Logical source uses | {alias_cache['alias_cache_logical_source_uses']:,} |",
                f"| Generic-path source records without cache | {alias_cache['alias_cache_generic_source_records']:,} |",
                f"| Net source-record reads avoided | {alias_cache['alias_cache_generic_source_records'] - alias_cache['alias_cache_distinct_source_records']:,} |",
                "",
                "Same-process ephemeral files use Linux submit-only writeback: they perform no explicit foreground wait or layer-end drain, although ordinary kernel dirty-page throttling may still block writes. Authenticated reopenable artifacts retain bounded foreground waits and a layer-end drain. Linux prefetch requests are capped by setup policy and further qualified at runtime from the backing device's BDI read-ahead geometry; the reported largest request is the actual submitted size. Exact singleton affine relations can hard-link an already validated one-layer file into a distinct private namespace; reused layer bytes are existing file lengths, while unique alias bytes are the new manifest only. A capability-only hard-link failure uses the ordinary admitted materializer. Transfer byte counts are application-level bytes, not device traffic; use host block-I/O telemetry to measure the Hyperdisk itself.",
            ]
        )
    lines.extend(
        [
            "",
            "## Server FHE operation ledger",
            "",
            "| Operation | Calls |",
            "|---|---:|",
            *[f"| `{name}` | {operations[name]:,} |" for name in operation_names],
            "",
            "Every published duration is from a process pinned to one logical CPU. The output digest records what was decrypted but is not an expected-output comparison and is not an integrity check.",
        ]
    )
    return "\n".join(lines)


def publish(output: Path, contents: str) -> None:
    if not output.parent.is_dir():
        raise ReportError(f"output parent is not a directory: {output.parent}")
    if os.path.lexists(output):
        if output.is_symlink() or not output.is_file():
            raise ReportError(f"refusing to replace non-regular output: {output}")
        marker = output.read_text(encoding="utf-8").splitlines()[:1]
        if marker != ["<!-- laminate-no-integrity-summary-v1 -->"]:
            raise ReportError("existing summary was not generated by this renderer")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".no-integrity-summary-", dir=output.parent
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
    parser.add_argument("--variant", choices=("noIntegrity",), required=True)
    parser.add_argument("--profile", choices=tuple(PROFILE_GEOMETRY), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.output.is_absolute():
        raise ReportError("--output must be absolute")
    lifecycle = acquire_lifecycle_lock(args.run_dir)
    try:
        expected_parent = (args.run_dir / "shared" / "report").resolve(strict=True)
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
