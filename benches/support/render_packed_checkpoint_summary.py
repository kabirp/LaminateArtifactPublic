#!/usr/bin/env python3
"""Validate and render a completed split-process packed benchmark run."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import math
import os
from pathlib import Path
import stat
import tempfile

from render_payload_profiles import (
    PROFILE_GEOMETRY, gate_counts, gate_summary, is_budgeted_workload, profile_geometry,
)


class ReportError(RuntimeError):
    pass


SERVER_STARTUP_SCOPE = (
    "role-preprocessing-load-reusable-replay-gkr-static-certification-and-"
    "persistent-reserve-derivation;excludes-one-shot-request-resources-peer-"
    "idle-wait-and-per-request-work"
)
SERVER_RECURRING_PRE_REQUEST_SCOPE = (
    "one-shot-work-root-creation-transcript-packing-admission-checkpoint-"
    "replay-scratch-and-host-capacity-admission;included-in-per-request-total-"
    "even-when-reserved-before-request-arrival"
)
SERVER_REQUEST_SCOPE = (
    "recurring-one-shot-resource-admission-request-read-and-codec-payload-"
    "evaluation-checkpoint-replay-gkr-and-transcript-packing-proof-response-"
    "codec-and-publication;excludes-reusable-static-preprocessing-and-peer-"
    "idle-wait"
)
PACKED_OUTPUT_MAXIMUM_CANONICAL_ERROR_NORM_BITS = 10
PUBLICATION_OBSERVATION_RACE_MS = 1_000
ADAPTIVE_FREE_DISK_RESERVE_BYTES = 100_000_000_000
ADAPTIVE_OPERATING_SYSTEM_RAM_RESERVE_BYTES = 16_000_000_000
ADAPTIVE_PAGE_CACHE_RAM_RESERVE_BYTES = 64_000_000_000
ADAPTIVE_HOST_RAM_SAFETY_RESERVE_BYTES = (
    ADAPTIVE_OPERATING_SYSTEM_RAM_RESERVE_BYTES
    + ADAPTIVE_PAGE_CACHE_RAM_RESERVE_BYTES
)
ADAPTIVE_SERVER_COMMON_DISK_RESERVE_BYTES = 128_000_000_000

SETUP_TIMING_PHASES = (
    "workload_compilation",
    "storage_preflight",
    "fhe_preprocessing",
    "packed_preprocessing",
    "verify_persisted",
    "resource_admission",
)
WIRE_KEYS = frozenset({"wire.request_bytes", "wire.response_bytes"})
PACKING_R1CS_INTEGER_FIELDS = (
    "ring_degree",
    "repetitions",
    "aligned_ciphertexts",
    "logical_packed_outputs",
    "physical_packed_ciphertexts",
    "packing_digit_count",
    "ciphertext_commitment_constraints_per_ciphertext",
    "ciphertext_commitment_constraints_total",
    "packing_relation_constraints",
    "active_constraints",
    "matrix_rows",
    "spartan_padded_constraints",
    "public_inputs",
    "active_witness_variables",
    "witness_extent",
    "spartan_assignment_half_size",
    "spartan_padded_assignment_variables",
)
LANED_PROOF_INGRESS_POLICY = "LaminateImpl/ConservativePackedProofIngress/v3"
FOLDED_PYRAMID_PROOF_INGRESS_POLICY = "LaminateImpl/ConservativePackedProofIngress/v4"
PACKED_FIAT_SHAMIR_SCHEDULE = "single-transcript-gkr-then-packing-v1"
GKR_MULTIPLICATION = "gruen-stripped-h0-v1"
GKR_CLAIM_TRANSITION = "selector-interpolation-v1"
GKR_CLAIM_TRANSITION_DESCRIPTION = "One claim by selector interpolation"
PACKED_FIAT_SHAMIR_DESCRIPTION = "One transcript: GKR, then Spartan packing argument"
WIDE_GATE_QUERIES = 300


def validate_packed_target_modulus(
    profile: str, variant: str, lanes: int, policy: str, widths: list[int],
    special_bits: int, primes: list[int], special_prime: int,
) -> None:
    if profile == "quick":
        return
    pyramid_headroom = (variant == "folded" and profile == "target-mulHeavyPyramid"
                        and policy == FOLDED_PYRAMID_PROOF_INGRESS_POLICY)
    expected_policy = ("LaminateImpl/ConservativePackedProofIngress/v1"
                       if variant == "folded" else LANED_PROOF_INGRESS_POLICY)
    if policy != expected_policy and not pyramid_headroom:
        raise ReportError("unsupported packed proof-ingress policy")
    # Validate the exact profile chain: a proof-ingress policy alone does not
    # identify the data moduli.
    limbs = 14 if variant == "folded" or lanes == 16_384 else 15
    expected = [60, 48, 48, 37, 37, 37, 37, 38, 38, 39] + [40] * (limbs - 10)
    if pyramid_headroom:
        expected = [60, 48, 48, 37, 37, 37] + [45] * 8
    if widths != expected or special_bits != 60:
        raise ReportError("packed target modulus does not match its fixed profile chain")
    expected_primes = [
        1053858393162252289, 281412698669057, 281449206448129,
        96638238721, 98785755137, 118113402881, 122408435713,
        246964387841, 272734584833, 547616686081,
    ]
    if limbs == 15:
        expected_primes.append(972824936449)
    expected_primes += [998595133441, 1005037682689, 1032955396097, 1095233372161]
    if pyramid_headroom:
        expected_primes = expected_primes[:6] + [
            35004517580801, 35017402679297, 35047467909121, 35092565753857,
            35111893401601, 35126926016513, 35144106147841, 35156991246337,
        ]
    if primes != expected_primes or special_prime != 1152921504606748673:
        raise ReportError("packed target exact primes do not match its fixed profile chain")


def validate_folded_pyramid_preflight(setup: dict[str, str]) -> None:
    if setup.get("schedule.proof_ingress_policy") != FOLDED_PYRAMID_PROOF_INGRESS_POLICY:
        return
    expected = {
        "noise_preflight.result": "PASS",
        "noise_preflight.policy": "folded-target-pyramid-live-key-v1",
        "noise_preflight.same_setup_key": "true",
        "noise_preflight.root_wire": "1042862",
        "noise_preflight.outer_spartan_included": "false",
        "schedule.proof_ingress_rns_limbs_by_layer": "1,4,6,4,6,4,6,4,6,4,6,4,6,4,6,4,6,4",
        "schedule.payload_modulus_switches_after_layer": "3,3,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,0",
    }
    if any(setup.get(key) != value for key, value in expected.items()):
        raise ReportError("Folded pyramid live-key preflight or fixed schedule is missing or inconsistent")
    for clock in ("wall_ms", "cpu_ms"):
        component = number(setup, f"timing.setup.live_key_noise_preflight.{clock}", "setup")
        parent = number(setup, f"timing.setup.workload_compilation.{clock}", "setup")
        if component <= 0 or component > parent + 1:
            raise ReportError("Folded pyramid live-key preflight timing is inconsistent")


def parse_record(path: Path) -> dict[str, str]:
    try:
        status = os.lstat(path)
        if not stat.S_ISREG(status.st_mode):
            raise ReportError(f"record is not a regular file: {path}")
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ReportError(f"cannot read {path}: {error}") from error
    result: dict[str, str] = {}
    for line_number, line in enumerate(lines, 1):
        if not line or "=" not in line:
            raise ReportError(f"{path}:{line_number}: expected one key=value record")
        key, value = line.split("=", 1)
        if not key or key in result:
            raise ReportError(f"{path}:{line_number}: empty or duplicate key {key!r}")
        result[key] = value
    return result


def require(record: dict[str, str], key: str, source: str) -> str:
    if key not in record:
        raise ReportError(f"{source} is missing {key}")
    return record[key]


def number(record: dict[str, str], key: str, source: str) -> float:
    value = require(record, key, source)
    try:
        result = float(value)
    except ValueError as error:
        raise ReportError(f"{source} has non-numeric {key}={value!r}") from error
    if not math.isfinite(result) or result < 0:
        raise ReportError(f"{source} has invalid {key}={value!r}")
    return result


def integer(record: dict[str, str], key: str, source: str) -> int:
    value = require(record, key, source)
    try:
        result = int(value)
    except ValueError as error:
        raise ReportError(f"{source} has non-integer {key}={value!r}") from error
    if result < 0 or str(result) != value:
        raise ReportError(f"{source} has non-canonical {key}={value!r}")
    return result


def pinned_cpu(record: dict[str, str], source: str) -> int:
    value = require(record, "environment.pinned_cpu", source)
    if value == "not-observed":
        raise ReportError(
            f"{source} did not observe a single pinned CPU; "
            "the GCP measurement is inadmissible"
        )
    return integer(record, "environment.pinned_cpu", source)


def role_cpu_allocation(record: dict[str, str], source: str, *, parallel_setup: bool = False) -> tuple[int, str]:
    threading = require(record, "environment.threading", source)
    if threading == "setup-worker-pool" and parallel_setup:
        workers = integer(record, "environment.worker_threads", source)
        affinity = require(record, "environment.cpu_affinity", source)
        parts = affinity.split(",")
        try:
            cpus = [int(part) for part in parts]
        except ValueError as error:
            raise ReportError("setup has an invalid CPU affinity list") from error
        if (not 2 <= workers <= 256 or len(cpus) != workers or
                any(cpu < 0 or str(cpu) != part for cpu, part in zip(cpus, parts)) or
                any(a >= b for a, b in zip(cpus, cpus[1:])) or
                "environment.pinned_cpu" in record):
            raise ReportError("setup worker count and CPU affinity are inconsistent")
        return workers, affinity
    if threading != "single-cpu-process":
        raise ReportError(f"{source} does not report single-CPU execution")
    if ("environment.worker_threads" in record and
            integer(record, "environment.worker_threads", source) != 1):
        raise ReportError(f"{source} reports multiple workers for single-CPU execution")
    cpu = pinned_cpu(record, source)
    if ("environment.cpu_affinity" in record and
            record["environment.cpu_affinity"] != str(cpu)):
        raise ReportError(f"{source} CPU affinity disagrees with its pinned CPU")
    return 1, str(cpu)


def integer_list(
    record: dict[str, str], key: str, source: str, *, allow_zero: bool = False,
) -> list[int]:
    value = require(record, key, source)
    if not value:
        raise ReportError(f"{source} has an empty {key}")
    parts = value.split(",")
    try:
        result = [int(part) for part in parts]
    except ValueError as error:
        raise ReportError(f"{source} has a non-integer {key}={value!r}") from error
    if any(item < 0 or (item == 0 and not allow_zero) for item in result) or (
        ",".join(map(str, result)) != value
    ):
        raise ReportError(f"{source} has a non-canonical {key}={value!r}")
    return result


def require_exit_zero(path: Path) -> None:
    record = parse_record(path)
    if record != {"process.exit_status": "0"}:
        raise ReportError(f"{path} is not the canonical zero-exit record")


STORAGE_STATIC_KEYS = (
    "storage.backend",
    "storage.artifact_root",
    "storage.mount_source",
    "storage.mount_target",
    "storage.filesystem_type",
    "storage.filesystem_total_bytes",
)

LOCAL_SSD_STATIC_KEYS = (
    "storage.local_ssd.raid_level",
    "storage.local_ssd.raid_member_count",
    "storage.local_ssd.raid_degraded_members",
    "storage.local_ssd.raid_chunk_bytes",
    "storage.local_ssd.raid_members",
)

DEDICATED_BLOCK_STATIC_KEYS = (
    "storage.dedicated_block.device",
    "storage.dedicated_block.device_type",
    "storage.dedicated_block.device_ancestry",
    "storage.dedicated_block.protected_ancestry",
)

SHARED_ROOT_STATIC_KEYS = (
    "storage.shared_root.directory",
    "storage.shared_root.shares_os",
)


def nonempty_name_list(
    record: dict[str, str], key: str, source: str, *, sorted_unique: bool,
) -> list[str]:
    raw = require(record, key, source)
    values = raw.split(",")
    if any(not value for value in values):
        raise ReportError(f"{source} has an invalid {key}")
    if len(values) != len(set(values)):
        raise ReportError(f"{source} has duplicate values in {key}")
    if sorted_unique and values != sorted(values):
        raise ReportError(f"{source} has a non-canonical {key}")
    return values


def target_storage_snapshot(path: Path, phase: str) -> dict[str, str]:
    record = parse_record(path)
    source = f"{phase} storage provenance"
    if require(record, "format", source) != "laminate-storage-provenance-v2":
        raise ReportError(f"{source} has an unsupported format")
    if require(record, "storage.capture_phase", source) != phase:
        raise ReportError(f"{source} has the wrong capture phase")
    timestamp = require(record, "storage.captured_at_utc", source)
    try:
        parsed_timestamp = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        parsed_timestamp = parsed_timestamp.replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ReportError(f"{source} has a non-canonical UTC timestamp") from error
    if parsed_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") != timestamp:
        raise ReportError(f"{source} has a non-canonical UTC timestamp")

    backend = require(record, "storage.backend", source)
    if backend not in {
        "google-local-ssd-raid0",
        "dedicated-block",
        "shared-root-filesystem",
    }:
        raise ReportError(f"{source} has an unsupported storage backend")

    artifact_root = Path(require(record, "storage.artifact_root", source))
    mount_source = Path(require(record, "storage.mount_source", source))
    mount_target = Path(require(record, "storage.mount_target", source))
    if (
        not artifact_root.is_absolute()
        or not mount_source.is_absolute()
        or not mount_target.is_absolute()
        or Path("/") in (artifact_root, mount_source)
        or (mount_target == Path("/") and backend != "shared-root-filesystem")
        or any(
            path != Path(os.path.normpath(path))
            for path in (artifact_root, mount_source, mount_target)
        )
        or mount_target not in artifact_root.parents
    ):
        raise ReportError(f"{source} has invalid absolute storage paths")
    if backend == "shared-root-filesystem" and mount_target != Path("/"):
        raise ReportError(
            f"{source} must use / as storage.mount_target for shared-root storage"
        )
    if require(record, "storage.filesystem_type", source) != "ext4":
        raise ReportError(f"{source} does not report ext4")
    mount_options = require(record, "storage.mount_options", source).split(",")
    if (
        any(not option for option in mount_options)
        or len(mount_options) != len(set(mount_options))
        or "rw" not in mount_options
        or (
            backend != "shared-root-filesystem"
            and "noatime" not in mount_options
        )
    ):
        raise ReportError(f"{source} does not report the required mount options")
    total = integer(record, "storage.filesystem_total_bytes", source)
    available = integer(record, "storage.filesystem_available_bytes", source)
    if total <= 0 or available > total:
        raise ReportError(f"{source} has invalid filesystem capacity")

    if backend == "google-local-ssd-raid0":
        member_count = integer(
            record, "storage.local_ssd.raid_member_count", source
        )
        if (
            require(record, "storage.local_ssd.raid_level", source) != "raid0"
            or member_count < 2
            or integer(
                record, "storage.local_ssd.raid_degraded_members", source
            ) != 0
            or integer(record, "storage.local_ssd.raid_chunk_bytes", source)
            != 524_288
        ):
            raise ReportError(f"{source} is not a healthy Local SSD RAID0")
        members = nonempty_name_list(
            record,
            "storage.local_ssd.raid_members",
            source,
            sorted_unique=True,
        )
        if len(members) != member_count:
            raise ReportError(
                f"{source} RAID member list does not match its member count"
            )
    elif backend == "dedicated-block":
        device = Path(require(record, "storage.dedicated_block.device", source))
        if (
            not device.is_absolute()
            or device == Path("/")
            or device != Path(os.path.normpath(device))
            or device != mount_source
            or require(record, "storage.dedicated_block.device_type", source)
            != "disk"
        ):
            raise ReportError(
                f"{source} does not describe a dedicated whole block device"
            )
        nonempty_name_list(
            record,
            "storage.dedicated_block.device_ancestry",
            source,
            sorted_unique=False,
        )
        nonempty_name_list(
            record,
            "storage.dedicated_block.protected_ancestry",
            source,
            sorted_unique=False,
        )
    elif backend == "shared-root-filesystem":
        shared_directory = Path(
            require(record, "storage.shared_root.directory", source)
        )
        if (
            not shared_directory.is_absolute()
            or shared_directory == Path("/")
            or shared_directory != Path(os.path.normpath(shared_directory))
            or shared_directory != Path("/var/lib/laminate-storage")
        ):
            raise ReportError(
                f"{source} shared-root storage must use "
                "/var/lib/laminate-storage"
            )
        if require(record, "storage.shared_root.shares_os", source) != "true":
            raise ReportError(
                f"{source} does not acknowledge shared OS filesystem and I/O"
            )
        if artifact_root != shared_directory / "laminate-bench":
            raise ReportError(
                f"{source} shared-root artifact storage must be exactly "
                "STORAGE/laminate-bench"
            )
    else:
        raise ReportError(f"{source} has an unsupported storage backend")
    return record


def target_storage_pair(run: Path) -> tuple[dict[str, str], dict[str, str]]:
    setup = target_storage_snapshot(
        run / "shared" / "storage-provenance.setup-start.txt", "setup-start"
    )
    server = target_storage_snapshot(
        run / "shared" / "storage-provenance.server-start.txt", "server-start"
    )
    for key in STORAGE_STATIC_KEYS:
        if require(setup, key, "setup-start storage provenance") != require(
            server, key, "server-start storage provenance"
        ):
            raise ReportError(f"setup/server storage provenance disagrees on {key}")
    setup_options = set(
        require(setup, "storage.mount_options", "setup storage provenance").split(",")
    )
    server_options = set(
        require(server, "storage.mount_options", "server storage provenance").split(",")
    )
    if setup_options != server_options:
        raise ReportError(
            "setup/server storage provenance disagrees on storage.mount_options"
        )
    backend = require(setup, "storage.backend", "setup storage provenance")
    if backend == "google-local-ssd-raid0":
        backend_keys = LOCAL_SSD_STATIC_KEYS
    elif backend == "dedicated-block":
        backend_keys = DEDICATED_BLOCK_STATIC_KEYS
    elif backend == "shared-root-filesystem":
        backend_keys = SHARED_ROOT_STATIC_KEYS
    else:
        raise ReportError("setup storage provenance has an unsupported backend")
    for key in backend_keys:
        if require(setup, key, "setup-start storage provenance") != require(
            server, key, "server-start storage provenance"
        ):
            raise ReportError(f"setup/server storage provenance disagrees on {key}")
    setup_time = require(setup, "storage.captured_at_utc", "setup storage")
    server_time = require(server, "storage.captured_at_utc", "server storage")
    if server_time < setup_time:
        raise ReportError("server-start storage provenance predates setup-start")
    return setup, server


def target_storage_report_rows(
    setup: dict[str, str], server: dict[str, str],
) -> list[str]:
    """Render the validated storage backend without assuming one topology."""
    rows = [
        f"| Backend | `{require(setup, 'storage.backend', 'setup storage')}` |",
        f"| Artifact root | `{require(setup, 'storage.artifact_root', 'setup storage')}` |",
        f"| Mount | `{require(setup, 'storage.mount_source', 'setup storage')}` on `{require(setup, 'storage.mount_target', 'setup storage')}` |",
        f"| Filesystem | `{require(setup, 'storage.filesystem_type', 'setup storage')}` (`{require(setup, 'storage.mount_options', 'setup storage')}`) |",
        f"| Filesystem capacity | {bytes_text(integer(setup, 'storage.filesystem_total_bytes', 'setup storage'))} |",
    ]
    backend = require(setup, "storage.backend", "setup storage")
    if backend == "google-local-ssd-raid0":
        rows.extend(
            [
                f"| Healthy Local SSD RAID0 members | {integer(setup, 'storage.local_ssd.raid_member_count', 'setup storage')} (`{require(setup, 'storage.local_ssd.raid_members', 'setup storage')}`) |",
                f"| RAID0 chunk | {bytes_text(integer(setup, 'storage.local_ssd.raid_chunk_bytes', 'setup storage'))} |",
            ]
        )
    elif backend == "dedicated-block":
        rows.extend(
            [
                f"| Dedicated whole block device | `{require(setup, 'storage.dedicated_block.device', 'setup storage')}` |",
                f"| Device ancestry | `{require(setup, 'storage.dedicated_block.device_ancestry', 'setup storage')}` |",
                f"| Protected root/boot ancestry | `{require(setup, 'storage.dedicated_block.protected_ancestry', 'setup storage')}` |",
            ]
        )
    elif backend == "shared-root-filesystem":
        rows.extend(
            [
                f"| Shared storage directory | `{require(setup, 'storage.shared_root.directory', 'setup storage')}` |",
                "| Shares OS filesystem and I/O | **true — benchmark artifacts and the operating system share the root filesystem and I/O path.** |",
            ]
        )
    else:
        raise ReportError("setup storage provenance has an unsupported backend")
    rows.extend(
        [
            f"| Available at setup start | {bytes_text(integer(setup, 'storage.filesystem_available_bytes', 'setup storage'))} at `{require(setup, 'storage.captured_at_utc', 'setup storage')}` |",
            f"| Available at server start | {bytes_text(integer(server, 'storage.filesystem_available_bytes', 'server storage'))} at `{require(server, 'storage.captured_at_utc', 'server storage')}` |",
        ]
    )
    return rows


def planner_preflight_ledger(
    setup: dict[str, str],
    storage_provenance: tuple[dict[str, str], dict[str, str]] | None,
    capacity: dict[str, int],
) -> dict[str, int | float | str]:
    """Validate a host-adaptive, formula-derived replay admission record."""
    classification = require(
        setup, "storage.planner_preflight.classification", "setup"
    )
    gross_live = integer(
        setup, "storage.planner_preflight.gross_live_disk_bytes", "setup"
    )
    max_live = integer(
        setup, "storage.planner_preflight.max_live_disk_bytes", "setup"
    )
    min_free = integer(
        setup, "storage.planner_preflight.min_free_disk_bytes", "setup"
    )
    client_private_reserve = integer(
        setup,
        "storage.planner_preflight.client_private_persistent_reserve_bytes",
        "setup",
    )
    server_common_reserve = integer(
        setup, "storage.planner_preflight.server_common_reserve_bytes", "setup"
    )
    required_available = integer(
        setup,
        "storage.planner_preflight.required_available_disk_bytes",
        "setup",
    )
    observed_available = integer(
        setup,
        "storage.planner_preflight.observed_available_disk_bytes",
        "setup",
    )
    selected_peak = integer(
        setup, "storage.planner_preflight.selected_peak_live_bytes", "setup"
    )
    checkpoint_count = integer(
        setup, "storage.planner_preflight.selected_checkpoint_count", "setup"
    )
    checkpoint_bytes = integer(
        setup, "storage.planner_preflight.selected_checkpoint_bytes", "setup"
    )
    initial_work = integer(
        setup, "storage.planner_preflight.initial_forward_work_units", "setup"
    )
    repeated_work = integer(
        setup, "storage.planner_preflight.repeated_work_units", "setup"
    )
    cumulative_work = integer(
        setup, "storage.planner_preflight.cumulative_work_units", "setup"
    )
    recomputation_factor = number(
        setup,
        "storage.planner_preflight.cumulative_recomputation_factor",
        "setup",
    )
    maximum_numerator = integer(
        setup,
        "storage.planner_preflight.maximum_recomputation_numerator",
        "setup",
    )
    maximum_denominator = integer(
        setup,
        "storage.planner_preflight.maximum_recomputation_denominator",
        "setup",
    )
    observed_ram = integer(
        setup, "memory.planner_preflight.observed_physical_ram_bytes", "setup"
    )
    ram_safety_reserve = integer(
        setup, "memory.planner_preflight.safety_reserve_bytes", "setup"
    )
    gross_resident = integer(
        setup,
        "memory.planner_preflight.gross_resident_budget_bytes",
        "setup",
    )
    client_resident_reserve = integer(
        setup,
        "memory.planner_preflight.client_peak_resident_reserve_bytes",
        "setup",
    )
    server_resident_cap = integer(
        setup,
        "memory.planner_preflight.server_resident_cap_bytes",
        "setup",
    )
    exact_gross_live = integer(
        setup, "storage.host_budget.gross_live_disk_bytes", "setup"
    )
    exact_client_private = integer(
        setup,
        "storage.host_budget.exact_client_private_persistent_bytes",
        "setup",
    )
    exact_server_live = integer(
        setup, "storage.host_budget.exact_server_live_disk_bytes", "setup"
    )
    measured_client_private = integer(
        setup, "storage.setup.client_private_persistent_bytes", "setup"
    )
    exact_gross_resident = integer(
        setup,
        "memory.host_budget.gross_resident_budget_bytes",
        "setup",
    )
    exact_client_resident = integer(
        setup,
        "memory.host_budget.exact_client_peak_resident_bytes",
        "setup",
    )
    exact_server_resident = integer(
        setup,
        "memory.host_budget.exact_server_resident_cap_bytes",
        "setup",
    )
    admitted_client_resident = integer(
        setup, "memory.client.admitted_peak_resident_bytes", "setup"
    )
    if (
        classification != "exact-compiled-trace-formula-only"
        or observed_available <= ADAPTIVE_FREE_DISK_RESERVE_BYTES
        or gross_live
        != observed_available - ADAPTIVE_FREE_DISK_RESERVE_BYTES
        or min_free != ADAPTIVE_FREE_DISK_RESERVE_BYTES
        or client_private_reserve <= 0
        or max_live != gross_live - client_private_reserve
        or server_common_reserve != ADAPTIVE_SERVER_COMMON_DISK_RESERVE_BYTES
        or server_common_reserve >= max_live
        or observed_ram <= ADAPTIVE_HOST_RAM_SAFETY_RESERVE_BYTES
        or ram_safety_reserve != ADAPTIVE_HOST_RAM_SAFETY_RESERVE_BYTES
        or gross_resident
        != observed_ram - ADAPTIVE_HOST_RAM_SAFETY_RESERVE_BYTES
        or client_resident_reserve <= 0
        or server_resident_cap
        != gross_resident - client_resident_reserve
        or server_resident_cap <= 0
        or (maximum_numerator, maximum_denominator) != (5, 2)
        or exact_gross_live != gross_live
        or exact_client_private != measured_client_private
        or exact_client_private <= 0
        or exact_client_private > client_private_reserve
        or exact_server_live != gross_live - exact_client_private
        or exact_server_live < max_live
        or exact_server_live != capacity["max_live_disk_bytes"]
        or exact_gross_resident != gross_resident
        or exact_client_resident != admitted_client_resident
        or exact_client_resident <= 0
        or exact_client_resident > client_resident_reserve
        or exact_server_resident
        != gross_resident - exact_client_resident
        or exact_server_resident <= 0
        or exact_server_resident < server_resident_cap
        or exact_server_resident != capacity["max_resident_ram_bytes"]
        or min_free != capacity["min_free_disk_bytes"]
        or required_available
        != max_live + client_private_reserve + min_free
        or required_available != observed_available
    ):
        raise ReportError("planner preflight policy is not the selected policy")
    if (
        observed_available < required_available
        or selected_peak > max_live
        or (checkpoint_count == 0) != (checkpoint_bytes == 0)
        or checkpoint_bytes > selected_peak
        or initial_work == 0
        or cumulative_work != initial_work + repeated_work
        or cumulative_work * maximum_denominator
        > initial_work * maximum_numerator
        or not math.isclose(
            recomputation_factor,
            cumulative_work / initial_work,
            rel_tol=0.0,
            abs_tol=0.000001,
        )
    ):
        raise ReportError("planner preflight ledger is inconsistent")
    if storage_provenance is not None:
        setup_storage, _ = storage_provenance
        if observed_available > integer(
            setup_storage,
            "storage.filesystem_available_bytes",
            "setup-start storage provenance",
        ):
            raise ReportError(
                "planner preflight available bytes exceed the setup-start snapshot"
            )
    return {
        "classification": classification,
        "gross_live": gross_live,
        "max_live": max_live,
        "min_free": min_free,
        "client_private_reserve": client_private_reserve,
        "server_common_reserve": server_common_reserve,
        "exact_client_private": exact_client_private,
        "exact_server_live": exact_server_live,
        "required_available": required_available,
        "observed_available": observed_available,
        "selected_peak": selected_peak,
        "checkpoint_count": checkpoint_count,
        "checkpoint_bytes": checkpoint_bytes,
        "initial_work": initial_work,
        "repeated_work": repeated_work,
        "cumulative_work": cumulative_work,
        "recomputation_factor": recomputation_factor,
        "maximum_numerator": maximum_numerator,
        "maximum_denominator": maximum_denominator,
        "observed_ram": observed_ram,
        "ram_safety_reserve": ram_safety_reserve,
        "gross_resident": gross_resident,
        "client_resident_reserve": client_resident_reserve,
        "server_resident_cap": server_resident_cap,
        "exact_client_resident": exact_client_resident,
        "exact_server_resident": exact_server_resident,
    }


def validate_replay_plan_ledger(
    setup: dict[str, str],
    capacity: dict[str, int],
    maximum_recomputation: tuple[int, int] | None,
) -> dict[str, int | float]:
    checkpoint_bytes = integer(
        setup, "storage.replay.selected_checkpoint_bytes", "setup"
    )
    persistent_reserve = integer(
        setup, "storage.replay.persistent_reserve_bytes", "setup"
    )
    consumer_artifact = integer(
        setup, "storage.replay.maximum_consumer_artifact_bytes", "setup"
    )
    admitted_peak = integer(
        setup, "storage.replay.admitted_peak_live_bytes", "setup"
    )
    alias_cache_resident_peak = integer(
        setup,
        "memory.replay.dense_multiplication_alias_cache_peak_resident_bytes",
        "setup",
    )
    admitted_resident_peak = integer(
        setup, "memory.replay.admitted_peak_resident_bytes", "setup"
    )
    initial = integer(setup, "work.replay.initial_forward_units", "setup")
    repeated = integer(setup, "work.replay.repeated_units", "setup")
    cumulative = integer(setup, "work.replay.cumulative_units", "setup")
    factor = number(setup, "work.replay.cumulative_factor", "setup")
    if (
        initial == 0
        or cumulative != initial + repeated
        or not math.isclose(
            factor, cumulative / initial, rel_tol=0.0, abs_tol=0.000001
        )
        or checkpoint_bytes > admitted_peak
        or persistent_reserve > admitted_peak
        or consumer_artifact > admitted_peak
        or admitted_peak > capacity["max_live_disk_bytes"]
        or alias_cache_resident_peak > admitted_resident_peak
        or admitted_resident_peak > capacity["max_resident_ram_bytes"]
    ):
        raise ReportError("setup checkpoint-replay plan ledger is inconsistent")
    if maximum_recomputation is not None:
        numerator, denominator = maximum_recomputation
        if (
            numerator <= 0
            or denominator <= 0
            or cumulative * denominator > initial * numerator
        ):
            raise ReportError(
                "setup checkpoint-replay plan exceeds the planner work ceiling"
            )
    return {
        "checkpoint_bytes": checkpoint_bytes,
        "persistent_reserve": persistent_reserve,
        "consumer_artifact": consumer_artifact,
        "admitted_peak": admitted_peak,
        "alias_cache_resident_peak": alias_cache_resident_peak,
        "admitted_resident_peak": admitted_resident_peak,
        "initial": initial,
        "repeated": repeated,
        "cumulative": cumulative,
        "factor": factor,
    }


def replay_plan_ledger_present(
    setup: dict[str, str], keys: tuple[str, ...], *, required: bool
) -> bool:
    presence = [key in setup for key in keys]
    if (required and not all(presence)) or (any(presence) and not all(presence)):
        raise ReportError("setup has an incomplete checkpoint-replay plan ledger")
    return all(presence)


def milliseconds(value: float) -> str:
    seconds = value / 1000.0
    if seconds < 60:
        return f"{seconds:.3f} s"
    minutes, remainder = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)} m {remainder:.3f} s"
    hours, remainder_minutes = divmod(int(minutes), 60)
    return f"{hours} h {remainder_minutes} m {remainder:.3f} s"


def bytes_text(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    scaled = float(value)
    unit = units[0]
    for candidate in units[1:]:
        if scaled < 1024.0:
            break
        scaled /= 1024.0
        unit = candidate
    return f"{value:,} B ({scaled:.3f} {unit})" if unit != "B" else f"{value:,} B"


def utilization(cpu_ms: float, wall_ms: float) -> str:
    return "n/a" if wall_ms == 0 else f"{100.0 * cpu_ms / wall_ms:.1f}%"


def throughput(byte_count: int, wall_ms: float) -> str:
    if wall_ms == 0:
        return "n/a"
    return f"{1000.0 * byte_count / (1024.0 * 1024.0) / wall_ms:.1f} MiB/s"


def ratio_text(numerator: int | float, denominator: int | float) -> str:
    if denominator <= 0:
        raise ReportError("cannot report a ratio with a zero denominator")
    return f"{numerator / denominator:.3f}x"


def power_of_two_log(value: int, label: str) -> int:
    if value <= 0 or value & (value - 1):
        raise ReportError(f"{label} is not a positive power of two")
    return value.bit_length() - 1


def packing_r1cs_geometry(
    record: dict[str, str], prefix: str, source: str,
) -> dict[str, int | str]:
    result: dict[str, int | str] = {
        field: integer(record, f"{prefix}.{field}", source)
        for field in PACKING_R1CS_INTEGER_FIELDS
    }
    result["ciphertext_hash"] = require(
        record, f"{prefix}.ciphertext_hash", source
    )
    validate_packing_r1cs_geometry(result, f"{source} {prefix}")
    return result


def validate_packing_r1cs_geometry(
    result: dict[str, int | str], label: str,
) -> None:

    aligned = int(result["aligned_ciphertexts"])
    per_ciphertext = int(
        result["ciphertext_commitment_constraints_per_ciphertext"]
    )
    commitment = int(result["ciphertext_commitment_constraints_total"])
    packing = int(result["packing_relation_constraints"])
    active = int(result["active_constraints"])
    matrix_rows = int(result["matrix_rows"])
    padded = int(result["spartan_padded_constraints"])
    assignment_half = int(result["spartan_assignment_half_size"])
    padded_assignment = int(result["spartan_padded_assignment_variables"])
    for field in (
        "aligned_ciphertexts",
        "physical_packed_ciphertexts",
        "packing_digit_count",
    ):
        if int(result[field]) <= 0:
            raise ReportError(f"{label} {field} is not positive")
    if commitment != aligned * per_ciphertext:
        raise ReportError(
            f"{label} commitment constraints do not equal "
            "aligned ciphertexts times the per-ciphertext relation"
        )
    if active != commitment + packing:
        raise ReportError(
            f"{label} active constraints do not equal the "
            "commitment and packing-relation sum"
        )
    if matrix_rows < active:
        raise ReportError(f"{label} matrix row extent is too small")
    expected_padded = 1 << (matrix_rows - 1).bit_length()
    if padded != expected_padded:
        raise ReportError(
            f"{label} Spartan constraint domain is not the "
            "smallest power of two containing the matrix rows"
        )
    power_of_two_log(assignment_half, f"{label} assignment half")
    if padded_assignment != 2 * assignment_half:
        raise ReportError(
            f"{label} padded assignment is not twice its half"
        )


def unique_telemetry_span(
    record: dict[str, str], name: str, source: str,
) -> tuple[float, float]:
    if require(record, "telemetry.schema", source) != "laminate-protocol-progress-v1":
        raise ReportError(f"{source} published an unsupported telemetry schema")
    if require(record, "telemetry.logging_status", source) != "complete":
        raise ReportError(f"{source} protocol telemetry did not complete")
    count = integer(record, "telemetry.completed_spans", source)
    matches: list[tuple[float, float]] = []
    for index in range(count):
        prefix = f"telemetry.span.{index}"
        if require(record, f"{prefix}.name", source) == name:
            matches.append(
                (
                    number(record, f"{prefix}.wall_ms", source),
                    number(record, f"{prefix}.cpu_ms", source),
                )
            )
    if len(matches) != 1:
        raise ReportError(
            f"{source} must publish exactly one completed {name!r} span"
        )
    return matches[0]


def timing_pair(record: dict[str, str], prefix: str, source: str) -> tuple[float, float]:
    return (
        number(record, f"{prefix}.wall_ms", source),
        number(record, f"{prefix}.cpu_ms", source),
    )


def require_timing_sum(
    record: dict[str, str],
    total_prefix: str,
    component_prefixes: tuple[str, ...],
    source: str,
) -> None:
    total = timing_pair(record, total_prefix, source)
    components = [
        timing_pair(record, prefix, source) for prefix in component_prefixes
    ]
    expected = tuple(
        sum(value[index] for value in components) for index in (0, 1)
    )
    for label, measured, computed in zip(("wall", "CPU"), total, expected):
        if not math.isclose(measured, computed, rel_tol=0.0, abs_tol=0.001):
            raise ReportError(
                f"{source} {total_prefix} {label} total {measured} does not equal "
                f"the declared phase sum {computed}"
            )


CLIENT_COMPUTATION_SCHEMA = "vcoed-client-computation-v1"
CLIENT_COMPUTATION_FIELDS = (
    "encrypt_inputs", "decrypt_output", "computation_total", "per_request_total",
    "verify.vcoed", "verify.gkr", "verify.gkr.transcript_recovery",
    "verify.gkr.plaintext", "verify.terminal_input_mle",
    "verify.transcript_packing_snark", "verify.well_formedness_noise",
)


def client_computation_ledger(record: dict[str, str]) -> dict[str, tuple[float, float]]:
    marker = record.get("timing.client.computation.schema")
    if marker is None:
        raise ReportError("client computation timing schema is missing")
    if marker != CLIENT_COMPUTATION_SCHEMA:
        raise ReportError("unknown client computation timing schema")
    ledger = {field: timing_pair(record, f"timing.client.{field}", "client")
              for field in CLIENT_COMPUTATION_FIELDS}
    for total, children in (
        ("verify.gkr", ("verify.gkr.transcript_recovery", "verify.gkr.plaintext")),
        ("verify.vcoed", ("verify.gkr", "verify.terminal_input_mle",
                          "verify.transcript_packing_snark", "verify.well_formedness_noise")),
        ("computation_total", ("encrypt_inputs", "decrypt_output", "verify.vcoed")),
        ("per_request_total", ("computation_total",)),
    ):
        # Each independently rounded three-decimal timer contributes <=0.0005ms.
        tolerance = 0.0005 * (len(children) + 1) + 1e-9
        for index in (0, 1):
            if abs(ledger[total][index] - sum(ledger[c][index] for c in children)) > tolerance:
                raise ReportError(f"client computation ledger does not reconcile {total}")
    return ledger


def client_computation_table(record: dict[str, str], ledger: dict[str, tuple[float, float]]) -> list[str]:
    rows = (
        ("Per-request client computation", "computation_total"),
        ("Input encryption", "encrypt_inputs"),
        ("Output decryption", "decrypt_output"),
        ("VCoED proof verification", "verify.vcoed"),
        ("↳ GKR proof verification", "verify.gkr"),
        ("↳↳ Transcript recovery (FS, decryption, plaintext assembly)", "verify.gkr.transcript_recovery"),
        ("↳↳ Plaintext GKR and affine gate-opening checks", "verify.gkr.plaintext"),
        ("↳ Terminal input MLE", "verify.terminal_input_mle"),
        ("↳ Spartan packing argument", "verify.transcript_packing_snark"),
        ("↳ Well-formedness noise checks", "verify.well_formedness_noise"),
    )
    result = ["", "## Client computation", "", "| Component | Wall | CPU |", "|---|---:|---:|"]
    for label, field in rows:
        measured = ledger[field]
        result.append(f"| {label} | {milliseconds(measured[0])} | {milliseconds(measured[1])} |")
    result.extend(["",
        "Client computation is input encryption + output decryption + VCoED proof verification. "
        "Preprocessing RAM loading, transport, peer waiting, and the optional output-noise audit are excluded. "
        "Verification rows form a hierarchy: add siblings only. Packed transcript recovery includes "
        "signed-digit recomposition into logical plaintexts.", ""])
    return result


def require_scope(
    record: dict[str, str], key: str, expected: str, source: str,
) -> str:
    actual = require(record, key, source)
    if actual != expected:
        raise ReportError(f"{source} has an unexpected {key} cost boundary")
    return actual


def require_exact_prefixed_keys(
    record: dict[str, str], prefix: str, expected: set[str] | frozenset[str],
    source: str,
) -> None:
    actual = {key for key in record if key.startswith(prefix)}
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected {', '.join(unexpected)}")
        raise ReportError(
            f"{source} has a noncanonical {prefix} schema: {'; '.join(details)}"
        )


def setup_timing_rows(
    record: dict[str, str], source: str,
) -> list[tuple[str, float, float]]:
    expected = {
        "timing.setup.started_unix_ms",
        "timing.setup.finished_unix_ms",
        "timing.setup.total.wall_ms",
        "timing.setup.total.cpu_ms",
    }
    for phase in SETUP_TIMING_PHASES:
        expected.add(f"timing.setup.{phase}.wall_ms")
        expected.add(f"timing.setup.{phase}.cpu_ms")
    if record.get("schedule.proof_ingress_policy") == FOLDED_PYRAMID_PROOF_INGRESS_POLICY:
        validate_folded_pyramid_preflight(record)
        # Already included in workload_compilation; validate the component
        # without adding it to the disjoint timing rows a second time.
        expected.update({"timing.setup.live_key_noise_preflight.wall_ms",
                         "timing.setup.live_key_noise_preflight.cpu_ms"})
    require_exact_prefixed_keys(record, "timing.setup.", expected, source)
    return [
        (phase, *timing_pair(record, f"timing.setup.{phase}", source))
        for phase in SETUP_TIMING_PHASES
    ]


def verifier_layer_rows(
    record: dict[str, str], proof_depth: int, source: str,
) -> list[tuple[int, str, float, float]]:
    expected_count = 2 * proof_depth + 1
    layer_count = integer(
        record, "timing.client.verify.layer_count", source
    )
    if layer_count != expected_count:
        raise ReportError(
            f"{source} verifier layer count {layer_count} does not match "
            f"the expected {expected_count} reductions"
        )

    expected_keys: set[str] = set()
    rows: list[tuple[int, str, float, float]] = []
    for index in range(layer_count):
        prefix = f"timing.client.verify.layer.{index}"
        expected_keys.update(
            {
                f"{prefix}.circuit_layer",
                f"{prefix}.kind",
                f"{prefix}.wall_ms",
                f"{prefix}.cpu_ms",
            }
        )
        circuit_layer = integer(record, f"{prefix}.circuit_layer", source)
        if circuit_layer != index:
            raise ReportError(
                f"{source} verifier row {index} names circuit layer "
                f"{circuit_layer}; expected {index}"
            )
        expected_kind = "affine" if index % 2 == 0 else "multiplication"
        kind = require(record, f"{prefix}.kind", source)
        if kind != expected_kind:
            raise ReportError(
                f"{source} verifier layer {index} has kind {kind!r}; "
                f"expected {expected_kind!r}"
            )
        wall, cpu = timing_pair(record, prefix, source)
        rows.append((circuit_layer, kind, wall, cpu))

    actual_keys = {
        key
        for key in record
        if key.startswith("timing.client.verify.layer.")
    }
    if actual_keys != expected_keys:
        unexpected = sorted(actual_keys - expected_keys)
        raise ReportError(
            f"{source} has unexpected verifier layer fields: "
            f"{', '.join(unexpected)}"
        )
    return rows


def require_canonical_transcript(run: Path) -> dict[str, int]:
    transcript = run / "shared" / "transcript"
    try:
        transcript_status = os.lstat(transcript)
        entries = list(transcript.iterdir())
    except OSError as error:
        raise ReportError(f"cannot inspect protocol transcript: {error}") from error
    if not stat.S_ISDIR(transcript_status.st_mode):
        raise ReportError("shared/transcript is not a real directory")
    expected = {"cli-to-srv-request.bin", "srv-to-cli-response.bin"}
    actual = {entry.name for entry in entries}
    if actual != expected:
        raise ReportError(
            "protocol transcript must contain exactly one canonical request "
            "and one canonical response"
        )
    sizes: dict[str, int] = {}
    for entry in entries:
        try:
            entry_status = os.lstat(entry)
        except OSError as error:
            raise ReportError(
                f"cannot inspect transcript artifact {entry}: {error}"
            ) from error
        if not stat.S_ISREG(entry_status.st_mode):
            raise ReportError(
                f"transcript artifact is not a regular file: {entry.name}"
            )
        sizes[entry.name] = entry_status.st_size
    return sizes


def timing_rows(
    record: dict[str, str], prefix: str, source: str,
    excluded: set[str] | None = None,
) -> list[tuple[str, float, float]]:
    excluded = excluded or set()
    rows: list[tuple[str, float, float]] = []
    suffix = ".wall_ms"
    for key in sorted(record):
        if not key.startswith(prefix) or not key.endswith(suffix):
            continue
        stem = key[: -len(suffix)]
        if stem in excluded:
            continue
        cpu_key = f"{stem}.cpu_ms"
        if cpu_key not in record:
            raise ReportError(f"timing {stem} has wall time but no CPU time")
        rows.append(
            (
                stem[len(prefix) :].lstrip("."),
                number(record, key, source),
                number(record, cpu_key, source),
            )
        )
    return rows


def table_timing(rows: list[tuple[str, float, float]]) -> list[str]:
    output = ["| Phase | Wall | CPU |", "|---|---:|---:|"]
    for name, wall, cpu in rows:
        output.append(
            f"| `{name.replace('_', ' ')}` | {milliseconds(wall)} | {milliseconds(cpu)} |"
        )
    return output


def table_verifier_layers(
    rows: list[tuple[int, str, float, float]],
) -> list[str]:
    output = [
        "| Circuit layer | Kind | Wall | CPU |",
        "|---:|---|---:|---:|",
    ]
    for layer, kind, wall, cpu in rows:
        output.append(
            f"| {layer} | `{kind}` | {milliseconds(wall)} | {milliseconds(cpu)} |"
        )
    return output


def operation_rows(
    record: dict[str, str], stage: str, source: str,
) -> list[tuple[str, int, int, str]]:
    prefix = f"operations.{stage}."
    suffix = ".calls"
    rows: list[tuple[str, int, int, str]] = []
    for key in sorted(record):
        if not key.startswith(prefix) or not key.endswith(suffix):
            continue
        operation = key[len(prefix) : -len(suffix)]
        limb_key = f"{prefix}{operation}.limb_operations"
        buckets_key = f"{prefix}{operation}.by_rns_limb"
        calls = integer(record, key, source)
        limb_operations = integer(record, limb_key, source)
        buckets = require(record, buckets_key, source)
        parsed_buckets: list[tuple[int, int]] = []
        if buckets != "none":
            try:
                for bucket in buckets.split(","):
                    limbs_text, calls_text = bucket.split(":", 1)
                    limbs = int(limbs_text)
                    bucket_calls = int(calls_text)
                    if (
                        limbs <= 0
                        or bucket_calls <= 0
                        or f"{limbs}:{bucket_calls}" != bucket
                    ):
                        raise ValueError
                    parsed_buckets.append((limbs, bucket_calls))
            except ValueError as error:
                raise ReportError(
                    f"{source} has invalid operation buckets {buckets_key}={buckets!r}"
                ) from error
        if sum(count for _, count in parsed_buckets) != calls or sum(
            limbs * count for limbs, count in parsed_buckets
        ) != limb_operations:
            raise ReportError(
                f"{source} operation buckets do not reconcile for {operation}"
            )
        rows.append(
            (
                operation,
                calls,
                limb_operations,
                buckets,
            )
        )
    if not rows:
        raise ReportError(f"{source} omitted {stage} FHE operation counts")
    return rows


def current_gkr_multiplication(
    setup: dict[str, str], server: dict[str, str], client: dict[str, str],
) -> bool:
    sources = (("setup", setup), ("server", server), ("client", client))
    key = "protocol.gkr_multiplication"
    values = {require(record, key, source) for source, record in sources}
    if len(values) != 1:
        raise ReportError(f"setup/server/client disagree on {key}")
    if values.pop() != GKR_MULTIPLICATION:
        raise ReportError(f"unknown {key}")
    return True


def gkr_claim_transition(
    setup: dict[str, str], server: dict[str, str], client: dict[str, str],
) -> str:
    sources = (("setup", setup), ("server", server), ("client", client))
    key = "protocol.gkr_claim_transition"
    values = {require(record, key, source) for source, record in sources}
    if len(values) != 1:
        raise ReportError(f"setup/server/client disagree on {key}")
    transition = values.pop()
    if transition != GKR_CLAIM_TRANSITION:
        raise ReportError("unknown GKR claim transition")
    return transition


def packed_fiat_shamir_schedule(
    setup: dict[str, str], server: dict[str, str], client: dict[str, str],
) -> str:
    sources = (("setup", setup), ("server", server), ("client", client))
    key = "protocol.fiat_shamir"
    values = {require(record, key, source) for source, record in sources}
    if len(values) != 1:
        raise ReportError(f"setup/server/client disagree on {key}")
    schedule = values.pop()
    if schedule != PACKED_FIAT_SHAMIR_SCHEDULE:
        raise ReportError("unknown packed Fiat–Shamir schedule")
    return schedule


def common_identity(
    setup: dict[str, str], server: dict[str, str], client: dict[str, str],
    variant: str, profile: str,
) -> None:
    sources = (("setup", setup), ("server", server), ("client", client))
    expected = {
        "protocol.variant": variant,
        "benchmark.profile": profile,
        "run.variant": variant,
        "run.profile": profile,
    }
    for source, record in sources:
        for key, value in expected.items():
            if require(record, key, source) != value:
                raise ReportError(f"{source} does not bind {key}={value}")
    shared_keys = (
        "run.id",
        "benchmark.evidence",
        "security.transcript_packing.actual_repetitions",
        "security.transcript_packing.selected_repetitions",
        "security.basefold.actual_queries",
        "security.basefold.selected_queries",
        "security.claim",
        "protocol.ciphertext_hash",
        "security.ciphertext_hash.claim",
        "schedule.policy",
        "schedule.proof_ingress_policy",
        "schedule.proof_ingress_schedule_digest",
        "schedule.proof_ingress_rns_limbs_by_layer",
        "schedule.payload_modulus_switches_after_layer",
        "geometry.N",
        "geometry.B",
        "geometry.depth",
        "geometry.workload",
        "geometry.width",
        "geometry.inputs",
        "geometry.outputs",
        "geometry.payload_operations",
        "geometry.payload_add_gates",
        "geometry.payload_add_plain_gates",
        "geometry.payload_mul_gates",
        "fhe.data_rns_limbs",
        "fhe.plain_modulus",
        "fhe.data_prime_bit_sizes",
        "fhe.data_primes_bottom_to_top",
        "fhe.special_prime_bits",
        "fhe.special_prime",
        "fhe.fresh_modulus_product_bits",
        "fhe.key_modulus_product_bits",
        "environment.git_commit",
        "environment.build_type",
        "environment.seal_acceleration",
        "environment.git_dirty",
        "environment.compiler",
        "environment.seal_version",
        "environment.fhe_backend",
        "environment.trace_execution",
        "environment.os",
        "environment.cpu",
        "environment.physical_cores",
        "environment.logical_cores",
        "environment.ram_bytes",
        "environment.cpu_features.probe",
        "environment.cpu_features.avx2_available",
        "environment.cpu_features.avx512f_available",
        "environment.cpu_features.avx512dq_available",
        "environment.cpu_features.avx512ifma_available",
    )
    for key in shared_keys:
        values = {require(record, key, source) for source, record in sources}
        if len(values) != 1:
            raise ReportError(f"setup/server/client disagree on {key}")
    for key in ("geometry.payload_mul_plain_gates",
                "geometry.payload_rotate_gates"):
        if any(key in record for _, record in sources):
            values = {require(record, key, source) for source, record in sources}
            if len(values) != 1:
                raise ReportError(f"setup/server/client disagree on {key}")
    gate_basefold_keys = (
        "parameters.gate_mle_basefold_log_rate",
        "parameters.gate_mle_basefold_queries",
    )
    if any(key in record for _, record in sources for key in gate_basefold_keys):
        for key in gate_basefold_keys:
            values = {require(record, key, source) for source, record in sources}
            if len(values) != 1:
                raise ReportError(f"setup/server/client disagree on {key}")
    policy_keys = ("security.basefold.bound_model", "security.basefold.target_bits")
    if any(key in record for _, record in sources for key in policy_keys):
        for key in policy_keys:
            values = {require(record, key, source) for source, record in sources}
            if len(values) != 1:
                raise ReportError(f"setup/server/client disagree on {key}")
    sha256_providers = [
        record.get("environment.sha256_acceleration")
        for _, record in sources
    ]
    if any(value is not None for value in sha256_providers) and (
        any(value is None for value in sha256_providers)
        or len(set(sha256_providers)) != 1
    ):
        raise ReportError(
            "setup, server, and client disagree on SHA-256 acceleration"
        )
    basefold_rate_presence = [
        "security.basefold.log_rate" in record for _, record in sources
    ]
    if any(basefold_rate_presence) and not all(basefold_rate_presence):
        raise ReportError(
            "setup/server/client disagree on the presence of "
            "security.basefold.log_rate"
        )
    if all(basefold_rate_presence):
        values = {
            require(record, "security.basefold.log_rate", source)
            for source, record in sources
        }
        if len(values) != 1:
            raise ReportError(
                "setup/server/client disagree on security.basefold.log_rate"
            )
    run_id = require(setup, "run.id", "setup")
    if len(run_id) != 64 or any(
        character not in "0123456789abcdef" for character in run_id
    ):
        raise ReportError("setup has a non-canonical run.id")


def render(args: argparse.Namespace) -> str:
    run = args.run_dir.resolve(strict=True)
    if not run.is_dir() or not args.run_dir.is_absolute() or run == Path("/"):
        raise ReportError("--run-dir must be an existing absolute directory below root")

    setup_path = run / "shared" / "setup-result.txt"
    server_path = run / "server" / "result.txt"
    client_path = run / "client" / "result.txt"
    setup = parse_record(setup_path)
    server = parse_record(server_path)
    client = parse_record(client_path)
    if require(setup, "format", "setup") != "laminate-packed-benchmark-setup-v1":
        raise ReportError("unsupported packed setup result format")
    if require(server, "format", "server") != "laminate-packed-benchmark-server-v1":
        raise ReportError("unsupported packed server result format")
    if require(client, "format", "client") != "laminate-packed-benchmark-client-v3":
        raise ReportError("unsupported packed client result format")
    if require(setup, "setup.result", "setup") != "PASS":
        raise ReportError("setup result is not PASS")
    if require(server, "server.result", "server") != "PASS":
        raise ReportError("server result is not PASS")
    if require(client, "verification.result", "client") != "PASS":
        raise ReportError("client verification is not PASS")
    require_exit_zero(run / "shared" / "setup-process-exit.txt")
    require_exit_zero(run / "server" / "process-exit.txt")
    require_exit_zero(run / "client" / "process-exit.txt")
    common_identity(setup, server, client, args.variant, args.profile)
    current_gkr_multiplication(setup, server, client)
    multiplication_description = "h(0) messages and stripped terminal product"
    claim_transition = gkr_claim_transition(setup, server, client)
    claim_transition_description = GKR_CLAIM_TRANSITION_DESCRIPTION
    fiat_shamir_schedule = packed_fiat_shamir_schedule(setup, server, client)
    fiat_shamir_description = PACKED_FIAT_SHAMIR_DESCRIPTION
    storage_provenance = target_storage_pair(run) if args.profile != "quick" else None
    binding = parse_record(run / "shared" / "run-binding.txt")
    expected_binding = {
        "format": "laminate-benchmark-run-v1",
        "run.variant": args.variant,
        "run.profile": args.profile,
        "run.id": require(setup, "run.id", "setup"),
    }
    if binding != expected_binding:
        raise ReportError("run binding does not exactly match the accepted role results")
    transcript_sizes = require_canonical_transcript(run)
    for source, record in (("setup", setup), ("server", server), ("client", client)):
        if require(record, "environment.git_dirty", source) != "false":
            raise ReportError(f"{source} was not built from a clean revision")
        if require(record, "environment.fhe_backend", source) != "seal-bgv":
            raise ReportError(f"{source} does not report the SEAL BGV backend")
        acceleration = require(record, "environment.seal_acceleration", source)
        if acceleration != "intel-hexl-runtime-dispatch":
            raise ReportError(f"{source} does not report Intel HEXL")
        for feature in ("avx2", "avx512f", "avx512dq", "avx512ifma"):
            key = f"environment.cpu_features.{feature}_available"
            if require(record, key, source) != "yes":
                raise ReportError(f"{source} does not report required {feature}")
    setup_workers, setup_affinity = role_cpu_allocation(
        setup, "setup", parallel_setup=args.variant == "folded")
    _, server_cpu = role_cpu_allocation(server, "server")
    _, client_cpu = role_cpu_allocation(client, "client")
    if ((setup_workers == 1 and setup_affinity != server_cpu) or
            server_cpu == client_cpu):
        raise ReportError("role CPU affinity does not match the setup/server/client policy")

    if require(setup, "schedule.policy", "setup") != "committed-conservative-no-search":
        raise ReportError("packed setup did not use the committed no-search schedule")
    proof_ingress_policy = require(
        setup, "schedule.proof_ingress_policy", "setup"
    )
    supported_proof_ingress_policies = (
        ("LaminateImpl/ConservativePackedProofIngress/v1", FOLDED_PYRAMID_PROOF_INGRESS_POLICY)
        if args.variant == "folded"
        else (LANED_PROOF_INGRESS_POLICY,)
    )
    if proof_ingress_policy not in supported_proof_ingress_policies:
        raise ReportError(
            "packed setup used an unexpected proof-ingress policy: "
            f"{proof_ingress_policy}"
        )
    proof_ingress_digest = require(
        setup, "schedule.proof_ingress_schedule_digest", "setup"
    )
    if len(proof_ingress_digest) != 64 or any(
        character not in "0123456789abcdef"
        for character in proof_ingress_digest
    ):
        raise ReportError("setup has a non-canonical proof-ingress digest")
    proof_ingress_schedule = integer_list(
        setup, "schedule.proof_ingress_rns_limbs_by_layer", "setup"
    )
    payload_switch_schedule = integer_list(
        setup,
        "schedule.payload_modulus_switches_after_layer",
        "setup",
        allow_zero=True,
    )

    slots = integer(setup, "geometry.N", "setup")
    lanes = integer(setup, "geometry.B", "setup")
    depth = integer(setup, "geometry.depth", "setup")
    width = integer(setup, "geometry.width", "setup")
    inputs = integer(setup, "geometry.inputs", "setup")
    outputs = integer(setup, "geometry.outputs", "setup")
    payload_operations = integer(setup, "geometry.payload_operations", "setup")
    workload = require(setup, "geometry.workload", "setup")
    try:
        expected = profile_geometry(args.profile, workload)
    except ValueError as error:
        raise ReportError(str(error)) from error
    unary_gate_counts = []
    for kind in ("mul_plain", "rotate"):
        key = f"geometry.payload_{kind}_gates"
        unary_gate_counts.append(
            integer(setup, key, "setup")
            if key in setup or is_budgeted_workload(workload) else 0
        )
    payload_gate_counts = (
        integer(setup, "geometry.payload_add_gates", "setup"),
        integer(setup, "geometry.payload_add_plain_gates", "setup"),
        integer(setup, "geometry.payload_mul_gates", "setup"),
        *unary_gate_counts,
    )
    expected_geometry = tuple(
        int(expected[key]) for key in ("depth", "width", "operations")
    )
    expected_workload = expected["workload"]
    expected_gate_counts = gate_counts(expected)
    if (
        slots != 16_384
        or lanes != (args.lanes if args.variant == "laned" else 0)
        or (depth, width, payload_operations) != expected_geometry
        or workload != expected_workload
        or payload_gate_counts != expected_gate_counts
        or inputs != 64
        or outputs != 1
    ):
        raise ReportError("packed workload geometry does not match the fixed profile")
    data_limbs = integer(setup, "fhe.data_rns_limbs", "setup")
    plain_modulus = integer(setup, "fhe.plain_modulus", "setup")
    data_prime_widths = integer_list(setup, "fhe.data_prime_bit_sizes", "setup")
    data_primes = integer_list(setup, "fhe.data_primes_bottom_to_top", "setup")
    special_prime_bits = integer(setup, "fhe.special_prime_bits", "setup")
    special_prime = integer(setup, "fhe.special_prime", "setup")
    fresh_modulus_bits = integer(
        setup, "fhe.fresh_modulus_product_bits", "setup"
    )
    key_modulus_bits = integer(setup, "fhe.key_modulus_product_bits", "setup")
    if plain_modulus != 65537:
        raise ReportError("packed profile does not use the selected plaintext modulus")
    if len(data_prime_widths) != data_limbs or len(data_primes) != data_limbs:
        raise ReportError("FHE data-prime schedule length disagrees with the limb count")
    if any(
        prime.bit_length() != width
        for prime, width in zip(data_primes, data_prime_widths)
    ):
        raise ReportError("an FHE data prime disagrees with its declared bit width")
    if special_prime.bit_length() != special_prime_bits:
        raise ReportError("the FHE special prime disagrees with its declared bit width")
    if len(set((*data_primes, special_prime))) != data_limbs + 1:
        raise ReportError("the FHE coefficient-modulus schedule repeats a prime")
    if any((prime - 1) % (2 * slots) != 0 for prime in (*data_primes, special_prime)):
        raise ReportError("an FHE coefficient prime does not support the selected NTT")
    fresh_modulus = math.prod(data_primes)
    if fresh_modulus.bit_length() != fresh_modulus_bits:
        raise ReportError("the fresh ciphertext modulus bit length is inconsistent")
    if (fresh_modulus * special_prime).bit_length() != key_modulus_bits:
        raise ReportError("the key modulus bit length is inconsistent")
    validate_packed_target_modulus(
        args.profile, args.variant, lanes, proof_ingress_policy,
        data_prime_widths, special_prime_bits, data_primes, special_prime)
    validate_folded_pyramid_preflight(setup)

    output_noise_measurement = require(
        client, "noise.final_output.measurement", "client"
    )
    output_ciphertexts_measured = integer(
        client, "noise.final_output.encrypted_ciphertext_count", "client"
    )
    output_rns_limbs = integer(
        client, "noise.final_output.data_rns_limb_count", "client"
    )
    output_modulus_bits = integer(
        client, "noise.final_output.data_modulus_product_bits", "client"
    )
    output_minimum_noise_budget = integer(
        client,
        "noise.final_output.minimum_invariant_noise_budget_bits",
        "client",
    )
    output_maximum_phase_norm_bits = integer(
        client,
        "noise.final_output.maximum_invariant_budget_implied_phase_norm_bits",
        "client",
    )
    output_maximum_canonical_error_norm = integer(
        client,
        "noise.final_output.maximum_canonical_error_norm",
        "client",
    )
    output_maximum_canonical_error_norm_bits = integer(
        client,
        "noise.final_output.maximum_canonical_error_norm_bits",
        "client",
    )
    output_target_maximum_norm_bits = integer(
        client, "noise.final_output.target_maximum_norm_bits", "client"
    )
    output_target_enforced = require(
        client, "noise.final_output.target_enforced", "client"
    )
    output_target_result = require(
        client, "noise.final_output.target_result", "client"
    )
    output_noise_claim = require(client, "noise.final_output.claim", "client")
    if (
        output_noise_measurement
        != "client-secret-exact-canonical-error-with-invariant-budget-secondary-diagnostic"
        or output_noise_claim
        != "secret-key-assisted-exact-canonical-error-honest-run-diagnostic-not-certificate"
        or output_ciphertexts_measured != outputs
        or output_rns_limbs != 1
        or output_modulus_bits != data_primes[0].bit_length()
        or output_minimum_noise_budget < 0
        or output_minimum_noise_budget >= output_modulus_bits
        or output_maximum_phase_norm_bits
        != output_modulus_bits - output_minimum_noise_budget - 1
        or output_maximum_canonical_error_norm < 0
        or output_maximum_canonical_error_norm_bits
        != output_maximum_canonical_error_norm.bit_length()
        or output_target_maximum_norm_bits
        != PACKED_OUTPUT_MAXIMUM_CANONICAL_ERROR_NORM_BITS
    ):
        raise ReportError("packed final-output honest-noise audit is inconsistent")
    if args.profile != "quick":
        if (
            output_target_enforced != "yes"
            or output_target_result != "PASS"
            or output_maximum_canonical_error_norm_bits
            > PACKED_OUTPUT_MAXIMUM_CANONICAL_ERROR_NORM_BITS
        ):
            raise ReportError("packed target final-output noise gate did not pass")
    elif (
        output_target_enforced != "no"
        or output_target_result != "NOT-ENFORCED-DIAGNOSTIC"
    ):
        raise ReportError("diagnostic packed output incorrectly enforces the target noise gate")

    actual_t = integer(setup, "security.transcript_packing.actual_repetitions", "setup")
    selected_t = integer(setup, "security.transcript_packing.selected_repetitions", "setup")
    actual_queries = integer(setup, "security.basefold.actual_queries", "setup")
    selected_queries = integer(setup, "security.basefold.selected_queries", "setup")
    basefold_log_rate = integer(setup, "security.basefold.log_rate", "setup")
    if (require(setup, "security.basefold.bound_model", "setup")
            != "unique-decoding-rbr"
            or integer(setup, "security.basefold.target_bits", "setup") != 110):
        raise ReportError("packed BaseFold bound policy is not selected")
    policy_queries, expected_log_rate = 150, 3
    basefold_analysis = (
        "unique-decoding local interactive RBR error at most `2^-110`; "
        "one opening instance; excludes Merkle binding and Fiat--Shamir composition"
    )
    if args.profile == "quick":
        basefold_analysis += "; actual reduced-query diagnostic is not certified"
    expected_actual = (
        (4, 4) if args.profile == "quick" else (120, policy_queries)
    )
    if (actual_t, actual_queries) != expected_actual or (
        selected_t, selected_queries
    ) != (120, policy_queries):
        raise ReportError("packed security parameters do not match the fixed profile policy")
    if basefold_log_rate != expected_log_rate:
        raise ReportError("packed profile does not use the selected BaseFold rate")
    basefold_rate = 1 << basefold_log_rate
    actual_query_work = actual_queries
    selected_query_work = selected_queries
    gate_strategy = require(setup, "parameters.gate_mle_profile", "setup")
    expected_gate_strategy = (
        "wide-local-adjoint-foldable" if args.variant == "folded"
        else "structured-sparse-basefold")
    if gate_strategy != expected_gate_strategy:
        raise ReportError("affine gate opening strategy does not match the variant")
    gate_log_rate = integer(setup, "parameters.gate_mle_basefold_log_rate", "setup")
    gate_queries = integer(setup, "parameters.gate_mle_basefold_queries", "setup")
    wide_gate_strategy = args.variant == "folded"
    expected_gate_queries = WIDE_GATE_QUERIES if wide_gate_strategy else 150
    if (gate_log_rate, gate_queries) != (3, expected_gate_queries):
        raise ReportError("GateMLE BaseFold parameters do not match selected policy")
    code_family = "generic foldable code" if wide_gate_strategy else "Reed–Solomon code"
    gate_basefold_rows = [
        f"| GateMLE BaseFold | code rate `1/8`; `{gate_queries}` queries; {code_family}; one FRI per PCS batch |"
    ]
    evidence = require(setup, "benchmark.evidence", "setup")
    security_claim = require(setup, "security.claim", "setup")
    ciphertext_hash = require(setup, "protocol.ciphertext_hash", "setup")
    ciphertext_hash_claim = require(
        setup, "security.ciphertext_hash.claim", "setup"
    )
    diagnostic = actual_t != selected_t or actual_queries != selected_queries
    expected_ciphertext_hash = (
        "simpleCTHash/v2" if args.profile == "quick" else "poseidon/v2"
    )
    if ciphertext_hash != expected_ciphertext_hash:
        raise ReportError(
            "ciphertext hash does not match the fixed profile policy"
        )
    if diagnostic:
        if (
            evidence != "reduced-security-stress-test"
            or security_claim != "none-diagnostic-only"
            or ciphertext_hash_claim != "none-diagnostic-no-ciphertext-binding"
        ):
            raise ReportError("reduced packed parameters are not labeled diagnostic-only")
    elif (
        evidence != "evaluation"
        or security_claim != "selected-rbr-target-pending-composition"
        or ciphertext_hash_claim != "poseidon-ciphertext-binding"
    ):
        raise ReportError("selected packed parameters are not labeled exactly")

    if require(
        setup, "packing.r1cs.actual.classification", "setup"
    ) != "exact-setup-bound-profile":
        raise ReportError(
            "setup does not classify the actual R1CS geometry exactly"
        )
    if require(
        setup, "packing.r1cs.selected_target.classification", "setup"
    ) != "formula-only-selected-target":
        raise ReportError(
            "setup does not classify the selected-target R1CS geometry exactly"
        )
    actual_r1cs = packing_r1cs_geometry(
        setup, "packing.r1cs.actual", "setup"
    )
    target_r1cs = packing_r1cs_geometry(
        setup, "packing.r1cs.selected_target", "setup"
    )
    target_depth = integer(
        setup, "packing.r1cs.selected_target.depth", "setup"
    )
    target_width = integer(
        setup, "packing.r1cs.selected_target.middle_width", "setup"
    )
    target_payload_operations = integer(
        setup, "packing.r1cs.selected_target.payload_operations", "setup"
    )
    r1cs_geometry_source = "setup-emitted, setup-cross-checked record"
    if (
        int(actual_r1cs["ring_degree"]) != slots
        or int(actual_r1cs["repetitions"]) != actual_t
        or actual_r1cs["ciphertext_hash"] != ciphertext_hash
    ):
        raise ReportError("actual R1CS geometry disagrees with the benchmark profile")
    target_profile = PROFILE_GEOMETRY[
        "target-balancedLaned" if args.profile == "quick" else args.profile]
    if (
        int(target_r1cs["ring_degree"]) != slots
        or int(target_r1cs["repetitions"]) != selected_t
        or target_r1cs["ciphertext_hash"] != "poseidon/v2"
        or (target_depth, target_width, target_payload_operations)
        != (target_profile["depth"], target_profile["width"], target_profile["operations"])
    ):
        raise ReportError("selected-target R1CS geometry disagrees with the fixed target profile")

    setup_rows = setup_timing_rows(setup, "setup")
    setup_total = timing_pair(setup, "timing.setup.total", "setup")
    server_startup = timing_pair(server, "timing.server.startup.total", "server")
    server_recurring_pre_request = timing_pair(
        server, "timing.server.recurring_pre_request.total", "server"
    )
    server_request = timing_pair(server, "timing.server.per_request_total", "server")
    server_payload_evaluation = timing_pair(
        server, "timing.server.payload_evaluation", "server"
    )
    server_prove = timing_pair(server, "timing.server.prove", "server")
    proof_phase_prefixes = (
        "timing.server.prove.witness_packing",
        "timing.server.prove.gkr",
        "timing.server.prove.transcript_packing",
    )
    proof_phase_keys = {
        f"{prefix}.{suffix}"
        for prefix in proof_phase_prefixes
        for suffix in ("wall_ms", "cpu_ms")
    }
    present_proof_phase_keys = proof_phase_keys.intersection(server)
    if present_proof_phase_keys and present_proof_phase_keys != proof_phase_keys:
        raise ReportError("server has an incomplete proof-phase timing ledger")
    server_proof_phases = (
        [timing_pair(server, prefix, "server") for prefix in proof_phase_prefixes]
        if present_proof_phase_keys
        else None
    )
    computation_ledger = client_computation_ledger(client)
    client_request = timing_pair(client, "timing.client.per_request_total", "client")
    client_response_read = timing_pair(
        client, "timing.client.read_response_file", "client"
    )
    client_response_decode = timing_pair(
        client, "timing.client.decode_response", "client"
    )
    client_verify = computation_ledger["verify.vcoed"]
    client_output_noise_audit = timing_pair(
        client, "timing.client.honest_output_noise_audit", "client"
    )
    server_process = timing_pair(server, "timing.server.process_total", "server")
    client_process = timing_pair(client, "timing.client.process_total", "client")
    client_wait = timing_pair(client, "timing.client.wait_for_response", "client")
    server_wait = timing_pair(server, "timing.server.wait_for_request", "server")
    server_startup_scope = require_scope(
        server, "timing.server.startup.total.scope", SERVER_STARTUP_SCOPE, "server"
    )
    server_recurring_pre_request_scope = require_scope(
        server,
        "timing.server.recurring_pre_request.total.scope",
        SERVER_RECURRING_PRE_REQUEST_SCOPE,
        "server",
    )
    server_request_scope = require_scope(
        server, "timing.server.per_request_total.scope", SERVER_REQUEST_SCOPE, "server"
    )
    client_request_scope = require_scope(
        client, "timing.client.per_request_total.scope",
        "input-encryption-output-decryption-vcoed-verification;excludes-preprocessing-load-transport-peer-wait-and-output-noise-audit", "client"
    )
    require_timing_sum(
        server,
        "timing.server.startup.total",
        (
            "timing.server.startup.load_preprocessing",
            "timing.server.startup.certify_replay_and_gkr_static",
            "timing.server.startup.derive_persistent_reserve",
        ),
        "server",
    )
    require_timing_sum(
        server,
        "timing.server.recurring_pre_request.total",
        (
            "timing.server.recurring_pre_request.prepare_roots",
            "timing.server.recurring_pre_request.admit_transcript_packing",
            "timing.server.recurring_pre_request.admit_checkpoint_and_host",
        ),
        "server",
    )
    if server_proof_phases is not None:
        require_timing_sum(
            server,
            "timing.server.prove",
            proof_phase_prefixes,
            "server",
        )
    require_timing_sum(
        server,
        "timing.server.per_request_total",
        (
            "timing.server.recurring_pre_request.total",
            "timing.server.read_request_file",
            "timing.server.validate_request_capacity",
            "timing.server.decode_request",
            "timing.server.payload_evaluation",
            "timing.server.prove",
            "timing.server.validate_proof_resource_reports",
            "timing.server.encode_response",
            "timing.server.finalize_and_retire_work",
            "timing.server.publish_response",
        ),
        "server",
    )
    verifier_transcript_packing = timing_pair(
        client, "timing.client.verify.transcript_packing", "client"
    )
    verifier_gate_mle = timing_pair(
        client, "timing.client.verify.gate_mle_opening", "client"
    )
    verifier_layers = verifier_layer_rows(client, depth, "client")
    spartan_prove = unique_telemetry_span(
        server, "transcript_packing.spartan_prove", "server"
    )
    spartan_verify = unique_telemetry_span(
        client, "transcript_packing.spartan_verify", "client"
    )
    setup_started = integer(setup, "timing.setup.started_unix_ms", "setup")
    setup_finished = integer(setup, "timing.setup.finished_unix_ms", "setup")
    client_started = integer(client, "timing.client.started_unix_ms", "client")
    request_published = integer(
        client, "timing.client.request_published_unix_ms", "client"
    )
    response_observed = integer(
        client, "timing.client.response_observed_unix_ms", "client"
    )
    verification_finished = integer(
        client, "timing.client.verification_finished_unix_ms", "client"
    )
    client_process_finished = integer(
        client, "timing.client.process_finished_unix_ms", "client"
    )
    client_finished = integer(client, "timing.client.finished_unix_ms", "client")
    server_started = integer(server, "timing.server.started_unix_ms", "server")
    request_observed = integer(
        server, "timing.server.request_observed_unix_ms", "server"
    )
    response_published = integer(
        server, "timing.server.response_published_unix_ms", "server"
    )
    server_finished = integer(server, "timing.server.finished_unix_ms", "server")
    if setup_started > setup_finished:
        raise ReportError("setup timestamps are not monotonic")
    if setup_finished > client_started or setup_finished > server_started:
        raise ReportError("an online role started before setup completed")
    if client_finished != client_process_finished or not (
        client_started
        <= request_published
        <= response_observed
        <= verification_finished
        <= client_process_finished
    ):
        raise ReportError("client timestamps are not monotonic")
    if not (
        server_started <= request_observed <= response_published <= server_finished
    ):
        raise ReportError("server timestamps are not monotonic")
    if request_published > request_observed + PUBLICATION_OBSERVATION_RACE_MS:
        raise ReportError(
            "server observed the request outside the allowed publication race"
        )
    if response_published > response_observed + PUBLICATION_OBSERVATION_RACE_MS:
        raise ReportError(
            "client observed the response outside the allowed publication race"
        )
    request_to_verification = verification_finished - request_published
    observed_run_span = max(client_process_finished, server_finished) - setup_started
    require_exact_prefixed_keys(server, "wire.", WIRE_KEYS, "server")
    require_exact_prefixed_keys(client, "wire.", WIRE_KEYS, "client")
    request_bytes = integer(client, "wire.request_bytes", "client")
    response_bytes = integer(client, "wire.response_bytes", "client")
    if integer(server, "wire.request_bytes", "server") != request_bytes or integer(
        server, "wire.response_bytes", "server"
    ) != response_bytes:
        raise ReportError("client and server disagree on request/response bytes")
    if (
        transcript_sizes["cli-to-srv-request.bin"] != request_bytes
        or transcript_sizes["srv-to-cli-response.bin"] != response_bytes
    ):
        raise ReportError("transcript artifact sizes disagree with the role results")

    proof_response_bytes = integer(server, "proof.response.total_bytes", "server")
    canonical_proof_bytes = integer(server, "proof.canonical.total_bytes", "server")
    proof_statement_bytes = integer(
        server, "proof.canonical.statement_and_metadata_bytes", "server"
    )
    committed_gkr_bytes = integer(
        server, "proof.canonical.committed_gkr_bytes", "server"
    )
    well_formedness_bytes = integer(
        server, "proof.canonical.well_formedness_reveal_bytes", "server"
    )
    packed_digit_bytes = integer(
        server, "proof.canonical.digit_packing_ciphertext_bytes", "server"
    )
    spartan_bytes = integer(
        server, "proof.canonical.spartan_packing_proof_bytes", "server"
    )
    if proof_response_bytes != response_bytes or canonical_proof_bytes > response_bytes:
        raise ReportError("proof-size accounting disagrees with the response size")
    if (
        proof_statement_bytes
        + committed_gkr_bytes
        + well_formedness_bytes
        + packed_digit_bytes
        + spartan_bytes
        != canonical_proof_bytes
    ):
        raise ReportError("canonical proof components do not sum to the proof size")
    commitment_digest_bytes = integer(
        server, "proof.committed_gkr.commitment_digest_bytes", "server"
    )
    gate_mle_opening_bytes = integer(
        server, "proof.committed_gkr.gate_mle_opening_bytes", "server"
    )
    committed_subcomponents = commitment_digest_bytes + gate_mle_opening_bytes
    if committed_subcomponents > committed_gkr_bytes:
        raise ReportError("committed-GKR subcomponents exceed their parent size")

    client_rss = integer(client, "memory.client.peak_rss_bytes", "client")
    server_rss = integer(server, "memory.server.peak_rss_bytes", "server")
    setup_rss = integer(setup, "memory.setup.peak_rss_bytes", "setup")
    admitted_live_storage = integer(
        setup, "storage.server.admitted_peak_live_bytes", "setup"
    )
    admitted_resident = integer(
        setup, "memory.server.admitted_peak_resident_bytes", "setup"
    )
    admitted_client_resident = integer(
        setup, "memory.client.admitted_peak_resident_bytes", "setup"
    )
    admitted_concurrent_resident = integer(
        setup, "memory.concurrent.admitted_peak_resident_bytes", "setup"
    )
    all_roles_persistent = integer(
        setup, "storage.setup.all_roles_persistent_bytes", "setup"
    )
    shared_persistent = integer(
        setup, "storage.setup.shared_persistent_bytes", "setup"
    )
    server_private_persistent = integer(
        setup, "storage.setup.server_private_persistent_bytes", "setup"
    )
    client_private_persistent = integer(
        setup, "storage.setup.client_private_persistent_bytes", "setup"
    )
    proving_key_bytes = integer(
        setup, "storage.setup.proving_key_bytes", "setup"
    )
    verifying_key_bytes = integer(
        setup, "storage.setup.verifying_key_bytes", "setup"
    )
    server_persistent = integer(
        setup, "storage.setup.server_persistent_bytes", "setup"
    )
    if (
        proving_key_bytes != shared_persistent + server_private_persistent
        or verifying_key_bytes != shared_persistent + client_private_persistent
        or all_roles_persistent
        != shared_persistent
        + server_private_persistent
        + client_private_persistent
        or server_persistent != proving_key_bytes
    ):
        raise ReportError("packed proving/verifying-key accounting is inconsistent")
    prepublication_existing = integer(
        setup, "storage.setup.prepublication_fhe_persistent_bytes", "setup"
    )
    prepublication_persistent = integer(
        setup,
        "storage.setup.prepublication_admitted_persistent_bytes",
        "setup",
    )
    prepublication_peak_live = integer(
        setup, "storage.setup.prepublication_admitted_peak_live_bytes", "setup"
    )
    prepublication_additional = integer(
        setup, "storage.setup.prepublication_additional_live_bytes", "setup"
    )
    prepublication_required_available = integer(
        setup,
        "storage.setup.prepublication_required_available_bytes",
        "setup",
    )
    prepublication_observed_available = integer(
        setup,
        "storage.setup.prepublication_observed_available_bytes",
        "setup",
    )
    prepublication_peak_resident = integer(
        setup,
        "memory.setup.prepublication_admitted_peak_resident_bytes",
        "setup",
    )
    prepublication_observed_peak_rss = integer(
        setup,
        "memory.setup.prepublication_observed_peak_rss_bytes",
        "setup",
    )
    prepublication_remaining_resident = integer(
        setup,
        "memory.setup.prepublication_remaining_resident_reserve_bytes",
        "setup",
    )
    capacity = {
        "max_live_disk_bytes": integer(
            setup, "capacity.profile.max_live_disk_bytes", "setup"
        ),
        "max_resident_ram_bytes": integer(
            setup, "capacity.profile.max_resident_ram_bytes", "setup"
        ),
        "min_free_disk_bytes": integer(
            setup, "capacity.profile.min_free_disk_bytes", "setup"
        ),
    }
    planner_preflight = planner_preflight_ledger(
        setup, storage_provenance, capacity
    )
    if integer(setup, "environment.ram_bytes", "setup") != int(
        planner_preflight["observed_ram"]
    ):
        raise ReportError(
            "planner RAM observation disagrees with environment.ram_bytes"
        )
    host_ram = integer(setup, "environment.ram_bytes", "setup")
    if not (
        prepublication_existing <= prepublication_persistent
        <= prepublication_peak_live
    ):
        raise ReportError(
            "setup prepublication persistent/live admission is not monotonic"
        )
    if (
        prepublication_additional
        != prepublication_peak_live - prepublication_existing
    ):
        raise ReportError(
            "setup prepublication additional live bytes do not equal "
            "peak live bytes minus already-present bytes"
        )
    if all_roles_persistent > prepublication_persistent:
        raise ReportError(
            "observed all-role setup persistence exceeds its prepublication "
            "admission"
        )
    setup_live_disk_cap = int(planner_preflight["gross_live"])
    if prepublication_peak_live > setup_live_disk_cap:
        raise ReportError(
            "setup prepublication peak live bytes exceed the whole-filesystem "
            "disk cap"
        )
    setup_resident_cap = int(planner_preflight["gross_resident"])
    if (
        prepublication_peak_resident > setup_resident_cap
        or prepublication_peak_resident > host_ram
    ):
        raise ReportError(
            "setup prepublication peak resident bytes exceed the "
            "whole-setup or host RAM cap"
        )
    if prepublication_peak_resident != (
        prepublication_observed_peak_rss
        + prepublication_remaining_resident
    ):
        raise ReportError(
            "setup prepublication resident admission does not equal the "
            "observed prefix peak plus the remaining reserve"
        )
    if prepublication_required_available != (
        prepublication_additional + capacity["min_free_disk_bytes"]
    ):
        raise ReportError(
            "setup prepublication required available bytes do not equal "
            "additional live bytes plus the profile free-space floor"
        )
    if prepublication_observed_available < prepublication_required_available:
        raise ReportError(
            "setup admission-time available disk is below the required "
            "prepublication envelope"
        )
    if setup_rss > prepublication_peak_resident:
        raise ReportError(
            "observed setup RSS exceeds its prepublication admission"
        )
    if (
        integer(server, "storage.server.admitted_peak_live_bytes", "server")
        != admitted_live_storage
    ):
        raise ReportError("setup and server disagree on admitted peak live storage")
    if admitted_live_storage > capacity["max_live_disk_bytes"]:
        raise ReportError("admitted server peak exceeds its net live-disk cap")
    if (
        integer(server, "memory.server.admitted_peak_resident_bytes", "server")
        != admitted_resident
    ):
        raise ReportError("setup and server disagree on admitted peak resident memory")
    if (
        integer(server, "memory.client.admitted_peak_resident_bytes", "server")
        != admitted_client_resident
        or integer(client, "memory.client.admitted_peak_resident_bytes", "client")
        != admitted_client_resident
    ):
        raise ReportError("roles disagree on admitted client resident memory")
    if (
        integer(server, "memory.concurrent.admitted_peak_resident_bytes", "server")
        != admitted_concurrent_resident
        or admitted_resident + admitted_client_resident
        != admitted_concurrent_resident
    ):
        raise ReportError("roles disagree on admitted concurrent resident memory")
    if (
        admitted_resident > capacity["max_resident_ram_bytes"]
        or (
            planner_preflight is None
            and admitted_client_resident > capacity["max_resident_ram_bytes"]
        )
        or admitted_concurrent_resident > host_ram
    ):
        raise ReportError("admitted role memory exceeds its process or host cap")
    if (
        planner_preflight is not None
        and admitted_concurrent_resident
        > int(planner_preflight["gross_resident"])
    ):
        raise ReportError(
            "admitted concurrent server/client memory exceeds the "
            "gross resident budget"
        )
    if server_rss > admitted_resident or client_rss > admitted_client_resident:
        raise ReportError("measured role RSS exceeds its admitted resident-memory bound")

    actual_active_constraints = int(actual_r1cs["active_constraints"])
    target_active_constraints = int(target_r1cs["active_constraints"])
    actual_matrix_rows = int(actual_r1cs["matrix_rows"])
    target_matrix_rows = int(target_r1cs["matrix_rows"])
    actual_padded_constraints = int(
        actual_r1cs["spartan_padded_constraints"]
    )
    target_padded_constraints = int(
        target_r1cs["spartan_padded_constraints"]
    )
    actual_domain_log = power_of_two_log(
        actual_padded_constraints, "actual Spartan constraint domain"
    )
    target_domain_log = power_of_two_log(
        target_padded_constraints, "selected-target Spartan constraint domain"
    )
    active_constraint_ratio = target_active_constraints / actual_active_constraints
    padded_constraint_ratio = (
        target_padded_constraints / actual_padded_constraints
    )
    workload_ratio = target_payload_operations / payload_operations

    target_projection: dict[str, float] | None = None
    if diagnostic:
        payload_timing = timing_pair(
            server, "timing.server.payload_evaluation", "server"
        )
        prove_timing = timing_pair(server, "timing.server.prove", "server")
        if spartan_prove[1] > prove_timing[1]:
            raise ReportError(
                "transcript-packing Spartan CPU exceeds its parent prove phase"
            )
        non_spartan_prove_cpu = prove_timing[1] - spartan_prove[1]
        fixed_server_cpu = server_request[1] - payload_timing[1] - prove_timing[1]
        if fixed_server_cpu < -0.001:
            raise ReportError(
                "server payload and prove CPU exceed the per-request total"
            )
        fixed_server_cpu = max(0.0, fixed_server_cpu)
        projected_payload_cpu = payload_timing[1] * workload_ratio
        projected_non_spartan_cpu = non_spartan_prove_cpu * workload_ratio
        projected_spartan_linear_cpu = spartan_prove[1] * padded_constraint_ratio
        projected_spartan_transform_cpu = projected_spartan_linear_cpu * (
            target_domain_log / actual_domain_log
        )
        projected_server_linear_cpu = (
            fixed_server_cpu
            + projected_payload_cpu
            + projected_non_spartan_cpu
            + projected_spartan_linear_cpu
        )
        projected_server_transform_cpu = (
            fixed_server_cpu
            + projected_payload_cpu
            + projected_non_spartan_cpu
            + projected_spartan_transform_cpu
        )
        if spartan_verify[1] > verifier_transcript_packing[1]:
            raise ReportError(
                "Spartan verification CPU exceeds its transcript-packing "
                "verification parent"
            )
        projected_client_query_cpu = (
            client_request[1]
            - spartan_verify[1]
            + spartan_verify[1]
            * (selected_query_work / actual_query_work)
        )
        projected_client_query_depth_cpu = (
            client_request[1]
            - spartan_verify[1]
            + spartan_verify[1]
            * (selected_query_work / actual_query_work)
            * (target_domain_log / actual_domain_log)
        )

        aligned_ciphertext_ratio = (
            int(target_r1cs["aligned_ciphertexts"])
            / int(actual_r1cs["aligned_ciphertexts"])
        )
        digit_ciphertext_ratio = (
            int(target_r1cs["physical_packed_ciphertexts"])
            * int(target_r1cs["packing_digit_count"])
            / (
                int(actual_r1cs["physical_packed_ciphertexts"])
                * int(actual_r1cs["packing_digit_count"])
            )
        )
        projected_committed_gkr_bytes = (
            committed_gkr_bytes
            - commitment_digest_bytes
            + round(commitment_digest_bytes * aligned_ciphertext_ratio)
        )
        projected_well_formedness_bytes = round(
            well_formedness_bytes * selected_t / actual_t
        )
        projected_digit_bytes = round(
            packed_digit_bytes * digit_ciphertext_ratio
        )
        projected_spartan_query_bytes = round(
            spartan_bytes * selected_query_work / actual_query_work
        )
        projected_spartan_query_depth_bytes = round(
            spartan_bytes
            * selected_query_work
            / actual_query_work
            * target_domain_log
            / actual_domain_log
        )
        response_envelope_bytes = response_bytes - canonical_proof_bytes
        projected_response_query_bytes = (
            response_envelope_bytes
            + proof_statement_bytes
            + projected_committed_gkr_bytes
            + projected_well_formedness_bytes
            + projected_digit_bytes
            + projected_spartan_query_bytes
        )
        projected_response_query_depth_bytes = (
            response_envelope_bytes
            + proof_statement_bytes
            + projected_committed_gkr_bytes
            + projected_well_formedness_bytes
            + projected_digit_bytes
            + projected_spartan_query_depth_bytes
        )

        # Target depth increases by two and targets also add one payload
        # head; quick profiles deliberately keep their original chain.
        candidate_target_data_limbs = data_limbs + target_depth - depth + 1
        if candidate_target_data_limbs <= 0:
            raise ReportError("selected-target candidate has no data limbs")
        candidate_limb_ratio = candidate_target_data_limbs / data_limbs
        verifier_layer_ratio = (2 * target_depth + 1) / len(verifier_layers)
        response_codec_cpu = 0.0
        non_spartan_verify_cpu = client_verify[1] - spartan_verify[1]
        other_client_cpu = (
            client_request[1] - client_verify[1] - response_codec_cpu
        )
        if non_spartan_verify_cpu < -0.001 or other_client_cpu < -0.001:
            raise ReportError(
                "client projection subphases exceed the per-request total"
            )
        non_spartan_verify_cpu = max(0.0, non_spartan_verify_cpu)
        other_client_cpu = max(0.0, other_client_cpu)
        response_query_ratio = projected_response_query_bytes / response_bytes
        response_query_depth_ratio = (
            projected_response_query_depth_bytes / response_bytes
        )
        projected_client_planning_cpu = (
            other_client_cpu * candidate_limb_ratio
            + response_codec_cpu * response_query_ratio
            + non_spartan_verify_cpu * verifier_layer_ratio
            + spartan_verify[1] * selected_query_work / actual_query_work
        )
        projected_client_planning_high_cpu = (
            other_client_cpu * candidate_limb_ratio
            + response_codec_cpu * response_query_depth_ratio
            + non_spartan_verify_cpu * workload_ratio
            + spartan_verify[1]
            * selected_query_work
            / actual_query_work
            * target_domain_log
            / actual_domain_log
        )
        packing_live_bytes = integer(
            setup, "storage.online.packing_peak_live_bytes", "setup"
        )
        target_projection = {
            "payload_cpu_ms": projected_payload_cpu,
            "non_spartan_cpu_ms": projected_non_spartan_cpu,
            "spartan_linear_cpu_ms": projected_spartan_linear_cpu,
            "spartan_transform_cpu_ms": projected_spartan_transform_cpu,
            "server_linear_cpu_ms": projected_server_linear_cpu,
            "server_transform_cpu_ms": projected_server_transform_cpu,
            "client_query_cpu_ms": projected_client_query_cpu,
            "client_query_depth_cpu_ms": projected_client_query_depth_cpu,
            "client_planning_cpu_ms": projected_client_planning_cpu,
            "client_planning_high_cpu_ms": projected_client_planning_high_cpu,
            "response_query_bytes": projected_response_query_bytes,
            "response_query_depth_bytes": projected_response_query_depth_bytes,
            "candidate_target_data_limbs": candidate_target_data_limbs,
            "packing_live_bytes": packing_live_bytes * padded_constraint_ratio,
        }

    replay_io_suffixes = (
        "monotone_relations",
        "monotone_range_readers",
        "monotone_source_records",
        "alias_cached_relations",
        "alias_cache_range_readers",
        "alias_cache_distinct_source_records",
        "alias_cache_logical_source_uses",
        "alias_cache_generic_source_records",
        "identity_affine_alias_relations",
        "identity_affine_alias_fallbacks",
        "identity_affine_alias_records_reused",
        "identity_affine_alias_layer_bytes_reused",
        "identity_affine_alias_unique_bytes_written",
    )
    replay_io_keys = [
        f"work.replay.{phase}.{suffix}"
        for phase in ("forward", "reverse")
        for suffix in replay_io_suffixes
    ]
    replay_io_presence = [key in server for key in replay_io_keys]
    if any(replay_io_presence) and not all(replay_io_presence):
        raise ReportError("server has an incomplete checkpoint-replay I/O ledger")
    replay_io: dict[str, dict[str, int]] = {}
    if all(replay_io_presence):
        for phase in ("forward", "reverse"):
            values = {
                suffix: integer(
                    server, f"work.replay.{phase}.{suffix}", "server"
                )
                for suffix in replay_io_suffixes
            }
            if values["monotone_range_readers"] != 2 * values["monotone_relations"]:
                raise ReportError(
                    f"{phase} monotone replay reader ledger is inconsistent"
                )
            if values["alias_cache_range_readers"] != values["alias_cached_relations"]:
                raise ReportError(
                    f"{phase} alias-cache reader ledger is inconsistent"
                )
            if values["alias_cached_relations"] == 0:
                if any(
                    values[suffix] != 0
                    for suffix in (
                        "alias_cache_range_readers",
                        "alias_cache_distinct_source_records",
                        "alias_cache_logical_source_uses",
                        "alias_cache_generic_source_records",
                    )
                ):
                    raise ReportError(
                        f"{phase} alias-cache counters exist without a relation"
                    )
            elif (
                values["alias_cache_distinct_source_records"] == 0
                or values["alias_cache_generic_source_records"]
                < 4 * values["alias_cache_distinct_source_records"]
            ):
                raise ReportError(
                    f"{phase} alias-cache savings ledger is inconsistent"
                )
            if values["identity_affine_alias_relations"] == 0 and any(
                values[suffix] != 0
                for suffix in (
                    "identity_affine_alias_records_reused",
                    "identity_affine_alias_layer_bytes_reused",
                    "identity_affine_alias_unique_bytes_written",
                )
            ):
                raise ReportError(
                    f"{phase} identity-affine alias bytes exist without a successful relation"
                )
            replay_io[phase] = values

    proof_phase_summary_rows = []
    if server_proof_phases is not None:
        witness_packing, gkr, transcript_packing = server_proof_phases
        proof_phase_summary_rows = [
            f"| ↳ Witness packing | {milliseconds(witness_packing[0])} wall; {milliseconds(witness_packing[1])} CPU |",
            f"| ↳ GKR | {milliseconds(gkr[0])} wall; {milliseconds(gkr[1])} CPU |",
            f"| ↳ Transcript packing | {milliseconds(transcript_packing[0])} wall; {milliseconds(transcript_packing[1])} CPU |",
        ]

    payload_pipeline_section = []
    replay_phases = (
        ("Forward evaluation", "forward"),
        ("Reverse replay", "reverse"),
        ("GKR source", "gkr_source"),
    )
    replay_phase_keys = (
        "work.replay.forward.timing.relation.wall_ms",
        "work.replay.reverse.timing.relation.wall_ms",
        "work.replay.gkr_source.storage.application_read_bytes",
    )
    replay_phase_presence = tuple(
        key in server for key in replay_phase_keys
    )
    if any(replay_phase_presence) and not all(replay_phase_presence):
        raise ReportError("server has incomplete replay storage phase timings")
    if all(replay_phase_presence):
        timing_metrics = [
            ("Circuit-relation evaluation", "relation"),
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
        payload_timing_rows = []
        phase_timings: dict[str, dict[str, tuple[float, float]]] = {
            phase: {} for _, phase in replay_phases
        }
        for label, key in timing_metrics:
            cells = []
            for _, phase in replay_phases:
                if phase == "gkr_source" and key not in ("prefetch", "storage_read"):
                    cells.append("not reported for read-only source diagnostics")
                    continue
                wall = number(
                    server, f"work.replay.{phase}.timing.{key}.wall_ms", "server"
                )
                cpu = number(
                    server, f"work.replay.{phase}.timing.{key}.cpu_ms", "server"
                )
                phase_timings[phase][key] = (wall, cpu)
                cells.append(
                    f"{milliseconds(wall)} wall; {milliseconds(cpu)} CPU; {utilization(cpu, wall)}"
                )
            payload_timing_rows.append(
                f"| {label} | " + " | ".join(cells) + " |"
            )
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
        derived_rows = []
        for label, selection in (
            ("FHE + ciphertext maintenance (derived)", ("fhe", "modulus_switch")),
            ("Trace maintenance (derived)", trace_keys),
        ):
            cells = []
            for _, phase in replay_phases:
                if phase == "gkr_source":
                    cells.append("not reported for read-only source diagnostics")
                    continue
                wall = sum(phase_timings[phase][key][0] for key in selection)
                cpu = sum(phase_timings[phase][key][1] for key in selection)
                cells.append(
                    f"{milliseconds(wall)} wall; {milliseconds(cpu)} CPU; {utilization(cpu, wall)}"
                )
            derived_rows.append(f"| {label} | " + " | ".join(cells) + " |")
        payload_timing_rows[1:1] = [
            *derived_rows,
        ]

        def phase_integer(phase: str, suffix: str) -> int:
            return integer(server, f"work.replay.{phase}.{suffix}", "server")

        def phase_bytes(phase: str, suffix: str) -> str:
            return bytes_text(phase_integer(phase, suffix))

        for _, phase in replay_phases:
            prefetch_bytes = phase_integer(
                phase, "storage.prefetch_bytes_requested"
            )
            maximum_prefetch = phase_integer(
                phase, "storage.maximum_prefetch_request_bytes"
            )
            if maximum_prefetch > prefetch_bytes:
                raise ReportError(
                    f"server has inconsistent replay storage telemetry for {phase}"
                )
            if phase == "gkr_source":
                continue
            submission_attempts = phase_integer(
                phase, "storage.writeback_submission_attempts"
            )
            submission_successes = phase_integer(
                phase, "storage.writeback_submission_successes"
            )
            submitted_bytes = phase_integer(
                phase, "storage.writeback_range_bytes_submitted"
            )
            maximum_submission = phase_integer(
                phase, "storage.maximum_writeback_submission_bytes"
            )
            wait_attempts = phase_integer(
                phase, "storage.writeback_wait_attempts"
            )
            wait_successes = phase_integer(
                phase, "storage.writeback_wait_successes"
            )
            waited_bytes = phase_integer(
                phase, "storage.writeback_range_bytes_waited"
            )
            submit_only_files = phase_integer(
                phase, "storage.writeback_files_submit_only"
            )
            if (
                submission_successes > submission_attempts
                or wait_successes > wait_attempts
                or (
                    submission_successes != 0
                    and maximum_submission > submitted_bytes
                )
                or waited_bytes > submitted_bytes
                or (
                    submit_only_files != 0
                    and (wait_attempts != 0 or wait_successes != 0 or waited_bytes != 0)
                )
            ):
                raise ReportError(
                    f"server has inconsistent replay storage telemetry for {phase}"
                )

        def count_pair(phase: str, left: str, right: str) -> str:
            return f"{phase_integer(phase, left):,} / {phase_integer(phase, right):,}"

        def count_triple(
            phase: str, first: str, second: str, third: str
        ) -> str:
            return (
                f"{phase_integer(phase, first):,} / "
                f"{phase_integer(phase, second):,} / "
                f"{phase_integer(phase, third):,}"
            )

        def transfer(phase: str, byte_suffix: str, timing_suffix: str) -> str:
            byte_count = phase_integer(phase, byte_suffix)
            wall_ms = phase_timings[phase][timing_suffix][0]
            return (
                f"{bytes_text(byte_count)} at {throughput(byte_count, wall_ms)} "
                "call-path throughput; not device traffic"
            )

        def storage_row(label, render, *, gkr_read_diagnostic=False) -> str:
            cells = [
                (
                    render(phase)
                    if phase != "gkr_source" or gkr_read_diagnostic
                    else "not reported for read-only source diagnostics"
                )
                for _, phase in replay_phases
            ]
            return f"| {label} | " + " | ".join(cells) + " |"

        storage_rows = [
            storage_row(
                "Application bytes submitted to write calls",
                lambda phase: transfer(
                    phase, "storage.application_write_bytes", "storage_write"
                ),
            ),
            storage_row(
                "Write batches / syscalls",
                lambda phase: count_pair(
                    phase, "storage.write_batches", "storage.write_syscalls"
                ),
            ),
            storage_row(
                "Largest write batch",
                lambda phase: phase_bytes(
                    phase, "storage.maximum_write_batch_bytes"
                ),
            ),
            storage_row(
                "Writeback-enabled / submit-only / fallback files",
                lambda phase: count_triple(
                    phase,
                    "storage.writeback_files_enabled",
                    "storage.writeback_files_submit_only",
                    "storage.writeback_files_fallback",
                ),
            ),
            storage_row(
                "Writeback submission attempts / successes",
                lambda phase: count_pair(
                    phase,
                    "storage.writeback_submission_attempts",
                    "storage.writeback_submission_successes",
                ),
            ),
            storage_row(
                "Foreground wait attempts / successes",
                lambda phase: count_pair(
                    phase,
                    "storage.writeback_wait_attempts",
                    "storage.writeback_wait_successes",
                ),
            ),
            storage_row(
                "Largest successful writeback range hint",
                lambda phase: phase_bytes(
                    phase, "storage.maximum_writeback_submission_bytes"
                ),
            ),
            storage_row(
                "Successful range-hint / explicitly waited range bytes",
                lambda phase: (
                    f"{phase_bytes(phase, 'storage.writeback_range_bytes_submitted')} / "
                    f"{phase_bytes(phase, 'storage.writeback_range_bytes_waited')}"
                ),
            ),
            storage_row(
                "Foreground wait window / maximum application-tracked unwaited range",
                lambda phase: (
                    f"{phase_bytes(phase, 'storage.writeback_window_bytes')} / "
                    f"{phase_bytes(phase, 'storage.maximum_unwaited_writeback_range_bytes')}"
                ),
            ),
            storage_row(
                "Foreground drains / deliberately skipped drains",
                lambda phase: count_pair(
                    phase,
                    "storage.writeback_drains",
                    "storage.writeback_drains_skipped",
                ),
            ),
            storage_row(
                "Foreground-drain range / successful range-hint bytes without explicit wait",
                lambda phase: (
                    f"{phase_bytes(phase, 'storage.writeback_drain_range_bytes')} / "
                    f"{phase_bytes(phase, 'storage.writeback_range_bytes_without_explicit_wait')}"
                ),
            ),
            storage_row(
                "Positional header-write calls / bytes",
                lambda phase: (
                    f"{phase_integer(phase, 'storage.positional_write_calls'):,} / "
                    f"{phase_bytes(phase, 'storage.positional_write_bytes')}"
                ),
            ),
            storage_row(
                "Application bytes returned by read calls",
                lambda phase: transfer(
                    phase, "storage.application_read_bytes", "storage_read"
                ),
                gkr_read_diagnostic=True,
            ),
            storage_row(
                "Read batches / syscalls",
                lambda phase: count_pair(
                    phase, "storage.read_batches", "storage.read_syscalls"
                ),
                gkr_read_diagnostic=True,
            ),
            storage_row(
                "Largest read batch",
                lambda phase: phase_bytes(
                    phase, "storage.maximum_read_batch_bytes"
                ),
                gkr_read_diagnostic=True,
            ),
            storage_row(
                "Prefetch requests / fallbacks / seek disables",
                lambda phase: count_triple(
                    phase,
                    "storage.prefetch_requests",
                    "storage.prefetch_fallbacks",
                    "storage.prefetch_seek_disables",
                ),
                gkr_read_diagnostic=True,
            ),
            storage_row(
                "Prefetch bytes requested",
                lambda phase: phase_bytes(
                    phase, "storage.prefetch_bytes_requested"
                ),
                gkr_read_diagnostic=True,
            ),
            storage_row(
                "Prefetch logical window / largest BDI-qualified request",
                lambda phase: (
                    f"{phase_bytes(phase, 'storage.prefetch_window_bytes')} / "
                    f"{phase_bytes(phase, 'storage.maximum_prefetch_request_bytes')}"
                ),
                gkr_read_diagnostic=True,
            ),
            storage_row(
                "Filesystem-capacity probes",
                lambda phase: (
                    f"{phase_integer(phase, 'storage.capacity_probes'):,} "
                    "(trace/layer boundaries only)"
                ),
            ),
            storage_row(
                "Private scratch integrity",
                lambda phase: (
                    f"`{require(server, f'work.replay.{phase}.storage.artifact_integrity', 'server')}`"
                ),
                gkr_read_diagnostic=True,
            ),
            storage_row(
                "Authenticated / same-process-unhashed record bytes",
                lambda phase: (
                    f"{phase_bytes(phase, 'storage.authenticated_record_bytes')} / "
                    f"{phase_bytes(phase, 'storage.same_process_unhashed_record_bytes')}"
                ),
            ),
            storage_row(
                "Whole-record bytes recopied into transfer slabs",
                lambda phase: phase_bytes(phase, "storage.record_copy_bytes"),
            ),
        ]
        payload_pipeline_section = [
            "",
            "## Payload storage pipeline",
            "",
            "| Pipeline timing | Forward evaluation | Reverse replay | GKR source |",
            "|---|---:|---:|---:|",
            *payload_timing_rows,
            "",
            "Derived rows sum disjoint leaf timers; output submission and drain/close/publication are shown separately and excluded because they enclose some of those leaves. Circuit-relation evaluation is not an enclosing phase total: the forward and reverse ledgers also include input/output, checkpoint, proof-ingress, validation, and retirement work outside relation evaluation. In particular, a zero-replay target can report zero reverse circuit-relation time while still performing required proof-ingress work, so leaf timers must not be subtracted from the relation timer.",
            "",
            "| Transfer evidence | Forward evaluation | Reverse replay | GKR source |",
            "|---|---:|---:|---:|",
            *storage_rows,
            "",
            "| Configured payload storage | Measured value |",
            "|---|---:|",
            f"| Planned ephemeral foreground wait window | {bytes_text(integer(setup, 'memory.payload_storage.writeback_window_bytes', 'setup'))} |",
            f"| Planned ephemeral writeback policy | `{require(setup, 'storage.payload_storage.ephemeral_writeback_policy', 'setup')}` |",
            f"| Planned writeback range-hint ceiling | {bytes_text(integer(setup, 'storage.payload_storage.maximum_writeback_submission_bytes', 'setup'))} |",
            f"| Planned sequential readers / prefetch page-cache budget | {integer(setup, 'memory.payload_storage.sequential_reader_count', 'setup'):,} / {bytes_text(integer(setup, 'memory.payload_storage.prefetch_page_cache_budget_bytes', 'setup'))} |",
            f"| Planned prefetch window / request ceiling | {bytes_text(integer(setup, 'memory.payload_storage.prefetch_window_bytes_each', 'setup'))} / {bytes_text(integer(setup, 'storage.payload_storage.maximum_prefetch_request_bytes', 'setup'))}; Linux qualifies the request size from the backing device's BDI read-ahead geometry |",
            "",
            "Phase columns keep reverse replay and GKR source reads distinct from forward materialization. Same-process ephemeral files use Linux submit-only writeback: they perform no explicit foreground wait or layer-end drain, although ordinary kernel dirty-page throttling may still block writes. Authenticated reopenable artifacts retain bounded foreground waits and a layer-end drain. Linux prefetch requests are capped by setup policy and further qualified at runtime from the backing device's BDI read-ahead geometry; the reported largest request is the actual submitted size. Transfer byte counts are application-level bytes, not device traffic; use host block-I/O telemetry to measure the Hyperdisk itself. Progress JSONL also records current and peak RSS at every coarse event boundary.",
        ]

    lines = [
        "<!-- laminate-packed-summary-v1 -->",
        f"# Laminate {args.variant.capitalize()} {args.profile} summary",
        "",
    ]
    if diagnostic:
        lines.extend(
            [
                "> **Diagnostic profile.** Its reduced parameters do not support a ciphertext-binding or transcript-packing integrity claim.",
                f"> This stress profile used `T={actual_t}` and `q_BF={actual_queries}` instead of the selected `T={selected_t}` and `q_BF={selected_queries}`.",
                "> ciphertext hash: simpleCTHash/v2 (diagnostic; no ciphertext-binding or transcript-packing integrity claim)",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "> **Selected-parameter evaluation profile.** Acceptance is evidence only for the exact admitted revision and geometry below.",
                "",
            ]
        )
    lines.extend(
        [
            "| Result | Measured value |",
            "|---|---:|",
            "| Client proof verification | **PASS** (includes transcript-packing well-formedness threshold checks) |",
            "| Process exits | setup `0`; server `0`; client `0` |",
            f"| Evidence class | `{evidence}` |",
            f"| Fiat–Shamir composition | {fiat_shamir_description} |",
            f"| GKR layer transitions | {claim_transition_description} |",
            f"| GKR multiplication | {multiplication_description} |",
            f"| Payload workload | `{workload}`; {gate_summary(payload_gate_counts)} |",
            f"| Ciphertext hash | {'Poseidon (poseidon/v2)' if ciphertext_hash == 'poseidon/v2' else 'simpleCTHash/v2 (diagnostic; no ciphertext-binding or transcript-packing integrity claim)'} |",
            f"| Packing parameters | actual `T={actual_t}`, `q_BF={actual_queries}`; selected `T={selected_t}`, `q_BF={selected_queries}` |",
            f"| BaseFold codeword expansion | `{basefold_rate}x` (code rate `1/{basefold_rate}`; log-rate {basefold_log_rate}) |",
            f"| BaseFold analysis | {basefold_analysis} |",
            *gate_basefold_rows,
            f"| Offline/static setup | {milliseconds(setup_total[0])} wall; {milliseconds(setup_total[1])} CPU |",
            f"| Proving key / server preprocessing | {bytes_text(proving_key_bytes)} |",
            f"| Verifying key / client preprocessing | {bytes_text(verifying_key_bytes)} |",
            f"| Reusable server startup | {milliseconds(server_startup[0])} wall; {milliseconds(server_startup[1])} CPU |",
            f"| One-shot recurring server admission | {milliseconds(server_recurring_pre_request[0])} wall; {milliseconds(server_recurring_pre_request[1])} CPU; included in per-request server |",
            f"| Payload evaluation | {milliseconds(server_payload_evaluation[0])} wall; {milliseconds(server_payload_evaluation[1])} CPU; {utilization(server_payload_evaluation[1], server_payload_evaluation[0])} CPU/wall |",
            f"| Proof generation | {milliseconds(server_prove[0])} wall; {milliseconds(server_prove[1])} CPU |",
            *proof_phase_summary_rows,
            f"| Per-request server | {milliseconds(server_request[0])} wall; {milliseconds(server_request[1])} CPU |",
            f"| Per-request client computation | {milliseconds(client_request[0])} wall; {milliseconds(client_request[1])} CPU |",
            f"| Request publication to verified client result | {milliseconds(float(request_to_verification))} elapsed |",
            f"| Observed setup-start to final role completion | {milliseconds(float(observed_run_span))} elapsed |",
            f"| Request | {bytes_text(request_bytes)} |",
            f"| Response (encrypted output and complete proof) | {bytes_text(response_bytes)} |",
            f"| Canonical proof inside response | {bytes_text(canonical_proof_bytes)} |",
            f"| Initial ciphertext data modulus | {fresh_modulus_bits} bits across {data_limbs} limbs |",
            f"| Ciphertext key modulus | {key_modulus_bits} bits including the {special_prime_bits}-bit special prime |",
            f"| Final encrypted-output honest noise | {output_ciphertexts_measured} ciphertext(s) at one {output_modulus_bits}-bit data prime; exact maximum canonical error {output_maximum_canonical_error_norm} ({output_maximum_canonical_error_norm_bits} bits; target at most {output_target_maximum_norm_bits}: `{output_target_result}`); secondary minimum invariant budget {output_minimum_noise_budget} bits (implied phase-norm bit count {output_maximum_phase_norm_bits}) |",
            f"| Post-verification honest payload-output noise audit | {milliseconds(client_output_noise_audit[0])} wall; {milliseconds(client_output_noise_audit[1])} CPU; excluded from verification and per-request client time |",
            f"| Peak RSS | setup {bytes_text(setup_rss)}; server {bytes_text(server_rss)}; client {bytes_text(client_rss)} |",
            f"| Admitted server phase peak | {bytes_text(admitted_live_storage)} live storage; {bytes_text(admitted_resident)} resident RAM |",
            "",
            "The protocol used exactly one encrypted-input request and one encrypted-output-and-proof response. Peer idle wait is excluded from both per-request totals. Reusable setup and server certification are reported separately; one-shot work-root and resource admission are charged to the per-request server total even when reserved before request arrival.",
            *payload_pipeline_section,
            "",
            "## Workload and provenance",
            "",
            "| Property | Bound value |",
            "|---|---:|",
            f"| Variant/profile | `{args.variant}` / `{args.profile}` |",
            f"| Fiat–Shamir schedule | `{fiat_shamir_schedule}` |",
            f"| GKR claim transition | `{claim_transition}` |",
            f"| Geometry | `N={slots}`, `B={lanes}`, depth {depth}, width {width} |",
            f"| Inputs / outputs | {inputs} / {outputs} ciphertexts |",
            f"| Payload operations | {payload_operations:,} |",
            f"| Plaintext modulus | {plain_modulus:,} |",
            f"| Fresh data modulus | {fresh_modulus_bits} bits across {data_limbs} limbs |",
            f"| Key modulus | {key_modulus_bits} bits including the {special_prime_bits}-bit special prime |",
            f"| Data-prime bit schedule (bottom to top) | `{','.join(map(str, data_prime_widths))}` |",
            f"| Data primes (bottom to top) | `{','.join(map(str, data_primes))}` |",
            f"| Special prime | `{special_prime}` |",
            f"| Proof-ingress policy | `{proof_ingress_policy}` |",
            f"| Proof-ingress schedule digest | `{proof_ingress_digest}` |",
            f"| Fixed proof-ingress RNS limbs by layer | `{','.join(map(str, proof_ingress_schedule))}` |",
            f"| Payload modulus switches after layer | `{','.join(map(str, payload_switch_schedule))}` |",
            f"| Git revision | `{require(setup, 'environment.git_commit', 'setup')}` |",
            f"| Build / SEAL / SHA-256 acceleration | `{require(setup, 'environment.build_type', 'setup')}` / `{require(setup, 'environment.seal_acceleration', 'setup')}` / `{setup.get('environment.sha256_acceleration', 'not-reported')}` |",
            f"| Host | `{require(setup, 'environment.cpu', 'setup')}`; {bytes_text(integer(setup, 'environment.ram_bytes', 'setup'))} RAM |",
            f"| Pinned CPUs | setup `{setup_affinity}`; server `{server_cpu}`; client `{client_cpu}`; observer excluded from measured role CPU |",
            f"| Threading | setup: `{setup_workers}` worker(s); server and client: `single-cpu-process` |",
            f"| Setup interval (Unix ms) | {setup_started} -- {setup_finished} |",
            f"| Request publication / server observation (Unix ms) | {request_published} / {request_observed} |",
            f"| Response publication / client observation (Unix ms) | {response_published} / {response_observed} |",
            f"| Server / client completion (Unix ms; independently ordered) | {server_finished} / {client_finished} |",
            "",
            "Publication-completion and peer-observation timestamps may be reversed by at most one polling interval when the peer observes the atomic file publication before the publisher samples its completion time.",
            "",
            "## Transcript-packing R1CS geometry",
            "",
            (
                f"The current-profile geometry comes from the {r1cs_geometry_source}. "
                + (
                    "This executed target profile is also the selected target, so the two columns agree."
                    if args.profile != "quick"
                    else "The selected-target column is formula-only; it does not claim that the target profile was executed."
                )
            ),
            "",
            "| Quantity | Current profile | Selected target | Target / current |",
            "|---|---:|---:|---:|",
            f"| Workload | depth {depth}, width {width}, {payload_operations:,} operations | depth {target_depth}, width {target_width:,}, {target_payload_operations:,} operations | {workload_ratio:.3f}x operations |",
            f"| Aligned ciphertexts | {int(actual_r1cs['aligned_ciphertexts']):,} | {int(target_r1cs['aligned_ciphertexts']):,} | {ratio_text(int(target_r1cs['aligned_ciphertexts']), int(actual_r1cs['aligned_ciphertexts']))} |",
            f"| Well-formedness repetitions | {int(actual_r1cs['repetitions']):,} | {int(target_r1cs['repetitions']):,} | {ratio_text(int(target_r1cs['repetitions']), int(actual_r1cs['repetitions']))} |",
            f"| Ciphertext commitment | `{actual_r1cs['ciphertext_hash']}` | `{target_r1cs['ciphertext_hash']}` | -- |",
            f"| Ciphertext-commitment constraints | {int(actual_r1cs['ciphertext_commitment_constraints_total']):,} | {int(target_r1cs['ciphertext_commitment_constraints_total']):,} | {ratio_text(int(target_r1cs['ciphertext_commitment_constraints_total']), int(actual_r1cs['ciphertext_commitment_constraints_total']))} |",
            f"| Packing-relation constraints | {int(actual_r1cs['packing_relation_constraints']):,} | {int(target_r1cs['packing_relation_constraints']):,} | {ratio_text(int(target_r1cs['packing_relation_constraints']), int(actual_r1cs['packing_relation_constraints']))} |",
            f"| **Active R1CS constraints** | **{actual_active_constraints:,}** | **{target_active_constraints:,}** | **{active_constraint_ratio:.3f}x** |",
            f"| Matrix row extent after structural gaps | {actual_matrix_rows:,} | {target_matrix_rows:,} | {ratio_text(target_matrix_rows, actual_matrix_rows)} |",
            f"| **Spartan padded constraint domain** | **{actual_padded_constraints:,} (`2^{actual_domain_log}`)** | **{target_padded_constraints:,} (`2^{target_domain_log}`)** | **{padded_constraint_ratio:.3f}x** |",
            f"| Public inputs | {int(actual_r1cs['public_inputs']):,} | {int(target_r1cs['public_inputs']):,} | {ratio_text(int(target_r1cs['public_inputs']), int(actual_r1cs['public_inputs']))} |",
            f"| Active witness variables | {int(actual_r1cs['active_witness_variables']):,} | {int(target_r1cs['active_witness_variables']):,} | {ratio_text(int(target_r1cs['active_witness_variables']), int(actual_r1cs['active_witness_variables']))} |",
            f"| Witness extent | {int(actual_r1cs['witness_extent']):,} | {int(target_r1cs['witness_extent']):,} | {ratio_text(int(target_r1cs['witness_extent']), int(actual_r1cs['witness_extent']))} |",
            "",
            "## One-time/static setup",
            "",
        ]
    )
    lines.extend(table_timing(setup_rows))
    lines.extend(["", "### Persisted and admitted setup storage", "", "| Quantity | Bytes |", "|---|---:|"])
    storage_rows = [(key, integer(setup, key, "setup")) for key in sorted(setup) if key.startswith("storage.") and key.endswith("bytes")]
    for key, value in storage_rows:
        lines.append(f"| `{key}` | {bytes_text(value)} |")

    replay_plan_keys = (
        "storage.replay.selection_objective",
        "storage.replay.selected_checkpoint_layers",
        "storage.replay.used_nonpreferred_checkpoint",
        "storage.replay.selected_checkpoint_bytes",
        "storage.replay.persistent_reserve_bytes",
        "storage.replay.maximum_consumer_artifact_bytes",
        "storage.replay.admitted_peak_live_bytes",
        "memory.replay.dense_multiplication_alias_cache_peak_resident_bytes",
        "memory.replay.admitted_peak_resident_bytes",
        "work.replay.initial_forward_units",
        "work.replay.repeated_units",
        "work.replay.cumulative_units",
        "work.replay.cumulative_factor",
    )
    has_replay_plan = replay_plan_ledger_present(
        setup, replay_plan_keys, required=planner_preflight is not None
    )
    if has_replay_plan:
        if require(
            setup, "storage.replay.selection_objective", "setup"
        ) != "minimum-replay-work":
            raise ReportError("setup has an unsupported replay selection objective")
        nonpreferred = integer(
            setup, "storage.replay.used_nonpreferred_checkpoint", "setup"
        )
        if nonpreferred not in (0, 1):
            raise ReportError("setup has a non-Boolean replay checkpoint flag")
        replay_ledger = validate_replay_plan_ledger(
            setup,
            capacity,
            None
            if planner_preflight is None
            else (
                int(planner_preflight["maximum_numerator"]),
                int(planner_preflight["maximum_denominator"]),
            ),
        )
        if args.profile != "quick" and int(replay_ledger["repeated"]) != 0:
            raise ReportError(
                "target report contains nonzero payload replay work"
            )
        lines.extend(
            [
                "",
                "### Checkpoint-replay plan",
                "",
                "The objective minimizes the committed replay-work proxy among fully admitted schedules; it is not a measured minimum-wall-time claim.",
                "",
                "| Quantity | Selected value |",
                "|---|---:|",
                f"| Objective | `{require(setup, 'storage.replay.selection_objective', 'setup')}` |",
                f"| Checkpoint layers | `{require(setup, 'storage.replay.selected_checkpoint_layers', 'setup')}` |",
                f"| Uses a nonpreferred checkpoint | {'yes' if nonpreferred else 'no'} |",
                f"| Checkpoint storage | {bytes_text(int(replay_ledger['checkpoint_bytes']))} |",
                f"| Persistent reserve | {bytes_text(int(replay_ledger['persistent_reserve']))} |",
                f"| Largest downstream consumer artifact | {bytes_text(int(replay_ledger['consumer_artifact']))} |",
                f"| Admitted replay peak | {bytes_text(int(replay_ledger['admitted_peak']))} |",
                f"| Setup-selected dense multiplication alias-cache peak | {bytes_text(int(replay_ledger['alias_cache_resident_peak']))} relation-scoped resident bound |",
                f"| Admitted replay resident peak | {bytes_text(int(replay_ledger['admitted_resident_peak']))} |",
                f"| Initial forward work | {int(replay_ledger['initial']):,} units |",
                f"| Repeated replay work | {int(replay_ledger['repeated']):,} units |",
                f"| Cumulative work | {int(replay_ledger['cumulative']):,} units |",
                f"| Cumulative / initial | {require(setup, 'work.replay.cumulative_factor', 'setup')}x |",
            ]
        )

    lines.extend(["", "## Reusable server startup", ""])
    startup_rows = timing_rows(
        server,
        "timing.server.startup",
        "server",
        {"timing.server.startup.total"},
    )
    lines.extend(table_timing(startup_rows))
    lines.extend(
        [
            "",
            f"Startup total: **{milliseconds(server_startup[0])} wall / {milliseconds(server_startup[1])} CPU**. This is reported separately from the recurring request path.",
            f"Machine-readable startup scope: `{server_startup_scope}`.",
            f"Peer wait for the request: {milliseconds(server_wait[0])} wall / {milliseconds(server_wait[1])} CPU; excluded from startup and recurring server totals.",
            "",
            "## One-shot recurring server admission",
            "",
        ]
    )
    recurring_pre_request_rows = timing_rows(
        server,
        "timing.server.recurring_pre_request",
        "server",
        {"timing.server.recurring_pre_request.total"},
    )
    lines.extend(table_timing(recurring_pre_request_rows))
    lines.extend(
        [
            "",
            f"One-shot recurring admission total: **{milliseconds(server_recurring_pre_request[0])} wall / {milliseconds(server_recurring_pre_request[1])} CPU**. It is charged to the per-request total even when resources are reserved before request arrival.",
            f"Machine-readable recurring-admission scope: `{server_recurring_pre_request_scope}`.",
            "",
            "## Per-request server",
            "",
        ]
    )
    server_rows = timing_rows(
        server,
        "timing.server",
        "server",
        {
            "timing.server.startup.total",
            "timing.server.per_request_total",
            "timing.server.process_total",
            "timing.server.wait_for_request",
        }
        | {f"timing.server.startup.{name}" for name, _, _ in startup_rows}
        | {
            "timing.server.recurring_pre_request.total",
            *{
                f"timing.server.recurring_pre_request.{name}"
                for name, _, _ in recurring_pre_request_rows
            },
        },
    )
    lines.extend(table_timing(server_rows))
    lines.extend(
        [
            "",
            f"Per-request total: **{milliseconds(server_request[0])} wall / {milliseconds(server_request[1])} CPU**. Whole process including startup and peer wait: {milliseconds(server_process[0])} wall / {milliseconds(server_process[1])} CPU.",
            f"Machine-readable per-request scope: `{server_request_scope}`.",
        ]
    )
    if replay_io:
        lines.extend(
            [
                "",
                "### Checkpoint-replay source I/O",
                "",
                "These counters cover the common replay engine used by Base, Folded, and Laned. Monotone relations stream two disjoint source halves; a relation-scoped alias cache reads each distinct source once only when setup admits its exact decoded-cache-plus-staging peak against the selected/global resident cap and it avoids at least fourfold generic-path rereads. The cache may deliberately exceed the ordinary tiny-chunk relation peak and is released at the relation boundary.",
                "",
                "The generic-path count is the measured no-cache reference; net source-record reads avoided equal that reference minus the distinct records the cache still reads.",
                "",
                "| Phase | Fast path | Relations | Range readers | Source records read | No-cache reference / net reads avoided |",
                "|---|---|---:|---:|---:|---:|",
            ]
        )
        for phase in ("forward", "reverse"):
            values = replay_io[phase]
            lines.append(
                f"| `{phase}` | monotone streams | {values['monotone_relations']:,} | {values['monotone_range_readers']:,} | {values['monotone_source_records']:,} | -- |"
            )
            lines.append(
                f"| `{phase}` | alias cache | {values['alias_cached_relations']:,} | {values['alias_cache_range_readers']:,} | {values['alias_cache_distinct_source_records']:,} | {values['alias_cache_logical_source_uses']:,} logical uses; {values['alias_cache_generic_source_records']:,} generic-path records; {values['alias_cache_generic_source_records'] - values['alias_cache_distinct_source_records']:,} net reads avoided |"
            )
        lines.extend(
            [
                "",
                "Identity affine relations can publish a distinct private namespace by hard-linking the already validated one-layer payload file. Reused layer bytes are existing file lengths, not newly allocated storage; unique bytes are the new alias manifest only. Capability-only link failures use the ordinary admitted materializer.",
                "",
                "| Phase | Linked relations | Capability fallbacks | Records reused | Existing layer bytes reused | Unique alias bytes written |",
                "|---|---:|---:|---:|---:|---:|",
            ]
        )
        for phase in ("forward", "reverse"):
            values = replay_io[phase]
            lines.append(
                f"| `{phase}` | {values['identity_affine_alias_relations']:,} | {values['identity_affine_alias_fallbacks']:,} | {values['identity_affine_alias_records_reused']:,} | {bytes_text(values['identity_affine_alias_layer_bytes_reused'])} | {bytes_text(values['identity_affine_alias_unique_bytes_written'])} |"
            )
    if "work.gkr.multiplication_sort.artifacts" in server:
        lines.extend(
            [
                "",
                "### GKR multiplication-source ordering",
                "",
                "| Quantity | Measured value |",
                "|---|---:|",
                f"| Multiplication artifacts | {integer(server, 'work.gkr.multiplication_sort.artifacts', 'server'):,} |",
                f"| Initial runs / total runs created | {integer(server, 'work.gkr.multiplication_sort.initial_runs', 'server'):,} / {integer(server, 'work.gkr.multiplication_sort.runs_created', 'server'):,} |",
                f"| Merge passes / maximum open runs | {integer(server, 'work.gkr.multiplication_sort.merge_passes', 'server'):,} / {integer(server, 'work.gkr.multiplication_sort.maximum_open_runs', 'server'):,} |",
                f"| Peak buffered payload | {bytes_text(integer(server, 'memory.gkr_multiplication_sort_peak_buffered_payload_bytes', 'server'))} |",
                f"| Temporary bytes written | {bytes_text(integer(server, 'storage.gkr_multiplication_sort_temporary_bytes_written', 'server'))} |",
                f"| Temporary bytes retained | {bytes_text(integer(server, 'storage.gkr_multiplication_sort_retained_temporary_bytes', 'server'))} |",
                "",
                "The reorder arena is one-shot: the retained-temporary row must be zero before the immutable multiplication source is consumed.",
            ]
        )
    lines.extend(
        [
            "",
            "### Measured FHE operation counts",
            "",
            "An operation on an RNS ciphertext contributes one limb operation per active coefficient-modulus limb. The bucket column records `limbs:calls`.",
            "",
            "| Server stage | Operation | Calls | Limb operations | Calls by RNS limbs |",
            "|---|---|---:|---:|---:|",
        ]
    )
    for operation_stage in ("server_payload_evaluation", "server_proving"):
        for operation, calls, limb_operations, buckets in operation_rows(
            server, operation_stage, "server"
        ):
            lines.append(
                f"| `{operation_stage}` | `{operation}` | {calls:,} | {limb_operations:,} | `{buckets}` |"
            )
    lines.extend(client_computation_table(client, computation_ledger))
    lines.extend(
        [
            "",
            "## Per-request client and verifier",
            "",
        ]
    )
    client_rows = timing_rows(
        client,
        "timing.client",
        "client",
        {
            "timing.client.per_request_total",
            "timing.client.process_total",
            "timing.client.wait_for_response",
            "timing.client.honest_output_noise_audit",
            *{f"timing.client.{field}" for field in CLIENT_COMPUTATION_FIELDS
              if field not in ("encrypt_inputs", "per_request_total")},
        },
    )
    client_auxiliary_names = {
        "load_preprocessing", "encode_request", "read_response_file", "decode_response", "open_response",
        "construct_inputs",
        "generate_nonce",
        "bind_request_session",
        "publish_request",
    }
    verifier_detail_names = {
        "verify.transcript_packing",
        "verify.gate_mle_opening",
        *{f"verify.layer.{index}" for index in range(len(verifier_layers))},
    }
    recurring_client_rows = [
        row
        for row in client_rows
        if row[0] not in client_auxiliary_names
        and row[0] not in verifier_detail_names
    ]
    auxiliary_client_rows = [
        row for row in client_rows if row[0] in client_auxiliary_names
    ]
    lines.extend(table_timing(recurring_client_rows))
    lines.extend(
        [
            "",
            f"Per-request computation total: **{milliseconds(client_request[0])} wall / {milliseconds(client_request[1])} CPU**. Whole process including peer wait: {milliseconds(client_process[0])} wall / {milliseconds(client_process[1])} CPU.",
            f"Machine-readable per-request scope: `{client_request_scope}`.",
            f"Peer wait for the response: {milliseconds(client_wait[0])} wall / {milliseconds(client_wait[1])} CPU; excluded from the per-request total.",
            f"Post-verification client-secret honest payload-output noise audit: {milliseconds(client_output_noise_audit[0])} wall / {milliseconds(client_output_noise_audit[1])} CPU; excluded from both proof verification and the per-request total. It measured exact maximum canonical error {output_maximum_canonical_error_norm} ({output_maximum_canonical_error_norm_bits} bits). The minimum invariant budget was {output_minimum_noise_budget} bits, whose separate phase-noise diagnostic is {output_maximum_phase_norm_bits} bits from `modulus bits - budget - 1`. The proof verifier's transcript-packing well-formedness threshold checks remain inside `verify`; this audit is not one of those checks.",
            "The verifier detail rows below are diagnostic subphases of `verify`, not additional work to add to the per-request total.",
            "",
            "### Verifier reduction breakdown",
            "",
            f"Complete transcript-packing verification and message recovery: {milliseconds(verifier_transcript_packing[0])} wall / {milliseconds(verifier_transcript_packing[1])} CPU. Gate-MLE opening: {milliseconds(verifier_gate_mle[0])} wall / {milliseconds(verifier_gate_mle[1])} CPU.",
            "",
        ]
    )
    lines.extend(table_verifier_layers(verifier_layers))
    lines.extend(
        [
            "",
            "### Client reusable loading and fixture/session/transport bookkeeping",
            "",
        ]
    )
    lines.extend(table_timing(auxiliary_client_rows))
    lines.extend(
        [
            "",
            "Deterministic benchmark-input construction is fixture work. Nonce generation and session binding are reported for transparency but excluded from the requested cryptographic cost boundary; filesystem publication is local transport bookkeeping rather than client computation.",
            "",
            "## Exact proof and verifier spans",
            "",
            "These spans are emitted by the protocol progress journal. Nested spans are not additive; use them to localize work, not to construct a second total.",
            "",
            "| Role | Span | Wall | CPU |",
            "|---|---|---:|---:|",
        ]
    )
    for role, record in (("server", server), ("client", client)):
        if require(record, "telemetry.schema", role) != "laminate-protocol-progress-v1":
            raise ReportError(f"{role} published an unsupported telemetry schema")
        if require(record, "telemetry.logging_status", role) != "complete":
            raise ReportError(f"{role} protocol telemetry did not complete")
        count = integer(record, "telemetry.completed_spans", role)
        if count == 0:
            raise ReportError(f"accepted packed {role} run published no telemetry spans")
        for index in range(count):
            prefix = f"telemetry.span.{index}"
            name = require(record, f"{prefix}.name", role)
            wall = number(record, f"{prefix}.wall_ms", role)
            cpu = number(record, f"{prefix}.cpu_ms", role)
            lines.append(f"| {role} | `{name}` | {milliseconds(wall)} | {milliseconds(cpu)} |")

    lines.extend(
        [
            "",
            "## Proof, communication, and resources",
            "",
            "| Quantity | Measured value |",
            "|---|---:|",
        ]
    )
    for role, record in (("server", server), ("client", client)):
        for key in sorted(record):
            if key.startswith("wire.") and key.endswith("bytes"):
                lines.append(f"| `{role}.{key}` | {bytes_text(integer(record, key, role))} |")
    for role, record in (("setup", setup), ("server", server), ("client", client)):
        for key in sorted(record):
            if key.startswith("memory.") and key.endswith("bytes"):
                lines.append(
                    f"| `{role}.{key}` | {bytes_text(integer(record, key, role))} |"
                )
    for key in sorted(server):
        if key.startswith("proof.") and key.endswith("bytes"):
            lines.append(f"| `server.{key}` | {bytes_text(integer(server, key, 'server'))} |")
    for key in sorted(server):
        if key.startswith("storage.") and key.endswith("bytes"):
            lines.append(f"| `server.{key}` | {bytes_text(integer(server, key, 'server'))} |")
    lines.extend(
        [
            "",
            "Peak RSS values are whole-process high-water marks. Storage and memory values above are either measured artifact bytes or explicitly named admission bounds; phase-local peaks are not summed.",
            "",
        ]
    )
    if storage_provenance is not None:
        setup_storage, server_storage = storage_provenance
        storage_rows = target_storage_report_rows(
            setup_storage, server_storage
        )
        lines.extend(
            [
                "## Target storage provenance",
                "",
                "| Property | Recorded value |",
                "|---|---:|",
                *storage_rows,
                "",
                "The GCP wrapper captured these immutable snapshots outside the measured setup and server timers. They prove which filesystem held the run; available bytes are boundary observations, not a live-storage high-water mark.",
                "",
            ]
        )
    if planner_preflight is not None:
        lines.extend(
            [
                "## Host-derived checkpoint planner",
                "",
                "| Preflight quantity | Formula-only result |",
                "|---|---:|",
                f"| Classification | `{planner_preflight['classification']}` |",
                f"| Observed available disk | {bytes_text(int(planner_preflight['observed_available']))} |",
                f"| Reserved free disk | {bytes_text(int(planner_preflight['min_free']))} |",
                f"| Gross live-disk budget | {bytes_text(int(planner_preflight['gross_live']))} |",
                f"| Conservative client-private persistence | {bytes_text(int(planner_preflight['client_private_reserve']))} |",
                f"| Preflight net server live-disk cap | {bytes_text(int(planner_preflight['max_live']))} |",
                f"| Server-common reserve inside that cap | {bytes_text(int(planner_preflight['server_common_reserve']))} |",
                f"| Exact client-private persistence | {bytes_text(int(planner_preflight['exact_client_private']))} |",
                f"| Exact net server live-disk cap | {bytes_text(int(planner_preflight['exact_server_live']))} |",
                f"| Observed physical RAM | {bytes_text(int(planner_preflight['observed_ram']))} |",
                f"| Reserved host RAM | {bytes_text(int(planner_preflight['ram_safety_reserve']))} |",
                f"| Gross resident-memory budget | {bytes_text(int(planner_preflight['gross_resident']))} |",
                f"| Conservative waiting-client resident reserve | {bytes_text(int(planner_preflight['client_resident_reserve']))} |",
                f"| Preflight net server resident cap | {bytes_text(int(planner_preflight['server_resident_cap']))} |",
                f"| Exact admitted client peak | {bytes_text(int(planner_preflight['exact_client_resident']))} |",
                f"| Exact net server resident cap | {bytes_text(int(planner_preflight['exact_server_resident']))} |",
                f"| Required available at setup preflight | {bytes_text(int(planner_preflight['required_available']))} |",
                f"| Selected replay peak | {bytes_text(int(planner_preflight['selected_peak']))} |",
                f"| Selected checkpoints | {int(planner_preflight['checkpoint_count']):,}, totaling {bytes_text(int(planner_preflight['checkpoint_bytes']))} |",
                f"| Payload replay work | {int(planner_preflight['initial_work']):,} initial + {int(planner_preflight['repeated_work']):,} repeated = {int(planner_preflight['cumulative_work']):,} cumulative |",
                f"| Cumulative recomputation factor | {float(planner_preflight['recomputation_factor']):.6f}x (policy maximum {int(planner_preflight['maximum_numerator'])}/{int(planner_preflight['maximum_denominator'])} = {int(planner_preflight['maximum_numerator']) / int(planner_preflight['maximum_denominator']):.3f}x) |",
                "",
                "This preflight is derived from the exact compiled trace before SEAL contexts, ciphertexts, checkpoints, or preprocessing artifacts are created. The gross disk budget is observed available space minus the 100 GB free-space floor. The gross resident budget is physical RAM minus an explicit 16 GB OS/measurement reserve and 64 GB page-cache reserve. Before choosing checkpoints, preflight subtracts conservative bounds for client-private persistence and the concurrently waiting client. Setup later binds the measured client-private bytes, the exact admitted client peak, and the corresponding exact net server caps. The 128 GB server-common disk reserve is inside each server disk cap; it is not a RAM cap. These are admission calculations, not measured high-water marks.",
                "",
            ]
        )
    if diagnostic:
        if target_projection is None:
            raise ReportError("diagnostic run is missing its target projection")
        lines.extend(
            [
                "## Target expectations (projection, not measurement)",
                "",
                "This diagnostic cannot support an integrity claim, but it does support explicit cost sensitivities. The estimates below rescale measured single-thread CPU work on this machine class under the stated assumptions.",
                "",
                "| Component | Current measured CPU | Selected-target CPU-work sensitivity |",
                "|---|---:|---:|",
                f"| Payload evaluation | {milliseconds(payload_timing[1])} | {milliseconds(target_projection['payload_cpu_ms'])} |",
                f"| Non-Spartan proof remainder | {milliseconds(non_spartan_prove_cpu)} | {milliseconds(target_projection['non_spartan_cpu_ms'])}, under coarse workload scaling |",
                f"| Transcript-packing Spartan | {milliseconds(spartan_prove[1])} | {milliseconds(target_projection['spartan_linear_cpu_ms'])} by padded-domain scaling; {milliseconds(target_projection['spartan_transform_cpu_ms'])} when also charging transform depth |",
                f"| **Total per-request server CPU** | **{milliseconds(server_request[1])}** | **{milliseconds(target_projection['server_linear_cpu_ms'])} to {milliseconds(target_projection['server_transform_cpu_ms'])}** |",
                f"| **Per-request client, query-only sensitivity** | **{milliseconds(client_request[1])}** | **{milliseconds(target_projection['client_query_cpu_ms'])} to {milliseconds(target_projection['client_query_depth_cpu_ms'])}** |",
                f"| **Per-request client, broader conditional sensitivity** | **{milliseconds(client_request[1])}** | **{milliseconds(target_projection['client_planning_cpu_ms'])} to {milliseconds(target_projection['client_planning_high_cpu_ms'])}** |",
                "",
                "These are single-thread CPU-work sensitivities, not elapsed or wall-time projections. Measured CPU utilization is not a wall-time conversion; target wall time depends on the admitted host and storage path and must be measured.",
                "",
                f"Payload uses the workload ratio `{target_payload_operations:,} / {payload_operations:,} = {workload_ratio:.3f}x`. The non-Spartan proof remainder contains GKR plus smaller work with other scaling variables, so applying that same ratio is deliberately coarse. Transcript-packing proving uses the `{padded_constraint_ratio:.3f}x` padded-domain ratio; its second figure also applies the domain-depth ratio `{target_domain_log} / {actual_domain_log}`.",
                "",
                f"The server CPU rows do not charge additional RNS limbs: they rescale the measured profile's CPU costs only by workload and Spartan-domain geometry, without modeling changes to BaseFold query work. The query-only client row holds non-Spartan work fixed, scales the complete measured Spartan-verifier span by the BaseFold total query-work ratio `{selected_query_work} / {actual_query_work}`, and optionally charges the domain-depth ratio `{target_domain_log} / {actual_domain_log}`. It is not a complete target-client projection, and it overcharges query-independent Spartan work while ignoring authentication-node sharing in batched multiproofs. The broader row additionally applies a measured-chain-plus-`{target_depth - depth + 1}`-limbs sensitivity (`{data_limbs}` to `{target_projection['candidate_target_data_limbs']:.0f}` limbs) to remaining non-verification work, scales response codec work by the response-size sensitivity below, and scales non-Spartan verification between the circuit-layer ratio and the coarse payload-work ratio. Both client ranges are conditional planning sensitivities, not measurements or bounds; additional target Gate-MLE work is not estimated.",
                "",
                "| Wire artifact | Current measured profile | Selected-target sensitivity |",
                "|---|---:|---:|",
                f"| Response under modeled components | {bytes_text(response_bytes)} | {bytes_text(round(target_projection['response_query_bytes']))} to {bytes_text(round(target_projection['response_query_depth_bytes']))} |",
                f"| Request | {bytes_text(request_bytes)} | not estimated; use the fixed target chain's exact serialized ciphertexts |",
                "",
                f"The response sensitivity scales commitment digests by the aligned-ciphertext ratio, well-formedness reveals by `{selected_t} / {actual_t}`, digit ciphertexts by their count ratio, and Spartan bytes first by `{selected_query_work} / {actual_query_work}` and then also by `{target_domain_log} / {actual_domain_log}`. It holds the measured response envelope and other committed-GKR bytes fixed. This is not a target measurement or bound, and it does not estimate any additional target Gate-MLE-opening bytes.",
                "",
                f"Scaling the setup-admitted transcript-packing live-storage envelope by the coincident `{padded_constraint_ratio:.3f}x` assignment/codeword-domain ratio gives about {bytes_text(round(target_projection['packing_live_bytes']))} for packing alone. This is neither an observed peak nor a whole-run disk bound; payload/GKR replay needs additional scratch.",
                "",
                "These are planning estimates from one diagnostic run, not target measurements, upper bounds, or security evidence. Use a completed target run for measured costs and its output-noise audit for honest-output noise; privacy estimates require the target profile's full key modulus and error distribution.",
                "",
            ]
        )
    return "\n".join(lines)


def publish(output: Path, contents: str) -> None:
    parent = output.parent
    if not parent.is_dir():
        raise ReportError(f"output parent is not a directory: {parent}")
    if os.path.lexists(output):
        if output.is_symlink() or not output.is_file():
            raise ReportError(f"refusing to replace non-regular output: {output}")
        try:
            with output.open("r", encoding="utf-8") as existing:
                marker = existing.readline().rstrip("\n")
        except OSError as error:
            raise ReportError(f"cannot inspect existing output {output}: {error}") from error
        if marker != "<!-- laminate-packed-summary-v1 -->":
            raise ReportError(
                "existing summary was not generated by this packed renderer"
            )
    descriptor, temporary_name = tempfile.mkstemp(prefix=".packed-summary-", dir=parent)
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
            raise ReportError(
                "benchmark lifecycle lock is not an owner-only regular file"
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ReportError("benchmark run is being cleaned up") from error
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--variant", choices=("folded", "laned"), required=True)
    parser.add_argument(
        "--profile",
        choices=tuple(PROFILE_GEOMETRY),
        required=True,
    )
    parser.add_argument("--lanes", type=int, choices=(1, 128, 16_384))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.variant == "laned" and args.lanes is None:
        raise ReportError("Laned summaries require --lanes 1, 128, or 16384")
    if args.variant == "folded" and args.lanes is not None:
        raise ReportError("--lanes is valid only for Laned summaries")
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
        contents = render(args)
        publish(args.output, contents)
    finally:
        fcntl.flock(lifecycle, fcntl.LOCK_UN)
        os.close(lifecycle)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReportError as error:
        raise SystemExit(f"error: {error}")
