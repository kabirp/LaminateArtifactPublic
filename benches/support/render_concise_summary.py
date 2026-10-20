#!/usr/bin/env python3
"""Render the canonical, reviewer-oriented benchmark summary.

The variant-specific renderers remain responsible for validating every source
artifact and producing their detailed internal report.  This final renderer
selects the run outcome, measured computation, proof sizes, and provenance
from that validated report.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import tempfile

from render_packed_checkpoint_summary import (
    PACKED_FIAT_SHAMIR_DESCRIPTION, GKR_CLAIM_TRANSITION_DESCRIPTION,
)


class ReportError(RuntimeError):
    pass


SOURCE_MARKERS = {
    "<!-- laminate-base-summary-v1 -->": "base",
    "<!-- laminate-packed-summary-v1 -->": "packed",
    "<!-- laminate-no-integrity-summary-v1 -->": "noIntegrity",
    "<!-- laminate-local-payload-summary-v1 -->": "local",
}
OUTPUT_MARKER = "<!-- laminate-benchmark-summary-v2 -->"
SAVED_RESPONSE_MARKER = "<!-- laminate-base-saved-response-v1 -->"
OWNED_MARKERS = {*SOURCE_MARKERS, OUTPUT_MARKER}
GCP_CONFIGURATION = (
    "`c4-highmem-48`; 10,000-GB Hyperdisk Balanced; "
    "2,400 MiB/s throughput; 150,000 IOPS (current campaign reference configuration)"
)
PLAINTEXT_MODULUS = 65_537


@dataclass(frozen=True)
class Table:
    header: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]


@dataclass(frozen=True)
class LiveContext:
    variant: str
    profile: str
    lanes: int | None
    setup: dict[str, str]


def read_regular(path: Path, description: str) -> str:
    try:
        metadata = os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode):
            raise ReportError(f"{description} is not a regular file: {path}")
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise ReportError(f"cannot read {description} {path}: {error}") from error


def parse_record(path: Path, description: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line_number, line in enumerate(
        read_regular(path, description).splitlines(), 1
    ):
        if not line or "=" not in line:
            raise ReportError(
                f"{path}:{line_number}: expected a nonempty key=value record"
            )
        key, value = line.split("=", 1)
        if not key or key in result:
            raise ReportError(f"{path}:{line_number}: duplicate or empty key")
        result[key] = value
    return result


def require(record: dict[str, str], key: str, description: str) -> str:
    try:
        return record[key]
    except KeyError as error:
        raise ReportError(f"{description} is missing {key}") from error


def parse_cells(line: str) -> tuple[str, ...]:
    if not line.startswith("|") or not line.rstrip().endswith("|"):
        raise ReportError(f"malformed Markdown table row: {line!r}")
    return tuple(cell.strip() for cell in line.strip().strip("|").split("|"))


def is_separator(line: str, columns: int) -> bool:
    if not line.startswith("|"):
        return False
    cells = parse_cells(line)
    return len(cells) == columns and all(
        re.fullmatch(r":?-{3,}:?", cell) is not None for cell in cells
    )


def parse_tables(lines: list[str]) -> list[Table]:
    tables: list[Table] = []
    index = 0
    while index + 1 < len(lines):
        if not lines[index].startswith("|"):
            index += 1
            continue
        header = parse_cells(lines[index])
        if not is_separator(lines[index + 1], len(header)):
            index += 1
            continue
        rows: list[tuple[str, ...]] = []
        index += 2
        while index < len(lines) and lines[index].startswith("|"):
            row = parse_cells(lines[index])
            if len(row) != len(header):
                raise ReportError("Markdown table has inconsistent column counts")
            rows.append(row)
            index += 1
        tables.append(Table(header, tuple(rows)))
    return tables


def heading_level(line: str) -> int | None:
    match = re.match(r"^(#{1,6})\s+", line)
    return len(match.group(1)) if match else None


def section(lines: list[str], heading: str) -> list[str]:
    matches = [index for index, line in enumerate(lines) if line == heading]
    if len(matches) != 1:
        raise ReportError(
            f"expected exactly one {heading!r} section, found {len(matches)}"
        )
    start = matches[0]
    level = heading_level(lines[start])
    assert level is not None
    end = len(lines)
    for index in range(start + 1, len(lines)):
        candidate = heading_level(lines[index])
        if candidate is not None and candidate <= level:
            end = index
            break
    return lines[start + 1 : end]


def optional_section(lines: list[str], heading: str) -> list[str] | None:
    matches = [index for index, line in enumerate(lines) if line == heading]
    if not matches:
        return None
    return section(lines, heading)


def first_table(lines: list[str], description: str) -> Table:
    tables = parse_tables(lines)
    if not tables:
        raise ReportError(f"{description} has no Markdown table")
    return tables[0]


def exact_row(table: Table, label: str) -> tuple[str, ...]:
    matches = [row for row in table.rows if row and row[0] == label]
    if len(matches) != 1:
        raise ReportError(
            f"expected exactly one {label!r} row, found {len(matches)}"
        )
    return matches[0]


def optional_row(table: Table, label: str) -> tuple[str, ...] | None:
    matches = [row for row in table.rows if row and row[0] == label]
    if len(matches) > 1:
        raise ReportError(f"found duplicate {label!r} rows")
    return matches[0] if matches else None


def value(table: Table, label: str) -> str:
    row = exact_row(table, label)
    if len(row) != 2:
        raise ReportError(f"{label!r} is not a two-column property row")
    return row[1]


def strip_code(value_text: str) -> str:
    result = value_text.strip()
    if len(result) >= 2 and result.startswith("`") and result.endswith("`"):
        return result[1:-1]
    return result


def markdown_table(header: tuple[str, ...], rows: list[tuple[str, ...]]) -> list[str]:
    if not rows:
        return []
    width = len(header)
    if any(len(row) != width for row in rows):
        raise ReportError("cannot render an inconsistent Markdown table")
    return [
        "| " + " | ".join(header) + " |",
        "| " + " | ".join("---" for _ in header) + " |",
        *("| " + " | ".join(row) + " |" for row in rows),
    ]


def append_section(output: list[str], title: str, body: list[str]) -> None:
    trimmed = list(body)
    while trimmed and not trimmed[0]:
        trimmed.pop(0)
    while trimmed and not trimmed[-1]:
        trimmed.pop()
    if not trimmed:
        return
    output.extend(["", f"## {title}", "", *trimmed])


def append_table_section(
    output: list[str], title: str, table: Table, rows: list[tuple[str, ...]]
) -> None:
    append_section(output, title, markdown_table(table.header, rows))


def without_table_rows(lines: list[str], labels: set[str]) -> list[str]:
    filtered: list[str] = []
    for line in lines:
        if line.startswith("|"):
            cells = parse_cells(line)
            if cells and cells[0] in labels:
                continue
        filtered.append(line)
    return filtered


def integer_from_text(text: str, pattern: str, description: str) -> int:
    match = re.search(pattern, text)
    if match is None:
        raise ReportError(f"cannot derive {description} from {text!r}")
    return int(match.group(1).replace(",", ""))


def scalar_gate_text(payload_operations: int, multiplier: int, name: str) -> str:
    scalar_gates = payload_operations * multiplier
    if scalar_gates <= 0:
        raise ReportError("derived scalar-gate count is not positive")
    return (
        f"{scalar_gates:,} ({payload_operations:,} payload gates × "
        f"{multiplier:,} {name})"
    )


def append_target_gcp_configuration(
    highlights: list[tuple[str, str]], profile: str
) -> None:
    if profile.startswith("target-"):
        highlights.append(("GCP VM and storage", GCP_CONFIGURATION))


def seconds_from_display(text: str) -> float:
    text = re.sub(r"\([^)]*\)", "", text).strip()
    if "wall" in text:
        text = text.split("wall", 1)[0].strip()
    total = 0.0
    matched = False
    for amount, unit in re.findall(r"([0-9]+(?:\.[0-9]+)?)\s*(h|m|s|ms)\b", text):
        matched = True
        number = float(amount)
        total += number * {"h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}[unit]
    if not matched:
        raise ReportError(f"cannot parse displayed duration {text!r}")
    return total


def seconds_text(seconds: float) -> str:
    if seconds < -0.002:
        raise ReportError("derived verifier subphase is negative")
    seconds = max(0.0, seconds)
    if seconds >= 3600:
        hours = int(seconds // 3600)
        remainder = seconds - hours * 3600
        minutes = int(remainder // 60)
        return f"{hours}h {minutes}m {remainder - minutes * 60:.3f} s"
    if seconds >= 60:
        minutes = int(seconds // 60)
        return f"{minutes}m {seconds - minutes * 60:.3f} s"
    return f"{seconds:.3f} s"


def wall_only(text: str) -> str:
    return text.split(" wall", 1)[0].strip().strip("*").strip()


def live_context(args: argparse.Namespace) -> LiveContext | None:
    values = (args.run_dir, args.variant, args.profile)
    if all(value is None for value in values) and args.lanes is None:
        return None
    if any(value is None for value in values):
        raise ReportError(
            "--run-dir, --variant, and --profile are all required for "
            "live-run rendering"
        )
    run_dir = args.run_dir
    assert run_dir is not None
    if not run_dir.is_absolute():
        raise ReportError("--run-dir must be absolute")
    if args.variant == "laned" and args.lanes not in (1, 128, 16_384):
        raise ReportError("Laned live summaries require --lanes 1, 128, or 16384")
    if args.variant != "laned" and args.lanes is not None:
        raise ReportError("--lanes is valid only for Laned summaries")
    setup = parse_record(run_dir / "shared" / "setup-result.txt", "setup result")
    if require(setup, "run.variant", "setup result") != args.variant:
        raise ReportError("summary variant disagrees with the setup result")
    if require(setup, "run.profile", "setup result") != args.profile:
        raise ReportError("summary profile disagrees with the setup result")
    return LiveContext(args.variant, args.profile, args.lanes, setup)


def live_plaintext_modulus(context: LiveContext) -> str:
    modulus = require(
        context.setup, "parameters.plaintext_modulus", "setup result"
    )
    try:
        numeric_modulus = int(modulus)
    except ValueError as error:
        raise ReportError("setup result has a nonnumeric plaintext modulus") from error
    if numeric_modulus != PLAINTEXT_MODULUS:
        raise ReportError(
            "setup result plaintext modulus disagrees with the campaign value"
        )
    return f"{PLAINTEXT_MODULUS:,}"


def client_computation_section(lines: list[str], packed: bool) -> list[str]:
    measured = section(lines, "## Client computation")
    # Keep the computation table and scope; nested diagnostic spans are separate.
    end = next((index for index, line in enumerate(measured)
                if heading_level(line) is not None), len(measured))
    return measured[:end]


def claim_transition_description(headline: Table, lines: list[str]) -> tuple[str, list[str]]:
    description = value(headline, "GKR layer transitions")
    if description != GKR_CLAIM_TRANSITION_DESCRIPTION:
        raise ReportError("unknown GKR layer transitions")
    return description, lines


def base_summary(lines: list[str], context: LiveContext | None) -> list[str]:
    headline = first_table(lines, "Base headline")
    transition, lines = claim_transition_description(headline, lines)
    profile = value(headline, "Profile").split(":", 1)[0]
    workload = value(headline, "Workload")
    n_fhe = integer_from_text(workload, r"n_FHE=([0-9,]+)", "n_FHE")
    slots = integer_from_text(workload, r"N=([0-9,]+)", "slot count")
    online = first_table(section(lines, "### Online server"), "Base server")
    client = first_table(section(lines, "### Per-request client"), "Base client")
    verifier_section = section(lines, "### Client GKR verifier detail")
    verifier = first_table(
        verifier_section, "Base verifier"
    )
    plaintext = integer_from_text(
        value(headline, "FHE parameter policy"), r"t=([0-9,]+)", "plaintext modulus"
    )
    if plaintext != PLAINTEXT_MODULUS:
        raise ReportError("Base plaintext modulus disagrees with the campaign value")
    highlights: list[tuple[str, str]] = [
        ("Laminate variant", "Base"),
        ("GKR layer transitions", transition),
        ("Payload profile", f"`{profile}`"),
        ("Scalar gates", scalar_gate_text(n_fhe, slots, "slots")),
        (
            "Initial ciphertext modulus (data primes only)",
            value(headline, "Initial ciphertext modulus"),
        ),
        ("Plaintext modulus", f"{PLAINTEXT_MODULUS:,}"),
        (
            "VCoED server wall time",
            wall_only(value(headline, "Online server (active; idle excluded)")),
        ),
        ("↳ Payload computation", wall_only(exact_row(online, "Evaluate encrypted payload")[2])),
        ("↳ GKR proving", wall_only(exact_row(online, "Produce GKR proof")[2])),
    ]
    computation = client_computation_section(lines, packed=False)
    computation_table = first_table(computation, "Base client computation")
    highlights.extend((row[0], row[1]) for row in computation_table.rows)
    append_target_gcp_configuration(highlights, profile)
    highlights.append(
        ("Proof-ingress schedule", value(headline, "Base proof-ingress schedule"))
    )
    if context is not None:
        if context.variant != "base" or context.profile != profile:
            raise ReportError("Base live arguments disagree with Markdown")

    output = [
        OUTPUT_MARKER,
        f"# Laminate Base benchmark summary — {profile}",
        "",
        "**PASS** — setup, server, and client completed, and the client "
        "accepted the proof.",
        "",
        "## Highlights",
        "",
        *markdown_table(("Highlight", "Measured result"), highlights),
    ]
    append_section(output, "Server layer reductions", section(lines, "### Server layer reductions"))
    append_section(
        output,
        "Sumcheck round details",
        section(lines, "### Sumcheck rounds (individual)"),
    )
    verifier_rows = list(verifier.rows)
    append_section(output, "Client computation", computation)
    verifier_detail = [
        *markdown_table(verifier.header, verifier_rows),
        "",
        "Layer-reduction and terminal-opening spans are nested inside the "
        "proof-verification timer and are non-additive.",
    ]
    append_section(output, "Client verifier details", verifier_detail)
    append_section(
        output,
        "Server FHE operation ledger",
        section(lines, "## Server FHE operation ledger"),
    )
    append_section(output, "Protocol artifacts", section(lines, "## Protocol artifacts"))
    append_section(output, "Memory and storage", section(lines, "## Memory and storage"))

    if "### Recovered preprocessing" in lines:
        append_section(
            output,
            "Recovered preprocessing",
            [
                "Setup timing covers recovery only and excludes the original "
                "preprocessing work. SEAL keys were restored and validated.",
                "",
                *section(lines, "### Recovered preprocessing"),
            ],
        )

    provenance_table = first_table(section(lines, "## Provenance"), "Base provenance")
    provenance_rows = [
        row
        for row in provenance_table.rows
        if row[0]
        not in {
            "Git commit",
            "Git dirty",
            "Run ID",
            "FHE backend",
            "Exact data-prime schedule",
        }
    ]
    append_table_section(output, "Provenance", provenance_table, provenance_rows)
    return output


def packed_summary(lines: list[str], context: LiveContext | None) -> list[str]:
    headline = first_table(lines, "packed headline")
    transition, lines = claim_transition_description(headline, lines)
    fiat_shamir_description = value(headline, "Fiat–Shamir composition")
    if fiat_shamir_description != PACKED_FIAT_SHAMIR_DESCRIPTION:
        raise ReportError("unknown packed Fiat–Shamir composition")

    workload_section = section(lines, "## Workload and provenance")
    workload = first_table(workload_section, "packed workload")
    variant_profile = strip_code(value(workload, "Variant/profile"))
    match = re.fullmatch(
        r"(folded|laned)`?\s*/\s*`?(quick|target-(?:balancedLaned|mulHeavyPyramid))", variant_profile
    )
    if match is None:
        # strip_code removes only an outer pair, while this cell has two code spans.
        match = re.fullmatch(
            r"`?(folded|laned)`?\s*/\s*`?(quick|target-(?:balancedLaned|mulHeavyPyramid))`?",
            value(workload, "Variant/profile"),
        )
    if match is None:
        raise ReportError("cannot parse packed variant/profile")
    variant, profile = match.groups()
    geometry = value(workload, "Geometry")
    slots = integer_from_text(geometry, r"N=([0-9,]+)", "slot count")
    lanes = integer_from_text(geometry, r"B=([0-9,]+)", "lane count")
    payload_operations = int(value(workload, "Payload operations").replace(",", ""))
    plaintext = int(
        strip_code(value(workload, "Plaintext modulus")).replace(",", "")
    )
    if plaintext != PLAINTEXT_MODULUS:
        raise ReportError("packed plaintext modulus disagrees with the campaign value")
    multiplier = slots if variant == "folded" else lanes
    multiplier_name = (
        "slots" if variant == "folded" else ("lane" if lanes == 1 else "lanes")
    )
    verifier_section = section(lines, "## Per-request client and verifier")
    verifier_table = first_table(verifier_section, "packed verifier")
    verifier_breakdown = section(lines, "### Verifier reduction breakdown")
    verifier_text = "\n".join(verifier_breakdown)
    transcript_match = re.search(
        r"Complete transcript-packing verification and message recovery:\s*([^\n]+?)\s+wall\s*/",
        verifier_text,
    )
    if transcript_match is None:
        raise ReportError("packed verifier is missing transcript-packing timing")
    transcript_wall = transcript_match.group(1).strip()
    gate_match = re.search(r"Gate-MLE opening:\s*([^\n]+?)\s+wall\s*/", verifier_text)
    if gate_match is None:
        raise ReportError("packed verifier is missing Gate-MLE timing")
    gate_wall = gate_match.group(1).strip()

    exact_spans = section(lines, "## Exact proof and verifier spans")
    spans = first_table(exact_spans, "packed exact spans")
    client_span_rows = [
        row
        for row in spans.rows
        if row[0] == "client"
        and "`transcript_packing." in row[1]
    ]

    if context is not None:
        if context.variant != variant or context.profile != profile:
            raise ReportError("packed live arguments disagree with Markdown")
        if variant == "laned" and context.lanes != lanes:
            raise ReportError("Laned live argument disagrees with Markdown lane count")

    highlights: list[tuple[str, str]] = [
        ("Laminate variant", variant.capitalize()),
        ("Payload profile", f"`{profile}`"),
        ("Fiat–Shamir composition", fiat_shamir_description),
        ("GKR layer transitions", transition),
    ]
    if variant == "laned":
        highlights.append(("Lanes", f"{lanes:,}"))
    highlights.extend(
        [
            ("Scalar gates", scalar_gate_text(payload_operations, multiplier, multiplier_name)),
        ]
    )
    highlights.extend(
        [
            (
                "Initial ciphertext modulus (data primes only)",
                value(headline, "Initial ciphertext data modulus"),
            ),
            ("Plaintext modulus", f"{PLAINTEXT_MODULUS:,}"),
            ("VCoED server wall time", wall_only(value(headline, "Per-request server"))),
            ("↳ Payload computation", wall_only(value(headline, "Payload evaluation"))),
            ("↳ Witness packing", wall_only(value(headline, "↳ Witness packing"))),
            ("↳ GKR proving", wall_only(value(headline, "↳ GKR"))),
            ("↳ Transcript packing", wall_only(value(headline, "↳ Transcript packing"))),
        ]
    )
    computation = client_computation_section(lines, packed=True)
    computation_table = first_table(computation, "packed client computation")
    highlights.extend((row[0], row[1]) for row in computation_table.rows)
    append_target_gcp_configuration(highlights, profile)
    highlights.append(
        (
            "Proof-ingress schedule",
            f"{value(workload, 'Proof-ingress policy')}; limbs by layer "
            f"{value(workload, 'Fixed proof-ingress RNS limbs by layer')}",
        )
    )

    output = [
        OUTPUT_MARKER,
        f"# Laminate {variant.capitalize()} benchmark summary — {profile}",
        "",
        "**PASS** — setup, server, and client completed, and the client "
        "accepted the proof.",
        "",
        "## Highlights",
        "",
        *markdown_table(("Highlight", "Measured result"), highlights),
    ]

    prefix = f"{variant}."
    reduction_rows = [
        row
        for row in spans.rows
        if row[0] == "server"
        and (
            row[1].startswith(f"`{prefix}reduction.reduction_")
            or ".sumcheck_round." in row[1]
            or ".slot_checkpoint." in row[1]
            or row[1] == f"`{prefix}gate_mle_opening`"
        )
    ]
    append_table_section(
        output, "Server layer reductions and sumcheck round details", spans, reduction_rows
    )

    append_section(output, "Client computation", computation)
    client_detail: list[str] = [
        f"Transcript-packing verification and message recovery: **{transcript_wall} wall**. "
        f"Gate-MLE opening: **{gate_wall} wall**. These are nested diagnostic spans; "
        "they do not define the disjoint computation hierarchy above.",
        "",
        *markdown_table(first_table(verifier_breakdown, "packed verifier reductions").header,
                        list(first_table(verifier_breakdown, "packed verifier reductions").rows)),
        "",
        "### Transcript-packing verifier spans",
        "",
        *markdown_table(spans.header, client_span_rows),
    ]
    append_section(output, "Client verifier details", client_detail)

    operations = first_table(
        section(lines, "### Measured FHE operation counts"), "packed FHE ledger"
    )
    append_table_section(output, "Server FHE operation ledger", operations, list(operations.rows))

    resources = first_table(
        section(lines, "## Proof, communication, and resources"), "packed resources"
    )
    artifact_rows = [
        (
            "Proving key / server preprocessing",
            value(headline, "Proving key / server preprocessing"),
        ),
        (
            "Verifying key / client preprocessing",
            value(headline, "Verifying key / client preprocessing"),
        ),
        *[
            row
            for row in resources.rows
            if ".wire." in row[0] or ".proof." in row[0]
        ],
    ]
    memory_rows = [
        row
        for row in resources.rows
        if ".memory." in row[0] or ".storage." in row[0]
    ]
    append_table_section(output, "Protocol artifacts", resources, artifact_rows)
    append_table_section(output, "Memory and storage", resources, memory_rows)

    provenance_rows = [
        row
        for row in workload.rows
        if row[0] in {
            "Build / SEAL / SHA-256 acceleration",
            "Host",
            "Pinned CPUs",
            "Threading",
        }
    ]
    provenance_body = markdown_table(workload.header, provenance_rows)
    storage_section = optional_section(lines, "## Target storage provenance")
    if storage_section is not None:
        storage_provenance = first_table(
            storage_section, "packed storage provenance"
        )
        storage_table = markdown_table(
            storage_provenance.header, list(storage_provenance.rows)
        )
        if provenance_body:
            provenance_body.extend(["", *storage_table])
        else:
            provenance_body = storage_table
    append_section(output, "Provenance", provenance_body)
    return output


def no_integrity_summary(
    lines: list[str], context: LiveContext | None
) -> list[str]:
    result = first_table(section(lines, "## Result"), "noIntegrity result")
    profile = strip_code(value(result, "Profile"))
    geometry = value(result, "Payload geometry")
    slots = integer_from_text(geometry, r"N=([0-9,]+)", "slot count")
    payload_operations = int(value(result, "Payload operations").replace(",", ""))
    data_bits = value(result, "Data / key modulus product").split("/", 1)[0].strip()
    highlights: list[tuple[str, str]] = [
        ("Laminate variant", "noIntegrity"),
        ("Payload profile", f"`{profile}`"),
        ("Scalar gates", scalar_gate_text(payload_operations, slots, "slots")),
        ("Initial ciphertext modulus (data primes only)", f"{data_bits} bits"),
        ("Plaintext modulus", f"{PLAINTEXT_MODULUS:,}"),
    ]
    if context is not None:
        if context.variant != "noIntegrity" or context.profile != profile:
            raise ReportError("noIntegrity live arguments disagree with Markdown")
        live_plaintext_modulus(context)
    highlights.extend(
        [
            (
                "Payload-only server wall time",
                wall_only(value(result, "Server online total, excluding peer wait")),
            ),
            ("↳ Payload computation", wall_only(value(result, "Server payload evaluation"))),
            ("Proof verification", "not applicable (no proof)"),
        ]
    )
    output_decryption = optional_row(result, "Client full output decryption")
    if output_decryption is not None:
        highlights.append(
            ("Client full output decryption", wall_only(output_decryption[1]))
        )
    append_target_gcp_configuration(highlights, profile)
    highlights.append(("Proof-ingress schedule", "not applicable (no proof)"))

    output = [
        OUTPUT_MARKER,
        f"# Laminate noIntegrity benchmark summary — {profile}",
        "",
        "**PASS** — the payload-only server returned an output ciphertext "
        "and the client decoded and fully decrypted it. No "
        "computation-integrity proof is provided.",
        "",
        "## Highlights",
        "",
        *markdown_table(("Highlight", "Measured result"), highlights),
    ]

    operations = first_table(
        section(lines, "## Server FHE operation ledger"), "noIntegrity FHE ledger"
    )
    append_table_section(output, "Server FHE operation ledger", operations, list(operations.rows))

    request_response = value(result, "Request / response").split("/", 1)
    if len(request_response) != 2:
        raise ReportError("noIntegrity request/response row is malformed")
    append_section(
        output,
        "Protocol artifacts",
        markdown_table(
            ("Artifact", "Size"),
            [
                ("Client → server request", request_response[0].strip()),
                ("Server → client response", request_response[1].strip()),
            ],
        ),
    )

    memory_terms = (
        "RSS",
        "RAM",
        "file-backed",
        "storage",
        "disk",
        "reserve",
        "buffer",
        "window",
        "readers",
        "prefetch",
        "replay",
        "checkpoint",
        "plan",
        "headroom",
    )
    memory_rows = [
        row
        for row in result.rows
        if any(term.lower() in row[0].lower() for term in memory_terms)
    ]
    append_table_section(output, "Memory and storage", result, memory_rows)

    provenance_rows: list[tuple[str, str]] = []
    build = optional_row(result, "Build")
    if build is not None:
        parts = [part.strip() for part in build[1].split(";")]
        provenance_rows.append(("Build", "; ".join(parts[1:])))
    for label in ("Pinned CPUs", "Target storage backend"):
        row = optional_row(result, label)
        if row is not None:
            provenance_rows.append(row)
    append_section(
        output,
        "Provenance",
        markdown_table(("Property", "Recorded value"), provenance_rows),
    )
    return output


def local_summary(lines: list[str], context: LiveContext | None) -> list[str]:
    result = first_table(section(lines, "## Result"), "local result")
    profile = strip_code(value(result, "Profile"))
    gate_total = optional_row(result, "Total scalar gate operations")
    scalar_total = (
        gate_total[1] if gate_total is not None
        else value(result, "Total scalar F_t operations")
    )
    highlights: list[tuple[str, str]] = [
        ("Laminate variant", "local"),
        ("Payload profile", f"`{profile}`"),
        ("Scalar gates", scalar_total),
        ("Plaintext modulus", f"{PLAINTEXT_MODULUS:,}"),
    ]
    if context is not None:
        if context.variant != "local" or context.profile != profile:
            raise ReportError("local live arguments disagree with Markdown")
        live_plaintext_modulus(context)
    highlights.extend(
        [
            (
                "Client-local payload evaluation",
                wall_only(value(result, "Client local payload evaluation")),
            ),
            ("Initial ciphertext modulus", "not applicable"),
            ("VCoED server wall time", "not applicable"),
            ("Proof verification", "not applicable"),
        ]
    )
    append_target_gcp_configuration(highlights, profile)
    highlights.append(("Proof-ingress schedule", "not applicable"))

    output = [
        OUTPUT_MARKER,
        f"# Local payload benchmark summary — {profile}",
        "",
        "**PASS** — the client completed the scalar payload computation on one logical CPU.",
        "",
        "## Highlights",
        "",
        *markdown_table(("Highlight", "Measured result"), highlights),
    ]
    append_section(output, "Scalar operation ledger", section(lines, "## Scalar operation ledger"))
    local_memory = without_table_rows(
        section(lines, "## Memory and execution model"), {"Arithmetic backend"}
    )
    append_section(output, "Memory and storage", local_memory)
    provenance_rows: list[tuple[str, str]] = []
    build = optional_row(result, "Build")
    if build is not None:
        parts = [part.strip() for part in build[1].split(";")]
        provenance_rows.append(("Build", "; ".join(parts[1:])))
    for label in ("Pinned CPUs",):
        row = optional_row(result, label)
        if row is not None:
            provenance_rows.append(row)
    append_section(
        output,
        "Provenance",
        markdown_table(("Property", "Recorded value"), provenance_rows),
    )
    return output


def render(source: str, context: LiveContext | None) -> str:
    lines = source.splitlines()
    if not lines:
        raise ReportError("source summary is empty")
    marker = lines[0]
    try:
        family = SOURCE_MARKERS[marker]
    except KeyError as error:
        raise ReportError(f"unsupported source summary marker: {marker!r}") from error
    if family == "base":
        output = base_summary(lines, context)
    elif family == "packed":
        output = packed_summary(lines, context)
    elif family == "noIntegrity":
        output = no_integrity_summary(lines, context)
    else:
        output = local_summary(lines, context)
    contents = "\n".join(output).rstrip() + "\n"
    forbidden = (
        "## Payload storage pipeline",
        "### Online server",
        "### Identity affine storage aliases",
        "### Per-request client",
        "## Per-request client and verifier",
        "## Evidence and warnings",
        "Git revision",
        "Git commit",
        "sec_level_type::none",
        "Client process total",
        "Whole process including peer wait",
        "Process exits",
        "FHE backend",
        "Exact data-prime schedule",
        "Setup wall time",
        "Run ID",
        "## Exact role commands",
        "Arithmetic backend",
        "q0=",
        "Data primes (bottom to top)",
    )
    present = [text for text in forbidden if text in contents]
    if present:
        raise ReportError(
            "concise summary retained forbidden report material: " + ", ".join(present)
        )
    # Reparse every emitted table to make column-count corruption fail closed.
    parse_tables(contents.splitlines())
    return contents


def publish(output: Path, contents: str) -> None:
    if not output.is_absolute():
        raise ReportError("--output must be absolute")
    if not output.parent.is_dir():
        raise ReportError(f"output parent is not a directory: {output.parent}")
    if os.path.lexists(output):
        if output.is_symlink() or not output.is_file():
            raise ReportError(f"refusing to replace non-regular output: {output}")
        existing = read_regular(output, "existing summary").splitlines()
        marker = existing[0] if existing else ""
        if marker not in OWNED_MARKERS:
            raise ReportError("existing output is not a renderer-owned summary")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".concise-summary-", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument(
        "--variant", choices=("base", "folded", "laned", "noIntegrity", "local")
    )
    parser.add_argument(
        "--profile", choices=("quick", "target-balancedLaned", "target-mulHeavyPyramid")
    )
    parser.add_argument("--lanes", type=int)
    args = parser.parse_args()
    source = read_regular(args.input, "source summary")
    if SAVED_RESPONSE_MARKER in source.splitlines():
        if args.run_dir is None:
            raise ReportError("saved-response summary requires --run-dir for source protection")
        source_run = args.run_dir.resolve(strict=True)
        output_parent = args.output.parent.resolve(strict=True)
        if (
            output_parent != args.input.parent.resolve(strict=True)
            or output_parent == source_run
            or source_run in output_parent.parents
            or output_parent in source_run.parents
        ):
            raise ReportError("saved-response summary output must remain in its separate diagnostic directory")
    context = live_context(args)
    publish(args.output, render(source, context))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReportError as error:
        raise SystemExit(f"error: {error}")
