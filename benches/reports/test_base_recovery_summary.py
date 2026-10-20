#!/usr/bin/env python3
"""Exercise recovered Base report admission and preserve its timing scope."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

renderer, concise_renderer, quick_source, target_source = map(Path, sys.argv[1:])


def read_record(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


def write_record(path, record):
    path.write_text("".join(f"{key}={value}\n" for key, value in record.items()))


def fresh_metadata(record):
    return {
        key.replace("timing.setup.key_restoration.", "timing.setup.key_generation."): value
        for key, value in record.items()
        if not key.startswith("recovery.")
        and key not in {"setup.mode", "timing.setup.scope", "storage.recovery_source_setup_bytes"}
    }


with tempfile.TemporaryDirectory(prefix="base-recovery-summary-") as temporary:
    root = Path(temporary)

    def fixture(name, source=target_source):
        run = root / name
        shutil.copytree(source, run)
        run.chmod(0o700)
        for path in run.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)
        return run

    def render(run, error=None, output=None):
        setup = read_record(run / "shared/setup-result.txt")
        command = [str(renderer), "--run-dir", str(run), "--variant", "base", "--profile", setup["run.profile"]]
        if output is not None:
            command += ["--output", str(output)]
        result = subprocess.run(command, text=True, capture_output=True)
        if error is None:
            assert result.returncode == 0, result.stderr
        else:
            assert result.returncode != 0 and error in result.stderr, result.stderr
        return result.stdout

    source_timing = {
        key.replace("timing.setup.key_generation.", "timing.setup.key_restoration."): value
        for key, value in read_record(quick_source / "shared/setup-result.txt").items()
        if key.startswith("timing.setup.")
    }

    def recovery_record(run):
        record = fresh_metadata(read_record(run / "shared/setup-result.txt"))
        record.pop("timing.setup.key_generation.wall_ms", None)
        record.pop("timing.setup.key_generation.cpu_ms", None)
        record.update(source_timing)
        record.update({
            "setup.mode": "recovered-preprocessing",
            "timing.setup.scope": "recovery-only-excludes-original-preprocessing",
            "recovery.source_run_directory": "/original/failed-base-run",
            "recovery.source_run_id": "b" * 64,
            "recovery.source_git_commit": "a" * 40,
            "recovery.source_setup_sha256": "c" * 64,
            "recovery.source_failure": "setup profile exceeds its decode limit",
            "storage.recovery_source_setup_bytes": "4096",
        })
        return record

    # The immutable original envelope remains 3.1 TB; actual recovery free
    # space may be lower (retained source artifacts) or higher (freed files).
    for name, snapshot, observed in (("less-free", 2_500_000_000_000, 2_490_000_000_000),
                                     ("more-free", 3_200_000_000_000, 3_190_000_000_000)):
        run = fixture(name)
        setup_path = run / "shared/setup-result.txt"
        record = recovery_record(run)
        record["storage.observed_setup_start_available_bytes"] = str(observed)
        write_record(setup_path, record)
        snapshot_path = run / "shared/storage-provenance.setup-start.txt"
        storage = read_record(snapshot_path)
        storage["storage.filesystem_available_bytes"] = str(snapshot)
        write_record(snapshot_path, storage)
        summary = render(run)
        for required in (
            "Setup recovery (active; original preprocessing excluded)",
            "Restore and validate SEAL context and keys",
            "500.000 ms",
            "recovery-only-excludes-original-preprocessing",
            "/original/failed-base-run",
            "Setup recovery active total",
        ):
            assert required in summary, required
        assert "SEAL context and key generation" not in summary
        assert "Setup recovery timing components are incomplete" not in summary
        write_record(setup_path, fresh_metadata(record))
        render(run, "host-derived disk and RAM policy")
        write_record(setup_path, record)

    good_run = root / "less-free"
    good_record = read_record(good_run / "shared/setup-result.txt")
    cases = {
        "insufficient-capacity": ("storage.observed_setup_start_available_bytes", "2199786919158", "host-derived disk and RAM policy"),
        "stale-snapshot": ("storage.observed_setup_start_available_bytes", "2500000000001", "host-derived disk and RAM policy"),
        "corrupt-disk-envelope": ("storage.host_budget.max_live_disk_bytes", "2999999999999", "host-derived disk and RAM policy"),
        "corrupt-ram-envelope": ("memory.host_budget.server_resident_cap_bytes", "283999999999", "host-derived disk and RAM policy"),
        "wrong-scope": ("timing.setup.scope", "complete-fresh-setup", "invalid recovered setup"),
        "wrong-source-path": ("recovery.source_run_directory", "/original/../failed-run", "invalid recovered setup"),
        "wrong-source-hash": ("recovery.source_setup_sha256", "x" * 64, "invalid recovered setup"),
        "wrong-failure": ("recovery.source_failure", "some other failure", "invalid recovered setup"),
        "conflicting-generation": ("timing.setup.key_generation.wall_ms", "0", "invalid recovered setup"),
        "wrong-mode": ("setup.mode", "fresh", "fresh setup contains recovery metadata"),
    }
    for name, (key, value, error) in cases.items():
        run = fixture(name, good_run)
        record = dict(good_record)
        record[key] = value
        write_record(run / "shared/setup-result.txt", record)
        render(run, error)
    for key in ("timing.setup.scope", "recovery.source_run_directory", "recovery.source_run_id",
                "recovery.source_git_commit", "recovery.source_setup_sha256", "recovery.source_failure",
                "storage.recovery_source_setup_bytes", "timing.setup.key_restoration.cpu_ms"):
        run = fixture("missing-" + key, good_run)
        record = dict(good_record)
        del record[key]
        write_record(run / "shared/setup-result.txt", record)
        result = subprocess.run([str(renderer), "--run-dir", str(run)], text=True, capture_output=True)
        assert result.returncode != 0, f"accepted missing {key}"

    # The user-facing concise summary must retain recovery provenance even
    # though its normal highlights intentionally omit setup timings.
    run = fixture("concise", quick_source)
    write_record(run / "shared/setup-result.txt", recovery_record(run))
    verbose = run / "verbose.md"
    render(run, output=verbose)
    concise = run / "concise.md"
    result = subprocess.run(
        [sys.executable, str(concise_renderer), "--input", str(verbose), "--output", str(concise),
         "--run-dir", str(run), "--variant", "base", "--profile", "quick"],
        text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    contents = concise.read_text()
    for required in ("## Recovered preprocessing", "excludes the original preprocessing work",
                     "recovery-only-excludes-original-preprocessing", "/original/failed-base-run",
                     "Source setup SHA-256"):
        assert required in contents, required
