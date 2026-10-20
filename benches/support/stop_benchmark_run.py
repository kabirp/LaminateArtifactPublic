#!/usr/bin/env python3
"""Stop only the verified measured processes of one immutable Linux run."""

import argparse
from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time


class StopError(RuntimeError):
    pass


ROLE_FILES = {
    "setup": "shared/setup-activity.jsonl",
    "client": "client/activity.jsonl",
    "server": "server/activity.jsonl",
}
VARIANT_EXECUTABLES = {
    "base": "laminate_base_checkpoint_bench",
    "folded": "laminate_packed_checkpoint_bench",
    "laned": "laminate_packed_checkpoint_bench",
    "noIntegrity": "laminate_no_integrity_bench",
    "local": "laminate_local_payload_bench",
}
WRAPPER_LOCKS = (
    "shared/client-measurement-attempt.lock",
    "shared/server-measurement-attempt.lock",
    "shared/measurement-campaign.lock",
)


def open_record(path):
    if path.resolve(strict=True) != path:
        raise StopError(f"noncanonical or symlinked record: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        os.close(fd)
        raise StopError(f"record must be a regular file owned by this user: {path}")
    return os.fdopen(fd, "r", encoding="utf-8")


def try_lock(record):
    try:
        fcntl.flock(record.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


def activity_pid(record, role):
    record.seek(0)
    # RoleActivity exclusively creates this immutable attempt file and writes
    # its start record first. Do not scan potentially large heartbeat logs or
    # their partially written final event to find the process identity.
    line = record.readline(64 * 1024 + 1)
    if len(line) > 64 * 1024 or not line.endswith("\n"):
        raise StopError(f"activity start record is incomplete or oversized: {record.name}")
    try:
        event = json.loads(line)
    except (ValueError, TypeError) as error:
        raise StopError(f"malformed activity start record: {record.name}") from error
    if (not isinstance(event, dict) or event.get("schema") != "laminate-role-activity-v1"
            or event.get("role") != role or event.get("event") != "start"):
        raise StopError(f"activity identity differs from selected role: {record.name}")
    pid = event.get("pid")
    if type(pid) is not int or pid <= 1:
        raise StopError(f"active role has no valid start PID: {record.name}")
    return pid


def open_pidfd(pid):
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise StopError("stopping active roles requires Linux pidfd support in Python 3.9+")
    return os.pidfd_open(pid)


def process_command(pid):
    raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    if not raw.endswith(b"\0"):
        raise StopError(f"PID {pid} has no complete process command")
    return [os.fsdecode(part) for part in raw[:-1].split(b"\0")]


def verify_command(command, run, variant, role):
    executable = VARIANT_EXECUTABLES.get(variant)
    if executable is None or role not in ROLE_FILES or (variant == "local" and role == "server"):
        raise StopError("unsupported variant or role")
    action = "setup" if role == "setup" else f"run_{role}"
    if len(command) < 2 or Path(command[0]).name != executable or command[1] != action:
        raise StopError(f"active {role} PID is not the expected benchmark executable/action")
    for flag, expected in (("--run-dir", str(run)), ("--variant", variant)):
        positions = [i for i, value in enumerate(command) if value == flag]
        if (len(positions) != 1 or positions[0] + 1 >= len(command)
                or command[positions[0] + 1] != expected):
            raise StopError(f"active {role} PID does not match exact {flag} {expected}")


def send_term(pidfd):
    signal.pidfd_send_signal(pidfd, signal.SIGTERM)


def stop_run(run, variant, timeout=30.0):
    run = Path(run)
    if not run.is_absolute() or run.resolve(strict=True) != run or not run.is_dir():
        raise StopError("--run-dir must be an existing canonical absolute directory")
    if variant not in VARIANT_EXECUTABLES:
        raise StopError("unsupported variant")
    if not 0 <= timeout <= 30:
        raise StopError("wait bound must be between zero and 30 seconds")
    with ExitStack() as stack:
        lifecycle = stack.enter_context(open_record(run / "shared/lifecycle.lock"))
        records = []
        # Wrappers retain these per-run locks until exit evidence is published.
        # They are absent for roles invoked directly, without run_gcp.sh.
        wrappers = []
        for relative in WRAPPER_LOCKS:
            path = run / relative
            if path.exists() or path.is_symlink():
                wrappers.append(stack.enter_context(open_record(path)))
        pending = []
        for role, relative in ROLE_FILES.items():
            path = run / relative
            if not path.exists() and not path.is_symlink():
                continue
            record = stack.enter_context(open_record(path))
            records.append(record)
            if try_lock(record):
                # Keep inactive role locks until the final inactivity check.
                continue
            pid = activity_pid(record, role)
            try:
                pidfd = open_pidfd(pid)
            except ProcessLookupError:
                continue  # Final lock checks must still prove this role stopped.
            stack.callback(os.close, pidfd)
            try:
                command = process_command(pid)
            except (FileNotFoundError, ProcessLookupError):
                continue
            verify_command(command, run, variant, role)
            pending.append((role, pid, pidfd))

        # Validate every candidate before signaling any process. pidfds keep a
        # PID recycled during validation from redirecting the eventual signal.
        for role, pid, pidfd in pending:
            try:
                send_term(pidfd)
                print(f"Sent SIGTERM to verified {role} PID {pid}.", flush=True)
            except ProcessLookupError:
                pass

        deadline = time.monotonic() + timeout
        while True:
            if (try_lock(lifecycle)
                    and all(try_lock(record) for record in records)
                    and all(try_lock(record) for record in wrappers)):
                print("STOPPED: lifecycle, role activity, and existing per-run wrapper locks are inactive.")
                print("Run artifacts are preserved; use explicit failed-run retirement when ready.")
                return
            if time.monotonic() >= deadline:
                raise StopError("run remains active after the bounded wait; no SIGKILL was sent")
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--variant", required=True, choices=tuple(VARIANT_EXECUTABLES))
    args = parser.parse_args()
    print("First interrupt the outer launch/follow shell with Ctrl-C so it cannot launch later roles.",
          file=sys.stderr, flush=True)
    try:
        stop_run(args.run_dir, args.variant)
    except (StopError, OSError, UnicodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
