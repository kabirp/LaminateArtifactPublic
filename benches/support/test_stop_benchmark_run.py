#!/usr/bin/env python3
"""Signal validation is mocked; real advisory locks exercise inactivity checks."""

from contextlib import ExitStack, redirect_stdout
import fcntl
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import stop_benchmark_run as stop


class StopRunTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.run = self.root / "run"
        for directory in ("shared", "client", "server"):
            (self.run / directory).mkdir(parents=True)
        self.lifecycle = self.run / "shared/lifecycle.lock"
        self.lifecycle.write_text("")
        self.commands = {}
        self.held = {}
        self.pid_to_fd = {}
        self.sent = []
        self.stack.enter_context(patch.object(stop, "process_command", side_effect=self.commands.__getitem__))
        self.stack.enter_context(patch.object(stop, "open_pidfd", side_effect=self.open_pidfd))
        self.stack.enter_context(patch.object(stop, "send_term", side_effect=self.send_term))
        self.output = self.stack.enter_context(redirect_stdout(io.StringIO()))

    def open_pidfd(self, pid):
        self.pid_to_fd[pid] = os.open(os.devnull, os.O_RDONLY)
        return self.pid_to_fd[pid]

    def send_term(self, pidfd):
        self.sent.append(pidfd)
        pid = next(pid for pid, fd in self.pid_to_fd.items() if fd == pidfd)
        fcntl.flock(self.held[pid].fileno(), fcntl.LOCK_UN)

    def active(self, role="server", variant="base", pid=4242):
        path = self.run / stop.ROLE_FILES[role]
        path.write_text(json.dumps({"schema": "laminate-role-activity-v1", "role": role,
                                    "event": "start", "pid": pid}) + "\n")
        held = self.stack.enter_context(path.open())
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.held[pid] = held
        executable = {
            "base": "laminate_base_checkpoint_bench",
            "folded": "laminate_packed_checkpoint_bench",
            "laned": "laminate_packed_checkpoint_bench",
            "noIntegrity": "laminate_no_integrity_bench",
            "local": "laminate_local_payload_bench",
        }[variant]
        action = "setup" if role == "setup" else f"run_{role}"
        self.commands[pid] = [f"/build/benches/{executable}", action, "--variant", variant,
                              "--profile", "target-balancedLaned", "--run-dir", str(self.run)]
        return path

    def snapshot(self):
        return {str(path.relative_to(self.run)): path.read_bytes()
                for path in self.run.rglob("*") if path.is_file()}

    def test_inactive_run_ignores_stale_unrelated_pid_without_signaling(self):
        path = self.active()
        fcntl.flock(self.held[4242].fileno(), fcntl.LOCK_UN)
        self.commands[4242] = ["unrelated-program"]
        before = self.snapshot()
        stop.stop_run(self.run, "base", 0)
        self.assertEqual(self.sent, [])
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(path.exists())

    def test_verified_roles_all_variants_stop_and_preserve_artifacts(self):
        for variant in ("base", "folded", "laned", "noIntegrity", "local"):
            with self.subTest(variant=variant):
                roles = ("setup", "client") if variant == "local" else ("setup", "client", "server")
                for index, role in enumerate(roles):
                    self.active(role, variant, 4242 + index)
                before = self.snapshot()
                stop.stop_run(self.run, variant, 0)
                self.assertEqual(self.snapshot(), before)
        self.assertEqual(len(self.sent), 14)

    def test_mismatched_processes_never_receive_a_signal(self):
        cases = {
            "run": lambda command: command.__setitem__(-1, str(self.root / "other-run")),
            "variant": lambda command: command.__setitem__(3, "unselected"),
            "executable": lambda command: command.__setitem__(0, "/bin/unrelated"),
            "action": lambda command: command.__setitem__(1, "status"),
            "duplicate_run": lambda command: command.extend(["--run-dir", str(self.run)]),
            "duplicate_variant": lambda command: command.extend(["--variant", "local"]),
        }
        for variant in ("base", "noIntegrity", "local"):
            for name, change in cases.items():
                with self.subTest(variant=variant, name=name):
                    self.active("client", variant)
                    change(self.commands[4242])
                    with self.assertRaises(stop.StopError):
                        stop.stop_run(self.run, variant, 0)
                    self.assertEqual(self.sent, [])
                    fcntl.flock(self.held[4242].fileno(), fcntl.LOCK_UN)

    def test_all_candidates_checked_before_any_signal(self):
        for variant in ("base", "noIntegrity", "local"):
            with self.subTest(variant=variant):
                self.active("setup", variant, pid=4242)
                self.active("client", variant, pid=4243)
                self.commands[4243] = ["unrelated-program"]
                with self.assertRaises(stop.StopError):
                    stop.stop_run(self.run, variant, 0)
                self.assertEqual(self.sent, [])
                for held in self.held.values():
                    fcntl.flock(held.fileno(), fcntl.LOCK_UN)

    def test_local_rejects_active_server_before_signaling_its_client(self):
        self.active("client", "local", pid=4242)
        self.active("server", "local", pid=4243)
        with self.assertRaisesRegex(stop.StopError, "unsupported variant or role"):
            stop.stop_run(self.run, "local", 0)
        self.assertEqual(self.sent, [])

    def test_local_run_without_server_directory_stops_and_keeps_wrapper_records(self):
        (self.run / "server").rmdir()
        for relative in ("shared/client-measurement-attempt.lock",
                         "shared/measurement-campaign.lock"):
            (self.run / relative).touch()
        self.active("client", "local")
        before = self.snapshot()
        stop.stop_run(self.run, "local", 0)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.run / "server").exists())

    def test_baseline_wrapper_locks_must_finish_before_stopped_claim(self):
        for variant in ("noIntegrity", "local"):
            for relative in stop.WRAPPER_LOCKS:
                with self.subTest(variant=variant, lock=relative):
                    self.active("client", variant)
                    path = self.run / relative
                    path.touch()
                    held = self.stack.enter_context(path.open())
                    fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with self.assertRaisesRegex(stop.StopError, "remains active"):
                        stop.stop_run(self.run, variant, 0)
                    self.assertNotIn("STOPPED:", self.output.getvalue())
                    fcntl.flock(held.fileno(), fcntl.LOCK_UN)
        self.assertEqual(len(self.sent), 6)

    def test_symlinked_wrapper_lock_prevents_any_signaling(self):
        self.active("client", "noIntegrity")
        (self.run / "shared/client-measurement-attempt.lock").symlink_to(self.lifecycle)
        with self.assertRaises(stop.StopError):
            stop.stop_run(self.run, "noIntegrity", 0)
        self.assertEqual(self.sent, [])

    def test_held_lifecycle_prevents_stopped_claim(self):
        held = self.stack.enter_context(self.lifecycle.open())
        fcntl.flock(held.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        with self.assertRaisesRegex(stop.StopError, "remains active"):
            stop.stop_run(self.run, "base", 0)
        self.assertNotIn("STOPPED:", self.output.getvalue())

    def test_term_does_not_escalate_if_role_keeps_lock(self):
        self.active()
        with patch.object(stop, "send_term") as term:
            with self.assertRaisesRegex(stop.StopError, "no SIGKILL"):
                stop.stop_run(self.run, "base", 0)
            term.assert_called_once()
        self.assertNotIn("STOPPED:", self.output.getvalue())

    def test_invalid_and_symlinked_records_fail_without_signal(self):
        path = self.active()
        for text in ("broken\n", json.dumps({"event": "start", "pid": 4242}) + "\n"):
            path.write_text(text)
            with self.assertRaises(stop.StopError):
                stop.stop_run(self.run, "base", 0)
        fcntl.flock(self.held[4242].fileno(), fcntl.LOCK_UN)
        path.unlink()
        path.symlink_to(self.lifecycle)
        with self.assertRaises(stop.StopError):
            stop.stop_run(self.run, "base", 0)
        self.assertEqual(self.sent, [])

    def test_disappeared_pid_still_requires_inactivity(self):
        self.active()
        with patch.object(stop, "open_pidfd", side_effect=ProcessLookupError):
            with self.assertRaisesRegex(stop.StopError, "remains active"):
                stop.stop_run(self.run, "base", 0)
        self.assertEqual(self.sent, [])

    def test_exited_process_during_signal_still_requires_releasing_activity_lock(self):
        self.active("client", "noIntegrity")
        with patch.object(stop, "send_term", side_effect=ProcessLookupError) as term:
            with self.assertRaisesRegex(stop.StopError, "remains active"):
                stop.stop_run(self.run, "noIntegrity", 0)
            term.assert_called_once_with(self.pid_to_fd[4242])
        self.assertNotIn("STOPPED:", self.output.getvalue())

    def test_only_complete_initial_record_is_used(self):
        path = self.active()
        with path.open("a") as output:
            output.write('{"event":"heartbeat"')
        stop.stop_run(self.run, "base", 0)
        self.assertEqual(len(self.sent), 1)

    def test_truncated_initial_record_never_signals(self):
        path = self.active()
        path.write_text(path.read_text().rstrip("\n"))
        with self.assertRaisesRegex(stop.StopError, "incomplete"):
            stop.stop_run(self.run, "base", 0)
        self.assertEqual(self.sent, [])


@unittest.skipUnless(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
                     "Linux pidfds required")
class LinuxPidfdTests(unittest.TestCase):
    def test_real_pidfd_signals_only_the_controlled_child(self):
        # This separate integration check never impersonates a benchmark:
        # verify_command has independent rejection/acceptance coverage above.
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            pidfd = stop.open_pidfd(child.pid)
            try:
                self.assertEqual(Path(stop.process_command(child.pid)[0]).name, Path(sys.executable).name)
                stop.send_term(pidfd)
                self.assertEqual(child.wait(timeout=5), -signal.SIGTERM)
            finally:
                os.close(pidfd)
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
