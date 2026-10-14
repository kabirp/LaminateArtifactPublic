#!/usr/bin/env python3
"""Check report transactions through the runner's real launcher lock."""

from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


RUNNER = Path(sys.argv[1]).resolve()
BASH = sys.argv[2]
sys.argv[1:] = []
SOURCE = RUNNER.read_text()
ACTION_GATES = [
    match.group(0)
    for match in re.finditer(r'^case "\$action" in\n.*?^esac$', SOURCE, re.M | re.S)
]
LOCK_GATES = [
    gate for gate in ACTION_GATES if "-launcher.lock" in gate
]
RENDER_FUNCTION = re.search(
    r"^render_human_summary\(\) \{\n.*?^\}", SOURCE, re.M | re.S
).group(0)


class SummaryLockSelection(unittest.TestCase):
    def test_summary_and_retirement_share_the_launcher_lock(self):
        self.assertEqual(len(LOCK_GATES), 1)
        actions = LOCK_GATES[0].splitlines()[1].strip().removesuffix(")").split("|")
        self.assertIn("summary", actions)
        self.assertIn("archive_retire", actions)

    def test_missing_flock_rejected_before_report_lock(self):
        prerequisites = [gate for gate in ACTION_GATES if "command -v flock" in gate]
        self.assertEqual(len(prerequisites), 1)
        with tempfile.TemporaryDirectory(prefix="laminate-summary-prerequisite-") as root:
            for action in ("summary", "archive_retire"):
                result = subprocess.run(
                    [BASH, "-c",
                     'set -euo pipefail\n'
                     'action="$1" artifact_root="$2" variant=laned profile=quick\n'
                     'command() { return 1; }\n'
                     + prerequisites[0] + "\n" + LOCK_GATES[0],
                     "fixture", action, root],
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("flock is required", result.stderr)
                self.assertEqual(list(Path(root).iterdir()), [])


@unittest.skipUnless(shutil.which("flock"), "flock CLI is required for concurrent runner checks")
class SummaryTransactions(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="laminate-summary-lock-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.summary = self.root / "run/shared/report/summary.md"
        self.summary.parent.mkdir(parents=True)
        self.original = "<!-- laminate-benchmark-summary-v2 -->\noriginal\n"
        self.summary.write_text(self.original)
        self.renderer = self.root / "renderer"
        self.renderer.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            "import os, sys, time\n"
            "root = Path(os.environ['FIXTURE'])\n"
            "tag = os.environ['RENDER_TAG']\n"
            "(root / (tag + '.entered')).touch()\n"
            "if os.environ.get('HOLD_RENDER') == '1':\n"
            "    deadline = time.monotonic() + 10\n"
            "    while not (root / (tag + '.release')).exists():\n"
            "        if time.monotonic() >= deadline: sys.exit(24)\n"
            "        time.sleep(0.01)\n"
            "if os.environ.get('FAIL_RENDER') == '1': sys.exit(23)\n"
            "(root / 'run/shared/report/summary.md').write_text(\n"
            "    '<!-- laminate-packed-summary-v1 -->\\n' + tag + '\\n')\n"
        )
        self.renderer.chmod(0o700)
        concise = self.root / "concise.py"
        concise.write_text(
            "from pathlib import Path\n"
            "import os\n"
            "path = Path(os.environ['FIXTURE']) / 'run/shared/report/summary.md'\n"
            "text = path.read_text()\n"
            "assert text.startswith('<!-- laminate-packed-summary-v1 -->\\n')\n"
            "path.write_text(text.replace('laminate-packed-summary-v1',\n"
            "                             'laminate-benchmark-summary-v2', 1))\n"
        )
        self.harness = self.root / "run.sh"
        # Keep the real action gate and report transaction. Replace affinity,
        # benchmark validation, rendering, and archive I/O with tiny fixtures.
        self.harness.write_text(
            "set -euo pipefail\n"
            "action=\"$1\" artifact_root=\"$FIXTURE\" variant=laned profile=quick\n"
            + LOCK_GATES[0] + "\n"
            + RENDER_FUNCTION + "\n"
            "require_executable() { test -x \"$1\"; }\n"
            "require_setup_pass() { :; }\n"
            "run_is_complete() { :; }\n"
            "taskset() { shift 2; \"$@\"; }\n"
            "run_directory=\"$FIXTURE/run\" observer_cpu=2 local_variant=false\n"
            "benchmark=\"$FIXTURE/renderer\" benchmark_target=fixture\n"
            "renderer=\"$benchmark\" renderer_target=fixture python_renderer=false\n"
            "concise_renderer=\"$FIXTURE/concise.py\" lane_arguments=(--lanes 128)\n"
            "render_human_summary\n"
            "if [[ \"$action\" == archive_retire ]]; then\n"
            "  cp -- \"$summary\" \"$FIXTURE/archived-summary.md\"\n"
            "fi\n"
        )

    def start(self, action, tag, *, hold=False, fail=False):
        environment = dict(os.environ, FIXTURE=str(self.root), RENDER_TAG=tag,
                           HOLD_RENDER=str(int(hold)), FAIL_RENDER=str(int(fail)))
        process = subprocess.Popen(
            [BASH, str(self.harness), action], env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self.addCleanup(self.stop, process)
        return process

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=15)

    def wait_for_renderer(self, tag):
        deadline = time.monotonic() + 5
        while not (self.root / f"{tag}.entered").exists():
            if time.monotonic() >= deadline:
                self.fail(f"renderer {tag} did not start")
            time.sleep(0.01)

    def finish(self, process, expected):
        output, _ = process.communicate(timeout=15)
        self.assertEqual(process.returncode, expected, output)
        return output

    def assert_report(self, tag):
        self.assertEqual(self.summary.read_text(),
                         f"<!-- laminate-benchmark-summary-v2 -->\n{tag}\n")
        self.assertEqual(list(self.summary.parent.glob(".summary-backup.*")), [])

    def test_successful_render_blocks_failed_render_and_retirement(self):
        first = self.start("summary", "first", hold=True)
        self.wait_for_renderer("first")
        for action in ("summary", "archive_retire"):
            output = self.finish(self.start(action, action, fail=True), 1)
            self.assertIn("retry after it finishes", output)
            self.assertFalse((self.root / f"{action}.entered").exists())
        (self.root / "first.release").touch()
        self.finish(first, 0)
        self.assert_report("first")
        # Once the lock is free, a real rendering failure restores that report.
        self.finish(self.start("summary", "later-failure", fail=True), 23)
        self.assert_report("first")

    def test_failed_render_preserves_report_and_releases_lock(self):
        first = self.start("summary", "failure", hold=True, fail=True)
        self.wait_for_renderer("failure")
        self.finish(self.start("summary", "blocked-success"), 1)
        self.assertFalse((self.root / "blocked-success.entered").exists())
        (self.root / "failure.release").touch()
        self.finish(first, 23)
        self.assertEqual(self.summary.read_text(), self.original)
        self.finish(self.start("summary", "next-success"), 0)
        self.assert_report("next-success")

    def test_retirement_blocks_summary_until_report_is_preserved(self):
        retirement = self.start("archive_retire", "archive", hold=True)
        self.wait_for_renderer("archive")
        self.finish(self.start("summary", "blocked"), 1)
        self.assertFalse((self.root / "blocked.entered").exists())
        (self.root / "archive.release").touch()
        self.finish(retirement, 0)
        self.assert_report("archive")
        self.assertEqual((self.root / "archived-summary.md").read_bytes(),
                         self.summary.read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
