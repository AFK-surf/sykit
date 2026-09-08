"""Exercise orchestration boundaries with a fake container engine, not Docker."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BuildTests(unittest.TestCase):
    def test_extraction_uses_build_id_and_check_rejects_extra_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "scripts").mkdir()
            shutil.copy(ROOT / "scripts/build.sh", repo / "scripts/build.sh")
            engine = repo / "engine"
            engine.write_text('''#!/usr/bin/env python3
import json, pathlib, sys
args = sys.argv[1:]
with open("calls.jsonl", "a") as log:
    log.write(json.dumps(args) + "\\n")
if args[0] == "build":
    pathlib.Path(args[args.index("--iidfile") + 1]).write_text("sha256:" + "a" * 64)
elif args[0] == "create":
    assert args[-2] == "sha256:" + "a" * 64, "extraction must use this build's immutable ID"
    assert "--pull=never" in args
    print("test-container")
elif args[0] == "cp":
    assert args[1] == "test-container:/artifacts/.", "do not copy Docker-injected root files"
    output = pathlib.Path(args[2])
    (output / "example.o").write_bytes(b"test object")
    (output / "SHA256SUMS").write_text("test checksums\\n")
elif args[0] == "rm":
    assert args[1] == "test-container"
else:
    raise AssertionError(args)
''')
            engine.chmod(0o755)
            env = dict(os.environ, CONTAINER_ENGINE=str(engine))
            command = ["sh", str(repo / "scripts/build.sh")]
            subprocess.run(command, env=env, check=True, capture_output=True)
            subprocess.run(command + ["--check"], env=env, check=True, capture_output=True)
            (repo / "objects/stale.o").write_bytes(b"obsolete")
            result = subprocess.run(command + ["--check"], env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            calls = [json.loads(line) for line in (repo / "calls.jsonl").read_text().splitlines()]
            for args in calls:
                if args[0] in ("build", "create"):
                    self.assertEqual(args[args.index("--platform") + 1], "linux/amd64")
            self.assertEqual(sum(args[0] == "rm" for args in calls), 3)
            self.assertIn("--no-cache", [args for args in calls if args[0] == "build"][1])

    def test_runtime_test_does_not_follow_dangling_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            tests = checkout / "crates/synch-sock/tests"
            tests.mkdir(parents=True)
            target = checkout / "must-not-be-created"
            link = tests / "sykit_artifacts.rs"
            link.symlink_to(target)
            result = subprocess.run(
                ["sh", str(ROOT / "scripts/test-runtime.sh"), str(checkout)],
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(target.exists())
            self.assertTrue(link.is_symlink())


if __name__ == "__main__":
    unittest.main()
