import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('session_client', ROOT / 'tools/session-client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class SessionTests(unittest.TestCase):
    def test_expired_invitation_never_downloads_or_starts(self):
        with patch.object(client.time, 'time', return_value=100), patch.object(client.subprocess, 'run') as run:
            with self.assertRaises(SystemExit):
                client.main({'expires_at': 100})
            run.assert_not_called()

    def test_refusing_consent_does_not_touch_machine(self):
        invitation = dict(expires_at=150, agent_key='agent')
        with patch.object(client.time, 'time', return_value=100), patch('builtins.input', return_value='no'), \
                patch.object(client.subprocess, 'run') as run, patch('sys.stdout', new=io.StringIO()):
            with self.assertRaises(SystemExit):
                client.main(invitation)
            run.assert_not_called()

    def test_remaining_is_bounded_by_wall_and_monotonic_time(self):
        invitation = {'expires_at': 200}
        with patch.object(client.time, 'time', return_value=50), patch.object(client.time, 'monotonic', return_value=150):
            self.assertEqual(client.remaining(invitation, 170), 20)
        with patch.object(client.time, 'time', return_value=201), patch.object(client.time, 'monotonic', return_value=150):
            self.assertEqual(client.remaining(invitation, 170), 0)

    def test_stop_waits_for_real_foreground_process(self):
        import subprocess
        import sys
        process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        try:
            client.stop_node(['/nonexistent/synch'], process, {})
            self.assertIsNotNone(process.poll())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

    def test_bootstrap_retries_recovery_and_cleans_up_on_expiry(self):
        import base64
        import hashlib
        import os
        import subprocess
        import sys
        import tarfile
        import time
        import zlib
        # A real foreground test process and control CLI, but no network or shell
        # access. The first control command deliberately reports runtime recovery.
        fake = "#!" + sys.executable + "\n" + """
import os, pathlib, signal, sys, time
root = pathlib.Path(sys.argv[2]); args = sys.argv[3:]
if args == ['daemon', 'run']:
    (root / 'pid').write_text(str(os.getpid()))
    (root / 'control.sock').touch()
    time.sleep(60)
elif args == ['daemon', 'stop']:
    os.kill(int((root / 'pid').read_text()), signal.SIGTERM)
elif args[:2] == ['source', 'add']:
    if not (root / 'retry').exists():
        (root / 'retry').touch()
        print('synch: daemon starting: recovering own head', file=sys.stderr)
        sys.exit(1)
elif args[:2] == ['socket', 'activate']:
    assert 'allowed_peers=agent' in args
    assert any(arg.startswith('expires_at=') for arg in args)
else:
    assert args[:2] == ['source', 'scan']
"""
        name = 'synchronicity-v0.1.10-aarch64-apple-darwin'
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w:gz') as tar:
            entry = tarfile.TarInfo(name + '/synch')
            content = fake.encode()
            entry.size = len(content)
            tar.addfile(entry, io.BytesIO(content))
        raw = archive.getvalue()
        invitation = dict(version='v0.1.10', expires_at=time.time() + 3,
                          agent_key='agent', device_key='temporary', space='temporary',
                          database=base64.b64encode(zlib.compress(b'fake-db')).decode(),
                          object=base64.b64encode(b'fake-object').decode(),
                          checksums={name + '.tar.gz': hashlib.sha256(raw).hexdigest()})
        real_run = subprocess.run
        directories = []
        def run(args, **kwargs):
            if args[0] == 'curl':
                destination = Path(args[-1])
                directories.append(destination.parent)
                destination.write_bytes(raw)
                return subprocess.CompletedProcess(args, 0)
            return real_run(args, **kwargs)
        output = io.StringIO()
        with patch.object(client.subprocess, 'run', side_effect=run), \
                patch.object(client.platform, 'system', return_value='Darwin'), \
                patch.object(client.platform, 'machine', return_value='arm64'), \
                patch('builtins.input', return_value='yes'), patch('sys.stdout', new=output):
            client.main(invitation)
        self.assertIn('READY: temporary', output.getvalue())
        self.assertIn('Temporary node stopped', output.getvalue())
        self.assertEqual(len(directories), 1)
        self.assertFalse(directories[0].exists())


if __name__ == '__main__':
    unittest.main()
