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


if __name__ == '__main__':
    unittest.main()
