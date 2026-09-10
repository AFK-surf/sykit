import contextlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from invitation_store import private_store, publish, read_record, shell_script, short_command, prune
spec = importlib.util.spec_from_file_location('downloads', ROOT / 'tools/serve-invitations.py')
downloads = importlib.util.module_from_spec(spec)
spec.loader.exec_module(downloads)


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / 'invitations'
        self.server = downloads.Downloads(('127.0.0.1', 0), self.root)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01})
        self.thread.start()
        self.token = secrets.token_urlsafe(24)
        self.script = '#!/bin/sh\nprintf SHORT_COMMAND_OK\\n'

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.temporary.cleanup()

    def request(self, path, method='GET'):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        try:
            connection.request(method, path)
            reply = connection.getresponse()
            return reply.status, dict(reply.getheaders()), reply.read()
        finally:
            connection.close()

    def test_download_short_command_headers_and_execution(self):
        publish(self.root, self.token, self.script, int(time.time()) + 30)
        _, command = short_command('https://support.example', self.token)
        self.assertLessEqual(len(command), 100)
        status, headers, body = self.request('/s/' + self.token)
        self.assertEqual(status, 200)
        self.assertEqual(body, self.script.encode())
        self.assertIn('no-store', headers['Cache-Control'])
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        self.assertEqual(self.request('/s/' + self.token, 'HEAD')[2], b'')
        # Exercise the real curl | sh shape locally without a production server.
        url = 'http://127.0.0.1:' + str(self.server.server_port) + '/s/' + self.token
        result = subprocess.run(['sh', '-c', 'curl -fsSL ' + url + ' | sh'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertIn('SHORT_COMMAND_OK', result.stdout)
        with self.assertRaises(FileExistsError):
            publish(self.root, self.token, '#!/bin/sh\nchanged', int(time.time()) + 30)
        self.assertEqual(read_record(self.root, self.token)['script'], self.script)

    def test_invalid_missing_expired_and_symlink_tickets_fail_closed(self):
        for path in ('/', '/s/', '/s/../secret', '/s/%2e%2e/secret', '/s/' + self.token,
                     '/s/' + self.token + '?copy=1'):
            self.assertEqual(self.request(path)[0], 404)
        publish(self.root, self.token, self.script, int(time.time()) + 30)
        path = self.root / (self.token + '.json')
        record = json.loads(path.read_text()); record['expires_at'] = int(time.time()) - 1
        path.write_text(json.dumps(record))
        self.assertEqual(self.request('/s/' + self.token)[0], 404)
        prune(self.root)
        self.assertFalse(path.exists())
        outside = Path(self.temporary.name) / 'secret'
        outside.write_text(json.dumps(dict(expires_at=int(time.time()) + 30, script=self.script)))
        path.symlink_to(outside)
        self.assertEqual(self.request('/s/' + self.token)[0], 404)
        self.assertTrue(outside.exists())

    def test_service_has_no_remote_issue_api_or_ticket_logs(self):
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            self.assertEqual(self.request('/s/' + self.token, 'POST')[0], 405)
            self.assertEqual(self.request('/s/' + self.token)[0], 404)
        self.assertNotIn(self.token, captured.getvalue())


class IssuanceTests(unittest.TestCase):
    def test_command_length_and_secure_base_validation(self):
        token = secrets.token_urlsafe(24)
        for base in ('http://example.com', 'https://u:p@example.com', 'https://example.com?a=1',
                     'https://example.com#x', 'https://example.com/white space'):
            with self.assertRaises(ValueError):
                short_command(base, token)
        _, command = short_command('https://' + 'a' * 50 + '.example/long-prefix', token)
        self.assertGreater(len(command), 100)  # length is a usability target, never an issuance gate
        with self.assertRaises(ValueError):
            short_command('https://example.com', '../secret')

    def test_permissions_and_lifetime_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'store'
            private_store(root)
            token = secrets.token_urlsafe(24)
            for expiry in (True, int(time.time()) - 1, int(time.time()) + 3601):
                with self.assertRaises(ValueError):
                    publish(root, token, '#!/bin/sh\nexit', expiry)
            publish(root, token, '#!/bin/sh\nexit', int(time.time()) + 30)
            self.assertEqual((root / (token + '.json')).stat().st_mode & 0o777, 0o600)
            root.chmod(0o755)
            with self.assertRaises(ValueError):
                private_store(root)

    def test_shell_wrapper_reads_consent_from_tty_and_is_valid_shell(self):
        source = "INVITATION = {}\ndef main(invitation):\n    pass\nif __name__ == '__main__':\n    main(INVITATION)\n"
        wrapper = shell_script(source)
        self.assertIn("open('/dev/tty')", wrapper)
        subprocess.run(['sh', '-n'], input=wrapper, text=True, check=True)
        # Run the generated wrapper on a real PTY, not a mocked stdin.
        import pty
        source = source.replace('    pass', "    print('CONSENT=' + input('yes? '), flush=True)")
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'invitation.sh'
            script.write_text(shell_script(source))
            pid, fd = pty.fork()
            if pid == 0:
                os.execl('/bin/sh', 'sh', str(script))
            os.write(fd, b'yes\n')
            output = b''
            try:
                import select
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if not select.select([fd], [], [], max(0, deadline - time.monotonic()))[0]:
                        break
                    try:
                        chunk = os.read(fd, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output += chunk
                self.assertIn(b'CONSENT=yes', output)
            finally:
                os.close(fd)
                try:
                    os.kill(pid, 15)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)


if __name__ == '__main__':
    unittest.main()
