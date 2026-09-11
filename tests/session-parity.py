"""Both variants must retain identical capabilities and SSH request handling."""
import os
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


def preprocess(name):
    return subprocess.check_output(
        [os.environ.get("CC", "cc"), "-E", "-P", "-I", str(ROOT / "include"),
         str(ROOT / "src" / (name + ".c"))], text=True)


class SessionParity(unittest.TestCase):
    def test_manifest_and_handlers_match(self):
        shell, session = (preprocess(n) for n in ("ssh-shell", "ssh-session"))
        # Adjacent C strings may remain separate; normalize the program name only.
        manifest = lambda s: re.search(r'static const char[^;]*sy_manifest[^;]*;', s).group()
        self.assertEqual(manifest(shell), manifest(session).replace('ssh-session', 'ssh-shell'))
        # This entire shared region includes channel admission, shell and SFTP requests.
        def handlers(source):
            return source[source.index("static sy_s64 handle_open"):
                          source.index("static void move_terminal")]
        self.assertEqual(handlers(shell), handlers(session))


if __name__ == '__main__':
    unittest.main()
