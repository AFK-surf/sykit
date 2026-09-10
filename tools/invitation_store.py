"""Private local invitation storage; HTTP only reads short-lived bearer URLs."""
import json
import os
from pathlib import Path
import re
import shlex
import stat
import tempfile
import time
from urllib.parse import urlsplit

TOKEN = re.compile(r'[A-Za-z0-9_-]{32}')
MAX_RECORD = 256 * 1024


def short_command(public_base, token):
    parts = urlsplit(public_base)
    _ = parts.port  # reject malformed/out-of-range ports before issuing a grant
    if (parts.scheme != 'https' or not parts.hostname or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment or not public_base.isascii()
            or any(c.isspace() for c in public_base)):
        raise ValueError('public-base must be an HTTPS URL without credentials, query or fragment')
    if not TOKEN.fullmatch(token):
        raise ValueError('invalid invitation token')
    url = public_base.rstrip('/') + '/s/' + token
    command = 'curl -fsSL ' + shlex.quote(url) + ' | sh'
    return url, command


def private_store(directory):
    path = Path(directory)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
        raise ValueError('invitation store must be a non-symlink directory with mode 0700')
    return path


def shell_script(source):
    # The downloaded stream is program text, NOT consent input. Open the TTY
    # before entering main, so curl | sh cannot accidentally authorize access.
    marker = "    main(INVITATION)"
    if source.count(marker) != 1:
        raise ValueError('unexpected invitation template')
    source = source.replace(marker, "    import sys\n    with open('/dev/tty') as terminal:\n        sys.stdin = terminal\n        main(INVITATION)")
    return "#!/bin/sh\nexec python3 - <<'SYKIT_PYTHON'\n" + source + '\nSYKIT_PYTHON\n'


def publish(directory, token, script, expires_at):
    root = private_store(directory)
    if not TOKEN.fullmatch(token):
        raise ValueError('invalid invitation token')
    if type(expires_at) is not int or not time.time() < expires_at <= time.time() + 3600:
        raise ValueError('invitation must expire within one hour')
    body = json.dumps(dict(expires_at=expires_at, script=script)).encode()
    if len(body) > MAX_RECORD:
        raise ValueError('invitation record too large')
    fd, temporary = tempfile.mkstemp(prefix='.pending-', dir=root)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(body)
            out.flush()
            os.fsync(out.fileno())
        # Atomic create, never overwrite another live ticket (even a symlink).
        os.link(temporary, root / (token + '.json'))
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_record(root, token):
    if not TOKEN.fullmatch(token):
        raise ValueError('invalid invitation token')
    fd = os.open(Path(root) / (token + '.json'), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RECORD:
            raise ValueError('invalid invitation record')
        record = json.loads(source.read(MAX_RECORD + 1))
    if (not isinstance(record, dict) or type(record.get('expires_at')) is not int
            or not isinstance(record.get('script'), str)
            or not record['script'].startswith('#!/bin/sh\n')):
        raise ValueError('invalid invitation record')
    return record


def prune(root):
    for path in Path(root).glob('*.json'):
        if not TOKEN.fullmatch(path.stem):
            continue
        try:
            if read_record(root, path.stem)['expires_at'] <= time.time():
                path.unlink(missing_ok=True)
        except (OSError, ValueError):
            # Never serve malformed records. Do not erase unrelated operator files.
            continue
