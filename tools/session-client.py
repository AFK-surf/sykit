#!/usr/bin/env python3
"""Template embedded in a private, expiring invitation by make-session.py."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import zlib

# Replaced by the generator. The database contains a TEMPORARY device secret.
INVITATION = None


def remaining(invitation, deadline):
    return max(0, min(invitation['expires_at'] - time.time(), deadline - time.monotonic()))


def stop_node(command, process, env):
    if process is None or process.poll() is not None:
        return
    try:
        subprocess.run(command + ['daemon', 'stop'], env=env, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process.wait(timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main(invitation):
    left = invitation['expires_at'] - time.time()
    if not 0 < left <= 3600:
        raise SystemExit('Invitation expired or clock incorrect; ask the agent for a new one.')
    deadline = time.monotonic() + left
    print('TEMPORARY REMOTE SHELL: the named agent can run commands as your OS user.')
    print('Agent key:', invitation['agent_key'])
    print('Expires:', time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(invitation['expires_at'])))
    print('Not a sandbox: commands may change files or start detached background processes.')
    print('Keep this terminal open. Ctrl-C stops the connection. No permanent service is installed.')
    if input('Allow this agent until the expiry above? Type yes: ').strip() != 'yes':
        raise SystemExit('Cancelled.')
    targets = {('Darwin', 'arm64'): 'aarch64-apple-darwin',
               ('Darwin', 'x86_64'): 'x86_64-apple-darwin',
               ('Linux', 'aarch64'): 'aarch64-unknown-linux-gnu',
               ('Linux', 'x86_64'): 'x86_64-unknown-linux-gnu'}
    target = targets.get((platform.system(), platform.machine()))
    if not target:
        raise SystemExit('Unsupported platform; requires macOS or glibc Linux, Python 3 and curl.')
    name = 'synchronicity-' + invitation['version'] + '-' + target
    env = {k: v for k, v in os.environ.items() if not k.startswith('SYNCH_')}
    process = None
    command = []
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    with tempfile.TemporaryDirectory(prefix='sykit-session-') as directory:
        root = Path(directory)
        try:
            archive = root / 'release.tar.gz'
            left = remaining(invitation, deadline)
            if not left:
                raise RuntimeError('Invitation expired before download.')
            subprocess.run(['curl', '-fL', '--connect-timeout', '15', '--max-time', str(min(120, int(left))),
                            'https://github.com/AFK-surf/synchronicity/releases/download/' +
                            invitation['version'] + '/' + name + '.tar.gz', '-o', str(archive)],
                           check=True, timeout=left)
            expected = invitation['checksums'][name + '.tar.gz']
            if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
                raise RuntimeError('Release checksum mismatch.')
            with tarfile.open(archive, 'r:gz') as tar:
                member = tar.getmember(name + '/synch')
                if not member.isfile():
                    raise RuntimeError('Expected a regular binary in the archive.')
                with tar.extractfile(member) as src, (root / 'synch').open('wb') as dst:
                    shutil.copyfileobj(src, dst)
            binary = root / 'synch'
            binary.chmod(0o700)
            data = root / 'node'
            data.mkdir(mode=0o700)
            (data / 'synchronicity.db').write_bytes(zlib.decompress(base64.b64decode(invitation['database'])))
            (data / 'synchronicity.db').chmod(0o600)
            source = root / 'source'
            source.mkdir(mode=0o700)
            (source / 'ssh-session.o').write_bytes(base64.b64decode(invitation['object']))
            command = [str(binary), '--data-dir', str(data)]
            def call(*args):
                while True:
                    left = remaining(invitation, deadline)
                    if not left:
                        raise RuntimeError('Invitation expired.')
                    result = subprocess.run(command + list(args), env=env,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            text=True, timeout=min(10, left))
                    if result.returncode == 0:
                        return result.stdout
                    if 'daemon starting:' not in result.stderr or process.poll() is not None:
                        raise RuntimeError(' '.join(args) + ': ' + result.stderr.strip())
                    time.sleep(min(0.1, left))
            if not remaining(invitation, deadline):
                raise RuntimeError('Invitation expired during setup.')
            with (root / 'daemon.log').open('w') as log:
                process = subprocess.Popen(command + ['daemon', 'run'], env=env, stdout=log, stderr=log)
                while not (data / 'control.sock').exists():
                    if process.poll() is not None or not remaining(invitation, deadline):
                        raise RuntimeError('Daemon did not become ready: ' + (root / 'daemon.log').read_text()[-2000:])
                    time.sleep(0.05)
                call('source', 'add', invitation['space'], str(source))
                call('source', 'scan', invitation['space'])
                call('socket', 'activate', 'temporary-shell', '--program', invitation['space'] + '/ssh-session.o',
                     '--config', 'allowed_peers=' + invitation['agent_key'],
                     '--config', 'expires_at=' + str(invitation['expires_at']))
                print('READY:', invitation['device_key'], flush=True)
                while remaining(invitation, deadline) > 0 and process.poll() is None:
                    time.sleep(min(0.2, remaining(invitation, deadline)))
        except KeyboardInterrupt:
            print('\nStopping temporary access…')
        finally:
            stop_node(command, process, env)
    print('Temporary node stopped; local session files removed. Delete this invitation script too.')


if __name__ == '__main__':
    if INVITATION is None:
        raise SystemExit('Use tools/make-session.py to generate a private invitation first.')
    main(INVITATION)
