#!/usr/bin/env python3
"""Start an isolated temporary node; an operator registers its public key via CP."""
import argparse
import re
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

VERSION = 'v0.1.10'
PROGRAM_REV = '531c9c068f887a6d07a717f66da7d84a6160e550'
PROGRAM_SHA256 = '6f41f4cd89f640a1a36f5625a6c85306ca3778850ec425a8575450fec8a50f72'
KEY = r'[ybndrfg8ejkmcpqxot1uwisza345h769]{52}'



def remaining(session, deadline):
    return max(0, min(session['expires_at'] - time.time(), deadline - time.monotonic()))


def stop_node(command, process, env):
    if process is None or process is None or process.poll() is not None:
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


def main(session):
    if not re.fullmatch(KEY, session['agent_key']):
        raise SystemExit('Agent key must be a device public key.')
    left = session['expires_at'] - time.time()
    if not 0 < left <= 3600:
        raise SystemExit('Session expired or clock incorrect; restart with a new deadline.')
    deadline = time.monotonic() + left
    print('TEMPORARY REMOTE SHELL: the named agent can run commands as your OS user.')
    print('Agent key:', session['agent_key'])
    print('Expires:', time.strftime('%Y-%m-%d %H:%M:%S UTC+8', time.gmtime(session['expires_at'] + 8 * 3600)))
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
    name = 'synchronicity-' + VERSION + '-' + target
    env = {k: v for k, v in os.environ.items() if not k.startswith('SYNCH_')}
    process = None
    command = []
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    handlers = {sig: signal.signal(sig, interrupted)
                for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    with tempfile.TemporaryDirectory(prefix='sykit-session-') as directory:
        root = Path(directory)
        try:
            archive = root / 'release.tar.gz'
            left = remaining(session, deadline)
            if not left:
                raise RuntimeError('Session expired before download.')
            subprocess.run(['curl', '-fL', '--connect-timeout', '15', '--max-time', str(min(120, int(left))),
                            'https://github.com/AFK-surf/synchronicity/releases/download/' +
                            VERSION + '/' + name + '.tar.gz', '-o', str(archive)],
                           check=True, timeout=left)
            sums = subprocess.check_output(['curl', '-fsSL', '--connect-timeout', '10', '--max-time', '25',
                'https://github.com/AFK-surf/synchronicity/releases/download/' + VERSION + '/SHA256SUMS'],
                text=True, timeout=remaining(session, deadline))
            checksums = {line.split()[1].lstrip('*'): line.split()[0]
                         for line in sums.splitlines() if len(line.split()) == 2}
            expected = checksums[name + '.tar.gz']
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
            source = root / 'source'
            source.mkdir(mode=0o700)
            program = source / 'ssh-session.o'
            local_program = Path(__file__).resolve().parents[1] / 'objects/ssh-session.o'
            if local_program.is_file():
                shutil.copyfile(local_program, program)
            else:
                subprocess.run(['curl', '-fsSL', '--connect-timeout', '10', '--max-time', '25',
                    'https://raw.githubusercontent.com/AFK-surf/sykit/' + PROGRAM_REV + '/objects/ssh-session.o',
                    '-o', str(program)], check=True, timeout=remaining(session, deadline))
            if hashlib.sha256(program.read_bytes()).hexdigest() != PROGRAM_SHA256:
                raise RuntimeError('Session program checksum mismatch.')
            command = [str(binary), '--data-dir', str(data)]
            def call(*args):
                while True:
                    left = remaining(session, deadline)
                    if not left:
                        raise RuntimeError('Session expired.')
                    result = subprocess.run(command + list(args), env=env,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            text=True, timeout=min(10, left))
                    if result.returncode == 0:
                        return result.stdout
                    if 'daemon starting:' not in result.stderr or process is None or process.poll() is not None:
                        raise RuntimeError(' '.join(args) + ': ' + result.stderr.strip())
                    time.sleep(min(0.1, left))
            initialized = call('init')
            device_key = re.search(r'^device key: (' + KEY + r')$', initialized, re.M)
            if not device_key:
                raise RuntimeError('Could not read generated device public key.')
            device_key = device_key[1]
            space = 'temporary-shell-' + device_key[:16]
            print('Register this public key through the control plane:', device_key, flush=True)
            print('Registration JSON:', json.dumps(dict(spaces=[space], expires_at=session['expires_at'])), flush=True)
            with (root / 'daemon.log').open('w') as log:
                def start(offline=False):
                    nonlocal process
                    process = subprocess.Popen(command + (['--offline'] if offline else []) + ['daemon', 'run'],
                                               env=env, stdout=log, stderr=log)
                    while not (data / 'control.sock').exists():
                        if process.poll() is not None or not remaining(session, deadline):
                            raise RuntimeError('Daemon did not become ready: ' + (root / 'daemon.log').read_text()[-2000:])
                        time.sleep(0.05)
                start(offline=True)
                call('trust', 'add', session['agent_key'])
                stop_node(command, process, env)
                start()
                call('source', 'add', space, str(source))
                call('source', 'scan', space)
                call('socket', 'activate', 'temporary-shell', '--program', space + '/ssh-session.o',
                     '--config', 'allowed_peers=' + session['agent_key'],
                     '--config', 'expires_at=' + str(session['expires_at']))
                print('LOCAL READY (operator must register delegate):', device_key, flush=True)
                while remaining(session, deadline) > 0 and process.poll() is None:
                    time.sleep(min(0.2, remaining(session, deadline)))
        except KeyboardInterrupt:
            print('\nStopping temporary access…')
        finally:
            # A second Ctrl-C must not interrupt the bounded teardown.
            for sig in handlers:
                signal.signal(sig, signal.SIG_IGN)
            try:
                stop_node(command, process, env)
            finally:
                for sig, previous in handlers.items():
                    signal.signal(sig, previous)
    print('Temporary node stopped; local session files removed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-key', required=True, help='only controller admitted by the socket')
    parser.add_argument('--seconds', type=int, default=600, help='total lifetime, including setup (30–3600)')
    args = parser.parse_args()
    if not 30 <= args.seconds <= 3600:
        parser.error('--seconds must be between 30 and 3600')
    main(dict(agent_key=args.agent_key, expires_at=int(time.time()) + args.seconds))
