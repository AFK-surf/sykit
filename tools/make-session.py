#!/usr/bin/env python3
"""Create a private, short-lived remote-shell invitation from a member node."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sqlite3
import subprocess
import tempfile
import time
import zlib
from invitation_store import private_store, publish, shell_script, short_command

ROOT = Path(__file__).resolve().parents[1]
KEY = r'[ybndrfg8ejkmcpqxot1uwisza345h769]{52}'


def run(command, **kwargs):
    return subprocess.check_output(command, text=True, timeout=30, **kwargs)


def generate(args):
    if bool(args.publish_dir) != bool(args.public_base):
        raise ValueError('--publish-dir and --public-base must be supplied together')
    token = secrets.token_urlsafe(24) if args.publish_dir else None
    command = None
    if token:
        _, command = short_command(args.public_base, token)  # validate the URL before issuing a grant
        private_store(args.publish_dir)
    if not args.output and not token:
        raise ValueError('provide --output or --publish-dir with --public-base')
    with tempfile.TemporaryDirectory(prefix='sykit-output-') as temporary:
        output = Path(args.output) if args.output else Path(temporary) / 'invitation.py'
        generate_to(args, output, token, command)


def generate_to(args, output, token, command):
    agent = [args.synch]
    if args.data_dir:
        agent += ['--data-dir', args.data_dir]
    identity = run(agent + ['id'])
    # A delegation issuer must be a named network member, not a delegate.
    if not re.search(r'^origin: [^\n]+@[^\n]+$', identity, re.M):
        raise RuntimeError('Run from an enrolled, named agent node.')
    key = re.search(r'^  (' + KEY + r') \(active\)$', identity, re.M)
    if not key:
        raise RuntimeError('Could not read agent public key.')
    version = 'v' + run(agent + ['--version']).strip().split()[-1]
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version):
        raise RuntimeError('Use an official release binary.')
    # No unauthenticated releases/latest API: match the agent runtime version.
    sums = run(['curl', '-fsSL', '--connect-timeout', '10', '--max-time', '25',
                'https://github.com/AFK-surf/synchronicity/releases/download/' + version + '/SHA256SUMS'])
    checksums = {}
    for line in sums.splitlines():
        digest, name = line.split()
        if not re.fullmatch('[0-9a-f]{64}', digest):
            raise RuntimeError('Malformed release checksum.')
        checksums[name.lstrip('*')] = digest
    program = ROOT / 'objects/ssh-session.o'
    run(agent + ['socket', 'inspect', str(program)])
    # Refuse overwrite before creating any identity or delegation.
    with output.open('x') as out:
        os.chmod(output, 0o600)
        granted = False
        device = None
        try:
            env = {k: v for k, v in os.environ.items() if not k.startswith('SYNCH_')}
            with tempfile.TemporaryDirectory(prefix='sykit-invitation-') as directory:
                data = Path(directory) / 'node'
                temp = [args.synch, '--data-dir', str(data)]
                initialized = run(temp + ['init'], env=env)
                match = re.search(r'^device key: (' + KEY + r')$', initialized, re.M)
                if not match:
                    raise RuntimeError('Could not read temporary public key.')
                device = match[1]
                started = False
                try:
                    run(temp + ['--offline', 'daemon', 'start'], env=env)
                    started = True
                    # Trust only the issuing agent; no permanent fleet membership.
                    run(temp + ['trust', 'add', key[1]], env=env)
                finally:
                    if started:
                        run(temp + ['daemon', 'stop'], env=env)
                # SQLite backup includes all WAL content without copying control tokens.
                backup = Path(directory) / 'invitation.db'
                with sqlite3.connect(data / 'synchronicity.db') as db, sqlite3.connect(backup) as dst:
                    db.backup(dst)
                space = 'temporary-shell-' + secrets.token_hex(12)
                expires = int(time.time()) + args.seconds
                payload = dict(version=version, checksums=checksums, agent_key=key[1], device_key=device,
                               expires_at=expires, space=space,
                               database=base64.b64encode(zlib.compress(backup.read_bytes())).decode(),
                               object=base64.b64encode(program.read_bytes()).decode())
                run(agent + ['delegate', 'add', device, '--space', space, '--until', str(args.seconds) + 's'])
                granted = True
                template = (ROOT / 'tools/session-client.py').read_text()
                out.write(template.replace('INVITATION = None', 'INVITATION = ' + repr(payload), 1))
                out.flush()
                os.fsync(out.fileno())
                if token:
                    publish(args.publish_dir, token, shell_script(output.read_text()), expires)
        except BaseException:
            output.unlink(missing_ok=True)
            if granted:
                run(agent + ['delegate', 'rm', device])
            raise
    proxy = shlex.join(agent + ['socket', 'connect', 'key:' + device + ':temporary-shell'])
    if command:
        print('PRIVATE command (' + str(len(command)) + ' characters):')
        print(command)
        print('The URL is an expiring bearer ticket; share only with the intended user.')
    if args.output:
        print('PRIVATE invitation:', output)
        print('User runs: python3', shlex.quote(str(output)))
    print('The invitation contains an expiring temporary device key.')
    print('Expires at Unix second:', expires)
    print('Agent connects after READY:')
    print(shlex.join(['ssh', '-tt', '-o', 'ProxyCommand=' + proxy, 'temporary-shell-' + device]))
    print('Revoke network access early:', shlex.join(agent + ['delegate', 'rm', device]))
    print('The user stops the local node with Ctrl-C. Delete the invitation after use.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synch', default='synch')
    parser.add_argument('--data-dir', help='existing agent node data directory')
    parser.add_argument('--seconds', type=int, default=600, help='lifetime from generation (30–3600 seconds)')
    parser.add_argument('--output', help='optional new PRIVATE invitation .py file (0600)')
    parser.add_argument('--publish-dir', help='private local store read by serve-invitations.py')
    parser.add_argument('--public-base', help='HTTPS public URL prefix; a short domain makes the command easier to copy')
    args = parser.parse_args()
    if not 30 <= args.seconds <= 3600:
        parser.error('--seconds must be between 30 and 3600')
    generate(args)
